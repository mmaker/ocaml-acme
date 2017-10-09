open Cohttp
open Cohttp_lwt_unix
open Lwt

open Acme_common

module Pem = X509.Encoding.Pem

type t = {
  account_key : Nocrypto.Rsa.priv ;
  csr :  X509.CA.signing_request ;
  mutable next_nonce : string ;
  d : directory_t ;
}

type challenge_t = {
  url : Uri.t ;
  token : string ;
}

type solver_t = {
  name : string ;
  get_challenge : Json.t -> (challenge_t, string) Result.result ;
  solve_challenge : t -> challenge_t -> string -> (unit, string) Result.result Lwt.t ;
}

let malformed_json j =
  let msg = Printf.sprintf "malformed json: %s" (Json.to_string j) in
  Error msg

let error_in endpoint code body =
  let body = String.escaped body in
  let errf = Printf.sprintf "Error at %s: code %d - body: %s" in
  let msg = errf endpoint code body in
  return_error msg

let http_get url =
  Client.get url >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  body |> Cohttp_lwt_body.to_string >>= fun body ->
  return (code, headers, body)

let get_header_or_fail name headers =
  match Header.get headers name with
  | Some nonce -> return nonce
  | None -> fail_with "Error: I could not fetch a new nonce."

let extract_nonce =
  get_header_or_fail "Replay-Nonce"

let discover directory =
  http_get directory >>= fun (code, headers, body) ->
  extract_nonce headers >>= fun nonce ->
  match Json.of_string body with
  | None -> error_in "discovery" code body
  | Some edir ->
    let p m = Json.string_member m edir in
    match p "new-authz", p "new-reg", p "new-cert", p "revoke-cert" with
    | Some new_authz, Some new_reg, Some new_cert, Some revoke_cert ->
      let u = Uri.of_string in
      let directory_t = {
        directory = directory;
        new_authz = u new_authz;
        new_reg = u new_reg;
        new_cert = u new_cert;
        revoke_cert = u revoke_cert }
      in
      return_ok (nonce, directory_t)
    | _, _, _, _ ->
      return (malformed_json edir)

let new_cli directory rsa_pem csr_pem =
  let maybe_rsa = Primitives.priv_of_pem rsa_pem in
  let maybe_csr = Pem.Certificate_signing_request.of_pem_cstruct (Cstruct.of_string csr_pem) in
  match maybe_rsa, maybe_csr with
  | None, _ -> return_error "Error parsing account key."
  | Some x, [] -> return_error "Error parsing signing request."
  | Some x, y0 :: y1 :: ys -> return_error "Error: too many signing requests."
  | Some account_key, [csr] ->
    discover directory >>= function
    | Error e -> return_error e
    | Ok (next_nonce, d)  ->
      return_ok { account_key ; csr ; next_nonce ; d }


let http_post_jws cli data url =
  let http_post key nonce data url =
    let body = Jws.encode key data nonce  in
    let body_len = string_of_int (String.length body) in
    let header = Header.init () in
    let header = Header.add header "Content-Length" body_len in
    let body = Cohttp_lwt_body.of_string body in
    Client.post ~body:body ~headers:header url
  in
  http_post cli.account_key cli.next_nonce data url >>= fun (resp, body) ->
  let code = resp |> Response.status |> Code.code_of_status in
  let headers = resp |> Response.headers in
  body |> Cohttp_lwt_body.to_string >>= fun body ->
  Logs.debug (fun m -> m "Got code: %d" code);
  Logs.debug (fun m -> m "headers \"%s\"" (String.escaped @@ Cohttp.Header.to_string headers));
  Logs.debug (fun m -> m "body \"%s\"" (String.escaped body));
  extract_nonce headers >>= fun next_nonce ->
  (* XXX: is this like cheating? *)
  cli.next_nonce <- next_nonce;
  return (code, headers, body)

let get_terms_of_service links =
  try Some (List.find
              (fun (link : Cohttp.Link.t) ->
                 link.Cohttp.Link.arc.Cohttp.Link.Arc.relation =
                 [Cohttp.Link.Rel.extension (Uri.of_string "terms-of-service")])
              links)
  with Not_found -> None

let new_reg cli =
  let url = cli.d.new_reg in
  let body = {|{"resource": "new-reg"}|} in
  http_post_jws cli body url >>= fun (code, headers, body) ->
  match code with
  | 201 ->
    (match Cohttp.Header.get_location headers with
     | Some accept_url ->
       let terms = match Cohttp.Header.get_links headers |> get_terms_of_service with
         | Some terms -> terms
         | None -> failwith "Accept url without terms-of-service"
       in
       Logs.info (fun m -> m "Must accept terms.");
       return_ok (Some (terms, accept_url))
     | None ->
       Logs.info (fun m -> m "Account created.");
       return_ok None)
  | 409 ->
    Logs.info (fun m -> m "Already registered.");
    return_ok None
  | _   -> error_in "new-reg" code body

let accept_terms cli ~url ~terms =
  let body =
    Json.to_string (`Assoc [
        ("resource", `String "reg");
        ("agreement", `String (Uri.to_string terms));
      ])
  in
  http_post_jws cli body url >>= fun (code, headers, body) ->
  match code with
  | 202 -> Logs.info (fun m -> m "Terms accepted."); return_ok ()
  | 409 -> Logs.info (fun m -> m "Already registered."); return_ok ()
  | _ -> error_in "accept_terms" code body


(*
   XXX. probably the structure of challenges different from http-01 and
   dns-01 is different, but for the two and only supported ones it's
   probably fine.
 *)
let get_challenge challenge_filter authorization =
  match Json.list_member "challenges" authorization with
  | None -> malformed_json authorization
  | Some challenges ->
    match List.filter challenge_filter challenges with
    | [] -> Error "No supported challenges found."
    | challenge :: _ ->
      let token = Json.string_member "token" challenge in
      let url = Json.string_member "uri" challenge in
      match token, url with
      | Some t, Some u -> Ok {token=t; url=Uri.of_string u}
      | _, _ -> malformed_json authorization

let http_solver writef =
  let name = "http-01" in
  let get_http01_challenge =
    let is_http01 c = Json.string_member "type" c = Some "http-01" in
    get_challenge is_http01
  in
  let solve_http01_challenge cli challenge domain =
    let token = challenge.token in
    let pk = Primitives.pub_of_priv cli.account_key in
    let thumbprint = Jwk.thumbprint (`Rsa pk) in
    let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
    writef domain token key_authorization;
    return_ok ()
  in
  {
    name = name ;
    get_challenge = get_http01_challenge ;
    solve_challenge = solve_http01_challenge
  }

let default_http_solver =
  let default_writef domain file content =
    Logs.info (fun f -> f "Domain %s wants file %s content %s\n" domain file content);
    read_line ()
  in
  http_solver default_writef

let dns_solver writef =
  let name = "dns-01" in
  let get_dns01_challenge =
    let is_dns01 c = Json.string_member "type" c = Some "dns-01" in
    get_challenge is_dns01
  in
  let solve_dns01_challenge cli challenge domain =
    let token = challenge.token in
    let pk = Primitives.pub_of_priv cli.account_key in
    let thumbprint = Jwk.thumbprint (`Rsa pk) in
    let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
    let solution = Primitives.sha256 key_authorization |> B64u.urlencode in
    writef domain solution;
    return_ok ()
  in
  {
    name = name ;
    get_challenge = get_dns01_challenge ;
    solve_challenge = solve_dns01_challenge
  }

let default_dns_solver =
  let default_writef domain record =
    Logs.info (fun f -> f "_acme-challenge.%s. 300 IN TXT \"%s\"\n" domain record);
    read_line ()
  in
  dns_solver default_writef

let new_authz cli domain get_challenge =
  let url = cli.d.new_authz in
  let body = Printf.sprintf
      {|{"resource": "new-authz", "identifier": {"type": "dns", "value": "%s"}}|}
      domain
  in
  http_post_jws cli body url >>= fun (code, headers, body) ->
  match code with
  | 201 ->
    begin
      match Json.of_string body with
      | Some authorization -> return (get_challenge authorization)
      | None -> error_in "new-auth" code body
    end
  (* XXX. any other codes to handle? *)
  | _ -> error_in "new-authz" code body


let challenge_met cli ct challenge =
  let token = challenge.token in
  let pub = Primitives.pub_of_priv cli.account_key in
  let thumbprint = Jwk.thumbprint (`Rsa pub) in
  let key_authorization = Printf.sprintf "%s.%s" token thumbprint in
  (* write key_authorization *)
  (**
   XXX. that's weird: the standard (page 40, rev. 5) specifies only a "type" and
   a "keyAuthorization" key in order to inform the CA of the accomplished
   challenge.
   However, following that I got

   "urn:acme:error:malformed",
   "detail": "Request payload does not specify a resource",
   "status": 400

   while specifying "challenge": type I am able to proceed.
   **)
  let data = Printf.sprintf
      {|{"resource": "challenge", "type": "%s", "keyAuthorization": "%s"}|}
      ct key_authorization
  in
  http_post_jws cli data challenge.url >>= fun _ ->
  (* XXX. here we should deal with the resulting codes, at least. *)
  return_ok ()


let poll_challenge_status cli challenge =
  http_get challenge.url >>= fun (code, headers, body) ->
  match Json.of_string body with
  | Some challenge_status ->
    begin
      let status =  Json.string_member "status" challenge_status in
      match status with
      | Some "valid" -> return_ok false
      (* «If this field is missing, then the default value is "pending".» *)
      | Some "pending" | None -> return_ok true
      | Some status -> error_in "polling" code body
    end
  | _ -> error_in "polling" code body


(* XXX. is there a more clever way for making this lazy ?*)
let default_sleep () = Unix.sleep 60

let rec poll_until ?(sleep=default_sleep) cli challenge =
  poll_challenge_status cli challenge >>= function
  | Error e  -> return_error e
  | Ok false -> return_ok ()
  | Ok true  ->
    Logs.info (fun m -> m "Polling...");
    sleep ();
    poll_until cli challenge


let der_to_pem der =
  let der = Cstruct.of_string der in
  match X509.Encoding.parse der with
  | Some crt -> Ok (Pem.Certificate.to_pem_cstruct [crt] |> Cstruct.to_string)
  | None -> Error "I got gibberish while trying to decode the new certificate."

let new_cert cli =
  let url = cli.d.new_cert in
  let der = X509.Encoding.cs_of_signing_request cli.csr |> Cstruct.to_string |> B64u.urlencode in
  let data = Printf.sprintf {|{"resource": "new-cert", "csr": "%s"}|} der in
  http_post_jws cli data url >>= fun (code, headers, body) ->
  match code with
  | 201 -> return (der_to_pem body)
  | _ -> error_in "new-cert" code body

let get_crt rsa_pem csr_pem ?(directory = letsencrypt_url) ?(solver = default_dns_solver) =
  Nocrypto_entropy_lwt.initialize () >>= fun () ->
  let open Lwt_result.Infix in
  (* create a new client *)
  new_cli directory rsa_pem csr_pem >>= fun cli ->

  (* if the client didn't register, then register. Otherwise proceed *)
  new_reg cli >>= (function
      | Some (terms_link, accept_url) ->
        let terms = terms_link.Cohttp.Link.target in
        Logs.info (fun f -> f "Accepting terms at %s\n" (Uri.to_string terms));
        accept_terms cli ~url:accept_url ~terms
      | None ->
        Logs.info (fun f -> f "No ToS.");
        return_ok ())
  >>= fun () ->
  (* for all domains, ask the ACME server for a certificate *)
  let csr = Pem.Certificate_signing_request.of_pem_cstruct1 (Cstruct.of_string csr_pem) in
  let domains = domains_of_csr csr in
  Lwt_list.fold_left_s
    (fun r domain ->
       match r with
       | Ok () ->
         new_authz cli domain solver.get_challenge >>= fun challenge ->
         solver.solve_challenge cli challenge domain >>= fun () ->
         challenge_met cli solver.name challenge >>= fun () ->
         poll_until cli challenge
       | Error r ->
         Lwt.return_error "oh fuck")
    (Ok ()) domains >>= fun () ->
  new_cert cli >>= fun pem ->
  return_ok pem
