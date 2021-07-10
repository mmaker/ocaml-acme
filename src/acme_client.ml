open Lwt.Infix

open Acme_common

let src = Logs.Src.create "letsencrypt" ~doc:"let's encrypt library"
module Log = (val Logs.src_log src : Logs.LOG)

let guard p err = if p then Ok () else err

let key_authorization key token =
  let pk = Primitives.pub_of_priv key in
  let thumbprint = Jwk.thumbprint (`Rsa pk) in
  Printf.sprintf "%s.%s" token thumbprint

type t = {
  account_key : Mirage_crypto_pk.Rsa.priv;
  mutable next_nonce : string;
  d : Directory.t;
  account_url : Uri.t;
}

type solver = {
  typ : Challenge.typ;
  solve_challenge : token:string -> key_authorization:string ->
    [`host] Domain_name.t -> (unit, [ `Msg of string]) result Lwt.t;
}

let error_in endpoint status body =
  Rresult.R.error_msgf
    "Error at %s: status %3d - body: %S"
    endpoint status body

let http_solver writef =
  let solve_challenge ~token ~key_authorization domain =
    let prefix = ".well-known/acme-challenge" in
    writef domain ~prefix ~token ~content:key_authorization
  in
  { typ = `Http ; solve_challenge }

let print_http =
  let solve domain ~prefix ~token ~content =
    Log.warn (fun f -> f "Setup http://%a/%s/%s to serve %s and press enter to continue"
                 Domain_name.pp domain prefix token content);
    ignore (read_line ());
    Lwt.return_ok ()
  in
  http_solver solve

let dns_solver writef =
  let solve_challenge ~token:_ ~key_authorization domain =
    let solution = Primitives.sha256 key_authorization |> B64u.urlencode in
    let domain_name = Domain_name.prepend_label_exn domain "_acme-challenge" in
    writef domain_name solution
  in
  { typ = `Dns ; solve_challenge }

let print_dns =
  let solve domain solution =
    Log.warn (fun f -> f "Setup a TXT record for %a to return %s and press enter to continue"
                 Domain_name.pp domain solution);
    ignore (read_line ());
    Lwt.return_ok ()
  in
  dns_solver solve

let nsupdate ?proto id now out ?recv ~zone ~keyname key =
  let open Dns in
  let nsupdate name record =
    Log.info (fun m -> m "solving dns by update to! %a (name %a)"
                 Domain_name.pp zone Domain_name.pp name);
    let zone = Packet.Question.create zone Rr_map.Soa
    and update =
      let up =
        Domain_name.Map.singleton name
          [
            Packet.Update.Remove (Rr_map.K Txt) ;
            Packet.Update.Add Rr_map.(B (Txt, (3600l, Txt_set.singleton record)))
      ]
      in
      (Domain_name.Map.empty, up)
    and header = (id, Packet.Flags.empty)
    in
    let packet = Packet.create header zone (`Update update) in
    match Dns_tsig.encode_and_sign ?proto packet (now ()) key keyname with
    | Error s -> Lwt.return_error (`Msg (Fmt.to_to_string Dns_tsig.pp_s s))
    | Ok (data, mac) ->
      out data >>= function
      | Error err -> Lwt.return_error err
      | Ok () ->
        match recv with
        | None -> Lwt.return_ok ()
        | Some recv -> recv () >|= function
          | Error e -> Error e
          | Ok data ->
            match Dns_tsig.decode_and_verify (now ()) key keyname ~mac data with
            | Error e -> Error (`Msg (Fmt.strf "decode and verify error %a" Dns_tsig.pp_e e))
            | Ok (res, _, _) ->
              match Packet.reply_matches_request ~request:packet res with
              | Ok _ -> Ok ()
              | Error mismatch ->
                Error (`Msg (Fmt.strf "error %a expected reply to %a, got %a"
                               Packet.pp_mismatch mismatch
                               Packet.pp packet Packet.pp res))
  in
  dns_solver nsupdate

let alpn_solver writef =
  (* on the ID-PE arc (from RFC 5280), 31 *)
  let id_pe_acme = Asn.OID.(base 1 3 <| 6 <| 1 <| 5 <| 5 <| 7 <| 1 <| 31)
  and alpn = "acme-tls/1"
  in
  (* extension value is an octet_string of the hash *)
  let encode_val hash =
    let enc = Asn.(encode (codec der S.octet_string)) in
    enc hash
  in
  let solve_challenge ~token:_ ~key_authorization domain =
    let priv = `RSA (Mirage_crypto_pk.Rsa.generate ~bits:2048 ()) in
    let open X509 in
    let solution = Primitives.sha256 key_authorization |> Cstruct.of_string in
    let name = Domain_name.to_string domain in
    let cn = Distinguished_name.CN name in
    let dn = [ Distinguished_name.Relative_distinguished_name.singleton cn ] in
    let extensions =
      let gn = General_name.(singleton DNS [ name ]) in
      let full = encode_val solution in
      Extension.(add Subject_alt_name (false, gn)
                   (singleton (Unsupported id_pe_acme) (true, full)))
    in
    let valid_from, valid_until = Ptime.epoch, Ptime.epoch in
    match
      let open Rresult.R.Infix in
      Signing_request.create dn priv >>= fun csr ->
      Rresult.R.error_to_msg ~pp_error:X509.Validation.pp_signature_error
        (Signing_request.sign csr ~valid_from ~valid_until ~extensions priv dn)
    with
    | Ok cert -> writef domain ~alpn priv cert
    | Error _ as e -> Lwt.return e
  in
  { typ = `Alpn ; solve_challenge }

let print_alpn =
  let solve domain ~alpn priv cert =
    Log.warn (fun f -> f "Setup a TLS server for %a (ALPN %s) to use key %s and certificate %s. Press enter to continue"
                 Domain_name.pp domain alpn
                 (Cstruct.to_string (X509.Private_key.encode_pem priv))
                 (Cstruct.to_string (X509.Certificate.encode_pem cert)));
    ignore (read_line ());
    Lwt.return_ok ()
  in
  alpn_solver solve

module Make (Http : HTTP_client.S) = struct

let location headers =
  match Http.Headers.get_location headers with
  | Some url -> Ok url
  | None ->
    Rresult.R.error_msgf "expected a location header, but couldn't find it"

let extract_nonce headers =
  match Http.Headers.get headers "Replay-Nonce" with
  | Some nonce -> Ok nonce
  | None -> Error (`Msg "Error: I could not fetch a new nonce.")

let headers =
  Http.Headers.init_with "user-agent" ("ocaml-letsencrypt/" ^ Version.t)

let http_get ?ctx url =
  Http.get ?ctx ~headers url >>= fun (resp, body) ->
  let status = Http.Response.status resp in
  let headers = Http.Response.headers resp in
  body |> Http.Body.to_string >>= fun body ->
  Log.debug (fun m -> m "HTTP get: %a" Uri.pp_hum url);
  Log.debug (fun m -> m "Got status: %3d" status);
  Log.debug (fun m -> m "headers %S" (Http.Headers.to_string headers));
  Log.debug (fun m -> m "body %S" body);
  Lwt.return (status, headers, body)

let http_head ?ctx url =
  Http.head ?ctx ~headers url >>= fun resp ->
  let status = Http.Response.status resp in
  let headers = Http.Response.headers resp in
  Log.debug (fun m -> m "HTTP HEAD: %a" Uri.pp_hum url);
  Log.debug (fun m -> m "Got status: %3d" status);
  Log.debug (fun m -> m "headers %S" (Http.Headers.to_string headers));
  Lwt.return (status, headers)

let discover ?ctx directory =
  http_get ?ctx directory >|= function
  | (200, _headers, body) -> Directory.decode body
  | (status, _, body) -> error_in "discover" status body

let get_nonce ?ctx url =
  http_head ?ctx url >|= function
  | 200, headers -> extract_nonce headers
  | s, _ -> error_in "get_nonce" s ""

let rec http_post_jws ?ctx ?(no_key_url = false) cli data url =
  let prepare_post key nonce =
    let kid_url = if no_key_url then None else Some cli.account_url in
    let body = Jws.encode_acme ?kid_url ~data:(json_to_string data) ~nonce url key in
    let body_len = string_of_int (String.length body) in
    let headers = Http.Headers.add headers  "Content-Length" body_len in
    let headers = Http.Headers.add headers "Content-Type" "application/jose+json" in
    (headers, body)
  in
  let headers, body = prepare_post cli.account_key cli.next_nonce in
  Log.debug (fun m -> m "HTTP post %a (data %s body %S)"
                Uri.pp_hum url (json_to_string data) body);
  let body = Http.Body.of_string body in
  Http.post ?ctx ~body ~headers url >>= fun (resp, body) ->
  let status = Http.Response.status resp in
  let headers = Http.Response.headers resp in
  Http.Body.to_string body >>= fun body ->
  Log.debug (fun m -> m "Got code: %3d" status);
  Log.debug (fun m -> m "headers %S" (Http.Headers.to_string headers));
  Log.debug (fun m -> m "body %S" body);
  (match extract_nonce headers with
   | Error `Msg e -> Log.err (fun m -> m "couldn't extract nonce: %s" e)
   | Ok next_nonce -> cli.next_nonce <- next_nonce);
  if status = 400 then begin
    let open Lwt_result.Infix in
    Lwt_result.lift (Error.decode body) >>= fun err ->
    if err.err_typ = `Bad_nonce then begin
      Log.warn (fun m -> m "received bad nonce %s from server, retrying same request"
                   err.detail);
      http_post_jws ?ctx cli data url
    end else begin
      Log.warn (fun m -> m "error %a in response" Error.pp err);
      Lwt.return_ok (status, headers, body)
    end
  end else
    Lwt.return_ok (status, headers, body)

let create_account ?ctx ?email cli =
  let url = cli.d.new_account in
  let contact = match email with
    | None -> []
    | Some email -> [ "contact", `List [ `String ("mailto:" ^ email) ] ]
  in
  let body = `Assoc (("termsOfServiceAgreed", `Bool true) :: contact) in
  http_post_jws ?ctx ~no_key_url:true cli body url >|= function
  | Error e -> Error e
  | Ok (201, headers, body) ->
    let open Rresult.R.Infix in
    Account.decode body >>= fun account ->
    guard (account.account_status = `Valid)
      (Rresult.R.error_msgf "account %a does not have status valid"
         Account.pp account) >>= fun () ->
    location headers >>| fun account_url ->
    { cli with account_url }
  | Ok (status, _headers, body) -> error_in "newAccount" status body

let get_account ?ctx cli url =
  let body = `Null in
  http_post_jws ?ctx cli body url >|= function
  | Error e -> Error e
  | Ok (200, _headers, body) ->
    let open Rresult.R.Infix in
    (* at least staging doesn't include orders *)
    Account.decode body >>| fun acc ->
    (* well, here we may encounter some orders which should be processed
       (or cancelled, considering the lack of a csr)! *)
    Log.info (fun m -> m "account %a" Account.pp acc)
  | Ok (status, _headers, body) -> error_in "get account" status body

let find_account_url ?ctx ?email ~nonce key directory =
  let url = directory.Directory.new_account in
  let body = `Assoc [ "onlyReturnExisting", `Bool true ] in
  let cli = {
    next_nonce = nonce ;
    account_key = key ;
    d = directory ;
    account_url = Uri.empty ;
  } in
  http_post_jws ?ctx ~no_key_url:true cli body url >>= function
  | Error e -> Lwt.return (Error e)
  | Ok (200, headers, body) ->
    let open Rresult.R.Infix in
    Lwt.return begin
      (* unclear why this is not an account object, as required in 7.3.0/7.3.1 *)
      Account.decode body >>= fun account ->
      guard (account.account_status = `Valid)
        (Rresult.R.error_msgf "account %a does not have status valid"
           Account.pp account) >>= fun () ->
      location headers >>| fun account_url ->
      { cli with account_url }
    end
  | Ok (400, _headers, body) ->
    let open Lwt_result.Infix in
    Lwt_result.lift (Error.decode body) >>= fun err ->
    if err.err_typ = `Account_does_not_exist then begin
      Log.info (fun m -> m "account does not exist, creating an account");
      create_account ?ctx ?email cli
    end else begin
      Log.err (fun m -> m "error %a in find account url" Error.pp err);
      Lwt.return (error_in "newAccount" 400 body)
    end
  (* according to RFC 8555 7.3.3 there can be a forbidden if ToS were updated,
     and the client should re-approve them *)
  | Ok (status, _headers, body) ->
    Lwt.return (error_in "newAccount" status body)

let challenge_solved ?ctx cli url =
  let body = `Assoc [] in (* not entirely clear why this now is {} and not "" *)
  http_post_jws ?ctx cli body url >|= function
  | Error e -> Error e
  | Ok (200, _headers, body) ->
    Log.info (fun m -> m "challenge solved POSTed (OK), body %s" body);
    Ok ()
  | Ok (201, _headers, body) ->
    Log.info (fun m -> m "challenge solved POSTed (CREATE), body %s" body);
    Ok ()
  | Ok (status, _headers, body) ->
    error_in "challenge solved" status body

let process_challenge ?ctx solver cli sleep host challenge =
  (* overall plan:
     - solve it (including "provisioning" - for now maybe a sleep 5)
     - report back to server that it is now solved
  *)
  (* good news is that we already ensured that the solver and challenge fit *)
  match challenge.Challenge.challenge_status with
  | `Pending ->
    (* do some work :) solve it! *)
    let open_err f = f >|= Rresult.R.open_error_msg in
    let open Lwt_result.Infix in
    let token = challenge.token in
    let key_authorization = key_authorization cli.account_key token in
    open_err (solver.solve_challenge ~token ~key_authorization host) >>= fun () ->
    challenge_solved ?ctx cli challenge.url
  | `Processing -> (* ehm - relax and wait till the server figured something out? *)
    (* but there's as well the notion of "Likewise, client requests for retries do not cause a state change." *)
    (* it looks like in processing after some _client_defined_timeout_, the client may approach to server to re-evaluate *)

    (* from Section 8.2 *)
    (* While the server is
       still trying, the status of the challenge remains "processing"; it is
       only marked "invalid" once the server has given up.

       The server MUST provide information about its retry state to the
       client via the "error" field in the challenge and the Retry-After
       HTTP header field in response to requests to the challenge resource.
       The server MUST add an entry to the "error" field in the challenge
       after each failed validation query.  The server SHOULD set the Retry-
       After header field to a time after the server's next validation
       query, since the status of the challenge will not change until that
       time.

       Clients can explicitly request a retry by re-sending their response
       to a challenge in a new POST request (with a new nonce, etc.).  This
       allows clients to request a retry when the state has changed (e.g.,
       after firewall rules have been updated).  Servers SHOULD retry a
       request immediately on receiving such a POST request.  In order to
       avoid denial-of-service attacks via client-initiated retries, servers
       SHOULD rate-limit such requests.
    *)
    (* so what shall we do? wait? *)
    Log.info (fun m -> m "challenge is processing, let's wait a second");
    sleep 1 >>= fun () ->
    Lwt.return_ok ()
  | `Valid -> (* nothing to do from our side *)
    Lwt.return_ok ()
  | `Invalid -> (* we lost *)
    Lwt.return_error (`Msg "challenge invalid")

(* yeah, we could parallelize them... but first not do it. *)
let process_authorization ?ctx solver cli sleep url =
  let body = `Null in
  http_post_jws ?ctx cli body url >>= function
  | Error e -> Lwt.return (Error e)
  | Ok (200, _headers, body) ->
    begin
      let open Lwt_result.Infix in
      Lwt_result.lift (Authorization.decode body) >>= fun auth ->
      Log.info (fun m -> m "authorization %a" Authorization.pp auth);
      match auth.authorization_status with
      | `Pending -> (* we need to work on some challenge here! *)
        let host = Domain_name.(host_exn @@ of_string_exn @@ snd auth.identifier) in
        begin match List.filter (fun c -> c.Challenge.challenge_typ = solver.typ) auth.challenges with
          | [] ->
            Log.err (fun m -> m "no challenge found for solver");
            Lwt.return (Rresult.R.error_msgf "couldn't find a challenge that matches the provided solver")
          | c::cs ->
            if not (cs = []) then
              Log.err (fun m -> m "multiple (%d) challenges found for solver, taking head"
                          (succ (List.length cs)));
            process_challenge ?ctx solver cli sleep host c
        end
      | `Valid -> (* we can ignore it - some challenge made it *)
        Log.info (fun m -> m "authorization is valid");
        Lwt.return_ok ()
      | `Invalid -> (* no chance this will ever be good again, or is there? *)
        Log.err (fun m -> m "authorization is invalid");
        Lwt.return_error (`Msg "invalid")
      | `Deactivated -> (* client-side deactivated / retracted *)
        Log.err (fun m -> m "authorization is deactivated");
        Lwt.return_error (`Msg "deactivated")
      | `Expired -> (* timeout *)
        Log.err (fun m -> m "authorization is expired");
        Lwt.return_error (`Msg "expired")
      | `Revoked -> (* server-side deactivated *)
        Log.err (fun m -> m "authorization is revoked");
        Lwt.return_error (`Msg "revoked")
    end
  | Ok (status, _, body) -> Lwt.return (error_in "authorization" status body)

let finalize ?ctx cli csr url =
  let body =
    let csr_as_b64 =
      X509.Signing_request.encode_der csr |> Cstruct.to_string |> B64u.urlencode
    in
    `Assoc [ "csr", `String csr_as_b64 ]
  in
  http_post_jws ?ctx cli body url >|= function
  | Error e -> Error e
  | Ok (200, headers, body) ->
    let open Rresult.R.Infix in
    Order.decode body >>| fun order ->
    headers, order
  | Ok (status, _, body) -> error_in "finalize" status body

let dl_certificate ?ctx cli url =
  let body = `Null in
  http_post_jws ?ctx cli body url >|= function
  | Error e -> Error e
  | Ok (200, _headers, body) ->
    (* body is a certificate chain (no comments), with end-entity certificate being the first *)
    (* TODO: check order? figure out chain? *)
    X509.Certificate.decode_pem_multiple (Cstruct.of_string body)
  | Ok (status, _header, body) -> error_in "certificate" status body

let get_order ?ctx cli url =
  let body = `Null in
  http_post_jws ?ctx cli body url >|= function
  | Error e -> Error e
  | Ok (200, headers, body) ->
    let open Rresult.R.Infix in
    Order.decode body >>| fun order ->
    headers, order
  | Ok (status, _header, body) ->
    error_in "getting order" status body

(* HTTP defines this header as "either seconds" or "absolute HTTP date" *)
let retry_after h =
  match Http.Headers.get h "Retry-after" with
  | None -> 1
  | Some x -> try int_of_string x with
      Failure _ ->
      Log.warn (fun m -> m "retry-after header is not an integer, but %s (using 1 second instead)" x);
      1

(* TODO this 'expires' stuff in the order *)
(* state machine is slightly unclear, from section 7.4 (page 47 top):
   "Once the client believes it has fulfilled the server's requirements,
   it should send a POST request to the order resource's finalize URL"
   does this mean e.g. retry-after should as well be done to the finalize URL?
   (rather than the order URL)

   page 48 says:
   "A request to finalize an order will result in error if the order is
   not in the "ready" state.  In such cases, the server MUST return a
   403 (Forbidden) error with a problem document of type
   "orderNotReady".  The client should then send a POST-as-GET request
   to the order resource to obtain its current state."

   and also
   "If a request to finalize an order is successful, the server will
   return a 200 (OK) with an updated order object.  The status of the
   order will indicate what action the client should take"

   so basically the "order" object returned by finalize is only every in
   "processing" or "pending", or do I misunderstand anything?
   if it is in a different state, a 403 would've been issued (not telling
   what is wrong) - with orderNotReady; if the CSR is bad, some unspecified
   HTTP status is returned, with "badCSR" as error code. how convenient.
*)
let rec process_order ?ctx solver cli sleep csr order_url headers order =
  (* as usual, first do the easy stuff ;) *)
  match order.Order.order_status with
  | `Invalid ->
    (* exterminate -- consider the order process abandoned *)
    Log.err (fun m -> m "order %a is invalid, falling apart" Order.pp order);
    Lwt.return (Rresult.R.error_msgf "attempting to process an invalid order")
  | `Pending ->
    (* there's still some authorization pending, according to the server! *)
    let open Lwt_result.Infix in
    Log.warn (fun m -> m "something is pending here... need to work on this");
    Lwt_list.fold_left_s (fun acc a ->
        match acc with
        | Ok () -> process_authorization ?ctx solver cli sleep a
        | Error e -> Lwt.return (Error e)) (Ok ()) order.authorizations >>= fun () ->
    get_order ?ctx cli order_url >>= fun (headers, order) ->
    process_order ?ctx solver cli sleep csr order_url headers order
  | `Ready ->
    (* server agrees that requirements are fulfilled, submit a finalization request *)
    let open Lwt_result.Infix in
    finalize ?ctx cli csr order.finalize >>= fun (headers, order) ->
    process_order ?ctx solver cli sleep csr order_url headers order
  | `Processing ->
    (* sleep Retry-After header field time, and re-get order to hopefully get a certificate url *)
    let retry_after = retry_after headers in
    Log.debug (fun m -> m "sleeping for %d seconds" retry_after);
    sleep retry_after >>= fun () ->
    let open Lwt_result.Infix in
    get_order ?ctx cli order_url >>= fun (headers, order) ->
    process_order ?ctx solver cli sleep csr order_url headers order
  | `Valid ->
    (* the server has issued the certificate and provisioned its URL in the certificate field of the order *)
    match order.certificate with
    | None ->
      Log.warn (fun m -> m "received valid order %a without certificate URL, should not happen" Order.pp order);
      Lwt.return (Rresult.R.error_msgf "valid order without certificate URL")
    | Some cert ->
      dl_certificate ?ctx cli cert >|= function
      | Error e -> Error e
      | Ok certs ->
        Log.info (fun m -> m "retrieved %d certificates" (List.length certs));
        List.iter (fun c ->
            Log.info (fun m -> m "%s" (Cstruct.to_string (X509.Certificate.encode_pem c))))
          certs;
        Ok certs

let new_order ?ctx solver cli sleep csr =
  let hostnames =
    X509.Host.Set.fold
      (fun (typ, name) acc ->
         let pre = match typ with `Strict -> "" | `Wildcard -> "*." in
         (pre ^ Domain_name.to_string name) :: acc)
      (X509.Signing_request.hostnames csr) []
  in
  let body =
    (* TODO this may contain "notBefore" and "notAfter" as RFC3339 encoded timestamps
       (what the client would like as validity of the certificate) *)
    let ids =
      List.map (fun name ->
          `Assoc [ "type", `String "dns" ; "value", `String name ])
        hostnames
    in
    `Assoc [ "identifiers", `List ids ]
  in
  http_post_jws ?ctx cli body cli.d.new_order >>= function
  | Error e -> Lwt.return (Error e)
  | Ok (201, headers, body) ->
    let open Lwt_result.Infix in
    Lwt_result.lift (Order.decode body) >>= fun order ->
    (* identifiers (should-be-verified to be the same set as the hostnames above?) *)
    Lwt_result.lift (location headers) >>= fun order_url ->
    process_order ?ctx solver cli sleep csr order_url headers order
  | Ok (status, _, body) -> Lwt.return (error_in "newOrder" status body)

let sign_certificate ?ctx solver cli sleep csr =
  (* send a newOrder request for all the host names in the CSR *)
  (* but as well need to check that we're able to solve authorizations for the names *)
  new_order ?ctx solver cli sleep csr

let initialise ?ctx ~endpoint ?email account_key =
  let open Lwt_result.Infix in
  (* create a new client *)
  discover ?ctx endpoint >>= fun d ->
  Log.info (fun m -> m "discovered directory %a" Directory.pp d);
  get_nonce ?ctx d.new_nonce >>= fun nonce ->
  Log.info (fun m -> m "got nonce %s" nonce);
  (* now there are two ways forward
     - register a new account based on account_key
     - retrieve account URL for account_key (if already registered)
     let's first try the latter -- the former is done by find_account_url if account does not exist!
  *)
  find_account_url ?ctx ?email ~nonce account_key d
end
