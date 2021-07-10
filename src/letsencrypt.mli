(** [Letsencrypt]: for when you love authorities.

    Letsencrypt is an implementation of the ACME protocol, for automating the
    generation of HTTPS certificates.

    Currently, this library has been tested (and is working) only with
    Letsencrypt servers.
 *)
val letsencrypt_production_url : Uri.t
val letsencrypt_staging_url : Uri.t

(** ACME Client.

    This module provides client commands.
    Note: right now this module implements only the strict necessary
    in order to register an account, solve http-01 challenges provided by the CA,
    and fetch the certificate.
    This means that you will be able to maintain your server with this.
 *)
module Client: sig
  type t

  type solver

  (** [http_solver (fun domain ~prefix ~token ~content)] is a solver for
      http-01 challenges. The provided function should return [Ok ()] once the
      web server at [domain] serves [content] as [prefix/token]:
      a GET request to http://[domain]/[prefix]/[token] should return [content].
      The [prefix] is ".well-known/acme-challenge".
  *)
  val http_solver :
    ([`host] Domain_name.t -> prefix:string -> token:string -> content:string ->
     (unit, [ `Msg of string ]) result Lwt.t) -> solver

  (** [print_http] outputs the HTTP challenge solution, and waits for user input
      before continuing with ACME. *)
  val print_http : solver

  (** [dns_solver (fun domain content)] is a solver for dns-01 challenges.
      The provided function should return [Ok ()] once the authoritative
      name servers serve a TXT record at [domain] with the content. The
      [domain] already has the [_acme-challenge.] prepended. *)
  val dns_solver :
    ([`raw] Domain_name.t -> string ->
     (unit, [ `Msg of string ]) result Lwt.t) -> solver

  (** [print_dns] outputs the DNS challenge solution, and waits for user input
      before continuing with ACME. *)
  val print_dns : solver

  (** [nsupdate ~proto id now send ~recv ~keyname key ~zone]
      constructs a dns solver that sends a DNS update packet (using [send])
      and optionally waits for a signed reply (using [recv] if present) to solve
      challenges. The update is signed with a hmac transaction signature
      (DNS TSIG) using [now ()] as timestamp, and the [keyname] and [key] for
      the cryptographic material. The [zone] is the one to be used in the
      query section of the update packet. If signing, sending, or receiving
      fails, the error is reported. *)
  val nsupdate : ?proto:Dns.proto -> int -> (unit -> Ptime.t) ->
    (Cstruct.t -> (unit, [ `Msg of string ]) result Lwt.t) ->
    ?recv:(unit -> (Cstruct.t, [ `Msg of string ]) result Lwt.t) ->
    zone:[ `host ] Domain_name.t ->
    keyname:'a Domain_name.t -> Dns.Dnskey.t -> solver

  (** [alpn_solver (fun domain ~alpn private_key certificate)] is a solver for
      tls-alpn-01 challenes. The provided function should return [Ok ()] once
      the TLS server at [domain] serves the self-signed [certificate] (with
      [private_key]) under the ALPN [alpn] ("acme-tls/1"). *)
  val alpn_solver :
    ([`host] Domain_name.t -> alpn:string -> X509.Private_key.t ->
     X509.Certificate.t -> (unit, [ `Msg of string ]) result Lwt.t) -> solver

  (** [print_alpn] outputs the ALPN challenge solution, and waits for user input
      before continuing with ACME. *)
  val print_alpn : solver

  module Make (Http : HTTP_client.S) : sig

    (** [initialise ~ctx ~endpoint ~email priv] constructs a [t] by
        looking up the directory and account of [priv] at [endpoint]. If no
        account is registered yet, a new account is created with contact
        information of [email]. The terms of service are agreed on. *)
    val initialise : ?ctx:Http.ctx -> endpoint:Uri.t -> ?email:string ->
      Mirage_crypto_pk.Rsa.priv -> (t, [> `Msg of string ]) result Lwt.t

    (** [sign_certificate ~ctx solver t sleep csr] orders a certificate for
        the names in the signing request [csr], and solves the requested
        challenges. *)
    val sign_certificate : ?ctx:Http.ctx ->
      solver -> t -> (int -> unit Lwt.t) ->
      X509.Signing_request.t ->
      (X509.Certificate.t list, [> `Msg of string ]) result Lwt.t
      (* TODO: use X509.Certificate.t * list *)
  end

end

(* a TODO list of stuff not implemented in respect to 8555:
   - incomplete orders (cancel the authorizations, get rid of orders)
     -> otherwise may hit rate limiting
   - deal with errors we can deal with
     -- connection failures / timeouts
     -- cohttp uses Lwt exceptions at times
   - make next_nonce immutable, and pass it through
   - SECURITY verify the TLS certificate provided by the server!
   - ES256 algorithm (only RS256 is there)
   - errors with "subproblems" (deal with them? decode them?)
   - "SHOULD user interaction" to accept terms of service
   - external account binding (data in json objects)
   - 7.3.2 account update
   - 7.3.3 changes of terms of service
   - 7.3.4 external binding
   - 7.3.5 account key rollover
   - 7.3.6 account deactivation
   - 7.4.1 pre-auth newAuth
   - 7.5 identifier authorization (+ 8) - WIP
     -> dns challenge: cleanup RRs once invalid / valid
   - 7.6 certificate revocation
*)
