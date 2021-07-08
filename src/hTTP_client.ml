module type S = sig
  type ctx
  (** Type of the user-defined {i context}.

      The context is an user-defined value which can be passed to your HTTP
      client implementation to be able to tweak some internal details about the
      underlying request/connection used to get an HTTP response.

      For instance, an HTTP implementation can optionally require some value
      such as the internal buffer size or a time-out value, etc. The interface
      wants to {b allow} the implementer to pass such information via the [ctx]
      type.

      In others words, anything optionnaly needed to initiate/do the HTTP
      request and that is not described over this interface (by arguments,
      types, etc.) can be passed via the user-defined [ctx] type.

      For instance, MirageOS uses this [ctx] as a ressource allocator to
      initiate a TCP/IP connection or a TLS connection - and, by this way,
      it fully abstracts the HTTP client implementation over the TCP/IP and
      the TLS stack (for more details, see [mimic]).

      Of course, [ctx = unit] if you don't need to pass extra-information when
      you want to do an HTTP request/connection. *)

  module Headers : sig
    type t
    (** The type of HTTP headers. *)

    val add : t -> string -> string -> t
    (** [add hdrs key value] adds a [key] and a [value] to an existing
        [hdrs] headers. *)

    val to_string : t -> string

    val get : t -> string -> string option
    (** [get hdrs key] retrieves a [key] from the given [hdrs] headers. If the
        header is one of the set of headers defined to have list values, then
        all of the values are concatenated into a single string separated by
        commas and returned. If it is a singleton header, then the first value
        is returned and no concatenation is performed. *)

    val get_location : t -> Uri.t option

    val init_with : string -> string -> t
    (** [init_with key value] constructs a fresh map of HTTP headers with a
        single key and value entry. *)
  end

  module Body : sig
    type t

    val of_string : string -> t
    val to_string : t -> string Lwt.t
  end

  module Response : sig
    type t

    val status : t -> int
    val headers : t -> Headers.t
  end

  val head :
    ?ctx:ctx -> ?headers:Headers.t -> Uri.t -> Response.t Lwt.t

  val get :
    ?ctx:ctx ->
    ?headers:Headers.t ->
    Uri.t ->
    (Response.t * Body.t) Lwt.t

  val post :
    ?ctx:ctx ->
    ?body:Body.t ->
    ?chunked:bool ->
    ?headers:Headers.t ->
    Uri.t ->
    (Response.t * Body.t) Lwt.t
end
