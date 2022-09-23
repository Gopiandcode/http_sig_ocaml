(**************************************************************************)
(*                                                                        *)
(*                              Http_sig                                  *)
(*                                                                        *)
(*                          Kiran Gopinathan                              *)
(*                                                                        *)
(*                   Copyright 2022 Kiran Gopinathan                      *)
(*                                                                        *)
(*                                                                        *)
(*   All rights reserved.  This file is distributed under the terms of    *)
(*   the GNU Lesser General Public License version 3.0, with the          *)
(*   special exception on linking described in the file LICENSE.          *)
(*                                                                        *)
(**************************************************************************)
open Containers

(** This package provides an implementation of the HTTP Signature
   scheme (https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12),
   and provides endpoints to use them with [Dream] and [Cohttp] for verifying and signing requests
*)

module StringMap : module type of Map.Make (String)

(** [verify ~signed_string ~signature key] returns true iff
   [signature] over [signed_string] is valid according to [key]. *)
val verify: signed_string:string -> signature:string -> X509.Public_key.t -> bool

(** [verify_request ~resolve_public_key req] verifies that a dream
   request has been signed according to the HTTP signature scheme *)
val verify_request:
  resolve_public_key:(string -> (X509.Public_key.t, 'a) Lwt_result.t) ->
  Dream.request -> (bool, 'a) result Lwt.t


(** [build_signed_headers ~priv_key ~key_id ~headers ~body_str
   ~current_time ~method_ ~uri] returns a list of signed headers using
   [priv_key] according to the HTTP signature scheme. [key_id] should
   be a string that can be used to look up the public key associated
   with [priv_key]. *)
val build_signed_headers:
  priv_key:X509.Private_key.t ->
  key_id:string ->
  headers:string StringMap.t ->
  body_str:string ->
  current_time:Ptime.t -> method_:string -> uri:Uri.t -> (string * string) list

(** [sign_headers ~priv_key ~key_id ~body ~headers ~uri ~method_]
   constructs a signed Cohttp header from the supplied parameters in
   accordance with the Http signature scheme.  *)
val sign_headers:
  priv_key:X509.Private_key.t ->
  key_id:string ->
  body:Cohttp_lwt.Body.t ->
  headers:Cohttp.Header.t ->
  uri:Uri.t -> method_:Cohttp.Code.meth ->
  Cohttp.Header.t Lwt.t
