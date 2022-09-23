# Http_sig - Http Signature Signing Scheme for OCaml

This library implements the [Http_sig
RFC](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12)
(or a subset therein).

## Examples
 
- For validating incoming requests:
```ocaml
let resolve_public_key url =
  let+ (_, body) = activity_req (Uri.of_string url) in
  let+ pub_key = Cohttp_lwt.Body.to_string body in
  let pub_key =
    pub_key
    |> Cstruct.of_string
    |> X509.Public_key.decode_pem
    |> Result.map_err (fun (`Msg err) -> err) in
  Lwt.return pub_key


let handle_post req =
  let+ valid_request =
    Http_sig.verify_request
      ~resolve_public_key req in
  if not valid 
  then Dream.respond ~status:`Bad_Request ""
  else Dream.respond "OK"
```

- For sending requests:
```ocaml
let req_post ~headers url body =
  let body = Cohttp_lwt.Body.of_string body in
  try
    Cohttp_lwt_unix.Client.post
      ~headers
      ~body
      url >> Result.return
  with exn ->
    Lwt.return (Result.of_exn exn)

let signed_post ~headers (key_id, priv_key) uri body_str =
  let current_time = Ptime_clock.now () in
  let headers =
    Http_sig.build_signed_headers
      ~current_time ~method_:"POST" ~body_str
      ~headers ~key_id ~priv_key ~uri
    |> Cohttp.Header.of_list in
  req_post ~headers uri body_str
```
