defmodule DPAPI do
  use Rustler, otp_app: :dpapi, crate: "dpapi"

  def wrap(_cleartext_bytes), do: :erlang.nif_error(:nif_not_loaded)

  def unwrap(_ciphertext_bytes), do: :erlang.nif_error(:nif_not_loaded)
end
