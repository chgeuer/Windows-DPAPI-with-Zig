defmodule DPAPI do
  use Rustler, otp_app: :rust_playground, crate: "dpapi"

  # When your NIF is loaded, it will override this function.
  def wrap(_cleartext_bytes), do: :erlang.nif_error(:nif_not_loaded)

  def unwrap(_ciphertext_bytes), do: :erlang.nif_error(:nif_not_loaded)
end
