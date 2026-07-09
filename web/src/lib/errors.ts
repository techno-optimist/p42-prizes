// Domain-layer error for invalid client input. It carries a public HTTP
// contract (`publicStatus` / `publicMessage`) that apiError() surfaces, so a
// genuinely unexpected error — one WITHOUT this contract — is reported as a
// generic 500 instead of leaking its raw message as a client (4xx) error.
export class ClientError extends Error {
  readonly publicStatus: number;
  readonly publicMessage: string;

  constructor(message: string, status = 400) {
    super(message);
    this.name = "ClientError";
    this.publicStatus = status;
    this.publicMessage = message;
  }
}
