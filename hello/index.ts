import { AzureFunction, Context, HttpRequest } from "@azure/functions"
import { authDigest } from '../lib/auth-digest';
import { authorizeClientCertificate } from '../lib/validate-certificate';

const httpTrigger: AzureFunction = async function (context: Context, req: HttpRequest): Promise<void> {
  try {
    await authorizeClientCertificate(req.headers, context);
    authDigest(req.headers);

    context.res = {
      body: { ok: true },
    };
  } catch (err) {
    context.log(err)
    context.res = {
      status: err.code,
      body: err.message,
    };
  }


};

export default httpTrigger;