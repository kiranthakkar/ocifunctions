import io
import json
from fdk import response
import logging

def handler(ctx, data: io.BytesIO=None):
    logging.getLogger().info("Inside view Request function")
    
    return response.Response(
        ctx, response_data=json.dumps(
            {"ctx.Config" : dict(ctx.Config()),
            "ctx.Headers" : ctx.Headers(),
            "ctx.AppID" : ctx.AppID(),
            "ctx.FnID" : ctx.FnID(),
            "ctx.CallID" : ctx.CallID(),
            "ctx.Format" : ctx.Format(),
            "ctx.Deadline" : ctx.Deadline(),
            "ctx.RequestURL": ctx.RequestURL(),
            "ctx.Method": ctx.Method()},
            sort_keys=True, indent=4),
        headers={"Content-Type": "application/json"}
    )