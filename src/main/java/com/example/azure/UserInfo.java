package com.example.azure;

import com.sun.identity.shared.debug.Debug;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class UserInfo {
    private final static String DEBUG_FILE = "ActiveDirectory";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    protected String access_token;
    protected String user_guid;

    // we'll start by getting a short lived access token, since it'll be needed later when we getStatus on the device's compliancy
    public UserInfo(String server, String scope, String usr, String pwd, String client_id, String client_secret) { // only setting vals n via the constructor to make scratch testing as 'real' as possible
        this.access_token = getToken(server, scope, usr, pwd, client_id, client_secret);
    }

    public String getGuid (String msUserUrl, String user_email) { // we'll query the MS Graph at this endpoint and get back a compliance state
        String guid = "";
        URL url = null;
        HttpGet http_get = null;
        try {
            HttpClient httpclient = HttpClients.createDefault();
            http_get = new HttpGet(msUserUrl + user_email);
            http_get.setHeader("Authorization", this.access_token); // latter was retrieved on class instantiation
            HttpResponse response = httpclient.execute(http_get);
            HttpEntity responseEntity = response.getEntity();
            if (responseEntity != null) {
                String entity_str = EntityUtils.toString(responseEntity);
                guid = stripNoise(entity_str, "id");
                //log("  userInfo. getGuid: " + guid);

                if (guid != "") {
                    return guid;
                }
            } else {
                guid = "connection error";
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return guid;
    }

    public String getStatus (String risk_url, String user_url, String user_email) { // we'll query the MS Graph at this endpoint and get back a compliance state
        String guid = getGuid(user_url, user_email); // get guid from email passed in, and with that check if it is compromised
        if (guid == "unknown") {
            return guid;
        } else {
            return getRisk(risk_url, guid);
        }
    }

    public String getRisk (String risk_url, String user_guid) { // we'll query the MS Graph at this endpoint and get back a compliance state
        String risk_status = "";
        URL url = null;
        HttpGet http_get = null;
        try {
            HttpClient httpclient = HttpClients.createDefault();
            http_get = new HttpGet(risk_url + user_guid);
            http_get.setHeader("Authorization", this.access_token); // latter was retrieved on class instantiation
            HttpResponse response = httpclient.execute(http_get);
            HttpEntity responseEntity = response.getEntity();
            if (responseEntity != null) {
                String entity_str = EntityUtils.toString(responseEntity);
                risk_status = stripNoise(entity_str, "riskLevel");
                //log("  userInfo. getStatus for user: " + user_guid + risk_status);

                if (risk_status != "") {
                    return risk_status;
                }
            } else {
                risk_status = "connection error";
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return risk_status;
    }

    public String getToken(String token_url, String scope, String usr, String pwd, String client_id, String client_secret) { //
        HttpPost http_post = null;
        String cook = "";
        try {
            HttpClient httpclient = HttpClients.createDefault();
            http_post = new HttpPost(token_url);
            http_post.setHeader("Accept", "application/json");
            http_post.setHeader("Accept", "*/*");
            http_post.setHeader("Cache-Control", "no-cache");
            http_post.setHeader("Host", "login.microsoftonline.com");
            http_post.setHeader("Content-Type", "application/x-www-form-urlencoded");
            http_post.setHeader("Connection", "keep-alive");

            List<NameValuePair> params = new ArrayList<NameValuePair>();
            params.add(new BasicNameValuePair("scope", scope));
            params.add(new BasicNameValuePair("username", usr));
            params.add(new BasicNameValuePair("password", pwd));
            params.add(new BasicNameValuePair("client_id", client_id));
            params.add(new BasicNameValuePair("client_secret", client_secret));

            params.add(new BasicNameValuePair("grant_type", "password"));
            params.add(new BasicNameValuePair("Content-Type", "application/x-www-form-urlencoded"));

            http_post.setEntity(new UrlEncodedFormEntity(params));
            HttpResponse response = httpclient.execute(http_post);
            HttpEntity responseEntity = response.getEntity();

            if (responseEntity != null) {
                cook = stripNoise(EntityUtils.toString(responseEntity), "access_token");
            }

        } catch (Exception e) {
            log(" getToken.error: " + e.toString());
        } finally {
            return cook;
        }
    }

    private String stripQuote(String val) {
        return (val.replace("\"", ""));
    }

    private static String stripNoise(String parent, String child) {
        String noise = "unknown";
        try {
            JSONObject jobj = new JSONObject(parent);
            Object idtkn = jobj.getString(child);
            noise = idtkn.toString();
            if (noise.startsWith("[")) { // get only 'value' from "["value"]"
                noise = noise.substring(1, noise.length() - 1);
            }
            if (noise.startsWith("\"")) {
                noise = noise.substring(1, noise.length() - 1);
            }
        } catch (JSONException e) {
            //e.printStackTrace();
        } finally {
            return noise;
        }
    }


    public void log(String str) {
        //System.out.println("+++  userInfo:   " + str);
        debug.error("+++  userInfo:    " + str); //rj? should be 'message' instead?
    }
}