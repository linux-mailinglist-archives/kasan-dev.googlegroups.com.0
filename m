Return-Path: <kasan-dev+bncBC6OLHHDVUOBBEMITGKAMGQE2HU34LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 151EB52D3C5
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 15:20:18 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id k15-20020a192d0f000000b004743fcaf464sf2658989lfj.17
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 06:20:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652966417; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xj5m5kZYYTRI4IBy9UcS9efJqIKNo/332LFlY2EqezeUSmIdsMq5Vs9g6URm2t9/RL
         my6igZI/HA0q74ZxLOl8SnM0KyZ+W7hjYsZu1hmCSILByds+Ael59hSZ/T/tsrnx/zTl
         51kcf0ehIvly0UVT0mDsghcD2NYh966gmDTzVIfRarlUNU2jPudiY510ULu1nNQ2kOz3
         UWtOBml73njRhX5gupLOOiZ8y7xMIv5Iz95RXUDBeqpyaCib5jfpHud7KUYQIWOc9+RW
         rAA3b7NneD74GQqKwm4L4nHslRIoYdMrCzchC1sX4E9BYMQOO//CV4aW38jIl8hi0c5M
         q5uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wY8ks1WXvNvoYieTRYPV0bLn1jthZlzGbU/CYF84tNY=;
        b=WOcltze2zDuQp+p6lYnvfW9i2rdEW39hTzm7XI0tul3OxbbV+Mwv1RxuMHXM6Iaqzh
         PRLSk79KgNbKlit1AuPxofKHLLuU6po0IMs56O2NoyOGlmoEqOpyechju2v8bDoo9pHt
         eZO5yErqlH0R0nQziRfmF4VyB+VG2YfQZPsF9C8L2P5COexELWhn5EU00vSy6WEZsFHU
         vawstDenQr+zkfeZPtItuQ1C0gGD1UOctn3XPqVK+f/KzH8IHcj0HuS2m0uNBYBZqw2d
         CLuDuVgXBRh2wu+Mc4qGn8/sYXYjI8ut+KEIDHL5+WGN8OQFzixozFzGXq7K0UbzSgV9
         kY0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bq6rWevK;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wY8ks1WXvNvoYieTRYPV0bLn1jthZlzGbU/CYF84tNY=;
        b=YsPYl1KhFUAcVN2S2lsk9GCYPBej1u4ikkW4ZcSg2RUvYVCQZXDUZm5r+JNvsA3DNR
         1G/aMLdV6FW/H7YkXPMi1+EIOHlBgkM8+DXWTkaxn1SJjWgjgnBssAPIc5UxifMfY/eY
         tDdyrxYTFSngRS3H5jfFFGR6k5q9CbwmDadNdO2xvTV7SMYlJrPNiZQSc/3To6rxqiQC
         Bd52Gr0Koj8zf7MOVx8pLFrLfvHMapeFUQZQpfqiy0oxLHzdG8GwUbktxVCPSukGvaWR
         Dh3vjJe1pZLCbQLHF8k3iZMJqdnSyGgt0k3KUR3lsMbx75v6LvHcDw0u6w3ieXws4oc7
         styg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wY8ks1WXvNvoYieTRYPV0bLn1jthZlzGbU/CYF84tNY=;
        b=sZFUkqyh1Fy4PasfMsOeOBLn2N2BxPDYGHXpSqqHkISQxzItU2ym0mTqktF6DRPS1g
         ou5vNlmPP4AvekZw5eSasRA590XDv0IIfSDzloEjoh49dkVNy456BxNg9D/Dwaz4sy3a
         5rThWHf9PWGN8sjCoSiZd7XJAzXguqAmBPY+2/CCLqjj7m6U10vvyzda5K5TnFLN1/NG
         88k8IvPUxBlpv/Z1qmgjiiJmmLtohYsdQoubVn836T+GXVH9OcpI5rcUCxJPkezzKiq+
         LwEGgkshz07RTzVmFDOk6ku7NazII/IMvMnKoWDK/3ShM/AQc5vxVfXeJ+oClw9s9Une
         RyBg==
X-Gm-Message-State: AOAM533dW4Ys+nsewTPfTVGHZR2y3EK/oIlHuBwpCyGUbyJ3IP3pDrjO
	giitL3UPUHqhYNfj8AoKYxs=
X-Google-Smtp-Source: ABdhPJyju5LkbGbCUzlAIqEcick+JgqG+2SGo2dwGcz+Ql741JaXYSokgHmXs/mj9lZI55jdneWuCQ==
X-Received: by 2002:a05:6512:2607:b0:477:96ea:d387 with SMTP id bt7-20020a056512260700b0047796ead387mr3466975lfb.79.1652966417316;
        Thu, 19 May 2022 06:20:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:210e:b0:250:5bd1:6dab with SMTP id
 a14-20020a05651c210e00b002505bd16dabls509662ljq.6.gmail; Thu, 19 May 2022
 06:20:15 -0700 (PDT)
X-Received: by 2002:a2e:885a:0:b0:253:cd9d:9a78 with SMTP id z26-20020a2e885a000000b00253cd9d9a78mr2746677ljj.186.1652966415784;
        Thu, 19 May 2022 06:20:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652966415; cv=none;
        d=google.com; s=arc-20160816;
        b=skGJwiIMh8FbMVsg23pmgofM1e9XXSQrF8hRoPnh3OEOD1zfoyTu8GQm2vjsJiXgmS
         f5DaBs51HaG7987jLjHWgkzqsdSuNk4x5B/FhWKab0WhzsXP//VpTL6ZmIGjN1JafhT7
         dZ9uGutqu/V57t2ZkTqC0wbcDL/7tjydBy31h2U0UDXCeNGb0TnRUqX+S7JiewXCZ/0H
         Jj/0jhIqHA7pt+iajE/VJl8uxqW8LpNpF4NauVMVC7X2VIPLymMK8fusyDNQTpniwNEn
         OQxDtOKQc4TMAlkRItatLkcj7hlVv+Es3OjQYHM5P/StHPRlkx5qkSNJIsd/WIsP+f1U
         SsHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R3VSqVVhWPxWKga+7qn+Fyy7FUIxPT1uyCPS1Lnr7bI=;
        b=SjkefcMDpt1fClM3t3p2z1oT1kojLNg/OdEjH02nyaWGqy7QFn1FbmvIdItp+PLSis
         uEA7czNBTlJxUZb7NN7lT9py9d57eCbCc3T5s0yXP5AjomRQdcGqoea8RI2KySFeoHo6
         Q98DfRdkzm+4hUAbe7mbSuD/zvKJfcKA+ARkmdK7EzXHdZA0GeLVCHkHUiqJqKsx8q4D
         3QOTRnom59OBnqC1/G5SVl4ON9AWUemtJKTFZ4bzdxom77umIyiUyLCE8btrzwpTTflf
         XTDHGNq13GLwMitJAMC7SA3f/3mUS1M0f60CPKFxQhNWNLSbPNn6YGOl87H8Fvylrb7K
         xFdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bq6rWevK;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id be31-20020a05651c171f00b0024eee872899si304583ljb.0.2022.05.19.06.20.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 May 2022 06:20:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id u27so6323567wru.8
        for <kasan-dev@googlegroups.com>; Thu, 19 May 2022 06:20:15 -0700 (PDT)
X-Received: by 2002:a05:6000:1549:b0:20c:7183:439 with SMTP id
 9-20020a056000154900b0020c71830439mr4086990wry.104.1652966415239; Thu, 19 May
 2022 06:20:15 -0700 (PDT)
MIME-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com> <20220518170124.2849497-2-dlatypov@google.com>
In-Reply-To: <20220518170124.2849497-2-dlatypov@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 May 2022 21:20:03 +0800
Message-ID: <CABVgOSnsZU1jnVbPuredPkDcxbJnq+1ojDU300yXV7jApj0=XQ@mail.gmail.com>
Subject: Re: [PATCH 1/3] Documentation: kunit: fix example run_kunit func to
 allow spaces in args
To: Daniel Latypov <dlatypov@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Marco Elver <elver@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Shuah Khan <skhan@linuxfoundation.org>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="00000000000008aa3305df5d3c1f"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bq6rWevK;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42f
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

--00000000000008aa3305df5d3c1f
Content-Type: text/plain; charset="UTF-8"

On Thu, May 19, 2022 at 1:01 AM Daniel Latypov <dlatypov@google.com> wrote:
>
> Without the quoting, the example will mess up invocations like
> $ run_kunit "Something with spaces"
>
> Note: this example isn't valid, but if ever a usecase arises where a
> flag argument might have spaces in it, it'll break.
>
> Signed-off-by: Daniel Latypov <dlatypov@google.com>
> ---

Looks correct to me, though I'm not a bash _expert_.

Reviewed-by: David Gow <davidgow@google.com>


-- David

>  Documentation/dev-tools/kunit/running_tips.rst | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kunit/running_tips.rst b/Documentation/dev-tools/kunit/running_tips.rst
> index c36f6760087d..da8677c32aee 100644
> --- a/Documentation/dev-tools/kunit/running_tips.rst
> +++ b/Documentation/dev-tools/kunit/running_tips.rst
> @@ -15,7 +15,7 @@ It can be handy to create a bash function like:
>  .. code-block:: bash
>
>         function run_kunit() {
> -         ( cd "$(git rev-parse --show-toplevel)" && ./tools/testing/kunit/kunit.py run $@ )
> +         ( cd "$(git rev-parse --show-toplevel)" && ./tools/testing/kunit/kunit.py run "$@" )
>         }
>
>  .. note::
> --
> 2.36.1.124.g0e6072fb45-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnsZU1jnVbPuredPkDcxbJnq%2B1ojDU300yXV7jApj0%3DXQ%40mail.gmail.com.

--00000000000008aa3305df5d3c1f
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIPnwYJKoZIhvcNAQcCoIIPkDCCD4wCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ggz5MIIEtjCCA56gAwIBAgIQeAMYYHb81ngUVR0WyMTzqzANBgkqhkiG9w0BAQsFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMDA3MjgwMDAwMDBaFw0yOTAzMTgwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFIzIFNNSU1FIENBIDIwMjAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvLe9xPU9W
dpiHLAvX7kFnaFZPuJLey7LYaMO8P/xSngB9IN73mVc7YiLov12Fekdtn5kL8PjmDBEvTYmWsuQS
6VBo3vdlqqXZ0M9eMkjcKqijrmDRleudEoPDzTumwQ18VB/3I+vbN039HIaRQ5x+NHGiPHVfk6Rx
c6KAbYceyeqqfuJEcq23vhTdium/Bf5hHqYUhuJwnBQ+dAUcFndUKMJrth6lHeoifkbw2bv81zxJ
I9cvIy516+oUekqiSFGfzAqByv41OrgLV4fLGCDH3yRh1tj7EtV3l2TngqtrDLUs5R+sWIItPa/4
AJXB1Q3nGNl2tNjVpcSn0uJ7aFPbAgMBAAGjggGKMIIBhjAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0l
BBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFHzM
CmjXouseLHIb0c1dlW+N+/JjMB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHsGCCsG
AQUFBwEBBG8wbTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3Ry
MzA7BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvcm9vdC1y
My5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXIz
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
G7p3AiuB2sgfq6cOpbO5MEwGA1UdIARFMEMwQQYJKwYBBAGgMgEoMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZoGCCsG
AQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
c2F0bGFzcjNzbWltZWNhMjAyMDBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
LmNvbS9jYWNlcnQvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3J0MB8GA1UdIwQYMBaAFHzMCmjXouse
LHIb0c1dlW+N+/JjMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Y2EvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQBsL34EJkCtu9Nu
2+R6l1Qzno5Gl+N2Cm6/YLujukDGYa1JW27txXiilR9dGP7yl60HYyG2Exd5i6fiLDlaNEw0SqzE
dw9ZSIak3Qvm2UybR8zcnB0deCUiwahqh7ZncEPlhnPpB08ETEUtwBEqCEnndNEkIN67yz4kniCZ
jZstNF/BUnI3864fATiXSbnNqBwlJS3YkoaCTpbI9qNTrf5VIvnbryT69xJ6f25yfmxrXNJJe5OG
ncB34Cwnb7xQyk+uRLZ465yUBkbjk9pC/yamL0O7SOGYUclrQl2c5zzGuVBD84YcQGDOK6gSPj6w
QuBfOooZPOyZZZ8AMih7J980MYICajCCAmYCAQEwaDBUMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAxMhR2xvYmFsU2lnbiBBdGxhcyBSMyBTTUlNRSBDQSAy
MDIwAhABQeVybOOpR4bOOXZYL5T3MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCDk
5uI6beIgArWk6wkAKW7hyYSzj6AiewLNB4QlrmrnODAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA1MTkxMzIwMTVaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAnioYNKDDIjk1oTk2pDX7
3DxVzPNutS0xlaB4q6ONc1OdsgioN5ZeCftDuDJ02htT9xdQyT9xcrlavyR4CoQAeu+HxzXJF6NG
BqX72wrTPnHWwWbL1NJSp1gXsfDjiPiTiUbVIhv72jX6EdhuQvQ+XNsjk249WvzZEbwDsoCBCigI
f379X3aEHxhikmV+ToSi1d2Ob3L64lhPezH47/zcHNpF/72ub8Ppn9uJKorWjz78CA7LRH5CZJ8o
8ztaQjpdeRbwFlQzswmBMSC+bLnyrEYtZW5bUR1XE/NTcSyTu1k4ulyLLollOYmT5HWCUkqbFqYe
whEmN/WkT1oVi6a82Q==
--00000000000008aa3305df5d3c1f--
