Return-Path: <kasan-dev+bncBC6OLHHDVUOBBXECTGKAMGQEFAGGXSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 59FA852D399
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 15:08:45 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id pj21-20020a170906d79500b006fea2020e78sf155002ejb.11
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 06:08:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652965725; cv=pass;
        d=google.com; s=arc-20160816;
        b=FXn/AJeJ57nwHk5CbLlb97bHy9UO9KgCZozq7cEsJZN/vZyicTvDA7BM3NH8GysFnh
         4vsH2XworwWjROflhvOvR6B8hXLSadlHNcLVWU5aa6MKcSrmqr3/Wob1RLBdO0F4ACyy
         6tj7fTaa5mdrTNxWDkiNEsqnA0a4ue1u2tQHnVyaqjkQGsEKmhU1qbzaRDxZcbqyCjeQ
         3eZz6kjvkhJErCL7tQLZsRAPd5Pj+UPDAJ4267TybPLdeZ1vbODx7m5ixw655/PBhX7n
         tGt0GdW6VpPOslBgpk/nNSjiD/wg3OM7Ua7CZS7wTVKInJtiUWED4zloLyf26sXKw5kJ
         wKLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=w+fQxUA7pqSGIWNKc1Y8s+QdZbA8BNmvZK7JnzkwsAU=;
        b=gb6GhFbb5fERPehZtEG6T75wbxAUvALt+hI5ERriqm6Hth0oyxytLSGQmB+wX68ath
         CbUTyWzpx1yy7lODP9aJMRWzD3EFotGKxzLQ/r+1hSFmpZxSU0aswMUmkSBXtdh31dvm
         mocyuMNmvGzDXQ97LcvPzRqu0zJZ8597xeJqrtFzjpwz+ZrYttqxGer5vm2a1pTr6+VK
         3Ma8WFf/SIvDwASpqgsDGW6pjrpDDihvgWhW7drp+kW5pTpgSkcRTe96DDDdyjbc5XHH
         yjhyAn763sIp0x4v6KSJHsWmzG9nGXYA1GOXGFXfSIOyy7dfABHLR60XC+muNbSdJGMM
         HF3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pA1R31td;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+fQxUA7pqSGIWNKc1Y8s+QdZbA8BNmvZK7JnzkwsAU=;
        b=oJ5+6XUHd1bUAT2soL3Tef+yGIobkJG/3fYogyEGqXYp5F9aVPpCvobWBXdayixxem
         MBMdYM3k8rtyTDPxnESvUmTcv9Gi7ZZ4Df3hJvZIq6RfBKQ9ULqjra8K5aJp3fSMjsJ9
         EQtOML+GEDH7oIWT89wKYyQO97Edz0WSRn8eYddmCMVLo97MNfMmhFqe44hVoSx4LEvx
         07FyRsk30eqewD3793S0AU4X8UrMpB/YzFHPwhpWq3Dlf8R4fdB+EQolth2TcE14EuJm
         KwtIusVR+IH2n8CLbAGR6OHL9KcFT1AIeQqwWmHZ5B2zVpPKjdFcTf+yFffP7Be9FRVB
         uJ2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+fQxUA7pqSGIWNKc1Y8s+QdZbA8BNmvZK7JnzkwsAU=;
        b=wHZA4Co3JxQCpGGebijf8IZqSl3CS8X0Py65RyrRiII1k1TH5O79MyWKwkopdSdIGb
         AHVs79RBmVF28ThriZLmM8HYDpEZZurXq6RaA4bmAVS1M99VCNVgcKYTYt69ma/zoMlC
         J0z73ZAsBDd+TIbWl7KLM+awOFW6UGDfcG5y8OOVuwWC9XZSFMHLf64ZlD6vDDfOXHNt
         dT1dLBJkmliSGc6t6PfNcYLkCut1px5/D/n9be9gMPpIZ4FIxloG8nHCH9UFI6KxOmDl
         8vui0fa5qtEI55A5Pqm9Vo1l3QxIF8TtX9CH+DAs/PaOHlRb02Ctn67d9Wilqc2hNjxo
         fd0Q==
X-Gm-Message-State: AOAM5306qMxGSU67NGb3/HtwaG0kltl7y1fL5fiLPz54xV/uWwYGc0q1
	CV9Tzz28Ie7sSCZroBd5GMk=
X-Google-Smtp-Source: ABdhPJy0yeblT5gyxFM0Gk86wCzxJ9/w70EIBwooPMpJFXqHkxODxC0FKL/xRcSPlUtr+/TMYo9hPA==
X-Received: by 2002:a05:6402:174c:b0:42a:b4df:3aa7 with SMTP id v12-20020a056402174c00b0042ab4df3aa7mr5186109edx.263.1652965724760;
        Thu, 19 May 2022 06:08:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7b8d:b0:6f4:951b:25a0 with SMTP id
 ne13-20020a1709077b8d00b006f4951b25a0ls1508877ejc.6.gmail; Thu, 19 May 2022
 06:08:43 -0700 (PDT)
X-Received: by 2002:a17:906:6bd5:b0:6fe:9f01:fb19 with SMTP id t21-20020a1709066bd500b006fe9f01fb19mr1537867ejs.154.1652965723458;
        Thu, 19 May 2022 06:08:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652965723; cv=none;
        d=google.com; s=arc-20160816;
        b=YiUVF0hWBZIE1x6HkT0TwbvyD9vaP4qrjS0YFmiZk4vMizKnZPIMlroK5RpWZg5RoW
         lDD+4/NJoQBT6T/4Af+fjLMT7aMh1CqlqurEUGaAdbrUwD1Q4ZrJrcIMDJjLGnZ+KpPI
         Kco4M915mYXSsvZD/T168GkhnzyHTUOTVuJJUfrLH/tmkEC6PMu2+H1KoHUFkEJBa0mW
         2H27mjqPSbDwVisjIia9BR76jRgyHpBFlEFSobhdgLz0u0FhoB+N6K4s8AYRrSqihDw9
         DFiaQQW+hGpa2TAJTbFrBrE+Ft7pnyOxIG9Wmix+q7UPjyjVfUQLcpWMJZxEXtcdOC0s
         KPYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IHX+Bk89NQJAxSU2RDMUyeDzqN8QP8tKpco2Gj52qHQ=;
        b=s2fPWIB2YUpcoF32LYd9hzLYXs2A2u1vfV5denbDb+mpmuzQbLQwn/qQ9cTNMoHYcQ
         1MhXdjDX/BrmkPjY8kl/c4pxa302qmtUrs7yYxw2j5xcVMUx1TkV40a4ZkMcqDj9nkgs
         n5vb8zxX2CfjzChHPOi4MiSfLT7QnWXThHdQ+Ri0MsrX5x2NLKdzyj/tZIEaWkqdBN03
         NHd9N+YWyJ7iCgXxda+JECv70OovK5skeb3G9wFREVgb1sRVhYCvAb2wRhATas8ooYIr
         Pbkuei3Eeerg9AxfyMvLqgWrxkHhUBWeaW8WHnx76fPrw6v9J49IblO9uWbQyjOZn2vL
         lpiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pA1R31td;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id d11-20020a50e40b000000b00425b0722545si354157edm.3.2022.05.19.06.08.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 May 2022 06:08:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id ay35so1257787wmb.5
        for <kasan-dev@googlegroups.com>; Thu, 19 May 2022 06:08:43 -0700 (PDT)
X-Received: by 2002:a05:600c:3512:b0:394:7c3b:53d1 with SMTP id
 h18-20020a05600c351200b003947c3b53d1mr4253775wmq.197.1652965722897; Thu, 19
 May 2022 06:08:42 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
 <YoS6rthXi9VRXpkg@elver.google.com>
In-Reply-To: <YoS6rthXi9VRXpkg@elver.google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 May 2022 21:08:31 +0800
Message-ID: <CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: Marco Elver <elver@google.com>
Cc: Brendan Higgins <brendanhiggins@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000c47bbc05df5d1272"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pA1R31td;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::332
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

--000000000000c47bbc05df5d1272
Content-Type: text/plain; charset="UTF-8"

On Wed, May 18, 2022 at 5:21 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, May 18, 2022 at 03:32PM +0800, David Gow wrote:
> > Add a .kunitconfig file, which provides a default, working config for
> > running the KCSAN tests. Note that it needs to run on an SMP machine, so
> > to run under kunit_tool, the x86_64-smp qemu-based setup should be used:
> > ./tools/testing/kunit/kunit.py run --arch=x86_64-smp --kunitconfig=kernel/kcsan
> >
> > Signed-off-by: David Gow <davidgow@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> Thanks for adding this.
>
> > ---
> >  kernel/kcsan/.kunitconfig | 20 ++++++++++++++++++++
> >  1 file changed, 20 insertions(+)
> >  create mode 100644 kernel/kcsan/.kunitconfig
> >
> > diff --git a/kernel/kcsan/.kunitconfig b/kernel/kcsan/.kunitconfig
> > new file mode 100644
> > index 000000000000..a8a815b1eb73
> > --- /dev/null
> > +++ b/kernel/kcsan/.kunitconfig
> > @@ -0,0 +1,20 @@
> > +# Note that the KCSAN tests need to run on an SMP setup.
> > +# Under kunit_tool, this can be done by using the x86_64-smp
> > +# qemu-based architecture:
> > +# ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan --arch=x86_64-smp
> > +
> > +CONFIG_KUNIT=y
> > +
> > +CONFIG_DEBUG_KERNEL=y
> > +
> > +CONFIG_KCSAN=y
> > +CONFIG_KCSAN_KUNIT_TEST=y
> > +
> > +# Needed for test_barrier_nothreads
> > +CONFIG_KCSAN_STRICT=y
> > +CONFIG_KCSAN_WEAK_MEMORY=y
>
> Note, KCSAN_STRICT implies KCSAN_WEAK_MEMORY.
>
> Also, a bunch of the test cases' outcomes depend on KCSAN's
> "strictness". I think to cover the various combinations would be too
> complex, but we can just settle on testing KCSAN_STRICT=y.

It's definitely possible to either have multiple .kunitconfigs, each
of which could have slightly different setups, e.g.:
- kernel/kcsan/.kunitconfig (defualt)
- kernel/kcsan/strict.kunitconfig (passed explicitly when desired)

Equally, if we got rid of KCSAN_STRICT in the .kunitconfig, you could
override it with --kconfig_add, e.g.
-  ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
--arch=x86_64-smp
- ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan
--arch=x86_64-smp --kconfig_add CONFIG_KSCAN_STRICT=y

> The end result is the same, but you could drop the
> CONFIG_KCSAN_WEAK_MEMORY=y line, and let the latest KCSAN_STRICT
> defaults decide (I don't expect them to change any time soon).
>
> If you want it to be more explicit, it's also fine leaving the
> CONFIG_KCSAN_WEAK_MEMORY=y line in.

Do you have a preference here? Or to get rid of both and default to
the non-strict version mentioned above?

>
> > +# This prevents the test from timing out on many setups. Feel free to remove
> > +# (or alter) this, in conjunction with setting a different test timeout with,
> > +# for example, the --timeout kunit_tool option.
> > +CONFIG_KCSAN_REPORT_ONCE_IN_MS=100
> > --
> > 2.36.0.550.gb090851708-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ%40mail.gmail.com.

--000000000000c47bbc05df5d1272
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
MDIwAhABQeVybOOpR4bOOXZYL5T3MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCBg
3kxCA+bJ6Pr4EBE/BjEv2DIDDLIxlJZejM8ULg1uHjAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA1MTkxMzA4NDNaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAOcrOtFS8EmyO69KlOQpt
k5aC+qmT0fDIITppu2U+rbI3kDeLODV6pF1NossdT5AWE0cDI+F9vcog6dhUSGfLGYhydyk47q5x
nS4t4r/49lv3eTp2hQbGW1p8WiqALEteCTrGV61BZXkCF/Pc3U6aslyGmUVIHNWSqsX8tT4LohCO
9FHFyUVsoHdUuQ4JHD0sSqCbrhrQJDIlWwAL+AtNgtNJal0NJdMZSap7dmYwNhm3SJSQh3TcHPO9
eff8cNgbWO3zB5kLz9dk58r0G1evCmFl8bfEMcpQqZnD+6z4zDrCUDDdfItb/ZkKEKXvPxod2HdZ
l2y22awXtQfHaW9imA==
--000000000000c47bbc05df5d1272--
