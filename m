Return-Path: <kasan-dev+bncBC6OLHHDVUOBB2FEYCNAMGQEZABEDFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6262F604A85
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 17:06:17 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-358c893992csf170884567b3.9
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 08:06:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666191976; cv=pass;
        d=google.com; s=arc-20160816;
        b=hnHHfK75jLedaUxYnLg8LJvcJ92F+M583pkyjXTLn9uh5MSfL3NhSERK7Ruv1LlVnm
         LhPGgJgbLPq2PBvFkmC41TcHZyGry+4Lyjmlv+qW51LPeJb1RanscRr6XszeWTmWaEVs
         kM7o/XuglLxu9mAcGzdAlzO1ACnhtX1wUSyWxSI0Q5aSzZo9wqKB0fCp6+WYlWOH5M6k
         a4FP9o1nd7jZAvgxbnW3gp/1cCOus5ii5qTIDw+sQL9Q2DUDYu0HDPJHjW0LvPNoGYU7
         kJSzLQTreXok9y6ncncYfuTMfOz+3KQmUjSI3ea+vTzEQ25BWoNFTFEIWEfMMvrk053Z
         Dkcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1i9uGLiYRBBIAs5M2KlpBgz5l8BL1WkBxoB//kMW1bE=;
        b=D0fTnUoN5d45c7FT7o6GYoq9maxMbcjjQWKwRAi8tpypsBnLC0eF/Egw1zEAx73xBE
         NDaEa0R/tevx3DOfSPyynQziFAWpFHAolXZoPGxFKUjNguqY8B00Ovrp+Tca0lplTBkp
         MOlKyDveopQMpwRXPxTpGhDTdS1+pGyNy7AN74pMYZ/frDg/vNqpl82NQY850/mztaWC
         iOCn6Ie/UbSAV9c1VH5ido4MdugnsuOD1GakevroKJddlIxSmohi25Zk+XQ0RCvqJVl9
         5qvfdvk5090t6CpBurOOdSafV18eOq8JtFrtUIFv5mUMI5hH/6109ASjfbYpB+iKrMWh
         dbeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iFRfKfLA;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1i9uGLiYRBBIAs5M2KlpBgz5l8BL1WkBxoB//kMW1bE=;
        b=nkGNTvuqhiKt53CD7WN8/YUDNBK2H86RNTWQ66VMISaA5nyX635CMe+FmkonbzOUjY
         qp6WRNZgC4GWnjN4bVC3UDdGzgLDFe6e3F6UsQM4+xav7tu/Q0haQZG4Cr1BhGz4uLfl
         CbRZmVR+BHOpk7NWRyCigSHvqblM65LS7UFxySHqM8c5Di3X2WKyqDI7WEuBCxmYROaK
         Pn74mTstlr8osHJgHcAwvNEbLVsAvlFXAZemZFh/cAQiGHsbszdOB3+oKyDzZ77KJ0O7
         Rs00Z6X0MHMGXDWigbGHDsVkHOi53rKM24cChBINt6s4yGG4W6F26f9kXmrO+dEHVJIo
         ZxCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1i9uGLiYRBBIAs5M2KlpBgz5l8BL1WkBxoB//kMW1bE=;
        b=PgU/ZxLMuKemirsTU/aolR7Km55vTm/pJY81kgD89HMkqFR47z5ulvOTlL4HXKr0bW
         1n0THZl2xDikEBQ/CHVETUt4jR98od97figEJADHXZOkMzmnqsSwe0Ixirllu8+RcZ5s
         X/t9BJN8kpmECpV9JObUZfb26yB7QhYBc6ZQ1lg9UNJm7d15KorBAtAhtph6d/U7dMgc
         bAjogQzEtnUtR9reb/+/cWHnWxwYBF8IT/0IcX/F54x82hfqqKA9DlmuaxxzkofDzKNw
         5CyxOpHyuls6ZHZcIWnqqjQR/kT6/fy+u8BMDs1CeEDzsGfjGcD92bcQz80o/gop3IDD
         jnnw==
X-Gm-Message-State: ACrzQf266jcaDur5pO9RhFkEAwvq82oT4SMXpjEeH5etXvGiGeBD0mmC
	oXIKTwRvxgbtHWfdLQrXHSE=
X-Google-Smtp-Source: AMsMyM5yRZrF+VTLmiumQceRsU21ehes/5WZsB5+Bf99i0JXGic0DrblbGD8IlzH7kzlcANY1Kz0CQ==
X-Received: by 2002:a25:7e84:0:b0:6ae:c1d6:4346 with SMTP id z126-20020a257e84000000b006aec1d64346mr7026018ybc.575.1666191976139;
        Wed, 19 Oct 2022 08:06:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b084:0:b0:6c5:5d52:73e7 with SMTP id f4-20020a25b084000000b006c55d5273e7ls2386830ybj.3.-pod-prod-gmail;
 Wed, 19 Oct 2022 08:06:15 -0700 (PDT)
X-Received: by 2002:a25:6c3:0:b0:6b0:4336:9d81 with SMTP id 186-20020a2506c3000000b006b043369d81mr7366425ybg.119.1666191975516;
        Wed, 19 Oct 2022 08:06:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666191975; cv=none;
        d=google.com; s=arc-20160816;
        b=nxl4UtmN4i6HVePryZo7b2L0Q4WW0kCXtoXvWHvqAmWzxXLyrLo+14soxxSsQpKQxy
         WvmjqZKwBWhF+Hxp4VM8GT/LYFbSNDfJP9gYSfO3ZmJ9JP4X+XpIoqC2ZyvWTfhKLRFR
         z10Jh/8aLhNJfua1FX8n9CEbSHzMAeWEdlblupgwIwVfNlDMkB6y+dLR6CzkkdXneZun
         zOTKNyHarSHaPObF6I2X5bTLj30HZ0VwIu/em5CjX/FLtK2IcZ+jO6vqlOsy5RExxEy0
         JscM0i9hvn6DrkNYTunK0SXacigZwZOJK5NfkhBchR7dWCTiOC5bUAAze9O7GMddniC5
         +P8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K3IqyyYMTNhFLxzh3672XqjDeuMZIdvfoNwz7Uuc5/I=;
        b=ZmcAxngmiSlXadNxZnIEG3HHAUD0RL3zPo2qzhwb9SbEeZFDop+lBKjgUVQeF8EC+e
         tjmED9zDkJd6cbaqwK7j6X49pNvQeJY6Lk526Wu3R4IiUrRodJaNWwHzEh38RDwFIrzD
         ykJEUO18O/BeOlWuA2/Ui0dYIgt9LmlyH+5dbK+HeyN7EBkEooFQFG7SpuIrFiuLHNxG
         xy83b9vowVzskf5jwM7mKG0ottERd8lFW8JQO9EqMrtT2E8DYEgI0sEH4haGR1n7gbwD
         PdcD8O4THxZE/NUcqeC2MRdrccAO+D/5WfuD9guqpfP3ZlTNqoGG8QntUM0KmAHdVbvl
         EnkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iFRfKfLA;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::935 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x935.google.com (mail-ua1-x935.google.com. [2607:f8b0:4864:20::935])
        by gmr-mx.google.com with ESMTPS id s68-20020a818247000000b00350b92acf33si1505284ywf.4.2022.10.19.08.06.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 08:06:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::935 as permitted sender) client-ip=2607:f8b0:4864:20::935;
Received: by mail-ua1-x935.google.com with SMTP id x20so7378400ual.6
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 08:06:15 -0700 (PDT)
X-Received: by 2002:ab0:7412:0:b0:3d1:c2f7:3250 with SMTP id
 r18-20020ab07412000000b003d1c2f73250mr4374614uap.21.1666191975065; Wed, 19
 Oct 2022 08:06:15 -0700 (PDT)
MIME-Version: 1.0
References: <20221019085747.3810920-1-davidgow@google.com> <CA+fCnZdPwjThjY7fd7vBkMzS1eFXySR2AKrDK8weJ3p25fzS3g@mail.gmail.com>
In-Reply-To: <CA+fCnZdPwjThjY7fd7vBkMzS1eFXySR2AKrDK8weJ3p25fzS3g@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Oct 2022 23:06:03 +0800
Message-ID: <CABVgOSmP1A4d_-SNrWg7VruxpKj3SZz=Bzb2Xebd=EXw1imXyA@mail.gmail.com>
Subject: Re: [PATCH] kasan: Enable KUnit integration whenever CONFIG_KUNIT is enabled
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000d2339805eb648c5e"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iFRfKfLA;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::935
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

--000000000000d2339805eb648c5e
Content-Type: text/plain; charset="UTF-8"

On Wed, Oct 19, 2022 at 10:18 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Wed, Oct 19, 2022 at 10:58 AM 'David Gow' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Enable the KASAN/KUnit integration even when the KASAN tests are
> > disabled, as it's useful for testing other things under KASAN.
> > Essentially, this reverts commit 49d9977ac909 ("kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT").
> >
> > To mitigate the performance impact slightly, add a likely() to the check
> > for a currently running test.
> >
> > There's more we can do for performance if/when it becomes more of a
> > problem, such as only enabling the "expect a KASAN failure" support wif
> > the KASAN tests are enabled, or putting the whole thing behind a "kunit
> > tests are running" static branch (which I do plan to do eventually).
> >
> > Fixes: 49d9977ac909 ("kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT")
> > Signed-off-by: David Gow <davidgow@google.com>
> > ---
> >
> > Basically, hiding the KASAN/KUnit integration broke being able to just
> > pass --kconfig_add CONFIG_KASAN=y to kunit_tool to enable KASAN
> > integration. We didn't notice this, because usually
> > CONFIG_KUNIT_ALL_TESTS is enabled, which in turn enables
> > CONFIG_KASAN_KUNIT_TEST. However, using a separate .kunitconfig might
> > result in failures being missed.
> >
> > Take, for example:
> > ./tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=y \
> >         --kunitconfig drivers/gpu/drm/tests
> >
> > This should run the drm tests with KASAN enabled, but even if there's a
> > KASAN failure (such as the one fixed by [1]), kunit_tool will report
> > success.
>
> Hi David,
>
> How does KUnit detect a KASAN failure for other tests than the KASAN
> ones? I thought this was only implemented for KASAN tests. At least, I
> don't see any code querying kunit_kasan_status outside of KASAN tests.

Yeah, there aren't any other tests which set up a "kasan_status"
resource to expect specific failures, but we still want the fallback
call to kunit_set_failure() so that any test which causes a KASAN
report will fail:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/mm/kasan/report.c#n130

> I'm currently switching KASAN tests from using KUnit resources to
> console tracepoints [1], and those patches will be in conflict with
> yours.

Ah, sorry -- I'd seen these go past, and totally forgot about them! I
think all we really want to keep is the ability to fail tests if a
KASAN report occurs. The tricky bit is then disabling that for the
KASAN tests, so that they can have "expected" failures.

-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmP1A4d_-SNrWg7VruxpKj3SZz%3DBzb2Xebd%3DEXw1imXyA%40mail.gmail.com.

--000000000000d2339805eb648c5e
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
z/tQRXr3iPeVmZCr7nttMEwGA1UdIARFMEMwQQYJKwYBBAGgMgEoMDQwMgYIKwYBBQUHAgEWJmh0
dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZoGCCsG
AQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9n
c2F0bGFzcjNzbWltZWNhMjAyMDBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5nbG9iYWxzaWdu
LmNvbS9jYWNlcnQvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3J0MB8GA1UdIwQYMBaAFHzMCmjXouse
LHIb0c1dlW+N+/JjMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20v
Y2EvZ3NhdGxhc3Izc21pbWVjYTIwMjAuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAx+EQjLATc/sze
VoZkH7OLz+/no1+y31x4BQ3wjW7lKfay9DAAVym896b7ECttSo95GEvS7pYMikzud57WypK7Bjpi
ep8YLarLRDrvyyvBuYtyDrIewkuASHtV1oy5E6QZZe2VOxMm6e2oJnFFjbflot4A08D3SwqDwV0i
OOYwT0BUtHYR/3903Dmdx5Alq+NDvUHDjozgo0f6oIkwDXT3yBV36utQ/jFisd36C8RD5mM+NFpu
3aqLXARRbKtxw29ErCwulof2dcAonG7cd5j+gmS84sLhKU+BhL1OQVXnJ5tj7xZ5Ri5I23brcwk0
lk/gWqfgs3ppT9Xk7zVit9q8MYICajCCAmYCAQEwaDBUMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
R2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAxMhR2xvYmFsU2lnbiBBdGxhcyBSMyBTTUlNRSBDQSAy
MDIwAhABh9LgIPnlfMFHR0Die8n7MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCAx
P3UYKjpLkVFR1w2fhFjJSDECimirl3RIC4Ton/PbojAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjEwMTkxNTA2MTVaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAI7d5VhZPkeOj+nVmZAgt
JhYzppd/+bwOeuXrU6fmr/P5oL1rH74x+YLhqOQzbpEh4Y92oc9DXlAvWTTL0HnWMxyzIs/EM3l7
uNgtvzQAmxhBsIMKWBlkDxrBhfW+6b8OVsBiB9coM+SxLcebcErOHQCEuzT+OaenYHaWge6+xVOc
Jm+faszP0EU4UZinG0HKK3G7fC0FwzqGwfjT8J21qrnmuaE8jiSXv+H74zo5Qbnp8uZX7QX43PVM
wQsSn8eN+T6tqDD5bN0mJmQut/dt3gLqZJPMaoyz8ik5RCc9Sm9t4fbN0HSsPy8gbmLecKWCNxZR
sntQX9fgWKb/DV6avQ==
--000000000000d2339805eb648c5e--
