Return-Path: <kasan-dev+bncBC6OLHHDVUOBB34FTGKAMGQEXTB4OPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CDA752D3B5
	for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 15:15:28 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id t9-20020a5d5349000000b0020d02cd51fbsf1547961wrv.13
        for <lists+kasan-dev@lfdr.de>; Thu, 19 May 2022 06:15:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652966127; cv=pass;
        d=google.com; s=arc-20160816;
        b=RrNsaBhnqYCWdVcg/fDlGx2LLZZCm1YCAvg78wYbAug7PN5alPPn2ZgI5CC354DOmc
         bHdP4x3W8ceL6S/WkFndOhhb1ElwEkOWeVqBGOnDuEsE1F9QXBJdT+hXysUy4LMcErol
         pweMJ9H+Z5J6gfyt7OAIBBhnefHPGPhCKS6/EM6/oXdAo7Dg+tN1O1sUgwldkgFz0aM0
         NlMMFD73HvLXbTYnBlKVPPkGQP1DmhMQaXlojp9PYH+7HeL99aOzM/37TwIN/10MISq+
         oYH3ZI7V5GIHdcExvAr1L8qqksG3Ku09/fGRIv6lhkl2DFVEOXIa/gucJI5wGT7y7K+d
         iqlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZZLR18t5H6dDlfnwiToOKILHvgIMfb/SuB3/XuFXNf0=;
        b=ODSyyn6GwnDCJ4Gj1CW3ixN1NLFjXWgEM57nAia0GVUeZojbYMU6mjkuknVW62yZpC
         mtSCMw+uOlS3tBpNLKCrND7PxiTPPth28HTW+QzMEQrLCiIQ6QEykz7cW1DhJwQz04TY
         M+b1TrXE48970sNXDGW5OJHCs/TMTsl860LzVeVKumixowL/1CuFjWzEmB+CRPLbVA6h
         Vwvl5m2b3P/Cl0urZsiFtXTuQMQF2cyA1LvGhBmVkE0Tli1DfNJ5ZFQMTFlF5Sobul7Q
         tsoYCTuQXnXEWxeahKyMnaFOlpigSpTkwHjHFioVPMpot3/9LnF6ps+r4bc4CvwqOTDe
         kIlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PVg1KbZa;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZLR18t5H6dDlfnwiToOKILHvgIMfb/SuB3/XuFXNf0=;
        b=Gpj3Nn/nJRmtHLcDcNfUsT0cyGK4MuG/YYw2ihC4oST5IfFVU8DwII10DUhyxrQ3vO
         wJWoddpRtYV3y6XvRWjbsnptQk3wug4AGtMwfNtfAMzMcO/BIgVeafZSN7+GXWFCE00V
         zGs8tR5qKbaPNO6GTsF3w475AdIy/KaoHefpCdRq1GoXGSSlJ9cCbRI67DYeBAKgn5+2
         iHJ+zsZvrzvqE9uHPwMtTZ5x0p6F5muyLZQ9bD7BBDk7Wo26UHa3DfaDE0aVlSlcaLjB
         F2bmlglzC74yQMna2F7hUTnMoTeXEo/3kBRyaFRLbbybDKZlUy4R4e9CDjcDmB2UFCSJ
         vdnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZLR18t5H6dDlfnwiToOKILHvgIMfb/SuB3/XuFXNf0=;
        b=ayNTO81A4e+IoCbfbvzRn/o3vrm4TowCm8Zs7vezRd72kkPeC6LNnnqeeBhdmPjl5S
         ZS4IzqucEny7dn3eVUyVRqhBkL0RIHcMyFWTdALS+Vc8RRzDPbjOtSSRigfvLIdOM/JR
         MefjxCzGJ96T62d4ZHUAG1YXQI++vESXbNp9TQZ6H6WOjdcQDtwDtwU/u5iU8+F1dm9R
         tg6coDnPgxlCK4t56hU900ggKgF1NOJ2Y2B5F+77LN/8pBj5BXevKmAk2f8rzXhTRU7j
         osnspJm0mh1dS44ycZRJ8IeL9rHKFF4NdFEXlLG9cqUR6XcYh3J1Qydvfz86FyYiz7Y0
         9g8g==
X-Gm-Message-State: AOAM533M/aHIsR1/h49ljxH2b6wfETg0CZPnaqsajZH0paAaE0FH1hPz
	V2V2Z08RoRDHiN7ixjztJIs=
X-Google-Smtp-Source: ABdhPJwfQi4GdXptj4y+JLFEF8CKT9ZHvvNNWHeYEtKthLdFg15D1p71MKsV34ZDuN1bNOmZQDSFJg==
X-Received: by 2002:a5d:69c5:0:b0:20e:5884:5c75 with SMTP id s5-20020a5d69c5000000b0020e58845c75mr4186209wrw.19.1652966127724;
        Thu, 19 May 2022 06:15:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1688:b0:20c:67b9:e68b with SMTP id
 y8-20020a056000168800b0020c67b9e68bls4429111wrd.3.gmail; Thu, 19 May 2022
 06:15:26 -0700 (PDT)
X-Received: by 2002:a5d:560f:0:b0:20d:b24:dadb with SMTP id l15-20020a5d560f000000b0020d0b24dadbmr3943772wrv.121.1652966126458;
        Thu, 19 May 2022 06:15:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652966126; cv=none;
        d=google.com; s=arc-20160816;
        b=FVXydsh8aEJzc+D3oV6SgWRlcBwEqvirD3bphnWY0e1uc1P8XHacD7eqBH2Z9gjSDi
         tgk9EPI3NiLtyav3jfoEmU8hzjDDTdxsLVAPoZK7jF9nGYFOXPF9ildS3VUmgy4ustEu
         m9owPj3iH61NXnbdFLnXUr4rk99JqNYGOfifI5UvHCnwNUT0Kyr0x44KYRrAa6rl5vFY
         1MiyrZQ5qItHiJEfpDfcYYOHXZmGE3AqLxzjxStKVt3pqOPC4LpOxOCTiWuK20VxU1AI
         Q0w4nlqUcHuUvtklftDTvP4CdlvMj38W+A1XSw+9CeHhfR8bHxmYY3WXYegwwxJrMTN9
         akjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/Bd1dTj4NcALS3+f9VZ4FkGsyBnA2UDPJkPi0npNX7Y=;
        b=Rf+L22YY3GsG63bizdtc4Ai66iXPHmYEYsq+v3l/NXxJw1D6moDVrDBGu3j7R5lRlQ
         TBkcqdgYfNSGmQTidiAoaHhkSCJewxIoMcLL/bfi4NsGWDftdy3vZp8gEAxOcYW1BQut
         xc7q5uj4BJSe5iJPE92NlrKtZjNDwnmQCTTwTVW7JcWcf4Y3u/gcvwcRtkgD8M1/3DyH
         UdAa3K3r8rRZjMltkQ79a+WEaX7MqdbTxpIdxkBC7bL8bKad0h4zsHPj8itBM5H7PslA
         Vo9S2b42/XieqQTMB//zP8Zwe+SrNcVyjqv2zUYAH68OKwsvbOn5QBJXe/5qRIL/HqtA
         DGBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PVg1KbZa;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id r14-20020adff70e000000b0020c9eedfe67si249126wrp.3.2022.05.19.06.15.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 May 2022 06:15:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id n6-20020a05600c3b8600b0039492b44ce7so2682879wms.5
        for <kasan-dev@googlegroups.com>; Thu, 19 May 2022 06:15:26 -0700 (PDT)
X-Received: by 2002:a05:600c:ad3:b0:394:46ae:549b with SMTP id
 c19-20020a05600c0ad300b0039446ae549bmr4242568wmr.113.1652966125877; Thu, 19
 May 2022 06:15:25 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA@mail.gmail.com>
 <CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA@mail.gmail.com>
In-Reply-To: <CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 19 May 2022 21:15:14 +0800
Message-ID: <CABVgOS=X51T_=hwTumnzL2yECgcshWBp1RT0F3GiT3+Fe_vang@mail.gmail.com>
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
To: Marco Elver <elver@google.com>
Cc: Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000ca50d305df5d2a82"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PVg1KbZa;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::336
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

--000000000000ca50d305df5d2a82
Content-Type: text/plain; charset="UTF-8"

On Wed, May 18, 2022 at 11:36 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 18 May 2022 at 17:31, Daniel Latypov <dlatypov@google.com> wrote:
> >
> > On Wed, May 18, 2022 at 12:32 AM 'David Gow' via KUnit Development
> > <kunit-dev@googlegroups.com> wrote:
> > >
> > > Add a new QEMU config for kunit_tool, x86_64-smp, which provides an
> > > 8-cpu SMP setup. No other kunit_tool configurations provide an SMP
> > > setup, so this is the best bet for testing things like KCSAN, which
> > > require a multicore/multi-cpu system.
> > >
> > > The choice of 8 CPUs is pretty arbitrary: it's enough to get tests like
> > > KCSAN to run with a nontrivial number of worker threads, while still
> > > working relatively quickly on older machines.
> > >
> >
> > Since it's arbitrary, I somewhat prefer the idea of leaving up
> > entirely to the caller
> > i.e.
> > $ kunit.py run --kconfig_add=CONFIG_SMP=y --qemu_args '-smp 8'
> >
> > We could add CONFIG_SMP=y to the default qemu_configs/*.py and do
> > $ kunit.py run --qemu_args '-smp 8'
> > but I'd prefer the first, even if it is more verbose.
> >
> > Marco, does this seem reasonable from your perspective?
>
> Either way works. But I wouldn't mind a sane default though, where
> that default can be overridden with custom number of CPUs.
>

I tend to agree that having both would be nice: I think there are
enough useful "machine configs" that trying to maintain, e.g, a 1:1
mapping with kernel architectures is going to leave a bunch of things
on the table, particularly as we add more tests for, e.g., drivers and
specific CPU models.

The problem, of course, is that the --kconfig_add flags don't allow us
to override anything explicitly stated in either the kunitconfig or
qemu_config (and I imagine there could be problems with --qemu_config,
too).

> > I think that a new --qemu_args would be generically useful for adhoc
> > use and light enough that people won't need to add qemu_configs much.
> > E.g. I can see people wanting multiple NUMA nodes, a specific -cpu, and so on.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DX51T_%3DhwTumnzL2yECgcshWBp1RT0F3GiT3%2BFe_vang%40mail.gmail.com.

--000000000000ca50d305df5d2a82
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
MDIwAhABQeVybOOpR4bOOXZYL5T3MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCAI
zxDdM63ohRMg2/Q6u8VwGIk6kXGZ1ugrQbXDgkLydzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA1MTkxMzE1MjZaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAr4OItgdvBbQnw+RRHfUR
S9sHUm/Rt/zyk55i9l/tKDXEI/xy+M1KoiwUcOYpqY8OTT28778qhiPd/9HLHNVc+TdvyGY1HS8/
TNNtAaELz2LcE8+d3RBM8Qy8LGivgow3+zGiBUcZ80kQsgPLYx5+fE29FY0sA6R5sWRkf9X4gMm6
8gs7+letJXuZiVEzs6e/OS7SDyiKH/zElmAMBOf4A8YOxDfDpR4hLsvD42/9P/4jYLf2rZYZV0PD
V78D6ttmM5owOqPnVm1JJ8emCmXbz/J7zxd7egOwjgyybFNH+5UY98HUzwIbkk0tiqdpqDFUHxpG
Kk3zhwrEclaNFo6UVg==
--000000000000ca50d305df5d2a82--
