Return-Path: <kasan-dev+bncBC6OLHHDVUOBBS4D7OKQMGQE6K62UFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 722D156307C
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 11:43:40 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id y35-20020a0565123f2300b0047f70612402sf891954lfa.12
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 02:43:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656668619; cv=pass;
        d=google.com; s=arc-20160816;
        b=wJDYbvEUH8sBs461Ykbn5GO3YgMmudTUqj1MVxZdlxqzAZcJZ9rqvdxn2seG37WGsl
         tx2Ytj54BA26whAkvk8ysSCTj8ONrEi13gB5PxoAOpO60iA9jSdlW3X4+ude2dTfrdUj
         Gaa78L7KqY07yKkxbZq0iLcz+r24Z1x+NFCcV1xq5d2g1PNpiljaF6mJtkmjlPsSc5ju
         G11nYkn0cWotGxK+u5MUkjroeL3FOvtvDQk+OpQ/KdcS2PTR8y5zxqOlA9b6ftTeRSn/
         yFH86le8Pvt47FHAVGgw+g4Nar1Lf0OofRtM17GNMqMHfNmv9xF/q+Fj7bZIWS5ayaDW
         GRQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e36+oYDK3mBD6KPcK1jMiUAXBOHDv7BzTKM5rbJD2Ic=;
        b=FKqi9eOcBYqgFur1i1oUmk9QMROxMAUOHFfxP2nitq4lwSDvI/gL7fuFoacP81k3ll
         uSrZV/4rBd8wCMcNGrZiUZ62kIY4AaVxzVDSBfb7q3/AbCiNCRk0jStfs1I1bKWDX+av
         0l5SEvZpmM4DU55v9iQD1y/80KtQEFhGxzM77SJRTQgAHqCGU8GagVgCnh3ssMcvYAYW
         Y67RkHPe5MXgpQm99iU+BGRDCwJTmklS7g5bmEOZ5JwNBOU7xm13Hjb5gAUniGTPFja8
         a9LIrJyDxu9NVYIh2Gst56rxih2T8JTgoYeAqznzdIf6sW51d6NFOMNWf9di8j5IGnXy
         kQ5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dWAdZvwL;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e36+oYDK3mBD6KPcK1jMiUAXBOHDv7BzTKM5rbJD2Ic=;
        b=jB8pTMvxJg2DejryADkKUDRDe7ChJ4SDlqlSYamPiK9C72eMU/Sp3MJYQBvFpEPRkx
         nmzhN0FLQDWoGFo/AgQuREsEH7AulCccmy1B/w6yBSMl/spt0jmjTVqgGva0U3CBz1Sq
         WO8Gchy/BUUzLTWKYqmYAocTSRIvFLscyUYWytIZZCDDbupareEQlTDAZ8zoKlE2JBCw
         dHiNMzqr5qnjTwjcGMprYGZ8xTgHa8vjSFcP/a0zX+gIV85bzusJvVb4Hl1r6toaJ1Vu
         Ox7cv0bYCkRoAi1Ky1YcmVE0WF/ZVaEyQdtQFCtjhYgUo67NJkG7h7vjOhr76moPs7k7
         0nvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e36+oYDK3mBD6KPcK1jMiUAXBOHDv7BzTKM5rbJD2Ic=;
        b=BADP3n4VUzGzqGzOAJh5k15nSdasNRzB415IsiEbcVUyZQHUqchHv2ti1wpWgimyYq
         s3varWqvNbjdgoQIV916cyg2kYz1JKkUwF6WtWi7wTNBWEErXbB1FYHXx5KmU1vt7/Px
         kwn63LMCpN4y4wq6BocqNrdP7MnKWygSu9ZKdoJk5mwhBRUlVqA84L4GRBbP7QMMeP0/
         ykvOQSqZeyCnQfsGP+RJM03oEsi9FmZTC590qRYcuXXrxqci0uKhSh0LxBmRpwMunKCD
         F1q2VUPnSISP8PB1DwtQVlcV74/tUmbqMWaH5A/ssInEXU7EwRB8xF/dzWPo9LtbAz0D
         2F8A==
X-Gm-Message-State: AJIora+839uAWXJiVsBm+rmvNhQUe4Lp/570L54LuB7CPxP/Pagrftx6
	NejVyuO85DmnHT4/Laqk8/A=
X-Google-Smtp-Source: AGRyM1uJcQFLXhvRW7t/DnfdTJxUShmAMhJunFkwLCtiJD42tEOkjf6fkP4/GTm7Fr3oY8OPuFf7YA==
X-Received: by 2002:a05:6512:130b:b0:47f:6622:c189 with SMTP id x11-20020a056512130b00b0047f6622c189mr8133129lfu.258.1656668619551;
        Fri, 01 Jul 2022 02:43:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9948:0:b0:25b:c0c2:7dec with SMTP id r8-20020a2e9948000000b0025bc0c27decls2698124ljj.11.gmail;
 Fri, 01 Jul 2022 02:43:38 -0700 (PDT)
X-Received: by 2002:a2e:98ca:0:b0:25a:76f4:bc8c with SMTP id s10-20020a2e98ca000000b0025a76f4bc8cmr7691451ljj.50.1656668618006;
        Fri, 01 Jul 2022 02:43:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656668618; cv=none;
        d=google.com; s=arc-20160816;
        b=ON4gzf+xcM1J22lWJ0OY7MfVkc2WRMaqW9/EPfwu1r+Ow7qDl+3M/NYMxarVmxsNba
         q9/gOxe8r5yIS2785N0THuw/2f7ktAxLTk6yOtUexpEtg7Zho3blGqTDbCAVxmAvKOC2
         QOmcCsI2cpRI/Fby6v6a2TGbwd3GrfYdGqVgAbK66qIwAU2zyKPFV2nwbvYGK1nRs/ek
         Malu7INHZsXPmlCregqgj/KviIWDyk1Mrvr7ZXiDxvJNJdYny+Vgq2RkD7sHE2k1bywO
         ElsTN6fyh+B8UDZ88bGtIoerZQXOrXfSgd1fA6lSP2AW8okcrRpx2gcZrWoB171EYIvH
         1c2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2o+nhkReAFO8MBe4VB1+9/N7eqkW6n9airhRLInTum8=;
        b=KVfQxdRiO6UsNgk5GyxtHZLA+NJh+4OKz/hX4MYKwNjy8lZmBWXS5dsGXiJ1ULF+Mc
         PqgENoZPEmoLvIQIXsTwJfiKql0YDM8omjCCyTq5uunoDnaf3eFQVGDtMEPejqWKMkNe
         jiihfe5DEKGZS5jpRVFt8/iPyR0r1ozSltIFWQ50PEjlG1ZGFEQ3hVH4p95b5V90rmUV
         DJ9ULcyZDJZFTSVjFfOnUqVLfBAy8RrRTUW1r9YDq6YOw8L/n+7dYhzEOQn8cVj9aiK6
         AaTJig3AnFUuBD/VzDJhEUTkqHkRXL0/n+YbnNamDTRKe2HpEpgRosD4eyRQeJa8DHun
         OpIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dWAdZvwL;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id cf26-20020a056512281a00b0047fb02e889fsi917230lfb.2.2022.07.01.02.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 02:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id k129so971642wme.0
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 02:43:37 -0700 (PDT)
X-Received: by 2002:a05:600c:4fd0:b0:39c:6565:31a5 with SMTP id
 o16-20020a05600c4fd000b0039c656531a5mr17123862wmq.60.1656668617649; Fri, 01
 Jul 2022 02:43:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220630080834.2742777-1-davidgow@google.com> <20220630080834.2742777-2-davidgow@google.com>
 <CACT4Y+ZahTu0pGNSdZmx=4ZJHt4=mVuhxQnH_7ykDA5_fBJZVQ@mail.gmail.com>
 <20220630125434.GA20153@axis.com> <CA+fCnZe6zk8WQ7FkCsnMPLpDW2+wJcjdcrs5fxJRh+T=FvFDVA@mail.gmail.com>
 <CABVgOSmxnTc31C-gbmbns+8YOkpppK77sdXLzASZ-hspFYDwfA@mail.gmail.com> <20220701091653.GA7009@axis.com>
In-Reply-To: <20220701091653.GA7009@axis.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Jul 2022 17:43:26 +0800
Message-ID: <CABVgOSnEEWEe16O4YsyuiWttffdAAbkpuXehefGEEeYvjPqVkA@mail.gmail.com>
Subject: Re: [PATCH v4 2/2] UML: add support for KASAN under x86_64
To: Vincent Whitchurch <vincent.whitchurch@axis.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Johannes Berg <johannes@sipsolutions.net>, Patricia Alfonso <trishalfonso@google.com>, 
	Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
	"anton.ivanov@cambridgegreys.com" <anton.ivanov@cambridgegreys.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"kunit-dev@googlegroups.com" <kunit-dev@googlegroups.com>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="0000000000007b5d3e05e2bb3858"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dWAdZvwL;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::334
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

--0000000000007b5d3e05e2bb3858
Content-Type: text/plain; charset="UTF-8"

On Fri, Jul 1, 2022 at 5:16 PM Vincent Whitchurch
<vincent.whitchurch@axis.com> wrote:
>
> On Fri, Jul 01, 2022 at 11:08:27AM +0200, David Gow wrote:
> > On Thu, Jun 30, 2022 at 9:29 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
> > > Stack trace collection code might trigger KASAN splats when walking
> > > stack frames, but this can be resolved by using unchecked accesses.
> > > The main reason to disable instrumentation here is for performance
> > > reasons, see the upcoming patch for arm64 [1] for some details.
> > >
> > > [1] https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?id=802b91118d11
> >
> > Ah -- that does it! Using READ_ONCE_NOCHECK() in dump_trace() gets rid
> > of the nasty recursive KASAN failures we were getting in the tests.
> >
> > I'll send out v5 with those files instrumented again.
>
> Hmm, do we really want that?  In the patch Andrey linked to above he
> removed the READ_ONCE_NOCHECK() and added the KASAN_SANITIZE on the
> corresponding files for arm64, just like it's already the case in this
> patch for UML.

Personally, I'm okay with the performance overhead so far: in my tests
with a collection of ~350 KUnit tests, the total difference in runtime
was about ~.2 seconds, and was within the margin of error caused by
fluctuations in the compilation time.

As an example, without the stacktrace code instrumented:
[17:36:50] Testing complete. Passed: 364, Failed: 0, Crashed: 0,
Skipped: 47, Errors: 0
[17:36:50] Elapsed time: 15.114s total, 0.003s configuring, 8.518s
building, 6.433s running

versus with it instrumented:
[17:35:40] Testing complete. Passed: 364, Failed: 0, Crashed: 0,
Skipped: 47, Errors: 0
[17:35:40] Elapsed time: 15.497s total, 0.003s configuring, 8.691s
building, 6.640s running

That being said, I'm okay with disabling it again and adding a comment
if it's slow enough in some other usecase to cause problems (or even
just be annoying). That could either be done in a v6 of this patchset,
or a follow-up patch, depending on what people would prefer. But I'd
not have a problem with leaving it instrumented for now.

-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnEEWEe16O4YsyuiWttffdAAbkpuXehefGEEeYvjPqVkA%40mail.gmail.com.

--0000000000007b5d3e05e2bb3858
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
MDIwAhABh9LgIPnlfMFHR0Die8n7MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCD0
Cw53c9MXnQuV6OAB9m31KZmbHdpUkRwCKAxRDdtpSTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA3MDEwOTQzMzdaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEANwyQ/iyHphnkN35OzEzT
zf1OP5w0MEMHnobvNSXQVcsbNA2jf2SaJNbAje3lP2OyZ+jndYPJHOHV42vtUFXQw76SWbh2uUKy
Ldhw9pRymQ5ri2K4UXgbr9QDBm87cXRtXVWDN7+bJGo/e/ZMpKACQjqVQ4N0cowTcdkFb5YKZfA5
UiCSbiYhVdyGLPFRp/7CCwFPTWa97YIq54WTdm3uYoNsX9lN1KIz6nGzDgIWLnufhiJNtdp/aevc
rshx9RfthLCX4u9vYrpanpjt7SDBZsjENsx2pML0Qafz29CtpO0TL3zpMEmns77XLmyIq9u3H1TZ
46Ug31te5c+rZY3ilg==
--0000000000007b5d3e05e2bb3858--
