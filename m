Return-Path: <kasan-dev+bncBC6OLHHDVUOBB75M6WKQMGQEFDAEVKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 289325613B7
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 09:53:36 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id y8-20020a2eb008000000b0025bf6ec0c6csf242922ljk.20
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 00:53:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656575615; cv=pass;
        d=google.com; s=arc-20160816;
        b=VxzCjDG+3O35haRltXR6PERkwSE0UgwRHQ3RfMvGi+2D1IwOf3lsY1BxWZdmV7nqzJ
         Z/wri3aUeLdglibN9oZw0OuanOk5nV5OIiatUeS1kUp+oSc1ObwzUoYtfESdwuBc6dac
         eFwo8zXzZug6lqlZmXFjZNd5cSAYR2UeYU5+2mOjJAfIWszEBqUZOs9eCLHnZJ6PcYeu
         ijYBGdxlDdn/bxZiLhGjd/zvM9yC3YsH9a/Kbc6lADxZvbyXY6GzeMoCgnVQP/29kXn8
         US39zVeeOK7jkdN3AyAQzQ0gYe9kCjzaFAq0WyT/xeS0IbM9KrHAwsOeo+NIX8VlfOv3
         kGXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UklLQ1pHJuUnjnd2SdNd/BSNr1OzBEj1u4q5mRYGwRc=;
        b=jnF8BdyXgMQKOAmkL+mv/4u0gom4+m0MNJKO8MCIi1Ns11Atqgy24130SorWldLylX
         oNDbrJ1OBnAkeHolC/37BIuJ0lphCEml+X0ns5DRZXm8CP20nAFReP5cyAIgD0zPIOlB
         HczPslmnrfpOOnRe4VlWuAl1+5hWSuitiMnwBvf3qI1RZ7jiSXCAsPRKZdgufbGvJB8w
         330Q377mPhren9n0UVG6XqP2ukT6XzoPvZhhLvBzy6JbAIwr/AIKseSwpx7HC6fzkK1E
         DNqHFbElcbRVD4Nve28JiZ5YgKuzkvtm7b9hQyWqbIkLVwntIPq7AE8tXBvLA3kdCy1c
         Xvkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="ozeEsz/u";
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UklLQ1pHJuUnjnd2SdNd/BSNr1OzBEj1u4q5mRYGwRc=;
        b=HAWdd2lELpsau4UR1K53J8roBaI9tDikBhW4hcvpuQes6RXuJ9ZugBF5rNd34NUsfb
         pLhrqWM+zQFAov218q7mcUvKdtrlu1wLc7lV13B7Sx5UeLqXAhj2m5iSukBQ5sITnYma
         +3Wla9gEu5Ej5QSW9CISR++/mlROEed5oIAPjCmulbGx6XClt6jj5wROW60NocZ2EMvI
         +hplsGYZtfmrLgU7smGJ71srgZCPvZa4ShxMDEkYhrhadz1OO1FLzbrXU2yVwSUJUZKB
         CzvGag5C/QSeuuU1JMJThqH4kDIKrYbb4opwWC4s3+4jJRXPq7I84479mVvSGrX9gvDL
         CcQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UklLQ1pHJuUnjnd2SdNd/BSNr1OzBEj1u4q5mRYGwRc=;
        b=Xu6ms+9PfhcoddNp+gZ0gm3zLOpV+KnQzB6PdaiqLXpjBiHqTOrBypE8ii0LmA0Qa1
         DaS34KWIZzwton7njd17cLIQ3jcLD83N0mTvZyRnfsT7wSp9Q5ikj63EkaShUqT/Y2Zo
         vtznxN3MsJ7z/gPcaJsC6uLrdLqYkBWHu6nJB5L7lGvcydeu3qatWuoB3HW19VTdN3NL
         Xeigsep5BGzI1a78nNFfUvhfVoGQrcwK9Ntv1qSBXgxH1CHI9SYombWwp/7ZmFzaMTjv
         kZYBM5uqpR3Xs43UmGL84ZYpVeDTV8ckrkkWP62hgGeVPELwP26d889S/CnLAxV5hBfa
         DjaQ==
X-Gm-Message-State: AJIora9PxTAh5qoSabHvk9UDJ4AK85roXxrWbjjlmPbr4PiblHeARjvZ
	cKFydNXlILj3DhX/6Iv/nAQ=
X-Google-Smtp-Source: AGRyM1vfrGi62j+2PyWBfB72e+eBXaZwuwb4hQKLzq9OVnE7JNw6yXZ6nZ5n9DJk+CaEIfmJafb0cg==
X-Received: by 2002:a2e:3808:0:b0:25a:703b:6d00 with SMTP id f8-20020a2e3808000000b0025a703b6d00mr4472975lja.352.1656575615554;
        Thu, 30 Jun 2022 00:53:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:97:b0:25b:be22:345d with SMTP id
 23-20020a05651c009700b0025bbe22345dls2115404ljq.8.gmail; Thu, 30 Jun 2022
 00:53:34 -0700 (PDT)
X-Received: by 2002:a2e:b0fa:0:b0:25a:7811:70d with SMTP id h26-20020a2eb0fa000000b0025a7811070dmr4267624ljl.370.1656575614181;
        Thu, 30 Jun 2022 00:53:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656575614; cv=none;
        d=google.com; s=arc-20160816;
        b=zgJatb48zjTBGi57XlFnjKkXRkUjhUv0GrQ57hzb9Q3OzgcbZQpJU1gE7FYplT4phR
         XL53V9oNv9UGZRItddlo2O3kq8oMsgQmBbtSRafTzngeo8b5NMMZhP7Fflj2qgDTl6tC
         DhyrCgYssXCci+z0C1c8vFcxlcBb3qTO8JHb8a5l2wqmxcAkJXhmc++OVGL1d0FZPjIU
         1KxsMKwtQFhzQG/8Yip2J8iAAbkRPpyNaG8rOebE8/+nfYSqA6MHoJuoXije3/ciwcyC
         gTLyx6Pwmuq6KG6ho4KcX3AOzyN3xA4/4MnphSVGGcU/q0WSWoCwgfDL1h6ZRVgvbWtV
         ivrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6C4J/OxQX3mubO9iKL6E/yqHG8Uiv6xLBNMVEabQwTo=;
        b=m+Rz4V58RWNUMTLUIUtanLivZYHUMJoqWzQW4EbqbYiUtb0ozqp47ZaNaQA+CCCn2n
         NveMtykYUXUPihaFUXn6FeC7oo+tzt5nChWQ1gdMp3leVaK872eBWCDXqB0/PMO9OfoL
         KVqeSMWUn4u2rLMiDbNllTKZhzxdQvVpiU+xKqQ15VNf5wZlivXXSIe8UJ0v1qFyw5aL
         k7iy82TNgcDkQNBHlTiw8BATJ/XnEouNESI34HfTabvAyaGDoBTvQ+IdUwS36xMvJ6ac
         TjmaG4y7PaPe5pEvkIRgrsU1mBepwOcvFrzhp9uiuJTWLow8KHoGcuiWkRC71x9euQCK
         gcUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="ozeEsz/u";
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id bp20-20020a056512159400b0047f8c989147si749473lfb.3.2022.06.30.00.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 00:53:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id k7so1490978wrc.12
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 00:53:34 -0700 (PDT)
X-Received: by 2002:a05:6000:144d:b0:21b:b3cc:162e with SMTP id
 v13-20020a056000144d00b0021bb3cc162emr7099100wrx.433.1656575613798; Thu, 30
 Jun 2022 00:53:33 -0700 (PDT)
MIME-Version: 1.0
References: <20220527185600.1236769-1-davidgow@google.com> <20220527185600.1236769-2-davidgow@google.com>
 <1a4e51a4d2ed51e7ae1ff55bd4da6a47fad7c0bf.camel@sipsolutions.net>
In-Reply-To: <1a4e51a4d2ed51e7ae1ff55bd4da6a47fad7c0bf.camel@sipsolutions.net>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Jun 2022 15:53:22 +0800
Message-ID: <CABVgOSmcwGa4tw8EvuxbeOvrTLh8d7V3mFxGyj2spnqqWkFp9Q@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
	Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-um <linux-um@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000059e1705e2a5915c"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="ozeEsz/u";       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::42b
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

--000000000000059e1705e2a5915c
Content-Type: text/plain; charset="UTF-8"

On Mon, May 30, 2022 at 1:04 AM Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Fri, 2022-05-27 at 11:56 -0700, David Gow wrote:
> >
> > The UML-specific KASAN initializer uses mmap to map the roughly 2.25TB
>
> You say 2.25TB here, and
>
> > +config KASAN_SHADOW_OFFSET
> > +     hex
> > +     depends on KASAN
> > +     default 0x100000000000
> > +     help
> > +       This is the offset at which the ~2.25TB of shadow memory is
>
> here too, of course.
>
> But I notice that I get ~16TB address space use when running,
>
> > +/* used in kasan_mem_to_shadow to divide by 8 */
> > +#define KASAN_SHADOW_SCALE_SHIFT 3
> > +
> > +#ifdef CONFIG_X86_64
> > +#define KASAN_HOST_USER_SPACE_END_ADDR 0x00007fffffffffffUL
> > +/* KASAN_SHADOW_SIZE is the size of total address space divided by 8 */
> > +#define KASAN_SHADOW_SIZE ((KASAN_HOST_USER_SPACE_END_ADDR + 1) >> \
> > +                     KASAN_SHADOW_SCALE_SHIFT)
>
> because this ends up being 0x100000000000, i.e. 16 TiB.
>
> Is that intentional? Was something missed? Maybe
> KASAN_HOST_USER_SPACE_END_ADDR was too big?
>
> It doesn't really matter, but I guess then the documentation should be
> updated.

Whoops, the amount of shadow memory allocated was changed for v1 of
this patch (it was ~2.25 TB in the original RFC). I've updated these
comments in v3:
https://lore.kernel.org/lkml/20220630074757.2739000-2-davidgow@google.com/

-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmcwGa4tw8EvuxbeOvrTLh8d7V3mFxGyj2spnqqWkFp9Q%40mail.gmail.com.

--000000000000059e1705e2a5915c
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
MDIwAhABh9LgIPnlfMFHR0Die8n7MA0GCWCGSAFlAwQCAQUAoIHUMC8GCSqGSIb3DQEJBDEiBCAC
4kJdF+2X25TeKcgcUQweuNOfKBGXpRPTwPX85b92ATAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
MBwGCSqGSIb3DQEJBTEPFw0yMjA2MzAwNzUzMzRaMGkGCSqGSIb3DQEJDzFcMFowCwYJYIZIAWUD
BAEqMAsGCWCGSAFlAwQBFjALBglghkgBZQMEAQIwCgYIKoZIhvcNAwcwCwYJKoZIhvcNAQEKMAsG
CSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcNAQEBBQAEggEAFOq49C9C+/7jAbmXMpO+
lVoTeO5gA2h71wuh4Nu4Km6zxPF0/b55zj3dQmxiACPcxvEI6GVlR6zOF5icVoQP51kMwn1X2mOx
hi6LROmQBljVaF33H+y2JVvlpIAJ+AzBv4vx9HxozNc7w2H4Rs0FVsrQZ7+r/ymZL1USwDMiinuV
5vJyGjoPbAG3SMmuufGU9qpp4ly8LtN+x/g9uVSTnDSGB/D47pbqKQzDo5t8ZwyngmN6Jkyn4SIi
+g75XK5RwkV97ESUsRyxIaW0EMEhoWXM6VFihvYUbrz1UcDLwR3MC06ifTgEyUvcK5e9COb3Dp0m
Ik2JTZrTnHoanWgcgg==
--000000000000059e1705e2a5915c--
