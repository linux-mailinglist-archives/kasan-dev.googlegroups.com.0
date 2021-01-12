Return-Path: <kasan-dev+bncBCCMH5WKTMGRBB5F6X7QKGQEKEADWJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 641C72F290B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 08:40:56 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id l7sf959797qvp.15
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 23:40:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610437255; cv=pass;
        d=google.com; s=arc-20160816;
        b=gpDDgbl87kjiVEn6EjjqYCK7bnzSb9BxHhioO/6L+s4NfPX4bqCoOInISgofIW4rw/
         kbZEOComoMt75c11IeQMpepWG+EdT3NxkmXVIwSQZM2CM0znt79DRDrgY7K0DJ+atjY6
         IjBa3Q1AmIG5LUlG65FD/L+K2AQaEkmwnQCs1EnQI0psmnLgzHgDxrEThq9fa0cs5RRA
         aH/OHRhMiHR+Uu8h9upjp2kqHPgTSaOZgMw4zxgKc+SVw85S+ME6nZZUvRmKBzHxomtX
         jVCaVbA9igJQf6EQjp7E+6STE7nWFx7JSFhfuSjt/hYMkzJZKREdHa4TEFPt3u6SsTen
         kXHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H8o8+d9YyCxlAmC4UVTj7olySRzid+rySqeJU4c1Gf4=;
        b=bSl1qAxunTK4Aq3OTyIV9YS/f8MzPpOXqDMbCqPwmTtUZr6Vbv1zWT5lKd8c7mBBvs
         pC6s2TF4IAoT4N6MxY40FiYD0jfX1sG8abB0yV1ArZzSNwzOpJPYcjceMqWeKSe9TZAL
         DLVck/IPMjk/9MSfzEsLaqZo04OaCHTdRp4eGYVCbSEQihUo8TxpsBD6aCOK2yqHpnyl
         n1f0DEwFvMmpFO/kAxBedzDvqg0bzHkFx39/yjpp4eJTclyAcn1AmIkmu3twYJ8k6D68
         iBs5/38wAJptyD41n+bFh8iz61x3OCj7NI4jrqxDSCc9YzFvm0WKXv/cmN3nEtgeXt6P
         WjXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CPW6waRy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=H8o8+d9YyCxlAmC4UVTj7olySRzid+rySqeJU4c1Gf4=;
        b=MspE97s/ljWMRHk+o5V/u7QZkzeDcEEeA3zBr8YnmD8RUSMLjvFAoxYnjtHgSrj7iE
         F0wB8kF6bvKru71qg0Oa/yfu8A7GpSxrAJzXvOWRCryl20wCKpPUvwpW00w1O5x47Hre
         oK7JgrR8wjH6U6ocqbvmC4XgEl3eb2qC3Bwzp82yHwfwniSSXCCkqSwFIWQyThWOUOvp
         Zeql3nks+RwtE93OQhnRCeOqaJt56AVXipn84REjckz4NkEakm1ZwJpU6ZdAC6M+41Vy
         PSSmAks97GDLpMKyYLZAFtJnO14Hk62d8+UP7UFfD7OYVzCVqaJiaH+uYkFiKd39kjJw
         O7/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H8o8+d9YyCxlAmC4UVTj7olySRzid+rySqeJU4c1Gf4=;
        b=UZTKKKfzihhX9JvK+5pD0IZOEpd7+SCFhWrQP2qDF72Y+YJrQgAcgsqyKYPrl/+9Gd
         l8Ngx9/+KqduyvKorA+V2oWEpXAJuzIq99F5sU+rBh67oK1lzkq2ddOJtpC/x4k8qe2O
         hTL07r604aIousasLHXZd0yLb9SeKdQlHZW6F4Pyhcfpl/szQJUhr58drvhZkeqLsWNr
         x1dhZ9pHxZHhZDblS6+mLmE5re3oaTp7NF6jX2k9coSNSia283U1CmvHTpw/J5TKhZGX
         BKS/tU8WtGnbRo5H8noHTXgJD+sb+tNbQ3V4NWCBX5kE6QoOuVUqk48pVrrm/RmbB38C
         MRpg==
X-Gm-Message-State: AOAM530QS0oBHhIw9hizBburIJ5cX/DkC/oRzmg6SsYQ7DTNCQz6EHIt
	g5X94Y3glf6UEdyTugD5BVc=
X-Google-Smtp-Source: ABdhPJyHIcaBig4oeFYChKzhWDeAw4nXIv52Bi6b86TYA0IUpFOt60jN5S7UOAjjk1XgWPd76QD5+w==
X-Received: by 2002:aed:2b45:: with SMTP id p63mr3278530qtd.111.1610437255378;
        Mon, 11 Jan 2021 23:40:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:c001:: with SMTP id u1ls1207881qkk.1.gmail; Mon, 11 Jan
 2021 23:40:55 -0800 (PST)
X-Received: by 2002:a37:9a84:: with SMTP id c126mr3101519qke.155.1610437254949;
        Mon, 11 Jan 2021 23:40:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610437254; cv=none;
        d=google.com; s=arc-20160816;
        b=SNmBkvbObwgJlJ4JJnyJqwm3/Ov4nbKJGldUHnFnhQeIZbOBo/qUHz2xhESL5sp7Co
         bB1ZwiUivMgkeMmX4jroVzxT86EcJNVnYqX9wFFrSgSziABV8Naix69aEbJlyBrxbK38
         V35gTNGM+Vm4BmUyQAGJ8WwHSA/oFJC9Boa3XIAzczIiVgnCpB81memX/RiVRsvYKUC9
         +WCFtwvd4O+6iL4XC3o1o5VUbTP/IUypdUFKWoBxYgJ7fMX4X02TGHKFXECljtYmAC+c
         D/x4sbkuvc7Rt9N/6dRYwNOcHA/kwGWmVvlLisbWB1HXJpVt2GhPGKHBz8o+tLT83gej
         M/Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BKnokxRD1I6llLoX7662tW98pzgHQdpcOb6fgDSpfGE=;
        b=LCectmx5A90XzVeWvQfKbXimaB6MRgnw/Moz/FZbO5amdC5ck8RGSYgDtKq+rFQ/Tq
         4VvY2/RC8k+PNp6zNpuFAASGxxCG7gVWNurMiTPHC/Jz4uNc2bcmXG+Z2+hQ0z6DSLgA
         fniiAUdduag1ucoo/IfJndDAqYEn/rjaJVx9xCCjrMqBsR1iRzD//HO1vS8vPbC2DI1l
         1dKo2nQafqB0gJqKdMYEJRdt/tB/eQRm4ShU2Zslgp0OQjecR14ERFtNyIdur0CHyp/i
         eIGbc4eXlNULY0B9RU5txhyBRjhiBFuWbyFawKBIctktwthU/qc4wHcvuArXoKpUlE6s
         JEAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CPW6waRy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id n18si160842qkk.7.2021.01.11.23.40.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 23:40:54 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id h4so1133263qkk.4
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 23:40:54 -0800 (PST)
X-Received: by 2002:a37:a747:: with SMTP id q68mr3196410qke.352.1610437254475;
 Mon, 11 Jan 2021 23:40:54 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <a5dfc703ddd7eacda0ee0da083c7afad44afff8c.1609871239.git.andreyknvl@google.com>
In-Reply-To: <a5dfc703ddd7eacda0ee0da083c7afad44afff8c.1609871239.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 08:40:41 +0100
Message-ID: <CAG_fn=WOSsVPOKVS8GF8h-hHavgcqMEdbjy4Puy=bajTmW7sbg@mail.gmail.com>
Subject: Re: [PATCH 02/11] kasan: clarify HW_TAGS impact on TBI
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CPW6waRy;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wro=
te:
>
> Mention in the documentation that enabling CONFIG_KASAN_HW_TAGS
> always results in in-kernel TBI (Top Byte Ignore) being enabled.
>
> Also do a few minor documentation cleanups.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Iba2a6697e3c6304cb53f89ec6=
1dedc77fa29e3ae
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  Documentation/dev-tools/kasan.rst | 16 +++++++++++-----
>  1 file changed, 11 insertions(+), 5 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 0fc3fb1860c4..26c99852a852 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -147,15 +147,14 @@ negative values to distinguish between different ki=
nds of inaccessible memory
>  like redzones or freed memory (see mm/kasan/kasan.h).
>
>  In the report above the arrows point to the shadow byte 03, which means =
that
> -the accessed address is partially accessible.
> -
> -For tag-based KASAN this last report section shows the memory tags aroun=
d the
> -accessed address (see `Implementation details`_ section).
> +the accessed address is partially accessible. For tag-based KASAN modes =
this
> +last report section shows the memory tags around the accessed address
> +(see the `Implementation details`_ section).
>
>  Boot parameters
>  ~~~~~~~~~~~~~~~
>
> -Hardware tag-based KASAN mode (see the section about different mode belo=
w) is
> +Hardware tag-based KASAN mode (see the section about various modes below=
) is
>  intended for use in production as a security mitigation. Therefore it su=
pports
>  boot parameters that allow to disable KASAN competely or otherwise contr=
ol
>  particular KASAN features.
> @@ -305,6 +304,13 @@ reserved to tag freed memory regions.
>  Hardware tag-based KASAN currently only supports tagging of
>  kmem_cache_alloc/kmalloc and page_alloc memory.
>
> +If the hardware doesn't support MTE (pre ARMv8.5), hardware tag-based KA=
SAN
> +won't be enabled. In this case all boot parameters are ignored.
> +
> +Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI=
 being
> +enabled. Even when kasan.mode=3Doff is provided, or when the hardware do=
esn't
> +support MTE (but supports TBI).
> +
>  What memory accesses are sanitised by KASAN?
>  --------------------------------------------
>
> --
> 2.29.2.729.g45daf8777d-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWOSsVPOKVS8GF8h-hHavgcqMEdbjy4Puy%3DbajTmW7sbg%40mail.gm=
ail.com.
