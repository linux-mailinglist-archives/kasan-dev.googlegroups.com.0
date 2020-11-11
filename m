Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2MRWD6QKGQE7UA7JEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id CA1A82AF580
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:53:14 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id v20sf1417728plo.3
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:53:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605109993; cv=pass;
        d=google.com; s=arc-20160816;
        b=f6icY3LGRItkZmGGVHeq5GLD/bxKDX/iNsBDejzEvgO1jGtT3fY0bw0Yz5v5XSJT4E
         eNfGCsOD+pKgIMfu0v0u7PflhFiWbn+lKTTFoakwt8XVwwC/ri49bP4uSIQa/2fLfkth
         //5Q6m/9tncLrm4JDR3ojAhL7CAS/4fWzVCwbHX9DrL+U8NY1Pbi2hMoSa7jpYQcwr6j
         NUFIQvL3eCYmtqLnUAwaghR4+OWVM32rpulmSVbswzGLHIHDD8y9MLAZH8Y3XV4Anz6T
         VyFHYogVW8/povqGN53ArKgKxO+dnHZ77vpUi134bIcZ1bmpqzE1cQPlHMre9RlV4KUP
         d5MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1v3VCeSP+CZ6Yt0Qsk3qI1iuMbVEXK5uVCVudYQaJz8=;
        b=irUqPNvQKdupmdspt/o3VSfZ81+gkIdeULCQhprVN7XBsGepBNYkQ+VuTOGNXPXAWX
         6tbrD0bsXzoYA8QbaLlwx+hbir+9hagCdPI+7J92a5WbhiAHTe08pw3ojCn8fftSUGoN
         olTDcRJDCC0K7+saXUe0De+Oc7HjqT1i0paeOwtrDwhrH8FuJ5tO+w6gnul+2c8SikyG
         R2APwbwjAr1rOJPMzxUx4SaICLkcTXl+at2xODtEnch7/nuAAZyy4a9IqxZ8QigYGc/g
         znLwZTMN1R2s4HnIwbxUj/9Upe9F1+OAqHgsfV8duAnZ04SFy04akjcIW/GHKMr/+7nL
         VYFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eNIdoik2;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=1v3VCeSP+CZ6Yt0Qsk3qI1iuMbVEXK5uVCVudYQaJz8=;
        b=kQi8KLGD8Ncz6emoVLwk+iYWCLREhwiguRlYFiaWyWxO9RwudQhzC0pyZCuMaA3Bx5
         Yo8a2c8IBxE7HlYf1FD41v3/2SFtCEVmFIDDufKqFaFNY+OKw102QOQY5apFNYFWJarR
         IFWakWSBceHRPjOOD2nh+ysUSxs64bMaGnL+7o1SkI5YvigoQOEkfjsb9MxBO8QoZKl7
         zKlC/iXdYGo2DW6OPt/rXUNJ3sY5BdmtNI37PJWeCYSifFu6tIawMs8CMHH5e6+zjxIY
         hmkxVMkMS4PVHFYeDBmPqxwyIIjdJvSf7A7sLyvHgg8ZMrgzZsUtUNbUYWSXahmTSCkE
         2VBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1v3VCeSP+CZ6Yt0Qsk3qI1iuMbVEXK5uVCVudYQaJz8=;
        b=UbP/oZGrl2UZh0dx+be9m92xGCNJp5kJlPDj8cBIu3DWwaa45WX/ZH5/7qXsuodMd7
         TDKOs0O4G8uN82TmI/Gho8YWfJbvYL8eC5Paaz9N0KFEIAmdUEbbOjcJQFikhKnkAUDT
         xMvxgmo05G7t8Yowu+yaPLlEdSW0LmrsneOeuBNGdk1TG04y4IHtqBCa5BC13wabX9KX
         CuRVFmlP7Eb0pO/582Nk8VP1CQ1cMSYTs7XonvzquRvXeBOr1vVij6L/r7xQIiSDIaiE
         fAyIuHXoXYUD8yZSsHo95PoR+eOflGnuTvHFjwaffUnNXOGuE3csfpMsG7Elsof6tAob
         PZmw==
X-Gm-Message-State: AOAM530/hV1f/T0tbcW82yCF+0TP+ghSMYgizlo3xpyn9CIRp4GVHjQ7
	PBd9iKqctH18OaPPhKKOVUg=
X-Google-Smtp-Source: ABdhPJxgL/asB4xvJZYM9S7GF2soHv2JuH1Y15MolhZhiQKRLoUsij3/zXEvw/y1VHxTXftIr7Ge0A==
X-Received: by 2002:aa7:8d14:0:b029:18b:8e8d:81e8 with SMTP id j20-20020aa78d140000b029018b8e8d81e8mr23089327pfe.14.1605109993502;
        Wed, 11 Nov 2020 07:53:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4e13:: with SMTP id c19ls42130pgb.9.gmail; Wed, 11 Nov
 2020 07:53:13 -0800 (PST)
X-Received: by 2002:a63:5d05:: with SMTP id r5mr20477331pgb.442.1605109992778;
        Wed, 11 Nov 2020 07:53:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605109992; cv=none;
        d=google.com; s=arc-20160816;
        b=i2cJ7qSfJh4pdAaX6tppSmUFn0xnTrdp9uaFyo4L9CyTTh6zIlvBhEI+wKaYvE2aQd
         hzekKt9Zulr1nmH3GUWCMCr2I4DYSlR6crkKUoFGINq771QeJSbzqOCI9xvvNDzMDisY
         C+xlw984kXAH/Gmk6RUkRLpra0TK9uYEmtWDVOz8qG/GyDOxMS61oKfvLYvzOqNzd+I7
         pHQo+GTs/zr0djZTxme5/w29c1Yg4KUqxzw0VSUsvQnM7EZBClR42cJi5xLqqHkxihRx
         usg2b0ooqS19TW5WvHEGVZRtXCkOfMQMT7qzm4nuwvz8D02gsrB0AutpMkCcIcjCCJSb
         DhvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=vRyAuwdRnLChBCBVFGTKtTcLQ1KujUMWRxgegUE/csw=;
        b=unwGZPHvhyXQBWnUMTvWGdo0aywBPFGST30UfnspW+LlWPtjRXaPOgkbk2UtI1ljxk
         KdevPvrPWkf1EJyaFl1GrZ5r0C1c/JyDFhhe5UIDfQUlS4dpneTuDL1UJffEZVDFBiIS
         8ECfSBVOTp1fs5eycAU0P9sgi9euWWQ+iaUQhSvLXud6tWPN9C7I8qObG8xUpiby2rQO
         KkFw4hOOH5FsAS4Dn31uc/E1uC90FIyzkAc9GR3xEQzb0MEpAlIzpOdlHOYnuLsI3+mb
         zir8/nMQb+LONi+DGjK9CZo1PlSUWekZ+6Q0kjsshpgzenQ0JaND0p87cTfHEUOvXgZ6
         drdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eNIdoik2;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id bd7si129083plb.0.2020.11.11.07.53.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:53:12 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id d9so2068150qke.8
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:53:12 -0800 (PST)
X-Received: by 2002:a37:bf04:: with SMTP id p4mr26719528qkf.326.1605109991955;
 Wed, 11 Nov 2020 07:53:11 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <67c17dafa28036b628234c8f1d88368af374449c.1605046192.git.andreyknvl@google.com>
In-Reply-To: <67c17dafa28036b628234c8f1d88368af374449c.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:52:59 +0100
Message-ID: <CAG_fn=UmcSrfwvuh36EXj-H1ZkwGxmVwqCm8GD5XZdkqOWpqAA@mail.gmail.com>
Subject: Re: [PATCH v9 24/44] kasan, arm64: don't allow SW_TAGS with ARM64_MTE
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eNIdoik2;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::742 as
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

On Tue, Nov 10, 2020 at 11:12 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Software tag-based KASAN provides its own tag checking machinery that
> can conflict with MTE. Don't allow enabling software tag-based KASAN
> when MTE is enabled.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: Icd29bd0c6b1d3d7a0ee3d50c20490f404d34fc97
> ---
>  arch/arm64/Kconfig | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 1515f6f153a0..25ead11074bf 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -134,7 +134,7 @@ config ARM64
>         select HAVE_ARCH_JUMP_LABEL
>         select HAVE_ARCH_JUMP_LABEL_RELATIVE
>         select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> -       select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> +       select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
>         select HAVE_ARCH_KGDB
>         select HAVE_ARCH_MMAP_RND_BITS
>         select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
> --
> 2.29.2.222.g5d2a92d10f8-goog
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/67c17dafa28036b628234c8f1d88368af374449c.1605046192.git.andreyk=
nvl%40google.com.



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
kasan-dev/CAG_fn%3DUmcSrfwvuh36EXj-H1ZkwGxmVwqCm8GD5XZdkqOWpqAA%40mail.gmai=
l.com.
