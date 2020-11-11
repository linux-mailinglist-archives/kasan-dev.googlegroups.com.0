Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJPGV76QKGQEK5Q74SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0196D2AF363
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:20:24 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id j43sf328121ooa.5
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:20:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605104423; cv=pass;
        d=google.com; s=arc-20160816;
        b=bY0QKrd2dQpdReyrKxB0mzBfVTOOnd5fLZjqmAuglmob+kieUTml0YGpJcxKbGfZi5
         54mAhFOKbyLq3zPM5JNgHSKl3JaXpj392mXYkIKMEs67/+O+fJUqF78BENyZ8V073qCh
         cynX0T4N8EW1qVNSDtAaminDcuN9aJBk38mMQ6Ji+a5iB1SDLhBpbkHOWK4GL8gNIjWt
         s6a2315GdQXc/NKbr9eyehixH6c+X8KR3fBfPuyu26+Zi5B0zlCGHDAMHJfcBD/6QAEj
         EJzke7noceGv9PY81kbhwk2uM/SP2gIpJtrRe/pnC7WR8Ui4LdhT8yV7y/cu+SY4MXkv
         ogFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mriRT1rc9csK28cHfHTWbTHpJWJ/udsgVNmdnQSmZoE=;
        b=yOUAlhdWN3TcRMIeqKvYMNnvLIUfBH47KxQA54mwR54LZ6R/U9pMUPr586aTf+uvMz
         kp4dhdKGgspPAHA+ufS/GFHi9BqHpUqbpAka8rjcFFQW/CHkwTYw7N9zLw/nSpY2STE+
         C80AoNYGroOOzw2pWCrqV1tz2N/MGYb0eGwU1RQch/um1WhCWOHzyvmz3Ugc2aWtoT7Z
         zOVrafsI9R4OIhtgijH48CMTI1ivN7c7/Ont5cButwypiF/G1KuwoOlz6FXHLhjvTqZb
         FTnqeTGiPgiG/BfTelKFkcNfjv0r6y87t7Y1snDYrrPitZ241gdHyH0h5sZt6rtwBTB3
         /vuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GFal+cQo;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mriRT1rc9csK28cHfHTWbTHpJWJ/udsgVNmdnQSmZoE=;
        b=nUzk17+GLNf/MZ9dVjnZM0/ksSSepEcw3aM7RKvKJ6ob1XCZOMVLxJr9BucyxINQqN
         W+0R8vdPCWr3cKCI/buDX+EZWGgFBFZKqy2nYCmonQyA2vu6ouo/y2tZzBBoB9KATjt5
         Y1MBM5W0WK2BoR200jC//Z8792J2N0uvWrWNfXMYr+X3trhrf1Kekrlb+jF55y4sX6w6
         K7iazodG/uWn+xDY0VEpXo5LbI5jMlgnyEDEVcGq/HQNaIkLDzJ/wjPVh5r9ZGGrWLX6
         lTtjdjIiVmyB3UHWdlnX06/9O/i1zm7eRPUlP6q9VkUnTgDbk0arMBM9C8/Cam+F9D3Z
         kL/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mriRT1rc9csK28cHfHTWbTHpJWJ/udsgVNmdnQSmZoE=;
        b=JPWO+Uz/InHWc8pRHBQ/5rlic3BaBgHKiFdF6TBM5XhbjTXlSmiYVldUWcE+rZcIhO
         FXKjJQSbvl9iDkibnIvkWoTRkQk/zQtTzRFbHMMFDfe01wjwV88yMKT/rsIfAmzXvbY0
         Jmx8jix86MPiAw/ZDD0A9gcK829v9TfpgcpuCBsyQLVMdp2tFm6sltEp/pZR2krGK+9o
         myQd2UF2x+IRw2CsktaVN3pSfrhKMI56kPcW9n+C8kDSdKjicKJyuxvSsijbd/ssBNBo
         f5gWeS8zZXKL0TUvOMjWcBKZ/L4PP21ioH/9IXvhlm/KuSeGAbbAsC8jgj3PWgqk8/VC
         mkYA==
X-Gm-Message-State: AOAM5314i6OWcTzCn3YQPxRJVC5phtLRB0/BbWF2AChIKNzauF9XgsGE
	speRN6SphkjUTw/aKtRxfXo=
X-Google-Smtp-Source: ABdhPJwsP5CvtKZjnDg/7AzQpZL9aDHF5ciUhtHxWPHcpN3OcwCBsnJ4A5nPZoXjY46/yNaXX7CaRg==
X-Received: by 2002:a9d:22e4:: with SMTP id y91mr17773233ota.72.1605104421147;
        Wed, 11 Nov 2020 06:20:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1ca0:: with SMTP id l32ls1220248ota.5.gmail; Wed, 11 Nov
 2020 06:20:19 -0800 (PST)
X-Received: by 2002:a05:6830:1e7a:: with SMTP id m26mr11881365otr.104.1605104419288;
        Wed, 11 Nov 2020 06:20:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605104419; cv=none;
        d=google.com; s=arc-20160816;
        b=rkJ6nucV4eojaxt3DVhUHZbZBeAhkH4i9VP+pufw98tsNZac1T1uh0z+Oc24NbAolV
         aBAI5hmQf2weJOPJPy5G93tjn+4lMfFuWbS3vwyKN7qEormcpSNylX6lKD5SGkOJRcjA
         O386lIEReVFrHl1L1wgQBUZsde2ANH6DmrAeP+kUBmribnILrJ/aDBrRMQoOJIAq2An/
         xKa0xC0CChp9LkeaYjirfZP3Q0etdA5XmadBLIKn/k1vaFnfCSEQosoUGx/nfKGGYPrO
         Si+fF5oUqL5qLM/CBwiQt/tKOG5qZhePoHsdt8vGRBNCuvQGvWT/scB0DYEfKaMfgzTf
         dq/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JMEn4lYfqSDEvjbMdtc4A2bwMj+MmSPwjJgTPuD5gJo=;
        b=zPQpx7WlJ3+3P5Lv5EDZmgXtL78v9hCCO3/HP5EFYOVYNnGiVOzRqUKL8BLyNTFPkl
         11VtS0YTp/BGx2yHbTpJI5h+5ZbylvG4au4MMYXJTWNpsltMd9VdutLnKsoAeKBIHst1
         zrl/MMvYKjKZY9wfVjDw2PMEnBmnlU8GuZXFr5TmJZPzGfaoovnm24rsLz8PkpXv9mw0
         xNor4TB1AhDT+4PR4/LyP/S/R8DXUwZTfp3vxfSIIyhxm50TWFOhDSV8Jxd3FT6SDRYj
         VjSD2nS3FZxbttWcDqZkppq4WQLibopzj/XrF6MrH3niWZODL4sUyMv3Pj2hy56D0XhK
         FmsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GFal+cQo;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id i23si146072oto.5.2020.11.11.06.20.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:20:19 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id i12so1370619qtj.0
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:20:19 -0800 (PST)
X-Received: by 2002:ac8:5c85:: with SMTP id r5mr18883719qta.8.1605104418550;
 Wed, 11 Nov 2020 06:20:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <fc3f94183e4229363d0a891abc791af5b85d20f7.1605046192.git.andreyknvl@google.com>
In-Reply-To: <fc3f94183e4229363d0a891abc791af5b85d20f7.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:20:07 +0100
Message-ID: <CAG_fn=Vojbt7Cqb=oiEsda1f4RpUXmfR7Pd38Tiadk1Vy2-uQQ@mail.gmail.com>
Subject: Re: [PATCH v9 12/44] kasan: don't duplicate config dependencies
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
 header.i=@google.com header.s=20161025 header.b=GFal+cQo;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Both KASAN_GENERIC and KASAN_SW_TAGS have common dependencies, move
> those to KASAN.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: I77e475802e8f1750b9154fe4a6e6da4456054fcd
> ---
>  lib/Kconfig.kasan | 8 ++------
>  1 file changed, 2 insertions(+), 6 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 8f0742a0f23e..ec59a0e26d09 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -24,6 +24,8 @@ menuconfig KASAN
>                    (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
>         depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
>         depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
> +       select CONSTRUCTORS
> +       select STACKDEPOT
>         help
>           Enables KASAN (KernelAddressSANitizer) - runtime memory debugge=
r,
>           designed to find out-of-bounds accesses and use-after-free bugs=
.
> @@ -46,10 +48,7 @@ choice
>  config KASAN_GENERIC
>         bool "Generic mode"
>         depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
> -       depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
>         select SLUB_DEBUG if SLUB
> -       select CONSTRUCTORS
> -       select STACKDEPOT
>         help
>           Enables generic KASAN mode.
>
> @@ -70,10 +69,7 @@ config KASAN_GENERIC
>  config KASAN_SW_TAGS
>         bool "Software tag-based mode"
>         depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
> -       depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
>         select SLUB_DEBUG if SLUB
> -       select CONSTRUCTORS
> -       select STACKDEPOT
>         help
>           Enables software tag-based KASAN mode.
>
> --
> 2.29.2.222.g5d2a92d10f8-goog
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
kasan-dev/CAG_fn%3DVojbt7Cqb%3DoiEsda1f4RpUXmfR7Pd38Tiadk1Vy2-uQQ%40mail.gm=
ail.com.
