Return-Path: <kasan-dev+bncBAABBBGY2KSQMGQE2B3C75Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DC2D7559C0
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jul 2023 04:48:38 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-78705f0e3fesf156943639f.1
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Jul 2023 19:48:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689562117; cv=pass;
        d=google.com; s=arc-20160816;
        b=Obqox5weNGfwVIl9ljPhGamNfEXI0vd08moolyMm0/pEqRyBbsSnCNvpF64QNxCcm1
         D+IRpw15m85lVBxuyUhWLpSIKRKDPXxBFbhF3rroFlRnTrEcs30s2mc4zifdfaQB2YFI
         cLMnUzoMQA/MAZI0IFCmmHVTQBL4W51ZmiS0km76sfMJGPVXAsRfS5JcZhG6yUypmJzN
         4klW76EuBKtQCdkePR443ls2qoeLYBfUQwZuJ3tj2ZdHzkhdv77nzxUGU0AxoQuFMb5v
         BoQWFHVMuOGe7VWQP13yKL65yauow/r/i6tblZfQZx3VmBilaMEvBuYPrM4rVDkqGR5R
         eruQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=bPCD3d7dRuNTkc6M4RkRmK9Ru5wIgOtdUXI7RT5Q/fQ=;
        fh=HY2DmbWzgLDWppENj/8AmO4BDwUdexIWkwRWEZfhCHg=;
        b=ir0hKpRFKgqdprIEtsf+uCsbEABVAWtEgpdGuvF5hQN6+dWeynuUBC9bqmhaajlTfT
         ZKtMl9xE2iY7BIvnSN/bVECuLjxk9KCFr5rXvOV5aLuqBXjVGvYsopaTSQ1YdbNQ/5Rq
         esSuJUYy1iIV3Tt5k3ac7z1z2kmue2DXR9mNLS83ij64cgD8J/UpfD8TIZkjjbewJr2E
         UK88IEAEOwX14QqTchPphoiKCY+j3SxSY+iawFWrZFN0KAUDrIcz3uDpeE2vuu5GQDnc
         9acYGZnTQlvW8MGpwwnUfNoJE48zcKxspo+2cF/cRa7UV+YkjJM7kUFr0Lf4/OguGL67
         nWmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wi8RUMiu;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689562117; x=1692154117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bPCD3d7dRuNTkc6M4RkRmK9Ru5wIgOtdUXI7RT5Q/fQ=;
        b=XBV0/zyaJrohTYHCmhWR+HDszkSqVKJ6/E2ADTd+aWlRW7pkTjfbDvNrSkNqzzWjEM
         TaguxRh0lKDGeSbu1oAzguMcA/8l+XLCCC7HPtKeJafXKFO8MSWxfH9xEfjmrqx4O5U4
         R8ziKp2NyK2ADkIVuGBoRDAutGX7jbmu1B6BHvrRdWsM2z9BvNzvzs10SVvXgJvQWT55
         rP+f2qDoG614ut4No5u9ubCu8Ltpt1EOKVDJeSmZIBKkiBFdln83joEwagAABbA0rRfg
         8HJUGqairI/ykdBgHgDN06nQ43i8CW/z0rKHPI2pR9L4wOSiuVm9ftF6vgetM4rcTSOx
         aO2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689562117; x=1692154117;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bPCD3d7dRuNTkc6M4RkRmK9Ru5wIgOtdUXI7RT5Q/fQ=;
        b=fWjqqwE+KoqUkkz1UWmOWCu1M77bryVeQN/N0Uy+XGMrZ7c5yiYLPDHHvMnp0zEvq4
         kwXNhH7iu4P1ri8Ia9P/LbQbcujAOM2gASFifwn+JYxV6pi6/ONpxJuAw8KrvcOAG+z3
         JRjmgDrF6XFwIHex+PQ0pTMR1bJ1gQ36cptiipqCjM777m6JYVzhMjNLzFbZLW/Ge0/U
         7pD9SeNLiTfgnJAaS4GaCeOKSszjQcn8ICpsvBmePcbb1BAwnK6UwxzcUzIIbhehSPio
         Og+KkWAakGn1wVomuWT3naB9CA7jAg24Gq8IYrA/qo7g9OofnTY8UTKPRVI8zEPq7PGC
         bNJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZ2px/rNL28XFQ8pvly+FEv3xkmjHGRCFa62QIlyWkXvNaDzWep
	qHxnXXubVr4W7PSlx1lJTbo=
X-Google-Smtp-Source: APBJJlEojluUf2dpWNhpmT9vQ8WeSxxb8QntOBrC2kdfBOIXmMl1Xx7GLqZeIeJvXB9ROEQ0TITfYQ==
X-Received: by 2002:a92:d4d0:0:b0:345:d58d:9ade with SMTP id o16-20020a92d4d0000000b00345d58d9ademr11219840ilm.3.1689562117048;
        Sun, 16 Jul 2023 19:48:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d05:b0:348:738d:f40 with SMTP id
 i5-20020a056e021d0500b00348738d0f40ls254090ila.2.-pod-prod-09-us; Sun, 16 Jul
 2023 19:48:36 -0700 (PDT)
X-Received: by 2002:a92:d3cc:0:b0:348:8d7c:ea95 with SMTP id c12-20020a92d3cc000000b003488d7cea95mr239955ilh.22.1689562116501;
        Sun, 16 Jul 2023 19:48:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689562116; cv=none;
        d=google.com; s=arc-20160816;
        b=hcby+nfv9NZSYb3ecFs/ykMNgpGo3WmBpUznyOcfBJeQ2cPfMapai1J+4UESbfeTP1
         FV7r+mzjqIhrSlzTie18REoZn561aWCSNlnmGvGkFlJzBdpyNHhW8UngRXeVssyukYyj
         t2P5IpHLVTVpTbkVf3tkcq0chyV6+FV0m5ewHeA+RHXE0SWaQZOcCxf3oftq4Fq71e6f
         +Jqj0S/mXFVKZhW/KGybKn1ScMKD1vIs4Vk6aW0vhJJ0uRMsDbJFWDe4bCwNylMDf4fi
         5t5yER/UJECTCRZ/lN+Cfkc6B+qILyhOVwFeqigtyloSC92Jy2BcA/VhuaoUuASkmHB4
         ne3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oXWx4FLYgjb+43zmucML9cQVTCQB8LGOvWRgGnohTww=;
        fh=HY2DmbWzgLDWppENj/8AmO4BDwUdexIWkwRWEZfhCHg=;
        b=gbAQdmoApUXdxwbo1tv46f24wDW9PbyOdpdD1iGD+o4W8kUrxPwvIN5AMC82sj7yLL
         Ag2Eo0QWHv+AEB/+nSPCxTDfZEXg7bjjY5wk0DrMOtpa3+Q7f5OMITEpV0r0kKeZ5TfV
         KYcgeAR/c3GB4EPcnFQmnZebmI5q1bhkZQ5nxS7amHgkFYf/z/+ktNM8aBajbEn7WA2L
         qEF/djTebP7pKh5l6YqPFjTdLtDt0LJN+vnNlq9/4PNKfnPEtspaLiGTo6ui2Kh2s4Cg
         9bVBVxPiJHmmz/XzF1+xNBZ/awyB6Lfw2yRwqRP2t8Qd6/F09MXwsgzyjV23m6+HvqXK
         3DHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wi8RUMiu;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id c1-20020a023f41000000b00429649d963fsi540668jaf.6.2023.07.16.19.48.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 16 Jul 2023 19:48:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CC70060F02
	for <kasan-dev@googlegroups.com>; Mon, 17 Jul 2023 02:48:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3ACDFC433CB
	for <kasan-dev@googlegroups.com>; Mon, 17 Jul 2023 02:48:35 +0000 (UTC)
Received: by mail-ed1-f48.google.com with SMTP id 4fb4d7f45d1cf-51e619bcbf9so5519781a12.3
        for <kasan-dev@googlegroups.com>; Sun, 16 Jul 2023 19:48:35 -0700 (PDT)
X-Received: by 2002:a05:6402:658:b0:51b:df62:4f0b with SMTP id
 u24-20020a056402065800b0051bdf624f0bmr9543590edx.6.1689562113445; Sun, 16 Jul
 2023 19:48:33 -0700 (PDT)
MIME-Version: 1.0
References: <20230712101344.2714626-1-chenhuacai@loongson.cn>
 <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com>
 <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com>
 <CANpmjNM_FEpXPVgoAbUwEK+9m90X54ykWnMvpUP2ZQ8sjoSByg@mail.gmail.com>
 <CAAhV-H4WUXVYv5er7UpPHKQDdBheT-UgEsOnBmPGPJ=LKWh4PQ@mail.gmail.com>
 <CANpmjNN-zypOUdJ-7XW0nN+gbGFwxC-JPFs=WA8FipsKiBhbKw@mail.gmail.com>
 <CAAhV-H7YLDQjVi8YKSv2ezz+d_wj3RPhnNchsh=HRwrf02rrCw@mail.gmail.com> <CAMuHMdUPnzfwPcTLUReVpbX5UyBdBVocWdLVAEYTyJryZ8VRcQ@mail.gmail.com>
In-Reply-To: <CAMuHMdUPnzfwPcTLUReVpbX5UyBdBVocWdLVAEYTyJryZ8VRcQ@mail.gmail.com>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Mon, 17 Jul 2023 10:48:21 +0800
X-Gmail-Original-Message-ID: <CAAhV-H43TK8hpeNQjhLjtzCucm6JU7mt5k3USt=pvVYhO+DsVA@mail.gmail.com>
Message-ID: <CAAhV-H43TK8hpeNQjhLjtzCucm6JU7mt5k3USt=pvVYhO+DsVA@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tests by removing -ffreestanding
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Huacai Chen <chenhuacai@loongson.cn>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Wi8RUMiu;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Geert,

On Fri, Jul 14, 2023 at 9:44=E2=80=AFPM Geert Uytterhoeven <geert@linux-m68=
k.org> wrote:
>
> Hi Huacai,
>
> On Fri, Jul 14, 2023 at 8:23=E2=80=AFAM Huacai Chen <chenhuacai@kernel.or=
g> wrote:
> > On Thu, Jul 13, 2023 at 6:09=E2=80=AFPM Marco Elver <elver@google.com> =
wrote:
> > > On Thu, 13 Jul 2023 at 11:58, Huacai Chen <chenhuacai@kernel.org> wro=
te:
> > > > On Thu, Jul 13, 2023 at 4:12=E2=80=AFPM Marco Elver <elver@google.c=
om> wrote:
> > > > > On Thu, 13 Jul 2023 at 06:33, Huacai Chen <chenhuacai@kernel.org>=
 wrote:
> > > > > > On Thu, Jul 13, 2023 at 12:12=E2=80=AFAM Andrey Konovalov <andr=
eyknvl@gmail.com> wrote:
> > > > > > > On Wed, Jul 12, 2023 at 12:14=E2=80=AFPM Huacai Chen <chenhua=
cai@loongson.cn> wrote:
> > > > > > > >
> > > > > > > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX hopes -fbuiltin for=
 memset()/
> > > > > > > > memcpy()/memmove() if instrumentation is needed. This is th=
e default
> > > > > > > > behavior but some archs pass -ffreestanding which implies -=
fno-builtin,
> > > > > > > > and then causes some kasan tests fail. So we remove -ffrees=
tanding for
> > > > > > > > kasan tests.
> > > > > > >
> > > > > > > Could you clarify on which architecture you observed tests fa=
ilures?
> > > > > > Observed on LoongArch [1], KASAN for LoongArch was planned to b=
e
> > > > > > merged in 6.5, but at the last minute I found some tests fail w=
ith
> > > > > > GCC14 (CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) so the patches =
are
> > > > > > dropped. After some debugging we found the root cause is
> > > > > > -ffreestanding.
> > > > > [...]
> > > > > > > >  CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> > > > > > > > +CFLAGS_REMOVE_kasan_test.o :=3D -ffreestanding
> > > > > > > >  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
> > > > > > > > +CFLAGS_REMOVE_kasan_test_module.o :=3D -ffreestanding
> > > > >
> > > > > It makes sense that if -ffreestanding is added everywhere, that t=
his
> > > > > patch fixes the test. Also see:
> > > > > https://lkml.kernel.org/r/20230224085942.1791837-3-elver@google.c=
om
> > > > >
> > > > > -ffreestanding implies -fno-builtin, which used to be added to th=
e
> > > > > test where !CC_HAS_KASAN_MEMINTRINSIC_PREFIX (old compilers).
> > > > >
> > > > > But ideally, the test doesn't have any special flags to make it p=
ass,
> > > > > because ultimately we want the test setup to be as close to other
> > > > > normal kernel code.
> > > > >
> > > > > What this means for LoongArch, is that the test legitimately is
> > > > > pointing out an issue: namely that with newer compilers, your cur=
rent
> > > > > KASAN support for LoongArch is failing to detect bad accesses wit=
hin
> > > > > mem*() functions.
> > > > >
> > > > > The reason newer compilers should emit __asan_mem*() functions an=
d
> > > > > replace normal mem*() functions, is that making mem*() functions
> > > > > always instrumented is not safe when e.g. called from uninstrumen=
ted
> > > > > code. One problem is that compilers will happily generate
> > > > > memcpy/memset calls themselves for e.g. variable initialization o=
r
> > > > > struct copies - and unfortunately -ffreestanding does _not_ prohi=
bit
> > > > > compilers from doing so: https://godbolt.org/z/hxGvdo4P9
> > > > >
> > > > > I would propose 2 options:
> > > > >
> > > > > 1. Removing -ffreestanding from LoongArch. It is unclear to me wh=
y
> > > > > this is required. As said above, -ffreestanding does not actually
> > > > > prohibit the compiler from generating implicit memset/memcpy. It
> > > > > prohibits some other optimizations, but in the kernel, you might =
even
> > > > > want those optimizations if common libcalls are already implement=
ed
> > > > > (which they should be?).
> > > > >
> > > > > 2. If KASAN is enabled on LoongArch, make memset/memcpy/memmove
> > > > > aliases to __asan_memset/__asan_memcpy/__asan_memmove. That means
> > > > > you'd have to invert how you currently set up __mem and mem funct=
ions:
> > > > > the implementation is in __mem*, and mem* functions alias __mem* =
-or-
> > > > > if KASAN is enabled __asan_mem* functions (ifdef
> > > > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX to make old compilers wor=
k as
> > > > > well).
> > > > >
> > > > > If you go with option #2 you are accepting the risk of using
> > > > > instrumented mem* functions from uninstrumented files/functions. =
This
> > > > > has been an issue for other architectures. In many cases you migh=
t get
> > > > > lucky enough that it doesn't cause issues, but that's not guarant=
eed.
> > > > Thank you for your advice, but we should keep -ffreestanding for
> > > > LoongArch, even if it may cause failing to detect bad accesses.
> > > > Because now the __builtin_memset() assumes hardware supports unalig=
ned
> > > > access, which is not the case for Loongson-2K series. If removing
> > > > -ffreestanding, Loongson-2K gets a poor performance.
> > > >
> > > > On the other hand, LoongArch is not the only architecture use
> > > > -ffreestanding, e.g., MIPS, X86_32, M68K and Xtensa also use, so th=
e
> > > > tests should get fixed.
> > >
> > > That's fair - in which case, I would recommend option #2 or some
> > > variant of it. Because fixing the test by removing -ffreestanding is
> > > just hiding that there's a real issue that needs to be fixed to have
> > > properly working KASAN on LoongArch.
> >
> > After some thinking, I found we can remove -ffreestanding in the arch
> > Makefile when KASAN is enabled -- because it is not the performance
> > critical configuration. And then, this patch can be dropped, thank
> > you.
>
> Doesn't this introduce an unwanted impact?
>
> And it's not just arch makefiles:
>
> crypto/Makefile:CFLAGS_aegis128-neon-inner.o +=3D -ffreestanding
> -march=3Darmv8-a -mfloat-abi=3Dsoftfp
> crypto/Makefile:aegis128-cflags-y :=3D -ffreestanding -mcpu=3Dgeneric+cry=
pto
> lib/Makefile:CFLAGS_string.o :=3D -ffreestanding
> lib/raid6/Makefile:NEON_FLAGS :=3D -ffreestanding
That's another story. What we are discussing in this thread is "global
-ffreestanding" which makes KASAN on mem*() globally uninstrumentable
(unexpected). On the other hand, what you mentioned here only makes
some specific files uninstrumentable, and this is an expected
behavior.

Huacai

>
> Gr{oetje,eeting}s,
>
>                         Geert
>
> --
> Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m6=
8k.org
>
> In personal conversations with technical people, I call myself a hacker. =
But
> when I'm talking to journalists I just say "programmer" or something like=
 that.
>                                 -- Linus Torvalds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H43TK8hpeNQjhLjtzCucm6JU7mt5k3USt%3DpvVYhO%2BDsVA%40mail.gm=
ail.com.
