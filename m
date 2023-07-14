Return-Path: <kasan-dev+bncBAABBEONYOSQMGQECZQLMII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A1727531C1
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jul 2023 08:09:24 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1b9e8eb2f99sf738955ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jul 2023 23:09:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689314962; cv=pass;
        d=google.com; s=arc-20160816;
        b=guj7M2kS/rmnIJjjQmUHo+IVHdmddE7hkp24LM59ajcMfjSBFgx2X1mYTmM17anT2Y
         4pkrntKAQLTXw09yjRJlunacF18dmTrxf/3ST4BqqV53T/+aJVU6fHWiC8zNG6UGAF+t
         +joRQHgoBfOTg3I6dsX+E9bsMYRasBvXR8havemkxrI8haeDGbl8INXfjcHtoPAQUU/G
         gtKcULDgGhugDWIgTKnV4BdvQDgntiedhkxqcRoBXOafWCLaDjcRqr0vdfSFYrj8zH4n
         jdiuM/QkVSy3XJxjO3HRkGjGXhF7ppQG5yAigKP2AO5jqy+IdYWkidHI0wgP/YCG9kXy
         mmzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=DxiIU49wrvqBOYpv02me/dEsm00fhQP9AVlR323dOHw=;
        fh=fMrwZ6gqbVUwX/RZa95S+UOHvY6rDNQfKRwlXb96bXM=;
        b=KI1DPiZ7v0t2zNCI88kMVb/E8lYsFJ8MX1KxjJCSRXw3gtxWHoYdik65i+XzBQjLQF
         ymup8SvC1+tdWQEdC9ZWGaNeabM8qvN7KtbOPmFVKX8/z7h6e6cccixG4/m40vz9hUOU
         NTYla33RKNdXQBalUOt5zsw9moEEb9o1vUqduO2AesnWRKiwuT5VFo1+Je1YTp/YZuPO
         r8Y8/cToD8j2pKwRbX+SVEqwmw96hZrFYT5JxHRK5/fuAlzd6efWGvvoWTXFO1g/X4SH
         z2wOL0BER5FIzSu1hiSx3ul8sks/4Ro26dKR6zln+8fm5Gmui7ALShYfLQAPrtu6SUEO
         bCEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mo6SGS+I;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689314962; x=1691906962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DxiIU49wrvqBOYpv02me/dEsm00fhQP9AVlR323dOHw=;
        b=V2MPFIjHPTr1TtMl0qmF4k1VqGNPI0j/UI94DFhjGD/EIsgsXkzE3qdpIk/QIpoj0e
         30PyLMq38Mg09VV4C19auT02IJoANJ1rkcvDl2wB4IImlPULrOT1+1tQOJnAW9Qpb6dl
         fRLljuYLkEgOc2eu8JZXVgFH0kNjgE3TDV8waBb7Sy6TYCasSVfsbsljXRKbmhx7nS2l
         nA/SyjUrb5/BNFyK/YCIHK+jy9sdWja/ANtNErffzLM0KUbkxPKzlMuL2yoe/x4cl1rM
         BYnHm1EOS/C0sBmbNlD6q5xwXFq6ThP/rCu7El9MqlKgYBM8/v5L8XYNMGN3/i13cXUV
         IugA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689314962; x=1691906962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DxiIU49wrvqBOYpv02me/dEsm00fhQP9AVlR323dOHw=;
        b=ZDPYFLOlBpoJxqe0JPi5OsjtQG3ZdoTznwdfo21STTxY0WRxDZblqW8r+Yk6TtDSBY
         s36iVcLSFnz1zwVZSVnQ+kn1anxcw0vDxm6MH/HjtNQ2flGrt1FC5+wyNojML2HDtdqX
         aJw6qj51PKFjXgIakJAfyIlskwYhKc2mm2prWSSpGrx8I5qi0DjjUiKbswcxy0eKkoA/
         +zI6fzKVSUBHwws3l5O7Tb5+6q7rd98lwxzy8HKjOdyxvoGZKnxHKsNYcs65FNJM76dj
         Lw3pKSxdNzXih8hhmbqnuMPLuC4tpgdMkSOjlVX2Pxrpwj8Qs+bB95q0xB0ooPTTiCWC
         eE/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZkw+p5rxvnTtsP7Iam9dfSgJYgjK4EJZHrRIYmjrAkq8kSquVe
	rJ9R7GX0nuC4h49H8ZwB0NQ=
X-Google-Smtp-Source: APBJJlEydfrOA5H7yl1+gCYBIPT0RnoNiKWfbVm2J+SDT5QpgJ+13UYSUB9SB4mxQf2hzWQVw1EBWg==
X-Received: by 2002:a17:902:ea02:b0:1b0:53dc:1f78 with SMTP id s2-20020a170902ea0200b001b053dc1f78mr669765plg.28.1689314962080;
        Thu, 13 Jul 2023 23:09:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:5387:b0:1b7:613c:2e91 with SMTP id
 h7-20020a056870538700b001b7613c2e91ls2353460oan.1.-pod-prod-01-us; Thu, 13
 Jul 2023 23:09:21 -0700 (PDT)
X-Received: by 2002:a05:6870:b507:b0:1ad:2e18:7086 with SMTP id v7-20020a056870b50700b001ad2e187086mr5205584oap.27.1689314961419;
        Thu, 13 Jul 2023 23:09:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689314961; cv=none;
        d=google.com; s=arc-20160816;
        b=AUcfcgQZzYB0RjtPmXaijTVKF69l/TtiLCXB7+E4h8jbH9T8rzBqmRnxszasjuv0bM
         65VNZAnwKNhNH8lXa5EKH6XVr3ngTIctQckEz9ib66cnowj34VLmgXE5tn9fQH6HBi/w
         WU96eMXStMy9p0QcRfAYZio0YmnxNRyhX6v40kzSN/rz5oTAwqG3rkgs3RXTZI/nULDv
         CQW/rTPxff3/sQKD8v5m8wcsutJ4aoZ3vZxrY2WV7Kv41ePhrHyU3kbSvTkNOSSLVSOy
         jQG4iUet7KBQvGfoJfGQnRkPQPhEgccmyd/XLGIWaT4c1l+S23mDAcucCDcWxvFlHOI6
         prqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uxjswzwjQUTBBaeQU8718j9Fgc7JFB9GLmptxvhHuVc=;
        fh=fMrwZ6gqbVUwX/RZa95S+UOHvY6rDNQfKRwlXb96bXM=;
        b=sf2Xo9NGycyKOwlBfektrnEG+uRHCuyMDc0VL+xKdpD4z2/ezus06SgEhftdif7Dz8
         55l18BzZ6ogPMVFvDU8pCkjk7UumA9evuRJppc0/hNxgXy7RAfkvJY5pjPZ58oENDhg9
         I6Ya2nnYy1IiMglfW4Ry5myXBuyHdzk780eC9OM6OGVaad7krYeE4uBmqIlTIKp+Eeh4
         R7bUA8vEpcQxSRz8A8WtmsIMb8hVLxh8gqrKJ0R9mbfPZEE20wwkrUa68STiODZtnZGU
         piCDJS/pdlg8rWp8TidAIql4SoUk/GrsK73u98jQYrAEryP6P8l2+Zv8J5DA50WIf3FM
         uIpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Mo6SGS+I;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id l14-20020a4ae2ce000000b00565ef8db272si522445oot.0.2023.07.13.23.09.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Jul 2023 23:09:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2BCBB61BCB
	for <kasan-dev@googlegroups.com>; Fri, 14 Jul 2023 06:09:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9456AC433C9
	for <kasan-dev@googlegroups.com>; Fri, 14 Jul 2023 06:09:20 +0000 (UTC)
Received: by mail-ed1-f54.google.com with SMTP id 4fb4d7f45d1cf-51e5da802afso1783418a12.3
        for <kasan-dev@googlegroups.com>; Thu, 13 Jul 2023 23:09:20 -0700 (PDT)
X-Received: by 2002:a05:6402:2038:b0:51e:293b:e1ce with SMTP id
 ay24-20020a056402203800b0051e293be1cemr3546076edb.31.1689314958865; Thu, 13
 Jul 2023 23:09:18 -0700 (PDT)
MIME-Version: 1.0
References: <20230712101344.2714626-1-chenhuacai@loongson.cn>
 <CA+fCnZd1nhG9FDzkeW42jFbPuGKZms-HzHXBiO5YTSnkmsZoZQ@mail.gmail.com>
 <CAAhV-H4nuwBJHE3VPj6yE2HUw3tDaLtgeRQ5mj0SRV6RoD8-9Q@mail.gmail.com>
 <CANpmjNM_FEpXPVgoAbUwEK+9m90X54ykWnMvpUP2ZQ8sjoSByg@mail.gmail.com>
 <CAAhV-H4WUXVYv5er7UpPHKQDdBheT-UgEsOnBmPGPJ=LKWh4PQ@mail.gmail.com> <CANpmjNN-zypOUdJ-7XW0nN+gbGFwxC-JPFs=WA8FipsKiBhbKw@mail.gmail.com>
In-Reply-To: <CANpmjNN-zypOUdJ-7XW0nN+gbGFwxC-JPFs=WA8FipsKiBhbKw@mail.gmail.com>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Fri, 14 Jul 2023 14:09:07 +0800
X-Gmail-Original-Message-ID: <CAAhV-H7YLDQjVi8YKSv2ezz+d_wj3RPhnNchsh=HRwrf02rrCw@mail.gmail.com>
Message-ID: <CAAhV-H7YLDQjVi8YKSv2ezz+d_wj3RPhnNchsh=HRwrf02rrCw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tests by removing -ffreestanding
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Huacai Chen <chenhuacai@loongson.cn>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Mo6SGS+I;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
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

Hi, Marco,

On Thu, Jul 13, 2023 at 6:09=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> On Thu, 13 Jul 2023 at 11:58, Huacai Chen <chenhuacai@kernel.org> wrote:
> >
> > Hi, Marco,
> >
> > On Thu, Jul 13, 2023 at 4:12=E2=80=AFPM Marco Elver <elver@google.com> =
wrote:
> > >
> > > On Thu, 13 Jul 2023 at 06:33, Huacai Chen <chenhuacai@kernel.org> wro=
te:
> > > >
> > > > Hi, Andrey,
> > > >
> > > > On Thu, Jul 13, 2023 at 12:12=E2=80=AFAM Andrey Konovalov <andreykn=
vl@gmail.com> wrote:
> > > > > On Wed, Jul 12, 2023 at 12:14=E2=80=AFPM Huacai Chen <chenhuacai@=
loongson.cn> wrote:
> > > > > >
> > > > > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX hopes -fbuiltin for mem=
set()/
> > > > > > memcpy()/memmove() if instrumentation is needed. This is the de=
fault
> > > > > > behavior but some archs pass -ffreestanding which implies -fno-=
builtin,
> > > > > > and then causes some kasan tests fail. So we remove -ffreestand=
ing for
> > > > > > kasan tests.
> > > > >
> > > > > Could you clarify on which architecture you observed tests failur=
es?
> > > > Observed on LoongArch [1], KASAN for LoongArch was planned to be
> > > > merged in 6.5, but at the last minute I found some tests fail with
> > > > GCC14 (CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX) so the patches are
> > > > dropped. After some debugging we found the root cause is
> > > > -ffreestanding.
> > > [...]
> > > > > >  CFLAGS_kasan_test.o :=3D $(CFLAGS_KASAN_TEST)
> > > > > > +CFLAGS_REMOVE_kasan_test.o :=3D -ffreestanding
> > > > > >  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
> > > > > > +CFLAGS_REMOVE_kasan_test_module.o :=3D -ffreestanding
> > >
> > > It makes sense that if -ffreestanding is added everywhere, that this
> > > patch fixes the test. Also see:
> > > https://lkml.kernel.org/r/20230224085942.1791837-3-elver@google.com
> > >
> > > -ffreestanding implies -fno-builtin, which used to be added to the
> > > test where !CC_HAS_KASAN_MEMINTRINSIC_PREFIX (old compilers).
> > >
> > > But ideally, the test doesn't have any special flags to make it pass,
> > > because ultimately we want the test setup to be as close to other
> > > normal kernel code.
> > >
> > > What this means for LoongArch, is that the test legitimately is
> > > pointing out an issue: namely that with newer compilers, your current
> > > KASAN support for LoongArch is failing to detect bad accesses within
> > > mem*() functions.
> > >
> > > The reason newer compilers should emit __asan_mem*() functions and
> > > replace normal mem*() functions, is that making mem*() functions
> > > always instrumented is not safe when e.g. called from uninstrumented
> > > code. One problem is that compilers will happily generate
> > > memcpy/memset calls themselves for e.g. variable initialization or
> > > struct copies - and unfortunately -ffreestanding does _not_ prohibit
> > > compilers from doing so: https://godbolt.org/z/hxGvdo4P9
> > >
> > > I would propose 2 options:
> > >
> > > 1. Removing -ffreestanding from LoongArch. It is unclear to me why
> > > this is required. As said above, -ffreestanding does not actually
> > > prohibit the compiler from generating implicit memset/memcpy. It
> > > prohibits some other optimizations, but in the kernel, you might even
> > > want those optimizations if common libcalls are already implemented
> > > (which they should be?).
> > >
> > > 2. If KASAN is enabled on LoongArch, make memset/memcpy/memmove
> > > aliases to __asan_memset/__asan_memcpy/__asan_memmove. That means
> > > you'd have to invert how you currently set up __mem and mem functions=
:
> > > the implementation is in __mem*, and mem* functions alias __mem* -or-
> > > if KASAN is enabled __asan_mem* functions (ifdef
> > > CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX to make old compilers work as
> > > well).
> > >
> > > If you go with option #2 you are accepting the risk of using
> > > instrumented mem* functions from uninstrumented files/functions. This
> > > has been an issue for other architectures. In many cases you might ge=
t
> > > lucky enough that it doesn't cause issues, but that's not guaranteed.
> > Thank you for your advice, but we should keep -ffreestanding for
> > LoongArch, even if it may cause failing to detect bad accesses.
> > Because now the __builtin_memset() assumes hardware supports unaligned
> > access, which is not the case for Loongson-2K series. If removing
> > -ffreestanding, Loongson-2K gets a poor performance.
> >
> > On the other hand, LoongArch is not the only architecture use
> > -ffreestanding, e.g., MIPS, X86_32, M68K and Xtensa also use, so the
> > tests should get fixed.
>
> That's fair - in which case, I would recommend option #2 or some
> variant of it. Because fixing the test by removing -ffreestanding is
> just hiding that there's a real issue that needs to be fixed to have
> properly working KASAN on LoongArch.
After some thinking, I found we can remove -ffreestanding in the arch
Makefile when KASAN is enabled -- because it is not the performance
critical configuration. And then, this patch can be dropped, thank
you.

Huacai

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H7YLDQjVi8YKSv2ezz%2Bd_wj3RPhnNchsh%3DHRwrf02rrCw%40mail.gm=
ail.com.
