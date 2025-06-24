Return-Path: <kasan-dev+bncBAABBH5V5LBAMGQEU2GN6JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 787D4AE64F4
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jun 2025 14:31:30 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-313d6d671ffsf430481a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jun 2025 05:31:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750768289; cv=pass;
        d=google.com; s=arc-20240605;
        b=IA/lnrmYLV3vRR7A+bDIEwpof13a3vNt/8xbbHA92s0lhwARLRgPWFXKd6furOP8uY
         A74KJZnbhxBIIoziMOK98VPFc+1oACe26GRNDLyQBRaHxEKRIGMqD9QR6Bb8NZqTAezk
         IfZvsEwwuWwBf5fm4cxWc9UfhToPVU92pRi5DrUpakzaNEL6CV01R2PdrJx07WzDYWN9
         WvMuY5akFpv9kt3K27Zbm8Fs8niiBrjHaC46QnABZJUSoSkWdNasfwRCCMXdSYyla7OF
         lKhivtZUYka5khFHfD8Utw0nQi2Gojq1sZcNhyM2nSJqfxylyxgQQjC4MikSqZh9G2x1
         DAmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fCs3jv24zb0hSgCYHcnVMXQ1D1ptacBrZ+jX0xscQj4=;
        fh=G1yhrXEzSfvK79FpUwgok0W69OMI7lA60VIuyDLtJ9g=;
        b=A9kUcSoqNRInCPo0HGJhGmRy5BEsCKFIR8bp74pBAiaUjySLUAEaDUeEHta5tfIQ8F
         erACuptS/f2tPxRPUoQ89YuADaGCUG87/wkWJC4qV8gos/sHxVndGkxTjv578mKD5/X3
         ytN/cyyS9caUN/HC2/upOZcWflOUacbEo/6FftvUywXNwKjxV5wwYUpzUZsSwvKlFPm2
         QYmahLvIHDO3TXV+/lC5nmLwDyAH6vM0PuphAgy3Aym2FBjb9+HlFQLdRdPWKAjDsvKq
         wYg2APhHmYviq8jYBnfu/3mmL/rsrrL4gDsyJ03Gl2Ae/0S51AjcA0c3xoqOSfSML8Pw
         GpTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eu9htEvB;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750768289; x=1751373089; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fCs3jv24zb0hSgCYHcnVMXQ1D1ptacBrZ+jX0xscQj4=;
        b=RA+ACG4a7PTuy1vRYw8WyJWnF8JRbPKdACbSBphv+845ZQTwFJCmgnfF9lqZ4DTZh5
         jIBeq1SqZKfA/9Z8Ss+7HxrGTz3ICehXZ7wPZGyxDwGnJXwyUoM0Coa/hnqVr3tH6kTS
         l7CS0G5/5gJ8RUXJ9mtQGZDcbImQKAjRawmxWylrJj8Uy1k9vQXtx27IdqHPbyxHC52c
         ulav/Nh3KWLvltWiYfsv33lQCm6D5juWjWUaIT2oYqgnFG1qle6Pdba9a/DYjz2M+BZN
         DgNZGU4brVGdCL94URexcG3OXeQY080OrOixOYnQhnYd+JvQosBOYFXPOyUmRUcbijTk
         UeWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750768289; x=1751373089;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fCs3jv24zb0hSgCYHcnVMXQ1D1ptacBrZ+jX0xscQj4=;
        b=s5/layj1WjM0w996vhNrB5iZypOC3NrylnKx5BbssntkMuV+MNrj/Y483oMXuMbPK0
         WZAXel0PPp3AC5exVlkrP3hr0YxxYhdy+PFyWNNs6coOcpa1v59+2Br08cv6Xi8puFBX
         wMYDi4ox/kvz+hauOPFSfn3NGIJk+Cy0bd8Tqqrw8WODqUMi1qqAkE+8714hkLhOFHyL
         ehupV0L+DvCRb2Y1SWTfAHT2B8wAFGSVIm1XKHgcndfEubSdXDu33wqWji7vZxWMaU43
         Ieu9nNRm+80yETe8Vfi6ozZQXEoceXod2sjcLwbt1eCUh43315nBRHOGbkucnTgmYPpj
         miCQ==
X-Forwarded-Encrypted: i=2; AJvYcCVmSEbvgHYq6oPX3I5l+Yt8FZSezz1iShybDb5fWhEpeHFRy/LB3O0kIRqKVGOPrvTMHYh/Bg==@lfdr.de
X-Gm-Message-State: AOJu0Yy2fuv/HQJqNmX/L4O4HsQNqNz3nBnuwbeHjpVr1izv6yOr9oCi
	nHxmSk0X5Y3oLEeXqMhWazKMHerGqnEMLHEE0/o/Osc42yl6mjkDS5jJ
X-Google-Smtp-Source: AGHT+IEJSW41zoEKBPfHaEicrNoelZza7A9+dhWJri4YUxTYqIJd8YRsML1X/sM1Z9duv5c9K/GS8A==
X-Received: by 2002:a17:90b:388c:b0:311:d258:3473 with SMTP id 98e67ed59e1d1-3159d646657mr24538204a91.13.1750768288235;
        Tue, 24 Jun 2025 05:31:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfxZ4tHAXBgm6YQPLaaOeuUmFTRvD2Uinjxoslgo8HWsw==
Received: by 2002:a17:90a:3d47:b0:313:17a4:80b0 with SMTP id
 98e67ed59e1d1-3158e22b4f3ls3882395a91.0.-pod-prod-01-us; Tue, 24 Jun 2025
 05:31:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXakomd0ViZ+TBWHB9z3Ib2eKM5ikN0ISEe/8yStmyJyma3KRDOv/6ZramSYSHlVXFhuvNgSC7YLs=@googlegroups.com
X-Received: by 2002:a17:90b:3dd0:b0:313:2768:3f6b with SMTP id 98e67ed59e1d1-3159d8daaecmr24237211a91.27.1750768286828;
        Tue, 24 Jun 2025 05:31:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750768286; cv=none;
        d=google.com; s=arc-20240605;
        b=H5C8oc9pW6FwIvzNuhbbuU8BbftODocKN7JfRUpGArXhnwgc6vLQWklNeMqtpKSBWS
         Q1E5TWe4h80ZPY7RMIJVVqPFdWDEzO50EipAZU5E0n2jDz3iDDmFKozMuXMgQ5U1bOz1
         1siCh1BuHNe1LOShYL8y+DR36fGEj+xvAwOtUsshTO5KnOIvOg/v2WT/mk84f3p/KgkQ
         GLQA/+yJiNrqFhG/3TCYOriT2A9HX0D/qvZythM6udkgijiBWqBF/rtE4hfKlChU934B
         kFZGymzVsKrZpRr3jcMH+Ipf4rOZ/EaVsKnLFl2eBKL2PCIXo4gxQXyMHdpN10+v37Zi
         yoMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cpbvBFRgVNiOR52WtcQgFji4Ck6KdtyZCENW2J3nYUw=;
        fh=8RuNzelcyJssXfOhdHOPkUVPOlJAE675XEXL1K/XCQM=;
        b=E3yG4F0n6hTQ9CBt/CKmGLedhMu/dzxfz0dUimMtWzwCyqXj+/4/iMHYhqm3BM1NNZ
         V8XCSoqKLQk/fT1S0E5ykgkUbNO361D5e/S8psg8ZKJmuCUNyealkWohSGVqnJnxpDri
         fAR4mCd68kYULAtYIXid6/s5hKCMsGPgtgB3wfx16EDXj+53cyWdpsf60mw3678s5XRI
         9TZtirlD7ObfLvRCXbJIGueYhxNbzVOKMTYAwqkfYbtBDGy4EszW9pH+DvUtfYHODo2X
         mSGFdRlJVGC4V4Sp3AUz7hmq9Ggdi/MNjB26AdDHkNjyWRwBDC/1PpLwoRpT/fAuCnJu
         JOTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eu9htEvB;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-315e3a56fd6si9961a91.0.2025.06.24.05.31.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Jun 2025 05:31:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 454DA45211
	for <kasan-dev@googlegroups.com>; Tue, 24 Jun 2025 12:31:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2129DC4AF09
	for <kasan-dev@googlegroups.com>; Tue, 24 Jun 2025 12:31:26 +0000 (UTC)
Received: by mail-ed1-f42.google.com with SMTP id 4fb4d7f45d1cf-607cf70b00aso768501a12.2
        for <kasan-dev@googlegroups.com>; Tue, 24 Jun 2025 05:31:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXo+eifa1Y5x8EktMlo1828UhIe+1gYRdBaLQC1FE0ZTC5bPfWELy+7QQQwicaWefXUuWqIsHs00rw=@googlegroups.com
X-Received: by 2002:a50:9e07:0:b0:607:5987:5ba1 with SMTP id
 4fb4d7f45d1cf-60a1d1676eamr10402408a12.20.1750768284578; Tue, 24 Jun 2025
 05:31:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250523043251.it.550-kees@kernel.org> <20250523043935.2009972-10-kees@kernel.org>
 <CAAhV-H4WxAwXTYVFOnphgHN80-_6jt77YZ_rw-sOBoBjjiN-yQ@mail.gmail.com>
In-Reply-To: <CAAhV-H4WxAwXTYVFOnphgHN80-_6jt77YZ_rw-sOBoBjjiN-yQ@mail.gmail.com>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Jun 2025 20:31:12 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5oHPG+etNawAmVwyDtg80iKUrAM_m3Vj57bBO0scHqvQ@mail.gmail.com>
X-Gm-Features: AX0GCFsgXJm0uAqj4ZcBCmgCp5XFBS8cfA5fjKZVFWrLP2ySZYpAIUKeGDxIJgs
Message-ID: <CAAhV-H5oHPG+etNawAmVwyDtg80iKUrAM_m3Vj57bBO0scHqvQ@mail.gmail.com>
Subject: Re: [PATCH v2 10/14] loongarch: Handle KCOV __init vs inline mismatches
To: Kees Cook <kees@kernel.org>
Cc: Arnd Bergmann <arnd@arndb.de>, WANG Xuerui <kernel@xen0n.name>, 
	Thomas Gleixner <tglx@linutronix.de>, Tianyang Zhang <zhangtianyang@loongson.cn>, 
	Bibo Mao <maobibo@loongson.cn>, Jiaxun Yang <jiaxun.yang@flygoat.com>, loongarch@lists.linux.dev, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, Christoph Hellwig <hch@lst.de>, Marco Elver <elver@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, 
	Justin Stitt <justinstitt@google.com>, linux-kernel@vger.kernel.org, x86@kernel.org, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-hardening@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-security-module@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, sparclinux@vger.kernel.org, 
	llvm@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eu9htEvB;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Kees,

On Thu, Jun 19, 2025 at 4:55=E2=80=AFPM Huacai Chen <chenhuacai@kernel.org>=
 wrote:
>
> Hi, Kees,
>
> On Fri, May 23, 2025 at 12:39=E2=80=AFPM Kees Cook <kees@kernel.org> wrot=
e:
> >
> > When KCOV is enabled all functions get instrumented, unless
> > the __no_sanitize_coverage attribute is used. To prepare for
> > __no_sanitize_coverage being applied to __init functions, we have to
> > handle differences in how GCC's inline optimizations get resolved. For
> > loongarch this exposed several places where __init annotations were
> > missing but ended up being "accidentally correct". Fix these cases and
> > force one function to be inline with __always_inline.
> >
> > Signed-off-by: Kees Cook <kees@kernel.org>
> > ---
> > Cc: Huacai Chen <chenhuacai@kernel.org>
> > Cc: WANG Xuerui <kernel@xen0n.name>
> > Cc: Thomas Gleixner <tglx@linutronix.de>
> > Cc: Tianyang Zhang <zhangtianyang@loongson.cn>
> > Cc: Bibo Mao <maobibo@loongson.cn>
> > Cc: Jiaxun Yang <jiaxun.yang@flygoat.com>
> > Cc: <loongarch@lists.linux.dev>
> > ---
> >  arch/loongarch/include/asm/smp.h | 2 +-
> >  arch/loongarch/kernel/time.c     | 2 +-
> >  arch/loongarch/mm/ioremap.c      | 4 ++--
> >  3 files changed, 4 insertions(+), 4 deletions(-)
> >
> > diff --git a/arch/loongarch/include/asm/smp.h b/arch/loongarch/include/=
asm/smp.h
> > index ad0bd234a0f1..88e19d8a11f4 100644
> > --- a/arch/loongarch/include/asm/smp.h
> > +++ b/arch/loongarch/include/asm/smp.h
> > @@ -39,7 +39,7 @@ int loongson_cpu_disable(void);
> >  void loongson_cpu_die(unsigned int cpu);
> >  #endif
> >
> > -static inline void plat_smp_setup(void)
> > +static __always_inline void plat_smp_setup(void)
> Similar to x86 and arm, I prefer to mark it as __init rather than
> __always_inline.
If you have no objections, I will apply this patch with the above modificat=
ion.


Huacai

>
> Huacai
>
> >  {
> >         loongson_smp_setup();
> >  }
> > diff --git a/arch/loongarch/kernel/time.c b/arch/loongarch/kernel/time.=
c
> > index bc75a3a69fc8..367906b10f81 100644
> > --- a/arch/loongarch/kernel/time.c
> > +++ b/arch/loongarch/kernel/time.c
> > @@ -102,7 +102,7 @@ static int constant_timer_next_event(unsigned long =
delta, struct clock_event_dev
> >         return 0;
> >  }
> >
> > -static unsigned long __init get_loops_per_jiffy(void)
> > +static unsigned long get_loops_per_jiffy(void)
> >  {
> >         unsigned long lpj =3D (unsigned long)const_clock_freq;
> >
> > diff --git a/arch/loongarch/mm/ioremap.c b/arch/loongarch/mm/ioremap.c
> > index 70ca73019811..df949a3d0f34 100644
> > --- a/arch/loongarch/mm/ioremap.c
> > +++ b/arch/loongarch/mm/ioremap.c
> > @@ -16,12 +16,12 @@ void __init early_iounmap(void __iomem *addr, unsig=
ned long size)
> >
> >  }
> >
> > -void *early_memremap_ro(resource_size_t phys_addr, unsigned long size)
> > +void * __init early_memremap_ro(resource_size_t phys_addr, unsigned lo=
ng size)
> >  {
> >         return early_memremap(phys_addr, size);
> >  }
> >
> > -void *early_memremap_prot(resource_size_t phys_addr, unsigned long siz=
e,
> > +void * __init early_memremap_prot(resource_size_t phys_addr, unsigned =
long size,
> >                     unsigned long prot_val)
> >  {
> >         return early_memremap(phys_addr, size);
> > --
> > 2.34.1
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAhV-H5oHPG%2BetNawAmVwyDtg80iKUrAM_m3Vj57bBO0scHqvQ%40mail.gmail.com.
