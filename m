Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB36H5CFQMGQEVZHHNPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AA5343DA2B
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 06:15:43 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id v21-20020a056402349500b003dfa41553f3sf754179edc.11
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Oct 2021 21:15:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635394543; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lb1Y8GVYh9D02q9uELmZ+md1a3obrO2CYWWqBGJqr6vZ+1YMDYjhzGaB0u8sAWEQsk
         tjC1c8r7ObFs5HS40owkiNXVgc+99OgM/Rwp+JLRbCmBTwJvROaTd1d0xeZPZQfaIXwd
         vSo0XGcrfVPpiwtmCniyBDyMSmUbxeF/N9qvPby8H/x0WbnLnSC5X76GFTbATdi5yQBH
         Da/03k2K3st/+uRWMrjBtrwGXJnOaMn9EG4zq7Gcn5iOXHvOzSMcXQ6K+U3MynXV1maM
         4xB0APxZSeVGLrOsurl9WTaqhntJJGotGrZiKAIxKIbZdGqpmlRsmPYK4CuAiv/YjsJc
         srxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=848jEHS2F6N/SR6z7pIjqQR9inW0AW2+bv3pdXJWrC0=;
        b=malO/q8cwmKdmmwBsi0kUWmkD2Gw8MvfM7zPaN84tQZyiSil5KFW1vN15BjAlJ1ILM
         Gqt99Xv4kdBc5BNQ0YmhmqwU2sPK+4ojcJ5NVriRsZajGA5d41LLfTKrZ0kk758cznyE
         MHbAXjrCTuEcjtDa2fn51ngVhFFXxcGRO3yl9EuuiSuI129b4wMEEzMphn6DO68IQuj9
         IVsbVuQ/wVxL28uUIus4+2bMa7q/5nG5yIGZnm6/1io9S15oMLDkXjFWVm49cDq//vBC
         IRR26n07jIEnnfb1C4r3NcGS8pG8KgVDVp7Xup3B3tqhJWAS8Pdmuudg0QqL1GUglFmE
         PRTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=M3QmDFDw;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=848jEHS2F6N/SR6z7pIjqQR9inW0AW2+bv3pdXJWrC0=;
        b=s0lauciItYe532F5Ku1H9IyzNqCkxZ75ALOjTEMxchDP/Y6C7NtLyt/hFTPyVR6ujY
         ZG34ONFkUUbIaMfL6Nc1MG+JpGgVtKCL8EmNVoeTxO3hxDrJbBlKUxOygaH9292O51zO
         DkYhuMk7eTEBUF0oCdrhOfQkwWww/XLLFC2Z8gEDRFEdIX26BNlv8b30q9ND8hN187nM
         71LM57y3rxQXDRvI1C8oiF9YWMuubN3TWGBBPyk2OORFtRlLduUFGa0Slst6ZIZQ8QLQ
         xgmByQWdCanKPFcQHM011XK6D4jTawVmP4fSc7HsbBn4l+k/BEOmdVhHn+5A9re7Blt+
         wbAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=848jEHS2F6N/SR6z7pIjqQR9inW0AW2+bv3pdXJWrC0=;
        b=7h/IMA75AjOoP0vpuq3WrjifJSe1pxsx1n8lCwMHlyzNLXxuL88jI0M8Ej7mkmzWRm
         lpgU2SFktGMgErOygwubGWKhF9vBW5xzMjE+KRk5ltmk6G1K/oxAiv88js2XA/6DVy8Y
         krG7K6aywuAyhA25+z/YjXvHjtDOvUy48xLKho0iPu6w8Vo4Rych8admqxLXvIoHtMeW
         DTX54DN1FnFAkp37kY6UmsYzmM4dHCNl+OcKyW6AHsYFuEG9WSdGL20joFAqQDdK5ekp
         zv8lmpbh0ZlWYaNJem9XzhkK90cED5VLsVpIdI8fXQwjmqVzI/79AhCWlHKgiBIpv51T
         2+YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324du0q4MtvOW5o41TuBn5IYlCQYsJR4925HYO5Dy2rOlBIU3Db
	oQ62ZalO2KYeXZYl08d/IHA=
X-Google-Smtp-Source: ABdhPJxVJowDKaDbuHOZYo4PBwQFb3Dyz2aLirVjF2Ldo9Tl11s+DN9Pgm9ltbvS7aP2HNyvySZ8Bg==
X-Received: by 2002:a05:6402:4406:: with SMTP id y6mr2786731eda.140.1635394543193;
        Wed, 27 Oct 2021 21:15:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd17:: with SMTP id i23ls591084eds.3.gmail; Wed, 27 Oct
 2021 21:15:42 -0700 (PDT)
X-Received: by 2002:aa7:cb59:: with SMTP id w25mr2763953edt.309.1635394542333;
        Wed, 27 Oct 2021 21:15:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635394542; cv=none;
        d=google.com; s=arc-20160816;
        b=ESk5oYiRyRYDx5qldlwLD8pJJsAw3We/idQ1y0qRlZwR68l+PIqvHJJGbPx+kGVih9
         zuH7i/3rd6FA2lnmHERWBUBpUB3D8rz+hO9jh9b0svR7jEaffSxWdUPMQAos+lwQZmNs
         Muvajpy8UWcHFBxK2B21RhcFfl+b+5PyU9whc0d/O9UgsIcCHkmnWxwMpZIcwl1oSFAI
         uHM2gyORz4FdvqdPCNs+qiep/UUUtD5uz3+ajN08cmzYgNGy2MsmICpiawoSGz0/Fq54
         GhlV9PzBxDC9GYhBUubPKZiuAIUR8sSjhoxSEGf8xyF4D5t3ua6YUKpox2IQRiLHstAt
         gUYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5LeZ4qJd1/I0CO3BOhH9jstVrpNoI/oz+UiYuO/v2Z4=;
        b=rNTQAzzoiDNMP/4hSY2mhRnWqyukwyOg1jp5IOI4EXAVxKgL9fAUxkfWXs3D8X3whU
         VckcdYaHnBpXxwz+EVKINyfthM2VuDx13ceEzoWEWWguJU1TXxleHHcF7TdFUkRgjXXq
         h4Nrnne7smNOQGzn8L9NAhkCuksTlD4hGsH2koFQiEeWhLgM78ve3OHNsPnlmt4XTbLB
         7rDKbjSG/Nron9CIu9eEfVTQuAMXBSHQOD7XvYm24FGLP7s16OFhRkaqUnQ3ywsCBjvx
         RmeynHI7wPSAKvZg2fd98IgZHyGiAlD9/tFKIv7oM2VcInCgcNFQdD4pEYsZfVeJeebh
         zplg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=M3QmDFDw;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id bi21si130916edb.0.2021.10.27.21.15.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Oct 2021 21:15:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 426FA3F192
	for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 04:15:41 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id g6-20020a056402424600b003dd2b85563bso4332245edb.7
        for <kasan-dev@googlegroups.com>; Wed, 27 Oct 2021 21:15:41 -0700 (PDT)
X-Received: by 2002:a05:6402:cb8:: with SMTP id cn24mr2785989edb.190.1635394540861;
        Wed, 27 Oct 2021 21:15:40 -0700 (PDT)
X-Received: by 2002:a05:6402:cb8:: with SMTP id cn24mr2785968edb.190.1635394540704;
 Wed, 27 Oct 2021 21:15:40 -0700 (PDT)
MIME-Version: 1.0
References: <20211027045843.1770770-1-alexandre.ghiti@canonical.com> <mhng-41b64d3e-5a5a-4d59-86fc-80f2148823e8@palmerdabbelt-glaptop>
In-Reply-To: <mhng-41b64d3e-5a5a-4d59-86fc-80f2148823e8@palmerdabbelt-glaptop>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Thu, 28 Oct 2021 06:15:28 +0200
Message-ID: <CA+zEjCuUCxqTtbox2K8c=ymHC8X97LV6CSO3ydJKgRR9cBXUEw@mail.gmail.com>
Subject: Re: [PATCH 1/2] riscv: Fix asan-stack clang build
To: Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com, 
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, 
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, nathan@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=M3QmDFDw;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Thu, Oct 28, 2021 at 1:06 AM Palmer Dabbelt <palmer@dabbelt.com> wrote:
>
> On Tue, 26 Oct 2021 21:58:42 PDT (-0700), alexandre.ghiti@canonical.com wrote:
> > Nathan reported that because KASAN_SHADOW_OFFSET was not defined in
> > Kconfig, it prevents asan-stack from getting disabled with clang even
> > when CONFIG_KASAN_STACK is disabled: fix this by defining the
> > corresponding config.
> >
> > Reported-by: Nathan Chancellor <nathan@kernel.org>
> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > ---
> >  arch/riscv/Kconfig             | 6 ++++++
> >  arch/riscv/include/asm/kasan.h | 3 +--
> >  arch/riscv/mm/kasan_init.c     | 3 +++
> >  3 files changed, 10 insertions(+), 2 deletions(-)
> >
> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> > index c1abbc876e5b..79250b1ed54e 100644
> > --- a/arch/riscv/Kconfig
> > +++ b/arch/riscv/Kconfig
> > @@ -162,6 +162,12 @@ config PAGE_OFFSET
> >       default 0xffffffff80000000 if 64BIT && MAXPHYSMEM_2GB
> >       default 0xffffffe000000000 if 64BIT && MAXPHYSMEM_128GB
> >
> > +config KASAN_SHADOW_OFFSET
> > +     hex
> > +     depends on KASAN_GENERIC
> > +     default 0xdfffffc800000000 if 64BIT
> > +     default 0xffffffff if 32BIT
>
> I thought I posted this somewhere, but this is exactly what my first
> guess was.  The problem is that it's hanging on boot for me.  I don't
> really have anything exotic going on, it's just a defconfig with
> CONFIG_KASAN=y running in QEMU.
>
> Does this boot for you?

Yes with the 2nd patch of this series which fixes the issue
encountered here. And that's true I copied/pasted this part of your
patch which was better than what I had initially done, sorry I should
have mentioned you did that, please add a Codeveloped-by or something
like that.

Thanks,

Alex

>
> > +
> >  config ARCH_FLATMEM_ENABLE
> >       def_bool !NUMA
> >
> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> > index a2b3d9cdbc86..b00f503ec124 100644
> > --- a/arch/riscv/include/asm/kasan.h
> > +++ b/arch/riscv/include/asm/kasan.h
> > @@ -30,8 +30,7 @@
> >  #define KASAN_SHADOW_SIZE    (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
> >  #define KASAN_SHADOW_START   KERN_VIRT_START
> >  #define KASAN_SHADOW_END     (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> > -#define KASAN_SHADOW_OFFSET  (KASAN_SHADOW_END - (1ULL << \
> > -                                     (64 - KASAN_SHADOW_SCALE_SHIFT)))
> > +#define KASAN_SHADOW_OFFSET  _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> >
> >  void kasan_init(void);
> >  asmlinkage void kasan_early_init(void);
> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> > index d7189c8714a9..8175e98b9073 100644
> > --- a/arch/riscv/mm/kasan_init.c
> > +++ b/arch/riscv/mm/kasan_init.c
> > @@ -17,6 +17,9 @@ asmlinkage void __init kasan_early_init(void)
> >       uintptr_t i;
> >       pgd_t *pgd = early_pg_dir + pgd_index(KASAN_SHADOW_START);
> >
> > +     BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
> > +             KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
> > +
> >       for (i = 0; i < PTRS_PER_PTE; ++i)
> >               set_pte(kasan_early_shadow_pte + i,
> >                       mk_pte(virt_to_page(kasan_early_shadow_page),

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCuUCxqTtbox2K8c%3DymHC8X97LV6CSO3ydJKgRR9cBXUEw%40mail.gmail.com.
