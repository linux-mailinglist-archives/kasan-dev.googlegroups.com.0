Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBUMC2GHAMGQE233624I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 669B34841CB
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jan 2022 13:45:06 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id d8-20020ac241c8000000b0042aa94a6454sf585085lfi.8
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jan 2022 04:45:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641300306; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gel9GO5vUk7dShtjO/cch8EyGW4crgpvwXb53d4QomM6/daY9/ZYxSD1NwBdUovv3A
         b+/z1z1gwF2RTw/zXbYfmxXNHZAowojTN1VHwONsATd+B7kS8pjdZKTf07T1LZvwaOEx
         ElKCfAbQKuOBeRCXGUYbWAl5IRfSvrNLFrQO3yGEFFFXct1hKDzYINNfGAwOlEyzBnjJ
         ARDukBFlveXhb2oKoKVCTbpyoXuyXcKTYOev7HrnERC8G9gmlOu9HpxWhj5+LQScZF9S
         v+TwqJ0r+Gcbt7NTc4hMsh/56oEZs2rTrnTj+C3Xkn3wZOSsDZfk/3JV0GQMGshdJrrN
         gbFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=fDD8FkoQWBN+b5dO/Bod5thrQtsxwEYJkLwhZahcoes=;
        b=OQ7ggRly3noT9B27keUPVe+AMsx+YZg4A5AUnsMOAhIKyZt7ED4bBUthkzrxuMn1j4
         nMknnnizBcxeNOWmtejWKXH/NaWBstjfVMGH0/S3JAOBdtWl2g9zKaH0S/a0ma81N6I6
         Mq7FyZvNaTyuhcqRUh+dgW5UYICGASenF2/P9Euc0jJLlkbu6yLMzAoqvriiqQoAh+up
         PJZLrTwm2LaSB8zeKPRO7lWFQ9uKLxQJEuAd0c4aOwj77Xn87YzRF/aKMRgrKxBQhpBD
         7nv+rkn70Xk5U8i9OWR+pdjXQLlcriMWOa6ciq8fY2yjnHmGHAVthSIgDY+4aavbaiJS
         qhJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=NPdB9lRu;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fDD8FkoQWBN+b5dO/Bod5thrQtsxwEYJkLwhZahcoes=;
        b=cX2iJMzJDLqq5clD2JD43CJBJu7oM582IIFTC3PC+jG6CHr3wm1GZBGa9RZlHYX+pq
         gciqFrjtlpLPLHmftQLc7/qddhLCloj/K/8Vdh8S6QQ/ZzzLZsLVhj3WU+p3x8TSPJ4h
         mbDxuPuhtU9dxesG8ySIt0OtVPQdfJY4LnjCznwSsLkualumYHoQO36OTky+V3cs0l2j
         76FzdGmLV3O7M+cNW4l5vowzbyaClvx5yHqkqYF3OFdD1TGbsXA4Ize75hl0Mmj10Yp2
         k6ioSLo2t+Uq0raouZkM2m5MM1ChleuNp+MsaMEZxazHrwM+DdakjotvxBuQyy3vNWb8
         ig6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fDD8FkoQWBN+b5dO/Bod5thrQtsxwEYJkLwhZahcoes=;
        b=urukCfG88ozfcAPOrn57B3/B0oRpL5K/h2ub28m6b0hIREoYq+mV4Iho+J+mN/ufll
         MhyRcTyYBtb1hrfhNpV8BUdioTCqm3+nQ9+IffZ4bxni44w9kohZ58u+Piw2NTFj+ugM
         65WG0uNVFAoLrQycwLbL5tUdPXv1e0hLpHpAC0voZHbw8StVlK9zqNXRTfQU/oFbhsCu
         TszNRElSLI7pV/e8R4oMLhw5d0Fi6YP5RTYj8kW/5pZC5EEQS2VtYSS1Ozc8+QLsF+Ma
         UKyk0Ea2/rromMxSEZsqUfu6fG8OhbkhBVxoWdDQkLQuR8l3+2Q0Z915yy1cCNWL2IxY
         muPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+uQXejAqC1CjVvPeFZfHpxOh8+iR4Dv+A/aS+ziVRmxeo68SO
	j722QO+nyiwcdux+ZPqzhpA=
X-Google-Smtp-Source: ABdhPJy2aQT+CCyThPsC2tX3nasOg0FcROeRwZw0znp+gA+p3qAbvIwv0row1zFR1LKaZwTSpOes9Q==
X-Received: by 2002:a2e:b043:: with SMTP id d3mr36137052ljl.415.1641300305689;
        Tue, 04 Jan 2022 04:45:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1112:: with SMTP id l18ls730731lfg.1.gmail; Tue, 04
 Jan 2022 04:45:04 -0800 (PST)
X-Received: by 2002:a19:920a:: with SMTP id u10mr41037105lfd.262.1641300304667;
        Tue, 04 Jan 2022 04:45:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641300304; cv=none;
        d=google.com; s=arc-20160816;
        b=A3E6CSCuZXCMDR2OyZNYg0Ps7phIx/alTrWkGAYrxPsLRzIxB1qMYP10WCJbFpgU2q
         MrjUtQ3KOOHviOjUxplf+ao03YfJw2UtHsQOLHqkavtthNCxmkK4qbOn5j4fE5ph7M6f
         LmjGDA205BOrNalGrSOTLnNBrKZ/Q8F7PG6eJO5Rhf9H4O0Y7dIQiCHKzfRebMbRtzx9
         F3A4/2cMooNQ433W4IImQFON4ypfruD2O81Q7z62VyXp/VOvgjuiJQbxOmDitPpUTSbI
         Gb2ALxGtuROu6gL0e+rLqj7lL9CPBO/g/3uVdnFiScwnVnKSmgA1oUAXgrtB0E0l/pBR
         uRCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YZ5JCmNAaym5qyzS1BUndpuF29mXcWJ8PYOyUnoSSLY=;
        b=ap+IdUxmFmXMCiwV4x1MvpkFtpPmn1zVJF3lj1pKIZx82zE0pLLhRjC/jBtH3lFMSV
         +U9bDuwXA80xGS6Xb/+9XlukCdff/aW6Nb2D9gki3yLjNy9gPknSMC71KNfP1zt3/q9i
         aujQcCpqhoMIa/jFaRjggkZ0q4G+Vf7/zxO9OU1fC0UvOh/PjoYFLwh5tp2ipUmGyGp5
         wOORnAuIzFME3rg59R1bJw5Uh436BUByfB1h6n/eSuCH1hpeFoQwHdv4Y7Mlncu5G57M
         CbKlWw8YCgxTl48CKdr6KJvR1tf/89bhfVk8po9Nn7P1PCTm2aQRbH9AHzc7on4nuLza
         EOpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=NPdB9lRu;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id r3si718306ljg.3.2022.01.04.04.45.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Jan 2022 04:45:04 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com [209.85.208.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 9D3153F1BA
	for <kasan-dev@googlegroups.com>; Tue,  4 Jan 2022 12:45:03 +0000 (UTC)
Received: by mail-ed1-f69.google.com with SMTP id r8-20020a05640251c800b003f9a52daa3fso2372977edd.22
        for <kasan-dev@googlegroups.com>; Tue, 04 Jan 2022 04:45:03 -0800 (PST)
X-Received: by 2002:a05:6402:520e:: with SMTP id s14mr48812021edd.10.1641300302760;
        Tue, 04 Jan 2022 04:45:02 -0800 (PST)
X-Received: by 2002:a05:6402:520e:: with SMTP id s14mr48811999edd.10.1641300302474;
 Tue, 04 Jan 2022 04:45:02 -0800 (PST)
MIME-Version: 1.0
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
 <20211206104657.433304-8-alexandre.ghiti@canonical.com> <20211226165932.1ded6f73@xhacker>
In-Reply-To: <20211226165932.1ded6f73@xhacker>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Tue, 4 Jan 2022 13:44:51 +0100
Message-ID: <CA+zEjCvvNCet+ACj=MGiQVitOqv1-ts5AdWP6Dvwc_dr0MXCUg@mail.gmail.com>
Subject: Re: [PATCH v3 07/13] riscv: Implement sv48 support
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>, 
	Anup Patel <anup@brainfault.org>, Atish Patra <Atish.Patra@rivosinc.com>, 
	Christoph Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>, 
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>, 
	Mayuresh Chitale <mchitale@ventanamicro.com>, panqinglin2020@iscas.ac.cn, 
	linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=NPdB9lRu;       spf=pass
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

Hi Jisheng,

On Sun, Dec 26, 2021 at 10:06 AM Jisheng Zhang
<jszhang3@mail.ustc.edu.cn> wrote:
>
> On Mon,  6 Dec 2021 11:46:51 +0100
> Alexandre Ghiti <alexandre.ghiti@canonical.com> wrote:
>
> > By adding a new 4th level of page table, give the possibility to 64bit
> > kernel to address 2^48 bytes of virtual address: in practice, that offers
> > 128TB of virtual address space to userspace and allows up to 64TB of
> > physical memory.
> >
> > If the underlying hardware does not support sv48, we will automatically
> > fallback to a standard 3-level page table by folding the new PUD level into
> > PGDIR level. In order to detect HW capabilities at runtime, we
> > use SATP feature that ignores writes with an unsupported mode.
> >
> > Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
> > ---
> >  arch/riscv/Kconfig                      |   4 +-
> >  arch/riscv/include/asm/csr.h            |   3 +-
> >  arch/riscv/include/asm/fixmap.h         |   1 +
> >  arch/riscv/include/asm/kasan.h          |   6 +-
> >  arch/riscv/include/asm/page.h           |  14 ++
> >  arch/riscv/include/asm/pgalloc.h        |  40 +++++
> >  arch/riscv/include/asm/pgtable-64.h     | 108 +++++++++++-
> >  arch/riscv/include/asm/pgtable.h        |  24 ++-
> >  arch/riscv/kernel/head.S                |   3 +-
> >  arch/riscv/mm/context.c                 |   4 +-
> >  arch/riscv/mm/init.c                    | 212 +++++++++++++++++++++---
> >  arch/riscv/mm/kasan_init.c              | 137 ++++++++++++++-
> >  drivers/firmware/efi/libstub/efi-stub.c |   2 +
> >  13 files changed, 514 insertions(+), 44 deletions(-)
> >
> > diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> > index ac6c0cd9bc29..d28fe0148e13 100644
> > --- a/arch/riscv/Kconfig
> > +++ b/arch/riscv/Kconfig
> > @@ -150,7 +150,7 @@ config PAGE_OFFSET
> >       hex
> >       default 0xC0000000 if 32BIT
> >       default 0x80000000 if 64BIT && !MMU
> > -     default 0xffffffd800000000 if 64BIT
> > +     default 0xffffaf8000000000 if 64BIT
> >
> >  config KASAN_SHADOW_OFFSET
> >       hex
> > @@ -201,7 +201,7 @@ config FIX_EARLYCON_MEM
> >
> >  config PGTABLE_LEVELS
> >       int
> > -     default 3 if 64BIT
> > +     default 4 if 64BIT
> >       default 2
> >
> >  config LOCKDEP_SUPPORT
> > diff --git a/arch/riscv/include/asm/csr.h b/arch/riscv/include/asm/csr.h
> > index 87ac65696871..3fdb971c7896 100644
> > --- a/arch/riscv/include/asm/csr.h
> > +++ b/arch/riscv/include/asm/csr.h
> > @@ -40,14 +40,13 @@
> >  #ifndef CONFIG_64BIT
> >  #define SATP_PPN     _AC(0x003FFFFF, UL)
> >  #define SATP_MODE_32 _AC(0x80000000, UL)
> > -#define SATP_MODE    SATP_MODE_32
> >  #define SATP_ASID_BITS       9
> >  #define SATP_ASID_SHIFT      22
> >  #define SATP_ASID_MASK       _AC(0x1FF, UL)
> >  #else
> >  #define SATP_PPN     _AC(0x00000FFFFFFFFFFF, UL)
> >  #define SATP_MODE_39 _AC(0x8000000000000000, UL)
> > -#define SATP_MODE    SATP_MODE_39
> > +#define SATP_MODE_48 _AC(0x9000000000000000, UL)
> >  #define SATP_ASID_BITS       16
> >  #define SATP_ASID_SHIFT      44
> >  #define SATP_ASID_MASK       _AC(0xFFFF, UL)
> > diff --git a/arch/riscv/include/asm/fixmap.h b/arch/riscv/include/asm/fixmap.h
> > index 54cbf07fb4e9..58a718573ad6 100644
> > --- a/arch/riscv/include/asm/fixmap.h
> > +++ b/arch/riscv/include/asm/fixmap.h
> > @@ -24,6 +24,7 @@ enum fixed_addresses {
> >       FIX_HOLE,
> >       FIX_PTE,
> >       FIX_PMD,
> > +     FIX_PUD,
> >       FIX_TEXT_POKE1,
> >       FIX_TEXT_POKE0,
> >       FIX_EARLYCON_MEM_BASE,
> > diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/kasan.h
> > index 743e6ff57996..0b85e363e778 100644
> > --- a/arch/riscv/include/asm/kasan.h
> > +++ b/arch/riscv/include/asm/kasan.h
> > @@ -28,7 +28,11 @@
> >  #define KASAN_SHADOW_SCALE_SHIFT     3
> >
> >  #define KASAN_SHADOW_SIZE    (UL(1) << ((VA_BITS - 1) - KASAN_SHADOW_SCALE_SHIFT))
> > -#define KASAN_SHADOW_START   (KASAN_SHADOW_END - KASAN_SHADOW_SIZE)
> > +/*
> > + * Depending on the size of the virtual address space, the region may not be
> > + * aligned on PGDIR_SIZE, so force its alignment to ease its population.
> > + */
> > +#define KASAN_SHADOW_START   ((KASAN_SHADOW_END - KASAN_SHADOW_SIZE) & PGDIR_MASK)
> >  #define KASAN_SHADOW_END     MODULES_LOWEST_VADDR
> >  #define KASAN_SHADOW_OFFSET  _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> >
> > diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.h
> > index e03559f9b35e..d089fe46f7d8 100644
> > --- a/arch/riscv/include/asm/page.h
> > +++ b/arch/riscv/include/asm/page.h
> > @@ -31,7 +31,20 @@
> >   * When not using MMU this corresponds to the first free page in
> >   * physical memory (aligned on a page boundary).
> >   */
> > +#ifdef CONFIG_64BIT
> > +#ifdef CONFIG_MMU
> > +#define PAGE_OFFSET          kernel_map.page_offset
> > +#else
> > +#define PAGE_OFFSET          _AC(CONFIG_PAGE_OFFSET, UL)
> > +#endif
> > +/*
> > + * By default, CONFIG_PAGE_OFFSET value corresponds to SV48 address space so
> > + * define the PAGE_OFFSET value for SV39.
> > + */
> > +#define PAGE_OFFSET_L3               _AC(0xffffffd800000000, UL)
> > +#else
> >  #define PAGE_OFFSET          _AC(CONFIG_PAGE_OFFSET, UL)
> > +#endif /* CONFIG_64BIT */
> >
> >  /*
> >   * Half of the kernel address space (half of the entries of the page global
> > @@ -90,6 +103,7 @@ extern unsigned long riscv_pfn_base;
> >  #endif /* CONFIG_MMU */
> >
> >  struct kernel_mapping {
> > +     unsigned long page_offset;
> >       unsigned long virt_addr;
> >       uintptr_t phys_addr;
> >       uintptr_t size;
> > diff --git a/arch/riscv/include/asm/pgalloc.h b/arch/riscv/include/asm/pgalloc.h
> > index 0af6933a7100..11823004b87a 100644
> > --- a/arch/riscv/include/asm/pgalloc.h
> > +++ b/arch/riscv/include/asm/pgalloc.h
> > @@ -11,6 +11,8 @@
> >  #include <asm/tlb.h>
> >
> >  #ifdef CONFIG_MMU
> > +#define __HAVE_ARCH_PUD_ALLOC_ONE
> > +#define __HAVE_ARCH_PUD_FREE
> >  #include <asm-generic/pgalloc.h>
> >
> >  static inline void pmd_populate_kernel(struct mm_struct *mm,
> > @@ -36,6 +38,44 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
> >
> >       set_pud(pud, __pud((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> >  }
> > +
> > +static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
> > +{
> > +     if (pgtable_l4_enabled) {
> > +             unsigned long pfn = virt_to_pfn(pud);
> > +
> > +             set_p4d(p4d, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> > +     }
> > +}
> > +
> > +static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
> > +                                  pud_t *pud)
> > +{
> > +     if (pgtable_l4_enabled) {
> > +             unsigned long pfn = virt_to_pfn(pud);
> > +
> > +             set_p4d_safe(p4d,
> > +                          __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> > +     }
> > +}
> > +
> > +#define pud_alloc_one pud_alloc_one
> > +static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             return __pud_alloc_one(mm, addr);
> > +
> > +     return NULL;
> > +}
> > +
> > +#define pud_free pud_free
> > +static inline void pud_free(struct mm_struct *mm, pud_t *pud)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             __pud_free(mm, pud);
> > +}
> > +
> > +#define __pud_free_tlb(tlb, pud, addr)  pud_free((tlb)->mm, pud)
> >  #endif /* __PAGETABLE_PMD_FOLDED */
> >
> >  static inline pgd_t *pgd_alloc(struct mm_struct *mm)
> > diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
> > index 228261aa9628..bbbdd66e5e2f 100644
> > --- a/arch/riscv/include/asm/pgtable-64.h
> > +++ b/arch/riscv/include/asm/pgtable-64.h
> > @@ -8,16 +8,36 @@
> >
> >  #include <linux/const.h>
> >
> > -#define PGDIR_SHIFT     30
> > +extern bool pgtable_l4_enabled;
> > +
> > +#define PGDIR_SHIFT_L3  30
> > +#define PGDIR_SHIFT_L4  39
> > +#define PGDIR_SIZE_L3   (_AC(1, UL) << PGDIR_SHIFT_L3)
> > +
> > +#define PGDIR_SHIFT     (pgtable_l4_enabled ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3)
> >  /* Size of region mapped by a page global directory */
> >  #define PGDIR_SIZE      (_AC(1, UL) << PGDIR_SHIFT)
> >  #define PGDIR_MASK      (~(PGDIR_SIZE - 1))
> >
> > +/* pud is folded into pgd in case of 3-level page table */
> > +#define PUD_SHIFT      30
> > +#define PUD_SIZE       (_AC(1, UL) << PUD_SHIFT)
> > +#define PUD_MASK       (~(PUD_SIZE - 1))
> > +
> >  #define PMD_SHIFT       21
> >  /* Size of region mapped by a page middle directory */
> >  #define PMD_SIZE        (_AC(1, UL) << PMD_SHIFT)
> >  #define PMD_MASK        (~(PMD_SIZE - 1))
> >
> > +/* Page Upper Directory entry */
> > +typedef struct {
> > +     unsigned long pud;
> > +} pud_t;
> > +
> > +#define pud_val(x)      ((x).pud)
> > +#define __pud(x)        ((pud_t) { (x) })
> > +#define PTRS_PER_PUD    (PAGE_SIZE / sizeof(pud_t))
> > +
> >  /* Page Middle Directory entry */
> >  typedef struct {
> >       unsigned long pmd;
> > @@ -59,6 +79,16 @@ static inline void pud_clear(pud_t *pudp)
> >       set_pud(pudp, __pud(0));
> >  }
> >
> > +static inline pud_t pfn_pud(unsigned long pfn, pgprot_t prot)
> > +{
> > +     return __pud((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
> > +}
> > +
> > +static inline unsigned long _pud_pfn(pud_t pud)
> > +{
> > +     return pud_val(pud) >> _PAGE_PFN_SHIFT;
> > +}
> > +
> >  static inline pmd_t *pud_pgtable(pud_t pud)
> >  {
> >       return (pmd_t *)pfn_to_virt(pud_val(pud) >> _PAGE_PFN_SHIFT);
> > @@ -69,6 +99,17 @@ static inline struct page *pud_page(pud_t pud)
> >       return pfn_to_page(pud_val(pud) >> _PAGE_PFN_SHIFT);
> >  }
> >
> > +#define mm_pud_folded  mm_pud_folded
> > +static inline bool mm_pud_folded(struct mm_struct *mm)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             return false;
> > +
> > +     return true;
> > +}
> > +
> > +#define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
> > +
> >  static inline pmd_t pfn_pmd(unsigned long pfn, pgprot_t prot)
> >  {
> >       return __pmd((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
> > @@ -84,4 +125,69 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
> >  #define pmd_ERROR(e) \
> >       pr_err("%s:%d: bad pmd %016lx.\n", __FILE__, __LINE__, pmd_val(e))
> >
> > +#define pud_ERROR(e)   \
> > +     pr_err("%s:%d: bad pud %016lx.\n", __FILE__, __LINE__, pud_val(e))
> > +
> > +static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             *p4dp = p4d;
> > +     else
> > +             set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
> > +}
> > +
> > +static inline int p4d_none(p4d_t p4d)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             return (p4d_val(p4d) == 0);
> > +
> > +     return 0;
> > +}
> > +
> > +static inline int p4d_present(p4d_t p4d)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             return (p4d_val(p4d) & _PAGE_PRESENT);
> > +
> > +     return 1;
> > +}
> > +
> > +static inline int p4d_bad(p4d_t p4d)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             return !p4d_present(p4d);
> > +
> > +     return 0;
> > +}
> > +
> > +static inline void p4d_clear(p4d_t *p4d)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             set_p4d(p4d, __p4d(0));
> > +}
> > +
> > +static inline pud_t *p4d_pgtable(p4d_t p4d)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             return (pud_t *)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
> > +
> > +     return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) });
> > +}
> > +
> > +static inline struct page *p4d_page(p4d_t p4d)
> > +{
> > +     return pfn_to_page(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
> > +}
> > +
> > +#define pud_index(addr) (((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))
> > +
> > +#define pud_offset pud_offset
> > +static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
> > +{
> > +     if (pgtable_l4_enabled)
> > +             return p4d_pgtable(*p4d) + pud_index(address);
> > +
> > +     return (pud_t *)p4d;
> > +}
> > +
> >  #endif /* _ASM_RISCV_PGTABLE_64_H */
> > diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> > index e1a52e22ad7e..e1c74ef4ead2 100644
> > --- a/arch/riscv/include/asm/pgtable.h
> > +++ b/arch/riscv/include/asm/pgtable.h
> > @@ -51,7 +51,7 @@
> >   * position vmemmap directly below the VMALLOC region.
> >   */
> >  #ifdef CONFIG_64BIT
> > -#define VA_BITS              39
> > +#define VA_BITS              (pgtable_l4_enabled ? 48 : 39)
> >  #else
> >  #define VA_BITS              32
> >  #endif
> > @@ -90,8 +90,7 @@
> >
> >  #ifndef __ASSEMBLY__
> >
> > -/* Page Upper Directory not used in RISC-V */
> > -#include <asm-generic/pgtable-nopud.h>
> > +#include <asm-generic/pgtable-nop4d.h>
> >  #include <asm/page.h>
> >  #include <asm/tlbflush.h>
> >  #include <linux/mm_types.h>
> > @@ -113,6 +112,17 @@
> >  #define XIP_FIXUP(addr)              (addr)
> >  #endif /* CONFIG_XIP_KERNEL */
> >
> > +struct pt_alloc_ops {
> > +     pte_t *(*get_pte_virt)(phys_addr_t pa);
> > +     phys_addr_t (*alloc_pte)(uintptr_t va);
> > +#ifndef __PAGETABLE_PMD_FOLDED
> > +     pmd_t *(*get_pmd_virt)(phys_addr_t pa);
> > +     phys_addr_t (*alloc_pmd)(uintptr_t va);
> > +     pud_t *(*get_pud_virt)(phys_addr_t pa);
> > +     phys_addr_t (*alloc_pud)(uintptr_t va);
> > +#endif
> > +};
> > +
> >  #ifdef CONFIG_MMU
> >  /* Number of entries in the page global directory */
> >  #define PTRS_PER_PGD    (PAGE_SIZE / sizeof(pgd_t))
> > @@ -669,9 +679,11 @@ static inline pmd_t pmdp_establish(struct vm_area_struct *vma,
> >   * Note that PGDIR_SIZE must evenly divide TASK_SIZE.
> >   */
> >  #ifdef CONFIG_64BIT
> > -#define TASK_SIZE (PGDIR_SIZE * PTRS_PER_PGD / 2)
> > +#define TASK_SIZE      (PGDIR_SIZE * PTRS_PER_PGD / 2)
> > +#define TASK_SIZE_MIN  (PGDIR_SIZE_L3 * PTRS_PER_PGD / 2)
> >  #else
> > -#define TASK_SIZE FIXADDR_START
> > +#define TASK_SIZE    FIXADDR_START
> > +#define TASK_SIZE_MIN        TASK_SIZE
> >  #endif
> >
> >  #else /* CONFIG_MMU */
> > @@ -697,6 +709,8 @@ extern uintptr_t _dtb_early_pa;
> >  #define dtb_early_va _dtb_early_va
> >  #define dtb_early_pa _dtb_early_pa
> >  #endif /* CONFIG_XIP_KERNEL */
> > +extern u64 satp_mode;
> > +extern bool pgtable_l4_enabled;
> >
> >  void paging_init(void);
> >  void misc_mem_init(void);
> > diff --git a/arch/riscv/kernel/head.S b/arch/riscv/kernel/head.S
> > index 52c5ff9804c5..c3c0ed559770 100644
> > --- a/arch/riscv/kernel/head.S
> > +++ b/arch/riscv/kernel/head.S
> > @@ -95,7 +95,8 @@ relocate:
> >
> >       /* Compute satp for kernel page tables, but don't load it yet */
> >       srl a2, a0, PAGE_SHIFT
> > -     li a1, SATP_MODE
> > +     la a1, satp_mode
> > +     REG_L a1, 0(a1)
> >       or a2, a2, a1
> >
> >       /*
> > diff --git a/arch/riscv/mm/context.c b/arch/riscv/mm/context.c
> > index ee3459cb6750..a7246872bd30 100644
> > --- a/arch/riscv/mm/context.c
> > +++ b/arch/riscv/mm/context.c
> > @@ -192,7 +192,7 @@ static void set_mm_asid(struct mm_struct *mm, unsigned int cpu)
> >  switch_mm_fast:
> >       csr_write(CSR_SATP, virt_to_pfn(mm->pgd) |
> >                 ((cntx & asid_mask) << SATP_ASID_SHIFT) |
> > -               SATP_MODE);
> > +               satp_mode);
> >
> >       if (need_flush_tlb)
> >               local_flush_tlb_all();
> > @@ -201,7 +201,7 @@ static void set_mm_asid(struct mm_struct *mm, unsigned int cpu)
> >  static void set_mm_noasid(struct mm_struct *mm)
> >  {
> >       /* Switch the page table and blindly nuke entire local TLB */
> > -     csr_write(CSR_SATP, virt_to_pfn(mm->pgd) | SATP_MODE);
> > +     csr_write(CSR_SATP, virt_to_pfn(mm->pgd) | satp_mode);
> >       local_flush_tlb_all();
> >  }
> >
> > diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> > index 1552226fb6bd..6a19a1b1caf8 100644
> > --- a/arch/riscv/mm/init.c
> > +++ b/arch/riscv/mm/init.c
> > @@ -37,6 +37,17 @@ EXPORT_SYMBOL(kernel_map);
> >  #define kernel_map   (*(struct kernel_mapping *)XIP_FIXUP(&kernel_map))
> >  #endif
> >
> > +#ifdef CONFIG_64BIT
> > +u64 satp_mode = !IS_ENABLED(CONFIG_XIP_KERNEL) ? SATP_MODE_48 : SATP_MODE_39;
> > +#else
> > +u64 satp_mode = SATP_MODE_32;
> > +#endif
> > +EXPORT_SYMBOL(satp_mode);
> > +
> > +bool pgtable_l4_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL) ?
> > +                             true : false;
>
> Hi Alex,
>
> I'm not sure whether we can use static key for pgtable_l4_enabled or
> not. Obviously, for a specific HW platform, pgtable_l4_enabled won't change
> after boot, and it seems it sits hot code path, so IMHO, static key maybe
> suitable for it.

Thanks for the suggestion, I'll explore that after this series is
merged if you don't mind.

Thanks,

Alex

>
> Thanks
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BzEjCvvNCet%2BACj%3DMGiQVitOqv1-ts5AdWP6Dvwc_dr0MXCUg%40mail.gmail.com.
