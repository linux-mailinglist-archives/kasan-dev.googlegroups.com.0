Return-Path: <kasan-dev+bncBAABBGV3Y2LAMGQEVHOGUFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A9C1576583
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 19:02:19 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id z23-20020a2e9b97000000b0025d7496a2f2sf1282543lji.15
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 10:02:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657904539; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tdv+DdsRLPxtm7I6YNd68hR1NskT0Ma0qMnUqKjC4YX8OzFLHYk8XaSmcRqU4i8c0n
         gqpHPZXAb5rgIXUYdAKjTNiGYLCpDeZFr4GfuaY/g/NOGjm7RPnCxdB+xl4MGMT4QMuF
         +z3A4Qw+Z1MfUvkbl9s+ncMfjXQyR3CHj6WDq9qrobPVRxkn8xbP9IsXq1++afz66SQp
         41cYAE7rAU47fZWvqi8rOSKtTaVJw4Zif5T//7Z87wKbkexhoxYZU1oj+x/FM33DqHj0
         rwaA2BO9Bh1b0jv1BUMZLw8vTQ2dKxTRmbg7ulyjYPa5MeCjXaQQmZZ9iRJyv05AevBd
         5PDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DRs/VbzwUk7SyNvmbnMBtnwXR69zma9u3qX92n4kIYM=;
        b=PfR3ggmuknMkhsVGHbZ1uC8yA8V/qnv5WKa9t0tVtSSDQIXllY4tnE0GvENYdQ+co4
         oVWXx2BgNrzafg0MXLGqaXZH7eA7psXXQXYmySRpE0yChWXIlLjxCckERjV28hcYVjE9
         5/2cpcJCpkSgO8WPVdSZ/DZdCDCq4qSke5G6Dg3vs/BvGE000mt2FHyJuvIRI30KMG1k
         WRC1Le24XMT9xAa6kKoY5Jk8NiME5uocqKrfv8xLSJ/KQpp9KlvurvAEriJKFLlVNxd9
         0zEbGCjZaSaXH4gfEsS2GIhgao6crLhWgO2ThE07+mZL7Nzjmv0eGFaxREmiGM1wqf7i
         s2IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ewKkhkla;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DRs/VbzwUk7SyNvmbnMBtnwXR69zma9u3qX92n4kIYM=;
        b=PY6Wt2MBif+tbcTEzaKGz6bkjPMRnroDHjrsNMO+dfJSsp/Y4r5XDdjfOCN9wuteiG
         COAkVKbDZ9VKYCWNsgZFdXGUogwCUrfTG/i/UHf0pVPYRTe5gLjCR5IE7zelTDFIBIFx
         WKjshzU3nXBNidijPyyeqnOtITMMDbcsKwV+zRqNs4ztOo2HekRabfuTM0XU7IqJetOC
         DGsKbDC7IxClj/ZeMfPv3yIwvJTWRM1QNZSNU40fy/lyEMAe/cQxCzAWYlZHed/sUhSK
         6jJhz+2A7hI2rSmH25zf42GnS+2rH2N6DK2hvzMV9EVbt4W4yL9zUlUonwxP7zqsGOMS
         nwmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DRs/VbzwUk7SyNvmbnMBtnwXR69zma9u3qX92n4kIYM=;
        b=ikywLEOkENWbv1MbSyVJ2oduB8pQ7GvB3momxThUBAuDemjqZ9y8SmZ7pJ94RgVMF8
         oPSoOw1X0Rgjtzadca+8XJequXunJWgGQyJL62vbDB6Sc3Xx/i5liMf27hSx/8jLWLi1
         yN6WfHoNY7F8TKStk0gW0eOf4/Ta5LSa/7U7OfYkVJBMOgInjBhQeiAQwr7hbQnIddwK
         LLBD0FuI2FF4UQdJHhOgDX8ATAtbDNboiLbkB3N1bfoLLeNT5Eguai0BY4Hs9+BfEvRS
         xNYxU8JWbtc02Qn/eAOmp9zy3YoGkXaqGoIYKbDTd4MZEQyWUJd63d6Z7D6ghLTT2AtQ
         eJGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/nCNTRiEd6JF1u2D4Hc1zxU8wTLpwmJrQraVbWrFEKuU2Jc4Kw
	NIo0CBZcTyMSDyaR9GTtmIM=
X-Google-Smtp-Source: AGRyM1tSFeScOVxkjCl84HkvgbaC4CcZpTmFYF7V0+AnXrox9Z19UQxR1MO3Ct6Y8aO4qRSJTp+7ZQ==
X-Received: by 2002:a2e:2a41:0:b0:25d:832d:2af9 with SMTP id q62-20020a2e2a41000000b0025d832d2af9mr7098364ljq.429.1657904538859;
        Fri, 15 Jul 2022 10:02:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e14:b0:487:cd81:f0e6 with SMTP id
 i20-20020a0565123e1400b00487cd81f0e6ls1579630lfv.0.gmail; Fri, 15 Jul 2022
 10:02:18 -0700 (PDT)
X-Received: by 2002:a05:6512:33c9:b0:48a:27ab:cc0b with SMTP id d9-20020a05651233c900b0048a27abcc0bmr1377681lfg.250.1657904538047;
        Fri, 15 Jul 2022 10:02:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657904538; cv=none;
        d=google.com; s=arc-20160816;
        b=WEGKmy7POnhF8abOI++VPXKkCt14bpsg1TZPBdYU93UDwLobl9svH6bT5H28y3YuAw
         4Md72wiv8g8kt0oB/chEdps6njOJ4dcoABE2rh0dEkdvlMRrIuYJ5C8Tja7pnPHo81uJ
         2E3URqRlWIfHDl1VAqU+UdArkm+i+bHflTUZ/mDyqmiTzj5X1gQVgIcemq65mrKVQRz1
         EyUc7SV6zKZdMphSS9u5bE21w0H2lOyQYseX7T5q4vtFC/EdI7dbptbtRegdfFv9P9ew
         YmZXaO3/D02ncsv/AT/bQfPcGo0Q+j95jo4w7AB1jBQFxeGuQxqrtMayaxEa62orimxk
         +FRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Jm4WEsYFEXelt4jj7bpdr6k9qHo4LSaun0jfbuAJdkE=;
        b=Iy2+OIGGjV5StVPg+gsDX/pdhM8cKHzZ0Rugr6IqdhxcnLKBUGWmRi9A0OfwhPznBc
         4U0eCF62NWnmwN6BwtQ4hr6CDUaw0kDCNzCD8HnVQ7Mg4PtUXcQi2pkMroTxxPjJU9vC
         8Rzdx/lNmknklxuRLNR7QvSToqaAO77vfpUb/mloCJDn1+w8sUjxdwjvk3EapIfXEhmc
         m0Dfx1wjXcUPcIjeL+PC6Imf39nIrNfwv99NA1Sg03GA+kGktqZcaZVttmZyl2BHhQqs
         bu0w3hJmjVQJjvYedzqWl7A8pxksR4fnhXNUsXlWTGBA//E4keeI78tH5mlWiGDOD/y5
         NlBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ewKkhkla;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id v1-20020a05651203a100b0047fb02e889fsi164919lfp.2.2022.07.15.10.02.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 10:02:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 63BEFB82D22;
	Fri, 15 Jul 2022 17:02:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 59449C34115;
	Fri, 15 Jul 2022 17:02:13 +0000 (UTC)
Date: Sat, 16 Jul 2022 00:53:18 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Emil Renner Berthing <emil.renner.berthing@canonical.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Anup Patel <anup@brainfault.org>
Subject: Re: [PATCH v5 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key
 for RV64
Message-ID: <YtGbfmEl7/IkQxZp@xhacker>
References: <20220715134847.2190-1-jszhang@kernel.org>
 <20220715134847.2190-3-jszhang@kernel.org>
 <CAJM55Z8JCePV8YRheyrsO1qQie79NM_-w-cYbNaJy-HLOtPfrw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJM55Z8JCePV8YRheyrsO1qQie79NM_-w-cYbNaJy-HLOtPfrw@mail.gmail.com>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ewKkhkla;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jul 15, 2022 at 05:04:38PM +0200, Emil Renner Berthing wrote:
> On Fri, 15 Jul 2022 at 15:59, Jisheng Zhang <jszhang@kernel.org> wrote:
> > On a specific HW platform, pgtable_l4|[l5]_enabled won't change after
> > boot, and the check sits at hot code path, this characteristic makes it
> > suitable for optimization with static key.
> >
> > _pgtable_l4|[l5]_enabled is used very early during boot, even is used
> > with MMU off, so the static key mechanism isn't ready. For this case,
> > we use another static key _pgtable_lx_ready to indicate whether we
> > have finalised pgtable_l4|[l5]_enabled or not, then fall back to
> > _pgtable_l4|[l5]_enabled_early bool.
> >
> > Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> > Reviewed-by: Anup Patel <anup@brainfault.org>
> > ---
> >  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
> >  arch/riscv/include/asm/pgtable-32.h |  3 ++
> >  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
> >  arch/riscv/include/asm/pgtable.h    |  5 +--
> >  arch/riscv/kernel/cpu.c             |  4 +-
> >  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
> >  arch/riscv/mm/kasan_init.c          | 16 ++++----
> >  7 files changed, 103 insertions(+), 65 deletions(-)
> >
> > diff --git a/arch/riscv/include/asm/pgalloc.h b/arch/riscv/include/asm/pgalloc.h
> > index 947f23d7b6af..0280eeb4756f 100644
> > --- a/arch/riscv/include/asm/pgalloc.h
> > +++ b/arch/riscv/include/asm/pgalloc.h
> > @@ -41,7 +41,7 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
> >
> >  static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
> >  {
> > -       if (pgtable_l4_enabled) {
> > +       if (pgtable_l4_enabled()) {
> >                 unsigned long pfn = virt_to_pfn(pud);
> >
> >                 set_p4d(p4d, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> > @@ -51,7 +51,7 @@ static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
> >  static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
> >                                      pud_t *pud)
> >  {
> > -       if (pgtable_l4_enabled) {
> > +       if (pgtable_l4_enabled()) {
> >                 unsigned long pfn = virt_to_pfn(pud);
> >
> >                 set_p4d_safe(p4d,
> > @@ -61,7 +61,7 @@ static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
> >
> >  static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
> >  {
> > -       if (pgtable_l5_enabled) {
> > +       if (pgtable_l5_enabled()) {
> >                 unsigned long pfn = virt_to_pfn(p4d);
> >
> >                 set_pgd(pgd, __pgd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> > @@ -71,7 +71,7 @@ static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
> >  static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd,
> >                                      p4d_t *p4d)
> >  {
> > -       if (pgtable_l5_enabled) {
> > +       if (pgtable_l5_enabled()) {
> >                 unsigned long pfn = virt_to_pfn(p4d);
> >
> >                 set_pgd_safe(pgd,
> > @@ -82,7 +82,7 @@ static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd,
> >  #define pud_alloc_one pud_alloc_one
> >  static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 return __pud_alloc_one(mm, addr);
> >
> >         return NULL;
> > @@ -91,7 +91,7 @@ static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
> >  #define pud_free pud_free
> >  static inline void pud_free(struct mm_struct *mm, pud_t *pud)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 __pud_free(mm, pud);
> >  }
> >
> > @@ -100,7 +100,7 @@ static inline void pud_free(struct mm_struct *mm, pud_t *pud)
> >  #define p4d_alloc_one p4d_alloc_one
> >  static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
> >  {
> > -       if (pgtable_l5_enabled) {
> > +       if (pgtable_l5_enabled()) {
> >                 gfp_t gfp = GFP_PGTABLE_USER;
> >
> >                 if (mm == &init_mm)
> > @@ -120,7 +120,7 @@ static inline void __p4d_free(struct mm_struct *mm, p4d_t *p4d)
> >  #define p4d_free p4d_free
> >  static inline void p4d_free(struct mm_struct *mm, p4d_t *p4d)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 __p4d_free(mm, p4d);
> >  }
> >
> > diff --git a/arch/riscv/include/asm/pgtable-32.h b/arch/riscv/include/asm/pgtable-32.h
> > index 59ba1fbaf784..1ef52079179a 100644
> > --- a/arch/riscv/include/asm/pgtable-32.h
> > +++ b/arch/riscv/include/asm/pgtable-32.h
> > @@ -17,6 +17,9 @@
> >
> >  #define MAX_POSSIBLE_PHYSMEM_BITS 34
> >
> > +#define pgtable_l5_enabled() 0
> > +#define pgtable_l4_enabled() 0
> > +
> >  /*
> >   * rv32 PTE format:
> >   * | XLEN-1  10 | 9             8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0
> > diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
> > index 5c2aba5efbd0..edfff00d8ca3 100644
> > --- a/arch/riscv/include/asm/pgtable-64.h
> > +++ b/arch/riscv/include/asm/pgtable-64.h
> > @@ -8,18 +8,38 @@
> >
> >  #include <linux/bits.h>
> >  #include <linux/const.h>
> > +#include <linux/jump_label.h>
> >  #include <asm/errata_list.h>
> >
> > -extern bool pgtable_l4_enabled;
> > -extern bool pgtable_l5_enabled;
> > +extern bool _pgtable_l5_enabled_early;
> > +extern bool _pgtable_l4_enabled_early;
> > +extern struct static_key_false _pgtable_l5_enabled;
> > +extern struct static_key_false _pgtable_l4_enabled;
> > +extern struct static_key_false _pgtable_lx_ready;
> 
> It amounts to the same, but I wonder if we ought to use the
> DECLARE_STATIC_KEY_FALSE macro here.

Thanks for the hint, will send out a newer version soon. Before
that, I will wait a bit for other review feedbacks.

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YtGbfmEl7/IkQxZp%40xhacker.
