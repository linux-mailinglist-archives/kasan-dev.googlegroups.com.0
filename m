Return-Path: <kasan-dev+bncBAABBQ4W6GKAMGQEQPYUX4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id E8A0A53DA62
	for <lists+kasan-dev@lfdr.de>; Sun,  5 Jun 2022 08:20:52 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id e3-20020a2e9303000000b00249765c005csf1699575ljh.17
        for <lists+kasan-dev@lfdr.de>; Sat, 04 Jun 2022 23:20:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654410052; cv=pass;
        d=google.com; s=arc-20160816;
        b=u1fxxFIeDIvAKxDPmhQynvkfmS+8iQdZVbiHQT8v4/lkhAuzZyB8op8hEfoTpuknRm
         vQTvgIGcqln/xhiYb6XriBvRjOFr82ry1E5Im7lLmIteEQWwp7ZG+auhJHai2E8qfgZN
         Nj4sLOqRFQw/NIvE/IseyqvvwiHlB8qrS1QtZuxd4+6HrZGtWjjEkzl3zMQw26WBQVYY
         bkhbQyMKfChhriUnO8ZNFueG5sHXnRPlig5Wq8wQbiFUGBlY3MUiz3MC67GV4tYUfgsa
         FQtF7qOyKK89qROSBKrNdZx/TSLJ3/FIVyJ7445r8dV1iREUea2BbyaAHU9uwC30u98M
         eR9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jT04Sb14e9fjookqIkafb9P4M56hme+DJaZrhStLtIg=;
        b=nSaUEwdbIyUKq86lXJgUobUMxbmARllddzMNBk0cstiDIXOz/sLhjrMddSpEjbcYuD
         o65htvDEPYEx0NFuFMva7XCq1Vg9Rsho/2SQf+bV72dDMdDXWfSrOzixml42lkLnC8pt
         8fOeqNiUsQQkkbOgR3ZYvw5jOhHWOrLgs51fsZPz9xzNNAkxovI2eZHRAiiXGaDZF0lh
         Sn2/yZYgXaUoONkJwcxuGh5doNXWJLjadxaVVi58wzl1PedELCAqCINRetjqZav5urhK
         euhlCveYBKE1z12OWEv1dwfTnjh8luH7N8jH5gtDiGohSl1Hj+wLTjAz0P8eT4Rvq+mn
         P5tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JT+d31vg;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jT04Sb14e9fjookqIkafb9P4M56hme+DJaZrhStLtIg=;
        b=Ot3R7UvcRNrtE7BpS+ufX/10ugO+/acBG9rZTu/BT2CdFnPa8n23XRd+ZWphAmVsi9
         L7G2EKPs2Du6dnIWOj0fqoge/GoeZw7rr+BCaBCRhcu8ZrgayQ+5zd+C976SihqRk8+H
         rupZhHz2fDNilx+DjqYy/x4kYUUvUaTkF3sEgNopP1VY+EPOL1fhifLL3MKN5btHKRc6
         EY5kypVmV3noJ4yTxNW+pPNNaid4F4VKBDUGpTtGfsOAWFBNUh523eUy4NYAuHbhM4me
         d4q1WNcoQ9zWHfCNUnkJl82SEewozzX4iiwonK7Q3t6mbdKDEe6OOc6Z9EV4iaSlMI9Y
         DlBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jT04Sb14e9fjookqIkafb9P4M56hme+DJaZrhStLtIg=;
        b=336javbEbsBRHhhxrXnQwIvGqrj5pCQUP5p0AAuzdKGNQe+FslTyY9BZ25aNpHFfoM
         DQ/f+k3JEaSBxazdjFeq2UW/QBvL5T/syQBMw68eEawnM9msol0Zbvto5WMQ8s9ClRSo
         /fnqtmnccvr+eQL3bNNqkryhDALxiEooiBDSQTO4hQ2z4aDXsQ/vOEyKXl2JHd9nJ1+3
         Qo+Gu8cMyAaQgUcHE0kv2eFbE0k7pwUH6oOMREyCRP7dEpmDA5MzfR+Ild+NuJ5025el
         7Vi4MEgJcQdqACUxYiczaFBvELVsCjc5O7NwwVOROjhoHLoPJZqOjc7LpUa/s76jsMtO
         OQrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531c6cMQU3SXpZRyze5yvOxXsTCGrhv314V3cgxBK3lA/6M2rr4h
	3ZNKvk379jaXCHIiasb0kFk=
X-Google-Smtp-Source: ABdhPJwxBkEDWNY0y812OFW2ION2LGemrpv5qSeXHEScIB3zT0YbHj3e5Q74nvr3d6Twl5opP874kQ==
X-Received: by 2002:a2e:93c6:0:b0:24d:422f:f8f0 with SMTP id p6-20020a2e93c6000000b0024d422ff8f0mr49351327ljh.469.1654410052219;
        Sat, 04 Jun 2022 23:20:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls2675364lfu.0.gmail; Sat, 04 Jun 2022
 23:20:51 -0700 (PDT)
X-Received: by 2002:a05:6512:1288:b0:479:40f2:d885 with SMTP id u8-20020a056512128800b0047940f2d885mr550559lfs.660.1654410051102;
        Sat, 04 Jun 2022 23:20:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654410051; cv=none;
        d=google.com; s=arc-20160816;
        b=tVwoRN9rkYCR0J+peSmADaHZhGTXJhvh7D/ddT+vw5M4SqzHYxwYwhhqMXzqzVaVWF
         DxiH7afJsJiTVsr3h7xDiXtYWzwao66I7My4aHduOiHgxzFMZFiUbCjvk0APY0aE4rvo
         4ejceEozPpjAB3LQbUzC90VUhC79m9Wr1ZSJUsNl6bbbHxE9HJKwuXBPZVOwfKEU7Y60
         4NUdnfx0j8jDmAvjjeVsc9IZCHLzsK81UiPvYsIvnpjhuLzmkoMVHbFioBa8xpf0BrkS
         mb2tg60x7B5q2yYLQSOpGOnUwCGKqP8u/6U8Ys7MZuaX+njx65YsJJ0YZYHe5egA0kJc
         brCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oVFLOAekByO/Ed7InKSS0vhTtHNm4mSSDUKlfIEuzv4=;
        b=XFixL74lpa5CC9HJz0RK071fCsfLQXddk0oiecVJ4z5TOJk7gdUznOOVTgZDAJbRs6
         i1vzzsVbZNqgoJaB4SO5OxekOU5YeAyJXWH+QVX7iXvv1V/Jx2fL6WuNljxXzjumdt/O
         XNp8UAuIezYpcgwZ8Pq7fx5k+RKkYom4HN7VfWQwe+YWi8iDuzIqmqX2rCuw3MuVALme
         X1z4vd4jTFUIf/uNKPe9ZET4AyPbRJD1l6KpCX260SAsj+2VGaP1jNpCAj+/gccdP8r4
         l74MEjG9lWFe6ycfp3dBOim78YHdsC6+K8G6EChcQqvfszDHUXkt62hDItk//zaUTMUT
         Nsjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JT+d31vg;
       spf=pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id b14-20020a0565120b8e00b004785b6eac92si565568lfv.7.2022.06.04.23.20.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 04 Jun 2022 23:20:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 35822B80749;
	Sun,  5 Jun 2022 06:20:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BFBD0C385A5;
	Sun,  5 Jun 2022 06:20:45 +0000 (UTC)
Date: Sun, 5 Jun 2022 14:12:07 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Anup Patel <anup@brainfault.org>, Palmer Dabbelt <palmer@dabbelt.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Atish Patra <atishp@rivosinc.com>,
	linux-riscv <linux-riscv@lists.infradead.org>,
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key
 for RV64
Message-ID: <YpxJN6d5l2b6ZTVr@xhacker>
References: <20220521143456.2759-1-jszhang@kernel.org>
 <20220521143456.2759-3-jszhang@kernel.org>
 <CAAhSdy0xVy8-UnNAKdCHRz8QANbTRwGiotFWCjPOiPuDMo+YTQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAhSdy0xVy8-UnNAKdCHRz8QANbTRwGiotFWCjPOiPuDMo+YTQ@mail.gmail.com>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JT+d31vg;       spf=pass
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

On Tue, May 24, 2022 at 09:29:04PM +0530, Anup Patel wrote:
> On Sat, May 21, 2022 at 8:13 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> >
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

Hi Palmer,

This series is missing for riscv v5.19 part2. Or Is there anything I
can do to improve the series?

Thanks in advance

> 
> Looks good to me.
> 
> Reviewed-by: Anup Patel <anup@brainfault.org>
> 
> Regards,
> Anup
> 
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
> > index 5b2e79e5bfa5..8af36d76b70d 100644
> > --- a/arch/riscv/include/asm/pgtable-32.h
> > +++ b/arch/riscv/include/asm/pgtable-32.h
> > @@ -16,4 +16,7 @@
> >
> >  #define MAX_POSSIBLE_PHYSMEM_BITS 34
> >
> > +#define pgtable_l5_enabled() 0
> > +#define pgtable_l4_enabled() 0
> > +
> >  #endif /* _ASM_RISCV_PGTABLE_32_H */
> > diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
> > index 7e246e9f8d70..d14a3a8f1f4b 100644
> > --- a/arch/riscv/include/asm/pgtable-64.h
> > +++ b/arch/riscv/include/asm/pgtable-64.h
> > @@ -7,17 +7,37 @@
> >  #define _ASM_RISCV_PGTABLE_64_H
> >
> >  #include <linux/const.h>
> > +#include <linux/jump_label.h>
> >
> > -extern bool pgtable_l4_enabled;
> > -extern bool pgtable_l5_enabled;
> > +extern bool _pgtable_l5_enabled_early;
> > +extern bool _pgtable_l4_enabled_early;
> > +extern struct static_key_false _pgtable_l5_enabled;
> > +extern struct static_key_false _pgtable_l4_enabled;
> > +extern struct static_key_false _pgtable_lx_ready;
> > +
> > +static __always_inline bool pgtable_l5_enabled(void)
> > +{
> > +       if (static_branch_likely(&_pgtable_lx_ready))
> > +               return static_branch_likely(&_pgtable_l5_enabled);
> > +       else
> > +               return _pgtable_l5_enabled_early;
> > +}
> > +
> > +static __always_inline bool pgtable_l4_enabled(void)
> > +{
> > +       if (static_branch_likely(&_pgtable_lx_ready))
> > +               return static_branch_likely(&_pgtable_l4_enabled);
> > +       else
> > +               return _pgtable_l4_enabled_early;
> > +}
> >
> >  #define PGDIR_SHIFT_L3  30
> >  #define PGDIR_SHIFT_L4  39
> >  #define PGDIR_SHIFT_L5  48
> >  #define PGDIR_SIZE_L3   (_AC(1, UL) << PGDIR_SHIFT_L3)
> >
> > -#define PGDIR_SHIFT     (pgtable_l5_enabled ? PGDIR_SHIFT_L5 : \
> > -               (pgtable_l4_enabled ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3))
> > +#define PGDIR_SHIFT     (pgtable_l5_enabled() ? PGDIR_SHIFT_L5 : \
> > +               (pgtable_l4_enabled() ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3))
> >  /* Size of region mapped by a page global directory */
> >  #define PGDIR_SIZE      (_AC(1, UL) << PGDIR_SHIFT)
> >  #define PGDIR_MASK      (~(PGDIR_SIZE - 1))
> > @@ -119,7 +139,7 @@ static inline struct page *pud_page(pud_t pud)
> >  #define mm_p4d_folded  mm_p4d_folded
> >  static inline bool mm_p4d_folded(struct mm_struct *mm)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 return false;
> >
> >         return true;
> > @@ -128,7 +148,7 @@ static inline bool mm_p4d_folded(struct mm_struct *mm)
> >  #define mm_pud_folded  mm_pud_folded
> >  static inline bool mm_pud_folded(struct mm_struct *mm)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 return false;
> >
> >         return true;
> > @@ -159,7 +179,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
> >
> >  static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 *p4dp = p4d;
> >         else
> >                 set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
> > @@ -167,7 +187,7 @@ static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
> >
> >  static inline int p4d_none(p4d_t p4d)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 return (p4d_val(p4d) == 0);
> >
> >         return 0;
> > @@ -175,7 +195,7 @@ static inline int p4d_none(p4d_t p4d)
> >
> >  static inline int p4d_present(p4d_t p4d)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 return (p4d_val(p4d) & _PAGE_PRESENT);
> >
> >         return 1;
> > @@ -183,7 +203,7 @@ static inline int p4d_present(p4d_t p4d)
> >
> >  static inline int p4d_bad(p4d_t p4d)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 return !p4d_present(p4d);
> >
> >         return 0;
> > @@ -191,7 +211,7 @@ static inline int p4d_bad(p4d_t p4d)
> >
> >  static inline void p4d_clear(p4d_t *p4d)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 set_p4d(p4d, __p4d(0));
> >  }
> >
> > @@ -207,7 +227,7 @@ static inline unsigned long _p4d_pfn(p4d_t p4d)
> >
> >  static inline pud_t *p4d_pgtable(p4d_t p4d)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 return (pud_t *)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
> >
> >         return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) });
> > @@ -224,7 +244,7 @@ static inline struct page *p4d_page(p4d_t p4d)
> >  #define pud_offset pud_offset
> >  static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
> >  {
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 return p4d_pgtable(*p4d) + pud_index(address);
> >
> >         return (pud_t *)p4d;
> > @@ -232,7 +252,7 @@ static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
> >
> >  static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 *pgdp = pgd;
> >         else
> >                 set_p4d((p4d_t *)pgdp, (p4d_t){ pgd_val(pgd) });
> > @@ -240,7 +260,7 @@ static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
> >
> >  static inline int pgd_none(pgd_t pgd)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 return (pgd_val(pgd) == 0);
> >
> >         return 0;
> > @@ -248,7 +268,7 @@ static inline int pgd_none(pgd_t pgd)
> >
> >  static inline int pgd_present(pgd_t pgd)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 return (pgd_val(pgd) & _PAGE_PRESENT);
> >
> >         return 1;
> > @@ -256,7 +276,7 @@ static inline int pgd_present(pgd_t pgd)
> >
> >  static inline int pgd_bad(pgd_t pgd)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 return !pgd_present(pgd);
> >
> >         return 0;
> > @@ -264,13 +284,13 @@ static inline int pgd_bad(pgd_t pgd)
> >
> >  static inline void pgd_clear(pgd_t *pgd)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 set_pgd(pgd, __pgd(0));
> >  }
> >
> >  static inline p4d_t *pgd_pgtable(pgd_t pgd)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 return (p4d_t *)pfn_to_virt(pgd_val(pgd) >> _PAGE_PFN_SHIFT);
> >
> >         return (p4d_t *)p4d_pgtable((p4d_t) { pgd_val(pgd) });
> > @@ -288,7 +308,7 @@ static inline struct page *pgd_page(pgd_t pgd)
> >  #define p4d_offset p4d_offset
> >  static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
> >  {
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 return pgd_pgtable(*pgd) + p4d_index(address);
> >
> >         return (p4d_t *)pgd;
> > diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> > index 046b44225623..ae01a9b83ac4 100644
> > --- a/arch/riscv/include/asm/pgtable.h
> > +++ b/arch/riscv/include/asm/pgtable.h
> > @@ -63,8 +63,8 @@
> >   * position vmemmap directly below the VMALLOC region.
> >   */
> >  #ifdef CONFIG_64BIT
> > -#define VA_BITS                (pgtable_l5_enabled ? \
> > -                               57 : (pgtable_l4_enabled ? 48 : 39))
> > +#define VA_BITS                (pgtable_l5_enabled() ? \
> > +                               57 : (pgtable_l4_enabled() ? 48 : 39))
> >  #else
> >  #define VA_BITS                32
> >  #endif
> > @@ -738,7 +738,6 @@ extern uintptr_t _dtb_early_pa;
> >  #define dtb_early_pa   _dtb_early_pa
> >  #endif /* CONFIG_XIP_KERNEL */
> >  extern u64 satp_mode;
> > -extern bool pgtable_l4_enabled;
> >
> >  void paging_init(void);
> >  void misc_mem_init(void);
> > diff --git a/arch/riscv/kernel/cpu.c b/arch/riscv/kernel/cpu.c
> > index ccb617791e56..29bb0ef75248 100644
> > --- a/arch/riscv/kernel/cpu.c
> > +++ b/arch/riscv/kernel/cpu.c
> > @@ -141,9 +141,9 @@ static void print_mmu(struct seq_file *f)
> >  #if defined(CONFIG_32BIT)
> >         strncpy(sv_type, "sv32", 5);
> >  #elif defined(CONFIG_64BIT)
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 strncpy(sv_type, "sv57", 5);
> > -       else if (pgtable_l4_enabled)
> > +       else if (pgtable_l4_enabled())
> >                 strncpy(sv_type, "sv48", 5);
> >         else
> >                 strncpy(sv_type, "sv39", 5);
> > diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> > index 05ed641a1134..42c79388e6fd 100644
> > --- a/arch/riscv/mm/init.c
> > +++ b/arch/riscv/mm/init.c
> > @@ -44,10 +44,16 @@ u64 satp_mode __ro_after_init = SATP_MODE_32;
> >  #endif
> >  EXPORT_SYMBOL(satp_mode);
> >
> > -bool pgtable_l4_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> > -bool pgtable_l5_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> > -EXPORT_SYMBOL(pgtable_l4_enabled);
> > -EXPORT_SYMBOL(pgtable_l5_enabled);
> > +DEFINE_STATIC_KEY_FALSE(_pgtable_l4_enabled);
> > +DEFINE_STATIC_KEY_FALSE(_pgtable_l5_enabled);
> > +DEFINE_STATIC_KEY_FALSE(_pgtable_lx_ready);
> > +EXPORT_SYMBOL(_pgtable_l4_enabled);
> > +EXPORT_SYMBOL(_pgtable_l5_enabled);
> > +EXPORT_SYMBOL(_pgtable_lx_ready);
> > +bool _pgtable_l4_enabled_early = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> > +bool _pgtable_l5_enabled_early = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> > +EXPORT_SYMBOL(_pgtable_l4_enabled_early);
> > +EXPORT_SYMBOL(_pgtable_l5_enabled_early);
> >
> >  phys_addr_t phys_ram_base __ro_after_init;
> >  EXPORT_SYMBOL(phys_ram_base);
> > @@ -555,26 +561,26 @@ static void __init create_p4d_mapping(p4d_t *p4dp,
> >  }
> >
> >  #define pgd_next_t             p4d_t
> > -#define alloc_pgd_next(__va)   (pgtable_l5_enabled ?                   \
> > -               pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled ?          \
> > +#define alloc_pgd_next(__va)   (pgtable_l5_enabled() ?                 \
> > +               pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled() ?        \
> >                 pt_ops.alloc_pud(__va) : pt_ops.alloc_pmd(__va)))
> > -#define get_pgd_next_virt(__pa)        (pgtable_l5_enabled ?                   \
> > -               pt_ops.get_p4d_virt(__pa) : (pgd_next_t *)(pgtable_l4_enabled ? \
> > +#define get_pgd_next_virt(__pa)        (pgtable_l5_enabled() ?                 \
> > +               pt_ops.get_p4d_virt(__pa) : (pgd_next_t *)(pgtable_l4_enabled() ?       \
> >                 pt_ops.get_pud_virt(__pa) : (pud_t *)pt_ops.get_pmd_virt(__pa)))
> >  #define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot)     \
> > -                               (pgtable_l5_enabled ?                   \
> > +                               (pgtable_l5_enabled() ?                 \
> >                 create_p4d_mapping(__nextp, __va, __pa, __sz, __prot) : \
> > -                               (pgtable_l4_enabled ?                   \
> > +                               (pgtable_l4_enabled() ?                 \
> >                 create_pud_mapping((pud_t *)__nextp, __va, __pa, __sz, __prot) :        \
> >                 create_pmd_mapping((pmd_t *)__nextp, __va, __pa, __sz, __prot)))
> > -#define fixmap_pgd_next                (pgtable_l5_enabled ?                   \
> > -               (uintptr_t)fixmap_p4d : (pgtable_l4_enabled ?           \
> > +#define fixmap_pgd_next                (pgtable_l5_enabled() ?                 \
> > +               (uintptr_t)fixmap_p4d : (pgtable_l4_enabled() ?         \
> >                 (uintptr_t)fixmap_pud : (uintptr_t)fixmap_pmd))
> > -#define trampoline_pgd_next    (pgtable_l5_enabled ?                   \
> > -               (uintptr_t)trampoline_p4d : (pgtable_l4_enabled ?       \
> > +#define trampoline_pgd_next    (pgtable_l5_enabled() ?                 \
> > +               (uintptr_t)trampoline_p4d : (pgtable_l4_enabled() ?     \
> >                 (uintptr_t)trampoline_pud : (uintptr_t)trampoline_pmd))
> > -#define early_dtb_pgd_next     (pgtable_l5_enabled ?                   \
> > -               (uintptr_t)early_dtb_p4d : (pgtable_l4_enabled ?        \
> > +#define early_dtb_pgd_next     (pgtable_l5_enabled() ?                 \
> > +               (uintptr_t)early_dtb_p4d : (pgtable_l4_enabled() ?      \
> >                 (uintptr_t)early_dtb_pud : (uintptr_t)early_dtb_pmd))
> >  #else
> >  #define pgd_next_t             pte_t
> > @@ -680,14 +686,14 @@ static __init pgprot_t pgprot_from_va(uintptr_t va)
> >  #ifdef CONFIG_64BIT
> >  static void __init disable_pgtable_l5(void)
> >  {
> > -       pgtable_l5_enabled = false;
> > +       _pgtable_l5_enabled_early = false;
> >         kernel_map.page_offset = PAGE_OFFSET_L4;
> >         satp_mode = SATP_MODE_48;
> >  }
> >
> >  static void __init disable_pgtable_l4(void)
> >  {
> > -       pgtable_l4_enabled = false;
> > +       _pgtable_l4_enabled_early = false;
> >         kernel_map.page_offset = PAGE_OFFSET_L3;
> >         satp_mode = SATP_MODE_39;
> >  }
> > @@ -816,11 +822,11 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
> >                            PGDIR_SIZE,
> >                            IS_ENABLED(CONFIG_64BIT) ? PAGE_TABLE : PAGE_KERNEL);
> >
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 create_p4d_mapping(early_dtb_p4d, DTB_EARLY_BASE_VA,
> >                                    (uintptr_t)early_dtb_pud, P4D_SIZE, PAGE_TABLE);
> >
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 create_pud_mapping(early_dtb_pud, DTB_EARLY_BASE_VA,
> >                                    (uintptr_t)early_dtb_pmd, PUD_SIZE, PAGE_TABLE);
> >
> > @@ -961,11 +967,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
> >
> >  #ifndef __PAGETABLE_PMD_FOLDED
> >         /* Setup fixmap P4D and PUD */
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 create_p4d_mapping(fixmap_p4d, FIXADDR_START,
> >                                    (uintptr_t)fixmap_pud, P4D_SIZE, PAGE_TABLE);
> >         /* Setup fixmap PUD and PMD */
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 create_pud_mapping(fixmap_pud, FIXADDR_START,
> >                                    (uintptr_t)fixmap_pmd, PUD_SIZE, PAGE_TABLE);
> >         create_pmd_mapping(fixmap_pmd, FIXADDR_START,
> > @@ -973,10 +979,10 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
> >         /* Setup trampoline PGD and PMD */
> >         create_pgd_mapping(trampoline_pg_dir, kernel_map.virt_addr,
> >                            trampoline_pgd_next, PGDIR_SIZE, PAGE_TABLE);
> > -       if (pgtable_l5_enabled)
> > +       if (pgtable_l5_enabled())
> >                 create_p4d_mapping(trampoline_p4d, kernel_map.virt_addr,
> >                                    (uintptr_t)trampoline_pud, P4D_SIZE, PAGE_TABLE);
> > -       if (pgtable_l4_enabled)
> > +       if (pgtable_l4_enabled())
> >                 create_pud_mapping(trampoline_pud, kernel_map.virt_addr,
> >                                    (uintptr_t)trampoline_pmd, PUD_SIZE, PAGE_TABLE);
> >  #ifdef CONFIG_XIP_KERNEL
> > @@ -1165,8 +1171,18 @@ static void __init reserve_crashkernel(void)
> >         crashk_res.end = crash_base + crash_size - 1;
> >  }
> >
> > +static void __init riscv_finalise_pgtable_lx(void)
> > +{
> > +       if (_pgtable_l5_enabled_early)
> > +               static_branch_enable(&_pgtable_l5_enabled);
> > +       if (_pgtable_l4_enabled_early)
> > +               static_branch_enable(&_pgtable_l4_enabled);
> > +       static_branch_enable(&_pgtable_lx_ready);
> > +}
> > +
> >  void __init paging_init(void)
> >  {
> > +       riscv_finalise_pgtable_lx();
> >         setup_bootmem();
> >         setup_vm_final();
> >  }
> > diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> > index a22e418dbd82..356044498e8a 100644
> > --- a/arch/riscv/mm/kasan_init.c
> > +++ b/arch/riscv/mm/kasan_init.c
> > @@ -209,15 +209,15 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
> >                 set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
> >  }
> >
> > -#define kasan_early_shadow_pgd_next                    (pgtable_l5_enabled ?   \
> > +#define kasan_early_shadow_pgd_next                    (pgtable_l5_enabled() ? \
> >                                 (uintptr_t)kasan_early_shadow_p4d :             \
> > -                                                       (pgtable_l4_enabled ?   \
> > +                                                       (pgtable_l4_enabled() ? \
> >                                 (uintptr_t)kasan_early_shadow_pud :             \
> >                                 (uintptr_t)kasan_early_shadow_pmd))
> >  #define kasan_populate_pgd_next(pgdp, vaddr, next, early)                      \
> > -               (pgtable_l5_enabled ?                                           \
> > +               (pgtable_l5_enabled() ?                                         \
> >                 kasan_populate_p4d(pgdp, vaddr, next, early) :                  \
> > -               (pgtable_l4_enabled ?                                           \
> > +               (pgtable_l4_enabled() ?                                         \
> >                         kasan_populate_pud(pgdp, vaddr, next, early) :          \
> >                         kasan_populate_pmd((pud_t *)pgdp, vaddr, next)))
> >
> > @@ -274,7 +274,7 @@ asmlinkage void __init kasan_early_init(void)
> >                                 (__pa((uintptr_t)kasan_early_shadow_pte)),
> >                                 PAGE_TABLE));
> >
> > -       if (pgtable_l4_enabled) {
> > +       if (pgtable_l4_enabled()) {
> >                 for (i = 0; i < PTRS_PER_PUD; ++i)
> >                         set_pud(kasan_early_shadow_pud + i,
> >                                 pfn_pud(PFN_DOWN
> > @@ -282,7 +282,7 @@ asmlinkage void __init kasan_early_init(void)
> >                                         PAGE_TABLE));
> >         }
> >
> > -       if (pgtable_l5_enabled) {
> > +       if (pgtable_l5_enabled()) {
> >                 for (i = 0; i < PTRS_PER_P4D; ++i)
> >                         set_p4d(kasan_early_shadow_p4d + i,
> >                                 pfn_p4d(PFN_DOWN
> > @@ -393,9 +393,9 @@ static void __init kasan_shallow_populate_p4d(pgd_t *pgdp,
> >  }
> >
> >  #define kasan_shallow_populate_pgd_next(pgdp, vaddr, next)                     \
> > -               (pgtable_l5_enabled ?                                           \
> > +               (pgtable_l5_enabled() ?                                         \
> >                 kasan_shallow_populate_p4d(pgdp, vaddr, next) :                 \
> > -               (pgtable_l4_enabled ?                                           \
> > +               (pgtable_l4_enabled() ?                                         \
> >                 kasan_shallow_populate_pud(pgdp, vaddr, next) :                 \
> >                 kasan_shallow_populate_pmd(pgdp, vaddr, next)))
> >
> > --
> > 2.34.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YpxJN6d5l2b6ZTVr%40xhacker.
