Return-Path: <kasan-dev+bncBCFKJ76CXICRBI4EY2LAMGQE3UVQS4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DDC557640C
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 17:05:08 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id v123-20020a1cac81000000b003a02a3f0beesf4389853wme.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 08:05:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657897508; cv=pass;
        d=google.com; s=arc-20160816;
        b=DAhkP48eSd0mv3BD8OZo9JKCj4Unnb/KT0G9DMB3qO19iVyirs4Jco1XzJYZzrvCdY
         nEHwNDxdr+3WNXMI3lvkr1wLIdTT+DK/My0nbSqDBE/uopitA/FkWzT3xf386qIp4HEv
         QyS7LqPzp2YRns2U1BA46uUG0C13Hylww7VUlmYf9eQKWA2ZKoeZl5q0K+gCEoqQbJnP
         Xv1vx7pGD+5IfAMasjeDDXSHG07tF4gJMGb9QV8sUFB6US0uWPu7DYwubaavZHwqMgFV
         UDkNTN81g0owW/GNWqP3Ndl+q75oBTbLgTGbfTMhRMC7RfqWB30DP/MIdp+uIO0IBWAW
         aYxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Xgzg4ljgg2WEYJMnTVEYCa0V/DZPu+LAddMc6tKlmLk=;
        b=B3VwL6u7a7xVc8Kw7Ey2fp5Ydw6CASD/3aO0DJl7n5ioa2NTjGhkjLLyX4h97PGCrp
         Lf26ekNoyjFZcR1I9hhHekTpQG3M8UL0GXHS0/iQFma5IBGTbh4bUXA81mqN5C9jrsJo
         4nTnMoqEkk/iUDpCxjRG2mf6kZqRhv5UyifQDwgnDFCeeaXeOfZieqMbX8kGC1E0W1NK
         XInbhat1gn5AQIsssIPnDrrgrHuNyvnjjQwfhRfhgrmlhoREojyYyP86PHQ/2IYakwXQ
         6rpbu9s6Zu85KY3mlXSF2oVPImeUXSOizkoP36cMHY1ZFIVNSx21J7esgLjAz3rX6ti1
         sP/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=DQI0jF7b;
       spf=pass (google.com: domain of emil.renner.berthing@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=emil.renner.berthing@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xgzg4ljgg2WEYJMnTVEYCa0V/DZPu+LAddMc6tKlmLk=;
        b=dZH9YkumndehLNorEkrTXrh5wh1EBwM6cDYurAqAlr2cja3uvTiyp62l7fcJTJhqVp
         lKf2Z6K4931o8GcN3p0fs23imVnFZKUbU+IDHoxP3ZKdOvtdRDmvBCOcM/r3vL6IsTZ1
         X59R1fhkDAgp2M3o1QgeuJUOzyEo9glp6NL3EyJN//Dg2kN6aoW+FUynyPU83Q8Js7uR
         N5s8WdKE9zhOkjT2k1l/MCNnliGxzGocDfoSVVWhBqtefPV7r7VpuZbGndPp/hY/Fd77
         zDtZ04LNUTkC3ZGmx5OOXJEsMqEn1XBRt6fepM5xnp8pLrUsRHSkwEs+bb/SuO3Wv7da
         D+AQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xgzg4ljgg2WEYJMnTVEYCa0V/DZPu+LAddMc6tKlmLk=;
        b=mN0EvBSr6V60HufRTDpImJF/mBci66ID7MMYvgMleUD+5xRZk9cKgNwXJ/viqc/lo/
         VmJBDPf7v9CimqB2K8MU0HR/pRhTk2+vjV6ERhz9ONUN8hSQ9Cw7Mq5Lqj35Fkr2h11e
         Huws1AarDg6YeEQ1HbfEoHHm66fps0i6PmY3l2WQntu/GvOBcdGNmqnWuXvLx03X4MFc
         D+vgfEVDmLmQ3KwIVHjuTe/uMUjQ+J1rG411zdJHjejEHG09cjhfd40gioGjwwOjS6tC
         xs5Za4Mn2yiq5vky+YYsR/YWeFJKQ58fK2doNgzf6SidBC5gv86ymQ5AvxwGlXTyJuet
         NOEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+4+Xrg+Tp4sLPXaToEyb+NPqAtH2qm0+MKt98UG152t7dWhVic
	STwoXgsNqSyL4NzjOWC6IKY=
X-Google-Smtp-Source: AGRyM1u15RFzkkSqD9jjqSd+tFDszCN9bP0EeEk6dNwaWDa7tT+RIG6lNYnG8QMHNpslllmpCaGzVQ==
X-Received: by 2002:a5d:4807:0:b0:21d:925b:d867 with SMTP id l7-20020a5d4807000000b0021d925bd867mr13508530wrq.354.1657897507794;
        Fri, 15 Jul 2022 08:05:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3a0:2da0:3609 with SMTP id
 m23-20020a05600c3b1700b003a02da03609ls5992986wms.1.gmail; Fri, 15 Jul 2022
 08:05:06 -0700 (PDT)
X-Received: by 2002:a05:600c:3845:b0:3a2:c04d:5ff9 with SMTP id s5-20020a05600c384500b003a2c04d5ff9mr20988912wmr.74.1657897506751;
        Fri, 15 Jul 2022 08:05:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657897506; cv=none;
        d=google.com; s=arc-20160816;
        b=XbeLq9dA2vzAjle4Lg5KPJpvwV3hSgqAjmPWmR2hhs89CQpHio42l60eG2ok8my03h
         Nqs8LvePfisjIi5fhM7CiPw/hevLdxI9iTb0gSkrycgKTjkm/YiwSN3VrMrak/OBW9Hd
         YngLc4UPtrmFwGKKsM8b/eJ+lLPi9lGXaeV/0gr2bybX2kMNtpZdbQVscvJx7iz8pFdJ
         6iWMWhs0cDWpYuKEAo9lkBARKSl5cIn+7CibUDUO62dqTE7ywcW9T/nQQFppTQpA4nau
         vooQNs1cSEjK9byueL8jiv5/u/Fe0JVzckHBwqYLZcppgtg/kyb2IZuasabPAAgncIJL
         y/Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jwJ8gkFWHdEs+TBswy3oImAZi2NInMOuC02Xr2RnuXM=;
        b=tTzMH1VadOYXUsU7TwLM7DOQmCBN1MzXwTeIr85HiMNCu66deWcE+3yKen4EpbSW2s
         IaXMyotEUeZM+KrltN0VKSHJ/JOub3nhAQiXcf7YJpCu08I4HjGGMR/B3UHY/BhSinIW
         ayD+8c55YeUBLF9iNPT22XcYIYGW8FF+54sYh3VE6Rw9Fae1fJKoAoRmEryzJqRG2LnY
         ERYocdlCIFG2u+QIa4o9OVkYcMO+QJIF/cKrmJ9gBvA3Vn3IhQmstYJsAZeSbKxOV6e9
         vtidMnUjDYl34S5nh9PbxNEmKp1FNKgq7NAEqFQM0SY10E25VW7eQ0c5Z5h9qUZX4dBY
         QDsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=DQI0jF7b;
       spf=pass (google.com: domain of emil.renner.berthing@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=emil.renner.berthing@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id r126-20020a1c2b84000000b003a050f3073asi407461wmr.4.2022.07.15.08.05.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Jul 2022 08:05:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of emil.renner.berthing@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-qt1-f198.google.com (mail-qt1-f198.google.com [209.85.160.198])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 3003A3F11D
	for <kasan-dev@googlegroups.com>; Fri, 15 Jul 2022 15:05:00 +0000 (UTC)
Received: by mail-qt1-f198.google.com with SMTP id x16-20020ac85f10000000b0031d3262f264so3804244qta.22
        for <kasan-dev@googlegroups.com>; Fri, 15 Jul 2022 08:05:00 -0700 (PDT)
X-Received: by 2002:a05:622a:1116:b0:31e:d8e4:ac30 with SMTP id e22-20020a05622a111600b0031ed8e4ac30mr4493624qty.660.1657897495276;
        Fri, 15 Jul 2022 08:04:55 -0700 (PDT)
X-Received: by 2002:a05:622a:1116:b0:31e:d8e4:ac30 with SMTP id
 e22-20020a05622a111600b0031ed8e4ac30mr4493562qty.660.1657897494752; Fri, 15
 Jul 2022 08:04:54 -0700 (PDT)
MIME-Version: 1.0
References: <20220715134847.2190-1-jszhang@kernel.org> <20220715134847.2190-3-jszhang@kernel.org>
In-Reply-To: <20220715134847.2190-3-jszhang@kernel.org>
From: Emil Renner Berthing <emil.renner.berthing@canonical.com>
Date: Fri, 15 Jul 2022 17:04:38 +0200
Message-ID: <CAJM55Z8JCePV8YRheyrsO1qQie79NM_-w-cYbNaJy-HLOtPfrw@mail.gmail.com>
Subject: Re: [PATCH v5 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key
 for RV64
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Anup Patel <anup@brainfault.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: emil.renner.berthing@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=DQI0jF7b;       spf=pass
 (google.com: domain of emil.renner.berthing@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=emil.renner.berthing@canonical.com;
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

On Fri, 15 Jul 2022 at 15:59, Jisheng Zhang <jszhang@kernel.org> wrote:
> On a specific HW platform, pgtable_l4|[l5]_enabled won't change after
> boot, and the check sits at hot code path, this characteristic makes it
> suitable for optimization with static key.
>
> _pgtable_l4|[l5]_enabled is used very early during boot, even is used
> with MMU off, so the static key mechanism isn't ready. For this case,
> we use another static key _pgtable_lx_ready to indicate whether we
> have finalised pgtable_l4|[l5]_enabled or not, then fall back to
> _pgtable_l4|[l5]_enabled_early bool.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> Reviewed-by: Anup Patel <anup@brainfault.org>
> ---
>  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
>  arch/riscv/include/asm/pgtable-32.h |  3 ++
>  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
>  arch/riscv/include/asm/pgtable.h    |  5 +--
>  arch/riscv/kernel/cpu.c             |  4 +-
>  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
>  arch/riscv/mm/kasan_init.c          | 16 ++++----
>  7 files changed, 103 insertions(+), 65 deletions(-)
>
> diff --git a/arch/riscv/include/asm/pgalloc.h b/arch/riscv/include/asm/pgalloc.h
> index 947f23d7b6af..0280eeb4756f 100644
> --- a/arch/riscv/include/asm/pgalloc.h
> +++ b/arch/riscv/include/asm/pgalloc.h
> @@ -41,7 +41,7 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
>
>  static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
>  {
> -       if (pgtable_l4_enabled) {
> +       if (pgtable_l4_enabled()) {
>                 unsigned long pfn = virt_to_pfn(pud);
>
>                 set_p4d(p4d, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> @@ -51,7 +51,7 @@ static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
>  static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
>                                      pud_t *pud)
>  {
> -       if (pgtable_l4_enabled) {
> +       if (pgtable_l4_enabled()) {
>                 unsigned long pfn = virt_to_pfn(pud);
>
>                 set_p4d_safe(p4d,
> @@ -61,7 +61,7 @@ static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
>
>  static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
>  {
> -       if (pgtable_l5_enabled) {
> +       if (pgtable_l5_enabled()) {
>                 unsigned long pfn = virt_to_pfn(p4d);
>
>                 set_pgd(pgd, __pgd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> @@ -71,7 +71,7 @@ static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
>  static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd,
>                                      p4d_t *p4d)
>  {
> -       if (pgtable_l5_enabled) {
> +       if (pgtable_l5_enabled()) {
>                 unsigned long pfn = virt_to_pfn(p4d);
>
>                 set_pgd_safe(pgd,
> @@ -82,7 +82,7 @@ static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd,
>  #define pud_alloc_one pud_alloc_one
>  static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return __pud_alloc_one(mm, addr);
>
>         return NULL;
> @@ -91,7 +91,7 @@ static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
>  #define pud_free pud_free
>  static inline void pud_free(struct mm_struct *mm, pud_t *pud)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 __pud_free(mm, pud);
>  }
>
> @@ -100,7 +100,7 @@ static inline void pud_free(struct mm_struct *mm, pud_t *pud)
>  #define p4d_alloc_one p4d_alloc_one
>  static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
>  {
> -       if (pgtable_l5_enabled) {
> +       if (pgtable_l5_enabled()) {
>                 gfp_t gfp = GFP_PGTABLE_USER;
>
>                 if (mm == &init_mm)
> @@ -120,7 +120,7 @@ static inline void __p4d_free(struct mm_struct *mm, p4d_t *p4d)
>  #define p4d_free p4d_free
>  static inline void p4d_free(struct mm_struct *mm, p4d_t *p4d)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 __p4d_free(mm, p4d);
>  }
>
> diff --git a/arch/riscv/include/asm/pgtable-32.h b/arch/riscv/include/asm/pgtable-32.h
> index 59ba1fbaf784..1ef52079179a 100644
> --- a/arch/riscv/include/asm/pgtable-32.h
> +++ b/arch/riscv/include/asm/pgtable-32.h
> @@ -17,6 +17,9 @@
>
>  #define MAX_POSSIBLE_PHYSMEM_BITS 34
>
> +#define pgtable_l5_enabled() 0
> +#define pgtable_l4_enabled() 0
> +
>  /*
>   * rv32 PTE format:
>   * | XLEN-1  10 | 9             8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0
> diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
> index 5c2aba5efbd0..edfff00d8ca3 100644
> --- a/arch/riscv/include/asm/pgtable-64.h
> +++ b/arch/riscv/include/asm/pgtable-64.h
> @@ -8,18 +8,38 @@
>
>  #include <linux/bits.h>
>  #include <linux/const.h>
> +#include <linux/jump_label.h>
>  #include <asm/errata_list.h>
>
> -extern bool pgtable_l4_enabled;
> -extern bool pgtable_l5_enabled;
> +extern bool _pgtable_l5_enabled_early;
> +extern bool _pgtable_l4_enabled_early;
> +extern struct static_key_false _pgtable_l5_enabled;
> +extern struct static_key_false _pgtable_l4_enabled;
> +extern struct static_key_false _pgtable_lx_ready;

It amounts to the same, but I wonder if we ought to use the
DECLARE_STATIC_KEY_FALSE macro here.

> +static __always_inline bool pgtable_l5_enabled(void)
> +{
> +       if (static_branch_likely(&_pgtable_lx_ready))
> +               return static_branch_likely(&_pgtable_l5_enabled);
> +       else
> +               return _pgtable_l5_enabled_early;
> +}
> +
> +static __always_inline bool pgtable_l4_enabled(void)
> +{
> +       if (static_branch_likely(&_pgtable_lx_ready))
> +               return static_branch_likely(&_pgtable_l4_enabled);
> +       else
> +               return _pgtable_l4_enabled_early;
> +}
>
>  #define PGDIR_SHIFT_L3  30
>  #define PGDIR_SHIFT_L4  39
>  #define PGDIR_SHIFT_L5  48
>  #define PGDIR_SIZE_L3   (_AC(1, UL) << PGDIR_SHIFT_L3)
>
> -#define PGDIR_SHIFT     (pgtable_l5_enabled ? PGDIR_SHIFT_L5 : \
> -               (pgtable_l4_enabled ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3))
> +#define PGDIR_SHIFT     (pgtable_l5_enabled() ? PGDIR_SHIFT_L5 : \
> +               (pgtable_l4_enabled() ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3))
>  /* Size of region mapped by a page global directory */
>  #define PGDIR_SIZE      (_AC(1, UL) << PGDIR_SHIFT)
>  #define PGDIR_MASK      (~(PGDIR_SIZE - 1))
> @@ -191,7 +211,7 @@ static inline struct page *pud_page(pud_t pud)
>  #define mm_p4d_folded  mm_p4d_folded
>  static inline bool mm_p4d_folded(struct mm_struct *mm)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return false;
>
>         return true;
> @@ -200,7 +220,7 @@ static inline bool mm_p4d_folded(struct mm_struct *mm)
>  #define mm_pud_folded  mm_pud_folded
>  static inline bool mm_pud_folded(struct mm_struct *mm)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return false;
>
>         return true;
> @@ -235,7 +255,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
>
>  static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 *p4dp = p4d;
>         else
>                 set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
> @@ -243,7 +263,7 @@ static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
>
>  static inline int p4d_none(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return (p4d_val(p4d) == 0);
>
>         return 0;
> @@ -251,7 +271,7 @@ static inline int p4d_none(p4d_t p4d)
>
>  static inline int p4d_present(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return (p4d_val(p4d) & _PAGE_PRESENT);
>
>         return 1;
> @@ -259,7 +279,7 @@ static inline int p4d_present(p4d_t p4d)
>
>  static inline int p4d_bad(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return !p4d_present(p4d);
>
>         return 0;
> @@ -267,7 +287,7 @@ static inline int p4d_bad(p4d_t p4d)
>
>  static inline void p4d_clear(p4d_t *p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 set_p4d(p4d, __p4d(0));
>  }
>
> @@ -283,7 +303,7 @@ static inline unsigned long _p4d_pfn(p4d_t p4d)
>
>  static inline pud_t *p4d_pgtable(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return (pud_t *)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
>
>         return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) });
> @@ -300,7 +320,7 @@ static inline struct page *p4d_page(p4d_t p4d)
>  #define pud_offset pud_offset
>  static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return p4d_pgtable(*p4d) + pud_index(address);
>
>         return (pud_t *)p4d;
> @@ -308,7 +328,7 @@ static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
>
>  static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 *pgdp = pgd;
>         else
>                 set_p4d((p4d_t *)pgdp, (p4d_t){ pgd_val(pgd) });
> @@ -316,7 +336,7 @@ static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
>
>  static inline int pgd_none(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return (pgd_val(pgd) == 0);
>
>         return 0;
> @@ -324,7 +344,7 @@ static inline int pgd_none(pgd_t pgd)
>
>  static inline int pgd_present(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return (pgd_val(pgd) & _PAGE_PRESENT);
>
>         return 1;
> @@ -332,7 +352,7 @@ static inline int pgd_present(pgd_t pgd)
>
>  static inline int pgd_bad(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return !pgd_present(pgd);
>
>         return 0;
> @@ -340,13 +360,13 @@ static inline int pgd_bad(pgd_t pgd)
>
>  static inline void pgd_clear(pgd_t *pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 set_pgd(pgd, __pgd(0));
>  }
>
>  static inline p4d_t *pgd_pgtable(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return (p4d_t *)pfn_to_virt(pgd_val(pgd) >> _PAGE_PFN_SHIFT);
>
>         return (p4d_t *)p4d_pgtable((p4d_t) { pgd_val(pgd) });
> @@ -364,7 +384,7 @@ static inline struct page *pgd_page(pgd_t pgd)
>  #define p4d_offset p4d_offset
>  static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return pgd_pgtable(*pgd) + p4d_index(address);
>
>         return (p4d_t *)pgd;
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> index 1d1be9d9419c..3eaa01d880b9 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -63,8 +63,8 @@
>   * position vmemmap directly below the VMALLOC region.
>   */
>  #ifdef CONFIG_64BIT
> -#define VA_BITS                (pgtable_l5_enabled ? \
> -                               57 : (pgtable_l4_enabled ? 48 : 39))
> +#define VA_BITS                (pgtable_l5_enabled() ? \
> +                               57 : (pgtable_l4_enabled() ? 48 : 39))
>  #else
>  #define VA_BITS                32
>  #endif
> @@ -834,7 +834,6 @@ extern uintptr_t _dtb_early_pa;
>  #define dtb_early_pa   _dtb_early_pa
>  #endif /* CONFIG_XIP_KERNEL */
>  extern u64 satp_mode;
> -extern bool pgtable_l4_enabled;
>
>  void paging_init(void);
>  void misc_mem_init(void);
> diff --git a/arch/riscv/kernel/cpu.c b/arch/riscv/kernel/cpu.c
> index fba9e9f46a8c..9b3697a97e41 100644
> --- a/arch/riscv/kernel/cpu.c
> +++ b/arch/riscv/kernel/cpu.c
> @@ -143,9 +143,9 @@ static void print_mmu(struct seq_file *f)
>  #if defined(CONFIG_32BIT)
>         strncpy(sv_type, "sv32", 5);
>  #elif defined(CONFIG_64BIT)
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 strncpy(sv_type, "sv57", 5);
> -       else if (pgtable_l4_enabled)
> +       else if (pgtable_l4_enabled())
>                 strncpy(sv_type, "sv48", 5);
>         else
>                 strncpy(sv_type, "sv39", 5);
> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index d466ec670e1f..11708cdb7094 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -44,10 +44,16 @@ u64 satp_mode __ro_after_init = SATP_MODE_32;
>  #endif
>  EXPORT_SYMBOL(satp_mode);
>
> -bool pgtable_l4_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> -bool pgtable_l5_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> -EXPORT_SYMBOL(pgtable_l4_enabled);
> -EXPORT_SYMBOL(pgtable_l5_enabled);
> +DEFINE_STATIC_KEY_FALSE(_pgtable_l4_enabled);
> +DEFINE_STATIC_KEY_FALSE(_pgtable_l5_enabled);
> +DEFINE_STATIC_KEY_FALSE(_pgtable_lx_ready);
> +EXPORT_SYMBOL(_pgtable_l4_enabled);
> +EXPORT_SYMBOL(_pgtable_l5_enabled);
> +EXPORT_SYMBOL(_pgtable_lx_ready);
> +bool _pgtable_l4_enabled_early = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> +bool _pgtable_l5_enabled_early = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> +EXPORT_SYMBOL(_pgtable_l4_enabled_early);
> +EXPORT_SYMBOL(_pgtable_l5_enabled_early);
>
>  phys_addr_t phys_ram_base __ro_after_init;
>  EXPORT_SYMBOL(phys_ram_base);
> @@ -585,26 +591,26 @@ static void __init create_p4d_mapping(p4d_t *p4dp,
>  }
>
>  #define pgd_next_t             p4d_t
> -#define alloc_pgd_next(__va)   (pgtable_l5_enabled ?                   \
> -               pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled ?          \
> +#define alloc_pgd_next(__va)   (pgtable_l5_enabled() ?                 \
> +               pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled() ?                \
>                 pt_ops.alloc_pud(__va) : pt_ops.alloc_pmd(__va)))
> -#define get_pgd_next_virt(__pa)        (pgtable_l5_enabled ?                   \
> -               pt_ops.get_p4d_virt(__pa) : (pgd_next_t *)(pgtable_l4_enabled ? \
> +#define get_pgd_next_virt(__pa)        (pgtable_l5_enabled() ?                 \
> +               pt_ops.get_p4d_virt(__pa) : (pgd_next_t *)(pgtable_l4_enabled() ?       \
>                 pt_ops.get_pud_virt(__pa) : (pud_t *)pt_ops.get_pmd_virt(__pa)))
>  #define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot)     \
> -                               (pgtable_l5_enabled ?                   \
> +                               (pgtable_l5_enabled() ?                 \
>                 create_p4d_mapping(__nextp, __va, __pa, __sz, __prot) : \
> -                               (pgtable_l4_enabled ?                   \
> +                               (pgtable_l4_enabled() ?                 \
>                 create_pud_mapping((pud_t *)__nextp, __va, __pa, __sz, __prot) :        \
>                 create_pmd_mapping((pmd_t *)__nextp, __va, __pa, __sz, __prot)))
> -#define fixmap_pgd_next                (pgtable_l5_enabled ?                   \
> -               (uintptr_t)fixmap_p4d : (pgtable_l4_enabled ?           \
> +#define fixmap_pgd_next                (pgtable_l5_enabled() ?                 \
> +               (uintptr_t)fixmap_p4d : (pgtable_l4_enabled() ?         \
>                 (uintptr_t)fixmap_pud : (uintptr_t)fixmap_pmd))
> -#define trampoline_pgd_next    (pgtable_l5_enabled ?                   \
> -               (uintptr_t)trampoline_p4d : (pgtable_l4_enabled ?       \
> +#define trampoline_pgd_next    (pgtable_l5_enabled() ?                 \
> +               (uintptr_t)trampoline_p4d : (pgtable_l4_enabled() ?     \
>                 (uintptr_t)trampoline_pud : (uintptr_t)trampoline_pmd))
> -#define early_dtb_pgd_next     (pgtable_l5_enabled ?                   \
> -               (uintptr_t)early_dtb_p4d : (pgtable_l4_enabled ?        \
> +#define early_dtb_pgd_next     (pgtable_l5_enabled() ?                 \
> +               (uintptr_t)early_dtb_p4d : (pgtable_l4_enabled() ?      \
>                 (uintptr_t)early_dtb_pud : (uintptr_t)early_dtb_pmd))
>  #else
>  #define pgd_next_t             pte_t
> @@ -710,14 +716,14 @@ static __init pgprot_t pgprot_from_va(uintptr_t va)
>  #if defined(CONFIG_64BIT) && !defined(CONFIG_XIP_KERNEL)
>  static void __init disable_pgtable_l5(void)
>  {
> -       pgtable_l5_enabled = false;
> +       _pgtable_l5_enabled_early = false;
>         kernel_map.page_offset = PAGE_OFFSET_L4;
>         satp_mode = SATP_MODE_48;
>  }
>
>  static void __init disable_pgtable_l4(void)
>  {
> -       pgtable_l4_enabled = false;
> +       _pgtable_l4_enabled_early = false;
>         kernel_map.page_offset = PAGE_OFFSET_L3;
>         satp_mode = SATP_MODE_39;
>  }
> @@ -846,11 +852,11 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
>                            PGDIR_SIZE,
>                            IS_ENABLED(CONFIG_64BIT) ? PAGE_TABLE : PAGE_KERNEL);
>
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 create_p4d_mapping(early_dtb_p4d, DTB_EARLY_BASE_VA,
>                                    (uintptr_t)early_dtb_pud, P4D_SIZE, PAGE_TABLE);
>
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 create_pud_mapping(early_dtb_pud, DTB_EARLY_BASE_VA,
>                                    (uintptr_t)early_dtb_pmd, PUD_SIZE, PAGE_TABLE);
>
> @@ -992,11 +998,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>
>  #ifndef __PAGETABLE_PMD_FOLDED
>         /* Setup fixmap P4D and PUD */
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 create_p4d_mapping(fixmap_p4d, FIXADDR_START,
>                                    (uintptr_t)fixmap_pud, P4D_SIZE, PAGE_TABLE);
>         /* Setup fixmap PUD and PMD */
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 create_pud_mapping(fixmap_pud, FIXADDR_START,
>                                    (uintptr_t)fixmap_pmd, PUD_SIZE, PAGE_TABLE);
>         create_pmd_mapping(fixmap_pmd, FIXADDR_START,
> @@ -1004,10 +1010,10 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>         /* Setup trampoline PGD and PMD */
>         create_pgd_mapping(trampoline_pg_dir, kernel_map.virt_addr,
>                            trampoline_pgd_next, PGDIR_SIZE, PAGE_TABLE);
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 create_p4d_mapping(trampoline_p4d, kernel_map.virt_addr,
>                                    (uintptr_t)trampoline_pud, P4D_SIZE, PAGE_TABLE);
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 create_pud_mapping(trampoline_pud, kernel_map.virt_addr,
>                                    (uintptr_t)trampoline_pmd, PUD_SIZE, PAGE_TABLE);
>  #ifdef CONFIG_XIP_KERNEL
> @@ -1196,6 +1202,15 @@ static void __init reserve_crashkernel(void)
>         crashk_res.end = crash_base + crash_size - 1;
>  }
>
> +static void __init riscv_finalise_pgtable_lx(void)
> +{
> +       if (_pgtable_l5_enabled_early)
> +               static_branch_enable(&_pgtable_l5_enabled);
> +       if (_pgtable_l4_enabled_early)
> +               static_branch_enable(&_pgtable_l4_enabled);
> +       static_branch_enable(&_pgtable_lx_ready);
> +}
> +
>  void __init paging_init(void)
>  {
>         setup_bootmem();
> @@ -1207,6 +1222,7 @@ void __init misc_mem_init(void)
>         early_memtest(min_low_pfn << PAGE_SHIFT, max_low_pfn << PAGE_SHIFT);
>         arch_numa_init();
>         sparse_init();
> +       riscv_finalise_pgtable_lx();
>         zone_sizes_init();
>         reserve_crashkernel();
>         memblock_dump_all();
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index a22e418dbd82..356044498e8a 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -209,15 +209,15 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
>                 set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
>  }
>
> -#define kasan_early_shadow_pgd_next                    (pgtable_l5_enabled ?   \
> +#define kasan_early_shadow_pgd_next                    (pgtable_l5_enabled() ? \
>                                 (uintptr_t)kasan_early_shadow_p4d :             \
> -                                                       (pgtable_l4_enabled ?   \
> +                                                       (pgtable_l4_enabled() ? \
>                                 (uintptr_t)kasan_early_shadow_pud :             \
>                                 (uintptr_t)kasan_early_shadow_pmd))
>  #define kasan_populate_pgd_next(pgdp, vaddr, next, early)                      \
> -               (pgtable_l5_enabled ?                                           \
> +               (pgtable_l5_enabled() ?                                         \
>                 kasan_populate_p4d(pgdp, vaddr, next, early) :                  \
> -               (pgtable_l4_enabled ?                                           \
> +               (pgtable_l4_enabled() ?                                         \
>                         kasan_populate_pud(pgdp, vaddr, next, early) :          \
>                         kasan_populate_pmd((pud_t *)pgdp, vaddr, next)))
>
> @@ -274,7 +274,7 @@ asmlinkage void __init kasan_early_init(void)
>                                 (__pa((uintptr_t)kasan_early_shadow_pte)),
>                                 PAGE_TABLE));
>
> -       if (pgtable_l4_enabled) {
> +       if (pgtable_l4_enabled()) {
>                 for (i = 0; i < PTRS_PER_PUD; ++i)
>                         set_pud(kasan_early_shadow_pud + i,
>                                 pfn_pud(PFN_DOWN
> @@ -282,7 +282,7 @@ asmlinkage void __init kasan_early_init(void)
>                                         PAGE_TABLE));
>         }
>
> -       if (pgtable_l5_enabled) {
> +       if (pgtable_l5_enabled()) {
>                 for (i = 0; i < PTRS_PER_P4D; ++i)
>                         set_p4d(kasan_early_shadow_p4d + i,
>                                 pfn_p4d(PFN_DOWN
> @@ -393,9 +393,9 @@ static void __init kasan_shallow_populate_p4d(pgd_t *pgdp,
>  }
>
>  #define kasan_shallow_populate_pgd_next(pgdp, vaddr, next)                     \
> -               (pgtable_l5_enabled ?                                           \
> +               (pgtable_l5_enabled() ?                                         \
>                 kasan_shallow_populate_p4d(pgdp, vaddr, next) :                 \
> -               (pgtable_l4_enabled ?                                           \
> +               (pgtable_l4_enabled() ?                                         \
>                 kasan_shallow_populate_pud(pgdp, vaddr, next) :                 \
>                 kasan_shallow_populate_pmd(pgdp, vaddr, next)))
>
> --
> 2.34.1
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJM55Z8JCePV8YRheyrsO1qQie79NM_-w-cYbNaJy-HLOtPfrw%40mail.gmail.com.
