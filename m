Return-Path: <kasan-dev+bncBDFJHU6GRMBBBVMBWSKAMGQE33YSJUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id DC39A532DF6
	for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 17:59:17 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id o23-20020a05600c511700b0039747b0216fsf1510526wms.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 08:59:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653407957; cv=pass;
        d=google.com; s=arc-20160816;
        b=QSNPWz8V02YqZok+JoFoQefXG4PdOL0O6oHUo9fRy1Fi5bAXqjPaFdiFOP9ONciscs
         F9K/bG9mthfdWaceP624aBjZfvFhF6tNcolpfN1N1uhBWYqM0/UT7fNYCapa+9RFV37R
         cYZqKInjjJA9iqZqHizp93Wxb2iIcfOHns6yz8k66Ww38cW4FLocnkw2gcuueSwqhD4q
         UJidco0UALksC/uYSseI54ma1rm1F8oZsinkXsclkp7bssaDPQrhlA26Bj6zOHPrWPIU
         Ay0hlZDp9E6BfpITWs7HRnXol9WVl/FNpKlIopb+wE19H5uftDDKW2yq8A+m7Q2gwMeT
         7c1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=3YK+PGfa9AmNNwQPmV1lIzfmlZ7iphlyISep8/tW8bs=;
        b=o+y5yItGecdWjy+XdXzLFnupRv7DjnzuX7Z6tDHpUFjxyJMshAciHGydGMn0vBJqaE
         ToqwCTQ9Mga9ohbgYBkfyfzB0LEYcU9Pw8B0coDCfESpe7cSdnQTZi314HL7uWsDa3j3
         w328jGcdm88EnicgbPpV+NtViwkbCElR5q9yc6rr7PA7YafZJ/JRejGRXEXMlXDAMEoc
         fvoEo8Un9UVv3B2wUEyqTpbwDKadlG5lgY09dEy/Kx1qDZIzr4f164UTvJ8x5bdcyYP3
         gbbKrFBahWBivFBQ1QnDNlH4fiRWJoOrkSqOnHllEe4YElgH/OcxKhO6hZOkhXtr300o
         7CmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=Mt81zUgG;
       spf=neutral (google.com: 2a00:1450:4864:20::436 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3YK+PGfa9AmNNwQPmV1lIzfmlZ7iphlyISep8/tW8bs=;
        b=ny5v9jfA5NFazR8P0Hb4YCq85pezudeYgki4pfgDlza+LoJZiKZi06O7QZgN5Rw7ZI
         ZjBv/PKmuVRUStqEBIzDbcHGkI0bDiOLrWIVBYwXFCR2uCRGOlhNOMXYjiOTf1sBYiIx
         MbvYKX6Z4D1qeYufo7Pq3yWWeZSahcDiZ4YuiQQQ1isnNcjtc8acfva8OREgMPpuKRPc
         mGAwCMJpSaRIX7B6NX7VxMvUYMoS7FGNJohq2Z98PAvbw8trGbiXhVjbljwi3fm+mzQh
         d+xQO9tHLYXGJBPm0SVX4ekQuWj5ehm3mqfRX8xXcAqkzwf6SS9IL8hV739/wftwy8uF
         99FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3YK+PGfa9AmNNwQPmV1lIzfmlZ7iphlyISep8/tW8bs=;
        b=kPPo3Y6SaZPCx9cti7LXvwl+uNyGs1onB0cZZyShjT8PX3Gj7rdWV+kxrpXPQK14jO
         HLjpxkU1U6kKepjdfb/rB/hC+b+jnu8U+nd3JhtnmefyT3dI2GlA7N1lvqmlF7gYOHGG
         vWaafHyLbsyT98zQFHvR9uOPoIY0kat3ONtvRZX622tyQAWPHrA1kX3AKMdI5AvHatGg
         oJdiBrQeRgvg0p0BfL9GHCycCZxDBEuZz8K4ta387QVZXhR42dPkKH2a5oTLHgIlfd1q
         3+0n44p94/JyAYQHmFaJCFORtD0tzOEL7ZoJ0UlvLKTeMr+Q4/k3z2hL1ASCM9v9qitv
         x5WQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532k3VqsB/XR4Hj7WOrn7/TsnhjD3fRx98mJykEBYQafduf66Yop
	HReTgTQYreCGyAjvY+0Teyg=
X-Google-Smtp-Source: ABdhPJxa6OdH5CIUGdZa3LHquZZxp7qaFyktNE20PZzMdQwn1h1KdWeIUf6ZlZuyEWY7fiePBi8Psw==
X-Received: by 2002:adf:f803:0:b0:20d:3a1:3c31 with SMTP id s3-20020adff803000000b0020d03a13c31mr24014151wrp.565.1653407957445;
        Tue, 24 May 2022 08:59:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f346:0:b0:20e:7267:9ee4 with SMTP id e6-20020adff346000000b0020e72679ee4ls17545808wrp.2.gmail;
 Tue, 24 May 2022 08:59:16 -0700 (PDT)
X-Received: by 2002:adf:f706:0:b0:20e:6788:c2b6 with SMTP id r6-20020adff706000000b0020e6788c2b6mr22818947wrp.633.1653407956403;
        Tue, 24 May 2022 08:59:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653407956; cv=none;
        d=google.com; s=arc-20160816;
        b=rSlzNggKtIQ8R4B5UR39O7qYoNDhGgiNMl4YVH30cG8r6wUjCfcrt530MuFdluGTBh
         guKZ2CG/DrA4EX7QDIuhlrX2odhaUKr6dRE0XS+y2cPdxdARxydHqIHoyQO/64CXmy8P
         UrkjlKZaVHD+dqRhSWEbrOi1PKEXxQ2pAIeHEYQVY9YcqEJcg94YKK7PKtw3/cRzBngt
         KoTQCsj3d22Ti782G/FxU2ilnRM2jjj7PBv704BZ4RQbkUm8ZZoeVHxuwwa0PGbbGXpb
         kRf65R4OP1K4lHWLEKtKQQdCTAcwUzOuL9sFU7B0HGjQbfeVMjZ6F9/qfZoox2lSdx7o
         3U+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cq5dWAa7ujluWQuhtKnezx79irQ5/czppxn1xIgB9NU=;
        b=EEfdbhX/4bV2cYTpbKTJrU1Q3DSTbG9l0DGeyyOJL4McyzGTrrhwmexpl4inxL6Be0
         oDg0wODqm1oiJIDU3fLrDFcj4Tbt1zLWlnCtwMDVg3W+gngTlHw5ktEOPcGAeWYv57Vm
         UBanXIli8Jj9DUGFS3D6sAqxXZNerNtaMR3/RdVzsKTBJF5rItPCyo1ByKeWUpQkcpA8
         IblLSUDNzY0vCstTo0I452exyt5zs3tsqxl/2monkFjYslPodme88cUWyL16IyYcT7Cb
         D1hEfqcnzCYnOcuUMu1QH+GJZaWRh7vJUjb/G5qf4GJm5ta2TxaFYMwqGEJ/kKo6owDu
         GvYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=Mt81zUgG;
       spf=neutral (google.com: 2a00:1450:4864:20::436 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id d10-20020a05600c34ca00b003973d014ec1si160331wmq.1.2022.05.24.08.59.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 May 2022 08:59:16 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::436 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id e2so14740925wrc.1
        for <kasan-dev@googlegroups.com>; Tue, 24 May 2022 08:59:16 -0700 (PDT)
X-Received: by 2002:adf:d1ca:0:b0:20f:ca28:27cf with SMTP id
 b10-20020adfd1ca000000b0020fca2827cfmr13658266wrd.86.1653407955808; Tue, 24
 May 2022 08:59:15 -0700 (PDT)
MIME-Version: 1.0
References: <20220521143456.2759-1-jszhang@kernel.org> <20220521143456.2759-3-jszhang@kernel.org>
In-Reply-To: <20220521143456.2759-3-jszhang@kernel.org>
From: Anup Patel <anup@brainfault.org>
Date: Tue, 24 May 2022 21:29:04 +0530
Message-ID: <CAAhSdy0xVy8-UnNAKdCHRz8QANbTRwGiotFWCjPOiPuDMo+YTQ@mail.gmail.com>
Subject: Re: [PATCH v4 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key
 for RV64
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, Atish Patra <atishp@rivosinc.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b=Mt81zUgG;       spf=neutral (google.com: 2a00:1450:4864:20::436 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Sat, May 21, 2022 at 8:13 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
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

Looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

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
> index 5b2e79e5bfa5..8af36d76b70d 100644
> --- a/arch/riscv/include/asm/pgtable-32.h
> +++ b/arch/riscv/include/asm/pgtable-32.h
> @@ -16,4 +16,7 @@
>
>  #define MAX_POSSIBLE_PHYSMEM_BITS 34
>
> +#define pgtable_l5_enabled() 0
> +#define pgtable_l4_enabled() 0
> +
>  #endif /* _ASM_RISCV_PGTABLE_32_H */
> diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
> index 7e246e9f8d70..d14a3a8f1f4b 100644
> --- a/arch/riscv/include/asm/pgtable-64.h
> +++ b/arch/riscv/include/asm/pgtable-64.h
> @@ -7,17 +7,37 @@
>  #define _ASM_RISCV_PGTABLE_64_H
>
>  #include <linux/const.h>
> +#include <linux/jump_label.h>
>
> -extern bool pgtable_l4_enabled;
> -extern bool pgtable_l5_enabled;
> +extern bool _pgtable_l5_enabled_early;
> +extern bool _pgtable_l4_enabled_early;
> +extern struct static_key_false _pgtable_l5_enabled;
> +extern struct static_key_false _pgtable_l4_enabled;
> +extern struct static_key_false _pgtable_lx_ready;
> +
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
> @@ -119,7 +139,7 @@ static inline struct page *pud_page(pud_t pud)
>  #define mm_p4d_folded  mm_p4d_folded
>  static inline bool mm_p4d_folded(struct mm_struct *mm)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return false;
>
>         return true;
> @@ -128,7 +148,7 @@ static inline bool mm_p4d_folded(struct mm_struct *mm)
>  #define mm_pud_folded  mm_pud_folded
>  static inline bool mm_pud_folded(struct mm_struct *mm)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return false;
>
>         return true;
> @@ -159,7 +179,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
>
>  static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 *p4dp = p4d;
>         else
>                 set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
> @@ -167,7 +187,7 @@ static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
>
>  static inline int p4d_none(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return (p4d_val(p4d) == 0);
>
>         return 0;
> @@ -175,7 +195,7 @@ static inline int p4d_none(p4d_t p4d)
>
>  static inline int p4d_present(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return (p4d_val(p4d) & _PAGE_PRESENT);
>
>         return 1;
> @@ -183,7 +203,7 @@ static inline int p4d_present(p4d_t p4d)
>
>  static inline int p4d_bad(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return !p4d_present(p4d);
>
>         return 0;
> @@ -191,7 +211,7 @@ static inline int p4d_bad(p4d_t p4d)
>
>  static inline void p4d_clear(p4d_t *p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 set_p4d(p4d, __p4d(0));
>  }
>
> @@ -207,7 +227,7 @@ static inline unsigned long _p4d_pfn(p4d_t p4d)
>
>  static inline pud_t *p4d_pgtable(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return (pud_t *)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
>
>         return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) });
> @@ -224,7 +244,7 @@ static inline struct page *p4d_page(p4d_t p4d)
>  #define pud_offset pud_offset
>  static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
>  {
> -       if (pgtable_l4_enabled)
> +       if (pgtable_l4_enabled())
>                 return p4d_pgtable(*p4d) + pud_index(address);
>
>         return (pud_t *)p4d;
> @@ -232,7 +252,7 @@ static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
>
>  static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 *pgdp = pgd;
>         else
>                 set_p4d((p4d_t *)pgdp, (p4d_t){ pgd_val(pgd) });
> @@ -240,7 +260,7 @@ static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
>
>  static inline int pgd_none(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return (pgd_val(pgd) == 0);
>
>         return 0;
> @@ -248,7 +268,7 @@ static inline int pgd_none(pgd_t pgd)
>
>  static inline int pgd_present(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return (pgd_val(pgd) & _PAGE_PRESENT);
>
>         return 1;
> @@ -256,7 +276,7 @@ static inline int pgd_present(pgd_t pgd)
>
>  static inline int pgd_bad(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return !pgd_present(pgd);
>
>         return 0;
> @@ -264,13 +284,13 @@ static inline int pgd_bad(pgd_t pgd)
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
> @@ -288,7 +308,7 @@ static inline struct page *pgd_page(pgd_t pgd)
>  #define p4d_offset p4d_offset
>  static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
>  {
> -       if (pgtable_l5_enabled)
> +       if (pgtable_l5_enabled())
>                 return pgd_pgtable(*pgd) + p4d_index(address);
>
>         return (p4d_t *)pgd;
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> index 046b44225623..ae01a9b83ac4 100644
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
> @@ -738,7 +738,6 @@ extern uintptr_t _dtb_early_pa;
>  #define dtb_early_pa   _dtb_early_pa
>  #endif /* CONFIG_XIP_KERNEL */
>  extern u64 satp_mode;
> -extern bool pgtable_l4_enabled;
>
>  void paging_init(void);
>  void misc_mem_init(void);
> diff --git a/arch/riscv/kernel/cpu.c b/arch/riscv/kernel/cpu.c
> index ccb617791e56..29bb0ef75248 100644
> --- a/arch/riscv/kernel/cpu.c
> +++ b/arch/riscv/kernel/cpu.c
> @@ -141,9 +141,9 @@ static void print_mmu(struct seq_file *f)
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
> index 05ed641a1134..42c79388e6fd 100644
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
> @@ -555,26 +561,26 @@ static void __init create_p4d_mapping(p4d_t *p4dp,
>  }
>
>  #define pgd_next_t             p4d_t
> -#define alloc_pgd_next(__va)   (pgtable_l5_enabled ?                   \
> -               pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled ?          \
> +#define alloc_pgd_next(__va)   (pgtable_l5_enabled() ?                 \
> +               pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled() ?        \
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
> @@ -680,14 +686,14 @@ static __init pgprot_t pgprot_from_va(uintptr_t va)
>  #ifdef CONFIG_64BIT
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
> @@ -816,11 +822,11 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
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
> @@ -961,11 +967,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
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
> @@ -973,10 +979,10 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
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
> @@ -1165,8 +1171,18 @@ static void __init reserve_crashkernel(void)
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
> +       riscv_finalise_pgtable_lx();
>         setup_bootmem();
>         setup_vm_final();
>  }
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy0xVy8-UnNAKdCHRz8QANbTRwGiotFWCjPOiPuDMo%2BYTQ%40mail.gmail.com.
