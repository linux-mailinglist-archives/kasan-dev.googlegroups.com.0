Return-Path: <kasan-dev+bncBDFJHU6GRMBBBKFD4KJQMGQEAOFW2JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DCAF51F320
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 05:59:37 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id q7-20020a2e8747000000b0024f2d363986sf3741329ljj.5
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 20:59:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652068776; cv=pass;
        d=google.com; s=arc-20160816;
        b=DEFr1ZnE7EYlocLC1rXnB9BI19eAwTdd7h2xJcx4wEPQ5ROMSrmQdKoZ+U9QiOE80B
         D0ZqYLiNFZ/KrCTedYN8n7Ep2SQ5PuyMAGWV1dG7VMxza2S+9aVEGFaF5nNRFPtqZCfC
         4zsaJuCMctitaRiAJZpzyzplq8c6qg0/j8U3tTmywh3wEQdS1ygEYyNAXkv0KsxCnD/8
         +NbdF3FvCM5vMr6ckeK8njTpT15+kOx8o4ZmHbECYgNRaGZndNoDJsilkGK9NBCZJR5d
         oEzGbFIIp83FvpzwgOkAFBfvx/SJ62QrL2Fvgp6cdjzgZCu7RmjLZ5rzLRaPgwxqp6+t
         8VRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=koA781L7fOYQVkzAuhG8CslU1LOMPyXfiHR8uydimi4=;
        b=EP5EjpqBIWbXUfLUXco0yo/yMcZqwK9ThYCU2yhP/1dxibdDYT1BwXD/OWs58dBgJu
         nykUKwh4yCwKGJCJvwr79lyx4iljXUb8MZfsveaiXgVxpT4iMSt86ijW45UvYYU3Fj8n
         P4IGuGNIA5khyyGMT3ncCc4VJU7d5mhDSQRFpp3b1LTcA94/Q35gSW7QGdvULSCJGEHN
         sNEhvmWWmnS6s4z0qpsqDYKMYK1jdeTsk3W+61Ab6F9AnylORcjJkk+Bt5iRGNbCDRWE
         toGch4DOcExKtiFIHxqSBcm78Sz/8Yfwtm7s5NkN/rqzMsWHTC66U86KGzbNBtYJ/GTT
         7lOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=2zNGqD8w;
       spf=neutral (google.com: 2a00:1450:4864:20::42a is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=koA781L7fOYQVkzAuhG8CslU1LOMPyXfiHR8uydimi4=;
        b=igVa2TaZojTHQ99S0IijdZNdvYFAGhggoOMjTbIi2W9XX7bcXiMcK/DgOxm9Mm5WYU
         cQDL5qyTRJOWbVhYulqQcHdaxu0eVF23LYq+JznMTRMFL/bx5jJetcC+UfhI5O8Xlh1N
         VA5DDeGmP0SIetYxOwvQUNK26gxPIi6lYqMlwuOAH4+f6v6L+1/GcjLLr0U7CxJtw8Im
         8Y0kPgC/RsHR93eXU+ge/Aiy/il/RgsYCnVqObFjSqyKjNOvna0kAZCpUTBmD6P7glGM
         JJas1FinAg+Nl64CzLzjy4nNBe25dRYxiNyxTvCd1H5xe6JWonW+tghMpZWaDTtsIEc0
         b+/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=koA781L7fOYQVkzAuhG8CslU1LOMPyXfiHR8uydimi4=;
        b=h32Q/El55wOKsKJL9MLdXx70nCnV/cpF9eFcUABxMV/1NhPr+s/4ncsICMjaqz6EXd
         L5M/RMTwMs1qEYsY7JrjH7aJnsT3S+2UGgS0I431/LkeCeqLJRTRCO6KhhXhIYPRaEFt
         kfwhCDwbLgWaLReEfSgCD2VTmZBNEXAYXGHLvsjWmE93rNXEOG1gYwH6OkaEH3lqtm8n
         1y42cSBKtdnhVLC+Vu+Rvjz/yoDCUM8oFNHi6p0xdyQ2cLs7h1s20mv/PewhuXrKGp3z
         Uiim98TG3/Xl2QvP883JBKsEwHXIimbnDRJk7QeHEf7y3+lG7miHxL5LkoL4gx12gzRB
         C9dg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RHDI4ay9qFEmUmIutnAYIGXwx1Iy5sTGQBzkngyc393t6/AKz
	72Ege5YVonAijpQ40wjgFMk=
X-Google-Smtp-Source: ABdhPJyc8Tau/8AVnvi8tzlHEdvDySkOksGiYMYhJfcsaqlmBO++3fyRQXCl9L55+HdS5CzIEo33Vg==
X-Received: by 2002:a05:6512:3451:b0:473:dc7d:4d32 with SMTP id j17-20020a056512345100b00473dc7d4d32mr11085831lfr.667.1652068776309;
        Sun, 08 May 2022 20:59:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a596:0:b0:250:5d3e:5653 with SMTP id m22-20020a2ea596000000b002505d3e5653ls2599296ljp.9.gmail;
 Sun, 08 May 2022 20:59:35 -0700 (PDT)
X-Received: by 2002:a2e:9bc5:0:b0:24f:b2c:6dc0 with SMTP id w5-20020a2e9bc5000000b0024f0b2c6dc0mr8965989ljj.280.1652068775072;
        Sun, 08 May 2022 20:59:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652068775; cv=none;
        d=google.com; s=arc-20160816;
        b=vmSmSW6zvQhvSNpzg2P8XWB4R152+uEJP77CylF8QhQJk1wxg0+uKwl6QL6dWrD4G3
         J86PJMyzkF+J68WzKgXwUmyG+wqcRO4ZaalJJyj3sKYj7SL89kCFCmMElNS+vVSvoCze
         wWb8su6kMQOtw3EdBqUdD4JTpAPieaWw0BRke5rF/eGQycDkc5A7E1ygwYmonfcCglBv
         zdfDamMn9RtEZxoYyw/q+WFpJXJrcvfMVqQ2yeqqZVgZDDdoiOp8mMUCPEnFu8pOSXWG
         Wsdnf+8RQ4QRTpgZqP8/tC5ya40nXEjKfcOQHeEf1OduBuuM2C430dGvYJAUAlIA/0wD
         ruIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JnuLuqhJE6Vetw7UbNOjKhHhTCgbtn7302dHPMdxJyM=;
        b=aYcetG34AvA1c3S254WSEe8RxjxFLDdPxmsBYLIO1svnPXNGhgVLL0UrZfJk3LelyA
         Tvv2Rnn9Hi596R11K4lUKvfm7XrqyVcsYZp5Pk+xbElbo/L+SKkMhDGLm32Oi8BMlBCU
         xux43KpgSaCJAs8u9IfatjGJwrM5GOlyorN7Y6o+aNu/EcVx09O7YsTC0xq+dUtupnYt
         jjRRjDOdB2Gi03YgF64MVV5/uhNtiwnY1DFSFWye8qfxeLOXrxAkOiqOUFmb6yin0ica
         D+/QnS1saK7ujrM3B02nFvZ8wLX1shSRaSR49imUk8j2P0tOKDDhFa1HCiVhYRWB1Xdy
         zLgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=2zNGqD8w;
       spf=neutral (google.com: 2a00:1450:4864:20::42a is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id s1-20020a056512214100b00471902f5be2si506000lfr.3.2022.05.08.20.59.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 May 2022 20:59:35 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::42a is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id u3so17649400wrg.3
        for <kasan-dev@googlegroups.com>; Sun, 08 May 2022 20:59:34 -0700 (PDT)
X-Received: by 2002:a05:6000:799:b0:20c:6e3c:a28c with SMTP id
 bu25-20020a056000079900b0020c6e3ca28cmr12033469wrb.346.1652068774184; Sun, 08
 May 2022 20:59:34 -0700 (PDT)
MIME-Version: 1.0
References: <20220508160749.984-1-jszhang@kernel.org> <20220508160749.984-5-jszhang@kernel.org>
In-Reply-To: <20220508160749.984-5-jszhang@kernel.org>
From: Anup Patel <anup@brainfault.org>
Date: Mon, 9 May 2022 09:29:22 +0530
Message-ID: <CAAhSdy0m5_nnVoM+4exxeDADY04d-QOytD0GfUX8buuinn6Djw@mail.gmail.com>
Subject: Re: [PATCH v2 4/4] riscv: convert pgtable_l4|[l5]_enabled to static key
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b=2zNGqD8w;       spf=neutral (google.com: 2a00:1450:4864:20::42a is
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

On Sun, May 8, 2022 at 9:47 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> On a specific HW platform, pgtable_l4|[l5]_enabled won't change after
> boot, and the check sits at hot code path, this characteristic makes it
> suitable for optimization with static key.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
>  arch/riscv/include/asm/cpufeature.h | 11 +++++++
>  arch/riscv/include/asm/pgalloc.h    | 16 +++++-----
>  arch/riscv/include/asm/pgtable-64.h | 40 ++++++++++++-------------
>  arch/riscv/include/asm/pgtable.h    |  5 ++--
>  arch/riscv/kernel/cpu.c             |  4 +--
>  arch/riscv/mm/init.c                | 46 +++++++++++++----------------
>  arch/riscv/mm/kasan_init.c          | 16 +++++-----
>  arch/riscv/tools/cpucaps            |  2 ++
>  8 files changed, 73 insertions(+), 67 deletions(-)
>
> diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
> index 634a653c7fa2..a51f2602a0e3 100644
> --- a/arch/riscv/include/asm/cpufeature.h
> +++ b/arch/riscv/include/asm/cpufeature.h
> @@ -96,4 +96,15 @@ static inline bool system_supports_fpu(void)
>         return IS_ENABLED(CONFIG_FPU) && !cpus_have_final_cap(RISCV_HAS_NO_FPU);
>  }
>
> +static inline bool system_supports_sv48(void)
> +{
> +       return IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL) &&
> +               !cpus_have_const_cap(RISCV_HAS_NO_SV48);
> +}
> +
> +static inline bool system_supports_sv57(void)
> +{
> +       return IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL) &&
> +               !cpus_have_const_cap(RISCV_HAS_NO_SV57);
> +}
>  #endif
> diff --git a/arch/riscv/include/asm/pgalloc.h b/arch/riscv/include/asm/pgalloc.h
> index 947f23d7b6af..f49233ca696a 100644
> --- a/arch/riscv/include/asm/pgalloc.h
> +++ b/arch/riscv/include/asm/pgalloc.h
> @@ -41,7 +41,7 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
>
>  static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
>  {
> -       if (pgtable_l4_enabled) {
> +       if (system_supports_sv48()) {
>                 unsigned long pfn = virt_to_pfn(pud);
>
>                 set_p4d(p4d, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> @@ -51,7 +51,7 @@ static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
>  static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
>                                      pud_t *pud)
>  {
> -       if (pgtable_l4_enabled) {
> +       if (system_supports_sv48()) {
>                 unsigned long pfn = virt_to_pfn(pud);
>
>                 set_p4d_safe(p4d,
> @@ -61,7 +61,7 @@ static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
>
>  static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
>  {
> -       if (pgtable_l5_enabled) {
> +       if (system_supports_sv57()) {
>                 unsigned long pfn = virt_to_pfn(p4d);
>
>                 set_pgd(pgd, __pgd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
> @@ -71,7 +71,7 @@ static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
>  static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd,
>                                      p4d_t *p4d)
>  {
> -       if (pgtable_l5_enabled) {
> +       if (system_supports_sv57()) {
>                 unsigned long pfn = virt_to_pfn(p4d);
>
>                 set_pgd_safe(pgd,
> @@ -82,7 +82,7 @@ static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd,
>  #define pud_alloc_one pud_alloc_one
>  static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 return __pud_alloc_one(mm, addr);
>
>         return NULL;
> @@ -91,7 +91,7 @@ static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
>  #define pud_free pud_free
>  static inline void pud_free(struct mm_struct *mm, pud_t *pud)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 __pud_free(mm, pud);
>  }
>
> @@ -100,7 +100,7 @@ static inline void pud_free(struct mm_struct *mm, pud_t *pud)
>  #define p4d_alloc_one p4d_alloc_one
>  static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
>  {
> -       if (pgtable_l5_enabled) {
> +       if (system_supports_sv57()) {
>                 gfp_t gfp = GFP_PGTABLE_USER;
>
>                 if (mm == &init_mm)
> @@ -120,7 +120,7 @@ static inline void __p4d_free(struct mm_struct *mm, p4d_t *p4d)
>  #define p4d_free p4d_free
>  static inline void p4d_free(struct mm_struct *mm, p4d_t *p4d)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 __p4d_free(mm, p4d);
>  }
>
> diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
> index 7e246e9f8d70..9ee4abf0f528 100644
> --- a/arch/riscv/include/asm/pgtable-64.h
> +++ b/arch/riscv/include/asm/pgtable-64.h
> @@ -7,17 +7,15 @@
>  #define _ASM_RISCV_PGTABLE_64_H
>
>  #include <linux/const.h>
> -
> -extern bool pgtable_l4_enabled;
> -extern bool pgtable_l5_enabled;
> +#include <asm/cpufeature.h>
>
>  #define PGDIR_SHIFT_L3  30
>  #define PGDIR_SHIFT_L4  39
>  #define PGDIR_SHIFT_L5  48
>  #define PGDIR_SIZE_L3   (_AC(1, UL) << PGDIR_SHIFT_L3)
>
> -#define PGDIR_SHIFT     (pgtable_l5_enabled ? PGDIR_SHIFT_L5 : \
> -               (pgtable_l4_enabled ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3))
> +#define PGDIR_SHIFT     (system_supports_sv57() ? PGDIR_SHIFT_L5 : \
> +               (system_supports_sv48() ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3))
>  /* Size of region mapped by a page global directory */
>  #define PGDIR_SIZE      (_AC(1, UL) << PGDIR_SHIFT)
>  #define PGDIR_MASK      (~(PGDIR_SIZE - 1))
> @@ -119,7 +117,7 @@ static inline struct page *pud_page(pud_t pud)
>  #define mm_p4d_folded  mm_p4d_folded
>  static inline bool mm_p4d_folded(struct mm_struct *mm)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 return false;
>
>         return true;
> @@ -128,7 +126,7 @@ static inline bool mm_p4d_folded(struct mm_struct *mm)
>  #define mm_pud_folded  mm_pud_folded
>  static inline bool mm_pud_folded(struct mm_struct *mm)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 return false;
>
>         return true;
> @@ -159,7 +157,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
>
>  static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 *p4dp = p4d;
>         else
>                 set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
> @@ -167,7 +165,7 @@ static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
>
>  static inline int p4d_none(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 return (p4d_val(p4d) == 0);
>
>         return 0;
> @@ -175,7 +173,7 @@ static inline int p4d_none(p4d_t p4d)
>
>  static inline int p4d_present(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 return (p4d_val(p4d) & _PAGE_PRESENT);
>
>         return 1;
> @@ -183,7 +181,7 @@ static inline int p4d_present(p4d_t p4d)
>
>  static inline int p4d_bad(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 return !p4d_present(p4d);
>
>         return 0;
> @@ -191,7 +189,7 @@ static inline int p4d_bad(p4d_t p4d)
>
>  static inline void p4d_clear(p4d_t *p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 set_p4d(p4d, __p4d(0));
>  }
>
> @@ -207,7 +205,7 @@ static inline unsigned long _p4d_pfn(p4d_t p4d)
>
>  static inline pud_t *p4d_pgtable(p4d_t p4d)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 return (pud_t *)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
>
>         return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) });
> @@ -224,7 +222,7 @@ static inline struct page *p4d_page(p4d_t p4d)
>  #define pud_offset pud_offset
>  static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
>  {
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 return p4d_pgtable(*p4d) + pud_index(address);
>
>         return (pud_t *)p4d;
> @@ -232,7 +230,7 @@ static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
>
>  static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 *pgdp = pgd;
>         else
>                 set_p4d((p4d_t *)pgdp, (p4d_t){ pgd_val(pgd) });
> @@ -240,7 +238,7 @@ static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
>
>  static inline int pgd_none(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 return (pgd_val(pgd) == 0);
>
>         return 0;
> @@ -248,7 +246,7 @@ static inline int pgd_none(pgd_t pgd)
>
>  static inline int pgd_present(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 return (pgd_val(pgd) & _PAGE_PRESENT);
>
>         return 1;
> @@ -256,7 +254,7 @@ static inline int pgd_present(pgd_t pgd)
>
>  static inline int pgd_bad(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 return !pgd_present(pgd);
>
>         return 0;
> @@ -264,13 +262,13 @@ static inline int pgd_bad(pgd_t pgd)
>
>  static inline void pgd_clear(pgd_t *pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 set_pgd(pgd, __pgd(0));
>  }
>
>  static inline p4d_t *pgd_pgtable(pgd_t pgd)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 return (p4d_t *)pfn_to_virt(pgd_val(pgd) >> _PAGE_PFN_SHIFT);
>
>         return (p4d_t *)p4d_pgtable((p4d_t) { pgd_val(pgd) });
> @@ -288,7 +286,7 @@ static inline struct page *pgd_page(pgd_t pgd)
>  #define p4d_offset p4d_offset
>  static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
>  {
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 return pgd_pgtable(*pgd) + p4d_index(address);
>
>         return (p4d_t *)pgd;
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> index 046b44225623..ef2a1654100a 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -63,8 +63,8 @@
>   * position vmemmap directly below the VMALLOC region.
>   */
>  #ifdef CONFIG_64BIT
> -#define VA_BITS                (pgtable_l5_enabled ? \
> -                               57 : (pgtable_l4_enabled ? 48 : 39))
> +#define VA_BITS                (system_supports_sv57() ? \
> +                               57 : (system_supports_sv48() ? 48 : 39))
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
> index ccb617791e56..c8f3989b08f3 100644
> --- a/arch/riscv/kernel/cpu.c
> +++ b/arch/riscv/kernel/cpu.c
> @@ -141,9 +141,9 @@ static void print_mmu(struct seq_file *f)
>  #if defined(CONFIG_32BIT)
>         strncpy(sv_type, "sv32", 5);
>  #elif defined(CONFIG_64BIT)
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 strncpy(sv_type, "sv57", 5);
> -       else if (pgtable_l4_enabled)
> +       else if (system_supports_sv48())
>                 strncpy(sv_type, "sv48", 5);
>         else
>                 strncpy(sv_type, "sv39", 5);
> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index 5f3f26dd9f21..b6a59a5d1a7f 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -21,6 +21,7 @@
>  #include <linux/crash_dump.h>
>  #include <linux/hugetlb.h>
>
> +#include <asm/cpufeature.h>
>  #include <asm/fixmap.h>
>  #include <asm/tlbflush.h>
>  #include <asm/sections.h>
> @@ -44,11 +45,6 @@ u64 satp_mode __ro_after_init = SATP_MODE_32;
>  #endif
>  EXPORT_SYMBOL(satp_mode);
>
> -bool pgtable_l4_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> -bool pgtable_l5_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
> -EXPORT_SYMBOL(pgtable_l4_enabled);
> -EXPORT_SYMBOL(pgtable_l5_enabled);
> -
>  phys_addr_t phys_ram_base __ro_after_init;
>  EXPORT_SYMBOL(phys_ram_base);
>
> @@ -555,26 +551,26 @@ static void __init create_p4d_mapping(p4d_t *p4dp,
>  }
>
>  #define pgd_next_t             p4d_t
> -#define alloc_pgd_next(__va)   (pgtable_l5_enabled ?                   \
> -               pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled ?          \
> +#define alloc_pgd_next(__va)   (system_supports_sv57() ?               \
> +               pt_ops.alloc_p4d(__va) : (system_supports_sv48() ?      \
>                 pt_ops.alloc_pud(__va) : pt_ops.alloc_pmd(__va)))
> -#define get_pgd_next_virt(__pa)        (pgtable_l5_enabled ?                   \
> -               pt_ops.get_p4d_virt(__pa) : (pgd_next_t *)(pgtable_l4_enabled ? \
> +#define get_pgd_next_virt(__pa)        (system_supports_sv57() ?               \
> +               pt_ops.get_p4d_virt(__pa) : (pgd_next_t *)(system_supports_sv48() ?     \
>                 pt_ops.get_pud_virt(__pa) : (pud_t *)pt_ops.get_pmd_virt(__pa)))
>  #define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot)     \
> -                               (pgtable_l5_enabled ?                   \
> +                               (system_supports_sv57() ?               \
>                 create_p4d_mapping(__nextp, __va, __pa, __sz, __prot) : \
> -                               (pgtable_l4_enabled ?                   \
> +                               (system_supports_sv48() ?               \
>                 create_pud_mapping((pud_t *)__nextp, __va, __pa, __sz, __prot) :        \
>                 create_pmd_mapping((pmd_t *)__nextp, __va, __pa, __sz, __prot)))
> -#define fixmap_pgd_next                (pgtable_l5_enabled ?                   \
> -               (uintptr_t)fixmap_p4d : (pgtable_l4_enabled ?           \
> +#define fixmap_pgd_next                (system_supports_sv57() ?               \
> +               (uintptr_t)fixmap_p4d : (system_supports_sv48() ?       \
>                 (uintptr_t)fixmap_pud : (uintptr_t)fixmap_pmd))
> -#define trampoline_pgd_next    (pgtable_l5_enabled ?                   \
> -               (uintptr_t)trampoline_p4d : (pgtable_l4_enabled ?       \
> +#define trampoline_pgd_next    (system_supports_sv57() ?               \
> +               (uintptr_t)trampoline_p4d : (system_supports_sv48() ?   \
>                 (uintptr_t)trampoline_pud : (uintptr_t)trampoline_pmd))
> -#define early_dtb_pgd_next     (pgtable_l5_enabled ?                   \
> -               (uintptr_t)early_dtb_p4d : (pgtable_l4_enabled ?        \
> +#define early_dtb_pgd_next     (system_supports_sv57() ?               \
> +               (uintptr_t)early_dtb_p4d : (system_supports_sv48() ?    \
>                 (uintptr_t)early_dtb_pud : (uintptr_t)early_dtb_pmd))
>  #else
>  #define pgd_next_t             pte_t
> @@ -680,14 +676,14 @@ static __init pgprot_t pgprot_from_va(uintptr_t va)
>  #ifdef CONFIG_64BIT
>  static void __init disable_pgtable_l5(void)
>  {
> -       pgtable_l5_enabled = false;
> +       cpus_set_cap(RISCV_HAS_NO_SV57);

Similar to the comments on PATCH2, clear the Sv57 ISA extension here
of setting "No Sv57" capability.

>         kernel_map.page_offset = PAGE_OFFSET_L4;
>         satp_mode = SATP_MODE_48;
>  }
>
>  static void __init disable_pgtable_l4(void)
>  {
> -       pgtable_l4_enabled = false;
> +       cpus_set_cap(RISCV_HAS_NO_SV48);

Same as above.

>         kernel_map.page_offset = PAGE_OFFSET_L3;
>         satp_mode = SATP_MODE_39;
>  }
> @@ -816,11 +812,11 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
>                            PGDIR_SIZE,
>                            IS_ENABLED(CONFIG_64BIT) ? PAGE_TABLE : PAGE_KERNEL);
>
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 create_p4d_mapping(early_dtb_p4d, DTB_EARLY_BASE_VA,
>                                    (uintptr_t)early_dtb_pud, P4D_SIZE, PAGE_TABLE);
>
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 create_pud_mapping(early_dtb_pud, DTB_EARLY_BASE_VA,
>                                    (uintptr_t)early_dtb_pmd, PUD_SIZE, PAGE_TABLE);
>
> @@ -961,11 +957,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)

At start of setup_vm() for RV64, enable "Sv57" and "Sv48" ISA extensions
which will be cleared by disable_pgtable_l5() or disable_pgtable_l4().

>
>  #ifndef __PAGETABLE_PMD_FOLDED
>         /* Setup fixmap P4D and PUD */
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 create_p4d_mapping(fixmap_p4d, FIXADDR_START,
>                                    (uintptr_t)fixmap_pud, P4D_SIZE, PAGE_TABLE);
>         /* Setup fixmap PUD and PMD */
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 create_pud_mapping(fixmap_pud, FIXADDR_START,
>                                    (uintptr_t)fixmap_pmd, PUD_SIZE, PAGE_TABLE);
>         create_pmd_mapping(fixmap_pmd, FIXADDR_START,
> @@ -973,10 +969,10 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>         /* Setup trampoline PGD and PMD */
>         create_pgd_mapping(trampoline_pg_dir, kernel_map.virt_addr,
>                            trampoline_pgd_next, PGDIR_SIZE, PAGE_TABLE);
> -       if (pgtable_l5_enabled)
> +       if (system_supports_sv57())
>                 create_p4d_mapping(trampoline_p4d, kernel_map.virt_addr,
>                                    (uintptr_t)trampoline_pud, P4D_SIZE, PAGE_TABLE);
> -       if (pgtable_l4_enabled)
> +       if (system_supports_sv48())
>                 create_pud_mapping(trampoline_pud, kernel_map.virt_addr,
>                                    (uintptr_t)trampoline_pmd, PUD_SIZE, PAGE_TABLE);
>  #ifdef CONFIG_XIP_KERNEL
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index a22e418dbd82..7b662661f7a9 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -209,15 +209,15 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
>                 set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
>  }
>
> -#define kasan_early_shadow_pgd_next                    (pgtable_l5_enabled ?   \
> +#define kasan_early_shadow_pgd_next            (system_supports_sv57() ?       \
>                                 (uintptr_t)kasan_early_shadow_p4d :             \
> -                                                       (pgtable_l4_enabled ?   \
> +                                               (system_supports_sv48() ?       \
>                                 (uintptr_t)kasan_early_shadow_pud :             \
>                                 (uintptr_t)kasan_early_shadow_pmd))
>  #define kasan_populate_pgd_next(pgdp, vaddr, next, early)                      \
> -               (pgtable_l5_enabled ?                                           \
> +               (system_supports_sv57() ?                                       \
>                 kasan_populate_p4d(pgdp, vaddr, next, early) :                  \
> -               (pgtable_l4_enabled ?                                           \
> +               (system_supports_sv48() ?                                       \
>                         kasan_populate_pud(pgdp, vaddr, next, early) :          \
>                         kasan_populate_pmd((pud_t *)pgdp, vaddr, next)))
>
> @@ -274,7 +274,7 @@ asmlinkage void __init kasan_early_init(void)
>                                 (__pa((uintptr_t)kasan_early_shadow_pte)),
>                                 PAGE_TABLE));
>
> -       if (pgtable_l4_enabled) {
> +       if (system_supports_sv48()) {
>                 for (i = 0; i < PTRS_PER_PUD; ++i)
>                         set_pud(kasan_early_shadow_pud + i,
>                                 pfn_pud(PFN_DOWN
> @@ -282,7 +282,7 @@ asmlinkage void __init kasan_early_init(void)
>                                         PAGE_TABLE));
>         }
>
> -       if (pgtable_l5_enabled) {
> +       if (system_supports_sv57()) {
>                 for (i = 0; i < PTRS_PER_P4D; ++i)
>                         set_p4d(kasan_early_shadow_p4d + i,
>                                 pfn_p4d(PFN_DOWN
> @@ -393,9 +393,9 @@ static void __init kasan_shallow_populate_p4d(pgd_t *pgdp,
>  }
>
>  #define kasan_shallow_populate_pgd_next(pgdp, vaddr, next)                     \
> -               (pgtable_l5_enabled ?                                           \
> +               (system_supports_sv57() ?                                       \
>                 kasan_shallow_populate_p4d(pgdp, vaddr, next) :                 \
> -               (pgtable_l4_enabled ?                                           \
> +               (system_supports_sv48() ?                                       \
>                 kasan_shallow_populate_pud(pgdp, vaddr, next) :                 \
>                 kasan_shallow_populate_pmd(pgdp, vaddr, next)))
>
> diff --git a/arch/riscv/tools/cpucaps b/arch/riscv/tools/cpucaps
> index cb1ff2747859..0b9e19ec8371 100644
> --- a/arch/riscv/tools/cpucaps
> +++ b/arch/riscv/tools/cpucaps
> @@ -3,3 +3,5 @@
>  # Internal CPU capabilities constants, keep this list sorted
>
>  HAS_NO_FPU
> +HAS_NO_SV48
> +HAS_NO_SV57
> --
> 2.34.1
>

Regards,
Anup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy0m5_nnVoM%2B4exxeDADY04d-QOytD0GfUX8buuinn6Djw%40mail.gmail.com.
