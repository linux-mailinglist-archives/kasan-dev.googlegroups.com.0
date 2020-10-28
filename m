Return-Path: <kasan-dev+bncBCMIZB7QWENRBS4F4X6AKGQERRAQHQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id DDCE129CF67
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 11:07:08 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id m64sf2680569pfm.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 03:07:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603879627; cv=pass;
        d=google.com; s=arc-20160816;
        b=TfF/Np8w/ETkwryjMuIoV40DYM0gLmaZF3/QQUoBQRlaUksHLQF0nt0X/b2vLdo1o+
         MQ2DaXuGpuq2BS99QAMU5KqpjSPi5JqMAYq09eJLE/Nd2oR3ss6TXvaJxWS5bNhVN9Ln
         jfdwW02u36S3XPQb2d1+uLTQC5xymHM5L01pwi+eu1/LC2K+g6loy63CjvO1PsAqwo6Q
         vb59I9jfpDIK79RtrBgvzVBS5Zys0EP6QyVYJIb5xbGSDk7FsqoXyRxM3QvmgHuBXMLO
         v8u75UTkvZnjuYY8+T07vlxDI2ky1FQ+oljU3a1wMPinbX2yXyalWZ231oDCIcDH5Dyn
         euEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VPzz/n80T8uErffIA/4GNUw6NMB2xEiXzpXB9tj0Lsw=;
        b=rV6M1l0Xn3hjdjiC4tA+hEXwH9wzTAsSuePMb+DOHnw9XZDgdni/pwQifg7O9NzMcO
         5bhc4yUTE7OVrVAKBLMaG3uxkW01sX34FauU+8xZD4yLEcGI6yjqbegwLpVcC/WhIkHK
         1yqomTN9L0//pKSRC/r0y4nhFWKzivyujEHOGS1cPYPcsrfv1hptlwxRKE96VQMZbaV3
         AQ01rPWKAkjAvLXKnEZ+4lHvnIwgVpqNm+aZZ0wSNZKKb80+cB1rvkhGMd6c/dIDvXbV
         e8E/v4aSRfzjvRZerKYNzzrBLFha1eK+C0pxf7tU5TkOUJvqcCiCpG4TPPrAWJ1ygPv/
         vn4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O7ooARZ7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VPzz/n80T8uErffIA/4GNUw6NMB2xEiXzpXB9tj0Lsw=;
        b=nSSu2dguygz5WU+XstrpdtcUkM+9WkI3b4P23J+S6ESLEWQni1ehwaus/cVfWwDXen
         MsZ7XdMEN6qDI49lcjv1rkBV4acY7WqbZLVqNoyNMRh4cZmaafoPpLGTcyyriRF4Iq0a
         PYF9PJv/9qWgAlPnexP6VID1GMAm5MLSDkFdvAupfO0FmYxPC0ia9WT5ioZc07GQMqU0
         CzQa4BgF/gieU8orMIxyRR3JLawmzgeE0zCEB4P+P99COMIWU+DVkcdJwlRQu7S5y+1G
         BQGDzpkjo/58mneWJKY5pczEtjfXXBVIoZRHJvptzSRkJ10hr32DCEL29qohNdlOLKf9
         Pnxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VPzz/n80T8uErffIA/4GNUw6NMB2xEiXzpXB9tj0Lsw=;
        b=Y44mEguL00R6ItMGK+TLjxxPBIMfpFCY/HK7AIBAhxQfo4wYIzIc/+CMiXzCYOc8G7
         wzTT/Hoe8AnibkZChaXS9Qkx/iFVL93zhTjLgsJl+XhANYW3/70SjpnpL/FyugJoQYYK
         MLTI7PViF8zFh82x0eZelcGODjz8Ddqn/Pdd38rZ32xoJgornqx6AXFIVjehdVN83t/z
         E5B64PhCsgrbIXWTUQUgLSv8jC9ebisC/7oHbuOBWuyGst0eH2I27urT9O6qaVtK/ZGT
         HiupljKoCXIeXlVz5F3V01QtG+c1VKTucaFeSrmi/7/WQDzLm/2SLXPyraHt5Rp5re3M
         nCfA==
X-Gm-Message-State: AOAM532wYnHTC7hWdlzme1iCYkVcZUB0ae90ChBlRxvlrForooXTZZV3
	Ay7MSflQfQ7sIRQqHsYcBLI=
X-Google-Smtp-Source: ABdhPJwABw1L9LlOEYrUE+IsoVakLBiJzoATv3VoS6NX0Ex1oY3l0oC9be025clOsQYDNs0UPRWB6g==
X-Received: by 2002:a17:902:529:b029:d6:aad:fd41 with SMTP id 38-20020a1709020529b02900d60aadfd41mr6780136plf.33.1603879627214;
        Wed, 28 Oct 2020 03:07:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4486:: with SMTP id t6ls2324764pjg.0.canary-gmail;
 Wed, 28 Oct 2020 03:07:06 -0700 (PDT)
X-Received: by 2002:a17:90b:3d5:: with SMTP id go21mr6292337pjb.149.1603879626617;
        Wed, 28 Oct 2020 03:07:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603879626; cv=none;
        d=google.com; s=arc-20160816;
        b=Zh/zQqq8fhzixvAV82ju33/kYdiHxfsB70Be5q9oBScEqYk9LDB/DJcm4JPBpO49B2
         k8y6ADGQmnJ/ytIeU+v8M/Iy5UUXS6rLFuzR3/JXojBnBRdO6htgfVtsANk9XNylhEoU
         60cd/DNVv+9WA+4ImPCf6Od9GDUdPzP8z7zHghzfaqq8EYY19Mk6rP+j93uDFvNWw8h9
         TbajLFeLB3JPaZlHZNHNRMKbksiNmMFn895RmNfS3k5VUl/9WKHvQZegVhc9TpjEFlKd
         AAActB2BRtyl2ThViczXWWu3k7fSKTl8vFi35J7el/Cvgii2HPR3Ii8uWS0EphY/QwtA
         PjFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PJlkXauM2ljM4AlQLzaN5NthsxVm6kRrZ7rEv/3OqdE=;
        b=N76t46jSzBtbiSnxpCqjg9aCUuvadQ/7sipP+Q6J9w/Z3mbNSKt2i245SfUXkhvR42
         VsrTPIccq680v2Oh0dFCoyt+hFKQDRLOrpR9iaQa2F7OLj55Y29UCM86qMo6itbOKtl2
         zGE2ryZ/mTe2llnCk3EaIa9skKb/K/DPz6zzIS8b9GRJqm66XcXqWJoFh0QnALlch0RE
         EIf3g3IY78CVAWsYCjtaLTBKQKXkRGNhXzcq4I2ITcpxI9wggGPD4Mny8/aX1vboeeS1
         JuBgpK9rQomlP5la97hK+9e6eYCCXCK9QE/GHt0MlTwF3yW+QPsamkgHLJWy9q5lsonl
         P6zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O7ooARZ7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id ce12si244700pjb.1.2020.10.28.03.07.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 03:07:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id s17so2083976qvr.11
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 03:07:06 -0700 (PDT)
X-Received: by 2002:a05:6214:a0f:: with SMTP id dw15mr6673023qvb.44.1603879625388;
 Wed, 28 Oct 2020 03:07:05 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com> <33c0811d707356b7b267b2de41b55b2728940723.1602535397.git.andreyknvl@google.com>
In-Reply-To: <33c0811d707356b7b267b2de41b55b2728940723.1602535397.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 11:06:54 +0100
Message-ID: <CACT4Y+ZyaqdYic_K6Mj9RcvO+23OQ0q2Pe-c3YS1zMW4j1woQw@mail.gmail.com>
Subject: Re: [PATCH v5 08/40] arm64: mte: Switch GCR_EL1 in kernel entry and exit
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=O7ooARZ7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f41
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Oct 12, 2020 at 10:45 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> When MTE is present, the GCR_EL1 register contains the tags mask that
> allows to exclude tags from the random generation via the IRG instruction.
>
> With the introduction of the new Tag-Based KASAN API that provides a
> mechanism to reserve tags for special reasons, the MTE implementation
> has to make sure that the GCR_EL1 setting for the kernel does not affect
> the userspace processes and viceversa.
>
> Save and restore the kernel/user mask in GCR_EL1 in kernel entry and exit.
>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
> Change-Id: I0081cba5ace27a9111bebb239075c9a466af4c84
> ---
>  arch/arm64/include/asm/mte-def.h   |  1 -
>  arch/arm64/include/asm/mte-kasan.h |  6 +++++
>  arch/arm64/include/asm/mte.h       |  2 ++
>  arch/arm64/kernel/asm-offsets.c    |  3 +++
>  arch/arm64/kernel/cpufeature.c     |  3 +++
>  arch/arm64/kernel/entry.S          | 41 ++++++++++++++++++++++++++++++
>  arch/arm64/kernel/mte.c            | 22 +++++++++++++---
>  7 files changed, 74 insertions(+), 4 deletions(-)
>
> diff --git a/arch/arm64/include/asm/mte-def.h b/arch/arm64/include/asm/mte-def.h
> index 8401ac5840c7..2d73a1612f09 100644
> --- a/arch/arm64/include/asm/mte-def.h
> +++ b/arch/arm64/include/asm/mte-def.h
> @@ -10,6 +10,5 @@
>  #define MTE_TAG_SHIFT          56
>  #define MTE_TAG_SIZE           4
>  #define MTE_TAG_MASK           GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> -#define MTE_TAG_MAX            (MTE_TAG_MASK >> MTE_TAG_SHIFT)
>
>  #endif /* __ASM_MTE_DEF_H  */
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index 3a70fb1807fd..a4c61b926d4a 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -29,6 +29,8 @@ u8 mte_get_mem_tag(void *addr);
>  u8 mte_get_random_tag(void);
>  void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
>
> +void mte_init_tags(u64 max_tag);

This should be marked as __init?


>  #else /* CONFIG_ARM64_MTE */
>
>  static inline u8 mte_get_ptr_tag(void *ptr)
> @@ -49,6 +51,10 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>         return addr;
>  }
>
> +static inline void mte_init_tags(u64 max_tag)
> +{
> +}
> +
>  #endif /* CONFIG_ARM64_MTE */
>
>  #endif /* __ASSEMBLY__ */
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index cf1cd181dcb2..d02aff9f493d 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -18,6 +18,8 @@
>
>  #include <asm/pgtable-types.h>
>
> +extern u64 gcr_kernel_excl;
> +
>  void mte_clear_page_tags(void *addr);
>  unsigned long mte_copy_tags_from_user(void *to, const void __user *from,
>                                       unsigned long n);
> diff --git a/arch/arm64/kernel/asm-offsets.c b/arch/arm64/kernel/asm-offsets.c
> index 7d32fc959b1a..dfe6ed8446ac 100644
> --- a/arch/arm64/kernel/asm-offsets.c
> +++ b/arch/arm64/kernel/asm-offsets.c
> @@ -47,6 +47,9 @@ int main(void)
>  #ifdef CONFIG_ARM64_PTR_AUTH
>    DEFINE(THREAD_KEYS_USER,     offsetof(struct task_struct, thread.keys_user));
>    DEFINE(THREAD_KEYS_KERNEL,   offsetof(struct task_struct, thread.keys_kernel));
> +#endif
> +#ifdef CONFIG_ARM64_MTE
> +  DEFINE(THREAD_GCR_EL1_USER,  offsetof(struct task_struct, thread.gcr_user_excl));
>  #endif
>    BLANK();
>    DEFINE(S_X0,                 offsetof(struct pt_regs, regs[0]));
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index eca06b8c74db..e76634ad5bc7 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -1721,6 +1721,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>
>         /* Enable in-kernel MTE only if KASAN_HW_TAGS is enabled */
>         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {
> +               /* Enable the kernel exclude mask for random tags generation */
> +               write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
> +
>                 /* Enable MTE Sync Mode for EL1 */
>                 sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>                 isb();
> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> index ff34461524d4..eeaac91021bf 100644
> --- a/arch/arm64/kernel/entry.S
> +++ b/arch/arm64/kernel/entry.S
> @@ -175,6 +175,43 @@ alternative_else_nop_endif
>  #endif
>         .endm
>
> +       .macro mte_set_gcr, tmp, tmp2
> +#ifdef CONFIG_ARM64_MTE
> +       /*
> +        * Calculate and set the exclude mask preserving
> +        * the RRND (bit[16]) setting.
> +        */
> +       mrs_s   \tmp2, SYS_GCR_EL1
> +       bfi     \tmp2, \tmp, #0, #16
> +       msr_s   SYS_GCR_EL1, \tmp2
> +       isb
> +#endif
> +       .endm
> +
> +       .macro mte_set_kernel_gcr, tmp, tmp2
> +#ifdef CONFIG_KASAN_HW_TAGS
> +alternative_if_not ARM64_MTE
> +       b       1f
> +alternative_else_nop_endif
> +       ldr_l   \tmp, gcr_kernel_excl
> +
> +       mte_set_gcr \tmp, \tmp2
> +1:
> +#endif
> +       .endm
> +
> +       .macro mte_set_user_gcr, tsk, tmp, tmp2
> +#ifdef CONFIG_ARM64_MTE
> +alternative_if_not ARM64_MTE
> +       b       1f
> +alternative_else_nop_endif
> +       ldr     \tmp, [\tsk, #THREAD_GCR_EL1_USER]
> +
> +       mte_set_gcr \tmp, \tmp2
> +1:
> +#endif
> +       .endm
> +
>         .macro  kernel_entry, el, regsize = 64
>         .if     \regsize == 32
>         mov     w0, w0                          // zero upper 32 bits of x0
> @@ -214,6 +251,8 @@ alternative_else_nop_endif
>
>         ptrauth_keys_install_kernel tsk, x20, x22, x23
>
> +       mte_set_kernel_gcr x22, x23
> +
>         scs_load tsk, x20
>         .else
>         add     x21, sp, #S_FRAME_SIZE
> @@ -332,6 +371,8 @@ alternative_else_nop_endif
>         /* No kernel C function calls after this as user keys are set. */
>         ptrauth_keys_install_user tsk, x0, x1, x2
>
> +       mte_set_user_gcr tsk, x0, x1
> +
>         apply_ssbd 0, x0, x1
>         .endif
>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index a9f03be75cef..ca8206b7f9a6 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -23,6 +23,8 @@
>  #include <asm/ptrace.h>
>  #include <asm/sysreg.h>
>
> +u64 gcr_kernel_excl __ro_after_init;
> +
>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  {
>         pte_t old_pte = READ_ONCE(*ptep);
> @@ -121,6 +123,17 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>         return ptr;
>  }
>
> +void mte_init_tags(u64 max_tag)
> +{
> +       /*
> +        * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
> +        * This conversion is required to extract the MTE tag from a KASAN one.
> +        */
> +       u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT, max_tag), 0);
> +
> +       gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> +}
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>         /* ISB required for the kernel uaccess routines */
> @@ -156,7 +169,11 @@ static void update_gcr_el1_excl(u64 excl)
>  static void set_gcr_el1_excl(u64 excl)
>  {
>         current->thread.gcr_user_excl = excl;
> -       update_gcr_el1_excl(excl);
> +
> +       /*
> +        * SYS_GCR_EL1 will be set to current->thread.gcr_user_excl value
> +        * by mte_set_user_gcr() in kernel_exit,
> +        */
>  }
>
>  void flush_mte_state(void)
> @@ -182,7 +199,6 @@ void mte_thread_switch(struct task_struct *next)
>         /* avoid expensive SCTLR_EL1 accesses if no change */
>         if (current->thread.sctlr_tcf0 != next->thread.sctlr_tcf0)
>                 update_sctlr_el1_tcf0(next->thread.sctlr_tcf0);
> -       update_gcr_el1_excl(next->thread.gcr_user_excl);
>  }
>
>  void mte_suspend_exit(void)
> @@ -190,7 +206,7 @@ void mte_suspend_exit(void)
>         if (!system_supports_mte())
>                 return;
>
> -       update_gcr_el1_excl(current->thread.gcr_user_excl);
> +       update_gcr_el1_excl(gcr_kernel_excl);
>  }
>
>  long set_mte_ctrl(struct task_struct *task, unsigned long arg)
> --
> 2.28.0.1011.ga647a8990f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZyaqdYic_K6Mj9RcvO%2B23OQ0q2Pe-c3YS1zMW4j1woQw%40mail.gmail.com.
