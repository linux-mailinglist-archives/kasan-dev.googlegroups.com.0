Return-Path: <kasan-dev+bncBCMIZB7QWENRBVNL4X6AKGQE3XSMPCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id E959A29CFAF
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 12:28:22 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id r5sf2606843qtw.13
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 04:28:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603884502; cv=pass;
        d=google.com; s=arc-20160816;
        b=MOBUYlzf7OMDiVcrkz9+gGjwoCzbJN+AGezExtzS3t/mP1VK062B/4G4BIwL/4FO2M
         rVe191u/eb7VNFZu7M9Dr57qw+AN/txMqNuktQctu2wW4vANlFrStTbKHYaaO46hSIBE
         m2Ad6kZRJOvabRCWR6l53GZM9SOpafhwrk3yThMPNxPNoF4UdAodaqPMkOHLDjCaBCjN
         X6pfSoBTU7fdt4qbImHIET5WRijrc5EK0tqXbL3bQdBps/0iFGIOUpmJScvu+iMHvIpe
         brIx85ajO9Y5CHgJN+uTaaaTm/r8phbnLmOlacSmMsV7lhUr3ilCRhD4LqWrNZjnrqHo
         fjfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=d2inqt1nrNwJiuRt1/PxLmyH1YezDA8jpDAoo15ZZj4=;
        b=bdhEwKEpafVHrt8weIEuAFcCt2k8pV8X3mEUVKKRVRg6DagRbZhcGb4MA5HvypkYK+
         3lS7kFZnBspbl56EjqMjX1SRzghW2tpfrV03Ux2GG6OEW4eQUe2sQlwOWnzy4NgOA6cI
         LPFRPVROYEbfur8im+/fn41cEI9Wt0OWHopPfrI/Krki90uc890aQwVN8z7RbsT3parO
         O5QU3DJcU7oGWLdKlHf91Il36awXr+HYTajNDOnl7Nv+uh6uBrh3k+kWuqn3keobKQsv
         Pr+nZy8IXCHyByjWCcPYrAwQfJT+42px3BdnP5JqRSCw7LbWK+kDCJ8vaDq7xMHG3C3U
         YHBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="j/gMAMTD";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d2inqt1nrNwJiuRt1/PxLmyH1YezDA8jpDAoo15ZZj4=;
        b=eurB1PhCcTnz5BjIO9W4W7jeXXJ13Qh5sCSn84+kdainG2Wp8x/VtkaYHHaJvaNkDU
         V09M4cntvwuL0PsguEUZesL+dKuL4rYr/WDWBpyBYA+Aen/1tq+SxwkwxuyyBRIbmYkG
         90vZWpkTbXJwpPkL2JHKk/RtUfzCIL+k4LbQq/uAlTnwdBHPT6fFsmv4XjztAbmhaUUo
         ehTpUNsabAgpxJuGDV5cLKcBR0Wo0rmpjaSMr95hEpXNp8baBmZa5Yb4AFQ3byZgh4QR
         +Bf+d3XKO3UrNpkpd64gS8a5uvsOodiEZXRShzJbAFU/tel/f8oTqo69Pwd8X5/aJAH0
         lfuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d2inqt1nrNwJiuRt1/PxLmyH1YezDA8jpDAoo15ZZj4=;
        b=Y3Ym1LogIsnuAIV0oq26MlMVJw3QI9z8joo5TYviNVjRCOBPGZxYSgP9g9adZYr+3I
         1cTNALAt3gZu0aQH/Cs5Z8KeiYePKB0XyDNyC1ITzSKdZBBuN5RLYTYVE5lyHDg+X47W
         DITU4CpJlRG/VvRf2V1m8ob0lQwc/EYlorf7t0Ot4ehjqLZourmMXkB10932Msl3q/eA
         kQ9GoaE+lJ8h5Cc8pd7Igjh1T4BBt7rtNr80MHpdMaxdxWvkuu1+Ck4IvMW9cd6MsimS
         KeW5QPTqQZMO/akisOLJzXb+RjRJKDiMhQF//KmuCZR/hCs1S22Yx4VbXxWKB/wTTu1u
         MlZA==
X-Gm-Message-State: AOAM531CvMmNnEk0O2LjSL1vWwZ208kW5Nhaa11LSOJJ7jJ5AHkri5jM
	0JruBf8f7kttmjQQGUMbXKQ=
X-Google-Smtp-Source: ABdhPJwfbG8BCg6e3XJvOyu4xn6nUTJCUyN1Ag5PFsyS0jXWbZ2JQYDo95dmdXYGO34AUfUckEqJFg==
X-Received: by 2002:ae9:f402:: with SMTP id y2mr6290940qkl.459.1603884501860;
        Wed, 28 Oct 2020 04:28:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4a21:: with SMTP id n1ls1288512qvz.11.gmail; Wed, 28 Oct
 2020 04:28:21 -0700 (PDT)
X-Received: by 2002:a05:6214:9a7:: with SMTP id du7mr6865631qvb.21.1603884501394;
        Wed, 28 Oct 2020 04:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603884501; cv=none;
        d=google.com; s=arc-20160816;
        b=W/OUJqZVwlXxmUnw3jJhafnu5s/jwlRP5ePww+Oy24hvFfZnEvgPJ1Q478RVhbPngF
         +TCVAMZVYWLl/PSHehg0A6EHU60VAta91J4jCdf70NZ/L+fUpgzAgZCu/30nBpLUPvBo
         ZCqTj5ai+M2TLAEgznZL/yXfJFy/7Z1FpZRJWnF0X69tfiGCM+VqAw3BDYDVGMsDosDC
         gdlTnwqeyn1rgFnlBpemMghC/c/8N5zjbkRt+diqSJBgo8/Lgu24Z/wQNs/tLNqmFziQ
         U8qYc9qfMCzL11Yd4oa5WkR1IMQ8hvXJ+tc277CiQfkTIFdJ3AacEE8l753FGhtRT+zb
         kXgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PZef5tw/nzxfeTNGoZfWo9FnqFR59/C7pLoAJniJg8E=;
        b=Uk4KwkcgXH2HBTpSNewtMm+5hHxE9CHwJttct2k+I9ax85yG2fgi2E+HmlKfY8qqoy
         qaenfcoP5lHx2PH+sAXEk5qzJOgCsdTRhAo21fX5xzwgxYO9vcFlX8g53e+rwcSMRXZk
         SFa7cuanFapbxeGjPAsotqXRtrUlDok317kirlclUTb8fdkMPLmOeF7GkcjuAtc9aPsO
         p5xI3A9v5Qp9Cp8YNCegDzWLx/UymR1DuKLBShMJhr1pf+fyOInal9QbKrRmEEkT7QVv
         VHiwXHKLpYQgVrnXrORTXmE2go4pS3j8BxoHJ3GC6h8GghhXkiEenTzVaahif75Sx+ir
         rn7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="j/gMAMTD";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id h21si241315qka.7.2020.10.28.04.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 04:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id r8so3204066qtp.13
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 04:28:21 -0700 (PDT)
X-Received: by 2002:ac8:44b1:: with SMTP id a17mr6582933qto.43.1603884500705;
 Wed, 28 Oct 2020 04:28:20 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com> <94dfda607f7f7a28a5df9ee68703922aa9a52a1e.1602535397.git.andreyknvl@google.com>
In-Reply-To: <94dfda607f7f7a28a5df9ee68703922aa9a52a1e.1602535397.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 12:28:09 +0100
Message-ID: <CACT4Y+YhWM0MhS8wVsAmFmpBf4A8yDTLuV-JXtFYr79FJ9GGrQ@mail.gmail.com>
Subject: Re: [PATCH v5 02/40] arm64: mte: Add in-kernel MTE helpers
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
 header.i=@google.com header.s=20161025 header.b="j/gMAMTD";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Mon, Oct 12, 2020 at 10:44 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> Provide helper functions to manipulate allocation and pointer tags for
> kernel addresses.
>
> Low-level helper functions (mte_assign_*, written in assembly) operate
> tag values from the [0x0, 0xF] range. High-level helper functions
> (mte_get/set_*) use the [0xF0, 0xFF] range to preserve compatibility
> with normal kernel pointers that have 0xFF in their top byte.
>
> MTE_GRANULE_SIZE and related definitions are moved to mte-def.h header
> that doesn't have any dependencies and is safe to include into any
> low-level header.
>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> ---
> Change-Id: I1b5230254f90dc21a913447cb17f07fea7944ece
> ---
>  arch/arm64/include/asm/esr.h       |  1 +
>  arch/arm64/include/asm/mte-def.h   | 15 ++++++++
>  arch/arm64/include/asm/mte-kasan.h | 56 ++++++++++++++++++++++++++++++
>  arch/arm64/include/asm/mte.h       | 20 +++++++----
>  arch/arm64/kernel/mte.c            | 48 +++++++++++++++++++++++++
>  arch/arm64/lib/mte.S               | 16 +++++++++
>  6 files changed, 150 insertions(+), 6 deletions(-)
>  create mode 100644 arch/arm64/include/asm/mte-def.h
>  create mode 100644 arch/arm64/include/asm/mte-kasan.h
>
> diff --git a/arch/arm64/include/asm/esr.h b/arch/arm64/include/asm/esr.h
> index 035003acfa87..bc0dc66a6a27 100644
> --- a/arch/arm64/include/asm/esr.h
> +++ b/arch/arm64/include/asm/esr.h
> @@ -103,6 +103,7 @@
>  #define ESR_ELx_FSC            (0x3F)
>  #define ESR_ELx_FSC_TYPE       (0x3C)
>  #define ESR_ELx_FSC_EXTABT     (0x10)
> +#define ESR_ELx_FSC_MTE                (0x11)
>  #define ESR_ELx_FSC_SERROR     (0x11)
>  #define ESR_ELx_FSC_ACCESS     (0x08)
>  #define ESR_ELx_FSC_FAULT      (0x04)
> diff --git a/arch/arm64/include/asm/mte-def.h b/arch/arm64/include/asm/mte-def.h
> new file mode 100644
> index 000000000000..8401ac5840c7
> --- /dev/null
> +++ b/arch/arm64/include/asm/mte-def.h
> @@ -0,0 +1,15 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Copyright (C) 2020 ARM Ltd.
> + */
> +#ifndef __ASM_MTE_DEF_H
> +#define __ASM_MTE_DEF_H
> +
> +#define MTE_GRANULE_SIZE       UL(16)
> +#define MTE_GRANULE_MASK       (~(MTE_GRANULE_SIZE - 1))
> +#define MTE_TAG_SHIFT          56
> +#define MTE_TAG_SIZE           4
> +#define MTE_TAG_MASK           GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
> +#define MTE_TAG_MAX            (MTE_TAG_MASK >> MTE_TAG_SHIFT)
> +
> +#endif /* __ASM_MTE_DEF_H  */
> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> new file mode 100644
> index 000000000000..3a70fb1807fd
> --- /dev/null
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -0,0 +1,56 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Copyright (C) 2020 ARM Ltd.
> + */
> +#ifndef __ASM_MTE_KASAN_H
> +#define __ASM_MTE_KASAN_H
> +
> +#include <asm/mte-def.h>
> +
> +#ifndef __ASSEMBLY__
> +
> +#include <linux/types.h>
> +
> +/*
> + * The functions below are meant to be used only for the
> + * KASAN_HW_TAGS interface defined in asm/memory.h.
> + */
> +#ifdef CONFIG_ARM64_MTE
> +
> +static inline u8 mte_get_ptr_tag(void *ptr)
> +{
> +       /* Note: The format of KASAN tags is 0xF<x> */
> +       u8 tag = 0xF0 | (u8)(((u64)(ptr)) >> MTE_TAG_SHIFT);
> +
> +       return tag;
> +}
> +
> +u8 mte_get_mem_tag(void *addr);
> +u8 mte_get_random_tag(void);
> +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
> +
> +#else /* CONFIG_ARM64_MTE */
> +
> +static inline u8 mte_get_ptr_tag(void *ptr)
> +{
> +       return 0xFF;
> +}
> +
> +static inline u8 mte_get_mem_tag(void *addr)
> +{
> +       return 0xFF;
> +}
> +static inline u8 mte_get_random_tag(void)
> +{
> +       return 0xFF;
> +}
> +static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +{
> +       return addr;
> +}
> +
> +#endif /* CONFIG_ARM64_MTE */
> +
> +#endif /* __ASSEMBLY__ */
> +
> +#endif /* __ASM_MTE_KASAN_H  */
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 1c99fcadb58c..cf1cd181dcb2 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -5,14 +5,16 @@
>  #ifndef __ASM_MTE_H
>  #define __ASM_MTE_H
>
> -#define MTE_GRANULE_SIZE       UL(16)
> -#define MTE_GRANULE_MASK       (~(MTE_GRANULE_SIZE - 1))
> -#define MTE_TAG_SHIFT          56
> -#define MTE_TAG_SIZE           4
> +#include <asm/compiler.h>
> +#include <asm/mte-def.h>
> +
> +#define __MTE_PREAMBLE         ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
>
>  #ifndef __ASSEMBLY__
>
> +#include <linux/bitfield.h>
>  #include <linux/page-flags.h>
> +#include <linux/types.h>
>
>  #include <asm/pgtable-types.h>
>
> @@ -45,7 +47,9 @@ long get_mte_ctrl(struct task_struct *task);
>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
>                          unsigned long addr, unsigned long data);
>
> -#else
> +void mte_assign_mem_tag_range(void *addr, size_t size);
> +
> +#else /* CONFIG_ARM64_MTE */
>
>  /* unused if !CONFIG_ARM64_MTE, silence the compiler */
>  #define PG_mte_tagged  0
> @@ -80,7 +84,11 @@ static inline int mte_ptrace_copy_tags(struct task_struct *child,
>         return -EIO;
>  }
>
> -#endif
> +static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> +{
> +}
> +
> +#endif /* CONFIG_ARM64_MTE */
>
>  #endif /* __ASSEMBLY__ */
>  #endif /* __ASM_MTE_H  */
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 52a0638ed967..8f99c65837fd 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -13,10 +13,13 @@
>  #include <linux/swap.h>
>  #include <linux/swapops.h>
>  #include <linux/thread_info.h>
> +#include <linux/types.h>
>  #include <linux/uio.h>
>
> +#include <asm/barrier.h>
>  #include <asm/cpufeature.h>
>  #include <asm/mte.h>
> +#include <asm/mte-kasan.h>
>  #include <asm/ptrace.h>
>  #include <asm/sysreg.h>
>
> @@ -72,6 +75,51 @@ int memcmp_pages(struct page *page1, struct page *page2)
>         return ret;
>  }
>
> +u8 mte_get_mem_tag(void *addr)
> +{
> +       if (!system_supports_mte())
> +               return 0xFF;
> +
> +       asm(__MTE_PREAMBLE "ldg %0, [%0]"
> +           : "+r" (addr));
> +
> +       return mte_get_ptr_tag(addr);
> +}
> +
> +u8 mte_get_random_tag(void)
> +{
> +       void *addr;
> +
> +       if (!system_supports_mte())
> +               return 0xFF;
> +
> +       asm(__MTE_PREAMBLE "irg %0, %0"
> +           : "+r" (addr));
> +
> +       return mte_get_ptr_tag(addr);
> +}
> +
> +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> +{
> +       void *ptr = addr;
> +
> +       if ((!system_supports_mte()) || (size == 0))
> +               return addr;
> +
> +       /* Make sure that size is MTE granule aligned. */
> +       WARN_ON(size & (MTE_GRANULE_SIZE - 1));
> +
> +       /* Make sure that the address is MTE granule aligned. */
> +       WARN_ON((u64)addr & (MTE_GRANULE_SIZE - 1));
> +
> +       tag = 0xF0 | tag;
> +       ptr = (void *)__tag_set(ptr, tag);
> +
> +       mte_assign_mem_tag_range(ptr, size);

This function will be called on production hot paths. I think it makes
sense to shave off some overheads here.

The additional debug checks may be useful, so maybe we need an
additional debug mode (debug of MTE/KASAN itself)?

Do we ever call this when !system_supports_mte()? I think we wanted to
have static_if's higher up the stack. Having additional checks
scattered across lower-level functions is overhead for every
malloc/free.

Looking at how this is called from KASAN code.
KASAN code already ensures addr/size are properly aligned. I think we
should either remove the duplicate alignment checks, or do them only
in the additional debugging mode.
Does KASAN also ensure proper tag value (0xF0 mask)?

KASAN wrapper is inlined in this patch:
https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3699
but here we still have 2 non-inlined calls. The
mte_assign_mem_tag_range is kinda inherent since it's in .S. But then
I think this wrapper should be inlinable.

Also, can we move mte_assign_mem_tag_range into inline asm in the
header? This would avoid register spills around the call in
malloc/free.

The asm code seems to do the rounding of the size up at no additional
cost (checks remaining size > 0, right?). I think it makes sense to
document that as the contract and remove the additional round_up(size,
KASAN_GRANULE_SIZE) in KASAN code.



> +       return ptr;
> +}
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>         /* ISB required for the kernel uaccess routines */
> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
> index 03ca6d8b8670..ede1ea65428c 100644
> --- a/arch/arm64/lib/mte.S
> +++ b/arch/arm64/lib/mte.S
> @@ -149,3 +149,19 @@ SYM_FUNC_START(mte_restore_page_tags)
>
>         ret
>  SYM_FUNC_END(mte_restore_page_tags)
> +
> +/*
> + * Assign allocation tags for a region of memory based on the pointer tag
> + *   x0 - source pointer
> + *   x1 - size
> + *
> + * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> + * size must be non-zero and MTE_GRANULE_SIZE aligned.
> + */
> +SYM_FUNC_START(mte_assign_mem_tag_range)
> +1:     stg     x0, [x0]
> +       add     x0, x0, #MTE_GRANULE_SIZE
> +       subs    x1, x1, #MTE_GRANULE_SIZE
> +       b.gt    1b
> +       ret
> +SYM_FUNC_END(mte_assign_mem_tag_range)
> --
> 2.28.0.1011.ga647a8990f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYhWM0MhS8wVsAmFmpBf4A8yDTLuV-JXtFYr79FJ9GGrQ%40mail.gmail.com.
