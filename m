Return-Path: <kasan-dev+bncBDV37XP3XYDRBB5A4OWQMGQERQQ24QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EE44584214C
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 11:31:36 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2145ceb3e0dsf3788569fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jan 2024 02:31:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706610695; cv=pass;
        d=google.com; s=arc-20160816;
        b=Df6cvNeE/D/+jGlKMU1lizsIVGUu6MMxgYKl9QNL5NFuVKV87urIrZLquk84Zi+hNp
         4iZG4iyoKvVT0SqjZ/eDLKHnmlESPTRYcX/UFJ98LLL7c2ZfEVgpQN/szSBRLTXOzjs3
         CCXV8wK8Gscymdz8JjzLDHM3Y1PY5hzhx9WpcAgbdr5GH+p1jMbMrhpbII3IdcX4bTDH
         WS8R+3zEM5y4itVppgtb9Uoou70s4A6XvdJ43acyNwZqBM5Tc4HcNbdWvEM8b3pUKz9y
         2hANoJvrC8g3gHKU+2z9KEn6TEciF9DKbbX75vKV72gWg34CVlYkVjQN65sRc8w82ELt
         2VWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IsxYo70XLuQmBWXAlYXYMLFdHSS2s0pez4ZVwEM3icM=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=ly0YI/rjlXqFCutzfesaICvhBXCR1kYnSYfS9pG2+8ocIXgwb37b7Ps86cUpXakYNg
         zRB1Vc3xcfrShca4OOxiX9jWLJ9FIO0KCvbX21AePqoe8/ThGNxpVgdkwHYU4bHo1aFk
         nZA+vzzbP2V63hMIIcQh1ma2CZIUU0XL3vvqYZWyYELt8IvRT+yrzQcacYEPdPOcOj8L
         omoV4ZEMa2fL74gyDuwsdsVOopwcJKKS25PYcbmYo2bjBxxsDfWMyNBSv2t4JANLb3xc
         XBgDVzeUdQSsYfdUM58U8oGQWcVCVkTTjf5lgWDmKDHHddlV0Uh+yIoQkDLqu4qK09eg
         fWbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706610695; x=1707215495; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IsxYo70XLuQmBWXAlYXYMLFdHSS2s0pez4ZVwEM3icM=;
        b=HmVlHiPhq1/akdOnphbTD+wPMgleKy8Pe/bbB6DWAdNISD+feAWaHFkgNP4jFGr7uM
         llQcZtjsd8i+0OKQOZXukrIUMK+0gkVriN0l22eaNf89hYZ6Wt7X30ctrEf9YnSsOZlX
         nEiQO8lo8tiVbu3IgRyrDQ2oNJddHOBjrLcAlsZusOMxX+SoqqXc+OBvzKrp6h4nTP6d
         QIpUI411mUWLw5DpVGS+6MunqQ7S2jCn2RX4UbAQn3CGJHngqKIQ81vNoTt3kebKim/2
         gtLo1CXMJ0q/ji/KjY8LjXJdshs44BAISpTK/CN5YeTKqZbBxUJowjmBiBHO/EkIpwgk
         UIMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706610695; x=1707215495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IsxYo70XLuQmBWXAlYXYMLFdHSS2s0pez4ZVwEM3icM=;
        b=E32+bWXly9OQmDkfY4RpyExh1r5aWnCcmOdDnrZ/U21GjCeDGS4r6eHLby4+Wv4UTu
         R6OIXO/W5p+ByvuRj7jBWxpuJo7/PktlAfVz7x6kOXhU190KkozgUtlQ369LGFICRFxb
         QsqSTGx3sp7i/KiPGfSdRFABOaViETzZddBq6W/l4VEU2qJFNAiK+zq25brHR2UJ8xsf
         P9EEnhCgx9vqyRuWVaop+I38pdoIrS/BPN4WgbQZmmgpdEe9LKpuqzSIyvcyPgfuepI4
         m1s60C8RdGaOSe6wGBmIh8U429KrsYVG2pEfDwc6INS5khQjybyb6VpA1sLH+1W3XwS5
         Lr0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyBx/4Upz0rThHvQ7BrP5O4RNz5bTwaJ+B2oTZVK4lEcQmMbttM
	tsXqPmDYhEOK5/6l0aPPvweRmxEUirApNE5fBybyOlBKg6aQhiZI
X-Google-Smtp-Source: AGHT+IEmEwMuSjh3EWC9VgNj+Cp/gmA4jv+U2sMwAjRdWErS/QKKSAzAg2L2jrMSXD2fg1+UyJ3XYA==
X-Received: by 2002:a05:6870:8185:b0:214:8026:7c83 with SMTP id k5-20020a056870818500b0021480267c83mr7865378oae.5.1706610695324;
        Tue, 30 Jan 2024 02:31:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:970e:b0:217:2d0a:d876 with SMTP id
 n14-20020a056870970e00b002172d0ad876ls148379oaq.0.-pod-prod-05-us; Tue, 30
 Jan 2024 02:31:34 -0800 (PST)
X-Received: by 2002:a05:6870:c0c1:b0:214:fd35:ae33 with SMTP id e1-20020a056870c0c100b00214fd35ae33mr7153610oad.10.1706610694526;
        Tue, 30 Jan 2024 02:31:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706610694; cv=none;
        d=google.com; s=arc-20160816;
        b=QvLfx0I69LPJbb8yJSXVlLGAyHR3lgweJFNJU1bcXzMwRIpS8VrX4ySkKBGW15CLuv
         htelhIyMnmjSDDgsjHCCoCzmCWBFJdjbTzUOM2X2sQQNUQRKlMYjECsc86R62/Qw/ZOe
         AVvIko57Yairq51s0gY/g/dRYgMr5l4bC3zLnHm4eKT5Dccq3kJthTelcwgkqmKLwUWq
         jAyOsfzJT4Na9NZc7JJ0aOQS3Xx1mdwT4E4Wf1gvuNOesdIwh4eHoQZVcikzEgKvJh66
         JQRrHZubrAVlX3ssSGQZVc3ndbWYB5L0AOkaRdkwoHf2BwXe1AT5PLtMYdfP6nMZz5fq
         Np+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=QlaqEGdjvVtt9Hktj02t+cxH84CpvThfs8eoH0JNE/w=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=AVshtnvnspZNIe3UON1IB8Ss88BdJTb9nuIGl37zCMaa3qmmsXYVtgI3FjeMXy+1H/
         5dTM7JdYAjrINBlM+mLYNyln91bUDQdb3LqsB2/SupZ+YOuCYOGx2iI2z8RqHCZi6AYB
         zxKjpToXVVDicSU4dz146K85nm7cv82vZEHr3qPbHBabvik97QEq0Ixl561XkPV4ch52
         jeuL3tehUDr0NJWKUjhTIS0/eIi/+TF5luwuDfK+nMzLbGJ9NemX6yEH6EX32AqOji2P
         NMu9/wRX51FkLQnor1Umu1Iy3jxwCp5DOJAGBA/2s6kHMqIFbJCrCHbcOANO6I5SfmOO
         qv+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id gh22-20020a0568703b1600b0021868acb041si728723oab.4.2024.01.30.02.31.34
        for <kasan-dev@googlegroups.com>;
        Tue, 30 Jan 2024 02:31:34 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 89A17DA7;
	Tue, 30 Jan 2024 02:32:17 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.48.92])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A855E3F5A1;
	Tue, 30 Jan 2024 02:31:29 -0800 (PST)
Date: Tue, 30 Jan 2024 10:31:27 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v10 5/6] arm64: support copy_mc_[user]_highpage()
Message-ID: <ZbjP_19VCYmtsGcg@FVFF77S0Q05N>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-6-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240129134652.4004931-6-tongtiangen@huawei.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 29, 2024 at 09:46:51PM +0800, Tong Tiangen wrote:
> Currently, many scenarios that can tolerate memory errors when copying page
> have been supported in the kernel[1][2][3], all of which are implemented by
> copy_mc_[user]_highpage(). arm64 should also support this mechanism.
> 
> Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
> architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
> __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
> 
> Add new helper copy_mc_page() which provide a page copy implementation with
> machine check safe. The copy_mc_page() in copy_mc_page.S is largely borrows
> from copy_page() in copy_page.S and the main difference is copy_mc_page()
> add extable entry to every load/store insn to support machine check safe.
> 
> Add new extable type EX_TYPE_COPY_MC_PAGE_ERR_ZERO which used in
> copy_mc_page().
> 
> [1]a873dfe1032a ("mm, hwpoison: try to recover from copy-on write faults")
> [2]5f2500b93cc9 ("mm/khugepaged: recover from poisoned anonymous memory")
> [3]6b970599e807 ("mm: hwpoison: support recovery from ksm_might_need_to_copy()")
> 
> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
> ---
>  arch/arm64/include/asm/asm-extable.h | 15 ++++++
>  arch/arm64/include/asm/assembler.h   |  4 ++
>  arch/arm64/include/asm/mte.h         |  5 ++
>  arch/arm64/include/asm/page.h        | 10 ++++
>  arch/arm64/lib/Makefile              |  2 +
>  arch/arm64/lib/copy_mc_page.S        | 78 ++++++++++++++++++++++++++++
>  arch/arm64/lib/mte.S                 | 27 ++++++++++
>  arch/arm64/mm/copypage.c             | 66 ++++++++++++++++++++---
>  arch/arm64/mm/extable.c              |  7 +--
>  include/linux/highmem.h              |  8 +++
>  10 files changed, 213 insertions(+), 9 deletions(-)
>  create mode 100644 arch/arm64/lib/copy_mc_page.S
> 
> diff --git a/arch/arm64/include/asm/asm-extable.h b/arch/arm64/include/asm/asm-extable.h
> index 980d1dd8e1a3..819044fefbe7 100644
> --- a/arch/arm64/include/asm/asm-extable.h
> +++ b/arch/arm64/include/asm/asm-extable.h
> @@ -10,6 +10,7 @@
>  #define EX_TYPE_UACCESS_ERR_ZERO	2
>  #define EX_TYPE_KACCESS_ERR_ZERO	3
>  #define EX_TYPE_LOAD_UNALIGNED_ZEROPAD	4
> +#define EX_TYPE_COPY_MC_PAGE_ERR_ZERO	5
>  
>  /* Data fields for EX_TYPE_UACCESS_ERR_ZERO */
>  #define EX_DATA_REG_ERR_SHIFT	0
> @@ -51,6 +52,16 @@
>  #define _ASM_EXTABLE_UACCESS(insn, fixup)				\
>  	_ASM_EXTABLE_UACCESS_ERR_ZERO(insn, fixup, wzr, wzr)
>  
> +#define _ASM_EXTABLE_COPY_MC_PAGE_ERR_ZERO(insn, fixup, err, zero)	\
> +	__ASM_EXTABLE_RAW(insn, fixup, 					\
> +			  EX_TYPE_COPY_MC_PAGE_ERR_ZERO,		\
> +			  (						\
> +			    EX_DATA_REG(ERR, err) |			\
> +			    EX_DATA_REG(ZERO, zero)			\
> +			  ))
> +
> +#define _ASM_EXTABLE_COPY_MC_PAGE(insn, fixup)				\
> +	_ASM_EXTABLE_COPY_MC_PAGE_ERR_ZERO(insn, fixup, wzr, wzr)
>  /*
>   * Create an exception table entry for uaccess `insn`, which will branch to `fixup`
>   * when an unhandled fault is taken.
> @@ -59,6 +70,10 @@
>  	_ASM_EXTABLE_UACCESS(\insn, \fixup)
>  	.endm
>  
> +	.macro          _asm_extable_copy_mc_page, insn, fixup
> +	_ASM_EXTABLE_COPY_MC_PAGE(\insn, \fixup)
> +	.endm
> +

This should share a common EX_TYPE_ with the other "kaccess where memory error
is handled but other faults are fatal" cases.

>  /*
>   * Create an exception table entry for `insn` if `fixup` is provided. Otherwise
>   * do nothing.
> diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm/assembler.h
> index 513787e43329..e1d8ce155878 100644
> --- a/arch/arm64/include/asm/assembler.h
> +++ b/arch/arm64/include/asm/assembler.h
> @@ -154,6 +154,10 @@ lr	.req	x30		// link register
>  #define CPU_LE(code...) code
>  #endif
>  
> +#define CPY_MC(l, x...)		\
> +9999:   x;			\
> +	_asm_extable_copy_mc_page    9999b, l
> +
>  /*
>   * Define a macro that constructs a 64-bit value by concatenating two
>   * 32-bit registers. Note that on big endian systems the order of the
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 91fbd5c8a391..9cdded082dd4 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -92,6 +92,7 @@ static inline bool try_page_mte_tagging(struct page *page)
>  void mte_zero_clear_page_tags(void *addr);
>  void mte_sync_tags(pte_t pte, unsigned int nr_pages);
>  void mte_copy_page_tags(void *kto, const void *kfrom);
> +int mte_copy_mc_page_tags(void *kto, const void *kfrom);
>  void mte_thread_init_user(void);
>  void mte_thread_switch(struct task_struct *next);
>  void mte_cpu_setup(void);
> @@ -128,6 +129,10 @@ static inline void mte_sync_tags(pte_t pte, unsigned int nr_pages)
>  static inline void mte_copy_page_tags(void *kto, const void *kfrom)
>  {
>  }
> +static inline int mte_copy_mc_page_tags(void *kto, const void *kfrom)
> +{
> +	return 0;
> +}
>  static inline void mte_thread_init_user(void)
>  {
>  }
> diff --git a/arch/arm64/include/asm/page.h b/arch/arm64/include/asm/page.h
> index 2312e6ee595f..304cc86b8a10 100644
> --- a/arch/arm64/include/asm/page.h
> +++ b/arch/arm64/include/asm/page.h
> @@ -29,6 +29,16 @@ void copy_user_highpage(struct page *to, struct page *from,
>  void copy_highpage(struct page *to, struct page *from);
>  #define __HAVE_ARCH_COPY_HIGHPAGE
>  
> +#ifdef CONFIG_ARCH_HAS_COPY_MC
> +int copy_mc_page(void *to, const void *from);
> +int copy_mc_highpage(struct page *to, struct page *from);
> +#define __HAVE_ARCH_COPY_MC_HIGHPAGE
> +
> +int copy_mc_user_highpage(struct page *to, struct page *from,
> +		unsigned long vaddr, struct vm_area_struct *vma);
> +#define __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
> +#endif
> +
>  struct folio *vma_alloc_zeroed_movable_folio(struct vm_area_struct *vma,
>  						unsigned long vaddr);
>  #define vma_alloc_zeroed_movable_folio vma_alloc_zeroed_movable_folio
> diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
> index 29490be2546b..a2fd865b816d 100644
> --- a/arch/arm64/lib/Makefile
> +++ b/arch/arm64/lib/Makefile
> @@ -15,6 +15,8 @@ endif
>  
>  lib-$(CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE) += uaccess_flushcache.o
>  
> +lib-$(CONFIG_ARCH_HAS_COPY_MC) += copy_mc_page.o
> +
>  obj-$(CONFIG_CRC32) += crc32.o
>  
>  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) += error-inject.o
> diff --git a/arch/arm64/lib/copy_mc_page.S b/arch/arm64/lib/copy_mc_page.S
> new file mode 100644
> index 000000000000..524534d26d86
> --- /dev/null
> +++ b/arch/arm64/lib/copy_mc_page.S
> @@ -0,0 +1,78 @@
> +/* SPDX-License-Identifier: GPL-2.0-only */
> +/*
> + * Copyright (C) 2012 ARM Ltd.
> + */
> +
> +#include <linux/linkage.h>
> +#include <linux/const.h>
> +#include <asm/assembler.h>
> +#include <asm/page.h>
> +#include <asm/cpufeature.h>
> +#include <asm/alternative.h>
> +#include <asm/asm-extable.h>
> +
> +/*
> + * Copy a page from src to dest (both are page aligned) with machine check
> + *
> + * Parameters:
> + *	x0 - dest
> + *	x1 - src
> + * Returns:
> + * 	x0 - Return 0 if copy success, or -EFAULT if anything goes wrong
> + *	     while copying.
> + */
> +SYM_FUNC_START(__pi_copy_mc_page)
> +CPY_MC(9998f, ldp	x2, x3, [x1])
> +CPY_MC(9998f, ldp	x4, x5, [x1, #16])
> +CPY_MC(9998f, ldp	x6, x7, [x1, #32])
> +CPY_MC(9998f, ldp	x8, x9, [x1, #48])
> +CPY_MC(9998f, ldp	x10, x11, [x1, #64])
> +CPY_MC(9998f, ldp	x12, x13, [x1, #80])
> +CPY_MC(9998f, ldp	x14, x15, [x1, #96])
> +CPY_MC(9998f, ldp	x16, x17, [x1, #112])
> +
> +	add	x0, x0, #256
> +	add	x1, x1, #128
> +1:
> +	tst	x0, #(PAGE_SIZE - 1)
> +
> +CPY_MC(9998f, stnp	x2, x3, [x0, #-256])
> +CPY_MC(9998f, ldp	x2, x3, [x1])
> +CPY_MC(9998f, stnp	x4, x5, [x0, #16 - 256])
> +CPY_MC(9998f, ldp	x4, x5, [x1, #16])
> +CPY_MC(9998f, stnp	x6, x7, [x0, #32 - 256])
> +CPY_MC(9998f, ldp	x6, x7, [x1, #32])
> +CPY_MC(9998f, stnp	x8, x9, [x0, #48 - 256])
> +CPY_MC(9998f, ldp	x8, x9, [x1, #48])
> +CPY_MC(9998f, stnp	x10, x11, [x0, #64 - 256])
> +CPY_MC(9998f, ldp	x10, x11, [x1, #64])
> +CPY_MC(9998f, stnp	x12, x13, [x0, #80 - 256])
> +CPY_MC(9998f, ldp	x12, x13, [x1, #80])
> +CPY_MC(9998f, stnp	x14, x15, [x0, #96 - 256])
> +CPY_MC(9998f, ldp	x14, x15, [x1, #96])
> +CPY_MC(9998f, stnp	x16, x17, [x0, #112 - 256])
> +CPY_MC(9998f, ldp	x16, x17, [x1, #112])
> +
> +	add	x0, x0, #128
> +	add	x1, x1, #128
> +
> +	b.ne	1b
> +
> +CPY_MC(9998f, stnp	x2, x3, [x0, #-256])
> +CPY_MC(9998f, stnp	x4, x5, [x0, #16 - 256])
> +CPY_MC(9998f, stnp	x6, x7, [x0, #32 - 256])
> +CPY_MC(9998f, stnp	x8, x9, [x0, #48 - 256])
> +CPY_MC(9998f, stnp	x10, x11, [x0, #64 - 256])
> +CPY_MC(9998f, stnp	x12, x13, [x0, #80 - 256])
> +CPY_MC(9998f, stnp	x14, x15, [x0, #96 - 256])
> +CPY_MC(9998f, stnp	x16, x17, [x0, #112 - 256])
> +
> +	mov x0, #0
> +	ret
> +
> +9998:	mov x0, #-EFAULT
> +	ret
> +
> +SYM_FUNC_END(__pi_copy_mc_page)
> +SYM_FUNC_ALIAS(copy_mc_page, __pi_copy_mc_page)
> +EXPORT_SYMBOL(copy_mc_page)

This is a duplicate of the existing copy_page logic; it should be refactored
such that the logic can be shared.

> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
> index 5018ac03b6bf..2b748e83f6cf 100644
> --- a/arch/arm64/lib/mte.S
> +++ b/arch/arm64/lib/mte.S
> @@ -80,6 +80,33 @@ SYM_FUNC_START(mte_copy_page_tags)
>  	ret
>  SYM_FUNC_END(mte_copy_page_tags)
>  
> +/*
> + * Copy the tags from the source page to the destination one wiht machine check safe
> + *   x0 - address of the destination page
> + *   x1 - address of the source page
> + * Returns:
> + *   x0 - Return 0 if copy success, or
> + *        -EFAULT if anything goes wrong while copying.
> + */
> +SYM_FUNC_START(mte_copy_mc_page_tags)
> +	mov	x2, x0
> +	mov	x3, x1
> +	multitag_transfer_size x5, x6
> +1:
> +CPY_MC(2f, ldgm	x4, [x3])
> +CPY_MC(2f, stgm	x4, [x2])
> +	add	x2, x2, x5
> +	add	x3, x3, x5
> +	tst	x2, #(PAGE_SIZE - 1)
> +	b.ne	1b
> +
> +	mov x0, #0
> +	ret
> +
> +2:	mov x0, #-EFAULT
> +	ret
> +SYM_FUNC_END(mte_copy_mc_page_tags)
> +
>  /*
>   * Read tags from a user buffer (one tag per byte) and set the corresponding
>   * tags at the given kernel address. Used by PTRACE_POKEMTETAGS.
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index a7bb20055ce0..9765e40cde6c 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -14,6 +14,25 @@
>  #include <asm/cpufeature.h>
>  #include <asm/mte.h>
>  
> +static int do_mte(struct page *to, struct page *from, void *kto, void *kfrom, bool mc)
> +{
> +	int ret = 0;
> +
> +	if (system_supports_mte() && page_mte_tagged(from)) {
> +		/* It's a new page, shouldn't have been tagged yet */
> +		WARN_ON_ONCE(!try_page_mte_tagging(to));
> +		if (mc)
> +			ret = mte_copy_mc_page_tags(kto, kfrom);
> +		else
> +			mte_copy_page_tags(kto, kfrom);
> +
> +		if (!ret)
> +			set_page_mte_tagged(to);
> +	}
> +
> +	return ret;
> +}

The boolean 'mc' argument makes this painful to read, and I don't think it's
necessary to have this helper anyway.

It'd be clearer to have this expanded inline in the callers, e.g.

	// in copy_highpage(), as-is today
	if (system_supports_mte() && page_mte_tagged(from)) {
		/* It's a new page, shouldn't have been tagged yet */
		WARN_ON_ONCE(!try_page_mte_tagging(to));
		mte_copy_page_tags(kto, kfrom);
		set_page_mte_tagged(to);
	}

	// in copy_mc_highpage()
	if (system_supports_mte() && page_mte_tagged(from)) {
		/* It's a new page, shouldn't have been tagged yet */
		WARN_ON_ONCE(!try_page_mte_tagging(to));
		ret = mte_copy_mc_page_tags(kto, kfrom);
		if (ret)
			return -EFAULT;
		set_page_mte_tagged(to);
	}

Mark.

> +
>  void copy_highpage(struct page *to, struct page *from)
>  {
>  	void *kto = page_address(to);
> @@ -24,12 +43,7 @@ void copy_highpage(struct page *to, struct page *from)
>  	if (kasan_hw_tags_enabled())
>  		page_kasan_tag_reset(to);
>  
> -	if (system_supports_mte() && page_mte_tagged(from)) {
> -		/* It's a new page, shouldn't have been tagged yet */
> -		WARN_ON_ONCE(!try_page_mte_tagging(to));
> -		mte_copy_page_tags(kto, kfrom);
> -		set_page_mte_tagged(to);
> -	}
> +	do_mte(to, from, kto, kfrom, false);
>  }
>  EXPORT_SYMBOL(copy_highpage);
>  
> @@ -40,3 +54,43 @@ void copy_user_highpage(struct page *to, struct page *from,
>  	flush_dcache_page(to);
>  }
>  EXPORT_SYMBOL_GPL(copy_user_highpage);
> +
> +#ifdef CONFIG_ARCH_HAS_COPY_MC
> +/*
> + * Return -EFAULT if anything goes wrong while copying page or mte.
> + */
> +int copy_mc_highpage(struct page *to, struct page *from)
> +{
> +	void *kto = page_address(to);
> +	void *kfrom = page_address(from);
> +	int ret;
> +
> +	ret = copy_mc_page(kto, kfrom);
> +	if (ret)
> +		return -EFAULT;
> +
> +	if (kasan_hw_tags_enabled())
> +		page_kasan_tag_reset(to);
> +
> +	ret = do_mte(to, from, kto, kfrom, true);
> +	if (ret)
> +		return -EFAULT;
> +
> +	return 0;
> +}
> +EXPORT_SYMBOL(copy_mc_highpage);
> +
> +int copy_mc_user_highpage(struct page *to, struct page *from,
> +			unsigned long vaddr, struct vm_area_struct *vma)
> +{
> +	int ret;
> +
> +	ret = copy_mc_highpage(to, from);
> +
> +	if (!ret)
> +		flush_dcache_page(to);
> +
> +	return ret;
> +}
> +EXPORT_SYMBOL_GPL(copy_mc_user_highpage);
> +#endif
> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
> index 28ec35e3d210..bdc81518d207 100644
> --- a/arch/arm64/mm/extable.c
> +++ b/arch/arm64/mm/extable.c
> @@ -16,7 +16,7 @@ get_ex_fixup(const struct exception_table_entry *ex)
>  	return ((unsigned long)&ex->fixup + ex->fixup);
>  }
>  
> -static bool ex_handler_uaccess_err_zero(const struct exception_table_entry *ex,
> +static bool ex_handler_fixup_err_zero(const struct exception_table_entry *ex,
>  					struct pt_regs *regs)
>  {
>  	int reg_err = FIELD_GET(EX_DATA_REG_ERR, ex->data);
> @@ -69,7 +69,7 @@ bool fixup_exception(struct pt_regs *regs)
>  		return ex_handler_bpf(ex, regs);
>  	case EX_TYPE_UACCESS_ERR_ZERO:
>  	case EX_TYPE_KACCESS_ERR_ZERO:
> -		return ex_handler_uaccess_err_zero(ex, regs);
> +		return ex_handler_fixup_err_zero(ex, regs);
>  	case EX_TYPE_LOAD_UNALIGNED_ZEROPAD:
>  		return ex_handler_load_unaligned_zeropad(ex, regs);
>  	}
> @@ -87,7 +87,8 @@ bool fixup_exception_mc(struct pt_regs *regs)
>  
>  	switch (ex->type) {
>  	case EX_TYPE_UACCESS_ERR_ZERO:
> -		return ex_handler_uaccess_err_zero(ex, regs);
> +	case EX_TYPE_COPY_MC_PAGE_ERR_ZERO:
> +		return ex_handler_fixup_err_zero(ex, regs);
>  	}
>  
>  	return false;
> diff --git a/include/linux/highmem.h b/include/linux/highmem.h
> index c5ca1a1fc4f5..a42470ca42f2 100644
> --- a/include/linux/highmem.h
> +++ b/include/linux/highmem.h
> @@ -332,6 +332,7 @@ static inline void copy_highpage(struct page *to, struct page *from)
>  #endif
>  
>  #ifdef copy_mc_to_kernel
> +#ifndef __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
>  /*
>   * If architecture supports machine check exception handling, define the
>   * #MC versions of copy_user_highpage and copy_highpage. They copy a memory
> @@ -354,7 +355,9 @@ static inline int copy_mc_user_highpage(struct page *to, struct page *from,
>  
>  	return ret ? -EFAULT : 0;
>  }
> +#endif
>  
> +#ifndef __HAVE_ARCH_COPY_MC_HIGHPAGE
>  static inline int copy_mc_highpage(struct page *to, struct page *from)
>  {
>  	unsigned long ret;
> @@ -370,20 +373,25 @@ static inline int copy_mc_highpage(struct page *to, struct page *from)
>  
>  	return ret ? -EFAULT : 0;
>  }
> +#endif
>  #else
> +#ifndef __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
>  static inline int copy_mc_user_highpage(struct page *to, struct page *from,
>  					unsigned long vaddr, struct vm_area_struct *vma)
>  {
>  	copy_user_highpage(to, from, vaddr, vma);
>  	return 0;
>  }
> +#endif
>  
> +#ifndef __HAVE_ARCH_COPY_MC_HIGHPAGE
>  static inline int copy_mc_highpage(struct page *to, struct page *from)
>  {
>  	copy_highpage(to, from);
>  	return 0;
>  }
>  #endif
> +#endif
>  
>  static inline void memcpy_page(struct page *dst_page, size_t dst_off,
>  			       struct page *src_page, size_t src_off,
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZbjP_19VCYmtsGcg%40FVFF77S0Q05N.
