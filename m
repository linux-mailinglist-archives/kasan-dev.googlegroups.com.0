Return-Path: <kasan-dev+bncBDV37XP3XYDRB2H5XK7AMGQEUPNDG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4972BA5912B
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Mar 2025 11:28:58 +0100 (CET)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2c24c595a08sf3250658fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Mar 2025 03:28:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741602537; cv=pass;
        d=google.com; s=arc-20240605;
        b=iRdzV4R2qDGT6MAI7WvcTzPPUTWOEIeOcZVkkIQKLOspxI63DqeNVeZ0QhdEkN1XdZ
         ujgGGREopKadBzzynzsv4ubybkirxLqXytDRGInMK5jfxoKW3Br8qvQbzFq95F5ISAKw
         7e9G1a0b2dI7azaCgdwR6FKiJhI8xrg4CO+XudMJjycc8TiSNr5p7niLiOE/0+9rWDT2
         7xMljwC4wfaP+SCjG9MC1yi7Kt5xtGUQk8zZSpCWiCkG3PUE6nh1x3f7NHNvfORO9j0h
         FsggWBnDb30F4vWsRjpiIj2bwo6rIQGxNxeYcsLXRPuhJBNQde+AEgdzDwKLSMxZ2i5A
         y2YA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+IH556Utk0bEHrOA0rOhXjb/jjBtEtTQMnqefCN9oB8=;
        fh=TGT77bDdB9g/5MiWjEU4sZFy4UX1Ov8TE0Bwh3IzC4I=;
        b=NBFF2ALzKeZL4JNt0dIRq5lKqXk4eEaQQEm3Rr0FnleqJUkUrgx7PrWNcR/1lqBb/a
         wWSTZsY2uSAK2jnWr19yYHhR5rhfxNpXTEhZOiuISmagQdHYK57u4j4hlCyE3PgVqYSd
         y0UHKOBG2rCcYFFE06Y0lNin8OuyrhjgnjArfIrhQaS4CEyWUyqA5LH87e3FkEEBWaWc
         mVsNajbtdekPbKReWRSE+AABDFPljNsoNk2YurIEFj3GZT9IZUnX25Dgm4VFXPGtdxvv
         fd8IzTGsb7v5jeEAY8H26T2OyHk4TEZCTzSR64S22g8jonOVi1U7kAKwpPk6qQ9UNkfG
         pRqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741602537; x=1742207337; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+IH556Utk0bEHrOA0rOhXjb/jjBtEtTQMnqefCN9oB8=;
        b=PzPs8rHEofLWrv0FelRIBbgWfHvIN+hxzcAX4yLnAFKh3Nj6cvuirA3dUP4NOokbds
         BEX4/ZOQ7sbsRWCDl6JDXg2JXobXmR4wNh+nDRaJGnPjM40WNAzaOp5Yj4JAx7gCZAQL
         nI2Zt48pqwJb6/htzKfUKVfXItwGTVENPA3vLq858oIRIRavOGU4up8uQ+2058GCbcI1
         liLe0bl+6I9kNM/dewhBsbLH/ugqVlNNKrIUxgEdxzGM59c2e8Fsh3KS2p3lKc2/1ava
         SYEgrJ58N+ugK99q81DXPw6I/py/A84ZvjeenVdtzcgVaiiXQ9gsLAEYc1blo+aOoO9L
         5mMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741602537; x=1742207337;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+IH556Utk0bEHrOA0rOhXjb/jjBtEtTQMnqefCN9oB8=;
        b=dgj/Wuu2LdCu7YDWYElr9iuygnZiBfV2YZ2+SSKUbZ7BNRX+UV+cNuZbvdNjJKN0tq
         brdCKEjfZ2yHHFAzcbOvKF2cfEfcJd1CFYXb1iISUVTE4CUGPhkqqWTf3ZWsGSq1NHgE
         hsaBVDHqEYsKkPC98bNIXnvhoofC/vLwgvn2HbE08cJa/cZVUfXsNMiJkQfe6Js2VxbR
         YASGHCj9Wrl2KWo3P5cLxOr/TULDPAbxkuoyjJpngVIUmu8NDydOfgAbbW/BZcdu0Wz1
         gNfXMv6btRRZ/Ds0aWEVlI+kz9pvTVvTVtaT7Nrllb3l2Pz3JffnatLpnJsqgFoMGf1l
         1aqw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW39e8lKxwjS6FEdQNb2b3QqdhNVsYlonufnRR4No38ED7wtk5VTSOp+yEk43+YNaCiS9RS5g==@lfdr.de
X-Gm-Message-State: AOJu0YxkoqQYwF5fLzZVhA55USRenfXHwB7JJq4obujWsOl4KsZkxjLX
	5bmgXQ1PS2Ztcf9mYEazTiAkPOTMrkelK3xQnkosdiLzqYyxfStQ
X-Google-Smtp-Source: AGHT+IHDVTxe2EX6UqqqrVjPQ00Zer0RTOxQSSKL4PGye9y3cRPu60MywICs05/iFVEaEy5EWp3FcQ==
X-Received: by 2002:a05:6870:5488:b0:287:471:41eb with SMTP id 586e51a60fabf-2c260f85f86mr6665782fac.6.1741602536747;
        Mon, 10 Mar 2025 03:28:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGSnvaxsF8n280QJQ+j7Xd/g3riaxC5P0PecbsO0Xb/YQ==
Received: by 2002:a05:6870:9e03:b0:2c1:52da:c80a with SMTP id
 586e51a60fabf-2c23f397510ls1408278fac.0.-pod-prod-07-us; Mon, 10 Mar 2025
 03:28:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcHgIdZKoKUBhjKHKrXaTQLLVPYqYigFnIwTzRyuCAPLG8cWaV/LxW10aaTJef07J8v64hLgCIqsE=@googlegroups.com
X-Received: by 2002:a05:6870:ce84:b0:2c1:504f:42ed with SMTP id 586e51a60fabf-2c26143449dmr7632401fac.29.1741602535782;
        Mon, 10 Mar 2025 03:28:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741602535; cv=none;
        d=google.com; s=arc-20240605;
        b=h8xk9ryOFlEYpTX9Kf/y1DAZsBueZ3e6E5ctoxiAR9nM/qWJgj15uNQxjixPlZ/d9X
         t5oc73gT0lacCCVHGYHU1OyI6LxBAFCVMS88ogB4RdgjAcVVpcq0ZtHAMr0IqnTtgTca
         yszR406B+odt/M2v0fxZLqYPLjyDYBedGfGimt8MD0IrknXL7IHUR8P1QePi5+JqOfgM
         xwSOo9KLo7XbInJVHoiWu4W2P/1XStcPXCl3glCeIoV1F4lWuE4qhdyhsLtBYDJg+e1P
         TJYxLnd2ppeDM5X0k27dkBPN/rIXIIDzLEXyhf23QVijXg2KFH8BwV81Rol8/YlRWAvF
         4XtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=dtLV0LiG0LFQ1YK0lfSbXhJTWpcd/ZLXb5ceM7IqAPI=;
        fh=3QuQka7KPx1922G/8CML75mtnMtvcnkBUCWzB/dscrw=;
        b=HI9tyn3hnGfHUvXkOT+G7WNv7TdiF1FAyqwFpBb6l4OwrTQ5KdK5Eiz6t80PJ4zzBy
         7TDVl3QQ7sHfF8wTQ4lQgUo7NVY6qJk1bHg4sjUhG708x6QF721vZGxjVbDnQZfYu1a8
         xCPCvOywe+ALyeEovmIqBMKWcRkqsdmCSnMSzcWdIccq85Ovvy4xsMhZxIadHqG+b5Xa
         JB1Mu9TQOiVzoce7keDmjfUbxq5us43X7NTo3PbGaeIaXIOAvbcXUgKhCAN6KEn4l1l6
         1DlfB7CN0NlO0EOP8mzaERMTNORHzckYfquCzGT1M8vQXscVBUOSWna5D46e/pp/TTLD
         rcBA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 586e51a60fabf-2c248ca4162si403809fac.3.2025.03.10.03.28.55
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Mar 2025 03:28:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0D645153B;
	Mon, 10 Mar 2025 03:29:07 -0700 (PDT)
Received: from J2N7QTR9R3.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A759B3F673;
	Mon, 10 Mar 2025 03:28:53 -0700 (PDT)
Date: Mon, 10 Mar 2025 10:28:47 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Ryan Roberts <ryan.roberts@arm.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH V2] arm64/mm: Define PTDESC_ORDER
Message-ID: <Z86-34-fgk7iskX_@J2N7QTR9R3.cambridge.arm.com>
References: <20250310040115.91298-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250310040115.91298-1-anshuman.khandual@arm.com>
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

On Mon, Mar 10, 2025 at 09:31:15AM +0530, Anshuman Khandual wrote:
> diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
> index fd5a08450b12..78c7e03a0e35 100644
> --- a/arch/arm64/include/asm/kernel-pgtable.h
> +++ b/arch/arm64/include/asm/kernel-pgtable.h
> @@ -45,11 +45,14 @@
>  #define SPAN_NR_ENTRIES(vstart, vend, shift) \
>  	((((vend) - 1) >> (shift)) - ((vstart) >> (shift)) + 1)
>  
> -#define EARLY_ENTRIES(vstart, vend, shift, add) \
> -	(SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
> +/* Number of VA bits resolved by a single translation table level */
> +#define PTDESC_TABLE_SHIFT	(PAGE_SHIFT - PTDESC_ORDER)

To be clear, when I suggested adding PTDESC_TABLE_SHIFT, I expected that
it would be used consistently in place of (PAGE_SHIFT - PTDESC_ORDER),
and not only replacing that within the EARLY_ENTRIES() macro
specifically.

Mark.

> -#define EARLY_LEVEL(lvl, lvls, vstart, vend, add)	\
> -	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
> +#define EARLY_ENTRIES(lvl, vstart, vend) \
> +	SPAN_NR_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * PTDESC_TABLE_SHIFT)
> +
> +#define EARLY_LEVEL(lvl, lvls, vstart, vend, add) \
> +	((lvls) > (lvl) ? EARLY_ENTRIES(lvl, vstart, vend) + (add) : 0)
>  
>  #define EARLY_PAGES(lvls, vstart, vend, add) (1 	/* PGDIR page */				\
>  	+ EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */	\
> diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
> index a9136cc551cc..3c544edc3968 100644
> --- a/arch/arm64/include/asm/pgtable-hwdef.h
> +++ b/arch/arm64/include/asm/pgtable-hwdef.h
> @@ -7,40 +7,43 @@
>  
>  #include <asm/memory.h>
>  
> +#define PTDESC_ORDER 3
> +
>  /*
>   * Number of page-table levels required to address 'va_bits' wide
>   * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
> - * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
> + * bits with (PAGE_SHIFT - PTDESC_ORDER) bits at each page table level. Hence:
>   *
> - *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
> + *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - PTDESC_ORDER))
>   *
>   * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
>   *
>   * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
>   * due to build issues. So we open code DIV_ROUND_UP here:
>   *
> - *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
> + *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - PTDESC_ORDER) - 1) / (PAGE_SHIFT - PTDESC_ORDER))
>   *
>   * which gets simplified as :
>   */
> -#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
> +#define ARM64_HW_PGTABLE_LEVELS(va_bits) \
> +	(((va_bits) - PTDESC_ORDER - 1) / (PAGE_SHIFT - PTDESC_ORDER))
>  
>  /*
>   * Size mapped by an entry at level n ( -1 <= n <= 3)
> - * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
> + * We map (PAGE_SHIFT - PTDESC_ORDER) at all translation levels and PAGE_SHIFT bits
>   * in the final page. The maximum number of translation levels supported by
>   * the architecture is 5. Hence, starting at level n, we have further
>   * ((4 - n) - 1) levels of translation excluding the offset within the page.
>   * So, the total number of bits mapped by an entry at level n is :
>   *
> - *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
> + *  ((4 - n) - 1) * (PAGE_SHIFT - PTDESC_ORDER) + PAGE_SHIFT
>   *
>   * Rearranging it a bit we get :
> - *   (4 - n) * (PAGE_SHIFT - 3) + 3
> + *   (4 - n) * (PAGE_SHIFT - PTDESC_ORDER) + PTDESC_ORDER
>   */
> -#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
> +#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - PTDESC_ORDER) * (4 - (n)) + PTDESC_ORDER)
>  
> -#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - PTDESC_ORDER))
>  
>  /*
>   * PMD_SHIFT determines the size a level 2 page table entry can map.
> @@ -49,7 +52,7 @@
>  #define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
>  #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
>  #define PMD_MASK		(~(PMD_SIZE-1))
> -#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - PTDESC_ORDER))
>  #endif
>  
>  /*
> @@ -59,14 +62,14 @@
>  #define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
>  #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
>  #define PUD_MASK		(~(PUD_SIZE-1))
> -#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - PTDESC_ORDER))
>  #endif
>  
>  #if CONFIG_PGTABLE_LEVELS > 4
>  #define P4D_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
>  #define P4D_SIZE		(_AC(1, UL) << P4D_SHIFT)
>  #define P4D_MASK		(~(P4D_SIZE-1))
> -#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - 3))
> +#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - PTDESC_ORDER))
>  #endif
>  
>  /*
> diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
> index 2b69e3beeef8..f74335e13929 100644
> --- a/arch/arm64/kernel/pi/map_range.c
> +++ b/arch/arm64/kernel/pi/map_range.c
> @@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
>  {
>  	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
>  	pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
> -	int lshift = (3 - level) * (PAGE_SHIFT - 3);
> +	int lshift = (3 - level) * (PAGE_SHIFT - PTDESC_ORDER);
>  	u64 lmask = (PAGE_SIZE << lshift) - 1;
>  
>  	start	&= PAGE_MASK;
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index b65a29440a0c..211821f80571 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
>   */
>  static bool __init root_level_aligned(u64 addr)
>  {
> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - PTDESC_ORDER);
>  
>  	return (addr % (PAGE_SIZE << shift)) == 0;
>  }
> @@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
>  	 */
>  	u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
>  							: vabits_actual;
> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - PTDESC_ORDER);
>  
>  	return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
>  }
> @@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
>   */
>  static int __init next_level_idx(u64 addr)
>  {
> -	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
> +	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - PTDESC_ORDER);
>  
>  	return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
>  }
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z86-34-fgk7iskX_%40J2N7QTR9R3.cambridge.arm.com.
