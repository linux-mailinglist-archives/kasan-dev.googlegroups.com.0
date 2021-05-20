Return-Path: <kasan-dev+bncBDDL3KWR4EBRBB6UTCCQMGQEXGUIA3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id A4D1A38A0BA
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 11:21:12 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id a24-20020a05620a1038b02902fa6ba180ffsf11980969qkk.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 02:21:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621502471; cv=pass;
        d=google.com; s=arc-20160816;
        b=iS2F6fB3iUn7F/+WWwYdKjnw2wvlomNGes85feM8wYKp4fGlXueMZRvovpmlPWOBjZ
         Z3UCNm37lJw38gLgRRWSY7AKhs5a3NG3FID5prmcSd1A9arJYNZRMJg/dTQrOb8LjB1o
         FhYm7hGq2fpJinDF1GImEPdI3dt/xVAtcOFol4CXuGq2Hym17O6gVQX2u+MmaDLPbkBl
         va2xEbN24IhyexjxVF799RjbjnuhE4GZbL9vGdy7ZIQZymns+iFj61csSToKVXenQCbU
         vwt4uEudFmg3x7xuFDMSIW7MIz4nARf6a+o1EBfHaXwC5Uq9x3Q0iJ7I4U983DmGsUbj
         v8vQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=52qfe8LMCaWZ7Co2vmcEquNSpAbfwS3c6Bz8r3iXy08=;
        b=uvC48QcYyhJ+x82OXj+XPLqTcDLNjLiLudbOQukHLyertCveWW3QXd1PorbRBBf4Yf
         natNK28x3UwlZsH2XWuIBm/AxLGj0lqqoldWEClcbL7uxxtHkU5YaGFIx5N04pXdAztN
         miZs633Pmwj2D9rk71WTKMeRVWcgjEjeaJvHdKrnm7ATXqlZNeEL/QJIpJSEgO0loeVo
         vZZ4EprHchMLwWc29yLJTWAkpUHCSjAR2jDtnv3xyJ1YZEZTcW/i5rBoY77/+tVyOWgY
         TrrCt17TpdKmwB3v2lwnSr2QQ6MBo0C4dMLMF7xpPWMCtlckIyZqOTA1oWkfsTDifR1I
         ceNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=52qfe8LMCaWZ7Co2vmcEquNSpAbfwS3c6Bz8r3iXy08=;
        b=JLA+e7qnAUdjMdozfpE88X1uKEJOUT+PatgRfDLojnIkStgCPjiaiWXcuL1u/Tl+8U
         oCMd4yO9cOlaKjBiyTWyYuIW2qP8FTuK0Mqk00Bnv7mP0qZiwq2JcIgXNbEamIln0tMl
         xT2T2Z10ndOEjcqSNYgVxo/HEJhAEZjJbVfEZ4PB9pCzJ15hrrf6pV9zglmAut3F+NyE
         9K5fnyq+7NfwvxTHWOEozzuPfhq69WRiXSKVQ0RmDu7viPGHg2IJvVSrpw6Ibrm+Wm99
         BXPFNdi0lzn6jdOWTkKgG+Jv8MX9xDwN6MJrxGb4UKVz+11Pk145X1sIAidj3DIZgJvK
         Aehg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=52qfe8LMCaWZ7Co2vmcEquNSpAbfwS3c6Bz8r3iXy08=;
        b=i5iLzwUB+jiM/+n1VUNPIu5BWzusNZcwd64uRFZ9vEm+v6xzdH+zhtTnhAJAvuumwY
         Rqq5Vymgh/LJ02pxTdV2GRg0HQLf5vlvG2iz9+QFEKptwI5Al2SacdSjR2gHOKETw2vg
         /jhxEriTu8qlzEAQNr1kmwrLfFHpVJjNoYP799i895HZkAy/Vq9K1YSNjXQO/DXyq0oY
         MjozpnMkTYwX+d/2AK7yygCVJzIp3rJXkD5XUetSaXlIer5JqsJ7Q15/EJBEE9vO1KOb
         1/nVnA5kq1SlB+IleNvZGAVY6QSOVueqNOv2YT7QDgJ7C4LZgHtRiMku2lR+OCdyv+Ln
         /v/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531paGjkX5xOG5u/H/kDnnooKwHMnjG9IYhZMalwDxyGLNfpzK4o
	7GRFn6U/7uHVgCJI7RC0gb4=
X-Google-Smtp-Source: ABdhPJylHm55H2YqFXy9IMk6dOEcashNupyyrUlEQhm41xWcF3wwCAupEVk99SSIXo5FnWyhsw4xfw==
X-Received: by 2002:a05:620a:13a8:: with SMTP id m8mr3636418qki.213.1621502471818;
        Thu, 20 May 2021 02:21:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:90d:: with SMTP id dj13ls681741qvb.11.gmail; Thu,
 20 May 2021 02:21:11 -0700 (PDT)
X-Received: by 2002:ad4:536a:: with SMTP id e10mr4640494qvv.9.1621502471323;
        Thu, 20 May 2021 02:21:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621502471; cv=none;
        d=google.com; s=arc-20160816;
        b=lCYr6unM+OKcunMQwwIADIBkn7fitDMAVWBX3y7ew4czlsgE25fVL3D0tMrPiaFFsi
         mC9YIal1eqriVM6VcbBy8Gg8zS9gSfDf0ScmCYFZsHPbgqHnLXLmajEzH8mb/z8NOQQN
         /MMVbLd+KnNfXLLO/bc/8Abo+AmG7POyaQEXcsvZ/TgRupNstcjcaHs96vi+0umbOWfi
         KdnCD9GXiOKXFqiFeVAFclKuTtJQvOMdVhdlhwPwzsltsznMqSS7YXCqFszulVusWeyK
         9za7+YLKlDTADs5pLH/cKfB7PR9atVrdz/IvwJQMr/B1fziuqxqitkE/jj4nFMorl+L0
         pQLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ZgkNWbwhz0s8CzvetLxEsicXqK2lRUKIgMJmUDV7I6Q=;
        b=qbnxOgvzmaC4skCXXDPN2EuiD/jMK73Nqf+t4R224R9+u7SwsL2V0v1gRqacZrSfGd
         v/TqvdRPjqoRxCvUCw30FuEnend13qs3nIxM1GjoRAPiGzsLAOB16Tdemhdct8sZ5hrw
         QW0v2eGXifC49zwxaamjLwHn5HVMDRDCBVjXLMafKJ/Z+mJRypKd3NU0ZJq7GK5m5U6Q
         9UDSTcpJH1R+hCOc6UZp47wk1vvAJl+PX1/TKSwNQYclwtt0vtm1qxkUCGuxfzypWzEj
         imO7Ja1aNXPw0jO7gxQfybriU89huCHIZ75c0VFi2tfkR0L3UZ9D7m4+o7NVdS1ybuLl
         dagw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h6si171659qth.2.2021.05.20.02.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 May 2021 02:21:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9B80B6124C;
	Thu, 20 May 2021 09:21:08 +0000 (UTC)
Date: Thu, 20 May 2021 10:21:06 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, Will Deacon <will@kernel.org>,
	Steven Price <steven.price@arm.com>,
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4] kasan: speed up mte_set_mem_tag_range
Message-ID: <20210520092105.GA12251@arm.com>
References: <20210520020305.2826694-1-eugenis@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210520020305.2826694-1-eugenis@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Wed, May 19, 2021 at 07:03:05PM -0700, Evgenii Stepanov wrote:
> Use DC GVA / DC GZVA to speed up KASan memory tagging in HW tags mode.
> 
> The first cacheline is always tagged using STG/STZG even if the address is
> cacheline-aligned, as benchmarks show it is faster than a conditional
> branch.
> 
> Signed-off-by: Evgenii Stepanov <eugenis@google.com>
> Co-developed-by: Peter Collingbourne <pcc@google.com>
> Signed-off-by: Peter Collingbourne <pcc@google.com>

Some nitpicks below but it looks fine otherwise.

> diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
> index ddd4d17cf9a0..34e23886f346 100644
> --- a/arch/arm64/include/asm/mte-kasan.h
> +++ b/arch/arm64/include/asm/mte-kasan.h
> @@ -48,43 +48,85 @@ static inline u8 mte_get_random_tag(void)
>  	return mte_get_ptr_tag(addr);
>  }
>  
> +static inline u64 __stg_post(u64 p)
> +{
> +	asm volatile(__MTE_PREAMBLE "stg %0, [%0], #16"
> +		     : "+r"(p)
> +		     :
> +		     : "memory");
> +	return p;
> +}
> +
> +static inline u64 __stzg_post(u64 p)
> +{
> +	asm volatile(__MTE_PREAMBLE "stzg %0, [%0], #16"
> +		     : "+r"(p)
> +		     :
> +		     : "memory");
> +	return p;
> +}
> +
> +static inline void __dc_gva(u64 p)
> +{
> +	asm volatile(__MTE_PREAMBLE "dc gva, %0" : : "r"(p) : "memory");
> +}
> +
> +static inline void __dc_gzva(u64 p)
> +{
> +	asm volatile(__MTE_PREAMBLE "dc gzva, %0" : : "r"(p) : "memory");
> +}
> +
>  /*
>   * Assign allocation tags for a region of memory based on the pointer tag.
>   * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> - * size must be non-zero and MTE_GRANULE_SIZE aligned.
> + * size must be MTE_GRANULE_SIZE aligned.
>   */
> -static inline void mte_set_mem_tag_range(void *addr, size_t size,
> -						u8 tag, bool init)
> +static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag,
> +					 bool init)
>  {
> -	u64 curr, end;
> +	u64 curr, DCZID, mask, line_size, end1, end2, end3;

Nitpick 1: please use lowercase for variables even if they match some
register.

>  
> -	if (!size)
> -		return;
> +	/* Read DC G(Z)VA store size from the register. */
> +	__asm__ __volatile__(__MTE_PREAMBLE "mrs %0, dczid_el0"
> +			     : "=r"(DCZID)::);
> +	line_size = 4ul << (DCZID & 0xf);

No need for __MTE_PREAMBLE here, this register has been available since
8.0. Even better, just use read_cpuid(DCZID_EL0) directly rather than
asm.

I'd also call this variable block_size (or dczid_bs etc.), it's not
necessarily a cache line size (we have CTR_EL0 for that), though most
implementations probably do just that. There are a few instances below
where the comments refer to cache lines.

>  	curr = (u64)__tag_set(addr, tag);
> -	end = curr + size;
> -
> -	/*
> -	 * 'asm volatile' is required to prevent the compiler to move
> -	 * the statement outside of the loop.
> +	mask = line_size - 1;
> +	/* STG/STZG up to the end of the first cache line. */
> +	end1 = curr | mask;
> +	end3 = curr + size;
> +	/* DC GVA / GZVA in [end1, end2) */
> +	end2 = end3 & ~mask;
> +
> +	/* The following code uses STG on the first cache line even if the start
> +	 * address is cache line aligned - it appears to be faster than an
> +	 * alignment check + conditional branch. Also, if the size is at least 2
> +	 * cache lines, the first two loops can use post-condition to save one
> +	 * branch each.
>  	 */

Nitpick 2: the multiline comments start with an empty /* (as per the
coding style doc).

> -	if (init) {
> -		do {
> -			asm volatile(__MTE_PREAMBLE "stzg %0, [%0]"
> -				     :
> -				     : "r" (curr)
> -				     : "memory");
> -			curr += MTE_GRANULE_SIZE;
> -		} while (curr != end);
> -	} else {
> -		do {
> -			asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> -				     :
> -				     : "r" (curr)
> -				     : "memory");
> -			curr += MTE_GRANULE_SIZE;
> -		} while (curr != end);
> -	}
> +#define SET_MEMTAG_RANGE(stg_post, dc_gva)		\
> +	do {						\
> +		if (size >= 2 * line_size) {		\
> +			do {				\
> +				curr = stg_post(curr);	\
> +			} while (curr < end1);		\
> +							\
> +			do {				\
> +				dc_gva(curr);		\
> +				curr += line_size;	\
> +			} while (curr < end2);		\
> +		}					\
> +							\
> +		while (curr < end3)			\
> +			curr = stg_post(curr);		\
> +	} while (0)
> +
> +	if (init)
> +		SET_MEMTAG_RANGE(__stzg_post, __dc_gzva);
> +	else
> +		SET_MEMTAG_RANGE(__stg_post, __dc_gva);
> +#undef SET_MEMTAG_RANGE
>  }
>  
>  void mte_enable_kernel_sync(void);
> -- 
> 2.31.1.751.gd2f1c929bd-goog

With the above fixed, feel free to add:

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

(aiming at 5.14)

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210520092105.GA12251%40arm.com.
