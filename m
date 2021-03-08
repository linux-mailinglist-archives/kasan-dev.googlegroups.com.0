Return-Path: <kasan-dev+bncBDV37XP3XYDRBTOQTGBAMGQEZTVKP5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id C68DA331586
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 19:09:18 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id h126sf7944606qkd.4
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 10:09:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615226958; cv=pass;
        d=google.com; s=arc-20160816;
        b=iFJGcfvr7HZ0jJyo7AUT0k5SkeufnCBu4TFVdsK7P5ATI4m+JqaPGNZqW3IivAunmZ
         feQKbNyXKzGSQFMIgxpyrbdhji/qHHdCZHH8rHrPTW1EYHYIV5N2pHW5xfU61UOI1kOQ
         XVmMIhum0LlU2NlxJhcOhjNrCcOwcJXAbQeaXrzhWZ4wYJAKBPWsnTZznl19obASeKPM
         /vAYSDmGrejuqG2Tz1VIi9KCx1LEL1QXwk44X7iUEdwLD5wNiW2zs5CskiUa7QxdKAw9
         jX45xv4d1Y46xNCJZ5z/VDi5R1CkvtJx+0d2y0zdrOslQ0sLObayLSNQTcm3cG0Zxnyd
         pkXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NS53DRhBznYtUak38JDZX5milpILBCqXvuT08WA4y+M=;
        b=SF/Vxf5qEwMAK9/5Mv4akO+myE6Tkkvffp6V16KJjbaQeRLwvZCDsvFBmlhsSIXaHF
         dndy1Ik/15Y+P1UQR4vm4sOLa7sgRICsHZpuZ4u97Sj+nfidt9nWVregBSZm9jNq5eKp
         2tA568XpEX5LwJHdsYcriEMTR6I8ebxeJcAh+AOpTNSyYsRLSlcfJAoh/MDkiiVh8suw
         vgod5+KpH+brr428wTCvZ4FtdRS1bQQmesMrGEgwcmgIdxin6MXAq+KLJSZy/WtihwX1
         eIRn4G2Srq35Ph4iNEfwxI2ZG+ASEQFgKeJvsEYU+Oy0GJ4n1aEsnEjI7fvEIK8U5YPt
         Vs5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NS53DRhBznYtUak38JDZX5milpILBCqXvuT08WA4y+M=;
        b=kZs8VjNJsvlA7XNpj2kqpNTvUKEAQ0hQsHcCus0fWFh4RjJE27sy04uFXZ9p8IiBY0
         UOzml3P6HxkPcpNNk2QzomyH29p0rxjc6svtHg6jsiXmjKYsYiAb1M/7UM2ncp+2gmFv
         Cy01HJ4ojc6yG8QoPCRM7m9SM6P+sqxtHJx2DILB9vRdP9VVXk72pE19n5FoCdj0Bs/C
         aAUBHPPs1+XibnMUMUf9HkYgJ8LInCngIzTDUb3iiLSgAKELGapWBI69WDw6NOChxAXU
         ZNmAVNVyvLbJmMLCNrQoi9uUi7ZL+v21ubClc120wQ6SMWiS0Gr1juK9p9x1hBITt8ZI
         AIPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NS53DRhBznYtUak38JDZX5milpILBCqXvuT08WA4y+M=;
        b=LaL3Y5b4F3FBe9uBc+aXpS7Ma7qL+S5y8dSbGiWmhiwSdqs5LogRWOPKQphhPX7WTg
         J0SJRPusWB439YmCfxzPdJVhbGDNKzgFFQr9Mc9qa89fw5I5enRzPeX5CfL7kT+xP5Xp
         drzf2XYPTDyH1sw748nUniHo4HoebcFZEu1aIszW4yPB7Bl/8UQ4nA/Z/MLGxfgPczee
         hraKxbfhrGydSdEHvTRAgBkiik9Q8ro/ICbgr2Jqbs6jWar0SbX4ERwoGwpxetA5Fwcq
         YaA77USQ6DfUbajcDGB63JFgG73/5hk+F3T5q6vVzJHdw8vrfIDVGw1jouqG+907aRXv
         mXfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317J/xIAh8cVUHSTmgHnYHPTPn6+3Wh/qdg3j1z1napF7S3vQiM
	3zrMeVckX8bHrdw4Ol3Sb4A=
X-Google-Smtp-Source: ABdhPJwa+8QgZ/64mLT+PUp34w77RSc7uWmk29CtfXBWeXacFvuAX+d1A8IBvYKDAHd96z+IAi1BBA==
X-Received: by 2002:a37:b585:: with SMTP id e127mr9272072qkf.337.1615226957865;
        Mon, 08 Mar 2021 10:09:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6b03:: with SMTP id w3ls4455856qts.11.gmail; Mon, 08 Mar
 2021 10:09:17 -0800 (PST)
X-Received: by 2002:ac8:1098:: with SMTP id a24mr18645316qtj.27.1615226957314;
        Mon, 08 Mar 2021 10:09:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615226957; cv=none;
        d=google.com; s=arc-20160816;
        b=Fam2tY+tiwjeTSRLORVGX8YisizWYofHHreozzgtoFsEW05IQlX/ahmnOOTPhJ9Szo
         xOye5pc3izlSC67TA2gtHEsob6SZZIz0Z2Z2ehD0yekNkP1mW2Vaic7TZYY9wzbM7XOh
         w3T83Wt6ZgyApw1MHph+1uph9UEG2SQiEbIPDsUT2SIcDsJntpfl4DdivhdGuqS085LT
         JPcmpPzy8PMY5yUTVvBT0NBscNlFI2iAQSK6YJiUrNLhEHxZvRR1fXcUzArx2ToTFg00
         tT1XRNazjoJ4dmH/YjrBeTmYVyYG8RH6tkVMm+t2syJumkAehflDgIO6D49tdWLKyx4f
         8GzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=xRSQHNMBOegDNNk79d/re8ya5mWjhyPGHxacYYVlT3c=;
        b=mB/GK+q94xWR7zA9AmTPNHT+tGUWxPIOuzdQZP7tz9KKO2JrfNH5HI6x7ocQW6dW1L
         6BL4IHIq/rzbK7wGBlVM49RwXDeWb6FuC7CAs8vt3xw9p9/AGOnBXhYdEKHhokVCPz7k
         jEOlY2U2qAPBD++Qe+Lb53jd327o7SXJwLk+fFYAf80y9TWtC7Wf+ZjK2Iipo/bIWnWr
         MK92s+yuklVx1p8IVoh+uQkC10OAUfcdG2gSU4DT2epTZyn0DNiRRUsLEjaUzDVLqIsS
         FgwQVLc5kZpLUqSC/FEZ0K9HFo3zdpb1qBS0NQ6EBpFYIrWCot88ZQtp9osXeReiQ6/y
         0CCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b4si786117qkh.2.2021.03.08.10.09.17
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 10:09:17 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8850AD6E;
	Mon,  8 Mar 2021 10:09:16 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.51.12])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2346E3F71B;
	Mon,  8 Mar 2021 10:09:12 -0800 (PST)
Date: Mon, 8 Mar 2021 18:09:10 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v14 5/8] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210308180910.GB17002@C02TD0UTHF1T.local>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
 <20210308161434.33424-6-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210308161434.33424-6-vincenzo.frascino@arm.com>
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

On Mon, Mar 08, 2021 at 04:14:31PM +0000, Vincenzo Frascino wrote:
> load_unaligned_zeropad() and __get/put_kernel_nofault() functions can
> read passed some buffer limits which may include some MTE granule with a
> different tag.

s/passed/past/

> When MTE async mode is enable, the load operation crosses the boundaries

s/enabel/enabled/

> and the next granule has a different tag the PE sets the TFSR_EL1.TF1 bit
> as if an asynchronous tag fault is happened.
> 
> Enable Tag Check Override (TCO) in these functions  before the load and
> disable it afterwards to prevent this to happen.
> 
> Note: The same condition can be hit in MTE sync mode but we deal with it
> through the exception handling.
> In the current implementation, mte_async_mode flag is set only at boot
> time but in future kasan might acquire some runtime features that
> that change the mode dynamically, hence we disable it when sync mode is
> selected for future proof.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Reported-by: Branislav Rankov <Branislav.Rankov@arm.com>
> Tested-by: Branislav Rankov <Branislav.Rankov@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/uaccess.h        | 24 ++++++++++++++++++++++++
>  arch/arm64/include/asm/word-at-a-time.h |  4 ++++
>  arch/arm64/kernel/mte.c                 | 22 ++++++++++++++++++++++
>  3 files changed, 50 insertions(+)
> 
> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
> index 0deb88467111..a857f8f82aeb 100644
> --- a/arch/arm64/include/asm/uaccess.h
> +++ b/arch/arm64/include/asm/uaccess.h
> @@ -188,6 +188,26 @@ static inline void __uaccess_enable_tco(void)
>  				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
>  }
>  
> +/* Whether the MTE asynchronous mode is enabled. */
> +DECLARE_STATIC_KEY_FALSE(mte_async_mode);

Can we please hide this behind something like:

static inline bool system_uses_mte_async_mode(void)
{
	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
		static_branch_unlikely(&mte_async_mode);
}

... like we do for system_uses_ttbr0_pan()?

That way the callers are easier to read, and kernels built without
CONFIG_KASAN_HW_TAGS don't have the static branch at all. I reckon you
can put that in one of hte mte headers and include it where needed.

Thanks,
Mark.

> +
> +/*
> + * These functions disable tag checking only if in MTE async mode
> + * since the sync mode generates exceptions synchronously and the
> + * nofault or load_unaligned_zeropad can handle them.
> + */
> +static inline void __uaccess_disable_tco_async(void)
> +{
> +	if (static_branch_unlikely(&mte_async_mode))
> +		 __uaccess_disable_tco();
> +}
> +
> +static inline void __uaccess_enable_tco_async(void)
> +{
> +	if (static_branch_unlikely(&mte_async_mode))
> +		__uaccess_enable_tco();
> +}
> +
>  static inline void uaccess_disable_privileged(void)
>  {
>  	__uaccess_disable_tco();
> @@ -307,8 +327,10 @@ do {									\
>  do {									\
>  	int __gkn_err = 0;						\
>  									\
> +	__uaccess_enable_tco_async();					\
>  	__raw_get_mem("ldr", *((type *)(dst)),				\
>  		      (__force type *)(src), __gkn_err);		\
> +	__uaccess_disable_tco_async();					\
>  	if (unlikely(__gkn_err))					\
>  		goto err_label;						\
>  } while (0)
> @@ -380,8 +402,10 @@ do {									\
>  do {									\
>  	int __pkn_err = 0;						\
>  									\
> +	__uaccess_enable_tco_async();					\
>  	__raw_put_mem("str", *((type *)(src)),				\
>  		      (__force type *)(dst), __pkn_err);		\
> +	__uaccess_disable_tco_async();					\
>  	if (unlikely(__pkn_err))					\
>  		goto err_label;						\
>  } while(0)
> diff --git a/arch/arm64/include/asm/word-at-a-time.h b/arch/arm64/include/asm/word-at-a-time.h
> index 3333950b5909..c62d9fa791aa 100644
> --- a/arch/arm64/include/asm/word-at-a-time.h
> +++ b/arch/arm64/include/asm/word-at-a-time.h
> @@ -55,6 +55,8 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
>  {
>  	unsigned long ret, offset;
>  
> +	__uaccess_enable_tco_async();
> +
>  	/* Load word from unaligned pointer addr */
>  	asm(
>  	"1:	ldr	%0, %3\n"
> @@ -76,6 +78,8 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
>  	: "=&r" (ret), "=&r" (offset)
>  	: "r" (addr), "Q" (*(unsigned long *)addr));
>  
> +	__uaccess_disable_tco_async();
> +
>  	return ret;
>  }
>  
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index fa755cf94e01..1ad9be4c8376 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -26,6 +26,10 @@ u64 gcr_kernel_excl __ro_after_init;
>  
>  static bool report_fault_once = true;
>  
> +/* Whether the MTE asynchronous mode is enabled. */
> +DEFINE_STATIC_KEY_FALSE(mte_async_mode);
> +EXPORT_SYMBOL_GPL(mte_async_mode);
> +
>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  {
>  	pte_t old_pte = READ_ONCE(*ptep);
> @@ -118,12 +122,30 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>  
>  void mte_enable_kernel_sync(void)
>  {
> +	/*
> +	 * Make sure we enter this function when no PE has set
> +	 * async mode previously.
> +	 */
> +	WARN_ONCE(static_key_enabled(&mte_async_mode),
> +			"MTE async mode enabled system wide!");
> +
>  	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
>  }
>  
>  void mte_enable_kernel_async(void)
>  {
>  	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
> +
> +	/*
> +	 * MTE async mode is set system wide by the first PE that
> +	 * executes this function.
> +	 *
> +	 * Note: If in future KASAN acquires a runtime switching
> +	 * mode in between sync and async, this strategy needs
> +	 * to be reviewed.
> +	 */
> +	if (!static_branch_unlikely(&mte_async_mode))
> +		static_branch_enable(&mte_async_mode);
>  }
>  
>  void mte_set_report_once(bool state)
> -- 
> 2.30.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308180910.GB17002%40C02TD0UTHF1T.local.
