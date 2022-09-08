Return-Path: <kasan-dev+bncBCJOX77DZ4GBBSEL46MAMGQE5P7CEXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 087985B1A1A
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Sep 2022 12:36:57 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id p8-20020a056512234800b0048b12cb7738sf4245159lfu.6
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Sep 2022 03:36:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662633416; cv=pass;
        d=google.com; s=arc-20160816;
        b=endU92if/F9/bNZ7MceJ3cL+FxMrSzuwZPjhsOU3MURkhFNMgoCZbgRDS6O5YBOIVE
         upd3twZDOOdV9Xkh1WfmNDGQfR28ePvm37uunv++v1OYvpLgb51QZeA5A67SfZqoUYMc
         d6XhuikeVDwkRdx5sEezK0T+wwhmD7pBZfuNpgZw/pnggordCkPBRsxHTJkQTHSBhkFu
         sDb339ujG3eXRIEbmp4fuGIkm74K6cTx9aRwHBWGZN3VM46YbEQ0afycVayHKefDHP5C
         tALRracd6fGtCHBxLHu748Uh56ktr8StQsN8+JaSg39hqaCdkRPP7/hFKEzKidSITaxn
         9jvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=CLg1jYhApKsNgDKncKkI+5X4CqbIYIn/+er/Nk0BDK8=;
        b=GBo8jMpvOkKoWwaJZfb+2UOKQhXzVYtSekTNTuPyUzn0tinpChJqSEevsSE+KP5QSv
         rU/gdooorpbvqvCIg7ZZzkPZsNY/PfOl1atJLBdBjAYJXNp1Tojs0yvHJu12NphTMKWy
         CKxAtjCv84GjXuPkPm1dY/+W2I4FoS0NOjHt5MnQeRbSb3BWS4nLL3McDoj0NvegIBCF
         b1RreoKv2wkIxC0dAnd1mH+IVuZOG2tunf89g+Ph3fEYTKmlMUKkndSkPiurHLXW+4zi
         kpLHi3ZP5MxtqJlrsX5aZKn+5cmRxjZmPOuXSP04pjhIejg9PWIGJLlMJMMSsdPqrzJp
         B9Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vladimir.murzin@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vladimir.murzin@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date;
        bh=CLg1jYhApKsNgDKncKkI+5X4CqbIYIn/+er/Nk0BDK8=;
        b=N66VCRp6S7LHTfCPZFMt1h+s1LKEeR63VBBDbYLiiN8IadbEF6YRrh+Vq2rdL5n8zl
         /X3FTKzcJZIAXQcChEsyHsEpUQTRkS7n+jUJEbcnM0oSczqp05+4khdnQUccuA2CGF7k
         4IeMSL+AetUwI2Fvov/q/GqFUy9r8gWaowvetZ5XHxcJdYWO+yK2FzluwxG4lwEIEdP5
         zrEtOntpmL8TfIHEX8qlTc6kE+cotFNXyWiwPWlMByaeW0ocIxZ/pWm48I2rJ71jtTsc
         FJjU2AK7fOP0TQV+ujhISiU6/t/n3P3gzeAyQOG24FvROLYVYk6OlVm5a1zA5spB7khq
         ZRIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=CLg1jYhApKsNgDKncKkI+5X4CqbIYIn/+er/Nk0BDK8=;
        b=hLMACcXmFGw0VF394QbOOjnBHvOGq90vt5uIcLgXFPoHZx4IAyjJ+ELsqhwzlEOtr3
         T/KDwZOsUcKjcKa3asEZpU34puFGq3W6Y4WFwIOkTc906CqnglRUyXMr4tHNIdT0yPc1
         aII4vyDehSZpGb3cq/ao3YjlhTXlvRJwVjcGWeZhUHzCM+VQDxWUAcsyqYr7BXIcMV0W
         QIaOTjgvNmIJu081AWXcdIc6AHqgpRbWcB2FS9DbJZtEHkxThkaINr1PHmBoSBnOKfhu
         Cyjq5SW3Jpx1HuS0Ioxqu8RdQyKIScJJ2y/lIzPZSOYzGGZjzgsEyJ+JYryhD4bnXa8+
         KVHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3JKH2MfwfoP6780SYYCLJkg3pnwjOd/tSerEmnkkeBnTp5j8V5
	SQKG8v3CLXMZw85qasmWkPE=
X-Google-Smtp-Source: AA6agR4DWRYr6RPNbwsG7RwUEW8dVAYUO93sgLpr9PhvDAuoHzGzRBY+OgEzHDo1n0GeGu0VqiGQmQ==
X-Received: by 2002:a2e:8397:0:b0:266:b7ac:c601 with SMTP id x23-20020a2e8397000000b00266b7acc601mr2470446ljg.356.1662633416450;
        Thu, 08 Sep 2022 03:36:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81d2:0:b0:25f:dcd4:53b4 with SMTP id s18-20020a2e81d2000000b0025fdcd453b4ls198987ljg.3.-pod-prod-gmail;
 Thu, 08 Sep 2022 03:36:55 -0700 (PDT)
X-Received: by 2002:a2e:9b89:0:b0:26a:a004:ac3 with SMTP id z9-20020a2e9b89000000b0026aa0040ac3mr2142708lji.104.1662633415133;
        Thu, 08 Sep 2022 03:36:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662633415; cv=none;
        d=google.com; s=arc-20160816;
        b=UHZekdknVKn/79EXNDWPnByTaS3BYsH1q7af2+AgYqJjHKeAuHH3WLLR/iuJ1nOBD9
         xLqLzpKe1n3DX9GTaMjZu0UO9cOmuYnCbralvLXwCzaE6yJwlGRH0VQT1cb+SdVNuc9B
         zsvhY2phYbCLvQmfe+B35O2M0A3vM9H4QODYEOv+9JagRXPPIpzctm4yWq5F9RnlAfA9
         HSSWSUJ5GaeohQfuMykkPvMymzer+CIkHMSkbPtBbKsgXv3U5j4anGhkb46xrWYPBX6j
         ckzA0wT0kMlRm94RGXtlEgt50Eq4De2VC9GewyP6jdPcY3VuNSyyx2E0AuRxdfAIG6Zq
         85Uw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=2bm6zQNRrkcJeAZA3/ff7/rB5LYV+vNeJu+3t/RMjeU=;
        b=MWeFHN2Mn5G95sYaKT/iiUwSPZCm4rBUwuQ8MUWbnlxYQisJ0okN5wiLrekz+Mzl7r
         kwb76M//4WvXo4z+RnrPfml3S3AKDImXjudlKcCeTBPVWrzUGztXAEN97rOasPFOhUuE
         SEurYdDfLgR9HykFEs6ZgFYbVqSgmJI1hN9iVZNYp0oujf0V4bhnLB6Md4WxYPNyBDNS
         1TRsfgkyJis66W4PzYHNN6HHdUkrbyb2pMyP7NO7dQhVQftbqej60AV+paHWw1KwnnDn
         XJ3SphwwbGFcu1tIiraDTNExhvpBRJwwe9jQnaDElpLsIxCk5hfit03Ju6ACET5gVqeF
         z5nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vladimir.murzin@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vladimir.murzin@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i24-20020a2ea238000000b002652a5a5536si798485ljm.2.2022.09.08.03.36.54
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Sep 2022 03:36:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of vladimir.murzin@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 29A1314BF;
	Thu,  8 Sep 2022 03:37:00 -0700 (PDT)
Received: from [10.1.27.146] (e121487-lin.cambridge.arm.com [10.1.27.146])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8B71C3F71A;
	Thu,  8 Sep 2022 03:36:52 -0700 (PDT)
Message-ID: <198b1486-d402-9061-a6f0-e522a548f040@arm.com>
Date: Thu, 8 Sep 2022 11:36:42 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.11.0
Subject: Re: [PATCH v2] mte: Initialize tag storage to KASAN_TAG_INVALID
Content-Language: en-US
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
References: <20220907110015.11489-1-vincenzo.frascino@arm.com>
From: Vladimir Murzin <vladimir.murzin@arm.com>
In-Reply-To: <20220907110015.11489-1-vincenzo.frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vladimir.murzin@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vladimir.murzin@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=vladimir.murzin@arm.com;       dmarc=pass
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

Hi Vincenzo,

On 9/7/22 12:00, Vincenzo Frascino wrote:
> When the kernel is entered on aarch64, the MTE allocation tags are in an
> UNKNOWN state.
> 
> With MTE enabled, the tags are initialized:
>  - When a page is allocated and the user maps it with PROT_MTE.
>  - On allocation, with in-kernel MTE enabled (HW_TAGS KASAN).
> 
> If the tag pool is zeroed by the hardware at reset, it makes it
> difficult to track potential places where the initialization of the
> tags was missed.
> 
> This can be observed under QEMU for aarch64, which initializes the MTE
> allocation tags to zero.
> 
> Initialize to tag storage to KASAN_TAG_INVALID to catch potential
> places where the initialization of the tags was missed.
> 
> This is done introducing a new kernel command line parameter
> "mte.tags_init" that enables the debug option.
> 
> Note: The proposed solution should be considered a debug option because
> it might have performance impact on large machines at boot.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/kernel/mte.c | 47 +++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 47 insertions(+)

Nothing in Documentation/ ?

> 
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index b2b730233274..af9a8eba9be4 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -6,6 +6,7 @@
>  #include <linux/bitops.h>
>  #include <linux/cpu.h>
>  #include <linux/kernel.h>
> +#include <linux/memblock.h>
>  #include <linux/mm.h>
>  #include <linux/prctl.h>
>  #include <linux/sched.h>
> @@ -35,6 +36,8 @@ DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
>  EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
>  #endif
>  
> +static bool mte_tags_init __ro_after_init;
> +
>  static void mte_sync_page_tags(struct page *page, pte_t old_pte,
>  			       bool check_swap, bool pte_is_tagged)
>  {
> @@ -98,6 +101,48 @@ int memcmp_pages(struct page *page1, struct page *page2)
>  	return ret;
>  }
>  
> +/* mte.tags_init=off/on */
> +static int __init early_mte_tags_init(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "off"))
> +		mte_tags_init = false;
> +	else if (!strcmp(arg, "on"))
> +		mte_tags_init = true;
> +	else
> +		return -EINVAL;
> +

You might want to offload parsing to kstrtobool()

> +	return 0;
> +}
> +early_param("mte.tags_init", early_mte_tags_init);
> +
> +static inline void __mte_tag_storage_init(void)
> +{
> +	static bool mte_tags_uninitialized = true;
> +	phys_addr_t pa_start, pa_end;
> +	u64 index;
> +
> +	if (mte_tags_init && !mte_tags_uninitialized)
> +		return;
> +
> +	for_each_mem_range(index, &pa_start, &pa_end) {
> +		void *va_start = (void *)__phys_to_virt(pa_start);
> +		void *va_end = (void *)__phys_to_virt(pa_end);
> +		size_t va_size = (u64)va_end - (u64)va_start;
> +
> +		if (va_start >= va_end)
> +			break;
> +
> +		mte_set_mem_tag_range(va_start, va_size, KASAN_TAG_INVALID, false);
> +	}
> +
> +	/* Tags are now initialized to KASAN_TAG_INVALID */
> +	mte_tags_uninitialized = false;
> +	pr_info("MTE: Tag Storage Initialized\n");

Why All Words Start With Capital Letter? :D

Anyway, you might want to advertise tag value used for initialization.

> +}
> +
>  static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>  {
>  	/* Enable MTE Sync Mode for EL1. */
> @@ -105,6 +150,8 @@ static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
>  			 SYS_FIELD_PREP(SCTLR_EL1, TCF, tcf));
>  	isb();
>  
> +	__mte_tag_storage_init();
> +
>  	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
>  }
>  

Cheers
Vladimir

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/198b1486-d402-9061-a6f0-e522a548f040%40arm.com.
