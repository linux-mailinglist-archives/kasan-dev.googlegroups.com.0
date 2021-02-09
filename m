Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBPE6ROAQMGQEWQ3CVVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E0A2F315596
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 19:06:54 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id k14sf11486485lfg.16
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 10:06:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612894014; cv=pass;
        d=google.com; s=arc-20160816;
        b=B5k8zP92ldZ76+3c3InQc7lEvG9Ixn/amojT5Ew/tr48AUthBzEvc3ejXvnuc9GMC2
         YullL0yxzMHfK1CyIqlE5s1jjbi863p4yIbTlu5hblPdUlJlVBkPms53jsBysl9Tj4/W
         mJXLB1RVs1IYgQjanZQzL6381MzREYuRsLAraOJuLHlplP7nF6mnXIUwD89asV8wYP8q
         9S9u7SSkaSZjAMX3SaLOtiiQ1ZdsUmtwRC1bn96jJo/gElKWwDc9tMRXxaGaRu76wDCq
         8qsjScX6iu8y2hYzPzx1al+kjgPLshY79hK5/n+rRUDTSIbUMvxXgKz8q0mjCPyCOnid
         gwqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=UHA+uquH5YM2T8ZSa4Mdk92+s1MnNvqf0S6cY5BIUTg=;
        b=yBUAeUAdqdr4tTEt+fSJK9OS2LS1exlH0Q3TO1UITN5Mvr4tJVWx/FdwCIKZRY4xNa
         h8rDeBUOxwlnbQofcGVDuEKDAM6oRCDUSdKvRaujF5jeGEgf2jFo4MkFKoX2Ny92e8Yp
         2Pep1ZMSb0yQmuvgE91FyPMlqo18odczzESoNXidgj/8XGDq+5f113QV6k0RJ1Wh2XT4
         nM8jylOYCZA/wdKB2jgsUT7SMIfLwUZ9dYKoM/2XDsajrUtCtxyHFlerMkvHYOFk6CHB
         0s5PVJF1uS/U/oOF/uidDuzui8FMz5xeUfK7ppW4QltSy+xLxzhdQBBand5iHLFxfLKY
         WSfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UHA+uquH5YM2T8ZSa4Mdk92+s1MnNvqf0S6cY5BIUTg=;
        b=FuqTzTzdMokrmHZoPs2eYG7HMs59y5jSVTV5/nZIovpsSehlHZgMT0xpqjo+aYH1y4
         jXBZAGUPxviaCQhVcQyKrHWpkk4EYkQqB0ZfQ5xdAaYFwb2d8k8v91lceBivNhw9eTHG
         kHm+sIDigj4IA6ad1uMhogPnYVMHPwvjmeojG1lumyw1ZhQdIjyd3/YsmcwpoowoRkJ/
         +27erfXPukAXBXE/tGZunm8PliMX8B+T4x3X6xsJFbg2u4Wg3poIqlmQOzTyLFuhntCW
         CrcXGMRmt68p/UUgwcNxk+pH13CWqRilR/Qa3Gepggad2n7dtL90zmBQyfS7V/vRhUFv
         mw2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UHA+uquH5YM2T8ZSa4Mdk92+s1MnNvqf0S6cY5BIUTg=;
        b=CtmMdQfhRe9eos7UlifiRGYZqTISbo2POljhpoGCoTLHtqwrg3MflkidHGCp8S38uG
         CTJ2XRdHc75b4+/ScL1051/VAUIBY31fI+8IsepBgqq2Gn2VXq01/wpUsjGmX4qPkuhy
         OkXALbcXsxbyumpDwVG7iWh4C2XD6pmuOpT8qgXhptMwIL626Ps74G7Qc/FG64IjzO0Z
         +r7ZKTz6v67ZlDT3RSPYWkltWps1AjVjL2kUePNP6nWSYsJlm6hjT4yjRJr7Hr3Vwfk+
         D1RcvENB6ljOlP2L92JyX+kkeqAO8QZxMe8ztxsBNUedmIaSaJKH4t5eekoMGy/wG06G
         4+qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532r+uP+V3JASPgJnkTlBYPnQfSPMgkIMah5YncQggvQBAVajelp
	smV3/Zt+qDbMs7pMeZI42xQ=
X-Google-Smtp-Source: ABdhPJycsKo/fcwrsVAY0iyOopUe1hm8sQsqOeckrQPou8B2NcFNud5tG8lan8pPUCuw8QA+gzOeDQ==
X-Received: by 2002:a2e:8ec9:: with SMTP id e9mr8000520ljl.372.1612894012994;
        Tue, 09 Feb 2021 10:06:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4adc:: with SMTP id m28ls1606556lfp.0.gmail; Tue, 09 Feb
 2021 10:06:51 -0800 (PST)
X-Received: by 2002:a19:d3:: with SMTP id 202mr13212490lfa.570.1612894011896;
        Tue, 09 Feb 2021 10:06:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612894011; cv=none;
        d=google.com; s=arc-20160816;
        b=SAN+5qmOI5lXHnhdz3/TXgiIfNpginnFFWf8imqpeIWZlF2zoN+P/TbRuOQiaCFOmk
         plDqKeRwMZzor1K63DR/R6TSVefXhLbzMcjIWVzFA9bo9/40gWWn8JjYG5bSiWpk06NK
         YDzwIsjvkSEPqUAf6Rg3WL2Ms6QD+CKTHjixypxR5dVvwCLWyMmgY/UE9j1tLDC3PNLh
         3pIAr/ig1SrFIh38MjAO5C0Y0OmRsuSDTknflgb/A51cHHmoFmRlM+Vxn7NlEjBKO2rc
         FHTT1yR8g2LH5bBvTB2eR7B5tM2TbfZjk7JtOJYCu4AmAJqOWJZNwCF2eYoB9r7pnylI
         Bbmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=W1ECk2yQ2Nw4iMrqAMMgTv/mrdD7rInUhBu4o6nE5kw=;
        b=DBZQ6zlPhfPk/S7nu4yG7KvFZrSCEeb8GKx1OD8xWakbP6h+5MmCsvegTSSfqKEaFn
         2WMyzBUe21YTRLxbP/8mEHST/6yudaPdYwFbtRV10SA7M+knp+tGUr/hEnXkCVoVdh07
         eEYN1zxG6HYXvoZx0+SyRzkwQU/pQmDcStwQaXlU6Ez4qkUVOAREJ8SG+7ze0db9Z90M
         cwUcNSpkvKjyNCzxGZ19+h38dDhMz/ogHm2GYT/rwGMCsQRYSVEeFm2iPSBAgQk5uulF
         BA/fuHG5SbupDP67X5gFsPJ5JAXfijJW/CMNTPeGpDUdINZCMfKx8v6Lq+u4AkrXYFxR
         vqRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id i190si941475lfi.8.2021.02.09.10.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 10:06:51 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 1FBFFAB71;
	Tue,  9 Feb 2021 18:06:51 +0000 (UTC)
Subject: Re: [PATCH mm] kfence: make reporting sensitive information
 configurable
To: Marco Elver <elver@google.com>, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com,
 jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, Timur Tabi <timur@kernel.org>,
 Petr Mladek <pmladek@suse.cz>, Kees Cook <keescook@chromium.org>,
 Steven Rostedt <rostedt@goodmis.org>
References: <20210209151329.3459690-1-elver@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <4f39ad95-a773-acc6-dd9e-cb04f897ca16@suse.cz>
Date: Tue, 9 Feb 2021 19:06:50 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <20210209151329.3459690-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/9/21 4:13 PM, Marco Elver wrote:
> We cannot rely on CONFIG_DEBUG_KERNEL to decide if we're running a
> "debug kernel" where we can safely show potentially sensitive
> information in the kernel log.
> 
> Therefore, add the option CONFIG_KFENCE_REPORT_SENSITIVE to decide if we
> should add potentially sensitive information to KFENCE reports. The
> default behaviour remains unchanged.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Hi,

could we drop this kconfig approach in favour of the boot option proposed here?
[1] Just do the prints with %p unconditionally and the boot option takes care of
it? Also Linus mentioned dislike of controlling potential memory leak to be a
config option [2]

Thanks,
Vlastimil

[1] https://lore.kernel.org/linux-mm/20210202213633.755469-1-timur@kernel.org/
[2]
https://lore.kernel.org/linux-mm/CAHk-=wgaK4cz=K-JB4p-KPXBV73m9bja2w1W1Lr3iu8+NEPk7A@mail.gmail.com/

> ---
>  Documentation/dev-tools/kfence.rst | 6 +++---
>  lib/Kconfig.kfence                 | 8 ++++++++
>  mm/kfence/core.c                   | 2 +-
>  mm/kfence/kfence.h                 | 3 +--
>  mm/kfence/report.c                 | 6 +++---
>  5 files changed, 16 insertions(+), 9 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
> index 58a0a5fa1ddc..5280d644f826 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -89,7 +89,7 @@ A typical out-of-bounds access looks like this::
>  The header of the report provides a short summary of the function involved in
>  the access. It is followed by more detailed information about the access and
>  its origin. Note that, real kernel addresses are only shown for
> -``CONFIG_DEBUG_KERNEL=y`` builds.
> +``CONFIG_KFENCE_REPORT_SENSITIVE=y`` builds.
>  
>  Use-after-free accesses are reported as::
>  
> @@ -184,8 +184,8 @@ invalidly written bytes (offset from the address) are shown; in this
>  representation, '.' denote untouched bytes. In the example above ``0xac`` is
>  the value written to the invalid address at offset 0, and the remaining '.'
>  denote that no following bytes have been touched. Note that, real values are
> -only shown for ``CONFIG_DEBUG_KERNEL=y`` builds; to avoid information
> -disclosure for non-debug builds, '!' is used instead to denote invalidly
> +only shown for ``CONFIG_KFENCE_REPORT_SENSITIVE=y`` builds; to avoid
> +information disclosure otherwise, '!' is used instead to denote invalidly
>  written bytes.
>  
>  And finally, KFENCE may also report on invalid accesses to any protected page
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 78f50ccb3b45..141494a5f530 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -55,6 +55,14 @@ config KFENCE_NUM_OBJECTS
>  	  pages are required; with one containing the object and two adjacent
>  	  ones used as guard pages.
>  
> +config KFENCE_REPORT_SENSITIVE
> +	bool "Show potentially sensitive information in reports"
> +	default y if DEBUG_KERNEL
> +	help
> +	  Show potentially sensitive information such as unhashed pointers,
> +	  context bytes on memory corruptions, as well as dump registers in
> +	  KFENCE reports.
> +
>  config KFENCE_STRESS_TEST_FAULTS
>  	int "Stress testing of fault handling and error reporting" if EXPERT
>  	default 0
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index cfe3d32ac5b7..5f7e02db5f53 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -648,7 +648,7 @@ void __init kfence_init(void)
>  	schedule_delayed_work(&kfence_timer, 0);
>  	pr_info("initialized - using %lu bytes for %d objects", KFENCE_POOL_SIZE,
>  		CONFIG_KFENCE_NUM_OBJECTS);
> -	if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> +	if (IS_ENABLED(CONFIG_KFENCE_REPORT_SENSITIVE))
>  		pr_cont(" at 0x%px-0x%px\n", (void *)__kfence_pool,
>  			(void *)(__kfence_pool + KFENCE_POOL_SIZE));
>  	else
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 1accc840dbbe..48a8196b947b 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -16,8 +16,7 @@
>  
>  #include "../slab.h" /* for struct kmem_cache */
>  
> -/* For non-debug builds, avoid leaking kernel pointers into dmesg. */
> -#ifdef CONFIG_DEBUG_KERNEL
> +#ifdef CONFIG_KFENCE_REPORT_SENSITIVE
>  #define PTR_FMT "%px"
>  #else
>  #define PTR_FMT "%p"
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 901bd7ee83d8..5e2dbabbab1d 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -148,9 +148,9 @@ static void print_diff_canary(unsigned long address, size_t bytes_to_show,
>  	for (cur = (const u8 *)address; cur < end; cur++) {
>  		if (*cur == KFENCE_CANARY_PATTERN(cur))
>  			pr_cont(" .");
> -		else if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> +		else if (IS_ENABLED(CONFIG_KFENCE_REPORT_SENSITIVE))
>  			pr_cont(" 0x%02x", *cur);
> -		else /* Do not leak kernel memory in non-debug builds. */
> +		else /* Do not leak kernel memory. */
>  			pr_cont(" !");
>  	}
>  	pr_cont(" ]");
> @@ -242,7 +242,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
>  
>  	/* Print report footer. */
>  	pr_err("\n");
> -	if (IS_ENABLED(CONFIG_DEBUG_KERNEL) && regs)
> +	if (IS_ENABLED(CONFIG_KFENCE_REPORT_SENSITIVE) && regs)
>  		show_regs(regs);
>  	else
>  		dump_stack_print_info(KERN_ERR);
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f39ad95-a773-acc6-dd9e-cb04f897ca16%40suse.cz.
