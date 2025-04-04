Return-Path: <kasan-dev+bncBD22BAF5REGBBG5SYC7QMGQEXZEB6GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id BA21BA7C296
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 19:38:37 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-3032f4ea8cfsf2478564a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 10:38:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743788316; cv=pass;
        d=google.com; s=arc-20240605;
        b=K5+evVIrj2mrAwBQ9FXVBHyJSr8ERIRLusBakFrQVSKb6WkNO4PLWM2iY4yfgUF+Kk
         JYkA9yjOiY/w03ALT8A9JngLiqvbxtOoMF0ddLeXvbjAU4si1OsC2Me+WQb3GF0y3VvI
         6OU7vYfM6aIqrmJgQsiRvdmabhmw9tO7ZtBcwfFeB9rS4Yozn1OQSjcUanZDDFCI5VlO
         3W4ZxAAC5iqK+ijBcA1Iy6QH+InJX5LcyHO0Eh8rO71r6j9MoCSPZHWWSOgGjGzJ1lek
         nPgwdQNN4OVgBuAlJVMHAro9Es8Qdsm5XzZKc2l+S3YvT18z0oknq9GXKIZxGN5FznkV
         mloQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=SStEHEkfzrezSyRRqSWoJD6r2zICzgF31JRQSAOW/SQ=;
        fh=IEypYIK3/Gmy4SZUNfMhFeAQXS92N4fj00lcI+1Ykz8=;
        b=abQci2gJroRIMV6VVv6RxlvZ10UtHDr90r6a6dLAQOChKzTPN8NDiwrQtvAClfb3UE
         czotwhp80dF7JY9xopCFFzqFhSMVXzDHfJKhCGGYVmuSa7x7gJ2IbJyDQ10gtljI63X2
         s+IhzkV8ZUlR/RRVTs+zxKD00ZlDXJJWbiu1Q1em4KHzqDaVN0q2IzoIq64fVahtYB9j
         6/5yzfQicRz6DDCiC+tmYk5l9de+yNT4v/L03sgKWOe/h6ssKLuc6Ed9t43aVPXSjfd9
         7X+6g9rZ1gGWNCO6uREG+tZbgZsUDYHnMCyE3j1z8v/t+ZpPXmrGiWNdaoFFNhVKz+gd
         c9EA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=f05RGLP4;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.8 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743788316; x=1744393116; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SStEHEkfzrezSyRRqSWoJD6r2zICzgF31JRQSAOW/SQ=;
        b=Z+mJPGWl51TkvI6XHsSAMdzjOpAELwzsWah7kiSBkNx3OQlAMpLJVvJN0PpRAi4lyW
         ugNzxBJPM4pRot6voA93qghmzTg1EEAanmbslozQkQS7iT/hwqPxkkg6gwPdxXciHJZF
         k7hwf6RdMtGacodVms7jeU5rgnnTBzpqkGEke5FvRZ1G2p0nehBi0WfjU3hw9wnhtcZz
         sINRHtFSjcf8i+RJ18idHLV+LvoihM/1XdcHzBfGaTQ4IoEY1OvskHymTD3pv4DqVSLX
         pLLkQ9oV6aIlZBYRXYqv3os6NJwEFeJ3/V30BTA9EXirPSqWjmojdsokUkVCClYhlhMa
         K1TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743788316; x=1744393116;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SStEHEkfzrezSyRRqSWoJD6r2zICzgF31JRQSAOW/SQ=;
        b=KcZY9ekQDa+DaVFG6KrgBPnzFLXTdRAmThcPUvK9oEe+qSFH+i2axRUzdUE7ZQAO9P
         iLwsQhwhTzV89l6D9EoHF4fQngYNT5JUdm9g3UIcxgLXuVs3qHopcbggOks2pLpSGdQn
         kPn/VM1vbq+Xt4alnyK86jxv8d0mWpGWuaicqwA9c0WqJ6HoPyrz8SG+9+77f1ZNHWwA
         Ty8Wwb4UHdj2ifOikwJ1Zi2HHFM5x8aDgehrpuk4CQ5u2Ae/gYfXg6ugwOiCP4NgwCf7
         owT60tr2Xc0/fhfOtvZGWNF1H8dfE9//ejmUPXchCLHhwlNr4/eOx1XPAGWC1ZNplY5C
         wBpQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXR0m3EN5Jtshwen4Y/SkELPpxVpO0WULPqPnLwx1SOf+3cU/lw5Benb90GeuqkdKagvJV4Bg==@lfdr.de
X-Gm-Message-State: AOJu0YxmDxd2E8hG4YmxPSH6p8NcagzcMENkDSk94ObFUyyInOer0K5V
	M+7B6O7fX1BpvD4oKXJ/JoZE5TvyEBCahaeCJk4NwauGCCDbaoTt
X-Google-Smtp-Source: AGHT+IGTZCE9Uhnp+q3dOsh69OCZWPtLLszMEqQo/zZRYTSbWyVFjR2gxJBt5zV3z58zwQMWiWwbFA==
X-Received: by 2002:a17:90b:51cd:b0:2ee:f80c:6889 with SMTP id 98e67ed59e1d1-306a492209bmr7001041a91.33.1743788316152;
        Fri, 04 Apr 2025 10:38:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKZPEUD2aVzAmXrOnBK5JalTm39XkFG1sAsSZaTibHb4g==
Received: by 2002:a17:90a:1602:b0:2ff:530b:43d9 with SMTP id
 98e67ed59e1d1-3057a012f30ls1650467a91.2.-pod-prod-05-us; Fri, 04 Apr 2025
 10:38:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/sc2IND+e681p92P0GguLgJGx6hPoKuTmaN+qmh8lwK8AhxWuLXuGLxqTpCP2e3B7gtsW48NzB5w=@googlegroups.com
X-Received: by 2002:a05:6a21:e8d:b0:1f5:8479:dfe2 with SMTP id adf61e73a8af0-20104591150mr6603617637.6.1743788314756;
        Fri, 04 Apr 2025 10:38:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743788314; cv=none;
        d=google.com; s=arc-20240605;
        b=IAI4b3i6H94GqhAfrnz/hXhJ16MoiuweaZ9gcpaoi5nw2vOxTZ8gDkebnRi2aCJauV
         PAdcPyn6ZhDFq1Zd51My6BCR64lcUUi68Y37CH8ri3oBotFsuYpP+TDmxSqvycTOD+DO
         e+wUbb5eT0+hwMMpiT6jAodVxmwxu2kJjm3tzhzO0ajN2/tYvDRu9VA2QZ9UFFepmwP2
         4LD43bsMAXkVQcfTJN0dOyOB72E1bF6PCHlMT2aCmdmlfFoyK+WRirO3DUHhnYIA5REz
         9W05gsI7mboAvBYlPj/gKxlDOaP/IPhCwe5zxpjOsAncA6PLmCmFxYNPnjK60ff4/LSu
         jiuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=MkhEDkzVvWbFSyHa0L/xQxztLFgjeaUGVrsCYpUu5fs=;
        fh=qAclqxczifa7kqZeY+RB5PN2iG3DrlxE7ZoinyFrUhQ=;
        b=MaDIczL4yJss+Z5Fm6WHih9+6ALgVvBmazx6VRg/+7x56CxU0UzZsB5I+SrclUsXCM
         pLYF/jilQm/7ENaYGIwNOvmLsXHFSPmefxidERq4vM7+8JMOCTxkmy4vyX19s6wdOcga
         sksWExynNlEE5IvTtJRiH92wbMKEkDpqr1CG6X8egDszowGmp8gLgR+oSelQ0kUaNa3B
         r5noQduMQHDh2uCZfjLVjzs+R+qkEtZKRQBV1qZUqFyzTSty1xlc0lYAFq66+9v16QG6
         DDeTHbGrATrRp8iZKjGdf+aiTjKB3Npk+GlGXQCaw8B6HRkljhNcA4gVLWHx44MsEWE2
         jhPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=f05RGLP4;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.8 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.8])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-739d97f2fb0si187047b3a.2.2025.04.04.10.38.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 10:38:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.8 as permitted sender) client-ip=192.198.163.8;
X-CSE-ConnectionGUID: RY7O9Z1+SvejeZYgeqHj8w==
X-CSE-MsgGUID: a5RF1vSQQjG0nWUQOJ99yQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="62773781"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="62773781"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by fmvoesa102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 10:38:32 -0700
X-CSE-ConnectionGUID: 3jueK+bYQvGsWn/SgG7b1Q==
X-CSE-MsgGUID: vVkKM15nSt2oK2nSl/uuYA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128215225"
Received: from daliomra-mobl3.amr.corp.intel.com (HELO [10.124.223.29]) ([10.124.223.29])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 10:37:54 -0700
Message-ID: <8416848c-700a-4ff0-8a22-aa62579d60cd@intel.com>
Date: Fri, 4 Apr 2025 10:37:53 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 10/14] x86: Update the KASAN non-canonical hook
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, hpa@zytor.com,
 hch@infradead.org, nick.desaulniers+lkml@gmail.com,
 kuan-ying.lee@canonical.com, masahiroy@kernel.org,
 samuel.holland@sifive.com, mingo@redhat.com, corbet@lwn.net,
 ryabinin.a.a@gmail.com, guoweikang.kernel@gmail.com, jpoimboe@kernel.org,
 ardb@kernel.org, vincenzo.frascino@arm.com, glider@google.com,
 kirill.shutemov@linux.intel.com, apopple@nvidia.com,
 samitolvanen@google.com, kaleshsingh@google.com, jgross@suse.com,
 andreyknvl@gmail.com, scott@os.amperecomputing.com, tony.luck@intel.com,
 dvyukov@google.com, pasha.tatashin@soleen.com, ziy@nvidia.com,
 broonie@kernel.org, gatlin.newhouse@gmail.com, jackmanb@google.com,
 wangkefeng.wang@huawei.com, thiago.bauermann@linaro.org, tglx@linutronix.de,
 kees@kernel.org, akpm@linux-foundation.org, jason.andryuk@amd.com,
 snovitoll@gmail.com, xin@zytor.com, jan.kiszka@siemens.com, bp@alien8.de,
 rppt@kernel.org, peterz@infradead.org, pankaj.gupta@amd.com,
 thuth@redhat.com, andriy.shevchenko@linux.intel.com,
 joel.granados@kernel.org, kbingham@kernel.org, nicolas@fjasle.eu,
 mark.rutland@arm.com, surenb@google.com, catalin.marinas@arm.com,
 morbo@google.com, justinstitt@google.com, ubizjak@gmail.com,
 jhubbard@nvidia.com, urezki@gmail.com, dave.hansen@linux.intel.com,
 bhe@redhat.com, luto@kernel.org, baohua@kernel.org, nathan@kernel.org,
 will@kernel.org, brgerst@gmail.com
Cc: llvm@lists.linux.dev, linux-mm@kvack.org, linux-doc@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, x86@kernel.org
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
 <c37c89e71ed5a8e404b24b31e23457af12f872f2.1743772053.git.maciej.wieczor-retman@intel.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <c37c89e71ed5a8e404b24b31e23457af12f872f2.1743772053.git.maciej.wieczor-retman@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=f05RGLP4;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.8 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 4/4/25 06:14, Maciej Wieczor-Retman wrote:
> The kasan_non_canonical_hook() is useful in pointing out that an address
> which caused some kind of error could be the result of
> kasan_mem_to_shadow() mapping. Currently it's called only in the general
> protection handler code path but can give helpful information also in
> page fault oops reports.
> 
> For example consider a page fault for address 0xffdefc0000000000 on a
> 5-level paging system. It could have been accessed from KASAN's
> kasan_mem_to_shadow() called on 0xfef0000000000000 address. Without the
> kasan_non_canonical_hook() in the page fault case it might be hard to
> figure out why an error occurred.
> 
> Add kasan_non_canonical_hook() to the beginning of show_fault_oops().
> 
> Update kasan_non_canonical_hook() to take into account the possible
> memory to shadow mappings in the software tag-based mode of x86.
> 
> Patch was tested with positive results by accessing the following
> addresses, causing #GPs and #PFs.
> 
> Valid mappings (showing kasan_non_canonical_hook() message):
> 	0xFFFFFFFF8FFFFFFF
> 	0xFEF0000000000000
> 	0x7FFFFF4FFFFFFFFF
> 	0x7EF0000000000000
> Invalid mappings (not showing kasan_non_canonical_hook() message):
> 	0xFFFFFFFFF8FFFFFF
> 	0xFFBFFC0000000000
> 	0x07EFFC0000000000
> 	0x000E000000000000
> 
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v3:
> - Move the report.c part from first patch in the series to this new
>   patch to have x86 changes in one place.
> - Add the call in fault oops.
> - Extend the comment in report.c with a graphical representation of what
>   addresses are valid and invalid in memory to shadow mapping.
> 
>  arch/x86/mm/fault.c |  2 ++
>  mm/kasan/report.c   | 36 +++++++++++++++++++++++++++++++++++-
>  2 files changed, 37 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
> index 697432f63c59..16366af60ae5 100644
> --- a/arch/x86/mm/fault.c
> +++ b/arch/x86/mm/fault.c
> @@ -511,6 +511,8 @@ show_fault_oops(struct pt_regs *regs, unsigned long error_code, unsigned long ad
>  	if (!oops_may_print())
>  		return;
>  
> +	kasan_non_canonical_hook(address);
> +
>  	if (error_code & X86_PF_INSTR) {
>  		unsigned int level;
>  		bool nx, rw;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index f24f11cc644a..135307c93c2c 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -700,7 +700,7 @@ void kasan_non_canonical_hook(unsigned long addr)
>  	 * operation would overflow only for some memory addresses. However, due
>  	 * to the chosen KASAN_SHADOW_OFFSET values and the fact the
>  	 * kasan_mem_to_shadow() only operates on pointers with the tag reset,
> -	 * the overflow always happens.
> +	 * the overflow always happens (for both x86 and arm64).
>  	 *
>  	 * For arm64, the top byte of the pointer gets reset to 0xFF. Thus, the
>  	 * possible shadow addresses belong to a region that is the result of
> @@ -715,6 +715,40 @@ void kasan_non_canonical_hook(unsigned long addr)
>  			return;
>  	}
>  
> +	 /*
> +	  * For x86-64, only the pointer bits [62:57] get reset, and bits #63
> +	  * and #56 can be 0 or 1. Thus, kasan_mem_to_shadow() can be possibly
> +	  * applied to two regions of memory:
> +	  * [0x7E00000000000000, 0x7FFFFFFFFFFFFFFF] and
> +	  * [0xFE00000000000000, 0xFFFFFFFFFFFFFFFF]. As the overflow happens
> +	  * for both ends of both memory ranges, both possible shadow regions
> +	  * are contiguous.
> +	  *
> +	  * Given the KASAN_SHADOW_OFFSET equal to 0xffeffc0000000000, the
> +	  * following ranges are valid mem-to-shadow mappings:
> +	  *
> +	  * 0xFFFFFFFFFFFFFFFF
> +	  *         INVALID
> +	  * 0xFFEFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL)
> +	  *         VALID   - kasan shadow mem
> +	  *         VALID   - non-canonical kernel virtual address
> +	  * 0xFFCFFC0000000000 - kasan_mem_to_shadow(0xFEUL << 56)
> +	  *         INVALID
> +	  * 0x07EFFBFFFFFFFFFF - kasan_mem_to_shadow(~0UL >> 1)
> +	  *         VALID   - non-canonical user virtual addresses
> +	  *         VALID   - user addresses
> +	  * 0x07CFFC0000000000 - kasan_mem_to_shadow(0x7EUL << 56)
> +	  *         INVALID
> +	  * 0x0000000000000000
> +	  */
> +	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_X86_64)) {

One overall comment on this series: there's a lot of unnecessary
complexity. Case in point:

	config ADDRESS_MASKING
	        depends on X86_64

and

	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING

and

	config KASAN_SW_TAGS
        	depends on HAVE_ARCH_KASAN_SW_TAGS ...


So you can't have CONFIG_KASAN_SW_TAGS set without CONFIG_X86_64.

> +		if ((addr < (u64)kasan_mem_to_shadow((void *)(0x7E UL << 56)) ||
> +		     addr > (u64)kasan_mem_to_shadow((void *)(~0UL >> 1))) &&
> +		    (addr < (u64)kasan_mem_to_shadow((void *)(0xFE UL << 56)) ||
> +		     addr > (u64)kasan_mem_to_shadow((void *)(~0UL))))
> +			return;
> +	}
This isn't looking great.

I'd much rather have those kasan_mem_to_shadow() arguments be built up
programmatically.

I'm also not following the description of where these ranges come from:

	[0x7E00000000000000, 0x7FFFFFFFFFFFFFFF]
	[0xFE00000000000000, 0xFFFFFFFFFFFFFFFF]

I obviously recognize the top kernel and top userspace addresses, but
there do 0x7E... and 0xFE... come from? Is that because both of them
only have 56 actual bits of address space?

Wouldn't we be better off writing that as, say:

#define HIGHEST_KER_ADDR (void *)0xFFFFFFFFFFFFFFFF
// ^ we probably have some macro for that already
#define LOWEST_KERN_ADDR (void *)(HIGHEST_KERNEL_ADDRESS - \
					(1<<56) + 1)
// ^ or can this be calculated by tag manipulation?

which yields:

   void *_addr = (u64)addr;
   ...

   in_kern_shadow = (_addr >= kasan_mem_to_shadow(LOWEST_KERN_ADDR) ||
		    (_addr <= kasan_mem_to_shadow(HIGHEST_KERN_ADDR);
   in_user_shadow = (_addr >= kasan_mem_to_shadow(LOWEST_USER_ADDR) ||
		    (_addr <= kasan_mem_to_shadow(HIGHEST_USER_ADDR);

   if (!in_kern_shadow &&
       !in_user_shadow)
	return;

I _think_ that's the same logic you have. Isn't it slightly more readable?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8416848c-700a-4ff0-8a22-aa62579d60cd%40intel.com.
