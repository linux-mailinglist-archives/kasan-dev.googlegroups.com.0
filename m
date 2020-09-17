Return-Path: <kasan-dev+bncBDDL3KWR4EBRBZ5JR35QKGQEK5WH44I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 03EBF26E146
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 18:55:05 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id u13sf2115769ilm.11
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 09:55:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600361704; cv=pass;
        d=google.com; s=arc-20160816;
        b=nMFA17rUz+2Wk0V9VrHqFTdS9XQcvC6cLFL435Lwg8aQWYLh9I6F7R9a6MA1xEsjEC
         5TyJD8s35UtAiPHMrEeZsaVUq/8TIt2A++uDLMQLEULUCjr8ON34UiVUgp6dDdZdDP8F
         J3yiRnhbqVLKXUOo5DmPDkXQK27g2VtPY6nS1cQr2k0mHfwhJdJt0PZAsF5iyZFk5jMR
         1/7Z4YDEQ0kkYtsTMGH2zilmT6nMDxl1AySLia5iSdYx5L9e/8YvjgQK+0p782bIb3wK
         f83qAPsvbtvCZqIilg+GgifiJy1Iht9MZYgazid8/JoYqOEe4Q3SmdVoNTnV5h1qWrLp
         25oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3Df2pkEKpPQmPELYZ8QxHyDvHTiLC6c9hUOS0opCkwg=;
        b=vu5O/McwkCKkLxvvEibCauagas+73/e71Fe4Q4XfTynt1vM9QK+nGFrl+3RJeDu9ye
         OJsIC9vtA8h3I6y7YB/Y5l1ATfJXoJgXmdY2ulEgW7IdKFQv7D7Z/rcNdifP9gvPsbT8
         sL9hcfSjG87/j5jQ5mx9VmG2GjXwrZizpfmNKC3Ci/zn6XIHd1Me6SObjwPHZxo6bgMm
         s4HJhXVnIXQA9hiTuzCOq1Y7lEhX0iovycCgFyoNTRmWg0Rd9F1agsnHQxD/oWLBQk+z
         LbMtYPeiDwhqPAgIIz6AvIVskpLr9Q/VNEzQmP4gCGK/nJLRJlvlS1CzpzjALk16Eed0
         VchA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3Df2pkEKpPQmPELYZ8QxHyDvHTiLC6c9hUOS0opCkwg=;
        b=k7fZAkXmERCNaWsQ3/Xe6GDYdnNvidU8wPj4o1EAauuQUiDpb42Y6E1lGVz3+cs8HL
         +Z1zB/l3iKbFDsvTPsmWuMJpMXzLplMiTWmB4gZ8Z4vb2FtvCfN5b8N7UWwbU+50RnpR
         KFH2q1Xb1hEa7YaesXleyo/yXA7YJrCJnaItkLiGb7xGfDWW/6HX8zYCxUWNXe2vH0+z
         0F8WFUuYafC+WNiCrbNvG2zgNAy/phDU8Z8eAQ9L1IVizmnR8FuFhrq171RqdwJJVEns
         0ZJXx0op7FqHeR109J1sPUQAWfR7kBdwr5+6MIv/L+/isDQ9be/CuMLPbkX7URGAbyQa
         E3Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3Df2pkEKpPQmPELYZ8QxHyDvHTiLC6c9hUOS0opCkwg=;
        b=cecsnvr/7fOUBmD+tMlcaBUOey0GtC+cDRSvS0FA3J2ftxK0l5laJCJVmoAilBg/Bb
         pD5P3Uzk0JHeqqZWuniBSjQjih2AB24S75qU5iSWHEYioEwd7Nhxr7WPwOjpEuqRlpy7
         XXmasGkwZ8gBzBf4/zyK9IC6a7BzcWt7ZbdGG6Z+oHGNbMTtqBrsdsmcTcDfuWvRmMbp
         tcSVEHx6gcKmLdy5KbNczua5H+9irkj0QT7xNW+JsYwjRY9WHvYW5+4lqPyK+gXjVG6b
         dH6Y+pLx8u9uMBi5Wl25/lML+OSIsEkeepjzhYJYiPJa30vbItdcEK+OzTlRKVuJVyWK
         BA5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hAkdP/nlMJcDE8UHmK93S51hV2xZXKNYQEqCMvIh8vZcjyRKD
	L2AMCG1lQ602rv0EWoyI42I=
X-Google-Smtp-Source: ABdhPJwaNmPWndGAqjhY6tAd1AR45EOxkAl1ffjzcGQnEuimVy5d0ClNsk7olPXUvbixMfa7ep4Bcw==
X-Received: by 2002:a02:a816:: with SMTP id f22mr27375223jaj.118.1600361703908;
        Thu, 17 Sep 2020 09:55:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1941:: with SMTP id e1ls792722ilm.3.gmail; Thu, 17 Sep
 2020 09:55:03 -0700 (PDT)
X-Received: by 2002:a92:dc81:: with SMTP id c1mr21542020iln.220.1600361703481;
        Thu, 17 Sep 2020 09:55:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600361703; cv=none;
        d=google.com; s=arc-20160816;
        b=TELzk07H7gWLVHseFOOPMHUZFDrRtgnDLiFM/hs7VHFR1Cl4U3vxEYJfB4DagHdmxz
         8BYT0st8ZBHVioHVe07Tvok/KsP4Ax65bY3pJYIKZp822gOgZF2Y0umwPEKar+KqSrKu
         SiX04invVqIilorGflZIoDsx3P33o/9crj2ScTgAZZ/mSkC4qctGFUElFPrJswgJfDof
         TsYa4lE1Xa9LT4jpwILbpHQSQGoy2uDXE0cm0uhgb4HfIPa6cDoeESLPJLwxHneHgbc0
         E8XTkK6f1dnpACggwhlGQPAeV49Dn5V9ipm96Hw5+A9fgCi/D9L8zcaiFQdVSDpF/100
         1O6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=yslr3nbIXURaonz0aOr9iOWHpWuvmYZeCt9Ex/lExZU=;
        b=e8o44BlDN6UUH7KZUgas3P0UsfC65dRcaw2ZBkZKnfv35SRPIiY5WWSYTVPhQrUL8T
         UpMZOrjWxVREzfFWL99fnxeAvzuMfhGqO06p9wBb63WQuWWhLZCJZgjVFjHs8pxvkrui
         pA6Sg/GsmnCa2N28LMwbvmLOeTHBiWPZmi2XkdXpspQjTKiRyqVv3OhvP6Yu+HhkZi+f
         nr026lcoYmR3eMPxTrea4hzaXKo6VuyJO4ZdG/ZZ+r2+c6C/a7tGXfhXa3oSOX4htxss
         BTWNG/RTvKCVvRVMCQRSMS6Ine/5sUstDu6MXQNhtttzW0W3a86XFgszI/oGQE1faZN8
         /1iQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m2si14991ill.5.2020.09.17.09.55.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 09:55:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 0CD1F2078D;
	Thu, 17 Sep 2020 16:54:59 +0000 (UTC)
Date: Thu, 17 Sep 2020 17:54:57 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 28/37] arm64: kasan: Enable TBI EL1
Message-ID: <20200917165457.GG10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <9ecc27d43a01ca32bcacf44b393a9a100e0dfdb2.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9ecc27d43a01ca32bcacf44b393a9a100e0dfdb2.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:16:10PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> index 5ba7ac5e9c77..1687447dee7a 100644
> --- a/arch/arm64/mm/proc.S
> +++ b/arch/arm64/mm/proc.S
> @@ -40,9 +40,13 @@
>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
>  
>  #ifdef CONFIG_KASAN_SW_TAGS
> -#define TCR_KASAN_FLAGS TCR_TBI1
> +#define TCR_KASAN_SW_FLAGS TCR_TBI1
>  #else
> -#define TCR_KASAN_FLAGS 0
> +#define TCR_KASAN_SW_FLAGS 0
> +#endif
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define TCR_KASAN_HW_FLAGS TCR_TBI1
>  #endif
>  
>  /*
> @@ -462,7 +466,7 @@ SYM_FUNC_START(__cpu_setup)
>  	 */
>  	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
>  			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
> -			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
> +			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
>  	tcr_clear_errata_bits x10, x9, x5
>  
>  #ifdef CONFIG_ARM64_VA_BITS_52
> @@ -495,6 +499,9 @@ SYM_FUNC_START(__cpu_setup)
>  	/* Update TCR_EL1 if MTE is supported (ID_AA64PFR1_EL1[11:8] > 1) */
>  	cbz	mte_present, 1f
>  	orr	x10, x10, #SYS_TCR_EL1_TCMA1
> +#ifdef CONFIG_KASAN_HW_TAGS
> +	orr	x10, x10, #TCR_KASAN_HW_FLAGS
> +#endif

That's fine in general but see my comment about refactoring the other
patch touching this file, this will move around a bit.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917165457.GG10662%40gaia.
