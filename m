Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQPNSD6QKGQERW4OQUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 907792A84E9
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 18:30:43 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id k16sf470984pji.4
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 09:30:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604597442; cv=pass;
        d=google.com; s=arc-20160816;
        b=IlWQtSDt7yNgXngjZ5X5hucE+tQGISQsUD4+JzjPw4eq7yR3hJLkpdGkzUb7pDDnhw
         COzMgCAWnOSS+Hy5IAGT/dqsSFMjiIyuv1Z854zQHkUa++r1qxPgwU7B2hCWddZeAYWu
         pZbBAuMYt2/4p7s99alazIaQlHK/ycYBz3C8fBogCyNeIXLu0WUIR50++qJqWoiezrol
         /oZYNfcaqbmuRcEjUSNhAfEzUOnGCj5Dcm38tbNErSk8IY2RbIhgBxUx9HBYUN/dpl6s
         meFDGiFypeBLnuziwuGUeS6Wgbs2DDcPxaOUhu2fR6+U2XRxqi+f/TtyPeO/Ks9BmnNt
         WuMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=ozYxEbF8NKMwQ4/bJvTii234lB91PDkXNEmB+cKHYo8=;
        b=v7950cSNZdzJAelSZ+hbY9EhS2RST2nKwqndUuIgYO0wGcR4X9eE9neOpFR1hjELnV
         wEAuBChIrqmZ1v2XnS33UTVsr1SYUJ38z1fuh7YFcouHrUF/MBai4ruCYgkMsJ01GBZd
         kow6mgulAXUyoImaWzpARhjjOyb/mJhfqizKzK2BvoPoteABUfBgst3uU7zaFU8L59+T
         dqHGzGW1zAfDNyYGrq6voKymD2XpDBEr0LFIipXD+n0fbJHkmAIiQMJ2n1JDSxXD8CiP
         wm+pCfbN12pCFZOBx/Hgg56/izEZwS4NbO+1u0rKrX0HY3BzQOIbHvgGS5y3EbRff9/F
         bSJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ozYxEbF8NKMwQ4/bJvTii234lB91PDkXNEmB+cKHYo8=;
        b=dRh0Nu0ZgTk8nsunnLTl/ZQwRUbneQ1xwJ5znBS4J1Gc29F/oRHwVx6Op7VdCsJgW0
         b3tNxjMehdzyiLBNfqbNrYRvB78HL5qTFq3y/bWWe7Bj1Q6JCfX7WxZ3vihqHgrPLjlP
         RkM3dmcxwRcqc7pvLgDMg01lQF8en86zIHsb2zHXbw7ggNHin7EVfz5RNHvkcCQAFxpN
         e0pSE+/IL8z2t+g5u5a+KwY/4sPKxrRmsRjiIMA8waKR21+6U4Tvlrpyn5hymxZdi1Cy
         JaBoL3oZ+f5cCElztnrPXb/D5g//3kTFSMWvcS3lKCT1iFUkYZXYsjdp9bX8kZHOfXY/
         paoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ozYxEbF8NKMwQ4/bJvTii234lB91PDkXNEmB+cKHYo8=;
        b=LiXx7phMv5YZcJtEWoZOcoz/fIyeZ2tiCoKe1cCOAaRCRQCepza1P18KZ+j9ZLhgjC
         g3lhwDRd4O2OReqjOE0orDWXWtXTxboFqswVNJL97NJOkJKvabY/rG+VMOJM0y/Ct8Lx
         MSzAaiwDw44tM+SypJ/O1ZptJkqH6QVyvFNCR1aHZLE6yTWtoWKXzeGh4UNIEEixjusN
         Oz4l8I+kmNtBXJ6wgGtAYLK2/7H/8c6tp2356tAs9Dig2c7G2ObFIbbhVa2zP7fh/Nkl
         rvKcsYxR/Ecuev7IhWTclxQjzp8yU4RP3+8Ma0H5ZSwYDR10jPl/FZREl/g/rjWL4OlY
         o07g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530U+RMxUCxyIqae4fAlk5zJfH9B5YalK4IBg3LO7nDCPTbjEhlD
	pIxn8aoZl6OK6zm4j2H9WRc=
X-Google-Smtp-Source: ABdhPJyaNLG2/PKWhxezyR+ub6nLMtHuGLpDKz/Zq/IZaC1q6ewO4yHWVLFDXg+/kNOAsn5uya2FEw==
X-Received: by 2002:a63:4c5b:: with SMTP id m27mr3464675pgl.211.1604597441926;
        Thu, 05 Nov 2020 09:30:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3e45:: with SMTP id t5ls1259316pjm.2.gmail; Thu, 05
 Nov 2020 09:30:41 -0800 (PST)
X-Received: by 2002:a17:90a:f3d1:: with SMTP id ha17mr3655223pjb.164.1604597441348;
        Thu, 05 Nov 2020 09:30:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604597441; cv=none;
        d=google.com; s=arc-20160816;
        b=lU0TYLevjlQL6ia0JauvpKLnq5yRwtGwEM92Jn1FDXReNQCr1dyrcxsli1uuExf4w+
         fkc4QG1OE3cKZDejeaU4Y11SNgSSh0+x+khxjSzFrY0STzUAuEwgAPMZVP6+ViExvAFC
         HUYVf57tjw60W91d+V/p8lDtc6ElpZZmjIF0O3NOg8x86FaR+gCe+UvjWS7AUne8VNRi
         3/wq8ABL7x1Iv2XT+FfRHAdkjEco6tqPGI/K2UwtYbnHzg1xPV18Q0TTdVPmh7PW7Dqi
         lvgtvJZ6ymy4T0LLJx/07Gz9ykY1zwHsv5r0h1oa/4rVyjt8OH4biixi5KTBhqDb54Pp
         3aDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=BaGXbzyrQpdNXOqTymflAsPQ7/jBHa6AoA2au2tokRo=;
        b=sJQN09V7kAZeG+2OOXrH+e+ltaAPrwkv6UdjNoMXwBuIE+6b3oYv+eYAfOwiojos8u
         EK2yZVTDG5eXVt9YsTPM3QaWcu3AwkxzAZJ0JkNAYY0t5IakYOaNNwf9DMz00yA02D01
         mIfJoSZkmKOyJDMxd2khb52YNDYDcIhy3fy30nmS4p+QQ+q/W/YRjfS1gG97VUgXWXRb
         N3AwL0yBFGun+6LXIVfIlehoxS80a4WLwcNsm6XQpcbz+eOPiN9EDi6EFLr+PjyQHa7n
         hZ3IFTm5A0PtHBtbtb94bJ6fN7MKyg3tPc+0XWKG9T/YLbRBKs3jnGCFOQUxbMVVeuuI
         WvpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a22si201383pfd.0.2020.11.05.09.30.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 09:30:41 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5C3DF206B6;
	Thu,  5 Nov 2020 17:30:37 +0000 (UTC)
Date: Thu, 5 Nov 2020 17:30:34 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v8 32/43] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20201105173033.GF30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <5d9ece04df8e9d60e347a2f6f96b8c52316bfe66.1604531793.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5d9ece04df8e9d60e347a2f6f96b8c52316bfe66.1604531793.git.andreyknvl@google.com>
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

On Thu, Nov 05, 2020 at 12:18:47AM +0100, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 14b0c19a33e3..cc7e0f8707f7 100644
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
>  	pte_t old_pte = READ_ONCE(*ptep);
> @@ -123,6 +125,23 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  
>  void __init mte_init_tags(u64 max_tag)
>  {
> +	static bool gcr_kernel_excl_initialized = false;
> +
> +	if (!gcr_kernel_excl_initialized) {
> +		/*
> +		 * The format of the tags in KASAN is 0xFF and in MTE is 0xF.
> +		 * This conversion extracts an MTE tag from a KASAN tag.
> +		 */
> +		u64 incl = GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT,
> +					     max_tag), 0);
> +
> +		gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> +		gcr_kernel_excl_initialized = true;
> +	}
> +
> +	/* Enable the kernel exclude mask for random tags generation. */
> +	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);

Same question as on a previous patch. Is SYS_GCR_EL1 written on the
other registers via cpu_enable_mte()?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105173033.GF30030%40gaia.
