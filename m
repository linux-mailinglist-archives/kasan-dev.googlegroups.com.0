Return-Path: <kasan-dev+bncBDDL3KWR4EBRB5U6T35AKGQET2ISBPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 149A5254402
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:48:24 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id c191sf4385129qkb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:48:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598525303; cv=pass;
        d=google.com; s=arc-20160816;
        b=bP2mEO9dK9ui4ZysKA11+Rj26nb4d17RfMRJpBVh3IG1jOpY0ga9rtIN05RoI1J+e8
         9rInaZgTklURAmlqmMLSbKLJLr5aymALA375+fhcnxYRtuoh2psmllX702HVDdKHsvOS
         /YHVnEg5SQ9SwrqQyafE7/OdA0GNTQGZEAgv9zJ9IbUD8JGXoigZkkqwbjDEkFPG9qsu
         csd/krH1A2J8zb15FtEn+nJQMqA2seMSOjhZdD84WzT+hjVELaIGHibcr5oB4sJ9oa6g
         usXs1fRy0oY9gYilGFKkND8IgtOtZdrke2XebyBfYcTrhNEccAfyuxtYTnhw53vOPrRa
         ruGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=BwEBhCCnSHroWYUXVWwpMqqouXdp5LcyUnDeRZoyxBg=;
        b=I9KjRz4g5DpdznApPnB02B1VYvzCnbnPYs4u0mdqPp2eFG7NDnZg6xsyTGOUqPwZS1
         TOG5ojQxIM0jEYaz3TrwIOGF9LcBSVK9l8D2p2nYVn7VQtojNjQNeWeHyL4iwpzAJ+yG
         OG60OJW4dqVdYbJxf2d8kMpvPBChHxDKI8VJYWYPAAbkBoI/F8NI3NCRE+uEYYySUvs1
         MMxhqgkLpx2sV7YdtnQj1SF/xinJT/Z4lxRuRt1p3EbnkrMPWQPr7XJhGsqr5kdoHeN9
         HnQyGSGhmkqMJwVs98nd11sN+JzHi9Yg2zR9kUeu2jreYcBkOBG5p1sUuSuWI0X62Hby
         NFpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BwEBhCCnSHroWYUXVWwpMqqouXdp5LcyUnDeRZoyxBg=;
        b=AIbTrTpGR/BaO6OjK8a5tExgIZbgyI4JX7sPfpjBu3j31knPrA4G930H279ljR/VSy
         +Xp72BNIgBfAViL4UO3OalnQyjdSoMrmvWPksKP7PU9uEwdvxrmsR/yzzJV7My4e/9yF
         8zZdRhjDc33Xs8fHdUcUrTU02wCX74Mg998iRRW0VQ9nJ4GNFORGln2Rl8bBiPbrIM0p
         hz5TkRfO9pGgLx02OCHGokmEaEbpoc71+LyV+rw5voRq1+fXw2hqh0sQ9y2sywVh3AjP
         0gjq0T6IhWkJGLK5ZA4AbaN2mBbxYSHTho9YXkjCgDaXMN+IrX3BIGEXUqmM23FkBeUs
         j+Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BwEBhCCnSHroWYUXVWwpMqqouXdp5LcyUnDeRZoyxBg=;
        b=UvS4UBPaEIgmwodSFxJmg/pS1nzGQRWb4ncw/28LrKT9qdKMuA5oCI1+K206P+A7PN
         Rfitcnx8BRGYQT9NVV6T3Id9co2ekX5XZYGIWm81nHDzfn7GZg5HxjGLmzczeUK9LB7k
         /+AlFUdHte4i+eL61U1vPv5CjR202zQqO+kGKVGMvXH7Vf+gjtbUniIYfFxN1oPRd7cf
         gHOXdjORcdl2ra58X336Eltg6lPDC7eAQPeKKlL0hJfcdd7UhWqyf/Oamt/k3kwMvH46
         RUDL2QI7GpJeznfUttw4kPnpF2Ms11nudnpkGkfiXpvYKvV/4jjBT2bLkcpNIW35FPsB
         v6MQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+sr17K1VBuWnRovzxYllFtS8ymlE04BQBxv1XXPNI/+AdJiJI
	pIqqlu2xEW2a47TOqKHLqOU=
X-Google-Smtp-Source: ABdhPJzUR3A45sMF2j9/O7meaeO/7SJ6ZkIqqfW4EfQaMIP3kXXSNMD4xAaEDLeAwWdgsV81A7Aolg==
X-Received: by 2002:a37:7dc2:: with SMTP id y185mr18093819qkc.381.1598525303041;
        Thu, 27 Aug 2020 03:48:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f408:: with SMTP id y8ls782051qkl.6.gmail; Thu, 27 Aug
 2020 03:48:22 -0700 (PDT)
X-Received: by 2002:a37:de17:: with SMTP id h23mr5012693qkj.368.1598525302710;
        Thu, 27 Aug 2020 03:48:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598525302; cv=none;
        d=google.com; s=arc-20160816;
        b=OCTuiNSVdvG31Tb1uKUi8htxrsMYT/8mZiueREAizjV5FZRWY2R7zIAapCy0yDT+U4
         xMjYSEVkwVF58h4DOYOfHJj7+sJbQ7IqMWer5nk/VvuqgybBa8nWXUvIOM8OsqpTjMFo
         e7mf9KJ9e+46BfmU77mAAwcEFs7rybpl1n+mvhHF/XDJYK+zUSayXcMbnisIHZ2R44cX
         9LTVhGd9rK3YGkFEWv01WLZbPfdToh7KG0zl/40cTfE0xIfnBYud9L0tN27k7KjUYk05
         4bsJPz7tpylna5XHpojM8fwLH9SbzIQ2MmXG7LxZdkCdpp0X59Z7EOvQv9wci2XBxK8Y
         BkWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=7DKl6QmcZi2Ii+clyA9atjAs7K+f9JbTgNVMB5138Ms=;
        b=Q7P1ZSorK/z3EF/EVzFRJkCMFKCVTPHf9efo2MOyhh7sMOtE0csQExiL1Sz2Aw/02Q
         1V/32gGUd+O8MYVqHOS70XzMN2ewi5HN/xPcdxADNquFYlDfJJU3HUWlzPFAP/PJTUss
         bukSwGSNMJzFkAsYVb7mhFv+qrNMq0oeR44WJilUQ1uvnIfV2vImAoOtNanA9zAFldrb
         h/aUSgTmCSO9vPVdpZQLmWI4DCyT2iX5I/oxxiGNRCGmwlQbiLwixOFWoGLPK50sPxK0
         lYN91Lk6JOERE2p8EjdWRdBeTbljml0J8HGxL4rwoRdfYW+Tgs1IHF/wqY9D8shQYVEr
         R2EA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d1si108370qtw.2.2020.08.27.03.48.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 03:48:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 445F3207F7;
	Thu, 27 Aug 2020 10:48:19 +0000 (UTC)
Date: Thu, 27 Aug 2020 11:48:16 +0100
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
Subject: Re: [PATCH 32/35] kasan, arm64: print report from tag fault handler
Message-ID: <20200827104816.GI29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <4691d6019ef00c11007787f5190841b47ba576c4.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4691d6019ef00c11007787f5190841b47ba576c4.1597425745.git.andreyknvl@google.com>
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

On Fri, Aug 14, 2020 at 07:27:14PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index c62c8ba85c0e..cf00b3942564 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -14,6 +14,7 @@
>  #include <linux/mm.h>
>  #include <linux/hardirq.h>
>  #include <linux/init.h>
> +#include <linux/kasan.h>
>  #include <linux/kprobes.h>
>  #include <linux/uaccess.h>
>  #include <linux/page-flags.h>
> @@ -314,11 +315,19 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
>  {
>  	bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
>  
> +#ifdef CONFIG_KASAN_HW_TAGS
> +	/*
> +	 * SAS bits aren't set for all faults reported in EL1, so we can't
> +	 * find out access size.
> +	 */
> +	kasan_report(addr, 0, is_write, regs->pc);
> +#else
>  	pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
>  	pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
>  	pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
>  			mte_get_ptr_tag(addr),
>  			mte_get_mem_tag((void *)addr));
> +#endif
>  }

More dead code. So what's the point of keeping the pr_alert() introduced
earlier? CONFIG_KASAN_HW_TAGS is always on for in-kernel MTE. If MTE is
disabled, this function isn't called anyway.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827104816.GI29264%40gaia.
