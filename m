Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBYUCX73AKGQEARXXX6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id F373D1E62BC
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 15:49:23 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id h26sf1388988otl.17
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 06:49:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590673762; cv=pass;
        d=google.com; s=arc-20160816;
        b=nQMt6hAxAsvvvr94WK2iCX7mDTj9bdhLdmdWykeA6psiM0ALMcZlDcmp69+fWi0XpW
         GzhkaIQyxL0HI96QYA2iD569uRy/2eERcRoe9jSh2n7YZPmVQ3CtY49Qrk5WOU0uq6CR
         zWPjhwlYCfGs4RC6i1DVDau3TbGbeiNvsnmpb4YoZMORqbDkkgyHZeutxRLiyYGVMpI6
         wD3F4cA0whvrhyKvKFF2nidXbWP1mzquA2CyO1x00rekBZ1QntCh6W8rtBDJpn+MJuDB
         EcNtOa734A0moQeVC/zHhtJlK2CmAKRsQn5Ny7FA3NRzPKekfdbAZoZEFaUZvWCfDt1J
         ZY2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TjfbRFsQcEpKlUVEp9uMqw1NacmhP2GGqs4t+VLBRMk=;
        b=kmnLUkk53qK6iUqzbjjiFH4VL/aGpRSRgAmaVCfHhzXSDbARHLtfb/XhYFJVuAdK+V
         xaYjbzzPtX7u0cKni+OpmB1PtOtUm63G2CacduhLx1x6E00U5+PEiiZttr9jxnTYWw0E
         /6ZltnnR108lKuCFQ1GFDaL9mmEFw47aaK1HC7upF+Ljfl/LysnhsF1iiyVPekb4Xj4i
         OQCcqpr/F3NOfjSj5GZEokgKWyMl7M/RJXRH83UzoF5Q/6veAEwmiZONpDnrW+DPzeWi
         3XH4Mdw0d16UZOI3pSmBy+6zxWivCUv+oF0BFKhA9hJc72NBWuRdZAthiIhRI1u2+Sc7
         vwpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=iyjGew0l;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TjfbRFsQcEpKlUVEp9uMqw1NacmhP2GGqs4t+VLBRMk=;
        b=B3N6TLgAGvJT53iTgX6bYvlqnGSI3Od/y2SeVC/GRjaanVvXg5oH7UIJXBeGZRchzJ
         BnNrXJQMsXEHbHcIujFbpuIdyFWLPCKbWAgbF6qkeOEdy3h4+pxlpxkroqckmOMKIq0U
         cOcrZFzWRT8TBoPGj1/2clJRQWYCXJTgnaPtj+KiNO2EN2uwW7EZ/1C0NiP/TV8VTbtK
         cutfnTvgWSyVrfNAQHjQ+q3S1uneueT1Vge6UFJA7p5+maBwApOvm64yjxW0pqDa5tFV
         LKmy4KPiE1V5lqVsFzgZFUa9wHJjxWLmRdEEMoOCvciZSDuAp6lWhlmdWH2CaNjiqOil
         xW2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TjfbRFsQcEpKlUVEp9uMqw1NacmhP2GGqs4t+VLBRMk=;
        b=cBPYfxRKT3mNeb0TMrSN09ynsPekll2qpODg+wzqc0Ia/rypGCgr57Gg5sdrf0FDJ2
         5osmtGv4iiP8KYsvHh9AgBRL4T9x7o7BsQXn5nclVKFvkpWgCQ1c95imeXgTLg+QGzek
         qNk6/6BMlVd2kJJENaC/pO2W4hftvWo7qMc+rkKczcWx8aH3pK2o+s6FEyCp8vky4D0V
         6RizivOgpMoSZTdfotlj604uDbQJBC3vkhV6IVxN9OO1s4Nm1KMPlLRev5LZ4mX61dUf
         aj2uXCLPZSPtBqwn++zdB43ZYxNYVX8/BMeOYJazg86dEyOrB52cE93geZ5rWB6mU7Tc
         OQpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zdXVVW9TT2hSbP/tb2G2/aW8L/4h55Ygzvn1/epCNCbDzbEyx
	nr20F7EHQ5K5+CRgFWw/CW8=
X-Google-Smtp-Source: ABdhPJzFemxHeLYhKYFCWPjBC9TRpi23mwC1bde/Jlss1RZUlJ/i5FZZH04FPaCLFCz8Nqvi/VYaGA==
X-Received: by 2002:a05:6830:20cc:: with SMTP id z12mr1638985otq.252.1590673762711;
        Thu, 28 May 2020 06:49:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:460f:: with SMTP id p15ls467842oip.7.gmail; Thu, 28 May
 2020 06:49:22 -0700 (PDT)
X-Received: by 2002:aca:c046:: with SMTP id q67mr2177359oif.53.1590673762386;
        Thu, 28 May 2020 06:49:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590673762; cv=none;
        d=google.com; s=arc-20160816;
        b=h8sBf1DrgGJCBc5Hq2DHQWE00FngKV+JrRR/qZGF84Sx2fS/FJTOT5kkk2ZGxPQvPI
         G3oI0B+IMPANgfZetyQnVxQpMdTmycsqT+5FBcQy4HQKzDC/TLt27BdJ09lfzSGcuB4N
         HWEctDGkAV94PmDqZcGI2gdmKoVNlmDoeLdky3c6a79EiaORC1YyDI/EJsSaxfRq0JBi
         gpUmzBXTzEAlv0hbdz1oZa0ZGyYfGp5AT6SE6bVhjvqxeyDyIIqHOHfadJBR+bvHqVg/
         8vkwDi7TVIue9Ti4dhLEauW+2yhigI0/E9U8u30Gr7LGqWEUSPZq1e2pa6vuhOf9/PQP
         2jIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=miWLmImDnuJKbH2UD6fJ0qtMBZgQrphKm0mtgZhQM7U=;
        b=kfXj0zb8iR29ZEfGaosUYaixR4IiTBfX0gkjJH61ZTsPK2BUErCd2Q6+eYw/Woq7vV
         9ZDi2akPCA6HVN2PsPxiUeyPQnaVJYM172X9OREI7uujQLx58OmkhRCgG/oGyJwj8J6r
         d/bxomLDO72Po2uamI0OICmBO1s17axmC9JbuvLP+at59tFXPyuI97VjccqVStlwutMV
         Qd74gK7x/X7T7INiJ4Uw1mJlDtwy7V3JB/P4O1VPKB0RTdKjbgTOCCeTe3eDfetlycAF
         FvY/PuAZR2jZ7nS/496YKOdAxSvXtrg4tqq0zDkXx7LjXrUajkg5Yzm4GQ8XMA5XZ3Ok
         THhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=iyjGew0l;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id q5si495664oic.5.2020.05.28.06.49.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 06:49:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id c12so3032564qkk.13
        for <kasan-dev@googlegroups.com>; Thu, 28 May 2020 06:49:22 -0700 (PDT)
X-Received: by 2002:a37:e205:: with SMTP id g5mr2875689qki.451.1590673761660;
        Thu, 28 May 2020 06:49:21 -0700 (PDT)
Received: from lca.pw (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id v53sm4006742qtv.10.2020.05.28.06.49.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 May 2020 06:49:21 -0700 (PDT)
Date: Thu, 28 May 2020 09:49:13 -0400
From: Qian Cai <cai@lca.pw>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	Leon Romanovsky <leonro@mellanox.com>,
	Leon Romanovsky <leon@kernel.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH 2/3] kasan: move kasan_report() into report.c
Message-ID: <20200528134913.GA1810@lca.pw>
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
 <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl@google.com>
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=iyjGew0l;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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

On Tue, May 12, 2020 at 05:33:20PM +0200, 'Andrey Konovalov' via kasan-dev wrote:
> The kasan_report() functions belongs to report.c, as it's a common
> functions that does error reporting.
> 
> Reported-by: Leon Romanovsky <leon@kernel.org>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Today's linux-next produced this with Clang 11.

mm/kasan/report.o: warning: objtool: kasan_report()+0x8a: call to __stack_chk_fail() with UACCESS enabled

kasan_report at mm/kasan/report.c:536

> ---
>  mm/kasan/common.c | 19 -------------------
>  mm/kasan/report.c | 22 ++++++++++++++++++++--
>  2 files changed, 20 insertions(+), 21 deletions(-)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2906358e42f0..757d4074fe28 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -33,7 +33,6 @@
>  #include <linux/types.h>
>  #include <linux/vmalloc.h>
>  #include <linux/bug.h>
> -#include <linux/uaccess.h>
>  
>  #include <asm/cacheflush.h>
>  #include <asm/tlbflush.h>
> @@ -613,24 +612,6 @@ void kasan_free_shadow(const struct vm_struct *vm)
>  }
>  #endif
>  
> -extern void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip);
> -extern bool report_enabled(void);
> -
> -bool kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
> -{
> -	unsigned long flags = user_access_save();
> -	bool ret = false;
> -
> -	if (likely(report_enabled())) {
> -		__kasan_report(addr, size, is_write, ip);
> -		ret = true;
> -	}
> -
> -	user_access_restore(flags);
> -
> -	return ret;
> -}
> -
>  #ifdef CONFIG_MEMORY_HOTPLUG
>  static bool shadow_mapped(unsigned long addr)
>  {
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 80f23c9da6b0..51ec45407a0b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -29,6 +29,7 @@
>  #include <linux/kasan.h>
>  #include <linux/module.h>
>  #include <linux/sched/task_stack.h>
> +#include <linux/uaccess.h>
>  
>  #include <asm/sections.h>
>  
> @@ -454,7 +455,7 @@ static void print_shadow_for_address(const void *addr)
>  	}
>  }
>  
> -bool report_enabled(void)
> +static bool report_enabled(void)
>  {
>  	if (current->kasan_depth)
>  		return false;
> @@ -479,7 +480,8 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>  	end_report(&flags);
>  }
>  
> -void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned long ip)
> +static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> +				unsigned long ip)
>  {
>  	struct kasan_access_info info;
>  	void *tagged_addr;
> @@ -518,6 +520,22 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
>  	end_report(&flags);
>  }
>  
> +bool kasan_report(unsigned long addr, size_t size, bool is_write,
> +			unsigned long ip)
> +{
> +	unsigned long flags = user_access_save();
> +	bool ret = false;
> +
> +	if (likely(report_enabled())) {
> +		__kasan_report(addr, size, is_write, ip);
> +		ret = true;
> +	}
> +
> +	user_access_restore(flags);
> +
> +	return ret;
> +}
> +
>  #ifdef CONFIG_KASAN_INLINE
>  /*
>   * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
> -- 
> 2.26.2.645.ge9eca65c58-goog
> 
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/78a81fde6eeda9db72a7fd55fbc33173a515e4b1.1589297433.git.andreyknvl%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200528134913.GA1810%40lca.pw.
