Return-Path: <kasan-dev+bncBCF5XGNWYQBRBVPDZGGQMGQEVVFL3QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 2617D46F5C7
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 22:15:03 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id t22-20020ab02696000000b002e970ec14a3sf4850547uao.19
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 13:15:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639084502; cv=pass;
        d=google.com; s=arc-20160816;
        b=NTe4NvTsf2EVmN9iuiiKG7m0pcTThGUJbk/9OYH89YaEXX/OM3RVpaWat5DRxXppgm
         Jr8eCKn7IRg0yEOelnEhAxrFhRdExKn/hkvQTtPFRNezTIx80yzpJN61G6dV/DE/ktAV
         hFBX+5XDfxnDZSLSCRTjnXVlTTtlM8ezPYskmSkmWN9x+4RQzL9/2B+RV0AefiKrRzkQ
         j7Jp31Fl/ddkyFFc2ztQ+ml06WDx2k+dhIL3iyALVQLofynEJ3FOAbz7IJ8iYFml5eYC
         Y374TktL3uOytUW/gB8eo/CVMezFBf55d+p//jMUR5VhOw8WvN/FDeIOUa7nyANyOXDY
         4GcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VWyHYipDRs0f6dIzJsdT2wdfr4/yNNapx6U5kQxeNKU=;
        b=OY+tRmwqbc/UMyVgdicKBGtJ2peYxZ9P+C7HJDQkYlSfUMjH9ja7OMcy6ylu/dUNMI
         2mylk5zOd8+gnhGPAtzGtRVFYSsmXoNsgPlnlk63eEF0KmgJGeAfGF6dW1rhJgOuO1mF
         s7MgXMkA7sLDpEOA3iVKme3b27lIMig8Tfgkvd1BYtoaKRoEqNS99yvtpEiwnsmYdvTU
         nHIIj3H99o1MUnjG3b1KdEG6CIb20qg1xITH5rTKOzUUX7ocatXBxty0icJjpWcjrrs4
         zY2T0B8x6a3k3Yltl6roQCg5TkO86nLQTerWiN7uEZwtxUAUv6nDPVQ/vf1Y8viBp+hY
         gwhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="IvRNfl/y";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VWyHYipDRs0f6dIzJsdT2wdfr4/yNNapx6U5kQxeNKU=;
        b=F8lIgcPQNpvdOfSZUuhk0HY/Xeu+IU8xUpJcakPnEt156FQ6Q8ZneoXKSMCvAV+ouW
         pVi3zUn77PmkYnWb99DQ5gwi1VQ1amFmLNJeHbRy8egN8oU1mCeD+V734qntu+bPEmM5
         L7bhf3XIrFG500W/nQBO6ZdtqiuzPSaRtO7YYxomolcEKouzvEHx8p2GOKjJP3OfxrQz
         M4vqwWYucq8s159MxKwHi+3UEW8oRKqCyguQIv5i8FY+XirpKryhel5YifJ38ucmNZjF
         NIijjY1RW3/JbXpeczMZY3yrz6D/lOvK8pnKZJHDkD1GfQnReYtXbIv6KNWh+RkSLllv
         T7hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VWyHYipDRs0f6dIzJsdT2wdfr4/yNNapx6U5kQxeNKU=;
        b=K8dG3cI1PFMPjjctxcNGdPomk7hxpR4yxWuTDnZeJKplwOMxRUN1UTYGuu8g+j7MLb
         ahdtp0UQkJVxqrIqpn2Bs/mZOLPOOUuG6ixyZsDjcOu2fGRI/UnvbmaBT95Q7tvPggjO
         AGx51DNDzeC1d6JMSk1TwGWRzpOKMr647UOf+GcfrMaaMiwamWP+mm30Z3A6JgFHEzAM
         AZcMA+SojHG7kNQaC56MEDHKtTW4gqDqPW+ffHQPYurX1wksoh0Oc+mpbgaaWczwGnQs
         6op6oAvINL/yr4X/LqdEZoAUeUg6G6AfJp4B2w1pGQbyxAfL1CxbJjeq13QG1qfRxhi5
         lr5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dq4poQn5TOLylQrTppxH3pf8re2BD5IPZ3cn4R7dkxjz2IbWK
	4l/hiR226RB57Zn4aAtyPvQ=
X-Google-Smtp-Source: ABdhPJzOyrwwu/5DpZgJWMonQ+Er6B2kJ5YAFQdoVudbCpm71A8ZHvMeA6tI11WSQdeDC+7pH1T/Uw==
X-Received: by 2002:a05:6122:7d4:: with SMTP id l20mr13310391vkr.26.1639084501904;
        Thu, 09 Dec 2021 13:15:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3d9a:: with SMTP id l26ls1164019uac.8.gmail; Thu, 09 Dec
 2021 13:15:01 -0800 (PST)
X-Received: by 2002:ab0:77ca:: with SMTP id y10mr9778594uar.49.1639084501413;
        Thu, 09 Dec 2021 13:15:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639084501; cv=none;
        d=google.com; s=arc-20160816;
        b=XfKE4CsRQ5JzZqQTo7fyb+y3IvmFsuvaAn4HQdOV9xPz8Yoj/L4Q+aUKWAj8zkvBgZ
         qAs63xbcPZC1dA74lyr/jxR57GD3e+o8UFVYQ306PPrAaFHwD7LLZCPsXzpcX3Hv4R08
         v0pQlo0W5VREpgObO83wNftwLtjKX5XOdTnfzLlsAnjrugOfoL/AUuDKWDLau4b52Dvb
         /TQMCjfT7W0CWe5TKo9UcJ6nIiqu9TUXEmLTWlW9yQ/AgIXnd5evtmf74Z68nUQ1W1yM
         98yRvK233vYkXTdETkBuC3+0urjuuzJs8gwx+qJ60rmiM2N2MGSIEtSgj2MMo1HgGvAJ
         XWjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=idhxYsGIqFY0iC2foXmRO1Y7kKO1WrOHXiDZA3WqNNo=;
        b=e44GASBY7k9UbucgcCpouQeT9sCKTaJECvajY8EHsLbQsZCn58Q2vW/rXTWZF88W4e
         2hYNah3lUlsoDjyZ89pghVlZh/xQzDAKAtI1EkzjOyJO9bBHQlYTnU94t+K+6TwTgM6k
         GcuGNYBKDbl+RyBl5l/eOo2RhbAMn5G6iuSusM02yX5m1ukekY0ZOQLEoBDy91fuQpl8
         Yoo/XWfRcZwzwiMxgB9WCuHSdbx22uIjCqQbMHvp7M0S/L95OYoXuk4iDxvqetxq/Lf3
         SfBUXDLavbMwWdud3tD7NLekPnmru06qK6cOEKcY6w5KRDEt7Tlm7BZ8s5LwiilK/rBp
         VZXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="IvRNfl/y";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id g8si147809vsk.0.2021.12.09.13.15.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 13:15:01 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id p13so6591563pfw.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 13:15:01 -0800 (PST)
X-Received: by 2002:a05:6a00:811:b0:4af:d1c9:fa3f with SMTP id m17-20020a056a00081100b004afd1c9fa3fmr14185879pfk.21.1639084500512;
        Thu, 09 Dec 2021 13:15:00 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id q10sm8940664pjd.0.2021.12.09.13.15.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Dec 2021 13:15:00 -0800 (PST)
Date: Thu, 9 Dec 2021 13:14:59 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Alexander Potapenko <glider@google.com>,
	Jann Horn <jannh@google.com>, Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Subject: Re: randomize_kstack: To init or not to init?
Message-ID: <202112091308.600DA7FE63@keescook>
References: <YbHTKUjEejZCLyhX@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YbHTKUjEejZCLyhX@elver.google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="IvRNfl/y";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
> Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> default since dcb7c0b9461c2, which is why this came on my radar. And
> Clang also performs auto-init of allocas when auto-init is on
> (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
> allocas.
> 
> add_random_kstack_offset() uses __builtin_alloca() to add a stack
> offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> enabled, add_random_kstack_offset() will auto-init that unused portion
> of the stack used to add an offset.
> 
> There are several problems with this:
> 
> 	1. These offsets can be as large as 1023 bytes. Performing
> 	   memset() on them isn't exactly cheap, and this is done on
> 	   every syscall entry.
> 
> 	2. Architectures adding add_random_kstack_offset() to syscall
> 	   entry implemented in C require them to be 'noinstr' (e.g. see
> 	   x86 and s390). The potential problem here is that a call to
> 	   memset may occur, which is not noinstr.
> 
> A defconfig kernel with Clang 11 and CONFIG_VMLINUX_VALIDATION shows:
> 
>  | vmlinux.o: warning: objtool: do_syscall_64()+0x9d: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: do_int80_syscall_32()+0xab: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: __do_fast_syscall_32()+0xe2: call to memset() leaves .noinstr.text section
>  | vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section
> 
> Switching to INIT_STACK_ALL_NONE resolves the warnings as expected.
> 
> To figure out what the right solution is, the first thing to figure out
> is, do we actually want that offset portion of the stack to be
> auto-init'd?

I actually can't reproduce this with the latest Clang. I see no memset
call with/without INIT_STACK_ALL_ZERO. I do see:

vmlinux.o: warning: objtool: fixup_bad_iret()+0x2f: call to memset() leaves .noinstr.text section

I assume that's from:

	struct bad_iret_stack tmp

But I'll try with Clang 11 and report back...

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202112091308.600DA7FE63%40keescook.
