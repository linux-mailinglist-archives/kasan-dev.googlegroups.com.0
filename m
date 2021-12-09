Return-Path: <kasan-dev+bncBCV5TUXXRUIBBBNUY6GQMGQEPUG4TJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A21C246E693
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 11:27:18 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id o4-20020adfca04000000b0018f07ad171asf1240372wrh.20
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 02:27:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639045638; cv=pass;
        d=google.com; s=arc-20160816;
        b=b/6p7m+ZkzwfVpMB1EKQSZIatGpsPjmKFa3zZEoqPoom4R9WgHppjJEQbEgDnfc5mf
         gs4+YxURvi2LHzEVZ2J3Aj7gvteYugGasHBTuUVMhPJEvJZi+SP1rO9uqCLizpTWQ7f5
         kX2YItqSeVE+KRok68cExw0JA6gVOdeysdknlMC3+F2UaFM0FDvqJg8mZsr3dGANWQAy
         z+zqcoAdVgMMyi6IXiT6fua6noQDQyFSTPJawKSKrLgO8+T8BMQ66P09yKT3tRHEJGCo
         VHmoighQsq1xWDFyXXHZWQcHihM/IZuFXchEmrXFOYywRDOGoj1Kcn6JYBU4zdZiM5wD
         hV8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7MkV5n+uXvQxIegojUt+lThhxxHineWl+4JPxOjMJiw=;
        b=YHvXES81fswgI96sSEZEV3MPznPmZI0chDnw96GLBACPArw5XH3mPF+703MZqScE5Q
         TqxDxhUx7YtY4pHgkBARyKDAgaYFNZZ4FHmPAb9qP/RC878ZVLi3g6F6qtVpppiL+tg2
         d1rWlqo+7Ubf8pES16p59FyIGXqpIZPGRUvS+cCM10166SQ4hNh+eKGQtZJ9dJ+OU2x3
         FTrMXLKQ9kPDsiW3EeJwA7ZnvrDIK/L6fvLjBxjXLOmC+ppGc/ImzqCjlVpP3bvU5s5p
         3bAPtt6pC/mJLP4zZMbyE33ERWLDSJoazMNb67Vjf0+flICW7a+/TfMTPVGlbwPBR55G
         3pVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=RLbwXjyW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7MkV5n+uXvQxIegojUt+lThhxxHineWl+4JPxOjMJiw=;
        b=OMRdW/eZHKHX2/evXOqb9RBseFElIbdechQJShHHH15t+eave6D07V3Bp1zn3XQYSS
         +kBMGP9dcLil/yiP/nk4DH7w/QghfQ22GLOGi+SbUQ7zkj5ndqCqyb68RevZRJXQR1cs
         1pQx3awTZCepK5BYIJire9DOCw3ySCTZLNBDNyKYZLqPTDcIhKpSWqq2YcXO3yk5b/+K
         HzaCvgFx2vxlwFIQlML136OF5GpB4UTTfML66YCriQ7hKAZG+Te1GudJLJQFaHX9GhKW
         mSckvB3g59yUcWoSb/BbloXQQSOlwf2tw44iIZV5LrAbGCqeBAKfxFeoM6CZ6+Rm/6Ea
         zMMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7MkV5n+uXvQxIegojUt+lThhxxHineWl+4JPxOjMJiw=;
        b=UmrRFgyMVugw4ClZtmYnyknIxAYwd9oHlk84h4TwE6mHkaCoG3dIJSxN/wiYhLNX9B
         /b6Pd8nvfpN09sEvvz1qSbu0sewM/3NGsRAgvxFIrEGPuvMHSntYT70qKuVRaK6tqNTm
         0GHk+POooxaFQNfwGiNCdcIPn7RzZxiYKddnMquhTs3LbnYNcRfqLLUTNNco1AImcreU
         m0nW7mA+cmuPrsO8DDEj+9TjvF7dXdbROGbVvAzSPfhsHxcXCJiIfN97FHlHd6n2w4Ar
         /ohpKptYzI+wJ3SBCcwf6idM9x/h1kt+dLsdFJKSmeqvv2AF7IstKa7ET+gmEoJKUT70
         F4FQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530hKbJxj7MkKsIzq8rucBfx1EQRa7RnpfMbcK83arJERJuE/Ptf
	V+CD5YHmsx0EhNs+DM3nTLw=
X-Google-Smtp-Source: ABdhPJyLt3dN71PaDFItCZ+RVzR1oicwvz0v7/jH9ARINNopFSB3zxm9YTJXjQBGjDxd8GXtAQQo0A==
X-Received: by 2002:a7b:c1cb:: with SMTP id a11mr6123703wmj.30.1639045638132;
        Thu, 09 Dec 2021 02:27:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80c3:: with SMTP id b186ls2152676wmd.2.gmail; Thu, 09
 Dec 2021 02:27:17 -0800 (PST)
X-Received: by 2002:a05:600c:210a:: with SMTP id u10mr5853711wml.33.1639045637277;
        Thu, 09 Dec 2021 02:27:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639045637; cv=none;
        d=google.com; s=arc-20160816;
        b=Oqy7I2M6CvW5UTnAakECnH15sMmPzOY2TCnng9K6YOdNzcWTS0fUxTiIltg9nyMHFW
         o/i9zwLBQyPTKQlbzI0hZ/DVNetvcZrYYijzLZ84nYcJdIU2cCo3Jowrz4If0bdutpBA
         A2Az0zn5i5Q9yEFVQBcqO3OZDOOBbVRT5UrRTD9DeDQwSLmRpxtP9uOpdQl6BZpsHcgK
         Ifi+lfGm+3BKb1ZpUvdm61wob9qopSN4IpC3QssZTWKKt+iWHgerORb2XT13bVB+9hcv
         Ka3IrJUtsx66ZQUUYUWxltjKaO2RiOQsWqXO3KC4eD90C1LuGW4RMiq6FhLPFLQ6e0Gy
         K5Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5RLLZ0ThJGB1WBGnDY4uNAU4BDJtEfGj6LzMMLZxmrc=;
        b=uZdAVz2o5QRWnnH9k02XgOlvqaO6TeS5y72PnlSldLnnNbShJB8HVGfnnFqYpLjNB2
         ExamWFgkPHZV1wjEeQl/bdchErCpZxMdpA1W2M9e1JsltsPWA9AKtGl8YWaUWyJ7yBoX
         u3sLuWX5hqXnhgo8M5wxRE+Gr0peIR7mJYa1QZ4ABCeEHi3J1TIHBQnrkvHc0ppY0VRA
         6FfUY6Y+zlNuDNNgQz/RrtABZF1jtk9LIYHkkbkalzQSpXPXvE3WpnFp4m+5IQpvTFJ7
         gKisHttFg7ICM3/LO1Uy5qRiflmzjYwkGRjf7GdicBt0FJskvx/Qiouxgsjpx9U0h8NK
         YGWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=RLbwXjyW;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id c2si1233816wmq.2.2021.12.09.02.27.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Dec 2021 02:27:17 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mvGdt-009FuS-FX; Thu, 09 Dec 2021 10:27:14 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 480B73002DB;
	Thu,  9 Dec 2021 11:27:13 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 30E652BB8EE66; Thu,  9 Dec 2021 11:27:13 +0100 (CET)
Date: Thu, 9 Dec 2021 11:27:13 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Elena Reshetova <elena.reshetova@intel.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Jann Horn <jannh@google.com>, Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Subject: Re: randomize_kstack: To init or not to init?
Message-ID: <YbHaASWR07kPfabg@hirez.programming.kicks-ass.net>
References: <YbHTKUjEejZCLyhX@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YbHTKUjEejZCLyhX@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=RLbwXjyW;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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
> 
> There are several options:
> 
> 	A. Make memset (and probably all other mem-transfer functions)
> 	   noinstr compatible, if that is even possible. This only solves
> 	   problem #2.

While we can shut up objtool real easy, the bigger problem is that
noinstr also excludes things like kprobes and breakpoints and other such
goodness from being placed in the text.

> 	B. A workaround could be using a VLA with
> 	   __attribute__((uninitialized)), but requires some restructuring
> 	   to make sure the VLA remains in scope and other trickery to
> 	   convince the compiler to not give up that stack space.
> 
> 	C. Introduce a new __builtin_alloca_uninitialized().
> 
> I think #C would be the most robust solution, but means this would
> remain as-is for a while.
> 
> Preferences?

I'm with you on C.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbHaASWR07kPfabg%40hirez.programming.kicks-ass.net.
