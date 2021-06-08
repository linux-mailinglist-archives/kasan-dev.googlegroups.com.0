Return-Path: <kasan-dev+bncBCV5TUXXRUIBBIO472CQMGQEAEZN46Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C53D839FE31
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jun 2021 19:51:33 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 128-20020a1c04860000b0290196f3c0a927sf1541417wme.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jun 2021 10:51:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623174691; cv=pass;
        d=google.com; s=arc-20160816;
        b=qCoJ/ilvyu6NtU/Z1a74bO2hUPr9+Kcv3q1HY5oFkA0AAUi0RYf4qHeTHRXQGRBV3E
         2jgA39g0pJFMUZNx1qiSYavzdZHvJ13vuRd7rigjI895thcjCDYA1RdUztvO0rGPMPTU
         kITJ4h0QjLCZR/dNXrl/jP8r2ZhsUI04BMLL0cxTiPsoM/zSg1n0f23vsk26rh4B0k+r
         XgPE2LNqwWqzfwLF0vVRc/S0ByksZ86wnC7wY5IncYjD+lj/Kyy7dOqAkYfr21lZOWKJ
         Gyf37yTVIX0iPaEkKFw6AW+gjeISU2xMIA+3UOdGViRn01rixmOKUxdbBIAINUfX0BM0
         xypA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=6Q8X56raG4KUr8YkUeV/cwAoCA5pG6V5E9TiLvQc2B4=;
        b=b/KRnzB/Os4OZbEvpalQCLQmiUii7lZK+/tREflj4zoVeeE0MYO6r5V4mcDYDjluuV
         wNYFrYetSTXC9nQMdFK7qIpwwFzBp20NqGOsb0i/AO4V8GxG6PE5KZAhz10GXmP0Btl8
         hmIXNcF+W2+gpRfsessTbKhIhE1V/3GWu20k9Q4Jm3QXgDUBXqmexYYRF4cVWz+ZLt//
         oaeIJvh7rzfbswSXN8NWybQDNXu+8L2sDioNElrrT7KdDT9j0FXGsUmTPBD9LQek8XEH
         MP9LiNvsTToP3MSO9XFECj0HmtcjvBYlT2MrKZXJHzTEboxkikuoCp0Xr/czsBeyyGaN
         4K6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=wPbpuXpg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6Q8X56raG4KUr8YkUeV/cwAoCA5pG6V5E9TiLvQc2B4=;
        b=DQtZM8R6Bto9xgBVg61pnKy+Yt7A50cI5QGuZc1TNrhXhMFMWEy+VmCQXw2N9TLOkK
         gUKzDVOA8aaxY7Nmzb9cpGW9+MpVKRVHuBUT0m9UwUscfXzWE8hI3Yyd0rI/w2FEoTMR
         sE8iuiUO3tmZlPGkgdSOGsgKxpWIqzNZ4dbXZLLCJiiPgO/PYA75mf/nUqIO9yMgznEV
         TG04m0cMTLGSer3aabF36/HZeouYny9ZgkoAlxBzLYeyuqlJr2e98fqqTxCQPkD58aoN
         8/Gn+Zxr9xxP6wFkrndJ34RlMvVzx4GEXH9ljlW0cKwBK7IR5r/bl/ls80f8PqzkFJC9
         I0ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6Q8X56raG4KUr8YkUeV/cwAoCA5pG6V5E9TiLvQc2B4=;
        b=DsOf4ffzPEya5Wq8hWb2LrZgp5tiywe8oQ2IBvOr93GuFqpiwpy1SYSBRepyR/qEeh
         /AGiv5vylDmHmvFh0YgSzyzxjk1CNDjvOUTXRcSJ2qflei63bmUPuHtyiEGlSu+CIShO
         rdja3935Y7ukyMlJvFZ2c6JI3N2jJ0awGMOUM8Rweu24LhStFrmZACKTqmgtK80zS5Ai
         79hCouWpyuz1Q8CJ0UUmCcj4EGYwn+lJQB0hLLV68vkL6J+HKHOkWjQy9A1taUA1muy8
         emzLShJkRKlo1J94e4Zf7TfA2k4GXU5bR24I9jgIhyAMq8VJygjyKDGFg/HcBNq/YOSE
         e6Lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ahxYoChJBC6Igfheo9vx4K66Y9oqDdKL2AvU+Mgwt56kb+AnQ
	WibCUByUCfmbvOlgPC4qMAo=
X-Google-Smtp-Source: ABdhPJzvR/XSNImYPFq5TmDIlEj1naT46ihzBY7X8bn54JIFy64ZP2PIwTl8PU/lcJjkEB7Ka+Bg3w==
X-Received: by 2002:a7b:c2a2:: with SMTP id c2mr21399328wmk.89.1623174689514;
        Tue, 08 Jun 2021 10:51:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eac1:: with SMTP id o1ls7112139wrn.2.gmail; Tue, 08 Jun
 2021 10:51:28 -0700 (PDT)
X-Received: by 2002:adf:fed0:: with SMTP id q16mr23488365wrs.426.1623174688678;
        Tue, 08 Jun 2021 10:51:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623174688; cv=none;
        d=google.com; s=arc-20160816;
        b=M/VM+eiN0SeGIM1Jfw3h4TLcQc9AV/CFo5TAsVqNV5X/uzFAlVHSjNlq0pdCkDvnS5
         JjQw8On1pMwnVJYvOwQnbUAZlzwgYEXbfhKpP/buHMq2CI1mC0jSYCPw+wGC/9On7LKl
         ndRi4ooMZUSExJ/u8nQa6QOnqCsGQN5xe9aMlUMk4QQXUivTMr/C1lIh8a3fIwtFns/s
         ee2ZTD8S8ZvE7d7YYOJg8OduNDaZJLWJ0ycyJzdTKjGf1QrcKXfV7BhRnO2B2XCEVBUd
         zg0SqSBEMW6spBWh/Ay/STAWQLfDz+KSa2+B2cpMsFloMvZRvEYR+JSYEsT937D20SEt
         nW3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=b3WsjQdgR3MSJTjU3lrqrbMQ+LQT0nybe5G1JEwCYNk=;
        b=DF93GkyVHW5RNs/EUpbm84zfRsaO5mxxcZQH7DZlpchCig/joBOF59rqAL1Y/GGLaj
         y26xjxieqF6JLCFJGwuvKpwjowiK6HSPIETy2MjMWKFYUA7CAKA7YAtaenQI0/Fsrj4j
         1vBajzcxPja0m/NUsQ9LqeK1ObO4d6uUo1/fhh5HSSUWveMb6+QDOEXZUlmkPuS6jT0s
         lSjpZuH7X9egdAxwqAO1LSpLOIaeRkFFJzDXk4BHZKSCbnyG3lnWri4/7U+8v1LuU13R
         qS+8NTqLZAF+89mOK4lxVDL1ql18rhBPGrlEpyKk3q4WhACfUZ+sd0edLgbO5SwN0JlT
         z73g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=wPbpuXpg;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id v4si390837wrg.2.2021.06.08.10.51.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Jun 2021 10:51:28 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94 #2 (Red Hat Linux))
	id 1lqfsV-00HEEL-Jg; Tue, 08 Jun 2021 17:51:13 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id B24A73001E3;
	Tue,  8 Jun 2021 19:51:02 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 9B9E42D1D1298; Tue,  8 Jun 2021 19:51:02 +0200 (CEST)
Date: Tue, 8 Jun 2021 19:51:02 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: qiang.zhang@windriver.com
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
	matthias.bgg@gmail.com, andreyknvl@google.com,
	akpm@linux-foundation.org, oleg@redhat.com,
	walter-zh.wu@mediatek.com, frederic@kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] irq_work: record irq_work_queue() call stack
Message-ID: <YL+uBq8LzXXZsYVf@hirez.programming.kicks-ass.net>
References: <20210331063202.28770-1-qiang.zhang@windriver.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210331063202.28770-1-qiang.zhang@windriver.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=wPbpuXpg;
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

On Wed, Mar 31, 2021 at 02:32:02PM +0800, qiang.zhang@windriver.com wrote:

> @@ -70,6 +70,9 @@ bool irq_work_queue(struct irq_work *work)
>  	if (!irq_work_claim(work))
>  		return false;
>  
> +	/*record irq_work call stack in order to print it in KASAN reports*/
> +	kasan_record_aux_stack(work);
> +
>  	/* Queue the entry and raise the IPI if needed. */
>  	preempt_disable();
>  	__irq_work_queue_local(work);

Thanks for the Cc :/ Also NAK.

I shall go revert this instantly. KASAN is not NMI safe, while
irq_work_queue() is very carefully crafted to be exactly that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YL%2BuBq8LzXXZsYVf%40hirez.programming.kicks-ass.net.
