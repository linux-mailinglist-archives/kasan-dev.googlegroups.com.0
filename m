Return-Path: <kasan-dev+bncBDBK55H2UQKRBIEAWWTAMGQETYTX64A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CC207707A5
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 20:14:57 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-3fe15547164sf15144345e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 11:14:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691172896; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rc4o3WlBf1v7tB3HatL3NeKJ9PqQz5wP3KP14LByO5wAHw7o8bmkAcCB4La9HOXIGn
         VnUo709Bq/vcYaI3xdbKIcZZo6keoZVkMwQ31CGH1msuknmlwLorV83wzdU+aoo5I7qr
         Uvsj/6bxhPyLxYd1l20Q4J+PRFdGXF7D2M+dTUueN46lcXebNCUfnvDHCo/Az56bFzee
         GfusDcFMTkPvymRf9t6XnA8wye7fhjtDu54XSnWoKKATdJxRcnX2PTuZ6jOHIYBWmUd5
         ckalsXFQCwWdh9zyJ48ZCHvxPr3oC7J73EjCpjxMgKmRVUP8PuY+4gz5Y6Yj1gQahQZG
         B0/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wi8Bm69Qwzpxy3f8k1/e0I9EF9x35RzPrz34tJh0Ugs=;
        fh=Q7vk1ybPT/2u5cJmBziECgnGvctkDcGY/fG0TU1C4v4=;
        b=V3/fIqcB2NKiUoLkVA4DoBeWW4GaBX724ZKAYEjJwAoP+aeS4yzxywZfCIGmDaYQ0U
         XPcXEAEKikuUN9GXdcZMbo5zo3yhl7YdzcX48+NttvuqMZuLo38IDA9Rf61oMKYcHtsQ
         F757KRBcU2Eq/pqCBJvtemfMqO5NPAnz+ONqjoeWSt3HFqFudIXFZwAj5UZkl/RpKnBx
         Xs+QW3UNduxCuGmL13EsjfWnteqIwndFkLv004/OdB5QxL01yvAz11wxD+9OKJU6K+zQ
         lILcl/760BD7XLJPlKfQu/jRzsf4468HlvxCJKZyK8SQYgVUkUGoAgrlcCvdONPrtqMB
         78+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=f1vfHE4L;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691172896; x=1691777696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wi8Bm69Qwzpxy3f8k1/e0I9EF9x35RzPrz34tJh0Ugs=;
        b=bobZtlLoqATV9LcWWARjn5r1vbp/upmFbE24kcd84h8yeYrEXEAoPPC4qZfMsAOK1m
         4tKIixQmrl896f/+UE1E78FAd79jIO3GG6aMfA5CTebBXRnK9GbxSbIumEd40RxuxGoV
         MymcVvHiCGr01PLO8dqFmGXq1CAJwJZnrFlqNQaOa2pYiLlFgzdsJyoPlOhVfuH4oeG8
         NJnyUSh0hhKvPSxcsCYfltFbnZvfm9OZjWVVKwEdJMi32EzqjJm+Xh0XBneYVwb1jcZp
         zpwwI6K1J8vbEqq2NzeuuIZ7/jpRG+vkeY+oB2mjgfciZjh3xVDBIRXffB3yELeDcJ6Z
         1rOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691172896; x=1691777696;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wi8Bm69Qwzpxy3f8k1/e0I9EF9x35RzPrz34tJh0Ugs=;
        b=YM6XbmcmFxmpbP7GwA2GhBRncVQ2NNtlj0IfJC0HuT/Lrdge066B0XzBNMwU5rccKa
         iAf4v57tCpUdWy0AmXiqK+Q09uT31K29iDrc8+LpDYEhHzxHaZlrHiBTU+GEm1NG0Pxf
         VpOZt2IQMRureS5KDlJEL4r6U31Y6ESvr9+KRaZwjV3hL77WSUO7cOBUGUNDvAR6QEU7
         APPfH31mH3aLgEiJknYDSkJEbVlvhhgva/JTsusLz0wiNlTGJrUOcpHVJ1vHAXG7lnMv
         qFBN6XSntMuwX8dEdtW5c2eUDNz5mwu21/kh7VDJe54xxhtQSyZJ9qXY3V2WES3TtWej
         MSnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwswnSxCPfCajF8El4sYOhK6zW2zLlMgMhyrQJxSoxjnRKVlazJ
	CK5fo1SFvzhsdknTITJ9X30=
X-Google-Smtp-Source: AGHT+IHwIiakKg4HdgE41RpWEUwIWXVk1QPg1/z/gfhYxMwYpfeotkqd9Sb9favemK3FdFxgRd8/XA==
X-Received: by 2002:a05:600c:b52:b0:3f9:255e:ee3b with SMTP id k18-20020a05600c0b5200b003f9255eee3bmr2070567wmr.30.1691172896242;
        Fri, 04 Aug 2023 11:14:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ba7:b0:3fe:240e:2547 with SMTP id
 n39-20020a05600c3ba700b003fe240e2547ls111665wms.0.-pod-prod-09-eu; Fri, 04
 Aug 2023 11:14:54 -0700 (PDT)
X-Received: by 2002:a7b:c3d6:0:b0:3fd:1cfa:939e with SMTP id t22-20020a7bc3d6000000b003fd1cfa939emr2059770wmj.4.1691172894430;
        Fri, 04 Aug 2023 11:14:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691172894; cv=none;
        d=google.com; s=arc-20160816;
        b=x91dhyzq597/UHR7xbhwQzSKEBIp3X98A5/GUbEtrcoLVuZ+jGr9RnqHnidNWTtteB
         avpHj9HT24eKOFj+f01FjL/B3cm3LI0Rd03tTMFuR7G6+EXhXIiwrH7Q5rWgnHeMluI3
         48lcWC/vXdSiQMuOdsqVk76kKx7WH4DS8UofkpEQFa1RDFSl5aQ3fPpYtd8Gv99mWZRe
         DeP02a8HSNRXApOO2/jJCiP/UsG/1CSx8l3dc0v1a3pm/UJlYqgZvswndXWGxT+yzPvH
         oGYy2icSl9npnWBcL6/NaMoi0K+BCIGiq65cfxfIy82kVsityNJY4NH1COAeFM9pFa2h
         31Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=YnOa/6fvU8ss9SgEPYf5nmoqAHQ4nJbGjVNgPXhtNF8=;
        fh=Q7vk1ybPT/2u5cJmBziECgnGvctkDcGY/fG0TU1C4v4=;
        b=fYVq7j6Yd7NtVfkeBWfwox7UL6IxIm1ZvDG6MpYJPndMfvWooLhMNJqy9Yj0CEcXYf
         iUDi4y7nTB7vWUVVpCSKdWcCjWjlY9+kJ56YABwEhrB/8xG3YEPWX3ctOpxbGYFC+lpt
         mcnakR1FwiRjYMMVFFdl1GlGhAoDcP0+siDNCtHS6mP5ZIYZ8C5sZq8Uy8BtIgZPe7eO
         B0dcPytKxV+shv/stUagvnYW4Kro9qI3rQp6SCIcIm9bTPtt9M3RCdz5LKihA+wIHFsb
         XGP3kvhD7ZcmCJFWai86jSu1hHiyfgJ6yvAxUkCNAQdMtrnAMQjod8ju12k/nvCEbmgZ
         nSVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=f1vfHE4L;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id h9-20020a05600c350900b003fe275df1e1si449655wmq.0.2023.08.04.11.14.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Aug 2023 11:14:54 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1qRzK0-00BK0t-UW; Fri, 04 Aug 2023 18:14:45 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id AE059300235;
	Fri,  4 Aug 2023 20:14:43 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 79E6127436E16; Fri,  4 Aug 2023 20:14:43 +0200 (CEST)
Date: Fri, 4 Aug 2023 20:14:43 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Mark Rutland <mark.rutland@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v2 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
Message-ID: <20230804181443.GJ214207@hirez.programming.kicks-ass.net>
References: <20230804090621.400-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230804090621.400-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=f1vfHE4L;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Fri, Aug 04, 2023 at 11:02:56AM +0200, Marco Elver wrote:
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 547ea1ff806e..12c4540335b7 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -106,6 +106,33 @@ static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
>  #define __cold
>  #endif
>  
> +/*
> + * On x86-64 and arm64 targets, __preserve_most changes the calling convention
> + * of a function to make the code in the caller as unintrusive as possible. This
> + * convention behaves identically to the C calling convention on how arguments
> + * and return values are passed, but uses a different set of caller- and callee-
> + * saved registers.
> + *
> + * The purpose is to alleviates the burden of saving and recovering a large
> + * register set before and after the call in the caller.  This is beneficial for
> + * rarely taken slow paths, such as error-reporting functions that may be called
> + * from hot paths.
> + *
> + * Note: This may conflict with instrumentation inserted on function entry which
> + * does not use __preserve_most or equivalent convention (if in assembly). Since
> + * function tracing assumes the normal C calling convention, where the attribute
> + * is supported, __preserve_most implies notrace.
> + *
> + * Optional: not supported by gcc.
> + *
> + * clang: https://clang.llvm.org/docs/AttributeReference.html#preserve-most
> + */
> +#if __has_attribute(__preserve_most__)
> +# define __preserve_most notrace __attribute__((__preserve_most__))
> +#else
> +# define __preserve_most
> +#endif

This seems to shrink the ARM64 vmlinux just a little and mirrors what we
do on x86 in asm. I'll leave it to the arm64 people to judge if this is
worth the hassle.

Index: linux-2.6/arch/arm64/include/asm/preempt.h
===================================================================
--- linux-2.6.orig/arch/arm64/include/asm/preempt.h
+++ linux-2.6/arch/arm64/include/asm/preempt.h
@@ -88,15 +88,18 @@ void preempt_schedule_notrace(void);
 #ifdef CONFIG_PREEMPT_DYNAMIC
 
 DECLARE_STATIC_KEY_TRUE(sk_dynamic_irqentry_exit_cond_resched);
-void dynamic_preempt_schedule(void);
+void __preserve_most dynamic_preempt_schedule(void);
 #define __preempt_schedule()		dynamic_preempt_schedule()
-void dynamic_preempt_schedule_notrace(void);
+void __preserve_most dynamic_preempt_schedule_notrace(void);
 #define __preempt_schedule_notrace()	dynamic_preempt_schedule_notrace()
 
 #else /* CONFIG_PREEMPT_DYNAMIC */
 
-#define __preempt_schedule()		preempt_schedule()
-#define __preempt_schedule_notrace()	preempt_schedule_notrace()
+void __preserve_most preserve_preempt_schedule(void);
+void __preserve_most preserve_preempt_schedule_notrace(void);
+
+#define __preempt_schedule()		preserve_preempt_schedule()
+#define __preempt_schedule_notrace()	preserve_preempt_schedule_notrace()
 
 #endif /* CONFIG_PREEMPT_DYNAMIC */
 #endif /* CONFIG_PREEMPTION */
Index: linux-2.6/kernel/sched/core.c
===================================================================
--- linux-2.6.orig/kernel/sched/core.c
+++ linux-2.6/kernel/sched/core.c
@@ -6915,7 +6915,7 @@ DEFINE_STATIC_CALL(preempt_schedule, pre
 EXPORT_STATIC_CALL_TRAMP(preempt_schedule);
 #elif defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)
 static DEFINE_STATIC_KEY_TRUE(sk_dynamic_preempt_schedule);
-void __sched notrace dynamic_preempt_schedule(void)
+void __sched __preserve_most dynamic_preempt_schedule(void)
 {
 	if (!static_branch_unlikely(&sk_dynamic_preempt_schedule))
 		return;
@@ -6924,6 +6924,11 @@ void __sched notrace dynamic_preempt_sch
 NOKPROBE_SYMBOL(dynamic_preempt_schedule);
 EXPORT_SYMBOL(dynamic_preempt_schedule);
 #endif
+#else
+void __sched __preserve_most preserve_preempt_schedule(void)
+{
+	preempt_schedule();
+}
 #endif
 
 /**
@@ -6988,7 +6993,7 @@ DEFINE_STATIC_CALL(preempt_schedule_notr
 EXPORT_STATIC_CALL_TRAMP(preempt_schedule_notrace);
 #elif defined(CONFIG_HAVE_PREEMPT_DYNAMIC_KEY)
 static DEFINE_STATIC_KEY_TRUE(sk_dynamic_preempt_schedule_notrace);
-void __sched notrace dynamic_preempt_schedule_notrace(void)
+void __sched __preserve_most dynamic_preempt_schedule_notrace(void)
 {
 	if (!static_branch_unlikely(&sk_dynamic_preempt_schedule_notrace))
 		return;
@@ -6997,6 +7002,11 @@ void __sched notrace dynamic_preempt_sch
 NOKPROBE_SYMBOL(dynamic_preempt_schedule_notrace);
 EXPORT_SYMBOL(dynamic_preempt_schedule_notrace);
 #endif
+#else
+void __sched __preserve_most preserve_preempt_schedule_notrace(void)
+{
+	preempt_schedule_notrace();
+}
 #endif
 
 #endif /* CONFIG_PREEMPTION */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230804181443.GJ214207%40hirez.programming.kicks-ass.net.
