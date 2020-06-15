Return-Path: <kasan-dev+bncBCV5TUXXRUIBBYVDT33QKGQEW4SNIVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BFB1B1F9BD2
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 17:21:07 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id o4sf12345885ilc.15
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 08:21:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592234466; cv=pass;
        d=google.com; s=arc-20160816;
        b=AVhqL/9jbIQqICQAeiia3BtQOTNNgSNEbPgohKZXBxwStucaPYwGFHPHkIyDWLUau4
         OsBZVt5JmmCWE4oOZRG120OHvpj5fuVcIZDCNNeOCnPeHmlhzhwJzdX9FHR+/VUlhFc3
         F4WkLgG2gs0ZRxty90KcemcZvgHDom+B3sr+H1ULXh4kZPX8KwnpmPjsE9QnKmROkCee
         pOZkfaACF+cLnAZuNxODD0/+UXm9vV/xAcVPq278+XW5aZfhzZhGcOO+FWbm8UW3Z865
         w58q3Hgg3f4KqlF9Ne7mFf0zF6yhq7Kdq/fa31We7DSIHHams+okdTN0ClTX9JnazLBm
         Wapw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ow5iJRh+Oy78sSHkmBIIu5UcrPHxnazHzER72kJo8dY=;
        b=PbJpfrr+CbUk6PMRG5yFMFbIhuYDhNl7UZnRVx10RxA5mVgnpqgCEdMIkeDoLWtbHW
         6x7fKN35S/gbvSpQ1FGj0ttNVWetUAbKwrReWRyfz5Vn17hmtBdFJ4LyeaJxF1/i9fDE
         XeQX9GpJhfXMmgL+4qKxDrXsSn2zdk2Ox3BkZXRQNBOVnmzcEACDp5kUIvImJZPT8OLR
         AXtqX8ZN1GlQBKUmn4jjTNCaib/VtCC/6lqpUx7A/Fe7KpdpBKRlRgeUFEyRMsjXu6iy
         vCo4zWEJ95bpfqMlZf6aYtXhlUgaOzNIc7kYObK+8bKyPhBDb1VYimKT1uKFK55pZlCj
         zO+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=H52QNX2j;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ow5iJRh+Oy78sSHkmBIIu5UcrPHxnazHzER72kJo8dY=;
        b=h3j3nXLZebiYQUNLhOgCfl3bZLHzw/73n/eDXXJFYpRFzRPknywpKI9zbuYbx5rzmi
         r/pSy3HZFoTUwuXV2+KLX/lePVCxG9zDy1v8/4VAHrS3bUj46Np9gVK64apnWf+zx6iS
         ltQU3KU7WFu3iOYtzSwtaJM9kOLugZQRoDYbSSQzHhN/t7PWeOS/YdjZ0JpkwfGz+wX5
         Er0z4cZSFxXcKYD25BXzHX/O7CnIsMvx6oTybcXWRgtjL7xZIj7DCEHIrYBl9+XM3yDZ
         WHw7giXEAnrIqz06Coqtd+2AOsWdoz0eOTMLIRJs5+eOCbJcE83iSE+C0DUWiiQnkj23
         icKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ow5iJRh+Oy78sSHkmBIIu5UcrPHxnazHzER72kJo8dY=;
        b=BRVktbNn2ZCuGU7DL16tBO+1eTtQFdH55l1z7891xWZ5B11G7kCPKnET11NALIoQME
         k2Jnr4OSyks5wGVh+Tq8IMbyJ4X+kMevQW+pwD5LeVDcBc3rkx+ukT/RzvMsLEkR9e/5
         hcaXayl735sn6bUd611DECKMgh6VGx5ZXEF4ufijkkYGvhXKqocb2e9guI40WvooLjCA
         bwS2cxdWezQ6TFwSXPeGUxrlkQaPkvYkyrBvtHMVVXoTFx3/CRyFu8zc9C74mZ6F1cT7
         nmgFcI7HMZ5n8cqN6DdyYIUcoDeOwNWbvtUy+3qWcPJyyH9rvG6tarS553IA5gfM+I8A
         XiUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TTDD0Un6E+pqokPnyO364LBFmv2ATKEr+cVgu4/bvoWr4eErS
	JWA9+oicd5T415I5FzitJqk=
X-Google-Smtp-Source: ABdhPJxgjd9ZH9vqatUyHuF4QygAB6wMZKxWvZ/7bYU/xAwE5SR83ocMuy6jGVBW5Z+B+9MKxqMgmg==
X-Received: by 2002:a02:2c6:: with SMTP id 189mr22601081jau.115.1592234466633;
        Mon, 15 Jun 2020 08:21:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:1453:: with SMTP id 80ls2627005iou.2.gmail; Mon, 15 Jun
 2020 08:21:06 -0700 (PDT)
X-Received: by 2002:a6b:1487:: with SMTP id 129mr28340399iou.197.1592234466275;
        Mon, 15 Jun 2020 08:21:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592234466; cv=none;
        d=google.com; s=arc-20160816;
        b=JVsmdlGFYQQO47LJ1IC6q7pehC4tgYJzoVCUkGsQZoRoPZhHwHeJkoCytRIpAgTmkT
         TUMuqvxbjvI6e2coBUknGGk67OksOg1UaFpBNzKNekgkFyL7sqCZ0sy5tiFKY/Orz68Q
         uwXJyAO7uI9Ant/OxSngK5kRI28AoqF3su+HGpVkQGRBC/NtoWoZwOksfuHHWVRB+/uy
         HRDNZfqTKV7axLXcjtf3IJd5PE17GxkjBi5hx2Hzo6yCGoaLi++A3bRzaHHDyNnt4aaJ
         BHw3J65myJBoWR0O/FezxCovnmAe9sUDPSME8bMtKQF+JoMLGHQa0Bi0QIsUqrrI/i6I
         UEVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Udue+LwwMS7xIun8pCno4Qdzcnv4kfX0ri/1a/g6c/k=;
        b=ek5R+jGXr/DrxOMdm0o1M/8HA9MjQCKWxzJjr1osW0su9RSlm+QFiYiftbCojvUKk5
         bznMi8/+RJ+Tdw8i8YYzm4S2UNHDRAk05xWTLwYZefprBKe2BQHIqQ1/A+257gdupS5C
         aqiagKgXMRrczb6tj1ix1gL64MjuD57f/OqdxhlzlCum0yNSj1GbHuB/DqAgX1NkpbYF
         MzJroQVwXGogJav8B976btVJz9R83WUNEhqmC+YXF+NGmQt7F6Sk4HOkFhqqWUEpqj6a
         CbX/k3dUZCekMA7a6pqXzrwI3ejKN4iGODwo/etdx+VLlK0soLlJCJehQm41T2gp8urf
         o3zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=H52QNX2j;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id i20si235761iow.2.2020.06.15.08.21.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jun 2020 08:21:06 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by bombadil.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jkquv-00053R-UE; Mon, 15 Jun 2020 15:20:58 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4EC123003E1;
	Mon, 15 Jun 2020 17:20:56 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3535C203C3762; Mon, 15 Jun 2020 17:20:56 +0200 (CEST)
Date: Mon, 15 Jun 2020 17:20:56 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Mark Rutland <mark.rutland@arm.com>, Borislav Petkov <bp@alien8.de>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Josh Poimboeuf <jpoimboe@redhat.com>
Subject: Re: [PATCH -tip v3 1/2] kcov: Make runtime functions
 noinstr-compatible
Message-ID: <20200615152056.GF2554@hirez.programming.kicks-ass.net>
References: <CACT4Y+Z+FFHFGSgEJGkd+zCBgUOck_odOf9_=5YQLNJQVMGNdw@mail.gmail.com>
 <20200608110108.GB2497@hirez.programming.kicks-ass.net>
 <20200611215538.GE4496@worktop.programming.kicks-ass.net>
 <CACT4Y+aKVKEp1yoBYSH0ebJxeqKj8TPR9MVtHC1Mh=jgX0ZvLw@mail.gmail.com>
 <20200612114900.GA187027@google.com>
 <CACT4Y+bBtCbEk2tg60gn5bgfBjARQFBgtqkQg8VnLLg5JwyL5g@mail.gmail.com>
 <CANpmjNM+Tcn40MsfFKvKxNTtev-TXDsosN+z9ATL8hVJdK1yug@mail.gmail.com>
 <20200615142949.GT2531@hirez.programming.kicks-ass.net>
 <20200615145336.GA220132@google.com>
 <20200615150327.GW2531@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200615150327.GW2531@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=H52QNX2j;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jun 15, 2020 at 05:03:27PM +0200, Peter Zijlstra wrote:

> Yes, I think so. x86_64 needs lib/memcpy_64.S in .noinstr.text then. For
> i386 it's an __always_inline inline-asm thing.

Bah, I tried writing it without memcpy, but clang inserts memcpy anyway
:/

---
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index af75109485c26..d74fd6313a4ed 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -686,17 +686,17 @@ struct bad_iret_stack *fixup_bad_iret(struct bad_iret_stack *s)
 	 * just below the IRET frame) and we want to pretend that the
 	 * exception came from the IRET target.
 	 */
-	struct bad_iret_stack tmp, *new_stack =
+	struct bad_iret_stack tmp = *s, *new_stack =
 		(struct bad_iret_stack *)__this_cpu_read(cpu_tss_rw.x86_tss.sp0) - 1;
+	unsigned long *p = (unsigned long *)s->regs.sp;
 
-	/* Copy the IRET target to the temporary storage. */
-	memcpy(&tmp.regs.ip, (void *)s->regs.sp, 5*8);
+	tmp.regs.ip	= p[0];
+	tmp.regs.cs	= p[1];
+	tmp.regs.flags	= p[2];
+	tmp.regs.sp	= p[3];
+	tmp.regs.ss	= p[4];
 
-	/* Copy the remainder of the stack from the current stack. */
-	memcpy(&tmp, s, offsetof(struct bad_iret_stack, regs.ip));
-
-	/* Update the entry stack */
-	memcpy(new_stack, &tmp, sizeof(tmp));
+	*new_stack = tmp;
 
 	BUG_ON(!user_mode(&new_stack->regs));
 	return new_stack;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200615152056.GF2554%40hirez.programming.kicks-ass.net.
