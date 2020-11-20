Return-Path: <kasan-dev+bncBCU73AEHRQBBBIVD4D6QKGQESEXUEAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 87A6C2BB3FE
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 19:57:39 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id a6sf12944760ybi.0
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 10:57:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605898658; cv=pass;
        d=google.com; s=arc-20160816;
        b=QjpsHovMQ9SGm0uwBoBRdi+JoTWjurizoTV8KYDeYHx6Cn9+JnRqrV7+R30qA1jhn1
         nmeEYxUEqCNxOSKd15sjzwkwq3KpiXIFoxkWcCxVkuxTXE/izJ2PKKNf32fYYt9sBPfi
         JXphGpql6c2X1qLRLzqpFE3RUrWio1ty9zy3iE7NFFZN56RBOtnLCK170Fn9X1dLWT97
         exMwNgPQS+tv0B8hKb8WIFzh1wkI+p9WbwLCXgBKpad8n9JZ9DLJD+WPlNDAJnCno5od
         OBMnKViSWBKq4Yxpp9Mm06C3/ErzFcM+R3RrbEDKAps9fjOHxWOlA3DvtqhzECVQTc6d
         XqTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=eS8OPL2AiPTIjmPcmG6L0k3RCzUziWUxHdEmzJjDhTY=;
        b=YKp3i9vDbWUdd99qVUH355NY8brdxJDwC7PmiQLe/UPDpvCmRS+dG410M1lRomwYnB
         ITXIxMIAuYnddUUAujxbCoMpKS2gWtCZdQhqPPCHgdxY5V3vVywLIL+qhGmoGIpSwnU1
         uWHCupQIwYi1j0dgGB96E37tlsJQIUg2GCKhtaQbXgU3LT9JvxacwuBJ7HXZd+PdlmU6
         FfTNTHlVbNuUs8+LoUwyxmUfr44R+/jBBmZRj2JexEnEFBsnIptNv1D72BSX88b0OCCD
         Rp6ZlHtWgaXstWv6lIGf2c4eVLQ7CRibKNCeoWlY5BIxmrQ4qhLf2AmgaRjX0psXj609
         m+pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eS8OPL2AiPTIjmPcmG6L0k3RCzUziWUxHdEmzJjDhTY=;
        b=azxBDX3MJEAY0bitEAh3/087mbGjjRCxgMbXZSIU9KMs7vz/Z7V2NqId5qIry64/4H
         Asy9o9+y9o4KiIMt6dGjw0Vm4ph56U0pkBVyaPqoa2r4y8TDaksg4p2unv5lBwoY2fgt
         2eLlG17eUtRLpMj5XHLheLC0emrqZZRTamk95SUanXZpArNp3nKqOx+LHh745+Nb87Ec
         bzNfVyY0jbgFDJKnWzNE0wo1w59NOMYzdxTkM5I94H42Gp/uraGnseytLasFgTdP9csK
         AY6Q8j+IxogxWdCNpRc9F7vVx58NEfuBZ+Lp/OvshNGHC3uV15pjOGywUK98juir/p/Y
         BbfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eS8OPL2AiPTIjmPcmG6L0k3RCzUziWUxHdEmzJjDhTY=;
        b=Xj7CzpYLAg0GEMJ4L7wipP0nzbrvzlFlVdhtrInHzWYF0whd83nO7THONXXV+ay36B
         lFmsyi+u50PHE0hFFxLccntraKWpjm3f6I6sAYuesx0RHYIXBbskKJUr3j/XCtIYFCBu
         se3cXqcilOiBfAGSb+FzEvG+X+HuC9Xpj8UHfZk4DbSOPiqdY+rG3BjFQ7XAdAu42GW3
         ixSGqGkdfxVu2XqceZ2zggMziriIT42y4CfMLqVhJS8vXLGeak4ZE9H+e6jxvNUwFB1E
         r/ZBbOoUxAR+Arlz08KyYJkRU/ahl8M8ypxZSQoPDDB0JRECArbCtpQejabF7I4mI/vi
         FlFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dXfBffT2h2SntX+ic4bAbmS4zw2MA5ZYtSFVz2azlbPwsID8s
	0rF4Ly9Ih6y28b60D0VO97I=
X-Google-Smtp-Source: ABdhPJwYBBCbkeneHmC8cB7VsGXBodFBnypXu7530giqSR5Kjd3PzJQEMqCxdViq3mK0cMEVwf3Lgw==
X-Received: by 2002:a25:cb03:: with SMTP id b3mr23825595ybg.207.1605898658570;
        Fri, 20 Nov 2020 10:57:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c0d3:: with SMTP id c202ls3770550ybf.5.gmail; Fri, 20
 Nov 2020 10:57:38 -0800 (PST)
X-Received: by 2002:a25:786:: with SMTP id 128mr21401327ybh.19.1605898658070;
        Fri, 20 Nov 2020 10:57:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605898658; cv=none;
        d=google.com; s=arc-20160816;
        b=Xn77vGPfnWY5FyR037hUIFeeaixTDeBPJ7whLBH8dIJf9fOk2B5+XrZDCf3uwg5+oK
         +qUyZLtuU/4UQLys9SY7QbedmPILubP4nWy6a5u0gKU69bLXJYt/CdSBuI2tinUoxFEW
         NG0DOL0F3LQlHLzBEd1KKbHkS7nayeC7B/p6P5B6D04DGQImLkaOOUziGgYWxs3+PKaO
         40abLYvp7K73nf295lpcNyX8DX18ILSY3yYxiko8vAEUrzKGUK51xccoFIDVf0CMyWqN
         LYqfwlumieU/CI0EGoJZlA0Lq+BwazcWtxQ9IAxbW1YRcowPeoCWRThhUbbozkvJOzjb
         0r3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=IAtoyrDzIMMkgIMZ2uA1CJV+7zHu4CtdMhcpEZb0GbY=;
        b=H13nQwzWBAqaEBMsEZkAhKzzLkbDO6Em8A+pH8ntwf6FzKz5ULwUdHV39HPQ11ryjS
         fYjcctke27C2IhwQFFdD1/fHN0UAY2oN3LyxockGJHrc6iVsCUfAbhSUd56DQ2kZFUC2
         TjjAow5Pb0SM8jgtUH/xhRiuWK5QpIVUNvq7bFfVZbkT+0FxqDtu7n7WRcDUnXqWUzuH
         +QfXU831X2QTH2Do4LvT3/WMentJ+n6nniGMlnat4tLBo+y+HOQksKRO6xneZzKdVXgi
         GUwdTOkVfMJFSLJ0iJkMOWJUUlV6Y/UOOL9znpWTF5aC9avaZHxzYJ+06xTx6dqkkEXh
         zsNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y4si367387ybr.2.2020.11.20.10.57.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 10:57:38 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 5F2AD22464;
	Fri, 20 Nov 2020 18:57:35 +0000 (UTC)
Date: Fri, 20 Nov 2020 13:57:33 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Anders Roxell
 <anders.roxell@linaro.org>, Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Jann Horn <jannh@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
 <jiangshanlai@gmail.com>, linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201120135733.0807c20f@gandalf.local.home>
In-Reply-To: <20201120181737.GA3301774@elver.google.com>
References: <20201118225621.GA1770130@elver.google.com>
	<20201118233841.GS1437@paulmck-ThinkPad-P72>
	<20201119125357.GA2084963@elver.google.com>
	<20201119151409.GU1437@paulmck-ThinkPad-P72>
	<20201119170259.GA2134472@elver.google.com>
	<20201119184854.GY1437@paulmck-ThinkPad-P72>
	<20201119193819.GA2601289@elver.google.com>
	<20201119213512.GB1437@paulmck-ThinkPad-P72>
	<20201120141928.GB3120165@elver.google.com>
	<20201120102613.3d18b90e@gandalf.local.home>
	<20201120181737.GA3301774@elver.google.com>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=g+oz=e2=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=G+oZ=E2=goodmis.org=rostedt@kernel.org"
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

On Fri, 20 Nov 2020 19:17:37 +0100
Marco Elver <elver@google.com> wrote:

> | # cat /sys/kernel/tracing/recursed_functions
> | trace_selftest_test_recursion_func+0x34/0x48:   trace_selftest_dynamic_test_func+0x4/0x28
> | el1_irq+0xc0/0x180:     gic_handle_irq+0x4/0x108
> | gic_handle_irq+0x70/0x108:      __handle_domain_irq+0x4/0x130
> | __handle_domain_irq+0x7c/0x130: irq_enter+0x4/0x28
> | trace_rcu_dyntick+0x168/0x190:  rcu_read_lock_sched_held+0x4/0x98
> | rcu_read_lock_sched_held+0x30/0x98:     rcu_read_lock_held_common+0x4/0x88
> | rcu_read_lock_held_common+0x50/0x88:    rcu_lockdep_current_cpu_online+0x4/0xd0
> | irq_enter+0x1c/0x28:    irq_enter_rcu+0x4/0xa8
> | irq_enter_rcu+0x3c/0xa8:        irqtime_account_irq+0x4/0x198
> | irq_enter_rcu+0x44/0xa8:        preempt_count_add+0x4/0x1a0
> | trace_hardirqs_off+0x254/0x2d8: __srcu_read_lock+0x4/0xa0
> | trace_hardirqs_off+0x25c/0x2d8: rcu_irq_enter_irqson+0x4/0x78
> | trace_rcu_dyntick+0xd8/0x190:   __traceiter_rcu_dyntick+0x4/0x80
> | trace_hardirqs_off+0x294/0x2d8: rcu_irq_exit_irqson+0x4/0x78
> | trace_hardirqs_off+0x2a0/0x2d8: __srcu_read_unlock+0x4/0x88

These look normal. They happen when an interrupt occurs while tracing
something with interrupts enabled, and the interrupt traces a function
before it sets the "preempt_count" to reflect that its in a new context.

That is:

	normal_context:
		func_A();
			trace_function();
				<interrupt>
					irq_enter();
						trace_function()
							if (int_interrupt())
							 [returns false]

					set_preempt_count (in interrupt)

And the recursion detection is tricked into thinking it recursed in the
same context. The lastest code handles this by allowing one level of
recursion:

 https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=b02414c8f045ab3b9afc816c3735bc98c5c3d262

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120135733.0807c20f%40gandalf.local.home.
