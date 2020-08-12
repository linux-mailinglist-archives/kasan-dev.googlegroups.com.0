Return-Path: <kasan-dev+bncBCV5TUXXRUIBB7G5Z34QKGQEPBD7TMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 47587242715
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 10:57:33 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id n68sf356594vkf.11
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 01:57:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597222652; cv=pass;
        d=google.com; s=arc-20160816;
        b=S+VB6py1QIPExk30xYW8kKEq5aLJavNKO7hGozL5aQ6qXifSlRdjKLKl+KqBx42Q6B
         60NePQQxaDo0tIdcBD6D4el7OnwUI4VFv2o5VA2Y4uD6Z4pD+bSiWAS+pcxGqkZ9uEGS
         OGesybDZPbeHaZEdp7T8xmBG4XMlLY4du4vSmUs5GtSv96q7j/cJjyXmSsYbtlGD0LeH
         uQYjeucd9bukIDYh6se/I5dFDO2LqaX1r5QNVm2z8QGejjVJGPwnfWHVBzTJ/yTL4vpQ
         0wOEOIhxbl+CqN5E7eeZQLxgdItlGK7ZatVgpio+YWTYuC3wuE1Bcv+Ijj2SarOWjKge
         9KZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4oJ1uLpWx/rLbdprNo97EqfzKPT8nDtUNqVnVnzcEm4=;
        b=di2/qke/uomx5lSadUhlOzQRpZTEzGFapdwKvnyTkAmyzbUQgSneSQiJtCMLJueM+Q
         gm7r3ls3luXZFc/xxmDw6NHQRl0Q8ONCdzk2zJOkt9V5FXeX6yeFjH4tEMfV7daENdVq
         hNY0qkootRYgp/1Momh0ZvEsMCunAkZdKZ6Z0HQYvFZNGG3yZEvmoGrzN1iiuvJvAm4/
         1n1HRypyv3EOLto9k93ZWoE/vowV9rdZJ2QLRSqe9jC2lDBFaR8eXMzt15fXftTVQDQY
         Hr0QI5IdGlpg4BGzOTG2i76V06UgbJct0ZjpBXRboMxrl80k1r39535R3i5pS2OPTMWw
         8F+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=oA0RL+AU;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4oJ1uLpWx/rLbdprNo97EqfzKPT8nDtUNqVnVnzcEm4=;
        b=WqM3EMJm7tFUPnmvGvhXoBDS1osa6eY0/FNvyvHmWKkzkJFEe2iPLtP9qcAtPEIsq/
         /GTVWQvQm9mb1dCKd1CBT0sgbIvPF0Bf6cS0yEZMhUkGUMEHSRag2itpBCUrrKJCKobw
         M+jEhOHMa0Bf72q4UcDq/2dIPU6kNBguGB1htRBGSRQrpwUEa8gtgpJA+LyuGvAM2bxY
         ibVGx0fDPdbZRTKEVNB8nautX8vr/IL9gWds6BctvOVJ7PTWkw2jKA7XnoxW4tjGHlR8
         yjfN1JH7P3zWKj9uvEGdC5JFDQn7FKYVHE7y9EvIbNVoCQSjuOYC4dprz7/Id9HQOhJW
         9VIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4oJ1uLpWx/rLbdprNo97EqfzKPT8nDtUNqVnVnzcEm4=;
        b=fEDqfvP9nwJ2wSBi12N/xzM1hn8U4pP5/RiU49QVRoydDBE0sqIstPbz5DRNavS9ys
         zuiSDmRXLG+k1Qksq4J7aKNstvXuctLECLAz+Hl3aiEouq8tz1o9n1yM7Lz4EXjw1lbP
         lW/W3wQUkhGFD8/flM6wl2Wpzlf5ePuPecp/tTtFWkjIqrWGn5y3zSggt5uOLJPRXl19
         hLFhlqv8v7MTZycpWjrxsaoCfgKRj6PSjuvXy/dZO0AokxCyPpebSvvSJPkutjiAtMVg
         ivD9GFuqNL+nVxr1uF+1Ak9xxr5mB7wv4buBEvDVnbi7spffuFNNGsc7knUuBRrq3VnG
         s0zA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LYNjhoNqZf9oDrDGu42erse0m7i5n82D22Pf9CViCBGO7fxou
	9tGdIG16fdIzPaYPPBfYL/s=
X-Google-Smtp-Source: ABdhPJwRHMel9cCHjBK0I7Rl/xv7ZsLYmJOyynIuIk6ZSP1mcnWWdYgKJ6MQOeVlxXBWlOlPPQ+V6w==
X-Received: by 2002:a05:6102:109a:: with SMTP id s26mr26759999vsr.81.1597222652133;
        Wed, 12 Aug 2020 01:57:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dd9a:: with SMTP id i26ls127324vsk.6.gmail; Wed, 12 Aug
 2020 01:57:31 -0700 (PDT)
X-Received: by 2002:a67:c388:: with SMTP id s8mr29135135vsj.61.1597222651813;
        Wed, 12 Aug 2020 01:57:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597222651; cv=none;
        d=google.com; s=arc-20160816;
        b=NMVKRdK8JbC6SPZha7kqqx2BGLKl3hAw7ZpjqnWVsyqsxKysY1kDGtC6p5+QonxO8k
         hxbQGk1PN4jWzPf4d0CXfBPPsXxhpxClbkyTgb/QMbDWXy/ZkrfVEjelas5fByRYfF+w
         iIeysTdWylPNK2f5z794XYUCfoVH9nIyq3F/iDm7MnuaBbJjf6vGU4v/CZ5pnHo8I+c8
         wPe2QOdtu8P88fBl1UdSvVXW1IkBPl+5iT1m/OS5fLopMsM3ZWOUl21M1gbuEAK4A0z/
         ffQHAh7/njLbM7aZI1y1vYFw7GCpgRdJ96+l9HfrUc9A3EXgdNJfzTDNzkElzi+pL+jA
         xrzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=nuSjbKLmgFUpujyztO9pZIgg8RwXK/k205UIQiNkmjY=;
        b=ck/sa1UggzCa0QiFhivaFDfnHLF1dpp5K1EjjPJ6nJtEDO1+08TUNKLfONvqt4CQiP
         XSQkGfb6to4dQQv6uEuJbdljalXipcwFYfR3FF+Gh2xRXzbML0FCMCdAa+YWSdDnpkMa
         3akuN4B/g3gNJO4SZzUti1ObnCMG52bX+nqEhsSFKYEFqNasxAvtvE9+4aIadj4XyzVo
         /nBYYZFJ5Aw+c0bZKbP315vSw+3Wy+aZNPKDvnvUrT2qtv/p4mIRoimZ2rikDM/5aR7p
         rxEBRYDZ2AI6FkcgdcZiP2gNtUdreDBuEKeuam2R2nUiiIC7+kxpEQHOzzsstpjdh3yy
         lNMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=oA0RL+AU;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id p19si102297vsn.2.2020.08.12.01.57.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Aug 2020 01:57:31 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1k5mZT-0007yN-FP; Wed, 12 Aug 2020 08:57:19 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3137830753E;
	Wed, 12 Aug 2020 10:57:17 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0F43625D0D543; Wed, 12 Aug 2020 10:57:17 +0200 (CEST)
Date: Wed, 12 Aug 2020 10:57:17 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
Cc: =?iso-8859-1?Q?J=FCrgen_Gro=DF?= <jgross@suse.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	sdeep@vmware.com, virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Wei Liu <wei.liu@kernel.org>, Steven Rostedt <rostedt@goodmis.org>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200812085717.GJ35926@hirez.programming.kicks-ass.net>
References: <20200807151903.GA1263469@elver.google.com>
 <20200811074127.GR3982@worktop.programming.kicks-ass.net>
 <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
 <20200811081205.GV3982@worktop.programming.kicks-ass.net>
 <07f61573-fef1-e07c-03f2-a415c88dec6f@suse.com>
 <20200811092054.GB2674@hirez.programming.kicks-ass.net>
 <20200811094651.GH35926@hirez.programming.kicks-ass.net>
 <20200811201755.GI35926@hirez.programming.kicks-ass.net>
 <20200812080650.GA3894595@elver.google.com>
 <20200812081832.GK2674@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200812081832.GK2674@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=oA0RL+AU;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Aug 12, 2020 at 10:18:32AM +0200, peterz@infradead.org wrote:
> > 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> > 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> > 	 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preemptirq.h:40
> > 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> > 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> > 	 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preemptirq.h:40
> > 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> > 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> > 	 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preemptirq.h:40
> > 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> > 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> > 
> > 	<... repeated many many times ...>
> > 
> > 	 trace_irq_enable_rcuidle+0x87/0x120 include/trace/events/preemptirq.h:40
> > 	 trace_hardirqs_restore+0x59/0x80 kernel/trace/trace_preemptirq.c:106
> > 	 rcu_irq_enter_irqson+0x43/0x70 kernel/rcu/tree.c:1074
> > 	Lost 500 message(s)!
> > 	BUG: stack guard page was hit at 00000000cab483ba (stack is 00000000b1442365..00000000c26f9ad3)
> > 	BUG: stack guard page was hit at 00000000318ff8d8 (stack is 00000000fd87d656..0000000058100136)
> > 	---[ end trace 4157e0bb4a65941a ]---
> 
> Wheee... recursion! Let me try and see if I can make something of that.

All that's needed is enabling the preemptirq tracepoints. Lemme go fix.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200812085717.GJ35926%40hirez.programming.kicks-ass.net.
