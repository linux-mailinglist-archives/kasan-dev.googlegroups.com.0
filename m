Return-Path: <kasan-dev+bncBDBK55H2UQKRBY54XXFQMGQEQTL7OZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 46E18D3C62C
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 11:52:21 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b78adfc09sf4670398e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 02:52:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768906340; cv=pass;
        d=google.com; s=arc-20240605;
        b=JGK+O668e8ALJCdxWd8H+D4fwnNfz54xPr77An+gaXxrz2FTWmdEiJT0vVRmpmzjmr
         2ijvWHPhIVAwS7hrvlFKLyyB3bhcXZ5gbz7rNRsUuqjUxC1v+LoyEXGOokB3uyiih1dd
         CMnofAKcHZUJKGWH9gSx4zf6jyFDbTVj4UxJIoyNs75s8tbss9ZlxQIcUhtG1wNBzSF5
         67r8wx6oTcGjyaQRiZmeDjog9VnvE+Cm3bARM2qRBK62H61zFvnNesutUXD30c6ZvjEq
         ELhLvDfJuxHCNRgdFwFTtFlZ9l/dmBI51OFb0hJuPwu1H2stx8wPWQayQDz+0o5Cz7nU
         hFJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NjXgxujnX2VMy/A2wF+FC8apHA58ed7VIIxGAJp926g=;
        fh=rKVipSSB05rpEnYlgxISQDrx1Qk4VBMLS0ux7MUCR9M=;
        b=M7owKEH2mIYxzghgikjkC6vhUrFP6feHBCNEAwCKVrl2flS1uTVZGGVGvYA0V+sjNk
         FRtlfvb8+jgBPgKSNVqfRGA8cjMpVYgdmFEowuZRcegF7k16k4ve98cKM72289QnwyAV
         vRGRLFCnHU2prUADxv8xywhaNrDHBPZTK9bVrKiermYtS+yQxLod+ynDjbsJKJo6TTI5
         /9jymZUPKYJkoqjj9uX0DqJWx/lXVTlYURJ1EO0tioHcMeqwsSFKMAZan6f76cGW3+X6
         WntWFjXjP0CWGTr8DCGXXKsFzh4B/XX1mbRL5u7HuTAKbgOiEJ4Zjccx9P9OBZWiclHD
         4cGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=POGQsvVP;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768906340; x=1769511140; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NjXgxujnX2VMy/A2wF+FC8apHA58ed7VIIxGAJp926g=;
        b=AzV6/mkroG8Ku8cxL4J5tzd+b3MTDTUpxG0uZzf1yxd4AyNPTnx0jlDIpW3nYijor8
         zMh8l7kfSlgCLhv/P48yvImOer1HCYzCsBFTFuSCrAfCPN9sWGIDRNcT7lmY1Nt3OvoN
         EZAQmKbQhKz0wnyfxWIzU/jExhOpgDpYXZ0ZKjGjZa2scN7NIfId74Z3BiSml0tCQODS
         B0T6rA2jgr9pywqclzdI8vDtRRo1rfJ5eDnVbnjJ15WL1rcDPUZ1vPEQONet45iHUQbd
         o6V3V/omA+vZrqtB/qURyVrdz1ANRL+k5zRRrMnTnfxT+QL2V9SYIO543unrlFUlYjbS
         LkHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768906340; x=1769511140;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NjXgxujnX2VMy/A2wF+FC8apHA58ed7VIIxGAJp926g=;
        b=EqQ667KpDv++NeLbwiY3VRXrYqcO3IYVMhWekIXdBARzwN/ZumZWyvjfhVy0KfHqeU
         z+sEd1QIRh/ECMnDDyRqmicn5xNd0obBbNG1Tit2au10HxJ6cCHiGi5vOuWe3bMp7+aS
         5u2iHAsgR1jEegkSAwMNeCDJi1tWqYvaEOsRpDnKqO+wmq1uRU7Sbdsj9S1axl5ixebH
         IL67p/yzrTV+fYhiNyARb2mnEYj240lB9KzK03Hhn9ok5Jg0Ard8frs44LTqIq0ff3ms
         GLXHcySBbD2ZzgWGZ4xYJq+7TBGxrOCvLHemo34zyebMcW+21wWjbfOZM8iJm+Tc5EyN
         4IqQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVgRsKmI7hjoZ5ueAXJtNFzeEMvRBVJBujBpDc7GtwKaNaAL47L6PyjKh/9bdWDkNWOrgneug==@lfdr.de
X-Gm-Message-State: AOJu0Yw6AfoZ8olcxGD4qogUYMw4Hihb3QqLQGioE3TmiUxqtRzXZ02h
	4LEThCujCbaFcHD4kcANYyISkBBG82LA4d041ofbCN5J21EXdZDH2KFL
X-Received: by 2002:a05:6512:3c9a:b0:59b:9fee:2602 with SMTP id 2adb3069b0e04-59bafdc1656mr5156381e87.19.1768906340030;
        Tue, 20 Jan 2026 02:52:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GeUfoCololYEDG7fhxG1KgJSYVwPGY0581Jj0iFKkZnA=="
Received: by 2002:a05:6512:1389:b0:59b:6cb9:a212 with SMTP id
 2adb3069b0e04-59ba6afde0als2144815e87.0.-pod-prod-04-eu; Tue, 20 Jan 2026
 02:52:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVI3e89QamU/c5FNIeeIbeSplNuRhiQc/G+2Jt1dV9AxjoBLRBxoLOilzvB0R4xFd1F8NavPBfFCgw=@googlegroups.com
X-Received: by 2002:a05:651c:1986:b0:383:1b4b:c2c8 with SMTP id 38308e7fff4ca-38386c768b8mr51369391fa.41.1768906336813;
        Tue, 20 Jan 2026 02:52:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768906336; cv=none;
        d=google.com; s=arc-20240605;
        b=hhLLKprv6LfQ/FWvQM8xT7q17qqh47BvE/LDXpQ82dNdSpDICygW/AZp2ra+gtrMLc
         MMKxjgba43VukiSCqpiLGokjBAhMn2suaD8Egu8ufsmPl9ZTHy1Ht2Q6PDqzo19b1VVK
         L59VNVjstILsBEZiXqy55JRCorMvQEUG0oVSDn/jFYIhAII/O4iNNdVEmDYxxrw6S0WG
         H2Zs/gofrxcXRGEns56e82a2WrQ4SEPD24uSmW9I24HYzFOgk+JETPqi8PNQG+SIRyBx
         2rTzjAWwvgzH3ZH0LaTRKepwVjB+koujAp6p4p3sgco04qgA/cj+A5XoxAS17WsZ9Atp
         0GvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qkRq9Kh+t9q2WeybfZmZ0D2kPKKoLj074IxXeupVa34=;
        fh=TUwS09QozRkuUhiwzF+zJ8cD+MuvSG0Qtmm2GF8pnTA=;
        b=lP8rzuynvelnhqxAwa0UCu3o6imyaIRsUJQZUC7WQNq61zExnfXoXe3S7oEry6Vagc
         McT/TfPhhpHO4LEdSGr1MgA/DnvpSg4RNwjPHkn9zHiAFYSffBd9dad00yXlPFax54Us
         RY4PxzyEZ27FlZp5Wa45c1m3/ZYu+kXCqswTQDpBuqEI08piiK8ze5MAMrNJxpy/2KQ2
         fQRckA34nmkRpUFtRq17dSifUoXqkWCPCBB6MjhAlQKF+q/op+QNyeUY93AaiyE2bPgh
         aWqGahy+LBdS0bOp3vS9rtaF1dmh8R3kbOWNMURIrXr9WZ8D6x38DBJGy+GhmVd+tfBp
         oCBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=POGQsvVP;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e285a2si2842351fa.5.2026.01.20.02.52.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 02:52:16 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vi9LI-0000000DqiH-27xI;
	Tue, 20 Jan 2026 10:52:12 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 022A5301C52; Tue, 20 Jan 2026 11:52:12 +0100 (CET)
Date: Tue, 20 Jan 2026 11:52:11 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Christoph Hellwig <hch@lst.de>
Cc: Marco Elver <elver@google.com>, Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Bart Van Assche <bvanassche@acm.org>, kasan-dev@googlegroups.com,
	llvm@lists.linux.dev, linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-security-module@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH tip/locking/core 0/6] compiler-context-analysis: Scoped
 init guards
Message-ID: <20260120105211.GW830755@noisy.programming.kicks-ass.net>
References: <20260119094029.1344361-1-elver@google.com>
 <20260120072401.GA5905@lst.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260120072401.GA5905@lst.de>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=POGQsvVP;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Tue, Jan 20, 2026 at 08:24:01AM +0100, Christoph Hellwig wrote:
> On Mon, Jan 19, 2026 at 10:05:50AM +0100, Marco Elver wrote:
> > Note: Scoped guarded initialization remains optional, and normal
> > initialization can still be used if no guarded members are being
> > initialized. Another alternative is to just disable context analysis to
> > initialize guarded members with `context_unsafe(var = init)` or adding
> > the `__context_unsafe(init)` function attribute (the latter not being
> > recommended for non-trivial functions due to lack of any checking):
> 
> I still think this is doing the wrong for the regular non-scoped
> cased, and I think I finally understand what is so wrong about it.
> 
> The fact that mutex_init (let's use mutexes for the example, applied
> to other primitives as well) should not automatically imply guarding
> the members for the rest of the function.  Because as soon as the
> structure that contains the lock is published that is not actually
> true, and we did have quite a lot of bugs because of that in the
> past.
> 
> So I think the first step is to avoid implying the safety of guarded
> member access by initialing the lock.  We then need to think how to
> express they are save, which would probably require explicit annotation
> unless we can come up with a scheme that makes these accesses fine
> before the mutex_init in a magic way.

But that is exactly what these patches do!

Note that the current state of things (tip/locking/core,next) is that
mutex_init() is 'special'. And I agree with you that that is quite
horrible.

Now, these patches, specifically patch 6, removes this implied
horribleness.

The alternative is an explicit annotation -- as you suggest.


So given something like:

struct my_obj {
	struct mutex	mutex;
	int		data __guarded_by(&mutex);
	...
};


tip/locking/core,next:

init_my_obj(struct my_obj *obj)
{
	mutex_init(&obj->mutex); // implies obj->mutex is taken until end of function
	obj->data = FOO;	 // OK, because &obj->mutex 'held'
	...
}

And per these patches that will no longer be true. So if you apply just
patch 6, which removes this implied behaviour, you get a compile fail.
Not good!

So patches 1-5 introduces alternatives.

So your preferred solution:

hch_my_obj(struct my_obj *obj)
{
	mutex_init(&obj->mutex);
	mutex_lock(&obj->mutex); // actually acquires lock
	obj->data = FOO;
	...
}

is perfectly fine and will work. But not everybody wants this. For the
people that only need to init the data fields and don't care about the
lock state we get:

init_my_obj(struct my_obj *obj)
{
	guard(mutex_init)(&obj->mutex); // initializes mutex and considers lock
					// held until end of function
	obj->data = FOO;
	...
}

For the people that want to first init the object but then actually lock
it, we get:

use_my_obj(struct my_obj *obj)
{
	scoped_guard (mutex_init, &obj->mutex) { // init mutex and 'hold' for scope
		obj->data = FOO;
		...
	}

	mutex_lock(&obj->lock);
	...
}

And for the people that *reaaaaaly* hate guards, it is possible to write
something like:

ugly_my_obj(struct my_obj *obj)
{
	mutex_init(&obj->mutex);
	__acquire_ctx_lock(&obj->mutex);
	obj->data = FOO;
	...
	__release_ctx_lock(&obj->mutex);

	mutex_lock(&obj->lock);
	...
}

And, then there is the option that C++ has:

init_my_obj(struct my_obj *obj)
	__no_context_analysis // STFU!
{
	mutex_init(&obj->mutex);
	obj->data = FOO;	 // WARN; but ignored
	...
}

All I can make from your email is that you must be in favour of these
patches.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260120105211.GW830755%40noisy.programming.kicks-ass.net.
