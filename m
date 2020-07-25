Return-Path: <kasan-dev+bncBCV5TUXXRUIBBLND6L4AKGQES55FPII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EC2B22D9C7
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 22:10:21 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id t3sf1713995wrr.5
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 13:10:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595707821; cv=pass;
        d=google.com; s=arc-20160816;
        b=PWvckOCwwUqQvCyzs/ASiE6u6/J14uSGUf7LVwKBCYglvWRSfXKhxznfkStCS93b3e
         S38Iwty72SymwdUHQdYpXmflAJNZ+Iwulo2QJwxC3GxfMSX43T1L434II2AyQfh88K5L
         QwtvBq/m88VmAWYK+kxVmfTvHLPoFeT2vz75pHPzP5IZeITTvDZWpE6Z1tQWdtD8JF33
         h4RZEUrMzp262W3AKmB4XmWDbYb7tKiam9XQj27U5ZAQhuyts12KiYp031KTJiNJ98pi
         DeSpqw1yZ8Sz8h4vAW50K2QyMh1f1U0RZ5FRcq4hDWDQC5iqDxOIp04322zchA/hEc4S
         5vgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tY8yws3zRsOsa5gaKskQaPMALXRD/VWk+2c1kTNjP3A=;
        b=faXHiLbGqHVehRXTI42C87zfTMKwKdyOhMT+XZkWaqjDwbUE53FXQNaH61luPSCpDU
         rHjK6W/eG23fMBeRO00vnKyB0aEgRYepb8+0jVrmce3mB4ogLdPbD4dAR4KfhpKGxIZs
         Pw0DsF5ffqJtXyhcFGu3r2nsFfvx1ca6Yzd973BC04V2PRjrtwhQycv+GWnOMITqQVTF
         d/E5Pq+kgdhUuaIBzEdmbiIs+Kq19Fh6YJFANYk9jve48TURJnJdmT/4HfqCbv9est3Y
         bVznsMDr6mty0tX+fFRKls15YD2jKvgMQgNIWy1Ou7gxAnKbHhXu/uD+TBzmeg3yPy5b
         HqCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=KOcxNFyF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tY8yws3zRsOsa5gaKskQaPMALXRD/VWk+2c1kTNjP3A=;
        b=XpbBnXehWYL9pWqq6vsoK8IFKLYaP2n1k2rU3guqFBiL+vPRJasR3DJfwCxu/kjJFh
         6f8FSBNL9gw/PJ9ALWTPgoSZJt0hv8lGHDcSLVGuYdmh1R4aNaUrygcfGLH0n/pSoTKG
         e+5jlR7mkINMMHobPMTEmTDt2KBKELNGlf3o5oV50f4AWyvpzmTMmRVZNnFbkAUI53w4
         n2ieZulhRXxNITzxrCVe8dRATvbo0jZa++RZ56GIaEX3fatoSb+8Rn392kJYyaAXX2Fs
         DWL3kowSE4htZfN0KgnNA+TzRfHWm7cMLL+bKW5KdcDh6hYXF6hPsCxTjFfC3gl54kFc
         8ydg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tY8yws3zRsOsa5gaKskQaPMALXRD/VWk+2c1kTNjP3A=;
        b=oEJjDFkn50UW3iXcVo1gQ1+BB5FXfuvA4DeZSz/8ejbZU86uN3OsNvqvTfATcWZVgM
         TeqVYvd5BXShvO+2HhSN8ZmZUpjYwrH6bm8QnA3ihMEuLOIxfyo+e2O3lNUz9mbGQc9C
         WQGj+DCW1n9nATfWjoAp7aWornENKGEdzttOE6B5JvBFDLRYpe0ewGB6RfTv2bVAi7VT
         i2W2Dh2cDfAwn6Vm1e9+WxXeWSKzwZKcKZvDRv3LMwtUmoOm4//joz6UFji3aFnU7uAA
         H2CYZEoJoD2ljdL3w6oO2kR2sfMCojX+3nbagNbU/tKWwR8aD45w6csNTZn36SlKtDvp
         rwZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Vy7LtnZ9XkWpTXu6nt0nm6O+6MNiVpEk33TLQGWjoxAAHjoFN
	4VeWgf2/p0lOyYWdSHQhdoA=
X-Google-Smtp-Source: ABdhPJwP7sP+SsOvzTEWP1ujah25uNrEJaCL4baq91tRnRvHcRMApYXKPS2nimXoqRav+4w9bacNJg==
X-Received: by 2002:a5d:438c:: with SMTP id i12mr14645943wrq.210.1595707821322;
        Sat, 25 Jul 2020 13:10:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:81f4:: with SMTP id 107ls3601208wra.2.gmail; Sat, 25 Jul
 2020 13:10:20 -0700 (PDT)
X-Received: by 2002:adf:f151:: with SMTP id y17mr6471959wro.179.1595707820766;
        Sat, 25 Jul 2020 13:10:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595707820; cv=none;
        d=google.com; s=arc-20160816;
        b=omN30FpVMhKvBe7/d5Ugw4jYY2AbBVmDrkP/CaBTjBwDPWFeBds+cRonHAV6/WZKLI
         F1amOE5KHsiyqii74pPNYbgDrE2pGSM2BNmRZGe5XZUliGc+u5ArDQojTrchP58+wMOA
         uLyfNemFAXNdM4Er+b+jWBOQGcEgY+kC8LYBpryLa+vyWyORPVP2rJzEPhvLnS+lbXxi
         /hqorwdW59ODj5KTxJCOzyybOylYNfmFQ4Mw++7bust2BR369vBi28CVrxqtqTB7vv6g
         PpR6slAyesZWOm+zRPZmvCQn3i4YCLh+XcBkbQLFJlgrFcGcyK8n1jeW5dhpj3/HrHnO
         O8mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Pw5RUMobivqcNCfDWDHWYkXzCXE5qOoVsxCJP/NEQ88=;
        b=JW0U9aikOcaSvvDNc5rqPBZii/+nNrXAGGm2zHofkYzECJ3xbwPSlHyLYisnLmKM7R
         uB3gHQyGQbonlemKpwWSBImw7dIzuWU2jjhKkqxit5ZI/Q8Z1CXz7MTEcmIgXq/J+h5d
         zhFngrA3YZItewHuGufCvLxNDyGu7YP2pGXDL98qZVUHu8MWWe9GhXYcTeBy7p3NDsWC
         0Ifg9CHmjmM1AHTdOYUmM5uLYfWD0A2dgS8ftq+ARKRp9YfDP2sLoGR5WdKsEJWFxKnw
         cq4o3DWFr6YsvS1VZ4j9l0gVqh8AVwq3Rt5K4RVlF/vK1mlEI8CE8f+D4DW1NdESK8hU
         E9hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=KOcxNFyF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id h10si267905wml.2.2020.07.25.13.10.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 25 Jul 2020 13:10:20 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jzQUr-0008Hv-PC; Sat, 25 Jul 2020 20:10:19 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 757B03013E5;
	Sat, 25 Jul 2020 22:10:13 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 6045B2B8A8164; Sat, 25 Jul 2020 22:10:13 +0200 (CEST)
Date: Sat, 25 Jul 2020 22:10:13 +0200
From: peterz@infradead.org
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200725201013.GZ119549@hirez.programming.kicks-ass.net>
References: <20200220141551.166537-1-elver@google.com>
 <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
 <20200725145623.GZ9247@paulmck-ThinkPad-P72>
 <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
 <20200725174430.GH10769@hirez.programming.kicks-ass.net>
 <20200725193909.GB9247@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200725193909.GB9247@paulmck-ThinkPad-P72>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=KOcxNFyF;
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

On Sat, Jul 25, 2020 at 12:39:09PM -0700, Paul E. McKenney wrote:
> On Sat, Jul 25, 2020 at 07:44:30PM +0200, Peter Zijlstra wrote:

> > So the thing is, since RCU count is 0 per context (an IRQ must have an
> > equal amount of rcu_read_unlock() as it has rcu_read_lock()), interrupts
> > are not in fact a problem, even on load-store (RISC) architectures
> > (preempt_count has the same thing).
> 
> True enough!
> 
> > So the addition/subtraction in rcu_preempt_read_{enter,exit}() doesn't
> > need to be atomic vs interrupts. The only thing we really do need is
> > them being single-copy-atomic.
> > 
> > The problem with READ/WRITE_ONCE is that if we were to use it, we'd end
> > up with a load-store, even on x86, which is sub-optimal.
> 
> Agreed.
> 
> > I suppose the 'correct' code here would be something like:
> > 
> > 	*((volatile int *)&current->rcu_read_lock_nesting)++;
> > 
> > then the compiler can either do a single memop (x86 and the like) or a
> > load-store that is free from tearing.
> 
> Hah!!!  That is the original ACCESS_ONCE(), isn't it?  ;-)
> 
> 	ACCESS_ONCE(current->rcu_read_lock_nesting)++;

Indeed :-)

> But open-coding makes sense unless a lot of other places need something
> similar.  Besides, open-coding allows me to defer bikeshedding on the
> name, given that there are actually two accesses.  :-/

Yeah, ISTR that being one of the reasons we got rid of it.

> So:
> 	(*(volatile int *)&(current->rcu_read_lock_nesting))++;

Urgh, sorry for messing that up.

> This gets me the following for __rcu_read_lock():
> 
> 00000000000000e0 <__rcu_read_lock>:
>       e0:	48 8b 14 25 00 00 00 	mov    0x0,%rdx
>       e7:	00 
>       e8:	8b 82 e0 02 00 00    	mov    0x2e0(%rdx),%eax
>       ee:	83 c0 01             	add    $0x1,%eax
>       f1:	89 82 e0 02 00 00    	mov    %eax,0x2e0(%rdx)
>       f7:	c3                   	retq   
>       f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
>       ff:	00 
> 
> One might hope for a dec instruction, but this isn't bad.  We do lose
> a few instructions compared to the C-language case due to differences
> in address calculation:
> 
> 00000000000000e0 <__rcu_read_lock>:
>       e0:	48 8b 04 25 00 00 00 	mov    0x0,%rax
>       e7:	00 
>       e8:	83 80 e0 02 00 00 01 	addl   $0x1,0x2e0(%rax)
>       ef:	c3                   	retq   

Shees, that's daft... I think this is one of the cases where GCC is
perhaps overly cautious when presented with 'volatile'.

It has a history of generating excessively crap code around volatile,
and while it has improved somewhat, this seems to show there's still
room for improvement...

I suppose this is the point where we go bug a friendly compiler person.

Alternatively we can employ data_race() and trust the compiler not to be
daft about tearing... which we've been relying with this code anyway.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200725201013.GZ119549%40hirez.programming.kicks-ass.net.
