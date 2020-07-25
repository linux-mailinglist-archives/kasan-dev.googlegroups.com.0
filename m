Return-Path: <kasan-dev+bncBAABBXUU6L4AKGQEZKTGHPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FE8522D99A
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 21:39:11 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id j7sf8890905qki.5
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 12:39:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595705950; cv=pass;
        d=google.com; s=arc-20160816;
        b=CjdYTDbp63O+9evs9Vcr9i1pIChQYr9ftBaxclf0uVES5YGCiBT8+QjCTNTXhrTfDD
         P3NqnimJtEzNnWho5fPuIZr3EPZYGyLoj94unlKpHQM44Gmjz+kys15SdmuZqciYH0xE
         p6n6SGBTqwvACWsipcbwtqDYUom/lF9SPsf3qj7cfVxYmqTNjU0ne8KGRrmSpTaU33my
         +IEeA8ftwWWtPxu41vR/45WzsNvHEDk4NUoRhfnnyQMpveOp4jfvoZ4bonTeYyyZtT5j
         ag5RM9NMcw+o0j4uKZ8dEUcsF72Rq1ZaKdI2GBhbyOcs+1sHuFhucpjRU8EfYYG7x13b
         RRYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=CbULAExkVis3/ZkmfonVlfO1izxK4j4+hZUm1N5T/fE=;
        b=L0q43TuisMk0ki5U9k61bFmc0yIvt7hphGrCCKSQRK22Dpn5WsMFIanwuvu5AUeSyx
         JOj9d4Kf+oDTF66hX1eyjlqV7CuNzqe6p8e2h5kVPi45hCgpxENy0HXUObUX8PdB/dyV
         odBodS4P+tEZ3NGZeuqFUio7hd8Q2zUcAzVNfXX0jSR57Mg8FegX3Fbg+itMgUjegNnV
         Q5gqHd8ebP4BxR0iLjGbbQ2TdZQTfatlP0wrsD+mpXyv6qbWb0Sejx/3+1mnSMjUiHP5
         bpSz3/2rzzN6Sq87L+zb+kdMRsuYcJT6cTaEezQMscSoljGWOQKZjlUwTQr+gPCsqVBq
         W8KQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Wx8JwBnf;
       spf=pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CbULAExkVis3/ZkmfonVlfO1izxK4j4+hZUm1N5T/fE=;
        b=mGWofDmHjuPqHPq+FF8OrCHwDjErB7Lcg1RNr6j00dBJvcYTMw0fA491TkAt+fbVJ2
         pCG18uboRcwaJZxfDvmf5pNInW7LU/DeGKxEduGbfW4761SksgwZOicAT1kBK969gBpp
         hmx0Vgn5Bl2ibxBKny4QZRob6NS+4bVTwCn3xjHK+nhlxxMjXWMp+sIjLiWWeVzhmzSy
         na+hmE1aAoICiPqeL+P9IDeHMBFSH0gtJQlcOnG8f5sxBbv46RFnO3pR8ivf8QfSdvXg
         vq5sr09mj/jWyLvoeISEO/0qpU4XMKCF/7Yryyx5JDyrjp+eOpk6s7FAMNT9Qj96YEc8
         V25w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CbULAExkVis3/ZkmfonVlfO1izxK4j4+hZUm1N5T/fE=;
        b=H6V8SzgRDNX8Uk1qVtl4DDbh8zjllImWFbyFsP2RiUl1WnENH5S2IOHahJwwpOV3+p
         DSJ8Ypbwj159utjlOwRqTJxtWif4gTfQUBszn9eMKqyvmRpWRrH4ZjnAWkhMfA0/jt9y
         IjXp2zXekfdNo2P+nQcWzKxKRUQDnL6C5BefW/rc48n4+ATH+QKdNP0rLq2Q04MLEdAM
         G9AjkZc6WNyJI76gaHpfbPdKkHpWRZvN56qhxG7ifQThrvCCIWmkroehz0CGdZpY78vU
         g+gI2SRotI8AhgQmyzWyNug6Xkmd6fX6hCuHHxIoBO5ekJKw9Iprb+UbVDp5dfEb38KC
         L9xw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532wUyeAY/5JcE6wrk8MntJj9rUiL3iTv5rYDYRCQHTwOvYOLSzJ
	zfQMro1Q1Eh73QVO7xAjEpE=
X-Google-Smtp-Source: ABdhPJyzzfN76pwJCv9b8M8s5TPj8ddPZct02fp71mSpCndAndY3I+bq1/6RZlZ5jiKUvNON6Gng8A==
X-Received: by 2002:a37:44c6:: with SMTP id r189mr16652155qka.235.1595705950593;
        Sat, 25 Jul 2020 12:39:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:786:: with SMTP id 6ls6209197qka.0.gmail; Sat, 25
 Jul 2020 12:39:10 -0700 (PDT)
X-Received: by 2002:a37:4916:: with SMTP id w22mr16896599qka.246.1595705950285;
        Sat, 25 Jul 2020 12:39:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595705950; cv=none;
        d=google.com; s=arc-20160816;
        b=XU8hLhU6exyJ8IFeNeZffm0Mg5KQhpv17/ulRZqrQVcZRYsD4cJm6qShc4t7xYX6oa
         4KAvVHrtNFeF4xS4fbDD0DLEWJAdJxce44qUbVWbz92ukXMAyEFlDY4bscShFbILJPIW
         0Kj3pbyn/WjdfouvHxAwgZuC7HBUx1Fq3/GneNths1BJFnKBCczJXafCieBzG0rNQ23I
         N2x3OFKOLc+Fqs1WeIw+FQuUI9y5DScz6bFRuC/Z6ShR0NVZvtXqTaWm8sibQkiLO6Pv
         uCzAHVAL6czGlqf4v3FHRKDIaECTDJXzCW7e/6DoRfXEBmqyoEtlrX21XpxmXS2RIjDX
         BvCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4Ffcjjap3DxsaA3A/5TApp2xdOnvXOUywtudTVEVogM=;
        b=AdJwNjnF7z10WYu5at+5ahy7MLJBqHqyvd43sYgZBKl6tX3i8qENc5gC5CRigmvlph
         HUBXdM97LKt0YDb7EsC0luMZUlNeErPXwsNDKtoqtrHSIjD+C4CygQvvEtZviYM+zFxu
         gGbZ5NBvgLdcixYqhGZrcGcdb4zDQWangZinymaLa6C9Ax+Rub4sJ55MCw8wb5nPijKu
         8yveUbWrn0ZtALBD/APHyPcOiTURu+qCVN0OrRokCbeh/oYQ0Igmhx9Rod8bVlgv54B2
         mSXZ6EFbr4HxDLk7sK8U1GjM9fJU0+ZFQOlk18UhvQVPCfZmYoUSFe2CTlYVbm4pS/yM
         IaYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Wx8JwBnf;
       spf=pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f38si150311qte.4.2020.07.25.12.39.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 25 Jul 2020 12:39:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-111-31.bvtn.or.frontiernet.net [50.39.111.31])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 25451206D8;
	Sat, 25 Jul 2020 19:39:09 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 0C9343522767; Sat, 25 Jul 2020 12:39:09 -0700 (PDT)
Date: Sat, 25 Jul 2020 12:39:09 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200725193909.GB9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200220141551.166537-1-elver@google.com>
 <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
 <20200725145623.GZ9247@paulmck-ThinkPad-P72>
 <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
 <20200725174430.GH10769@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200725174430.GH10769@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Wx8JwBnf;       spf=pass
 (google.com: domain of srs0=ej9m=be=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=eJ9M=BE=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Sat, Jul 25, 2020 at 07:44:30PM +0200, Peter Zijlstra wrote:
> On Sat, Jul 25, 2020 at 05:17:43PM +0200, Marco Elver wrote:
> > On Sat, 25 Jul 2020 at 16:56, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > On Thu, Feb 20, 2020 at 10:33:17PM +0100, Marco Elver wrote:
> > > > On Thu, 20 Feb 2020, Paul E. McKenney wrote:
> > > > > On Thu, Feb 20, 2020 at 03:15:51PM +0100, Marco Elver wrote:
> > > > > > Add option to allow interrupts while a watchpoint is set up. This can be
> > > > > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > > > > > parameter 'kcsan.interrupt_watcher=1'.
> > [...]
> > > > > > As an example, the first data race that this found:
> > > > > >
> > > > > > write to 0xffff88806b3324b8 of 4 bytes by interrupt on cpu 0:
> > > > > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]
> > > > > >  __rcu_read_lock+0x3c/0x50 kernel/rcu/tree_plugin.h:373
> > [...]
> > > > > > read to 0xffff88806b3324b8 of 4 bytes by task 6131 on cpu 0:       |
> > > > > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  ----+
> > [...]
> > > > > >
> > > > > > The writer is doing 'current->rcu_read_lock_nesting++'. The read is as
> > > > > > vulnerable to compiler optimizations and would therefore conclude this
> > > > > > is a valid data race.
> > > > >
> > > > > Heh!  That one is a fun one!  It is on a very hot fastpath.  READ_ONCE()
> > > > > and WRITE_ONCE() are likely to be measurable at the system level.
> > > > >
> > > > > Thoughts on other options?
> 
> > > > diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
> > > > index c6ea81cd41890..e0595abd50c0f 100644
> > > > --- a/kernel/rcu/tree_plugin.h
> > > > +++ b/kernel/rcu/tree_plugin.h
> > > > @@ -350,17 +350,17 @@ static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp)
> > > >
> > > >  static void rcu_preempt_read_enter(void)
> > > >  {
> > > > -     current->rcu_read_lock_nesting++;
> > > > +     local_inc(&current->rcu_read_lock_nesting);
> > > >  }
> > > >
> > > >  static void rcu_preempt_read_exit(void)
> > > >  {
> > > > -     current->rcu_read_lock_nesting--;
> > > > +     local_dec(&current->rcu_read_lock_nesting);
> > > >  }
> > > >
> > > >  static void rcu_preempt_depth_set(int val)
> > > >  {
> > > > -     current->rcu_read_lock_nesting = val;
> > > > +     local_set(&current->rcu_read_lock_nesting, val);
> > 
> > > I agree that this removes the data races, and that the code for x86 is
> > > quite nice, but aren't rcu_read_lock() and rcu_read_unlock() going to
> > > have heavyweight atomic operations on many CPUs?
> > >
> > > Maybe I am stuck with arch-specific code in rcu_read_lock() and
> > > rcu_preempt_read_exit().  I suppose worse things could happen.
> > 
> > Peter also mentioned to me that while local_t on x86 generates
> > reasonable code, on other architectures it's terrible. So I think
> > something else is needed, and feel free to discard the above idea.
> > With sufficient enough reasoning, how bad would a 'data_race(..)' be?
> 
> Right, so local_t it atrocious on many architectures, they fall back to
> atomic_t.
> 
> Even architectures that have optimized variants (eg. Power), they're
> quite a lot more expensive than what we actually need here.
> 
> Only architectures like x86 that have single instruction memops can
> generate anywhere near the code that we'd want here.
> 
> So the thing is, since RCU count is 0 per context (an IRQ must have an
> equal amount of rcu_read_unlock() as it has rcu_read_lock()), interrupts
> are not in fact a problem, even on load-store (RISC) architectures
> (preempt_count has the same thing).

True enough!

> So the addition/subtraction in rcu_preempt_read_{enter,exit}() doesn't
> need to be atomic vs interrupts. The only thing we really do need is
> them being single-copy-atomic.
> 
> The problem with READ/WRITE_ONCE is that if we were to use it, we'd end
> up with a load-store, even on x86, which is sub-optimal.

Agreed.

> I suppose the 'correct' code here would be something like:
> 
> 	*((volatile int *)&current->rcu_read_lock_nesting)++;
> 
> then the compiler can either do a single memop (x86 and the like) or a
> load-store that is free from tearing.

Hah!!!  That is the original ACCESS_ONCE(), isn't it?  ;-)

	ACCESS_ONCE(current->rcu_read_lock_nesting)++;

But open-coding makes sense unless a lot of other places need something
similar.  Besides, open-coding allows me to defer bikeshedding on the
name, given that there are actually two accesses.  :-/

Ah, but that gets compiler warnings:

kernel/rcu/tree_plugin.h:354:52: error: lvalue required as increment operand
  *((volatile int *)&current->rcu_read_lock_nesting)++;

Let's try the old ACCESS_ONCE().  Dialing back to v3.0:

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

So:
	(*(volatile int *)&(current->rcu_read_lock_nesting))++;

This gets me the following for __rcu_read_lock():

00000000000000e0 <__rcu_read_lock>:
      e0:	48 8b 14 25 00 00 00 	mov    0x0,%rdx
      e7:	00 
      e8:	8b 82 e0 02 00 00    	mov    0x2e0(%rdx),%eax
      ee:	83 c0 01             	add    $0x1,%eax
      f1:	89 82 e0 02 00 00    	mov    %eax,0x2e0(%rdx)
      f7:	c3                   	retq   
      f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
      ff:	00 

One might hope for a dec instruction, but this isn't bad.  We do lose
a few instructions compared to the C-language case due to differences
in address calculation:

00000000000000e0 <__rcu_read_lock>:
      e0:	48 8b 04 25 00 00 00 	mov    0x0,%rax
      e7:	00 
      e8:	83 80 e0 02 00 00 01 	addl   $0x1,0x2e0(%rax)
      ef:	c3                   	retq   

For the relevant portion of __rcu_read_unlock(), this gets us
the following:

00000000000027f0 <__rcu_read_unlock>:
    27f0:	48 8b 3c 25 00 00 00 	mov    0x0,%rdi
    27f7:	00 
    27f8:	53                   	push   %rbx
    27f9:	8b 87 e0 02 00 00    	mov    0x2e0(%rdi),%eax
    27ff:	8d 50 ff             	lea    -0x1(%rax),%edx
    2802:	85 c0                	test   %eax,%eax
    2804:	89 97 e0 02 00 00    	mov    %edx,0x2e0(%rdi)
    280a:	75 0a                	jne    2816 <__rcu_read_unlock+0x26>

Here we have a load-subtract-store, but given that we need to test
the value, this seems reasonable to me.  We again lose a few instructions
compared to the C-language case, and again due to address calculation:

00000000000027e0 <__rcu_read_unlock>:
    27e0:	53                   	push   %rbx
    27e1:	48 8b 3c 25 00 00 00 	mov    0x0,%rdi
    27e8:	00 
    27e9:	83 af e0 02 00 00 01 	subl   $0x1,0x2e0(%rdi)
    27f0:	75 0a                	jne    27fc <__rcu_read_unlock+0x1c>

Thoughts?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200725193909.GB9247%40paulmck-ThinkPad-P72.
