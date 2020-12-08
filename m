Return-Path: <kasan-dev+bncBAABBD5MX37AKGQE7B46KMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 38EBB2D2DD1
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 16:04:48 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id o130sf8964606oig.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 07:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607439887; cv=pass;
        d=google.com; s=arc-20160816;
        b=jmq8sIK2Ufw55EVGQBq1ZuCE51dPkCR9Mrbvilc5zCPXY2L8rNmD7RRL0lgs7O8Rnw
         0wQZ4bAPbeaej0XcH7GDv7nXdMt1F50JMNKtgaZjQ9Qry+tRBStxs84eWt+fFYXavGUP
         fjyhZQVu83f3JWSmLQ1Qn6j6GT6DNYcZMQu7v/36tZGeRfqt1lSM3TCvemfdy5CX97oV
         cRlZ190OgA5RFec6MGanFoiShbajcVB/CW0CpQMVJc3xZVZrr/gJ3hSlJpMpku15II6i
         MpAa7EJ9zrrRbkNXUY9KH3azPyevPk5JFU/Zq4yucjbxscwlOiuwrkS5yVoIE/o79fos
         3DsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=wB8YULO2SHeuiRBBnKPaBS1XmwID8KxsJSZ02tE+4Q8=;
        b=TubMn8aV5t+1sqWpd5yIhj3RZN+Sf8k8qvUhxpRQv4E6XMl84h3G6dCxJde5cHcAj5
         OrICOBttmOdbrIGEaBOF6kLXe4WBZ/GbYhI6vgodPgGQdXXeNuDLzhgSKy9iuxAjni9s
         XOpUvZSXDqNHxNztNdTfYnhSoPBmGPlzP1+dcSVMW54PE2NBM7xU4Q0zTz1YJmGEpM2f
         FLs66D9lvU/jJO/1obWd3sQ5DCvvKm7nHNlrytdJ1d6DtcSv3DpBY11yk+H0+uqGe0Ec
         iD07uAQ33PzKbROXCwK8rWVDHaZMA5y+zspuOsiZOZDptJa7la7N6l/RqCBEkx/nkF5L
         2W6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZwBLAa1Y;
       spf=pass (google.com: domain of srs0=lyxh=fm=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lyxH=FM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wB8YULO2SHeuiRBBnKPaBS1XmwID8KxsJSZ02tE+4Q8=;
        b=kHZC4UHYNxjaGrl56HgVlPNBMP4EtfTSwFaPwbNChnU5LpKuJpKe3a7qoHedI/nKKc
         tzztYdRjff/DMFPk1TrUmQD5hHvNQmZaZfMtbr2+G3y3E8tl8woguzblFrZQgg0HpEhg
         OTyEPXZQGUuStj5iTbsXrbUc0vjwKEM38AGMhPQdQtgkpEtyLqkd7VBjd24dO8Tu3Sr4
         sUxPAlXbfV0IBCuBX1C0g9xf6Tm/bo5v/1irSCot0QbeGMbDcdkcYzMfkcV9qqV/fQJd
         YXTynGUO67ubqFI7lU3SiOkc+p98/8h73gRV78cnLDOK/gaI/dSJnbrRoj6TNQmPOc2H
         wYGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wB8YULO2SHeuiRBBnKPaBS1XmwID8KxsJSZ02tE+4Q8=;
        b=mXhy4zK7xiEJv2ilC6zo6pmxmJQU3aaNIWpQAUfOYd/vgq1+U4f/W20molYKrbuv7f
         KJTiUw9yUtmBio1G8Fu1MFhfwLzefSaVOXrTD2cRah6U4aU/dSeKUgGmktHl2zA0nSUa
         0Q37+mOwvJXJA/DMKOFqCuqhHcnmuQBF450IiFCqLj9LC1uqw+sYkckZvVak7SPJLwsf
         4ilg5EDsZWamaOPS9HpU4VmZ2BzfByyT8tunN5EiX5oeRP+ecS5X75zsiAo06DGouX0S
         q+bfXd/hfTOrI0LGpgHvu6rlw7yadMstMDMbtH0hi9iI96QogM8KC3aWO7TH+XeGIaz9
         s+vA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530r7rVEKnUPlw5CVqHZQarubkPf2Le0iRz0ASMhb5T8pUjkZL1D
	meWM7cEThCuL5yVBwfz7EVc=
X-Google-Smtp-Source: ABdhPJyIqNnUjgENEChjBl/lYESPOfHekGg7Xtbgxrm5jAUj0/usCsCf8+NbsuewLGZIz3gQWpVOSg==
X-Received: by 2002:a9d:7a4b:: with SMTP id z11mr13322564otm.305.1607439887090;
        Tue, 08 Dec 2020 07:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:648d:: with SMTP id g13ls5163085otl.0.gmail; Tue, 08 Dec
 2020 07:04:46 -0800 (PST)
X-Received: by 2002:a05:6830:1d71:: with SMTP id l17mr499901oti.269.1607439886800;
        Tue, 08 Dec 2020 07:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607439886; cv=none;
        d=google.com; s=arc-20160816;
        b=pNFd8N6ZOsU5FGUPvtWfkEtqNt04aUAHSl5enMtaNFcJVLa1UcDj1s2jFpazvvwIjO
         LxSJhVANYDqrtADvZ7b4W6O57ePd7cVLYz4ub+eQ35lGnmJyFGQwsy76jwpAS/wqUX4+
         tkhHhVriBXQiMLtqF3pjSIgYpBj5BrhdDXuc2U4sZR0189HS+0VDALDfLYT0d6PsII1C
         Q+4H0ncc809Pc5xwLN0TWegotnyGnXG7sruojEWHRraR9FqmZ+vEPUxb82mLe3QjeckP
         Kogutc2N/ZpmqCBC34Q7VF6sSmUfRMCX4uXeCxuP9ebkBP/DIvH/n0rsS+2UDPW3Nngx
         HkWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=xBkdFn7EL+OXGCPtl/SSVhBMOevVo3JorkuQReAK8NI=;
        b=d9tRRLCAPXaCUHYu1CISK+cXbIy3fnqg0xKqvSeyz76PG8/lfP9Gf7Kw8nB4yDO7x4
         zYzWBPs5oL4yNybzLxvAZFO+VGj0rNftu9I/dxiyVinSh0gxthLxXb6gnM+rPaEQt4eG
         KqdbfcvsueCp0q5WJQjQ3KVisZjAoDqivZIrX5HqBE9dpkXcqv3RRFM4v0uKEYakXbsa
         EHERut39AkTFzi2kL8Ttrd0IurWhxPHJidqUfqJjcqeYTvxokhG3W0bpEzQl6K6+Sf2j
         V67qylsAYgUZp9X3zvpufCB7ceLK1Hb+jBYywYltQ0JTMB5lh/P4qq+99KVVCMPjAQC6
         XTDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZwBLAa1Y;
       spf=pass (google.com: domain of srs0=lyxh=fm=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lyxH=FM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u2si97081otg.1.2020.12.08.07.04.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Dec 2020 07:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=lyxh=fm=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Tue, 8 Dec 2020 07:04:46 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>
Subject: Re: timers: Move clearing of base::timer_running under base::lock
Message-ID: <20201208150446.GQ2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <87lfea7gw8.fsf@nanos.tec.linutronix.de>
 <20201207130753.kpxf2ydroccjzrge@linutronix.de>
 <87a6up7kpt.fsf@nanos.tec.linutronix.de>
 <20201207152533.rybefuzd57kxxv57@linutronix.de>
 <20201207160648.GF2657@paulmck-ThinkPad-P72>
 <20201208085049.vnhudd6qwcsbdepl@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201208085049.vnhudd6qwcsbdepl@linutronix.de>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZwBLAa1Y;       spf=pass
 (google.com: domain of srs0=lyxh=fm=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=lyxH=FM=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Dec 08, 2020 at 09:50:49AM +0100, Sebastian Andrzej Siewior wrote:
> On 2020-12-07 08:06:48 [-0800], Paul E. McKenney wrote:
> > > Yes, but it triggers frequently. Like `rcuc' is somehow is aligned with
> > > the timeout.
> > 
> > Given that a lot of RCU processing is event-driven based on timers,
> > and given that the scheduling-clock interrupts are synchronized for
> > energy-efficiency reasons on many configs, maybe this alignment is
> > expected behavior?
> 
> No, it is the fact that rcu_preempt has a higher priority than
> ksoftirqd. So immediately after the wakeup (of rcu_preempt) there is a
> context switch and expire_timers() has this:
> 
> |   raw_spin_unlock_irq(&base->lock);
> |   call_timer_fn(timer, fn, baseclk);
> |   raw_spin_lock_irq(&base->lock);
> |   base->running_timer = NULL;
> |   timer_sync_wait_running(base);
> 
> So ->running_timer isn't reset and try_to_del_timer_sync() (that
> del_timer_sync() from schedule_timeout()) returns -1 and then the corner
> case is handled where `expiry_lock' is acquired. So everything goes as
> expected.

Makes sense!  Thank you for the explanation!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201208150446.GQ2657%40paulmck-ThinkPad-P72.
