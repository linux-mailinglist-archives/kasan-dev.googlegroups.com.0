Return-Path: <kasan-dev+bncBAABBN5D4D6QKGQERHT2R5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F35A2BB3FF
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 19:58:00 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id x3sf7088433plr.23
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Nov 2020 10:58:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605898679; cv=pass;
        d=google.com; s=arc-20160816;
        b=GvOjklKxYQfjgKZOobb4ZS7kv05MFDUpVMSJH4ANSWyMT95CTIS/h6KVYrfe7h9zRh
         uFg2b6SaPKKLU6lDvwwnG3Udk2bMBLRz9UszA1h5SOf5NEmlrlwzfHsGHSKS6BMv9+ra
         5g1JedRrEf93sk5iHWrxr88kyJtKicrRryU8sW8rDFav63Bjyss3q936fkiPhcaA0Iq2
         YHwnuoe0BRw9WaobyfKKQjdDJJFPZGzKDQv3mrVq4VtjHGQZCQViwGQar7e9wofzg7tM
         SeGUIIDNrZ3N7POpFUHbjUZV1bhMlZ58o3PWipMFTVDbjbXg6BTgxmdwCQYyH6sc+Jp3
         6mfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=+6XjHRs65K4MXYhoD5ffbzrSLWI96tFYvKvobW60hhU=;
        b=IdhKx5VEiyYKgFVvIr3C0yqnuu/hllG8NZgv0nlcvBg+0ZuiueHpVyqaLigeBcKHHZ
         M9vAsN18ZMOazdmW6ahooDw2Zf2Uc3hifnEYhilTPwyxwaU55HwV0+283HkbKEGvh2ht
         F+eVPFX0JhiRtj4JR7voC+ba5MPLEe6hjybnuVS+jksV3jOstIi41OJAu+PQjMdjGkuv
         EfRvh1LYsxXZqtyqQX3PkkFpsE3mUuqr7aejgRMcNh0ssJcwyF8Ra0tQyOPBrV5uhW6O
         O+ZrtwPI3IJAffKpYzjqvF8oKj94wlcmhQULCyNqqBNPiQF1G9SO9qS7gTOzPVO4crwO
         tF5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wJPsspjB;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+6XjHRs65K4MXYhoD5ffbzrSLWI96tFYvKvobW60hhU=;
        b=j8rfm/jUuu/uiqE9tteeS5OBaehqEhp8IHrAoLyXtChDNNOIHkQRbT67qImtzd2u5K
         TujRClXfJ50kq/QP1BLNg+JL+NZNZOpogzXUx3qIDiWflUgHAXOFuydvrKFrULinLbUg
         L2FkU3HVvWWyRQpjrsuo5LT4hOWLsqMKMAPzMpt5wdT8bgs3MHAbBw+bRTG5MPcDDfU4
         o+5CzsZ35ccRbzMUd1dndXL14cXFPTrt8SveXUdoS63dO3gsDxhxfjT8myO9MoUHVXK1
         eREZft48Dk3vqDBl1V64Ubdi+6s1fYz7Ljl1Bv16ngHaOTrBoSK1oS2Ac5Ij3h38nzaH
         h2Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+6XjHRs65K4MXYhoD5ffbzrSLWI96tFYvKvobW60hhU=;
        b=NMFSpkKMT/PmDrkE51sYyebSsNpCIH1xX79PM3ZCJRJfgxjV8r8qZfkJymNUZ45Ko+
         +rYxpuN+qvOeCIh+mHwTLgee8CduB1WUWrTVadsQbAARjoHNRjR3pcxZtFNF8YHM5Pef
         vpzwCnBAuJwG8IDfwEa8vxSDcLN+hYt4GrH6riQnpVnHf7ID5j9tNJZ7X+Mjs1fMvyz1
         JVwtHE4S0j1y/SXQUAAvMQBSgvkBCnF87KGviJiCDeJSXFNN6MR0CGcMRRqnqroi7ORo
         uvnLw9q7Ui/b3MVHImzNh6Oze1wR3kGkoKQ+1AvF1zChHI9sQS+WrWVAePXVEzv16MKP
         V6rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531aOG2TwdBSeKwmw1L7RsQ8ygtNx23MqOngOn84K8IYgOfg29Mj
	/o4dB/Aw4RvFQFt0rlihq7Y=
X-Google-Smtp-Source: ABdhPJyumIzxw7Ag7l8UQ1VOgFIMIW+/X7TOUXjfOrfWOwpOqdpVylwIN6pLYQyj/wrYyAzcygKxgA==
X-Received: by 2002:a17:90a:ee87:: with SMTP id i7mr10578181pjz.89.1605898679176;
        Fri, 20 Nov 2020 10:57:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c113:: with SMTP id 19ls3538667pli.11.gmail; Fri, 20
 Nov 2020 10:57:58 -0800 (PST)
X-Received: by 2002:a17:902:b582:b029:d6:6008:264d with SMTP id a2-20020a170902b582b02900d66008264dmr14747723pls.80.1605898678663;
        Fri, 20 Nov 2020 10:57:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605898678; cv=none;
        d=google.com; s=arc-20160816;
        b=oh4RC+aE4LNuSkBRUdP1kcycUtd/+1GvkCew77xnlS9hgJEBdYCDLzTRIQlbn0vM1D
         z+fdDUaa7Ezq5ySVtZlqbVQwWfhX6X6NwD1qUEeg+JFs1A3fLsiQmZ4KRCgwdN6wB+va
         6idoRE/ebdl3gAXKZ3i2QuHY9wdiAbccnoZ4YjT1O2nkUTKFgXhpe8cxlFm2HoYGmR0s
         c5jEvablKbhOI3kPfGEmHvQ/irfxGJxhZXZJ3XVcBcZjIGX8IvUf6jIMpS/i107dY4DM
         bV/HGZP/Hw5+y9BCQEpTw9L7mIfRT3Nl9fYSQqoQ99+gTwVg2sr4Pgze0MFkRRw6/58n
         9sIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=wU6gkQj7TSeLw0/pJ9KekwpgvUr4XxwhC4H75OmSIpc=;
        b=DDcIaMYg23Ptoee6tiAkMTlsuLEwKAGUouIFYB5eONXh+w7a/YEuFLSXVnRXcUcWms
         fE3tfpYVYwYBfb1XvZjJvsyuE+zauWXdo/Cb2iUUsyB9cJJtRk11XwWwISKiJAX1T5Ve
         1W01l0w2mk1ZXr26AL++dZHdlg68dlaxlQcSSjCPPvuPUFi6kMdYkB1z6AqaU/frkadi
         I5r06BCpwnuQLF0ui78vwH+pGtdDmT/CwP93KvFeyOopqGD3xNZ0B46NfmzsGJ7FEZZz
         puZvYe38LOn+HP/amkzfNwXuJfPWEPc4O/h1w3f1Xtqal7g9HPsTZL0A7lnZOomh2UFn
         Yy7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wJPsspjB;
       spf=pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g4si447208pju.0.2020.11.20.10.57.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 20 Nov 2020 10:57:58 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4C01222464;
	Fri, 20 Nov 2020 18:57:58 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id E2B203522637; Fri, 20 Nov 2020 10:57:57 -0800 (PST)
Date: Fri, 20 Nov 2020 10:57:57 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Steven Rostedt <rostedt@goodmis.org>,
	Anders Roxell <anders.roxell@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux-MM <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>, rcu@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>, Tejun Heo <tj@kernel.org>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	linux-arm-kernel@lists.infradead.org
Subject: Re: linux-next: stall warnings and deadlock on Arm64 (was: [PATCH]
 kfence: Avoid stalling...)
Message-ID: <20201120185757.GL1437@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201119151409.GU1437@paulmck-ThinkPad-P72>
 <20201119170259.GA2134472@elver.google.com>
 <20201119184854.GY1437@paulmck-ThinkPad-P72>
 <20201119193819.GA2601289@elver.google.com>
 <20201119213512.GB1437@paulmck-ThinkPad-P72>
 <20201120141928.GB3120165@elver.google.com>
 <20201120143928.GH1437@paulmck-ThinkPad-P72>
 <20201120152200.GD2328@C02TD0UTHF1T.local>
 <20201120173824.GJ1437@paulmck-ThinkPad-P72>
 <20201120180206.GF2328@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201120180206.GF2328@C02TD0UTHF1T.local>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=wJPsspjB;       spf=pass
 (google.com: domain of srs0=zhla=e2=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ZHLA=E2=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Fri, Nov 20, 2020 at 06:02:06PM +0000, Mark Rutland wrote:
> On Fri, Nov 20, 2020 at 09:38:24AM -0800, Paul E. McKenney wrote:
> > On Fri, Nov 20, 2020 at 03:22:00PM +0000, Mark Rutland wrote:
> > > On Fri, Nov 20, 2020 at 06:39:28AM -0800, Paul E. McKenney wrote:
> > > > On Fri, Nov 20, 2020 at 03:19:28PM +0100, Marco Elver wrote:
> > > > > I found that disabling ftrace for some of kernel/rcu (see below) solved
> > > > > the stalls (and any mention of deadlocks as a side-effect I assume),
> > > > > resulting in successful boot.
> > > > > 
> > > > > Does that provide any additional clues? I tried to narrow it down to 1-2
> > > > > files, but that doesn't seem to work.
> > > > 
> > > > There were similar issues during the x86/entry work.  Are the ARM guys
> > > > doing arm64/entry work now?
> > > 
> > > I'm currently looking at it. I had been trying to shift things to C for
> > > a while, and right now I'm trying to fix the lockdep state tracking,
> > > which is requiring untangling lockdep/rcu/tracing.
> > > 
> > > The main issue I see remaining atm is that we don't save/restore the
> > > lockdep state over exceptions taken from kernel to kernel. That could
> > > result in lockdep thinking IRQs are disabled when they're actually
> > > enabled (because code in the nested context might do a save/restore
> > > while IRQs are disabled, then return to a context where IRQs are
> > > enabled), but AFAICT shouldn't result in the inverse in most cases since
> > > the non-NMI handlers all call lockdep_hardirqs_disabled().
> > > 
> > > I'm at a loss to explaim the rcu vs ftrace bits, so if you have any
> > > pointers to the issuies ween with the x86 rework that'd be quite handy.
> > 
> > There were several over a number of months.  I especially recall issues
> > with the direct-from-idle execution of smp_call_function*() handlers,
> > and also with some of the special cases in the entry code, for example,
> > reentering the kernel from the kernel.  This latter could cause RCU to
> > not be watching when it should have been or vice versa.
> 
> Ah; those are precisely the cases I'm currently fixing, so if we're
> lucky this is an indirect result of one of those rather than a novel
> source of pain...

Here is hoping!

> > I would of course be most aware of the issues that impinged on RCU
> > and that were located by rcutorture.  This is actually not hard to run,
> > especially if the ARM bits in the scripting have managed to avoid bitrot.
> > The "modprobe rcutorture" approach has fewer dependencies.  Either way:
> > https://paulmck.livejournal.com/57769.html and later posts.
> 
> That is a very good idea. I'd been relying on Syzkaller to tickle the
> issue, but the torture infrastructure is a much better fit for this
> problem. I hadn't realise how comprehensive the scripting was, thanks
> for this!

But why not both rcutorture and Syzkaller?  ;-)

> I'll see about giving that a go once I have the irq-from-idle cases
> sorted, as those are very obviously broken if you hack
> trace_hardirqs_{on,off}() to check that RCU is watching.

Sounds good!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201120185757.GL1437%40paulmck-ThinkPad-P72.
