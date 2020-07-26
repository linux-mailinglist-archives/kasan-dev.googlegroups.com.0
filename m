Return-Path: <kasan-dev+bncBAABBR4N674AKGQEFMLETYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BFEC22E1E2
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Jul 2020 20:09:12 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id 1sf10336705qkm.19
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Jul 2020 11:09:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595786951; cv=pass;
        d=google.com; s=arc-20160816;
        b=YR2tbi7k7IXzuxFpjdEPRNgJ0lfpbG0PCVZrdxFhO5ggd//C6brXVRuDHTWfL8TqqL
         cMpRFxmRA9P2k4iyk0RzLO3QcJGxP4pIAaCVTopenuaZAFbmc7MPD/M3iq9R2Ke2yQdz
         XTGa3rzNvY/6xCpbf3oRi9O0eXt91zq2rx7YMBa+9BkG+5PSyKUpr5CBX2hfv7V7CTZw
         FOGhLPHeB9O494wokeOKQ6ucHqFD/RJj4Gx5pzqvu1M6YZfWabX+iavGuIU4kabnplEU
         DIfqBcO0Yu4jWmIgbJ+n9ZAse05UxjJixG6kB9rIeeChked9NfRvr2e6MvACl+OyEJDg
         2q6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=hNHu+wEhTwdpDjh3DfZ/7s9LV5fTb0Nfo5tktDsoTZg=;
        b=zMDIk/tAn5+CClS0BvOPMQcNSVuOZOrlJ+9cApV1CUrzA/+2KJ1YrRa70dzPzvYbY3
         lpr20E5lxv8HWtn/VErsYaus6qoNlmes+Hyx+cysLDtkLLRuqCGC/sKNq2h7+vKGR/6L
         8wwn4KwmC0TQ6b8RR8QpoM1U7JEVdRBHKK4C/uYEvTd/Ag8m48jGSxw9epbp0jrIAeqb
         Q4q4x31S/ZAPDXVAs117Ve3J4bS3J5eRW+erHKLvUzlLUqXhwOmQlagNK3aOKYtq3R1g
         XeiaRHkRwW5X67LIMwxnBQ4rxVGaFJMhD2sC6WEkMwlF/2gj7FmkZNUduiTyMsWLjs7i
         yHpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="CgW/KPae";
       spf=pass (google.com: domain of srs0=ftl/=bf=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ftl/=BF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hNHu+wEhTwdpDjh3DfZ/7s9LV5fTb0Nfo5tktDsoTZg=;
        b=iwQSs2nhvgtmpQC8HEybbdt5fEaMgq9Rt4uXjspsdrwQlYbh/6bcdJRw0wix5GdELj
         fl25+bpLrqLu9minVjkQamb8I1ZjWf4B+B1K5vrKZtOvJdYL2Deg7k3xx92tvN0xm6EQ
         zW9pu6id+ZnEkhEz6+1yBLcPjuns9UabIPkTym7DRpYtcdtzLwdGX8TXH5rBzjLg31rm
         gM1slicrXnP/j2Hpo4m4GmGp1AwxaIMbLL2zkNJuqLUgTd/eUlKaA0S6Ff+aobOMuy1F
         wvQOvvxn7vmyR8Ra0y0izM2YvfMiaNEWs9+qAD1V1WX2CXKIHLPnvyX+kAlW2O8NRwOt
         bMSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hNHu+wEhTwdpDjh3DfZ/7s9LV5fTb0Nfo5tktDsoTZg=;
        b=bS2FgkLsiqLhWrSEVgbxGw5Bu4goVm6nIWRS0PiVJuIuhCrbjGd6ZRmldT4uf8z1DO
         M9ikq7xoeQlObgTRQxVQjFivCG4IkFe2ZJWP4K1zfkHpDKfIUb3deWkbFSid9PlVJCXL
         PTepMe0LMOm2hsXh5kgvrJHfkj8op+RZWwPpUdzj2qbqpZ33ZWq854dHl7xRjirnItH8
         C6Urq5bsNUEUHS5jvjf2gnGD6KkeYu7PSJcACPWdbvzCcNhhCVxUHaEnx3Zj4r5VOzbf
         neUKSoXE/vwvqkaw8fhW0hHoq7NfmOHi1gC7y50NDP2y1s0WjFEdKLOmvEhs6Gy4an2v
         VEzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323+5qM0Gcd1NRbWt3t3YSSiH9pUM9yvA2IbSJfikJT6i9L6GPq
	8cIMokPP9bzOVNj/dH6Q4rE=
X-Google-Smtp-Source: ABdhPJzDeh/s20weSByEJRgP+UvL94vlrjsgUE/NNe5JGiw9tbent+IRIYMApdYnwk5cqjguemCkMQ==
X-Received: by 2002:aed:31c3:: with SMTP id 61mr8299953qth.369.1595786951430;
        Sun, 26 Jul 2020 11:09:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2ac4:: with SMTP id t62ls5529674qtd.7.gmail; Sun, 26 Jul
 2020 11:09:11 -0700 (PDT)
X-Received: by 2002:ac8:431b:: with SMTP id z27mr18903723qtm.5.1595786951096;
        Sun, 26 Jul 2020 11:09:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595786951; cv=none;
        d=google.com; s=arc-20160816;
        b=wjQsQO+0aTDd1idrS00/qxmLhvknlpp6CHphY5LmBggBUkYuOyivaPxAl/UJOt8zfG
         AT4dCLdZ8KOStWZ7SGuu3hOHQX6/fMFv9WoKlRzVJUt+DP6DHzD8+V99vYm2pAsKdD4p
         h2h49YxYsbb6ObUQ/aDTWFky4lb4vnSjTNQN7kTBGx2l1uTg9AAKfGxvfvVqZsSIMD0W
         LpffZRDzy+rpVl4dUnOkxds1tPTVDpCuRP1eM1JXFWFysLQGpmOA1lUiZRXoHyhuBLPe
         FD7GoEEQeuJ0VHuC2yBGmdaNtMl6kAEpy9XIVQEsTuX/a5yy5BbOvHmHMPGUyoV6WHvz
         GOoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=NcspvM2zECf20Ixoqc8LAWCi5L3GTHnysxHjK9LRx80=;
        b=Lh6XinpZjkAXnT/T3LVjWyFNtML79WNa9aN1ldTfExCD5QB6mAS85E2/H+kkjfB+wv
         9r9KKeiBio3J66nDvzGemGPCbnWXDEsVGLU1XyEB0eCx4AgEZnymcHAT/6P1maMq2vEn
         bV0NMxVO3B5+I3U935CxBskHGV7X2WgzrZDueXi63/ZTXJFIPsYgPrtJpYr/Y7hsmXMM
         k2cYu0itkdfVfpurZxK3w02SR6JJBGt+Z9SrqXlz+bkh6InPbMvOfqLqxoMWdwYSda36
         WIyg/r/Xbo+m9jZOiGgpUZ2EQtqdvpsn2XfAg4rRTo0/ZyY0lAkSGwtyeSpNoz3y0tzl
         MmoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b="CgW/KPae";
       spf=pass (google.com: domain of srs0=ftl/=bf=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ftl/=BF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v201si939931qka.4.2020.07.26.11.09.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 26 Jul 2020 11:09:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ftl/=bf=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-111-31.bvtn.or.frontiernet.net [50.39.111.31])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E69AF2065C;
	Sun, 26 Jul 2020 18:09:09 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id D003F3523102; Sun, 26 Jul 2020 11:09:09 -0700 (PDT)
Date: Sun, 26 Jul 2020 11:09:09 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: peterz@infradead.org
Cc: Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, jakub@redhat.com,
	hjl.tools@gmail.com
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
Message-ID: <20200726180909.GE9247@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com>
 <20200725145623.GZ9247@paulmck-ThinkPad-P72>
 <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
 <20200725174430.GH10769@hirez.programming.kicks-ass.net>
 <20200725193909.GB9247@paulmck-ThinkPad-P72>
 <20200725201013.GZ119549@hirez.programming.kicks-ass.net>
 <20200725202131.GM43129@hirez.programming.kicks-ass.net>
 <20200725220750.GC9247@paulmck-ThinkPad-P72>
 <20200726115242.GA119549@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200726115242.GA119549@hirez.programming.kicks-ass.net>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b="CgW/KPae";       spf=pass
 (google.com: domain of srs0=ftl/=bf=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Ftl/=BF=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Sun, Jul 26, 2020 at 01:52:42PM +0200, peterz@infradead.org wrote:
> On Sat, Jul 25, 2020 at 03:07:50PM -0700, Paul E. McKenney wrote:
> > On Sat, Jul 25, 2020 at 10:21:31PM +0200, peterz@infradead.org wrote:
> > > On Sat, Jul 25, 2020 at 10:10:13PM +0200, peterz@infradead.org wrote:
> > > > On Sat, Jul 25, 2020 at 12:39:09PM -0700, Paul E. McKenney wrote:
> > > 
> > > > > This gets me the following for __rcu_read_lock():
> > > > > 
> > > > > 00000000000000e0 <__rcu_read_lock>:
> > > > >       e0:	48 8b 14 25 00 00 00 	mov    0x0,%rdx
> > > > >       e7:	00 
> > > > >       e8:	8b 82 e0 02 00 00    	mov    0x2e0(%rdx),%eax
> > > > >       ee:	83 c0 01             	add    $0x1,%eax
> > > > >       f1:	89 82 e0 02 00 00    	mov    %eax,0x2e0(%rdx)
> > > > >       f7:	c3                   	retq   
> > > > >       f8:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
> > > > >       ff:	00 
> > > > > 
> > > > > One might hope for a dec instruction, but this isn't bad.  We do lose
> > > > > a few instructions compared to the C-language case due to differences
> > > > > in address calculation:
> > > > > 
> > > > > 00000000000000e0 <__rcu_read_lock>:
> > > > >       e0:	48 8b 04 25 00 00 00 	mov    0x0,%rax
> > > > >       e7:	00 
> > > > >       e8:	83 80 e0 02 00 00 01 	addl   $0x1,0x2e0(%rax)
> > > > >       ef:	c3                   	retq   
> > > > 
> > > > Shees, that's daft... I think this is one of the cases where GCC is
> > > > perhaps overly cautious when presented with 'volatile'.
> > > > 
> > > > It has a history of generating excessively crap code around volatile,
> > > > and while it has improved somewhat, this seems to show there's still
> > > > room for improvement...
> > > > 
> > > > I suppose this is the point where we go bug a friendly compiler person.
> > 
> > Sounds very good!  Do you have someone specific in mind?
> 
> Jakub perhaps?, Cc'ed
> 
> > > Having had a play with godbolt.org, it seems clang isn't affected by
> > > this particular flavour of crazy, but GCC does indeed refuse to fuse the
> > > address calculation and the addition.
> > 
> > So there is hope, then!
> > 
> > And even GCC's current state is an improvement.  Last I messed with this,
> > the ACCESS_ONCE()++ approach generated a load, a register increment,
> > and a store.
> > 
> > Do you still have the godbolt.org URLs?  I would be happy to file
> > a bugzilla.
> 
> https://godbolt.org/z/rP8rYM

Thank you!

Now creating a GCC bugzilla account.  For some strange reason, my old
ibm.com account no longer functions.  ;-)

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200726180909.GE9247%40paulmck-ThinkPad-P72.
