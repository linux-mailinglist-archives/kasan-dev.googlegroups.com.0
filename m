Return-Path: <kasan-dev+bncBCV5TUXXRUIBBS7FXT7AKGQE2R4ASKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id A901F2D2547
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 09:01:15 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id t17sf4883641ejd.12
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 00:01:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607414475; cv=pass;
        d=google.com; s=arc-20160816;
        b=OuRMycn6QfFGTmUJObcU7iGtOQ9RBl7hLl++qWXzYLQTHsPj5wvMPXNKwsa2dv3Qh3
         dqJvxwj8Cbqe9RBdMiee/HS3/7xgqFMSA+bGbdi2b+WHVEVDD+2kJ1KJ562v5lXY0NrE
         thccwFGS2wFZ1Nn9t/0j4y0VKnMN5x951CC9N5KFy1ESoMnzZ3XYRppORyCJx+crMZ0H
         D8qEXZadR97vMHMnDQH++wDaM6UyH4Vlo7P93F+W8tt85L7NQ/S9T4sJLnD6Ejn9cja7
         VPcFGusK9cyYTOc8vFBSaToUZhDtIFdrfCR2+rI6+Yz18YBqVmbuVcwyRHcSs4s/jtGA
         RBCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lpXf0EK/E/uQ5DORIolcjNX6ES0n/pYVnou/KDVmNhk=;
        b=gCltrfmCA8RrXnDWFrI/Cta8YrXfEEhuYNHVyibFTh/5zKzXMXUnPvoKeq97ZpjjhB
         KY0G1xAQL+gf9DpBrjQN+fMysc6cwmPD7gUpxRu4rnIVVYsMym2x1tSbdJtbHb1Zrupl
         rCULlP/n6a21OwYhyZkOAniRbFfFN6uj3cEmjJm5DOCk+xdsFulXjmbqpjuWmlKNCyK9
         lvzJi4Ka6VGqcex6vRkRWg1C9OrZ6oLYuZF81P3KGzx0cbOoyjJSmJvjxHNlnRQ66Df8
         YJ9vcnUMacQAD4AgOLiwqZrzNZAeGw7kXa77R/99Wv6wRD1JCcvl1UL8M/2l8c5UiTYF
         VhZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=m+tg9FhO;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lpXf0EK/E/uQ5DORIolcjNX6ES0n/pYVnou/KDVmNhk=;
        b=R/Kv2M2VsRCHT9RLA4OUNjhAYFHngMNyRBG7P8pJtcArTkR9wZFKMgzM43Ryg1PyNm
         16VjbPilOAILYm/BOZ0IKaeP1E0bwF2Th1dEY6tBc/zxmq+B+6SZdPQwFcfHZ2uC+CS+
         +d3VujVesjZqV+Pa819VDiYqyIdAAaF0SA/pH+tOQRTZhQ0FrgPg8CQtNGSrkERRPskX
         3vkR5N7egj3ZuJLfTPecJHLP13ZDdqLzR9Te9v5SVk5x/N+NYLD8w8aC3jJ+M2w8zBd8
         XHcSRZgnHKZlf1vrOdyOFmgGhREfGOPgc7uXKZu6T8h2g99wzOKdJjMwjZrqDc4RaXfm
         2H/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lpXf0EK/E/uQ5DORIolcjNX6ES0n/pYVnou/KDVmNhk=;
        b=NHfas6XoIfw1ugKQeosT2r2NbiW3whNnJxfEYrSps9N6d4hDq9JbhdGbJlCbrfbClL
         zMvZb4UmGoVaaPoe0IK/rGKV4PW8Rb+pnT0XLuaVw4g9kd4Fx2chvisbRbGaKLBnZPvd
         ichbHQeblym3JHFa//Bib7Ad+J8Nop8yMUtaSYqxlJIb/gw4OfLgBxGUnHS3pcyr7MlA
         C5rfewOWVSDcU7aTnFbuJzxYgGk8ySXbXh2wxZtGBYKx+MM2we9nQX6JaRYCKBx0O7pS
         UzL2+ek56K1TLbzNbhk04Gi44e7OUfyF3G7+Z7N/R7NEMt8PKB8Oh79nACV/CpBO/tEn
         q0SQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530FTZxQvfgrijSuEagWoerwVNKYCDwdfRwGyVgHvXLDOKiYO4rb
	wI8wM0BItY16Yiys6UbNXts=
X-Google-Smtp-Source: ABdhPJwcr/I/JJjQfAP7boRTDT9nlnNuJQK84DuNhFFqdzX1fbReTqZDC92/cgnRvqprCPxDf9wg7g==
X-Received: by 2002:a17:906:8617:: with SMTP id o23mr22199551ejx.274.1607414475431;
        Tue, 08 Dec 2020 00:01:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:22d3:: with SMTP id dm19ls2174358edb.2.gmail; Tue,
 08 Dec 2020 00:01:14 -0800 (PST)
X-Received: by 2002:a50:d646:: with SMTP id c6mr4153739edj.177.1607414474458;
        Tue, 08 Dec 2020 00:01:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607414474; cv=none;
        d=google.com; s=arc-20160816;
        b=w6quTHMAXg7ME7IzyhMEoqasxA8icbPsLk+cS2s+HoeAQOW1QSW5mbCauRnOfVAnVq
         bDoXHfCWEt9KKDXFLS5BNVBCkMuzdQcm+h+iykh8OdL+thF1jRolZjf2fZPhAGx0F/6P
         caERDbuaYx+FyAlYkIps1Zb4muneaEH7zNBT4uJV3IVSDpUwV0/3ZYqPtcz9Qnhnpxe6
         w+PPb8GLlYgUD8fyQ9RqY1yhU3WToQMhzBmr3pBQdElakwzN4SuXHD20sgSeuUg0IKn9
         lJiK3XyZhO6VIpVs8/i4TaXqeRzaiFDnEf6c0M0jQ9J9dtvT19eIZ3FQYfjA8GpYKhLR
         rdmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=xazLnsFKp509NzkNSliY4NnLb3Zp1YnEQsS4iT/8KVo=;
        b=Av1H405dT2unP1Slh2VDjwmdCKcr3uPgj/y8nX7ApOUfl/GtE2WNEq5Xt2/gB1QBk1
         2IsxtG3RjphedkaQCwzRUS2PeppYVdjp5wKmtCqUl1y9U4Mqx6twHeBly11KE9TnWRfZ
         aXWUKg2Aj0NoNrFJVdI/kPAxHL+YHmtaC9n4K+VU75w5wgkxv+uHKYs/t4nEhd3ad3uy
         8oyezhHTI1MMjSTt8aoCprCt/52t/YoJyIDHUUdauDgpdr9zVMSkfGUJu77uhI4Gj0BF
         6pNl/stiCUjZ8pijRnDE1MHFf7JssWD3hL4AQ5fnjAUH4FbXki0t4+10NcNXfHxslhJT
         c1Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=m+tg9FhO;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id v7si935622edj.5.2020.12.08.00.01.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Dec 2020 00:01:14 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kmXvs-0003VN-MS; Tue, 08 Dec 2020 08:01:12 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id C2A493011F0;
	Tue,  8 Dec 2020 09:01:08 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 6B7AB20812BB0; Tue,  8 Dec 2020 09:01:08 +0100 (CET)
Date: Tue, 8 Dec 2020 09:01:08 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com,
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com,
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
Message-ID: <20201208080108.GP2414@hirez.programming.kicks-ass.net>
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=m+tg9FhO;
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

On Mon, Dec 07, 2020 at 07:19:51PM +0100, Marco Elver wrote:
> On Mon, 7 Dec 2020 at 18:46, Thomas Gleixner <tglx@linutronix.de> wrote:
> > On Mon, Dec 07 2020 at 13:09, Peter Zijlstra wrote:
> > > On Sun, Dec 06, 2020 at 10:12:56PM +0100, Thomas Gleixner wrote:
> > >> +            if (data_race(tick_do_timer_cpu) == TICK_DO_TIMER_BOOT) {
> > >
> > > I prefer the form:
> > >
> > >       if (data_race(tick_do_timer_cpu == TICK_DO_TIMER_BOOT)) {
> > >
> > > But there doesn't yet seem to be sufficient data_race() usage in the
> > > kernel to see which of the forms is preferred. Do we want to bike-shed
> > > this now and document the outcome somewhere?
> >
> > Yes please before we get a gazillion of patches changing half of them
> > half a year from now.
> 
> That rule should be as simple as possible. The simplest would be:
> "Only enclose the smallest required expression in data_race(); keep
> the number of required data_race() expressions to a minimum." (=> want
> least amount of code inside data_race() with the least number of
> data_race()s).
> 
> In the case here, that'd be the "if (data_race(tick_do_timer_cpu) ==
> ..." variant.

So I was worried that data_race(var) == const, would not allow the
compiler to emit

	cmpq $CONST, ();

but would instead force a separate load. But I checked and it does
generate the right code.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201208080108.GP2414%40hirez.programming.kicks-ass.net.
