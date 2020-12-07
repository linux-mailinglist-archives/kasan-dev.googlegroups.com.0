Return-Path: <kasan-dev+bncBAABBCEMXL7AKGQEPFDMHJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 386302D19E5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 20:44:09 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id b4sf6614727vkg.10
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 11:44:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607370248; cv=pass;
        d=google.com; s=arc-20160816;
        b=JVAbsGYNoxNGFhPOGYBf+kp4q6ppbFIP/ESqCg3PgEo8+3dGDIgiy4YxQv1VuLEcKX
         VohyZl532nS+Tu8T1fZP1Z23Y0iW8m3ZFnn0z0w+D7MQYwsPNi7JgKFPU2X1PmpGvb09
         Pi63fyAsQimsYIvbMpmKX847Mu/TmTBb00WSkaKv4mTY7zdYTPh6lVUKZS/9W+ifCYQ3
         +ldBiW217RAICQDS+71OqCyD03o+qEI7cCLGKZV9nPbavSmTvgDpqOUx2gE2z5EaeMRE
         pxwPyFgP1whXdYhUDOjB388JTF3j5IBWDVvz9+aLyUWo/9HkAvrxd5a0ekwpfeVXmsll
         o3dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=x8I4Fi7ZRMlMSReMqfbZhHkguw1+XHSReQVa6i1dsUk=;
        b=BOysjOGixUcP3mx35gG3vVV8jDhr6gqKILm9CgUbWubnIkZhi8Ef+9hQlBWYE3nhPf
         8SXyyf0IimUwqV0WmAe7MQq/uq0Fzl+aJpQ85B8jMxzBP2xcqbSYLIyc7Z1l/EYUq+F4
         A/t4Q02H+SdZtHm0nvMh+Rid+05EtwpIRc0MWxocztYW2/GLiKGHzxhQatbIuJB8YMgE
         mQ4QyyBVnAtisrOz8juMzBy5cIwrQcGR1Rx7BIthq7rgMUEHNTgCNyXftvGawFMWkJ1Z
         CbWQy0iOt54e43EsDJcXlmy2Hxu0T6RqUTCl0VbDWFDdQCMEamH+/rJlt0J4vOLQk9mw
         +K8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V1kAKtuI;
       spf=pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x8I4Fi7ZRMlMSReMqfbZhHkguw1+XHSReQVa6i1dsUk=;
        b=NR2Ck+UPsseV/x3tY/Jnfz0HkBGN72Dj2U1HHRFB4apKakl530s9GGzlLR/DnaqKBb
         f4TZZxN4nKDAUaF3mlyXD3+BatxbDYhF4394OwMWL0AhPQUmu17nUyMmqEmpddTDiLWd
         LI2tkoXcoc5XHdyhL1IBqnoQw4zYw22O8tXd6/FdFdGH3rSthrHZOCHTnRbnLURiiLb1
         Cc4/OeJ6WUeIEkMzUjcVmAiK47jm5oq12cjQPw7k+Rw5K0/MhlCOQCyhPF14ZOFST9AP
         jGoWu0VS68BEIxxxtoj1b5p0dk+Jr5/41PpgsexrRm6x12EVhTkLXsEKRAWrn+iZDXlF
         Sf2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x8I4Fi7ZRMlMSReMqfbZhHkguw1+XHSReQVa6i1dsUk=;
        b=dasOpcHkgPhMJjPqovU+wbTMP5fLxv9KgaJygpLALm2A5lLEzPK3sqXP8LebwvB57Z
         wRb0jL9o+IlXZ+aVtAA9IqV5zrW+55Ph/juA+ajPvtXs9X3CxICH4l4UeM6jaf7PIWcJ
         tr4bbocwvXbBmYj8PDU6Gs1UMsxwxI+5BBsS6I6hL0ZStZcaEevV7HRcKhGw+8l3Wn5D
         sF6dwaJhIMrCHscfgN8SuAhwE+vm1YHGY4jIw6srRw9HogK51B5TnGT8yu2O7twZGo/K
         7BaX2BlnAFwLWETGe0VFz4kN6seUSwRNQNlCoCkA0iQ7UaB6gu27iGfgVPVrUQU08qWp
         rk6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310EjWUtH7r2aoIqqlIhvTGq9/rYU/800rhOJxcglrJwA1SJsKt
	rPCOe4KxTlE75VfaPDZd/h4=
X-Google-Smtp-Source: ABdhPJxFb2u6girnJHen0h88JpVrlLXDBcYcg1iV8m98U4n68ZKhBQwhL5iQTCYzvTwUvGuDuv7fYg==
X-Received: by 2002:a67:7dc4:: with SMTP id y187mr14266464vsc.58.1607370248315;
        Mon, 07 Dec 2020 11:44:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c291:: with SMTP id h17ls255825vkk.1.gmail; Mon, 07 Dec
 2020 11:44:07 -0800 (PST)
X-Received: by 2002:a1f:dec2:: with SMTP id v185mr4944027vkg.8.1607370247918;
        Mon, 07 Dec 2020 11:44:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607370247; cv=none;
        d=google.com; s=arc-20160816;
        b=YxoYR3HiO5g+h1C7JZzO868D0WFs1sH9Vt7DgdeonDF7gIvECVM8Dm0WKtIsU3N/Gy
         joUA8H7PglkxmS7vPSTBIx7aLi3U4RSXfXYpmLQqH90lJPqf/AoPqE/3HosJ+rt1v1Hz
         hPol7iFDgQzt2Klz89Lgs9Miryx8W8ZLJWxYaDs5xvjwDkBl/q9BIU6hykXpKFUW0z87
         XarXhTNaBo8FFpSRHhv8VlnM6PpC1bOrt+q8va02j+GF1tHu7UgpNFvEvbFU6bBFPYQu
         WF1Cj+F75ruaY8ozpEClCmF5SLX9qP61DJ5z1fl/iWWqV3vGem+BJZ3eSmLhn5g5nde+
         TOAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:dkim-signature:date;
        bh=s9TbkhmGrBs7L19UzBiTcx3edgSr5tmaoL0n6gSqs3Y=;
        b=MXXWe1oIaRyXMl006UVwX1b/FKVRxeqmCBpwq09d1Ce7OsNsfd8yRgCAh4klZE5P6B
         ZydJeDxvHk+5J5RzTfiEPFxFBXFXU0/ntnpLpzkdXgziVOa4pBSU/t106v7TNFdSojdF
         y5rNccPlXq4gxKooWlYZl9aWa8FAx64/GGVT8OOS/rCjs/+qvyRl/wehq9UQJdI01gyW
         pmjsHf9bGX8SWP9TlUv8OZVZCTJstwSiJbw7af6tMWNWBXv4bv8W/LDR3ipCk9PoS4fq
         DQx+3RuyCCmWVbslS5e/XEhNFo2Vf0pYZg4j0HJz183ruxbCO0YGkF94g538wyEac6Kw
         1AJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V1kAKtuI;
       spf=pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r207si217968vkf.2.2020.12.07.11.44.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Dec 2020 11:44:07 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Mon, 7 Dec 2020 11:44:06 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Will Deacon <will@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>,
	syzbot+23a256029191772c2f02@syzkaller.appspotmail.com,
	syzbot+56078ac0b9071335a745@syzkaller.appspotmail.com,
	syzbot+867130cb240c41f15164@syzkaller.appspotmail.com
Subject: Re: [patch 3/3] tick: Annotate tick_do_timer_cpu data races
Message-ID: <20201207194406.GK2657@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201206211253.919834182@linutronix.de>
 <20201206212002.876987748@linutronix.de>
 <20201207120943.GS3021@hirez.programming.kicks-ass.net>
 <87y2i94igo.fsf@nanos.tec.linutronix.de>
 <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNQiTbnkkj+ZHS5xxQuQfnWN_JGwSnN-_xqfa=raVrXHQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=V1kAKtuI;       spf=pass
 (google.com: domain of srs0=y2i0=fl=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Y2I0=FL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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
> 
> Otherwise there's the possibility that we'll end up with accesses
> inside data_race() that we hadn't planned for. For example, somebody
> refactors some code replacing constants with variables.
> 
> I currently don't know what the rule for Peter's preferred variant
> would be, without running the risk of some accidentally data_race()'d
> accesses.
> 
> Thoughts?

I am also concerned about inadvertently covering code with data_race().

Also, in this particular case, why data_race() rather than READ_ONCE()?
Do we really expect the compiler to be able to optimize this case
significantly without READ_ONCE()?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201207194406.GK2657%40paulmck-ThinkPad-P72.
