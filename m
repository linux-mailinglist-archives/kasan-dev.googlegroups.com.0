Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5OU3GCQMGQE3VTN7EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id ABAB33978D7
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Jun 2021 19:12:23 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id a6-20020a1709027d86b02901019f88b046sf3739005plm.21
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Jun 2021 10:12:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622567542; cv=pass;
        d=google.com; s=arc-20160816;
        b=KKe/xPeZXWKqCSj+t9IufyozR3w5G4H5RzfqcNDyiD4rV/P1uCRIlUFjzGA+iT4Jv9
         uJirXQBNW8grsSkO6EtzlngTRRIcQ6DEiWjo+jR4YLw5MISLC2ptwz6McqIQh9zq4Z5T
         XiGqMxKd7CItIKP5/cQoGcotY2cTmNwHuqpmOkahN66qOS4eiRRlzGcIXhZa9Krjfxp2
         VHui3UzB3sTVKj9a2rwk9KR/6ZycrlKiGQWhUHAzlylXb/1ye30cooAxBWwa75+S4QFa
         C0u6R3gHF9kywRnqTaAi3OQVFuDt2Ma4ozmhFhs/kbxaXGssu/0GrPP9yw2e5MToud5L
         R0fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=1rvBDoQ0YpEmUm02es7DPR1LV33mrm0PgHxxuIjaSao=;
        b=aXZ2iKUwojzjjBGUrT9LEoUSbt3SkepvDYtlFoaZlWauVtta2JBMI8QBxNd98x5dG+
         kshmCJ/ZB0p7TJyEJsKrnmh3rabZbjszjS8x59ptBZ1gTQSo5vLzNI+BlJhC6KcKsHWF
         gtT4TwIT+iDp+n16XPih7ljsABklvw054rd14VH4C7Im4QcApLh9QrD98w+uyvIy7cBG
         wtCAjANJCcWhAmTtAcqc0n09QSf9SB6cuHan/L0URqVXSkE1z98VaN5VyhAukLXWloeG
         rNSUhv0V6OdYkag56d1NU5/Bz5BjrCDQsA40dxbVkgIRu1WIZZNocQHIUAfryqkwkywT
         FW+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ajWEceEs;
       spf=pass (google.com: domain of srs0=z9fb=k3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z9fB=K3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1rvBDoQ0YpEmUm02es7DPR1LV33mrm0PgHxxuIjaSao=;
        b=jNcHFquUlLk1t7aUKGeb6d6VKY7S7z7nYR0fcmvhgm2BvCgEDsXmuwckjFbzvKM9cg
         qGJN0/1m+VxOVP1ZRrXuw3yPEjBfpNLb1vqLeQSjjxB3wsjvVJLiXvvP+1SUpjaB51KV
         Wo6REVE9s7Re3LPBG6hNUwJLWkfMhj4yPVE99cWwb+oMKlcXaDCGVSTly6PXxy7O29jw
         GSjzXi9ZIAT0OOa6BpEebVVD90IA89EE3q4UoDr2UnsK+fAdQDDWAXFB2T1j7JBVtsNE
         fPVsQz0bvo0YW9lPu0fsqZZJkKkzczuxMTMQ7oSNjpD/VOQLBYPhi5njpNvmfXFmXI6q
         seRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1rvBDoQ0YpEmUm02es7DPR1LV33mrm0PgHxxuIjaSao=;
        b=t8Wi8cvAtQ/8vLBibZOhUdiAsPyCPSe1Ya1lQysw+7h1cgfpuGl+LTr7om+5LcZXbi
         AlZqpQ+5rA15pWBipUgLqkGNLkLQh61N29/3Vx4vFnh9yonI5P/6LEqtuxoLU2166BAp
         eMuCwq5mV5BgyVchA4cbhTh8C9rsAH+XKtKsf0//mn9XJYhR481i8HF4T+2G5VrWBPgK
         CVppc4SJ2zhrXs+BI5DNrdsyrktVTma/fbDkwZsFM8w9L38a5GsMNHG9CKd1ABChdDpk
         mOUsya1jbecTDq6eiEgZFFYmYXadLW6pzIUiEQwkD5WK1Wm9S7BuTYFPWO/bkJm4rQo1
         ksBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bvGf3GP31y5sJC6xtamgUM2jORh3B5H5RcVVkCQ+TE5rZU/0A
	ixTRMnhoHRNNaPztmXhYbqo=
X-Google-Smtp-Source: ABdhPJyqBF/5ekkRgjYMsviPyPZEtArTqK24XWqjX2ErmkVAt7E6tA6AJYFi7ekIF3qc6RVlTyXDhg==
X-Received: by 2002:a17:902:eccb:b029:102:23ab:27a8 with SMTP id a11-20020a170902eccbb029010223ab27a8mr17024257plh.70.1622567541998;
        Tue, 01 Jun 2021 10:12:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b611:: with SMTP id b17ls820079pls.4.gmail; Tue, 01
 Jun 2021 10:12:21 -0700 (PDT)
X-Received: by 2002:a17:90a:4d01:: with SMTP id c1mr864298pjg.143.1622567541446;
        Tue, 01 Jun 2021 10:12:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622567541; cv=none;
        d=google.com; s=arc-20160816;
        b=ng4YVWDQ46vYRxWQOyo/LvPTWNlB7ZkRA7qd1FXQWw9m4/GrFLai8rx8tr6OjWBjS1
         kj8J+gV1TBfo0E8FkpVesvg12WgPLnjkV5e339V+l19xLsZhmhMnBr2LaaSRsgg/D7lg
         8u6ZAvbQBjBLQGcJsoc0xfrjmyNMvksxZkcIG7bjC+j3Lm63JXmyG7GTJVtwNkAIagO/
         qgbmnwZ4omwsAlh6atguyoN2QJoOJmBDCQ6qCx7kcnd35QIwCD/oBzR5V9pZ1JSdmCbX
         gDepDjh6DU8nszUWqSRzl21Bm+dpO9yWeFdG8rtgeuKj86TUt+vCUiuRKh6qIq+NQ9TB
         5RvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3SNF1IDzO3RpbyEL6UFm9jv1re0yJRYDajCbErZdmgY=;
        b=bFOwvRlbGyNBw7Az7UCf3glYsvDsiucs6gFEiOneOqSLkmTnUJQ/6A+rwzmhwjj4Fj
         5yzwryPWuxBAN+vpVtUX1syqHxz39PKmTNjHcHoyUWTUxczirfsRUODa1DZmptgh7jvZ
         eWC9jRhpgnfZPuQeCuxhJ73Dan8r4y08t6kzVqDt5DXCA+PPQ4lid/Vl8z7P7cN1LmdA
         Bz+jS4mPdv1oSIhA1fbjCUmWQA0EUOKg8+u7lVRzc9Sb0yudVKbhOog7VxTJNKIGvTOx
         J+wMx3f94AXcDc5aH4A/biTI6gVr5Ieh37FJkCnVrJBA2OlenLl4z54NzCy+dV8G9T6c
         rIAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ajWEceEs;
       spf=pass (google.com: domain of srs0=z9fb=k3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z9fB=K3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o15si1360766pgu.4.2021.06.01.10.12.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Jun 2021 10:12:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=z9fb=k3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 274CA60FF1;
	Tue,  1 Jun 2021 17:12:21 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id E5FE05C08EB; Tue,  1 Jun 2021 10:12:20 -0700 (PDT)
Date: Tue, 1 Jun 2021 10:12:20 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: Plain bitop data races
Message-ID: <20210601171220.GO4397@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <YLSuP236Hg6tniOq@elver.google.com>
 <20210601154804.GB3326@C02TD0UTHF1T.local>
 <CANpmjNNOoVg5hcm0-omi-CB9zPVnKxBdCir1WmD0rMpoAQSOjw@mail.gmail.com>
 <20210601163209.GC3326@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210601163209.GC3326@C02TD0UTHF1T.local>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ajWEceEs;       spf=pass
 (google.com: domain of srs0=z9fb=k3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=z9fB=K3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Tue, Jun 01, 2021 at 05:32:09PM +0100, Mark Rutland wrote:
> On Tue, Jun 01, 2021 at 06:18:44PM +0200, Marco Elver wrote:
> > On Tue, 1 Jun 2021 at 17:48, Mark Rutland <mark.rutland@arm.com> wrote:
> > > On Mon, May 31, 2021 at 11:37:03AM +0200, Marco Elver wrote:
> > > > In the context of LKMM discussions, did plain bitop data races ever come
> > > > up?
> > > >
> > > > For example things like:
> > > >
> > > >                CPU0                                   CPU1
> > > >       if (flags & SOME_FLAG) {...}  |  flags |= SOME_OTHER_FLAG;
> > > >
> > > >       // Where the reader only reads 1 bit, and/or writer only writes 1 bit.
> > > >
> > > > This kind of idiom is all over the kernel.
> > > >
> > > > The first and primary question I have:
> > > >
> > > >       1. Is it realistic to see all such accesses be marked?
> > > >
> > > > Per LKMM and current KCSAN rules, yes they should of course be marked.
> > > > The second question would be:
> > > >
> > > >       2. What type of marking is appropriate?
> > > >
> > > > For many of them, it appears one can use data_race() since they're
> > > > intentionally data-racy. Once memory ordering requirements are involved, it's
> > > > no longer that simple of course.
> > > >
> > > > For example see all uses of current->flags, or also mm/sl[au]b.c (which
> > > > currently disables KCSAN for that reason).
> > >
> > > FWIW, I have some local patches adding read_ti_thread_flags() and
> > > read_thread_flags() using READ_ONCE() that I was planning on sending out
> > > for the next cycle. Given we already have {test_and_,}{set,clear}
> > > helpers, and the common entry code tries to use READ_ONCE(), I'm hoping
> > > that's not controversial.
> > 
> > Interesting, please do Cc me as I've been thinking about if we can add
> > more bitop helpers to avoid having to READ_ONCE()/WRITE_ONCE() or
> > data_race() the accesses, which thus far never looked too ergonomic.
> 
> Will do!
> 
> FWIW, I have an old version pushed out at:
> 
>   https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=treewide/thread-flags&id=971e3a9ace1d896ec8f0995037a25808ed6028e9
> 
> > > Are there many other offenders? ... and are those a few primitives used
> > > everywhere, or lots of disparate piece of code doing this?
> > 
> > AFAIK it's all over the kernel. For example all current->flags
> > accesses somehow suffer from this everywhere. Also various accesses in
> > mm/ (KCSAN is disabled for parts there for that reason), and a bunch
> > more in fs/ that I keep ignoring.
> > 
> > > > The 3rd and final question for now would be:
> > > >
> > > >       3. If the majority of such accesses receive a data_race() marking, would
> > > >          it be reasonable to teach KCSAN to not report 1-bit value
> > > >          change data races? This is under the assumption that we can't
> > > >          come up with ways the compiler can miscompile (including
> > > >          tearing) the accesses that will not result in the desired
> > > >          result.
> > > >
> > > > This would of course only kick in in KCSAN's "relaxed" (the default)
> > > > mode, similar to what is done for "assume writes atomic" or "only report
> > > > value changes".
> > > >
> > > > The reason I'm asking is that while investigating data races, these days
> > > > I immediately skip and ignore a report as "not interesting" if it
> > > > involves 1-bit value changes (usually from plain bit ops). The recent
> > > > changes to KCSAN showing the values changed in reports (thanks Mark!)
> > > > made this clear to me.
> > > >
> > > > Such a rule might miss genuine bugs, but I think we've already signed up
> > > > for that when we introduced the "assume plain writes atomic" rule, which
> > > > arguably misses far more interesting bugs. To see all data races, KCSAN
> > > > will always have a "strict" mode.
> > >
> > > My personal preference is always to do the most stringent checks we can,
> > > but I appreciate that can be an uphill struggle. As above, if there are
> > > a few offenders I reckon it'd be worth trying to wrap those with
> > > helpers, but if that's too much fo a pain then I don't have strong
> > > feeling, and weakening the default mode sounds fine.
> > 
> > Because I'd also prefer to avoid weakening the default, the new rules
> > will not be enabled by default. But in the past year, I've found
> > myself trying to keep on top of new CI systems, robots, or drive-by
> > testers trying to use KCSAN, and every time there is significant
> > negative feedback because of too many of these trivial data races that
> > not many care about at this time.
> > 
> > One recent discussion in particular [1] prompted me to have a think,
> > and I realized we need something simpler than writing long
> > explanations to avoid discussions derailing. Having an even more
> > permissive mode might be the simpler answer to those cases until those
> > folks come around (gradually, or perhaps not so gradual by e.g. a data
> > race crashing their system).
> > [1] https://lkml.kernel.org/r/YHSPfiJ/h/f3ky5n@elver.google.com
> > 
> > On syzbot we have several stages of moderation (although initially
> > I'll also enable this new mode on syzbot). But every time I suggest
> > moderation to other CI systems that enable KCSAN, they just disable
> > it. So I'm trying to bridge the gap from both directions: fixing data
> > races, but also making KCSAN more permissive. Once we reach a point
> > where KCSAN is mostly silent, we can then gradually make KCSAN
> > stricter again by tweaking options.
> 
> Sure thing; if adding that more permissive mode makes the tool more
> useful, that's clearly the right ting to do overall.

I would put it another way:  A tool that is never used can never locate
any bugs.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210601171220.GO4397%40paulmck-ThinkPad-P17-Gen-1.
