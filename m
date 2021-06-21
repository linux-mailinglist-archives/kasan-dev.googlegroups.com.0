Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVWUYGDAMGQEGFS3ROY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C57E3AE72D
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 12:30:46 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id z11-20020a194c0b0000b029032331652cf9sf384215lfa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 03:30:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624271446; cv=pass;
        d=google.com; s=arc-20160816;
        b=xEdJ3boHaG+fhvnljMlC0o85vZcCNB4Ri7rX5lQgLp1R069y4BPRTZMOyXRqaX3MWj
         vD1hP1ue9mg4VIyPcEaK/0UnWFgm5kwO0HDkr/+IktVFiLkpPsAWFsqA7WLMYnF4wMWh
         kENjl+a27AFlFEBzM3hManeZ74LWZ5+I8FAWXDNzR9uhEfecBg+Mi+TE10zvi6DnDuWH
         pVg/4Se+VgqQ2nkidrejOM5EUB3TEs9V+6h5Mbc92cDid8WtfVoTXQ/C976EjxQSzeT6
         4T/+qVJg+MjQTDjdEQexJEJfgqgI6IaIxAfWAQFHkrLhdoRiA2O9iwPC1vY/N/u42qCZ
         cxBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=K5+LJKzov7ntTEkJjtSdWGBuoIGC1vOoaBdvjJG3Yao=;
        b=aKEXxkAVZg3XfgSSIUyeBPjysfDo7nFHtwybqIQ+TARcYnamtYcfEDbT26dgzVpmWi
         aL4y8JPTFeE7uC4NX7Wb9BTPRtzcAJwvOpGwv09aXw1CNHnA1VFOLcfkHYGwUKLVXcdr
         GNOHkd75vV+hjM36+RpHbOWyvbjmFxjfqtVy5nD/Jcwzzl3HoB8HI/V7lmjcmSTmQCMr
         R4OO/PS9uqDtipdNO3yMJZZGjiZ4M2S/WsRWbVvHGH1ClE4Zv7KAMykXcauax3ZZZSQJ
         bo0+vmPH42l9Jafx9l5drYEJOsyjEVKnVDmVy9haJpUZodFw4uM+mi24Jk4JltE4EPOZ
         NuTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g7s0XJvL;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=K5+LJKzov7ntTEkJjtSdWGBuoIGC1vOoaBdvjJG3Yao=;
        b=aPzr/j+cSV5XkBgTU4yRrP8Wm3Q666iVpCDLD1hJbENBRo12scvkM7bKbNL08LKHOW
         UyHt2GuXz4KDZP4IlmfB8gijUf0WoC5dbg5XD8oOMzlqBAVVYgYzaKJdMvplwuv4uDdw
         WIW2ppFLAXqkmbn9V+5sD2Uw/cqchoxNhN2/OWsTLNxKVGCPqPl7h6Ipzxy88c8MH/Ne
         T5XjP/HKpdLFtzcsoHeRN/Gmg7l3qW/M7tZY/IbEImdW9DaBz2NE4wxF2paIDt2dVg7R
         MIw7PxtRFaPLeo7RwFaz8+VB29nzacwGINfBzsrU+pqj2BBpDsBc8pYWfot1WYJ1uctW
         u4VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K5+LJKzov7ntTEkJjtSdWGBuoIGC1vOoaBdvjJG3Yao=;
        b=SUcUlEyibESI4hzL5yaBwbCgzIOvZDUO2iObjEB3vag6pTAK6mOvWOMekjUL/XPPPY
         xmNtZE7oBidQvCY3a3ANmgXd/OS6RJCnv8YJwYMDUxcBKCgnEHTf6qmGBpyvTv2zNpZo
         +yH3fTojgAIKF3yC/7qXzBRr8DrKHvDkwItwyeZ/c29cHVzULwAocaCNiBSRf+ymI+7t
         YzbXXmjRSryRoiF/dMXXV830ZbbCxuS50OvRsBo8yfdYawVijQtBgHYH2nHR1cEAfoit
         yBXWmdiYTZ6FKHaTX+2vfXuOpfg4trXDWQ6RZBk8Cj0hbBsgmtl2KiA2o+q5H8e2H3wY
         64HQ==
X-Gm-Message-State: AOAM532sGGLT9qhYNanovJXvlUAHzwuOPhAZh5r78WgDOYRHyeQ4xwxl
	jnzJ5L1vEijI4cC+QUM8830=
X-Google-Smtp-Source: ABdhPJz0m+H9yKINjDuXQBUzb50AXLSCSs94TqtQiMcVqVWxcIbAeJ0YSAqtkRum58+zHeOIDctHfw==
X-Received: by 2002:a19:4096:: with SMTP id n144mr14058880lfa.433.1624271446217;
        Mon, 21 Jun 2021 03:30:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:f515:: with SMTP id j21ls31482lfb.1.gmail; Mon, 21 Jun
 2021 03:30:45 -0700 (PDT)
X-Received: by 2002:a05:6512:203a:: with SMTP id s26mr13984712lfs.394.1624271445022;
        Mon, 21 Jun 2021 03:30:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624271445; cv=none;
        d=google.com; s=arc-20160816;
        b=avq+NrTMJ6B+mtcLCPqQVuIgbCZyxWy8BjoNrEvwdqDpQn6xnizYK0hL/rxHYeA0V/
         QmxmqPVCSeiZsMYOHOUmxtTMI7sKqbosCXMo+6g3o0cDSJEkueRP0dvn3dynTrzfnVA8
         tyTt8L3lCpGf7LFp/L9HAaLFBbgwalzGKzvMHbeCQ+aHJuCYm9StUNe73ZZPA05uWdMQ
         1/3AAdFYl8J/vUYcL/T8IqtvO4E/gA3LmgWpH7lIiieLXyGPKPzVyndrW/Cqx+x3pmou
         GrPaB0FQ5KQLeyD7IIZgTUo8Wsg0Y39GrfK9l3Si/1mW+F/Ld6UxgBI0TvYBzXvJ+8PA
         SSQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=lFoiBKZtD98dZmzCBxXD6R0VVGwRjhBQinGa5Vre968=;
        b=maUoXe+PtI1HCiUkhyRdwg794invn91ezrxz1KNzDAoGT4R7Rqh4VdcSG7XfPuousO
         DoXx4BrI7iNjYSSau3bXFIWPG9Ks6e/L6jfiy6xoDetfVm0IUPsUAiNf5HJ9hf4+Cxzb
         dclk4DYjrvVa4uEa3T6rw5Y8iLs2lmj5xsQHoDZftYkm+z6C3rdFafIjFwQtlQp8driG
         OS+vkNiR4TfjnsT2sDastylXAdkt3GjmY6+cF4WXfQtIPsidKoGk77PNqBZieBMta05e
         z/59T7wGSRhH6FE+dFLorRSih+S3iLqp8V93rMHZxE5aMQzw+dgifLkymLdXrzAtUdd1
         stpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g7s0XJvL;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id x23si631809lfd.5.2021.06.21.03.30.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jun 2021 03:30:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id n7so19040575wri.3
        for <kasan-dev@googlegroups.com>; Mon, 21 Jun 2021 03:30:44 -0700 (PDT)
X-Received: by 2002:a5d:65c1:: with SMTP id e1mr516081wrw.196.1624271444633;
        Mon, 21 Jun 2021 03:30:44 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:6679:9a60:529b:288d])
        by smtp.gmail.com with ESMTPSA id s16sm4764489wrm.36.2021.06.21.03.30.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Jun 2021 03:30:44 -0700 (PDT)
Date: Mon, 21 Jun 2021 12:30:37 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Daniel Bristot de Oliveira <bristot@redhat.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
Message-ID: <YNBqTVFpvpXUbG4z@elver.google.com>
References: <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com>
 <YMyC/Dy7XoxTeIWb@elver.google.com>
 <35852e24-9b19-a442-694c-42eb4b5a4387@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <35852e24-9b19-a442-694c-42eb4b5a4387@redhat.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g7s0XJvL;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, Jun 21, 2021 at 10:23AM +0200, Daniel Bristot de Oliveira wrote:
[...]
> > Yes, unlike code/structural coverage (which is what we have today via
> > KCOV) functional coverage checks if some interesting states were reached
> > (e.g. was buffer full/empty, did we observe transition a->b etc.).
> 
> So you want to observe a given a->b transition, not that B was visited?

An a->b transition would imply that a and b were visited.

> I still need to understand what you are aiming to verify, and what is the
> approach that you would like to use to express the specifications of the systems...
> 
> Can you give me a simple example?

The older discussion started around a discussion how to get the fuzzer
into more interesting states in complex concurrent algorithms. But
otherwise I have no idea ... we were just brainstorming and got to the
point where it looked like "functional coverage" would improve automated
test generation in general. And then I found RV which pretty much can
specify "functional coverage" and almost gets that information to KCOV
"for free".
 
> so, you want to have a different function for every transition so KCOV can
> observe that?

Not a different function, just distinct "basic blocks". KCOV uses
compiler instrumentation, and a sequence of non-branching instructions
denote one point of coverage; at the next branch (conditional or otherwise)
it then records which branch was taken and therefore we know which code
paths were covered.

> > 
> > From what I can tell this doesn't quite happen today, because
> > automaton::function is a lookup table as an array.
> 
> It is a the transition function of the formal automaton definition. Check this:
> 
> https://bristot.me/wp-content/uploads/2020/01/JSA_preprint.pdf
> 
> page 9.
> 
> Could this just
> > become a generated function with a switch statement? Because then I
> > think we'd pretty much have all the ingredients we need.
> 
> a switch statement that would.... call a different function for each transition?

No, just a switch statement that returns the same thing as it does
today. But KCOV wouldn't see different different coverage with the
current version because it's all in one basic block because it looks up
the next state given the current state out of the array. If it was a
switch statement doing the same thing, the compiler will turn the thing
into conditional branches and KCOV then knows which code path
(effectively the transition) was covered.
 
> > Then:
> > 
> > 1. Create RV models for states of interests not covered by normal code
> >    coverage of code under test.
> > 
> > 2. Enable KCOV for everything.
> > 
> > 3. KCOV's coverage of the RV model will tell us if we reached the
> >    desired "functional coverage" (and can be used by e.g. syzbot to
> >    generate better tests without any additional changes because it
> >    already talks to KCOV).
> > 
> > Thoughts?
> > 
> > Thanks,
> > -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YNBqTVFpvpXUbG4z%40elver.google.com.
