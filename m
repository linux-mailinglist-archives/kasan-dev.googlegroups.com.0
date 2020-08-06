Return-Path: <kasan-dev+bncBCMIZB7QWENRB4UJWD4QKGQEVHEIYII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4806A23DAB2
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 15:26:11 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id j205sf10688647vsd.5
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 06:26:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596720370; cv=pass;
        d=google.com; s=arc-20160816;
        b=ySF1a0UDR5hllt2v47zeBvOgoVhoqhXmAF0APvPoSvhssFZSug/RtRCx91eUQaRxIn
         xQUJ7rpf8NRkLOgOTQs0c04YGFRL3m9GGb4Ue9eEyLZWT99jF78DOdZjKOLX3904cvFA
         EsJX9W0HODBhFQ6nt1kmPnrTnTe0cCy5l/sFNEXF0A1sW1YT0fcjFf2XyLK3CzdkxSH7
         hcmZo9q0GvdrCtQHacxzE1sX7LF2TDRVY/F3hCPHQ+JP5Vgyi1pL/hudpJ8KKElgEcX4
         HBKkN2VZelk1JhFGrwnnxARaSiczmQFf2WYL2hhMLGdox+YuyZO7TBVQjRLcql4GbpOX
         xvqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cffuNjJKVPbcCD+n9g5peUV1PLGOmFBUhRn5tiGumq4=;
        b=Bc8oDOgCB/umvBJX7yehVAFAbQaMtd4gZo4chAzKQT3DZC2EPwCx5peUBvn/RZQ4Gu
         WxBG3/pIKZfSZn6xTowZ5isgzoMRzG+WQ9NkCtLXKC4uhvfUnJlJ8Y6as+b2oD5snwcd
         IiOncTEFTjQJ4PYUAHpBTr3i7b02H9YN10RmrlVAfmNa/oKdSUgLS3hRQDXEM8GJ1EPw
         Af6xYtTaMFRP9mLlyTGGOaIVP4wsoEVFJ1NODyfRzrFH/RZaahlHTB7Jn/DWF4H6gYuJ
         5PSd+yeNPoiTxA3oJwD4fpV7qqaaTS2QeeqCigH6gG3Fn+tiF3qHzeNiMEBovsQSuSEX
         oitg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y4ynlCXK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cffuNjJKVPbcCD+n9g5peUV1PLGOmFBUhRn5tiGumq4=;
        b=YrgABUhd/zRnQOk0xKshc0KhuzeLYndE29osviyYb/efOg0YZYtlJDARDtAsbbNbm7
         r6rEV/SmB8NYsTahSC8xuNKXj//q3PVSyJMCH92ESglAefMWSqGNCXFUvPUXqkmZ3R0V
         b/oTD7XIcheyXMsZhl/SCE9a9EaNjOA79cMkv02FYsD1KfF7PVxuqsW8xr4ItaViatbe
         BHdYmI4GlbM6enQAlvlGzbormp6hi93cObbtJlMbAoPwaKqMA+Y69zXsPQ5cmI/ihqyA
         4obUKMre34MdiF5VkhS8uz/UR96RRVWAelY1JVDvp8CXAktrSQaUhufE8TxuYg5Y5TdU
         0f3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cffuNjJKVPbcCD+n9g5peUV1PLGOmFBUhRn5tiGumq4=;
        b=ZUeXuC9wJzhWzLbeSu7rkf8yHNBc3lojw55HgQid8TOZq3pSIXr0ByluiSD9yUAWfJ
         lPsJGbKRS4mOGq3cyexXlHjz6uP6iLN/PNaGZWGtoVTcDpwRwbzl3JBDeHd6ErtzyEdy
         Uj12PBMlP07DrdiK8AjIIPTI6Jk0lwH/4NG+tm7LbWCNWP/rlWolTx6KVmG14ggfJUeE
         xVDgDPBrRTK6tZ4sTMTLaUNoiee5lmCsv1+8W7MatHCwoL6AIzrypf1DmzD3NacMBPd6
         lq65nzGDwRydKYfI+Gjfb7aDBo52rmcdnRAe8p1MsiZEfZ5wtIhx0p7Rp1z5sPXvd9oj
         yWpw==
X-Gm-Message-State: AOAM532QudIF/aY1hC7+5EwbfPIX7FnsY5JsqyN26QSQi5t3kK2xDzDy
	GYQ3rhmoN0xWEmDO+lTu4t8=
X-Google-Smtp-Source: ABdhPJxxyDKS/5cRA1Mc7ehPjdPfPcPktpJlktFnbVg5fvYO1rsiYSl3VB30Jy09IVnsemIW9uLXGw==
X-Received: by 2002:a67:f544:: with SMTP id z4mr5909937vsn.217.1596720370355;
        Thu, 06 Aug 2020 06:26:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1d84:: with SMTP id l4ls281543uak.9.gmail; Thu, 06 Aug
 2020 06:26:10 -0700 (PDT)
X-Received: by 2002:ab0:1d18:: with SMTP id j24mr6266066uak.30.1596720369975;
        Thu, 06 Aug 2020 06:26:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596720369; cv=none;
        d=google.com; s=arc-20160816;
        b=hc0cPzPrjPMQbual8yTteDIp1WK5Cc4XTUFzCzp1szXssEpDrKiRVVhzMEip2sWpXs
         c5dyMU81LOuCSs7n62GVP693gGGkfxNQRxp7FimZNcicqkRjMp6xG6FNlSFB0Ix5v5L3
         H4Dssb4BfFp2oxvhEAnE2h+EjDgHfuqMYQzsJGoCeXoY92DcuQ5YBDHuecK2Mc/ETzWK
         1NtRap4+JW8tKdnQgq64lwXotjVdhebJ4gE0L9CW2Ev/RtnQwsZ6EOCmiDmI5UzOFf0N
         o9yEZwTusqbHs3HcgUYsvc4jKvifuInjHcxUX/n7Bfb1lga/CG4P2+Y7L4pwT1uuogEY
         YNmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T2iPfxLBjVspZYrNz+huCOCqkAd+X2FNwnJZLpWw+hM=;
        b=sMvRkxXusLT2PCd1s+tg9v0ybaQO+LKHuWNxxJ+gtCUttf560V+2k2wIDxxJWcENi2
         Wd4pbKe5M/BZGNcvkRQSCF4l3INx32dlat/Til73sZD+UgWf6a+vMC3/zAj9XYAtO1FR
         mkrdiR0NC1kJSR4/cs0D0P+VUmiNNVEll/b+ReWHMXNpuAwlCugqY38F2TZ8bt4XYkx9
         3v4DQXnzIhQKIIuY3qFhmAzfXMZjgHMMbzru+a2I8rVzsa9VqD61UYFkBUj2SPDPuSNr
         zHt1cwnoaMBDZbSrZmhO/LQA0S/0AvGKu6/zQRTW+YUsPhcLMRsQ/IOirQDDFDh0QtzC
         7uOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Y4ynlCXK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id l129si421361vkg.2.2020.08.06.06.26.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Aug 2020 06:26:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id d14so44851733qke.13
        for <kasan-dev@googlegroups.com>; Thu, 06 Aug 2020 06:26:09 -0700 (PDT)
X-Received: by 2002:a05:620a:676:: with SMTP id a22mr8706700qkh.8.1596720369262;
 Thu, 06 Aug 2020 06:26:09 -0700 (PDT)
MIME-Version: 1.0
References: <20200805230852.GA28727@paulmck-ThinkPad-P72> <CANpmjNPxzOFC+VQujipFaPmAV8evU2LnB4X-iXuHah45o-7pfw@mail.gmail.com>
 <CACT4Y+Ye7j-scb-thp2ubORCoEnuJPHL7W6Wh_DLP_4cux-0SQ@mail.gmail.com>
In-Reply-To: <CACT4Y+Ye7j-scb-thp2ubORCoEnuJPHL7W6Wh_DLP_4cux-0SQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Aug 2020 15:25:57 +0200
Message-ID: <CACT4Y+aF=Y-b7Lm7+UAD7Zb1kS1uWF+G_3yBbXsY6YO3k2dBuw@mail.gmail.com>
Subject: Re: Finally starting on short RCU grace periods, but...
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Kostya Serebryany <kcc@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	"'Dmitry Vyukov' via syzkaller-upstream-moderation" <syzkaller-upstream-moderation@googlegroups.com>, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Y4ynlCXK;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Aug 6, 2020 at 3:22 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Aug 6, 2020 at 12:31 PM Marco Elver <elver@google.com> wrote:
> >
> > +Cc kasan-dev
> >
> > On Thu, 6 Aug 2020 at 01:08, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > Hello!
> > >
> > > If I remember correctly, one of you asked for a way to shorten RCU
> > > grace periods so that KASAN would have a better chance of detecting bugs
> > > such as pointers being leaked out of RCU read-side critical sections.
> > > I am finally starting entering and testing code for this, but realized
> > > that I had forgotten a couple of things:
> > >
> > > 1.      I don't remember exactly who asked, but I suspect that it was
> > >         Kostya.  I am using his Reported-by as a placeholder for the
> > >         moment, but please let me know if this should be adjusted.
> >
> > It certainly was not me.
> >
> > > 2.      Although this work is necessary to detect situtions where
> > >         call_rcu() is used to initiate a grace period, there already
> > >         exists a way to make short grace periods that are initiated by
> > >         synchronize_rcu(), namely, the rcupdate.rcu_expedited kernel
> > >         boot parameter.  This will cause all calls to synchronize_rcu()
> > >         to act like synchronize_rcu_expedited(), resulting in about 2-3
> > >         orders of magnitude reduction in grace-period latency on small
> > >         systems (say 16 CPUs).
> > >
> > > In addition, I plan to make a few other adjustments that will
> > > increase the probability of KASAN spotting a pointer leak even in the
> > > rcupdate.rcu_expedited case.
> >
> > Thank you, that'll be useful I think.
> >
> > > But if you would like to start this sort of testing on current mainline,
> > > rcupdate.rcu_expedited is your friend!
>
> Hi Paul,
>
> This is great!
>
> I understand it's not a sufficiently challenging way of tracking
> things, but it's simply here ;)
> https://bugzilla.kernel.org/show_bug.cgi?id=208299
> (now we also know who asked for this, +Jann)
>
> I've tested on the latest mainline and with rcupdate.rcu_expedited=1
> it boots to ssh successfully and I see:
> [    0.369258][    T0] All grace periods are expedited (rcu_expedited).
>
> I have created https://github.com/google/syzkaller/pull/2021 to enable
> it on syzbot.
> On syzbot we generally use only 2-4 CPUs per VM, so it should be even better.
>
> > Do any of you remember some bugs we missed due to this? Can we find
> > them if we add this option?
>
> The problem is that it's hard to remember bugs that were not caught :)
> Here is an approximation of UAFs with free in rcu callback:
> https://groups.google.com/forum/#!searchin/syzkaller-bugs/KASAN$20use-after-free$20rcu_do_batch%7Csort:date
> The ones with low hit count are the ones that we almost did not catch.
> That's the best estimation I can think of. Also potentially we can get
> reproducers for such bugs without reproducers.
> Maybe we will be able to correlate some bugs/reproducers that appear
> soon with this change.

Wait, it was added in 2012?
https://github.com/torvalds/linux/commit/3705b88db0d7cc4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaF%3DY-b7Lm7%2BUAD7Zb1kS1uWF%2BG_3yBbXsY6YO3k2dBuw%40mail.gmail.com.
