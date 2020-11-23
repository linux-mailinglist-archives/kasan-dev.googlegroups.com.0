Return-Path: <kasan-dev+bncBCU73AEHRQBBBIOG576QKGQESHCE6VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C23922C1036
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 17:28:18 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id a13sf23740344ybj.3
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 08:28:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606148897; cv=pass;
        d=google.com; s=arc-20160816;
        b=TSohmhFi2hA1I0s5gTUKqzPrBlXr5emlumvOgVkztfxVVSNu6MnbqHgc4idHIDo4VV
         5rJPbxVG7MBIcgNrz5uaqTwWJjnaGB73CRoNKw6lnxmBAh+TOGfzTZ8bKZYaGKy6AL1H
         PhduEDxjoqVzxvDJ8L67e0KbQBCCG4mmameya30dLgWCfAjw9sqb5eE7tLHOXv7deUGB
         hT+kX4Jws2gT36Jdu5w9np5YH9zHYmy6hYNSNBEOl2V6/MClX3k+NT5sO8LJUuz7Pz03
         lHabHew0qPGY47u4Kq4irFCI1okvTmQ8bsqLFHnUnP8Lp75iGeEUGKgEEgcryVy2vQe1
         TocA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=smvWuE08HSTALXtZJDbB4uh1quxV7RSfNglvg6LhXd4=;
        b=WvDN7ZgR3S+RvCthkS2wvEraMONHX/7AW3RsL32vCKnDftzu9O0ns0HZN05twt/2sF
         OITiAOAcI1Zjww02GW5qLaMkGPe0G2KxCYAxCGZpYQULEG+nbhfrpyiCYytua9qFup91
         G13sXdSmcKzK4stzJxGWtt3tEMbzMaA33GVWbK0Hul2Vk3c3pTuihaDWLaQaSsl/4sIG
         HBxmfxRzoxA8LbFwCmJHMy6K1PdLcqBLx5xc0ram5ZItktq7tdGe117hAYPc0MoqjfT9
         f/NhaIqmBV2+z7thU6eecAPLE5n8PbIKY0dqPuc/yKbi/WO6dBCGAd/PHsoDtBCil8wu
         PeqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=smvWuE08HSTALXtZJDbB4uh1quxV7RSfNglvg6LhXd4=;
        b=is39tA5EcHXOJgFrJ2lL8XcMrUAml7D93ZmSvP1OxpepJ/oL6qeqBoWjt/g6qHZkf6
         RtC2P5aEGfX39oP8gA/QORBCP3jWzD/TmHZiBP34bpSqDYNzZatx4NEFWxuwQxqPe+tG
         5nT8fb46XABlw8C+xKNwYiKk4U32Lyhph3x/XbCmc/ox49PwUyFpaBzPoJwqO4XX94tD
         9fFTf78FQ094CedBBI9xy2O8PArtVON3P9utiQIeqaS/ODsKEJTQNYBZS90bdNAwvAY4
         AGSNKJbeX4vF1BQUz6BzPPeisoFqaZd0SOdRpqIn1SNEgfrQE95o+CNxvN3B0DeavG/W
         W14A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=smvWuE08HSTALXtZJDbB4uh1quxV7RSfNglvg6LhXd4=;
        b=PVDPy6WjafHrkmLQOipT/Sdy36FqHzqJ734gypPK91vFHTWj+MOQJr/Scosf8BSMr2
         gLKhTYVUdrO7M9SbofWjSVwFkW1y8694Q8/lQLFQw4WxnROVjGkVn2VgYNrpD0/8asj6
         Sys4cuB+VzJqjt0uthviI1NG7nmp8n6VTUqHxs9nZ/Oq0SkrvPTKB6oHGit8SOyMU7qK
         ly58HwdgikxDKrMsqKVpaIfqmB9AIyxxtKE9asNnoBTjWf0a8Tl7dpp0GNOznnveogo+
         BaYIGmC/ug5lS4nUL5hDdxFKFy4m4yM5pyDxbQR5SLsk0LFZjYEbMantUBblxkjpCIkb
         9rfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JTD7/Ea9PYzgMJbJUkqi/BSUz2Yk/EyhMBtEW4LkMbdqAbhUJ
	2gn14wBqcYC3cpq1Rzh8QpA=
X-Google-Smtp-Source: ABdhPJw6rrvars0d9vgMryNKEpJQv/3ndpeHOuCkL7gTlrcixZi/STBLIAgeu7u4ckSn/shIY/s/MQ==
X-Received: by 2002:a5b:cd1:: with SMTP id e17mr296082ybr.177.1606148897813;
        Mon, 23 Nov 2020 08:28:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:610b:: with SMTP id v11ls228533ybb.3.gmail; Mon, 23 Nov
 2020 08:28:17 -0800 (PST)
X-Received: by 2002:a25:d695:: with SMTP id n143mr310361ybg.125.1606148897393;
        Mon, 23 Nov 2020 08:28:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606148897; cv=none;
        d=google.com; s=arc-20160816;
        b=lCB/FBqhtEK2DFulBA3ryPRo/N/5tmLpwCLHGBU2hpAC0XA0ZouoATsa1o5+Uv2G4i
         ElSgYcH/YKSPWvS0XhLJTfGdIFa7dSRxqIvlKLYYhCK2igfi9BnCBl3YFsvfFd/Hn0YI
         4t2n/EW4+uVz59mB746fl4Ro00GT5lOaFN5dEG4p8zzYVHqtRyPpiWBFAaaWzgfCxzi0
         /oqUchV9vGsgcacgm13HDiOaea/DQU7g8fxKa7NIUMRgrAjMGNqISEaMvAomufvnBskR
         3tqP1VO+QILc1ThJhC1frq94K1DnVBNEeBpEO+cIEj/gzgkHxnlvLSP/ADXNjvOr0D1P
         +fUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=PQPppfzsBmPDr08/CgUCnm+8xPvjpsh4XO4EiojNulI=;
        b=WqdlDvjQQlYbAlyJ+Kbd60En24zZ2UHihNqQBqHc11YcoD9/DyKeGo0aZtUWQAkstD
         jVI609BFfnH2GmngJ+HohtHQZSLvbtXLGpN9DRrdB/SpO7soqEUV4AtRyx3q48LNJ3yr
         9Z9yt+blu03mFiuvalP1IRPiXsU2BQZgZUreNtQnXXyH0iFyZ0esY0psLkielnuQZS13
         y5w13KdWr6ZpXO0wOA3CLEHs4U8QC968/QjL9N2VF9RohjZ/e5ANjIMvPKV8WttPDNof
         udSBj0HgadpnxqIrfqaZX2xmjqiuhhdwmYyitluy4wq1Tfv2MkUo3o4U6A1/vL4a/bsU
         HZkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n185si716878yba.3.2020.11.23.08.28.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Nov 2020 08:28:17 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 7106E20644;
	Mon, 23 Nov 2020 16:28:14 +0000 (UTC)
Date: Mon, 23 Nov 2020 11:28:12 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Anders Roxell
 <anders.roxell@linaro.org>, Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Jann Horn <jannh@google.com>, Mark Rutland
 <mark.rutland@arm.com>, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, kasan-dev
 <kasan-dev@googlegroups.com>, rcu@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
 <jiangshanlai@gmail.com>
Subject: Re: [PATCH] kfence: Avoid stalling work queue task without
 allocations
Message-ID: <20201123112812.19e918b3@gandalf.local.home>
In-Reply-To: <20201123152720.GA2177956@elver.google.com>
References: <CANpmjNNyZs6NrHPmomC4=9MPEvCy1bFA5R2pRsMhG7=c3LhL_Q@mail.gmail.com>
	<20201112161439.GA2989297@elver.google.com>
	<20201112175406.GF3249@paulmck-ThinkPad-P72>
	<20201113175754.GA6273@paulmck-ThinkPad-P72>
	<20201117105236.GA1964407@elver.google.com>
	<20201117182915.GM1437@paulmck-ThinkPad-P72>
	<20201118225621.GA1770130@elver.google.com>
	<20201118233841.GS1437@paulmck-ThinkPad-P72>
	<20201119125357.GA2084963@elver.google.com>
	<20201120142734.75af5cd6@gandalf.local.home>
	<20201123152720.GA2177956@elver.google.com>
X-Mailer: Claws Mail 3.17.3 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=epz8=e5=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EPZ8=E5=goodmis.org=rostedt@kernel.org"
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

On Mon, 23 Nov 2020 16:27:20 +0100
Marco Elver <elver@google.com> wrote:

> On Fri, Nov 20, 2020 at 02:27PM -0500, Steven Rostedt wrote:
> > On Thu, 19 Nov 2020 13:53:57 +0100
> > Marco Elver <elver@google.com> wrote:
> >   
> > > Running tests again, along with the function tracer
> > > Running tests on all trace events:
> > > Testing all events: 
> > > BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 12s!  
> > 
> > The below patch might be noisy, but can you add it to the kernel that
> > crashes and see if a particular event causes the issue?
> > 
> > [ note I didn't even compile test. I hope it works ;) ]
> > 
> > Perhaps run it a couple of times to see if it crashes on the same set of
> > events each time.  
> 
> Thanks! I have attached the logs of 2 runs. I think one problem here is
> that the enabling of an event doesn't immediately trigger the problem,
> so it's hard to say which one caused it.
> 

I noticed:


[  237.650900] enabling event benchmark_event

In both traces. Could you disable CONFIG_TRACEPOINT_BENCHMARK and see if
the issue goes away. That event kicks off a thread that spins in a tight
loop for some time and could possibly cause some issues.

It still shouldn't break things, we can narrow it down if it is the culprit.

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201123112812.19e918b3%40gandalf.local.home.
