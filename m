Return-Path: <kasan-dev+bncBAABBIF6X3ZQKGQEKZDCDKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 64BE5186EE4
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Mar 2020 16:45:38 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id h125sf13049533pfg.3
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Mar 2020 08:45:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584373537; cv=pass;
        d=google.com; s=arc-20160816;
        b=juyEbYDSXTgtkisACTQ8vQTRkVHIN2T36NkkvIvrjoLn5VS8RcUOBzHkqVM7pjWt+y
         A4fWy07SLwgBOSMUFuR+sfLiFXNqSAdEqlf8W5JgDyYDmvX5AR01lIU8ui8UmvmyP9nO
         PhbFm55Oj3L9tDQRb8LdlXsgL64RKcHglBBKUj/ZBQcIKcT1xVzqdWCEXHxWCzoiQJai
         Hl2eMzYfUE4J7jHpAEDk7IP3pHH7VPSlCqKPmMEDYBYTfrFYDelJVuLegKxe7jE/jwmU
         tPsSaWKWGUmxvKKk3JFHK+zlhu9BfRxv2gBV1Gr7rO56lX65fuaomFX4vKAxiradeUPl
         De6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=vQ8jp9s3cX2WM+TZ71e7MuHAeQsNysONoHqHA7HMj2A=;
        b=CUr8cu51g6PhHg6M3qP1kr8rjxU7k7xGllz3j2gUI3Y338vWQSjGvaPSH0VXj4KMOq
         us6PgBFnCgYnWlmrJt3HuuYZC0ztrb0Cd8PDCtuOGWihclDBHXJla1XnqTdDkZFmhZqZ
         M3P1rbBMqnLMo/byGhiQBtyFeuBIFPgHbfNAOsbq/KkNuhhkg+gUzd9DfwMlXHlz2rdO
         BXLnn9dgaGlMr4QiKmWGJDx+3JoNx+wk7+yCl6LX9uORlB26Z108Zt356XxvHl28v86c
         W0VZ0Mk3hYCcKxCv5V/PG1FciRii5oEZ2qlKWFcmM0LJ9ZhTsLErCxCHFO5KEi75gADA
         JZXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=P1EkSJ3r;
       spf=pass (google.com: domain of srs0=3wbc=5b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3WBc=5B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vQ8jp9s3cX2WM+TZ71e7MuHAeQsNysONoHqHA7HMj2A=;
        b=FcjQAAItKHtaJs6OTMX9QdZOXn7imxk6aEG+InJGvvlq2hFIDqvm/QuuD6BOtUOQdQ
         SLYUVo/K41+fWVXBu7DJjcwRcGyPDdosgx1xnmrmUZdqLV++A2nNoF6WRISiOVYk+2Jg
         pTTaXFqUvr3ITAPY+2ZPxV8pgXgbqFsfAkBSaSmmdswI2XjjCWIevIMXS9sPagtO845a
         k8mbPtZo0h5UGQPBzBhzLMitw0JTbRqhZ/aUkbKbve54+r3WUCuC/SxYNihiJf/KqJRp
         TGZ8Cw1QOzwzaU7P0+voyOwzj5qfXSJ5NCEwdjDT7alcLsT96KTqTyYiKS52+UU1JIol
         2Tbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vQ8jp9s3cX2WM+TZ71e7MuHAeQsNysONoHqHA7HMj2A=;
        b=JG31NdExpgrEsvEXPdbXGqLagdCVZuhOpmzy4d/8Xhc8cps9hsML7qoszL+8L0zofI
         Kf/wh/3SS2C73iwiQ7GO0L/HlFrGxNmVythLipya27DXBYynJfDfgbMIhTN6BtMsEzIl
         lDavTmCe5tGwzt6tbaU/EkI5zsekM4y35gc+5yyXE7EIglBnoNuC4JVVgEt/vEkgImrC
         /hUSYBBLExOH6FBkGmst7qH7MXU/88TKU/FRJuhT/JBnyEAN4YHY0joasiHfPkJpzj/z
         Gsi71rO4P2goDhapywtmM7qdJEecuv7XpTfaUkwDI6cvFQN/a92rAqjPSi3q/ERYzrpT
         2Dzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2qG2R0F0FfXIQM/EQ/ikgby/ozYuvfrlCGA3SkCIMtmoADmBnz
	4huq0Ob3CoPI4jLzVnjtg3o=
X-Google-Smtp-Source: ADFU+vvODd5bj0n/f3RUuxdtrBFaVnDOUz5EvHXoiKtS6A64gcFMz1OyaY4Bvh3ELReYzJfSsF7l2A==
X-Received: by 2002:a17:902:8492:: with SMTP id c18mr28100796plo.147.1584373537063;
        Mon, 16 Mar 2020 08:45:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:150:: with SMTP id 77ls9146460pgb.0.gmail; Mon, 16 Mar
 2020 08:45:36 -0700 (PDT)
X-Received: by 2002:a63:7c0f:: with SMTP id x15mr454360pgc.173.1584373536296;
        Mon, 16 Mar 2020 08:45:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584373536; cv=none;
        d=google.com; s=arc-20160816;
        b=ztHi7lddoLk2UwU7cy71PrTDdU06zf4qwBpwIM7M6BYLMB+Srxu8pxOg7sMeqbBaTB
         NhgAXBEwP6pHFG87EPAHJSgGPKPmwF63Jrb+tRK5faSv6rlrG94cke7ziPC8ckzSYlyJ
         s9DGpvJ8PWBCzAdwL3vkMtugaHpPqxaJ/XTplwSjLUGBGe0ZjvbVa0WpzezghV5adfkW
         ncaCOUbtV45rG8cYNKbTFRC9qhETonNcnM1hXtajkdHEzUUCutWebfe2qOmD7S2IPUqT
         PzD+j7wW1zTFesW+5IHECf+2Gg67oGiJduOqZsDjGC+90dRNU40mHBz0xe51gQgDndiW
         bPTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=V8EfCzRe1ZkKcWppbRZ8GWcfVxFypi+/FZ7jQAKdV6o=;
        b=jCj55RdVJwqXVDdG9DbkM9ePDota15Nb3dvMyOpEt9tIAW9OX/dI25t+0L/790/SW3
         tflM4XnQXe6a/8W77Q/Ob7lnNoWA5AGRkY37IrS81D/nnseJ4FYiokx8ou99WzYSuzgt
         l9nFukviITXjJgmKfBXPR0cVo7VXnBV6gyo/SFtZvybr9O8iNXzsfkDWgy91tbgq8NI7
         YbOHDV7LfBkmVSlJc5Uc0hDF4NqxrNQLNE/b7mbP3WKEuVsXc1joePDtwETxJ4eTngfj
         lCuZkojBqyZfHbO0zrkc38h7R0a7sKdwka3NywF0AU1PHU4stuG0y3l3ee1W0rVjim1B
         1qTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=P1EkSJ3r;
       spf=pass (google.com: domain of srs0=3wbc=5b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3WBc=5B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q197si20866pfc.5.2020.03.16.08.45.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Mar 2020 08:45:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=3wbc=5b=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id F310220679;
	Mon, 16 Mar 2020 15:45:35 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id BD7EC3522DE1; Mon, 16 Mar 2020 08:45:35 -0700 (PDT)
Date: Mon, 16 Mar 2020 08:45:35 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, kernel-team@fb.com,
	Ingo Molnar <mingo@kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>,
	Boqun Feng <boqun.feng@gmail.com>
Subject: Re: [PATCH kcsan 27/32] kcsan: Add option to allow watcher
 interruptions
Message-ID: <20200316154535.GX3199@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
 <20200309190420.6100-27-paulmck@kernel.org>
 <20200312180328.GA4772@paulmck-ThinkPad-P72>
 <20200312180414.GA8024@paulmck-ThinkPad-P72>
 <CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw@mail.gmail.com>
 <CANpmjNO=jGNNd4J0hBhz4ORLdw_+EHQDvyoQRikRCOsuMAcXYg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO=jGNNd4J0hBhz4ORLdw_+EHQDvyoQRikRCOsuMAcXYg@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=P1EkSJ3r;       spf=pass
 (google.com: domain of srs0=3wbc=5b=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=3WBc=5B=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Transfer-Encoding: quoted-printable
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

On Mon, Mar 16, 2020 at 02:56:38PM +0100, Marco Elver wrote:
> On Fri, 13 Mar 2020 at 16:28, Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 12 Mar 2020 at 19:04, Paul E. McKenney <paulmck@kernel.org> wro=
te:
> > >
> > > On Thu, Mar 12, 2020 at 11:03:28AM -0700, Paul E. McKenney wrote:
> > > > On Mon, Mar 09, 2020 at 12:04:15PM -0700, paulmck@kernel.org wrote:
> > > > > From: Marco Elver <elver@google.com>
> > > > >
> > > > > Add option to allow interrupts while a watchpoint is set up. This=
 can be
> > > > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > > > > parameter 'kcsan.interrupt_watcher=3D1'.
> > > > >
> > > > > Note that, currently not all safe per-CPU access primitives and p=
atterns
> > > > > are accounted for, which could result in false positives. For exa=
mple,
> > > > > asm-generic/percpu.h uses plain operations, which by default are
> > > > > instrumented. On interrupts and subsequent accesses to the same
> > > > > variable, KCSAN would currently report a data race with this opti=
on.
> > > > >
> > > > > Therefore, this option should currently remain disabled by defaul=
t, but
> > > > > may be enabled for specific test scenarios.
> > > > >
> > > > > To avoid new warnings, changes all uses of smp_processor_id() to =
use the
> > > > > raw version (as already done in kcsan_found_watchpoint()). The ex=
act SMP
> > > > > processor id is for informational purposes in the report, and
> > > > > correctness is not affected.
> > > > >
> > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > >
> > > > And I get silent hangs that bisect to this patch when running the
> > > > following rcutorture command, run in the kernel source tree on a
> > > > 12-hardware-thread laptop:
> > > >
> > > > bash tools/testing/selftests/rcutorture/bin/kvm.sh --cpus 12 --dura=
tion 10 --kconfig "CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONFIG_KCSAN_ASSU=
ME_PLAIN_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn CONFIG=
_KCSAN_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VERBOSE=3Dy CONFIG_KCSAN_INT=
ERRUPT_WATCHER=3Dy" --configs TREE03
> > > >
> > > > It works fine on some (but not all) of the other rcutorture test
> > > > scenarios.  It fails on TREE01, TREE02, TREE03, TREE09.  The common=
 thread
> > > > is that these are the TREE scenarios are all PREEMPT=3Dy.  So are R=
UDE01,
> > > > SRCU-P, TASKS01, and TASKS03, but these scenarios are not hammering
> > > > on Tree RCU, and thus have far less interrupt activity and the like=
.
> > > > Given that it is an interrupt-related feature being added by this c=
ommit,
> > > > this seems like expected (mis)behavior.
> > > >
> > > > Can you reproduce this?  If not, are there any diagnostics I can ad=
d to
> > > > my testing?  Or a diagnostic patch I could apply?
> >
> > I think I can reproduce it.  Let me debug some more, so far I haven't
> > found anything yet.
> >
> > What I do know is that it's related to reporting. Turning kcsan_report
> > into a noop makes the test run to completion.
> >
> > > I should hasten to add that this feature was quite helpful in recent =
work!
> >
> > Good to know. :-)  We can probably keep this patch, since the default
> > config doesn't turn this on. But I will try to see what's up with the
> > hangs, and hopefully find a fix.
>=20
> So this one turned out to be quite interesting. We can get deadlocks
> if we can set up multiple watchpoints per task in case it's
> interrupted and the interrupt sets up another watchpoint, and there
> are many concurrent races happening; because the other_info struct in
> report.c may never be released if an interrupt blocks the consumer due
> to waiting for other_info to become released.

Been there, done that!  ;-)

> Give me another day or 2 to come up with a decent fix.

My thought is to send a pull request for the commits up to but not
including this patch, allowing ample development and testing time for
the fix.  My concern with sending this, even with a fix, is that any
further bugs might cast a shadow on the whole series, further slowing
acceptance into mainline.

Fair enough?

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200316154535.GX3199%40paulmck-ThinkPad-P72.
