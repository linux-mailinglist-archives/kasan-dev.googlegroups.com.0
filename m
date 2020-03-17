Return-Path: <kasan-dev+bncBAABBMMKYTZQKGQEKIFLMJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A4E1D188BD1
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 18:13:22 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id d2sf17401120ilf.19
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 10:13:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584465201; cv=pass;
        d=google.com; s=arc-20160816;
        b=etQNq2Ojw0oHQGIolV2NT5+TjlLS45hNAZGMQLciZWfaDXt9HSmh+8Xk3NBU8XfpCy
         eW5PdkyCCZm+UAjUb4OGeta5jvVXWtrTF041zv62o8dgQ0PLPbz2u5/dNGXfHqVKuAjS
         6p5cft5TBZdJ8TYqZ+9Cwq9l2Bv0s+GzDWxizKEy6lzjD0wZLof3dDKkjLn9vpC/T9ol
         BIyR/p2gN+gLUJfzTCn6w0y4C9JMuAQX1BAbo+CHYGWzid81Muea/VKX4y86/gIK0cHz
         +vZFCMZUV1qIosMDeCJe8ZZB2CScEMqjDTBH5yb9R/CZXuDbSRAaysmdfcjYF+UsMTbO
         yFxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=hb9lxj6LHyUIMRirLd1D7PCe73JrBzgxDcW4j9ozo78=;
        b=YURWjBlt/QbsXJete0mI2k5j6z9rIrCGeWuZzcnWWiH+0nBq3T/8vNDT0wOJBypmgo
         sG0bE3waffBR1nYWz9ZSNf+X93f2Dgf1NgSrtCZbDFYsjkkxS0Ghd0X5YUw1O4e7jKJG
         hiY/seB3GSysJjX2ffjmYcS2bHtxg2NCrS0wwWWJsBDfnkrDXVkAF22mjuAr4gx5xt+p
         ElxDAmR0ouON2dP4gqxkeVEaZAcU+HB2Qi15Vz4qaXMyTjFdF1k/LHkBbseURrg0s1EQ
         uIEVJIIpDJNJbJo+1NAJh82RS/ISkTZTr5aoHNrgbmvQsIqzi9p2N3+Q4EQKhr2cMb0A
         LUgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mR6aXKPi;
       spf=pass (google.com: domain of srs0=04wj=5c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=04Wj=5C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hb9lxj6LHyUIMRirLd1D7PCe73JrBzgxDcW4j9ozo78=;
        b=Es3TyuDpGlIr/S0aeLQQ/1YrBwwcvCJdTbJGTuvisrBJxQY3i59xiiVAz7eyodhpxL
         JdzCz/16ZGin23cj5q+9hezWrqwy6TCGVxB4GOJDLaXS+mQ37CwQbDEaUaNgvDnQtFKx
         yP3AyVFJG6ETt4Wei2/uRH4oEwfBPDFWk722Pf+fhEmimdxlrDbGDBysNgDkAINMm51M
         xTW7g6mBETO3qoNUaK0wwatrxQU2iBj/wFPxn9dyfktdfPURxf5R0KuMzVD+ZSZPa13V
         /R7/Wum7SiSGF53O2slM7kuuN3jkwwTyC6qUH13hfYvvIYalv3Xz5avsVbghdl2UYDiH
         zLMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hb9lxj6LHyUIMRirLd1D7PCe73JrBzgxDcW4j9ozo78=;
        b=KotQpTMEkB6GyDLs1SMElmL1l9p5SNr8vMAbqIxUVenbATR3GMMipmp0J9HV6KtSXc
         o0S1m4dDvt/jB31HS3/YBq/PcblCLjYhS3DjeCd6YebL8pRUFFD76ywYuquNnXNIHpYF
         /yqfoITzb2rUI+ECq9LpkmrhrNT/EZwrNY3fAZ+e81lbNqdbqXxhYunbElFutF4c+bS4
         +jIApxA3VkkBIDypZ8n9NDlma6NNGY9flDrVWghZyBn/rAA9tnRa0HYwMyQRIJ7EBQBg
         FYjP3ZQwoasHoU4QRnWNHWuy2/eR+f/hVyByBC7Ufr7lyu4SgNMUizs8EW8mFLxU3MBY
         aIKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ055kvEmgvSk5GUYHOOXvYbEo5Ht6mezIWQL4Q7Q0TfvLqr+jtg
	X9MdLAbCzN96FFvaO/pdph0=
X-Google-Smtp-Source: ADFU+vsGPyhSyOQqX/PjYnfOupMNmk2zb1ItV89rTTqyCQoI8LiyFoTxesghqp3JHGP8Rq1MIu5D0g==
X-Received: by 2002:a92:86d1:: with SMTP id l78mr6204085ilh.172.1584465201395;
        Tue, 17 Mar 2020 10:13:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8106:: with SMTP id e6ls6033599ild.6.gmail; Tue, 17 Mar
 2020 10:13:21 -0700 (PDT)
X-Received: by 2002:a92:4b12:: with SMTP id m18mr6447383ilg.204.1584465201122;
        Tue, 17 Mar 2020 10:13:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584465201; cv=none;
        d=google.com; s=arc-20160816;
        b=RPe1jh44BIdGzxvRB4wJHU5xX6VwTV1QvPy8OLZIFS9O7BFzNeZivUKmLibUrDJJj4
         yNYWTdm5Ea8647dGQUgx0fbWJMMhGqpm+pu0IhqcAf5tFq8ZYDRoAYfF2wEdf9zrmGaQ
         g23fH/PUBLCEN+2DFQD/2LuHcSu+kR2w6tJ7z6HzGjj3mji6eW0VNSUjE/G2PNO51trJ
         eeq9jKpnuh9YWRw7N+IDm6zd4GXd6IXtjnJuCKigBu3wvjKGd1mMTB+QHsODTR3yoUi7
         a4//QKPmD6VGi1XwdeU6X8eT/N8xtcwuIXzWhJoymdoFjvut4CQo92FF0ZRQuZ3wBxvs
         VuhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=W9B5D8RNzLHSs5ex7KSZazRjBGKa0YOcmwTm3BEQz9M=;
        b=xcfrct4yIciOGsKqxBKpq6egRrk/5qrvxC2MiK0+40lFdoAgC5XyzzYkt0cpTS4Z7m
         mZCk1Ljd/58MArSdUK8cC7d3Kac9syEBmLc2DBymWQ5wodMiWOzx3W76VtxaBnzPAn1G
         2dupVbvIJyLH2Krd+TQv2t1htMdUaAtlQW2Yfxi/K/8OC4EKS7WWZawRhdezBfAe3yVA
         oQv13RuR/x4u1chbAa073IYE7j9M9JaYFQB55J8efGLPEWzOLU2pQNhGrM0PHuoCNOmq
         vZVQ1cW73RshmZNrU10TeR9I9E9XKB5k8thOYaotssr+lijcWCwtetysnR6QqCYJAnsa
         BvKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=mR6aXKPi;
       spf=pass (google.com: domain of srs0=04wj=5c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=04Wj=5C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v13si232866ilg.4.2020.03.17.10.13.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Mar 2020 10:13:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=04wj=5c=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 57CFC20738;
	Tue, 17 Mar 2020 17:13:20 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 30E1C35226E2; Tue, 17 Mar 2020 10:13:20 -0700 (PDT)
Date: Tue, 17 Mar 2020 10:13:20 -0700
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
Message-ID: <20200317171320.GI3199@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
 <20200309190420.6100-27-paulmck@kernel.org>
 <20200312180328.GA4772@paulmck-ThinkPad-P72>
 <20200312180414.GA8024@paulmck-ThinkPad-P72>
 <CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw@mail.gmail.com>
 <CANpmjNO=jGNNd4J0hBhz4ORLdw_+EHQDvyoQRikRCOsuMAcXYg@mail.gmail.com>
 <20200316154535.GX3199@paulmck-ThinkPad-P72>
 <CANpmjNOsLeiD6hYXeD4g8fA=Ti6EiUsbtiv4VshRGg+oG1ct-g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOsLeiD6hYXeD4g8fA=Ti6EiUsbtiv4VshRGg+oG1ct-g@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=mR6aXKPi;       spf=pass
 (google.com: domain of srs0=04wj=5c=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=04Wj=5C=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Mon, Mar 16, 2020 at 05:22:34PM +0100, Marco Elver wrote:
> On Mon, 16 Mar 2020 at 16:45, Paul E. McKenney <paulmck@kernel.org> wrote=
:
> >
> > On Mon, Mar 16, 2020 at 02:56:38PM +0100, Marco Elver wrote:
> > > On Fri, 13 Mar 2020 at 16:28, Marco Elver <elver@google.com> wrote:
> > > >
> > > > On Thu, 12 Mar 2020 at 19:04, Paul E. McKenney <paulmck@kernel.org>=
 wrote:
> > > > >
> > > > > On Thu, Mar 12, 2020 at 11:03:28AM -0700, Paul E. McKenney wrote:
> > > > > > On Mon, Mar 09, 2020 at 12:04:15PM -0700, paulmck@kernel.org wr=
ote:
> > > > > > > From: Marco Elver <elver@google.com>
> > > > > > >
> > > > > > > Add option to allow interrupts while a watchpoint is set up. =
This can be
> > > > > > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the =
boot
> > > > > > > parameter 'kcsan.interrupt_watcher=3D1'.
> > > > > > >
> > > > > > > Note that, currently not all safe per-CPU access primitives a=
nd patterns
> > > > > > > are accounted for, which could result in false positives. For=
 example,
> > > > > > > asm-generic/percpu.h uses plain operations, which by default =
are
> > > > > > > instrumented. On interrupts and subsequent accesses to the sa=
me
> > > > > > > variable, KCSAN would currently report a data race with this =
option.
> > > > > > >
> > > > > > > Therefore, this option should currently remain disabled by de=
fault, but
> > > > > > > may be enabled for specific test scenarios.
> > > > > > >
> > > > > > > To avoid new warnings, changes all uses of smp_processor_id()=
 to use the
> > > > > > > raw version (as already done in kcsan_found_watchpoint()). Th=
e exact SMP
> > > > > > > processor id is for informational purposes in the report, and
> > > > > > > correctness is not affected.
> > > > > > >
> > > > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > > > >
> > > > > > And I get silent hangs that bisect to this patch when running t=
he
> > > > > > following rcutorture command, run in the kernel source tree on =
a
> > > > > > 12-hardware-thread laptop:
> > > > > >
> > > > > > bash tools/testing/selftests/rcutorture/bin/kvm.sh --cpus 12 --=
duration 10 --kconfig "CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONFIG_KCSAN_=
ASSUME_PLAIN_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn CO=
NFIG_KCSAN_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VERBOSE=3Dy CONFIG_KCSAN=
_INTERRUPT_WATCHER=3Dy" --configs TREE03
> > > > > >
> > > > > > It works fine on some (but not all) of the other rcutorture tes=
t
> > > > > > scenarios.  It fails on TREE01, TREE02, TREE03, TREE09.  The co=
mmon thread
> > > > > > is that these are the TREE scenarios are all PREEMPT=3Dy.  So a=
re RUDE01,
> > > > > > SRCU-P, TASKS01, and TASKS03, but these scenarios are not hamme=
ring
> > > > > > on Tree RCU, and thus have far less interrupt activity and the =
like.
> > > > > > Given that it is an interrupt-related feature being added by th=
is commit,
> > > > > > this seems like expected (mis)behavior.
> > > > > >
> > > > > > Can you reproduce this?  If not, are there any diagnostics I ca=
n add to
> > > > > > my testing?  Or a diagnostic patch I could apply?
> > > >
> > > > I think I can reproduce it.  Let me debug some more, so far I haven=
't
> > > > found anything yet.
> > > >
> > > > What I do know is that it's related to reporting. Turning kcsan_rep=
ort
> > > > into a noop makes the test run to completion.
> > > >
> > > > > I should hasten to add that this feature was quite helpful in rec=
ent work!
> > > >
> > > > Good to know. :-)  We can probably keep this patch, since the defau=
lt
> > > > config doesn't turn this on. But I will try to see what's up with t=
he
> > > > hangs, and hopefully find a fix.
> > >
> > > So this one turned out to be quite interesting. We can get deadlocks
> > > if we can set up multiple watchpoints per task in case it's
> > > interrupted and the interrupt sets up another watchpoint, and there
> > > are many concurrent races happening; because the other_info struct in
> > > report.c may never be released if an interrupt blocks the consumer du=
e
> > > to waiting for other_info to become released.
> >
> > Been there, done that!  ;-)
> >
> > > Give me another day or 2 to come up with a decent fix.
> >
> > My thought is to send a pull request for the commits up to but not
> > including this patch, allowing ample development and testing time for
> > the fix.  My concern with sending this, even with a fix, is that any
> > further bugs might cast a shadow on the whole series, further slowing
> > acceptance into mainline.
> >
> > Fair enough?
>=20
> That's fine. I think the features changes can stay on -rcu/kcsan-dev
> for now, but the documentation updates don't depend on them.
> If it'd be useful, the updated documentation could be moved before
> this patch to -rcu/kcsan, so we'd have
>=20
>  kcsan: Add current->state to implicitly atomic accesses
>  kcsan: Add option for verbose reporting
>  kcsan: Add option to allow watcher interruptions
> -- cut --
>  kcsan: Update API documentation in kcsan-checks.h
>  kcsan: Update Documentation/dev-tools/kcsan.rst
>  kcsan: Fix a typo in a comment
> .. rest of series ..
>=20
> Although I'm fine with either.

Given my churn with a recent merge window, I am more reluctant than
I might otherwise be to do that sort of rearrangement.  Sorry to be
so cowardly!

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200317171320.GI3199%40paulmck-ThinkPad-P72.
