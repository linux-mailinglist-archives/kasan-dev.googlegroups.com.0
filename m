Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIULX3ZQKGQEDLFLZDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E1E0186CB0
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Mar 2020 14:56:52 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id np18sf10126564pjb.1
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Mar 2020 06:56:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584367011; cv=pass;
        d=google.com; s=arc-20160816;
        b=c0/YII5Sf27qZNUEW0qg5GzYyPJsRvVHqkQd2V4qMCArtNg2FS6YRfPb32GsPA0w5+
         gYg03BuIIeAC8q5GKvaiz69erzlcInmoNyvSaQk4QoAHuKVFN4pULx0hw0F08OSbCBip
         2h4zXunguNeeSZPTgjBEpDMSpROaqNZONE7c3W4jpnwmw4dH6P+x9sxzC4eaSjljD6rd
         0KeVWUSiSL9EmX5UQ3yn+fgfIr8adfAvazf1XM4Mtjt5mQDEsiQo1XJZwO3qvZuNbl2a
         KcCM/I0oZM8L5eCoqHmKWCbEcv5KuurGWUz9Ue06iZiPKW3Ydli6TLjK/TbPbHl1d1Lz
         nTPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aPw821r7B4WuupMm/4Ckfh0rOWE0HiEtttMPXiwytco=;
        b=Xn55w1w1Vt4cEy6RQqB8r5nL7gwrzfoDjxDpTcEhFYIy7gQPG9orUZ+xZYMRVoYu4K
         hP3OWq1cxKULfbwPcigTTWs05abkn4pQ4f1kINqGZNmmtjsz64CBzW4jhbhyz3WWcqI0
         dOuQ0yX7craGmbv8XnMyCIn7lo5wjntckL+fZ2h7dASdA6OnRtcd6D8Td9VY5K7J45Xs
         m031kqSjPOT12kuASPDCGEaAgOxH2v/uPdDon8JbYcs9z3wCb3kLlTQAqB6V/moFkTdd
         itocfgeW+fhf+2zlMpXBcU0VtMpVJGohJeW2UgxxGEv9Cu4TfGPj9JVfWOn/cu3cKbne
         b2Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BuHh1iQw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aPw821r7B4WuupMm/4Ckfh0rOWE0HiEtttMPXiwytco=;
        b=QS725Rpx4H6XBS9XG8TCfC8nrGhKRIA8S60A54VV4GRLzKeP54cvkw7eScs+BiZ1pM
         w4GTex7stXLmIpSqH2+i2Pmb2Lc30pmOsHTPJzjkOyOKCVJWnxP1XmLCCOtWq121dFIY
         25eZlTBm1TBjlbJSWKwP47u2uCa3jP7FIdKL8XBnZKjzG9vcyrLG65PFgigsCxnFsp45
         alZkONhgshen8LK56BRzsOauaL5g6U5IG6WFbAMA800ueTBMeeK5jffewf7f1kep+eHx
         JBZbzexjgSmHu2u4taBQuf/5M7stViY5xWs+SVrkcyabC/wl7qAYliER1renZThwpD+L
         CFeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aPw821r7B4WuupMm/4Ckfh0rOWE0HiEtttMPXiwytco=;
        b=RtCc7w1QGLuj9It6Q19GuR3G44kClGDBnCWIUiLkwVFaWzWoyQ2SYhxpK2lp+TIvQA
         gdhitn8ConWJ9wQZfKgbNHSZc/grLcwMC1BZZIBrq8fU4ab6yuHMOKMp8UEJuv5bisih
         4tR4i3Vl0w8gEIr8ApJLV7+HcSEvfYW7UmjlogjehJqOV+iX4kTThic9/ODtF5XKnnxE
         7KTE1/eILFEooEHj7CVNKcOdqar1MskGyWcetX2s3Pas3VZTNN/n3UZFJI1yrzs9mtt4
         MKwRrcPufbx4xU4Ywfp+itNsz8Try3Z8s0hSsY0USkJhAQPh10L/dN0AgcVKbphth2ev
         aESw==
X-Gm-Message-State: ANhLgQ1UpHzyfsIzlwBvlrnoFQYsn54I3Xfx1S75X1S5uJszfdlWAoLX
	+fGvRmyLcbEc28I8kY0sDoI=
X-Google-Smtp-Source: ADFU+vvIkbEfuSeYeghmWv1xATZsm2SRBs8mEoF9oPX4+9GkhgkbFqbsCENzogpStPelpmCTQa5XBw==
X-Received: by 2002:a17:902:7581:: with SMTP id j1mr4707279pll.316.1584367010868;
        Mon, 16 Mar 2020 06:56:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:86c7:: with SMTP id x190ls8544553pfd.4.gmail; Mon, 16
 Mar 2020 06:56:50 -0700 (PDT)
X-Received: by 2002:a63:6c8a:: with SMTP id h132mr45346pgc.42.1584367010337;
        Mon, 16 Mar 2020 06:56:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584367010; cv=none;
        d=google.com; s=arc-20160816;
        b=FOEYPHyFUtBEbOGkORlTIfCqDl/YKpyO+zHrpEO+48q7obLAR63nJd4Zi+qoAHS6ft
         DXsRymOvolbIpu+H8QF6FMwidssxXfrsJJOkTwXoUOTD6kroNK1HHVliWqqMzqd4Ovxx
         /kOUGuGBbPLKo+68NJifpR8O0vFLihwD9o2MR5ed/cFdl/kkHMZo46izZ8omb9MrTq7P
         F5Yhay0lIVv3HGENU14zc1kwEAeV5/y8ovDBNZhVB/QF4l9C7Fr3WrcL8RtYyuJvXClv
         vUsr5AHDgA9NDP3cdVhZAMc7D/P6aaXHkIURBnp7nut4jioUvUs7Hkp/pQeEijLwqO6n
         LTwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SSNdADPq40Icef6Tc/mRDZ+zWsTXT5yssnz0a7eZlsw=;
        b=E1JhA9TK7/P6rlXJPBXRFvIY+Cbgh07nppWKlx6KXElB9iOTv+kiarwlB6vieU4I9C
         u4xNOgGdtrf2WajzA70/a+YmJDCxJ/cjWy/d4S49B8r2tBap3TTxOA4A+hlN1kryhvW8
         Dn61505POdTJvZyOw84Ahyd9mtI8Ph11tXHpFRhwdG7jYaQ3z0P6oBRMsehmw1afd3j+
         xHZrGhutFfaAovwWXp0ZAYQry19Z0w5aacdR9o49jC5rqg5RLJEGJGiyS6e8ohAJwJ1P
         UI4BSigqrRSQc932Y5YG9MgEv/YAgnWOJe2DgY4fQztEGUoUmfQBrYM4crhMIGmtzQTt
         0FWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BuHh1iQw;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id l6si744209pgb.3.2020.03.16.06.56.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Mar 2020 06:56:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id a49so15122365otc.11
        for <kasan-dev@googlegroups.com>; Mon, 16 Mar 2020 06:56:50 -0700 (PDT)
X-Received: by 2002:a9d:2c64:: with SMTP id f91mr2675599otb.17.1584367009313;
 Mon, 16 Mar 2020 06:56:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200309190359.GA5822@paulmck-ThinkPad-P72> <20200309190420.6100-27-paulmck@kernel.org>
 <20200312180328.GA4772@paulmck-ThinkPad-P72> <20200312180414.GA8024@paulmck-ThinkPad-P72>
 <CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw@mail.gmail.com>
In-Reply-To: <CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Mar 2020 14:56:38 +0100
Message-ID: <CANpmjNO=jGNNd4J0hBhz4ORLdw_+EHQDvyoQRikRCOsuMAcXYg@mail.gmail.com>
Subject: Re: [PATCH kcsan 27/32] kcsan: Add option to allow watcher interruptions
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel-team@fb.com, Ingo Molnar <mingo@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>, Boqun Feng <boqun.feng@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BuHh1iQw;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Fri, 13 Mar 2020 at 16:28, Marco Elver <elver@google.com> wrote:
>
> On Thu, 12 Mar 2020 at 19:04, Paul E. McKenney <paulmck@kernel.org> wrote=
:
> >
> > On Thu, Mar 12, 2020 at 11:03:28AM -0700, Paul E. McKenney wrote:
> > > On Mon, Mar 09, 2020 at 12:04:15PM -0700, paulmck@kernel.org wrote:
> > > > From: Marco Elver <elver@google.com>
> > > >
> > > > Add option to allow interrupts while a watchpoint is set up. This c=
an be
> > > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > > > parameter 'kcsan.interrupt_watcher=3D1'.
> > > >
> > > > Note that, currently not all safe per-CPU access primitives and pat=
terns
> > > > are accounted for, which could result in false positives. For examp=
le,
> > > > asm-generic/percpu.h uses plain operations, which by default are
> > > > instrumented. On interrupts and subsequent accesses to the same
> > > > variable, KCSAN would currently report a data race with this option=
.
> > > >
> > > > Therefore, this option should currently remain disabled by default,=
 but
> > > > may be enabled for specific test scenarios.
> > > >
> > > > To avoid new warnings, changes all uses of smp_processor_id() to us=
e the
> > > > raw version (as already done in kcsan_found_watchpoint()). The exac=
t SMP
> > > > processor id is for informational purposes in the report, and
> > > > correctness is not affected.
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > >
> > > And I get silent hangs that bisect to this patch when running the
> > > following rcutorture command, run in the kernel source tree on a
> > > 12-hardware-thread laptop:
> > >
> > > bash tools/testing/selftests/rcutorture/bin/kvm.sh --cpus 12 --durati=
on 10 --kconfig "CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONFIG_KCSAN_ASSUME=
_PLAIN_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn CONFIG_K=
CSAN_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VERBOSE=3Dy CONFIG_KCSAN_INTER=
RUPT_WATCHER=3Dy" --configs TREE03
> > >
> > > It works fine on some (but not all) of the other rcutorture test
> > > scenarios.  It fails on TREE01, TREE02, TREE03, TREE09.  The common t=
hread
> > > is that these are the TREE scenarios are all PREEMPT=3Dy.  So are RUD=
E01,
> > > SRCU-P, TASKS01, and TASKS03, but these scenarios are not hammering
> > > on Tree RCU, and thus have far less interrupt activity and the like.
> > > Given that it is an interrupt-related feature being added by this com=
mit,
> > > this seems like expected (mis)behavior.
> > >
> > > Can you reproduce this?  If not, are there any diagnostics I can add =
to
> > > my testing?  Or a diagnostic patch I could apply?
>
> I think I can reproduce it.  Let me debug some more, so far I haven't
> found anything yet.
>
> What I do know is that it's related to reporting. Turning kcsan_report
> into a noop makes the test run to completion.
>
> > I should hasten to add that this feature was quite helpful in recent wo=
rk!
>
> Good to know. :-)  We can probably keep this patch, since the default
> config doesn't turn this on. But I will try to see what's up with the
> hangs, and hopefully find a fix.

So this one turned out to be quite interesting. We can get deadlocks
if we can set up multiple watchpoints per task in case it's
interrupted and the interrupt sets up another watchpoint, and there
are many concurrent races happening; because the other_info struct in
report.c may never be released if an interrupt blocks the consumer due
to waiting for other_info to become released.
Give me another day or 2 to come up with a decent fix.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNO%3DjGNNd4J0hBhz4ORLdw_%2BEHQDvyoQRikRCOsuMAcXYg%40mail.gm=
ail.com.
