Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJGNV3ZQKGQEJT7AKAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 01B5E184AB1
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Mar 2020 16:28:38 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id e2sf6080335pgb.17
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Mar 2020 08:28:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584113316; cv=pass;
        d=google.com; s=arc-20160816;
        b=j8AHG1Ka7XpQrhCg2QiufhBsX23y49GPtfkYJkZkwRW3uB+UW4Jr5P05MdWhqas0lZ
         qCXA2jS9YEh7/jnrcyOsQJ1ifyTMvlvAV74vCPNtUTKvmPeLveDQwM+iVbH8/ZUY0iU+
         Na4NUh6rhQSFCblOPxxGuYka4Yd80EiN2zPmr0Dms4FJTnDb+MlHhZBNimy0nfEbs4Xn
         MrbJ+IBH+rbt8tVyeSgmCiRdRDxC8g9lDHaWqxg2G1yZnotoy7u5XhUQ52VRrEavt0dz
         xEH/Szb/WccIXqeeXp/n1Mc8GMj+xnjamAnIYJ2eJ4Ifg0xbNAKes1gnpZGzHskNmWrd
         utyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ddy7gYqEzmFcyH04MW97fVTETelC4N+ojVZuo7ppoPA=;
        b=BCHPnsJB4n+spFhb8DlnVvpHaMCmkCDP2YqwTOpLL/lYLSl+KGxaCXyumMY80H/pfb
         G3Vqa9wuidugpiAC2V72YJNSa8d8FIObGFbFzq9rmihcFjcF5oudMjd99e6EIOKnFzf3
         gZ5Rha/SUkWtHshlj4fp42PIUyUZfc748dZG5CKMKq+BwP2QIxHbI25jfR0mOCCKRcyy
         vawxWd00860wJ1Le/hDeegOCvsAu7yqYEs6PIiTo3518UC++H5a728LAVBBCbjofjXcB
         GK6JqOVMZ02LYIq9LITd/DrhwXtilMCMnlDNQ7PHwZ+9LnCyMUn9z/NCuiWZBMCSlFfx
         nohQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t+u32kyh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ddy7gYqEzmFcyH04MW97fVTETelC4N+ojVZuo7ppoPA=;
        b=oM8aK9Hs0viFNsqA1te6Vm/rE7ITN15S2bEWF8SSoKFrVZkZLz7erRF3Q3D5zkvMuo
         p0vphj0Lr4cP7SHfgQMNfaNo9Z16QWA2GyFnMj7dSTTRKfG30qT3P7hSsS77yvoQB1Un
         hFxAIKdR9V+t2046FwS+80GKInYCaMwXmF+85cHbVckXxMDN292uVGBlbtDKBK67hrmb
         xJto/Vqu+oKL6ItWFSENskyhJILyir6JW0unIBCNH1d1WrQoYAFxP5ay/PQKobPBRIUg
         ONmcwGyJe+xxfatMMUemb1ANpgRnRvg/WhsV69bOSQgBjTYxF7wQNoDApQxEjLS+HVho
         6NzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ddy7gYqEzmFcyH04MW97fVTETelC4N+ojVZuo7ppoPA=;
        b=Uz+rhUJ9ZVeHq4mMUUfjhLJzmuzFxkg3FVK+cClxLit5nYdsFM6pCzwj2nnz02zYnd
         KHQ9YirKNF5KjSgWSOO4daapkzrs5/bz+Fve4mbFd/W36Zo8jTjM3tcuQLJ3wH2MGRbj
         pTKCjTs78j/4XsMwUf9bQX6Oot2T5LrPXlmTaQGEn0tdRVVhPDcvP55k+qWxZ9N/DOsE
         xl28LSHjrQW8gSJKapZQUvOOpflUaqEwU+QqycvmdpLkQLGmkLPi2OvoVfI5y+0UGbTt
         Y1bHpw2nH+3l7T4vmjPLx1gKNf2T2nWUvGk2uxlvtq0zVSno10mroY0y44a7+fcVnZ6s
         syPQ==
X-Gm-Message-State: ANhLgQ3k5H+oOw23UTj/b3S7WyaigTZjbd56xVgqb6TieIIC9jTxDoA2
	+rReRfWLg3USYdHdJf5n4CQ=
X-Google-Smtp-Source: ADFU+vu/RCe/OGjFvRR1bt5LTwJoHKDrxBiKzVQ24VqT4ui/0JeMEgXwAeTDgypuDaNT4UqNZ8T47Q==
X-Received: by 2002:a63:330f:: with SMTP id z15mr13863821pgz.104.1584113316381;
        Fri, 13 Mar 2020 08:28:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb93:: with SMTP id m19ls4511918pls.6.gmail; Fri, 13
 Mar 2020 08:28:35 -0700 (PDT)
X-Received: by 2002:a17:902:b591:: with SMTP id a17mr2239905pls.333.1584113315852;
        Fri, 13 Mar 2020 08:28:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584113315; cv=none;
        d=google.com; s=arc-20160816;
        b=KU4ONx6atwjgp92lNfnbNlrVzfnOdCpBXJ6aQUeRhLLwDpEMccquOZniU1CP5bsKv0
         ob+QDWupxY1/DIg248J1SqDvq3WjG1KdjMZVqeNmpHvm8Lny6+kgPPpKFdw4ZWXQtPcH
         GI7O0CVAeZKhNDpUHXUgCDZAPAqc3WuN+yno90CvRrqWa60JdwbUVwZ+rF04O4svU/Hx
         +BmfRqUsQK9GlzETmBjaGxxO5b48ShTdRXk7QXDOAJP+QiPlZmZPlJCnfeL5dZ3MEG7h
         2CMdJUZEcXZiy5zKx6S202AISE6vCSXjh4eqB50r1HOdHN8Ye5MNZrZwklVJjxgm7FJK
         FTAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JhUIJfLxmDw2Pu91CEiBsHmiHtKiQT2VqIQ9110wd4A=;
        b=L9CCM6S5wNk7lNnTSmnnR9gswVStabMpRcWEAwzu2M3hDfl2olV7xbUIC8Cdw2v+x1
         FkYY5hpy/ZEobEu0D32ztEqpFgPONNtbpH0YFcVbIOxV5cnwj5ud/jRVKPCZQ3KiIaB1
         fkxxFv9XGeVBbte6mMLXbxiVrjpEMjy9976wJpcetcieGDMCeqAVIBR+KI6Gpu1tQu0+
         /pmHxFFSJHoQ+L35bHHwXu8ip3BUMQgZXuIY6M6Y/e2lN6384+uVqSZuuy8LpWlvtYyd
         CFF5gCnS3A2DY/+dBDXRR+2FdQGtAwIVGtN5C9C24wKD8Zu52fu+H62p/hSVQIqsMcC/
         +lTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t+u32kyh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id x128si495909pgx.2.2020.03.13.08.28.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Mar 2020 08:28:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id a22so9739469oid.13
        for <kasan-dev@googlegroups.com>; Fri, 13 Mar 2020 08:28:35 -0700 (PDT)
X-Received: by 2002:aca:4cd8:: with SMTP id z207mr7211572oia.155.1584113314909;
 Fri, 13 Mar 2020 08:28:34 -0700 (PDT)
MIME-Version: 1.0
References: <20200309190359.GA5822@paulmck-ThinkPad-P72> <20200309190420.6100-27-paulmck@kernel.org>
 <20200312180328.GA4772@paulmck-ThinkPad-P72> <20200312180414.GA8024@paulmck-ThinkPad-P72>
In-Reply-To: <20200312180414.GA8024@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 13 Mar 2020 16:28:23 +0100
Message-ID: <CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=t+u32kyh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Thu, 12 Mar 2020 at 19:04, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Mar 12, 2020 at 11:03:28AM -0700, Paul E. McKenney wrote:
> > On Mon, Mar 09, 2020 at 12:04:15PM -0700, paulmck@kernel.org wrote:
> > > From: Marco Elver <elver@google.com>
> > >
> > > Add option to allow interrupts while a watchpoint is set up. This can=
 be
> > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > > parameter 'kcsan.interrupt_watcher=3D1'.
> > >
> > > Note that, currently not all safe per-CPU access primitives and patte=
rns
> > > are accounted for, which could result in false positives. For example=
,
> > > asm-generic/percpu.h uses plain operations, which by default are
> > > instrumented. On interrupts and subsequent accesses to the same
> > > variable, KCSAN would currently report a data race with this option.
> > >
> > > Therefore, this option should currently remain disabled by default, b=
ut
> > > may be enabled for specific test scenarios.
> > >
> > > To avoid new warnings, changes all uses of smp_processor_id() to use =
the
> > > raw version (as already done in kcsan_found_watchpoint()). The exact =
SMP
> > > processor id is for informational purposes in the report, and
> > > correctness is not affected.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> >
> > And I get silent hangs that bisect to this patch when running the
> > following rcutorture command, run in the kernel source tree on a
> > 12-hardware-thread laptop:
> >
> > bash tools/testing/selftests/rcutorture/bin/kvm.sh --cpus 12 --duration=
 10 --kconfig "CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONFIG_KCSAN_ASSUME_P=
LAIN_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn CONFIG_KCS=
AN_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VERBOSE=3Dy CONFIG_KCSAN_INTERRU=
PT_WATCHER=3Dy" --configs TREE03
> >
> > It works fine on some (but not all) of the other rcutorture test
> > scenarios.  It fails on TREE01, TREE02, TREE03, TREE09.  The common thr=
ead
> > is that these are the TREE scenarios are all PREEMPT=3Dy.  So are RUDE0=
1,
> > SRCU-P, TASKS01, and TASKS03, but these scenarios are not hammering
> > on Tree RCU, and thus have far less interrupt activity and the like.
> > Given that it is an interrupt-related feature being added by this commi=
t,
> > this seems like expected (mis)behavior.
> >
> > Can you reproduce this?  If not, are there any diagnostics I can add to
> > my testing?  Or a diagnostic patch I could apply?

I think I can reproduce it.  Let me debug some more, so far I haven't
found anything yet.

What I do know is that it's related to reporting. Turning kcsan_report
into a noop makes the test run to completion.

> I should hasten to add that this feature was quite helpful in recent work=
!

Good to know. :-)  We can probably keep this patch, since the default
config doesn't turn this on. But I will try to see what's up with the
hangs, and hopefully find a fix.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw%40mail.gmail.=
com.
