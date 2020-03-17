Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAUZYTZQKGQEVSE6H5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 13128188C63
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 18:44:36 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id t3sf9787083qvr.13
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Mar 2020 10:44:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584467075; cv=pass;
        d=google.com; s=arc-20160816;
        b=lBoHmLyTIKyyz32EW+EDv88A6ta7LmKUzkRqeHAyEelry1aARcyr3eIr+xF07GAHju
         2Zt6TQzMZbdO5fFeVMRJ9CCnW8tSIU++OBbgEuqwNlMYT0kpEFaQKGtJqM+49QRX6Ak+
         KenfR/oDTkjbd9GLJYvZnFQnGT6ndwRdHM591hWbPGjSpwPZMJQeKmI9Gdn9tAVy7OM8
         8WO1DdJAie57pP383hibGzm38iG+SK7fRo3zgnIjhOJS33n+bJ7C36/1zqimnLfWFV3z
         8z9rhEdpyNNtnhzY/6A23rYG0lClvSdToiaiz5hfm3d0ToXAf1M8yD6MmMqlCGI8B2lM
         H4Mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ovdpz/Ya8GjWVwN0M/gNYFt+soaUsBHpjQr+/fG39pE=;
        b=HVATobcZQ2doCdJo1zyBbXKj13AwYC4bAcc9oiGGhhp0lAnzbs7r5oG6jBCUUNX7XI
         tpa3miHNgeVNdD0SnQsDWR6c+e4LF6f1HguNFmjJnzJs0/b55QkDI17ayJQM2LQBJKMw
         NnkChkFQrIm/M336c7FOfp9QEfMU5z9dXVP1iLKE9HWRuJaJVIPwcv1Pujcsue315aUQ
         UZzYXZjYmTxkim0npxvjymtvVdKfjB62Q26WD+k1BawHLIZTcZpmXn1sAREf02DNQ2UE
         A6+WH8sWWrpTzRhdDby5CxK/Ll3FSMY7eHVaaxfiCaCXUopLVcVKST3NiLU1WuuqJiFV
         uawg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DThUjTgT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Ovdpz/Ya8GjWVwN0M/gNYFt+soaUsBHpjQr+/fG39pE=;
        b=Z/U3HqEqRx+wDbZt5elmtcZJxyNHJkyyM6+oWxiL8jxFWX/sTmaHJTdWod0hUlC1vF
         JqOacDd9B8v8nDXATr9H2cPBiNeYdJqql7QTB12ndmpHKlGYuag5zWip0lFxiHnPC2Yb
         g+gvoP6z4WRJJfHiTj4wq0Lk+P4/aAcMaPpn2m3/0vQ/nVDxNzy7O2ZjnNKpHIBeUDbA
         JUrkJC0pFaUFnjkp1pWlTVgaRkNKCCoudbXBYOnZnDvfPpfd6IYzI/OednG8GTfyd08z
         wzQ4iIVMQynYX5KaScZonc9dOqcb8gfbXdYXC6b+Eb1LFpr7KyTVYpvGXwgR68j62QPT
         YYZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ovdpz/Ya8GjWVwN0M/gNYFt+soaUsBHpjQr+/fG39pE=;
        b=kaPk5MSBOO1F19gXcqjSd3itdKSm/h/2yPqWkCa4ZyLWQALrpi2Jq8iDLzY1bBB0Jv
         3yvEVOX1Ww3ohrwihfc3SFcOb+/SDo8JoEiHmU6tuLkndeKNYDFPZ4OuNpQ+zL0RQk4V
         lXn3NrYaCMq966jc0Rlia9qPFd2T+pxOX6usMnU8ZQp92k0yXscsms372NWgjMZ1qhMH
         9E1+OVb/MxSPJxa9uaytBUZlHhdyc+JXHdPVwVRuiVkIjMbzODfDt8kBvvfDjf/T1yGc
         +GVPshmMJVNH5KBtniop/Ruaog1saX4dYWuXgOPICQlnE9yqfe6gaGsoDs65RVtUDOB7
         ey+Q==
X-Gm-Message-State: ANhLgQ0u2zQY+GYnZOueU7eEIsT5jXD8V/1J9u3CfCItXZs47MnGfQNt
	M4ucrdp4JU2sn6sb9Bxu+Lk=
X-Google-Smtp-Source: ADFU+vusQr25ikMs8D1WqU9NqfMtGoFrSUjwFH66Ks0G2+3vmOmVPZS4Z0iTuAq1lfXyB7mi2RIcFw==
X-Received: by 2002:a25:b16:: with SMTP id 22mr9837049ybl.380.1584467074794;
        Tue, 17 Mar 2020 10:44:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3454:: with SMTP id b81ls3289873yba.8.gmail; Tue, 17 Mar
 2020 10:44:34 -0700 (PDT)
X-Received: by 2002:a25:54d:: with SMTP id 74mr10086534ybf.490.1584467074407;
        Tue, 17 Mar 2020 10:44:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584467074; cv=none;
        d=google.com; s=arc-20160816;
        b=P7d8CxNZHCnTWi3d0mfERTSovpVYwevmvB0kikbwg9NHuvPxKsS14HBfh7YtFh+IfL
         tSf2J2QDLPKJNy43K5gwQpI6hAgOXn2rmcoPmXgfD9dvvqWfs+AvH/3xeu3B20U03ebK
         1OIHFxQ11M/DT2w5JC/Py8lV8ilOdKQQAMZsQ1jBwUh8xM4ElKQ5klwmZ3Rd6PA5Niul
         gxxOdczc46ixyEfPWip4yW2q1gzGgXFr4nIlSZoE9lAEUOOqEUFS5XanSLczpfeJmjNZ
         0rK/qzPNPkTF3+5YmR8+5P4ywfBvDedylKMCtS1xN5KuLtGmtNe88s5YuCWJ/5BtJ4/0
         Mf+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uny09Ikq2gRYtvFRYVAmcVvvtWssTyutAcTyjFY40Jo=;
        b=OUuSAZn1EhYjjoJtdzgFOyimX0DUKeHJGYb2HxV94MMwtSlJzeXDpal9GExPjoq2He
         OKFDUdHqouWEaDQMeUzhDIjXuOa3ZEPOdPQHqclF6HsocGa54jYKYUPBMAFEOeh+S/mf
         YZ1wl3UweVPboCa8h58v57N7Pk1ohhuMC7FqvBVmCP7Z0BWs6Jf+8rO9bwm3fs6mgmUJ
         1AAlr/odNIMg6hLiKOr/cgNVMVxTOjb26BW0hl9EXK/EHdT0tavOqiLAwS+VMwtrkyn4
         pec+nfqoFoWMx02dPPaGuVYA/gKtRvNwVYJbo2wfQvtSQ3MUzlezU754NDhx8kBQjxqO
         bWNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DThUjTgT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id e14si392969ybp.0.2020.03.17.10.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Mar 2020 10:44:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id d63so22700800oig.6
        for <kasan-dev@googlegroups.com>; Tue, 17 Mar 2020 10:44:34 -0700 (PDT)
X-Received: by 2002:aca:f541:: with SMTP id t62mr14021oih.172.1584467073577;
 Tue, 17 Mar 2020 10:44:33 -0700 (PDT)
MIME-Version: 1.0
References: <20200309190359.GA5822@paulmck-ThinkPad-P72> <20200309190420.6100-27-paulmck@kernel.org>
 <20200312180328.GA4772@paulmck-ThinkPad-P72> <20200312180414.GA8024@paulmck-ThinkPad-P72>
 <CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw@mail.gmail.com>
 <CANpmjNO=jGNNd4J0hBhz4ORLdw_+EHQDvyoQRikRCOsuMAcXYg@mail.gmail.com>
 <20200316154535.GX3199@paulmck-ThinkPad-P72> <CANpmjNOsLeiD6hYXeD4g8fA=Ti6EiUsbtiv4VshRGg+oG1ct-g@mail.gmail.com>
 <20200317171320.GI3199@paulmck-ThinkPad-P72>
In-Reply-To: <20200317171320.GI3199@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Mar 2020 18:44:21 +0100
Message-ID: <CANpmjNMN0DTxCXVL+OOPRaDiZUMGn5EsdyEQ==w_=5MOXc8J4Q@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=DThUjTgT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Tue, 17 Mar 2020 at 18:13, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, Mar 16, 2020 at 05:22:34PM +0100, Marco Elver wrote:
> > On Mon, 16 Mar 2020 at 16:45, Paul E. McKenney <paulmck@kernel.org> wro=
te:
> > >
> > > On Mon, Mar 16, 2020 at 02:56:38PM +0100, Marco Elver wrote:
> > > > On Fri, 13 Mar 2020 at 16:28, Marco Elver <elver@google.com> wrote:
> > > > >
> > > > > On Thu, 12 Mar 2020 at 19:04, Paul E. McKenney <paulmck@kernel.or=
g> wrote:
> > > > > >
> > > > > > On Thu, Mar 12, 2020 at 11:03:28AM -0700, Paul E. McKenney wrot=
e:
> > > > > > > On Mon, Mar 09, 2020 at 12:04:15PM -0700, paulmck@kernel.org =
wrote:
> > > > > > > > From: Marco Elver <elver@google.com>
> > > > > > > >
> > > > > > > > Add option to allow interrupts while a watchpoint is set up=
. This can be
> > > > > > > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via th=
e boot
> > > > > > > > parameter 'kcsan.interrupt_watcher=3D1'.
> > > > > > > >
> > > > > > > > Note that, currently not all safe per-CPU access primitives=
 and patterns
> > > > > > > > are accounted for, which could result in false positives. F=
or example,
> > > > > > > > asm-generic/percpu.h uses plain operations, which by defaul=
t are
> > > > > > > > instrumented. On interrupts and subsequent accesses to the =
same
> > > > > > > > variable, KCSAN would currently report a data race with thi=
s option.
> > > > > > > >
> > > > > > > > Therefore, this option should currently remain disabled by =
default, but
> > > > > > > > may be enabled for specific test scenarios.
> > > > > > > >
> > > > > > > > To avoid new warnings, changes all uses of smp_processor_id=
() to use the
> > > > > > > > raw version (as already done in kcsan_found_watchpoint()). =
The exact SMP
> > > > > > > > processor id is for informational purposes in the report, a=
nd
> > > > > > > > correctness is not affected.
> > > > > > > >
> > > > > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > > > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > > > > >
> > > > > > > And I get silent hangs that bisect to this patch when running=
 the
> > > > > > > following rcutorture command, run in the kernel source tree o=
n a
> > > > > > > 12-hardware-thread laptop:
> > > > > > >
> > > > > > > bash tools/testing/selftests/rcutorture/bin/kvm.sh --cpus 12 =
--duration 10 --kconfig "CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONFIG_KCSA=
N_ASSUME_PLAIN_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn =
CONFIG_KCSAN_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VERBOSE=3Dy CONFIG_KCS=
AN_INTERRUPT_WATCHER=3Dy" --configs TREE03
> > > > > > >
> > > > > > > It works fine on some (but not all) of the other rcutorture t=
est
> > > > > > > scenarios.  It fails on TREE01, TREE02, TREE03, TREE09.  The =
common thread
> > > > > > > is that these are the TREE scenarios are all PREEMPT=3Dy.  So=
 are RUDE01,
> > > > > > > SRCU-P, TASKS01, and TASKS03, but these scenarios are not ham=
mering
> > > > > > > on Tree RCU, and thus have far less interrupt activity and th=
e like.
> > > > > > > Given that it is an interrupt-related feature being added by =
this commit,
> > > > > > > this seems like expected (mis)behavior.
> > > > > > >
> > > > > > > Can you reproduce this?  If not, are there any diagnostics I =
can add to
> > > > > > > my testing?  Or a diagnostic patch I could apply?
> > > > >
> > > > > I think I can reproduce it.  Let me debug some more, so far I hav=
en't
> > > > > found anything yet.
> > > > >
> > > > > What I do know is that it's related to reporting. Turning kcsan_r=
eport
> > > > > into a noop makes the test run to completion.
> > > > >
> > > > > > I should hasten to add that this feature was quite helpful in r=
ecent work!
> > > > >
> > > > > Good to know. :-)  We can probably keep this patch, since the def=
ault
> > > > > config doesn't turn this on. But I will try to see what's up with=
 the
> > > > > hangs, and hopefully find a fix.
> > > >
> > > > So this one turned out to be quite interesting. We can get deadlock=
s
> > > > if we can set up multiple watchpoints per task in case it's
> > > > interrupted and the interrupt sets up another watchpoint, and there
> > > > are many concurrent races happening; because the other_info struct =
in
> > > > report.c may never be released if an interrupt blocks the consumer =
due
> > > > to waiting for other_info to become released.
> > >
> > > Been there, done that!  ;-)
> > >
> > > > Give me another day or 2 to come up with a decent fix.
> > >
> > > My thought is to send a pull request for the commits up to but not
> > > including this patch, allowing ample development and testing time for
> > > the fix.  My concern with sending this, even with a fix, is that any
> > > further bugs might cast a shadow on the whole series, further slowing
> > > acceptance into mainline.
> > >
> > > Fair enough?
> >
> > That's fine. I think the features changes can stay on -rcu/kcsan-dev
> > for now, but the documentation updates don't depend on them.
> > If it'd be useful, the updated documentation could be moved before
> > this patch to -rcu/kcsan, so we'd have
> >
> >  kcsan: Add current->state to implicitly atomic accesses
> >  kcsan: Add option for verbose reporting
> >  kcsan: Add option to allow watcher interruptions
> > -- cut --
> >  kcsan: Update API documentation in kcsan-checks.h
> >  kcsan: Update Documentation/dev-tools/kcsan.rst
> >  kcsan: Fix a typo in a comment
> > .. rest of series ..
> >
> > Although I'm fine with either.
>
> Given my churn with a recent merge window, I am more reluctant than
> I might otherwise be to do that sort of rearrangement.  Sorry to be
> so cowardly!

No problem. This should be fine either way.

Thank you!
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMN0DTxCXVL%2BOOPRaDiZUMGn5EsdyEQ%3D%3Dw_%3D5MOXc8J4Q%40mai=
l.gmail.com.
