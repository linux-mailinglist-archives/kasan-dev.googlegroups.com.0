Return-Path: <kasan-dev+bncBC7OBJGL2MHBB752ZHZQKGQEKXGLLCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A94218A1BD
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Mar 2020 18:42:25 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id l5sf2597786pjr.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Mar 2020 10:42:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584553343; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ev6dR1rVu9sRJp/PjOV1DSfxDCGbjRVOvL/IUDZ5sgxoWtIsSbrtB2hvk7CBpAugpn
         nFUnQ5BohWCEC5xIjmDrjLtxT/ehmQoSadhMeeMuv2X7y7Z6AFLiaPtfyQVgeBgXZ3yZ
         XGWw6yY6RsrZlR+X+Iz69adRXMgeAF8ydEb/S7ZSxXO6DNTTvUcdndClNYRzzryf7SfY
         hKCWH77i1x4XU7NM5KTemyeKZd+z/j+qkgcLpQzK76yjY6aRaSb+M5zDH8Enu51TQSIr
         z9bxAO6dFVqrapHmyGhG+hQ/v9thcNvKFFkzSGaATyq+O1IrxZub4BygRJipHDKveDk2
         Gjzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EYU6ECSUKFnZmNFI46O/hMefO1f7E3pMCMy6ZVRdsAY=;
        b=C8DkNv3E0JJZ8duLkhWGT73WA/Uz44UKo8neGRFZAQ3sVCa8SiI0JM/PtDqxmePtvD
         wa1YugbwV8dvCjZLYT3arHDpTfWReyhgasTL3LasTGHjs0u2/0nptAoOJ0prPDogn3B+
         Cl8AU5HIZnLz/EjRZvEGBGqXQLspSxZtQEs2kCMVU9emZt+SgfPksMMSXZrDQ+4aJ9kf
         YBndKcv1AK0ErmL2jmV5YReUXp9/OM9EhNcAqAHz7d2xmOkSBWQCefh2waKSNK+0hrN9
         qxFMI36Cw98gXgKaclODji13UgGBESTjGzrfaoFrhxuk4VTfAScCOXwNmmOzzy1dco/D
         nefg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eq8b+myj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=EYU6ECSUKFnZmNFI46O/hMefO1f7E3pMCMy6ZVRdsAY=;
        b=ZI+oosISmH5IUbqsx2gZ5i8yop54FwdGNgmPXmqsHSPp7qqg6vGwBZjZKfkK8k76oW
         sTeRMgjXBgj+NAHRDGdIOvck9ykxzyCFHjqB/leiWWF/WnuJAFSiCOfI+VjmzbGP1qfk
         Nk0Mj+PqnM0V7xr/R7OWbkOmE+nXLjChPNdijD++HUEMlvU3GB4J81LeNkvNqUy8EzPe
         wY3OBqo84WV6LCM9g+I92jrBh1TKdFmTHFvuHnYucTWIgHr0tu+wLISj7Sv732g6RaZ/
         ZU4JFR6TXR8JQg7/t7v2racOJGnztoGTgg5N3ZaxafmdfgQt7DzMC9GJtVtHdI9jHzwX
         e6zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EYU6ECSUKFnZmNFI46O/hMefO1f7E3pMCMy6ZVRdsAY=;
        b=QQLSuF8wYAsjIEYwizZLY3pa4C3ABkGWOVQOAQV/0g/egeB08Jh5e6x4Zq1PDWP0I8
         eEizkRqBww6MdErB6XT7+fL+Prm/ut8reDICyYZ6yrp7my4phD9vz4HWB0gUj1SCCEaZ
         R94++huEfOubxKEjEVWHacQCOgN37NxMPJTHnWiKbt4EqxO0Y7nh7w2w+8a/iutMZgXs
         P16Vh1glDWHgHaNpRZ5XbyQSDEFbtSFRLAg9bAz1zE9UtQe6NezIXsBH/VKR12hvJIqH
         drwQlLEH2fUbRzLWZKWllfCSiR9Y5EwCS601DBCgzoMj3uZvP0y9IbcEQcdoA6bDvmAW
         iMzw==
X-Gm-Message-State: ANhLgQ3eVok6R5/uTFeocNkDFZu40ruAZrvIjK+VU17luz8aWZGQ5L3b
	FXk3hcWKI6VOa1+rqFZAVdw=
X-Google-Smtp-Source: ADFU+vvCVN+nqJjcW6OlGwW8nDLHi9G7WpAEm7KYRqFdXsbOL/l9MqCdgtf93L/PK3stMa80yMrdsQ==
X-Received: by 2002:aa7:8711:: with SMTP id b17mr5099190pfo.315.1584553343555;
        Wed, 18 Mar 2020 10:42:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9708:: with SMTP id a8ls12677519pfg.9.gmail; Wed, 18 Mar
 2020 10:42:23 -0700 (PDT)
X-Received: by 2002:a62:1a50:: with SMTP id a77mr5563536pfa.289.1584553342907;
        Wed, 18 Mar 2020 10:42:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584553342; cv=none;
        d=google.com; s=arc-20160816;
        b=BL2xuta/YM9d00suMuR5KqKd4or/hPe5C3PAguiBTyW6a9VPk8a44XDJ8OIJVOwlIh
         1cAfg38AG9jgK8FvAM56R3jIXvwtraO8SaqT+xi5tz99jwPSAYHfAcWnGwXGlB2Aomi0
         hpluVamBppK7vPWwAmFYqQT3RUcDuTu4ch3oD3cmAICpuMSeTnWt6ZaC6dSXc15hCHDc
         TFrPJDji5d/8kAcSlQpg6DTOs6v5o8N+goGJy+Lb+BxOxMAElSTzur0O3MygWD+dqliO
         QYI03ToXxVCW02bKtPM25C4I/upuSUBdc7iiOD4mWWGLfbbLQ/DegNkPiLXL4yu7gW0Q
         IexQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fukrr76bOiZh5lh10kgVm2Vkii/yxFVJxA3G3n1k3QE=;
        b=SB16/X9tzZMP59rth+eTyV4GqQ5cIiW/r2sepQiY/5run5DMDykhU/ezKsUzv0KEi7
         Au4Zhh7E/xMN3Gno5Bm5wZu4hKbKeowyxRjqa1gNm5BqQRxoi51wyasoJE7ftwoG7OaX
         9txedL+0ctUU2+WGWiZesSdUsIdlyCTchLGuuVMjcb/paKS1b8S0UiH8LUiagYJyc23t
         GGlIGqIQuB/78DutedLO81X/G6Myq3OhG953zWlp3DUAqcs3IejLH9HgKBhnKDHg6yYM
         YxlTZpKWnaqQ2yvs5Fc87DuyD/HFWlgoa6XwSgwSt/qaYIvSySAwL1v9f3qm7Zy5QgdE
         SLmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eq8b+myj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id f29si424118pga.0.2020.03.18.10.42.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Mar 2020 10:42:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id t28so23775453ott.5
        for <kasan-dev@googlegroups.com>; Wed, 18 Mar 2020 10:42:22 -0700 (PDT)
X-Received: by 2002:a9d:6d87:: with SMTP id x7mr5110501otp.233.1584553342180;
 Wed, 18 Mar 2020 10:42:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200309190359.GA5822@paulmck-ThinkPad-P72> <20200309190420.6100-27-paulmck@kernel.org>
 <20200312180328.GA4772@paulmck-ThinkPad-P72> <20200312180414.GA8024@paulmck-ThinkPad-P72>
 <CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw@mail.gmail.com> <CANpmjNO=jGNNd4J0hBhz4ORLdw_+EHQDvyoQRikRCOsuMAcXYg@mail.gmail.com>
In-Reply-To: <CANpmjNO=jGNNd4J0hBhz4ORLdw_+EHQDvyoQRikRCOsuMAcXYg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Mar 2020 18:42:10 +0100
Message-ID: <CANpmjNOyaEMPpKrfLYCCz722toZFH7YJx2Tj8wjyBxHSEMHWzQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Eq8b+myj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Mon, 16 Mar 2020 at 14:56, Marco Elver <elver@google.com> wrote:
>
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
>
> So this one turned out to be quite interesting. We can get deadlocks
> if we can set up multiple watchpoints per task in case it's
> interrupted and the interrupt sets up another watchpoint, and there
> are many concurrent races happening; because the other_info struct in
> report.c may never be released if an interrupt blocks the consumer due
> to waiting for other_info to become released.
> Give me another day or 2 to come up with a decent fix.

The patch-series fixing this:
http://lkml.kernel.org/r/20200318173845.220793-1-elver@google.com

Please do confirm it resolves the problems in your test scenarios.

Many thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOyaEMPpKrfLYCCz722toZFH7YJx2Tj8wjyBxHSEMHWzQ%40mail.gmail.=
com.
