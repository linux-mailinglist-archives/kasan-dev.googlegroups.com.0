Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVWPX3ZQKGQEYDLBIPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id E4F75186FE7
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Mar 2020 17:22:47 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id z18sf1604342uap.23
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Mar 2020 09:22:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584375767; cv=pass;
        d=google.com; s=arc-20160816;
        b=EfVxpY1zoMKmIgp3r9jb8/2fwcfsZGVVo8UaWdkBx8nxRAKro/33Z6civ0P/siVh/4
         0Nnqq0jKjhDhpkN0254Gcz1CnTgBD/tYl+Y3kb/6pck95lrT2xX8Fc2OnBQomxXxY5hr
         HjW51upe6HMufewYrsTPBQWrNJO0WHEWtyUBw6CVXfZmfmXBRifo1TJ0pcJI1herTT/0
         q2HzhNMA4+TK92eYopydo0YH9mN1mR3UhnUPkWV7DmjHe+Mq6QoWnaWeX7qg+Xet3jJ3
         y5LR1FGu87kXZ2ZBx1tJnL3IjDrrtXTOUwPmx5RO7oq1OdoaUsbzJ+Oy7jQNYhqGA3Jr
         +iZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HOdVJIH7HDfztgLf7TZYOCXHQV5Hp6Gj8bUpNzuiXls=;
        b=R4zcpFoEuBzWc6zKv7J3CDFeuzIIElANkC3waxzkVKuiACkdfXr1R75WXJqzXZCgTc
         /UcUpXzv8XpF3bl8oLU0i1RDluHZdKetVUq/fRE4GXj6F03+KcUqT1eTZMAxg5Erit7l
         a1YV3Q6kJxf4Ube9SVeD7MYcGMPTFTYMs9CwXeeccRmrYb7+KzfNVtmgqHoBaLG/4fq+
         gWV4vg3vyDNY5LB4iqDp2/jCk2pePnuYkEkZE2ivo6U/0WkUMB3769ANtF0TT9Q0bntU
         aZgQyYEqAwK8gbsX/57UJABQDm6/fOoVUyd1oPKoVE8VaXtRUhRXcjvDA66bpl5oGiVn
         rocw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GfO5cCJa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=HOdVJIH7HDfztgLf7TZYOCXHQV5Hp6Gj8bUpNzuiXls=;
        b=PU4XCFf2xMPxFTUQUIjFAHvXGa0deVntKiBOiJnsrQsBhMjfWFcrVyKEKSpKIx2De2
         YL/zAq44zXenAXBLvIegL3OIrAm442KdnwqD1hBlkoc4quNoonMFdJ+gYW+sZTZdQ8k9
         eDQN491FjyRTE0R5fXkx2xNbCUWRaER9HY00pqn0JEksHzrj2MeJCmMNqZK0ZSqQiQGp
         2W/uoiANLPsckVlPmSkuHJJEoPBQdueCv9VZgpMHtZTZ8i4EodIDu4wIGAITLpPqFcfA
         Nof8w1yrmCC0W1kY0tcIdzy0GNLOHuutelvljfNvkAj56PAelIFkP02kqNqiaLPJ83w9
         0OoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HOdVJIH7HDfztgLf7TZYOCXHQV5Hp6Gj8bUpNzuiXls=;
        b=UWlfEDOPKUtrjGn+gXRh7iqPr1f+CJSUXbYOjeARIYiPzckfUX4MgR3w3my5tkVtZc
         l90gl1LlcTLOKE5u8aVFo76senNPWLWqUXbjbhAC1HN7u6cdhaG8fU4Qcjnfw53fmkD0
         4TDeWSP5gIJ74nkE0xSlmbjHTZfNeaIJ8DlorBMf7YR4fljMY+09QCBQSsXSvjagcS4H
         ZtVBUZOqkUBeWK3i1qQ9VLGlYRNaUQHkwSq6eUj+I/W+oM99Z4NpUM47IWXjmjROU4xz
         z9mjc4dxoLxZUT6ith2noWKq+xtMD0A+nkPZ+22th6gtodLIyFZU9j/OYCfes7UPyWpb
         Z0kw==
X-Gm-Message-State: ANhLgQ1HByBimivg9gMhFOkt3f2K8ddndx2Q9uEUYTn0YEtMzbJVXd/b
	Ki6gqisxX3wvL28nK6glYTs=
X-Google-Smtp-Source: ADFU+vsN27/AdD5vKXEiZZGsugpwC1cdIk1vRkEAsjvjt6qiyex242YsM7zFWzNdklvfdN6TFcIzAA==
X-Received: by 2002:a67:b85:: with SMTP id 127mr414257vsl.62.1584375766802;
        Mon, 16 Mar 2020 09:22:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:93c6:: with SMTP id v189ls993060vkd.2.gmail; Mon, 16 Mar
 2020 09:22:46 -0700 (PDT)
X-Received: by 2002:a1f:310d:: with SMTP id x13mr688510vkx.38.1584375766373;
        Mon, 16 Mar 2020 09:22:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584375766; cv=none;
        d=google.com; s=arc-20160816;
        b=CPDTS6ixUYatebghMFB+uyPpBNrIRSzlCdUlSrC5RgBNPV5JG5nm7eZYmPkHyMUes2
         utPb0xlLarJb4lnZykbME4pJLJWGPydg46IPpgY6TRyD+bcaOmQlcmaC3JpswADJs86J
         HcNh7fKwm+6d441ccGfB+z8lWkU63nsmJJTkUqGDS0wwIw4fuJIQH9CklzwZwyhJhzbU
         tKBhvSfNv44mBusLVTG1nvL+Pl5EW8SSZWeVGlCMiIOXU3gfuxPNT6GFrV+OQNqFLIKW
         /Xfo9Kunk+e7Yj1YrRbfnkwQsep5sAT5JGThOfFxI4NDIlEb1B7IRRE66UHlZNMwR96p
         hivQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0YSwpvB1oyD4y2ce8RBaDN9TnhxehmimDnF/JqC+Zgs=;
        b=a8MRDz7RsA6YTupnd5imS7kLk5+c3F6YlRxTKpWDeVXPr4w0IwwmUM6mAgVeNXTkd6
         EmE/ZFFVXDZgJNDD8Ei9G8HeS1G74+TLxrHDFOALrLWg7kpQfKf8j0uTWgaUBqO+tu/t
         s2sZOy+BDjwR2JT4aRrGvKLtKx67SLQr+bdekaDGY/wdum3OMAToTIe0c1yr7GwhOAT0
         Efawr8fKP1I05RMuOIM9vd2UK2lVVKNBNSnA8L4n0NX5BtvqWgMrSgPq+GR1clgRRZQf
         I1MuTWLXdTh4WMDgbKB+SBER8EVZCJR4Tdzrs88GLWQQq/rFAHcnmkM9f04JXvy79m7E
         2AVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GfO5cCJa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id w12si11439uaq.0.2020.03.16.09.22.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Mar 2020 09:22:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id r7so18446765oij.0
        for <kasan-dev@googlegroups.com>; Mon, 16 Mar 2020 09:22:46 -0700 (PDT)
X-Received: by 2002:a05:6808:4e:: with SMTP id v14mr283233oic.70.1584375765709;
 Mon, 16 Mar 2020 09:22:45 -0700 (PDT)
MIME-Version: 1.0
References: <20200309190359.GA5822@paulmck-ThinkPad-P72> <20200309190420.6100-27-paulmck@kernel.org>
 <20200312180328.GA4772@paulmck-ThinkPad-P72> <20200312180414.GA8024@paulmck-ThinkPad-P72>
 <CANpmjNOqmsm69vfdCAVGhLzTV-oB3E5saRbjzwrkbO-6nGgTYw@mail.gmail.com>
 <CANpmjNO=jGNNd4J0hBhz4ORLdw_+EHQDvyoQRikRCOsuMAcXYg@mail.gmail.com> <20200316154535.GX3199@paulmck-ThinkPad-P72>
In-Reply-To: <20200316154535.GX3199@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Mar 2020 17:22:34 +0100
Message-ID: <CANpmjNOsLeiD6hYXeD4g8fA=Ti6EiUsbtiv4VshRGg+oG1ct-g@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=GfO5cCJa;       spf=pass
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

On Mon, 16 Mar 2020 at 16:45, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, Mar 16, 2020 at 02:56:38PM +0100, Marco Elver wrote:
> > On Fri, 13 Mar 2020 at 16:28, Marco Elver <elver@google.com> wrote:
> > >
> > > On Thu, 12 Mar 2020 at 19:04, Paul E. McKenney <paulmck@kernel.org> w=
rote:
> > > >
> > > > On Thu, Mar 12, 2020 at 11:03:28AM -0700, Paul E. McKenney wrote:
> > > > > On Mon, Mar 09, 2020 at 12:04:15PM -0700, paulmck@kernel.org wrot=
e:
> > > > > > From: Marco Elver <elver@google.com>
> > > > > >
> > > > > > Add option to allow interrupts while a watchpoint is set up. Th=
is can be
> > > > > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the bo=
ot
> > > > > > parameter 'kcsan.interrupt_watcher=3D1'.
> > > > > >
> > > > > > Note that, currently not all safe per-CPU access primitives and=
 patterns
> > > > > > are accounted for, which could result in false positives. For e=
xample,
> > > > > > asm-generic/percpu.h uses plain operations, which by default ar=
e
> > > > > > instrumented. On interrupts and subsequent accesses to the same
> > > > > > variable, KCSAN would currently report a data race with this op=
tion.
> > > > > >
> > > > > > Therefore, this option should currently remain disabled by defa=
ult, but
> > > > > > may be enabled for specific test scenarios.
> > > > > >
> > > > > > To avoid new warnings, changes all uses of smp_processor_id() t=
o use the
> > > > > > raw version (as already done in kcsan_found_watchpoint()). The =
exact SMP
> > > > > > processor id is for informational purposes in the report, and
> > > > > > correctness is not affected.
> > > > > >
> > > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> > > > >
> > > > > And I get silent hangs that bisect to this patch when running the
> > > > > following rcutorture command, run in the kernel source tree on a
> > > > > 12-hardware-thread laptop:
> > > > >
> > > > > bash tools/testing/selftests/rcutorture/bin/kvm.sh --cpus 12 --du=
ration 10 --kconfig "CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONFIG_KCSAN_AS=
SUME_PLAIN_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn CONF=
IG_KCSAN_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VERBOSE=3Dy CONFIG_KCSAN_I=
NTERRUPT_WATCHER=3Dy" --configs TREE03
> > > > >
> > > > > It works fine on some (but not all) of the other rcutorture test
> > > > > scenarios.  It fails on TREE01, TREE02, TREE03, TREE09.  The comm=
on thread
> > > > > is that these are the TREE scenarios are all PREEMPT=3Dy.  So are=
 RUDE01,
> > > > > SRCU-P, TASKS01, and TASKS03, but these scenarios are not hammeri=
ng
> > > > > on Tree RCU, and thus have far less interrupt activity and the li=
ke.
> > > > > Given that it is an interrupt-related feature being added by this=
 commit,
> > > > > this seems like expected (mis)behavior.
> > > > >
> > > > > Can you reproduce this?  If not, are there any diagnostics I can =
add to
> > > > > my testing?  Or a diagnostic patch I could apply?
> > >
> > > I think I can reproduce it.  Let me debug some more, so far I haven't
> > > found anything yet.
> > >
> > > What I do know is that it's related to reporting. Turning kcsan_repor=
t
> > > into a noop makes the test run to completion.
> > >
> > > > I should hasten to add that this feature was quite helpful in recen=
t work!
> > >
> > > Good to know. :-)  We can probably keep this patch, since the default
> > > config doesn't turn this on. But I will try to see what's up with the
> > > hangs, and hopefully find a fix.
> >
> > So this one turned out to be quite interesting. We can get deadlocks
> > if we can set up multiple watchpoints per task in case it's
> > interrupted and the interrupt sets up another watchpoint, and there
> > are many concurrent races happening; because the other_info struct in
> > report.c may never be released if an interrupt blocks the consumer due
> > to waiting for other_info to become released.
>
> Been there, done that!  ;-)
>
> > Give me another day or 2 to come up with a decent fix.
>
> My thought is to send a pull request for the commits up to but not
> including this patch, allowing ample development and testing time for
> the fix.  My concern with sending this, even with a fix, is that any
> further bugs might cast a shadow on the whole series, further slowing
> acceptance into mainline.
>
> Fair enough?

That's fine. I think the features changes can stay on -rcu/kcsan-dev
for now, but the documentation updates don't depend on them.
If it'd be useful, the updated documentation could be moved before
this patch to -rcu/kcsan, so we'd have

 kcsan: Add current->state to implicitly atomic accesses
 kcsan: Add option for verbose reporting
 kcsan: Add option to allow watcher interruptions
-- cut --
 kcsan: Update API documentation in kcsan-checks.h
 kcsan: Update Documentation/dev-tools/kcsan.rst
 kcsan: Fix a typo in a comment
.. rest of series ..

Although I'm fine with either.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOsLeiD6hYXeD4g8fA%3DTi6EiUsbtiv4VshRGg%2BoG1ct-g%40mail.gm=
ail.com.
