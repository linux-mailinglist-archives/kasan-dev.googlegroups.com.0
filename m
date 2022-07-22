Return-Path: <kasan-dev+bncBCMIZB7QWENRBIHZ5GLAMGQEZQ3QYTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C5DA857DFDA
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 12:32:01 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id d41-20020a0565123d2900b00489ed34ed26sf1709174lfv.15
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 03:32:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658485921; cv=pass;
        d=google.com; s=arc-20160816;
        b=wrAlrNPr39tcjAy8/skaKpUoqJSecZq8MapSXgsGgYIc5H5J6YJIJNNcijpYRFI9HS
         k2Cyg3kEJ7JGgngJEewuXaU7i7g5ny7N52ClR2MoAZ6oa/4aAN7a0b6sVcFQkI0KQs4W
         N8LR4uSiujsTlRrmUj9u6wh+gEaWoLrDGeMI/DOUM1Ahtv0+ykS3GJF8M+MPNTd+Y6hM
         QMA3sv7xTbAuldmA6jnSm7h3vmsbQpBadHLywHgl6w46H+xF+KRLd6eP79WtU63QGU9r
         SHKe69pNazUleyEKLEwR5LMqTCznqvkYjRRNPc0gp3WJAN070KM/M66yYJgrb/GIRXap
         E4MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WoZH5C5NrRv5vRsMu97op/fA201SfKEJg7kkiXHoayo=;
        b=y+Ng47By7rZ6gAXkjB0In81FedTEto2ell2tXdPXScunbRpdGSd3YS+h/3XBzh1+vK
         3+Zk9tQyvc2Sc8Kr7dmmQAJqCSMdvPOafQlRQhrmglhcU4whPLds5r9bKBhvwIAnoew9
         tTahh/WmzgWTrnmR1cM2ZFgdmbg0bW9qTC/AHmB+73n5I1LGLCjjSbRRDinV5Ihpfkwo
         vquF/rRXey7yqnAgBo6hDd6/w5dSjma1hNX8aLoQzvRtmEeRv7Ey88WosxuJEuiuho2v
         DdtN0dVg3AMTguG6WB2AOSOBe4YsSXA5LoYTfYvIvDROSKYRKea9pxRfgfo+RsAqqITa
         4+ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pnVwjwP2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WoZH5C5NrRv5vRsMu97op/fA201SfKEJg7kkiXHoayo=;
        b=lTMP99M8RYiL2xS0kS629ydMJR/bSr2U/Y+S60y3pWg0OG7eWREAINJBDs8T+CSzk3
         OxrKSCSEppQvJ7nFUH+nrEX0VMSy2NEjjlUDVPnmOPw50lNoIvo47qOH7wZpZ0KsqO+h
         E0nHd4lEPRvwxgtJi57/LaDzAhk5doS+PJKGlyf6T9fdtElYefzx/3inrRkBkULu1XDh
         H+5geVkTVLE+b2e8P7yOwPlOKz7VHt4RHK20PU3Syn/k4dzqVrNbeFc33aZiEJFFf8BL
         1pOa7aKK1Sa09856iHxXs1+ksbcXiCuZDhPgmMJzqqyHa/rlff7/tsptKMmmdRh7G/Tf
         aGOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WoZH5C5NrRv5vRsMu97op/fA201SfKEJg7kkiXHoayo=;
        b=tYq4JKiUCsLfd4p4Kk/uSIrM/gziFGOrhRKkuvC9jsMSlqGIyBGm3+ep5eIsMRWx7H
         n6sLal9s1g6bZw/gDoBjEK+7cVOZdS5MpMuxOc5sgS0PFdlE7ukBAfdpHuyRFglhjNp9
         WbOG3lahe0MdbKbN+sCfrUkypOm4D/H2bh8AZP6QflBwFXGoZDwigJScd2eZchCvOdac
         4dYo4+KJ5FzBJS/0ByHp2yX++CIUgXJ/Foo2ChKLH0nWGw03Y7DlDlh3eYS8maiyFP8l
         8R2NnbQtFL1aG1pi7UNxTqn9+5taxSB0xDf2HjUWNDFlo3BEgBJIxH19+pNVnXuKZp6z
         wjWg==
X-Gm-Message-State: AJIora/hc6eaIQJX0OFCshjZw6WNBXMru5M9R9cAfpj8xhC04LqszR5/
	Tibxe7B5UMwghKjEVeXEpug=
X-Google-Smtp-Source: AGRyM1uO35S9RHVwr4rvGgonUTRBuJWkgbVCm1wkURi6pczXt7o4UahjFLi79v5U9wZDSH8m2upvRA==
X-Received: by 2002:a05:6512:c02:b0:48a:80f:b92d with SMTP id z2-20020a0565120c0200b0048a080fb92dmr1145731lfu.675.1658485920823;
        Fri, 22 Jul 2022 03:32:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:78f:b0:488:e60f:2057 with SMTP id
 x15-20020a056512078f00b00488e60f2057ls1160905lfr.2.-pod-prod-gmail; Fri, 22
 Jul 2022 03:31:59 -0700 (PDT)
X-Received: by 2002:a05:6512:3404:b0:48a:29b9:f069 with SMTP id i4-20020a056512340400b0048a29b9f069mr1212432lfr.296.1658485919595;
        Fri, 22 Jul 2022 03:31:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658485919; cv=none;
        d=google.com; s=arc-20160816;
        b=Gp/qyDBVFQKxcMMCjXGlhvuEupCRiIdm1+lODUxZ8OFao78rolAqzKyZc0kAFR+zS5
         v6q2ANewf7vh5dfn8kExg/G7nGxflhJlgcEMPKWfte2xHaAIpE6EDP/cXB3no3EvBifG
         Wc7zMVQKAQ93Dxl4/ibcTQMgCJsuo0r6w14q4/36HhCwzOITUrT4molr9PkULOei2ecz
         0PrKUXl258oEt8W8w59N9goPcGTVr/ypQ/IXiM4AxKMFgenLBblLxPhkNTXJOeTlWqen
         Kat0Zx+h7aJTekzDEjaU1iXs55p4rGHji+XhV5bmNIVDE8MYxO9LSZDuZRV45pEolqDo
         wxQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eXqhKXWkyJJg9+g/9EohedHzzZKAjuqa2sFmi97JD9Y=;
        b=vcK5EpZBa6rSsnyjm1uK2hnMRC0rcavThRvb4fh2YiJo33CwcLNs8ww3cJDveQC8mJ
         PWMGIjnZg6MX5XrhvU5C7v2fCgraOhcEknmy0fMMEyME0hBNcF2aDmKKopegDljiLj4y
         iluf4q7w/b0hrijWW6ri7mwAJtCF2d+qzWnqjTP1z63wLs/eWUKFlAAhzMmJy5Yuag15
         wx6hDwPHwNPJbUS57AZTtlAieFJGN+NsM6iuSs3OuD2gKbB72RelwHgL0vqShyqD+faF
         DwVBLGXX9tAuQEBim8C93LuyO3CSSMNjM9MyhRzUEmTqbVPk4rmv/z48Zaum4WN0/2xT
         K/TQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pnVwjwP2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id o22-20020ac25e36000000b0047fae47ce32si96366lfg.9.2022.07.22.03.31.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jul 2022 03:31:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id e11so4945257ljl.4
        for <kasan-dev@googlegroups.com>; Fri, 22 Jul 2022 03:31:59 -0700 (PDT)
X-Received: by 2002:a05:651c:1310:b0:25d:efe5:109d with SMTP id
 u16-20020a05651c131000b0025defe5109dmr742781lja.465.1658485917645; Fri, 22
 Jul 2022 03:31:57 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-2-elver@google.com>
 <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com> <20220722091044.GC18125@willie-the-truck>
 <CACT4Y+ZOXXqxhe4U3ZtQPCj2yrf6Qtjg1q0Kfq8+poAOxGgUew@mail.gmail.com> <20220722101053.GA18284@willie-the-truck>
In-Reply-To: <20220722101053.GA18284@willie-the-truck>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jul 2022 12:31:45 +0200
Message-ID: <CACT4Y+Z0imEHF0jM-f-uYdpfSpfzMpa+bFZfPeQW1ECBDjD9fA@mail.gmail.com>
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
To: Will Deacon <will@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pnVwjwP2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22a
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

On Fri, 22 Jul 2022 at 12:11, Will Deacon <will@kernel.org> wrote:
> > > > [adding Will]
> > > >
> > > > On Mon, Jul 04, 2022 at 05:05:01PM +0200, Marco Elver wrote:
> > > > > Add KUnit test for hw_breakpoint constraints accounting, with various
> > > > > interesting mixes of breakpoint targets (some care was taken to catch
> > > > > interesting corner cases via bug-injection).
> > > > >
> > > > > The test cannot be built as a module because it requires access to
> > > > > hw_breakpoint_slots(), which is not inlinable or exported on all
> > > > > architectures.
> > > > >
> > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > >
> > > > As mentioned on IRC, I'm seeing these tests fail on arm64 when applied atop
> > > > v5.19-rc7:
> > > >
> > > > | TAP version 14
> > > > | 1..1
> > > > |     # Subtest: hw_breakpoint
> > > > |     1..9
> > > > |     ok 1 - test_one_cpu
> > > > |     ok 2 - test_many_cpus
> > > > |     # test_one_task_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > > |     Expected IS_ERR(bp) to be false, but is true
> > > > |     not ok 3 - test_one_task_on_all_cpus
> > > > |     # test_two_tasks_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > > |     Expected IS_ERR(bp) to be false, but is true
> > > > |     not ok 4 - test_two_tasks_on_all_cpus
> > > > |     # test_one_task_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > > |     Expected IS_ERR(bp) to be false, but is true
> > > > |     not ok 5 - test_one_task_on_one_cpu
> > > > |     # test_one_task_mixed: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > > |     Expected IS_ERR(bp) to be false, but is true
> > > > |     not ok 6 - test_one_task_mixed
> > > > |     # test_two_tasks_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > > |     Expected IS_ERR(bp) to be false, but is true
> > > > |     not ok 7 - test_two_tasks_on_one_cpu
> > > > |     # test_two_tasks_on_one_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > > |     Expected IS_ERR(bp) to be false, but is true
> > > > |     not ok 8 - test_two_tasks_on_one_all_cpus
> > > > |     # test_task_on_all_and_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > > |     Expected IS_ERR(bp) to be false, but is true
> > > > |     not ok 9 - test_task_on_all_and_one_cpu
> > > > | # hw_breakpoint: pass:2 fail:7 skip:0 total:9
> > > > | # Totals: pass:2 fail:7 skip:0 total:9
> > > >
> > > > ... which seems to be becasue arm64 currently forbids per-task
> > > > breakpoints/watchpoints in hw_breakpoint_arch_parse(), where we have:
> > > >
> > > >         /*
> > > >          * Disallow per-task kernel breakpoints since these would
> > > >          * complicate the stepping code.
> > > >          */
> > > >         if (hw->ctrl.privilege == AARCH64_BREAKPOINT_EL1 && bp->hw.target)
> > > >                 return -EINVAL;
> > > >
> > > > ... which has been the case since day one in commit:
> > > >
> > > >   478fcb2cdb2351dc ("arm64: Debugging support")
> > > >
> > > > I'm not immediately sure what would be necessary to support per-task kernel
> > > > breakpoints, but given a lot of that state is currently per-cpu, I imagine it's
> > > > invasive.
> > >
> > > I would actually like to remove HW_BREAKPOINT completely for arm64 as it
> > > doesn't really work and causes problems for other interfaces such as ptrace
> > > and kgdb.
> >
> > Will it be a localized removal of code that will be easy to revert in
> > future? Or will it touch lots of code here and there?
> > Let's say we come up with a very important use case for HW_BREAKPOINT
> > and will need to make it work on arm64 as well in future.
>
> My (rough) plan is to implement a lower-level abstraction for handling the
> underlying hardware resources, so we can layer consumers on top of that
> instead of funneling through hw_breakpoint. So if we figure out how to make
> bits of hw_breakpoint work on arm64, then it should just go on top.
>
> The main pain point for hw_breakpoint is kernel-side {break,watch}points
> and I think there are open design questions about how they should work
> on arm64, particularly when considering the interaction with user
> watchpoints triggering on uaccess routines and the possibility of hitting
> a kernel watchpoint in irq context.

I see. Our main interest would be break/watchpoints on user addresses
firing from both user-space and kernel (uaccess), so at least on irqs.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ0imEHF0jM-f-uYdpfSpfzMpa%2BbFZfPeQW1ECBDjD9fA%40mail.gmail.com.
