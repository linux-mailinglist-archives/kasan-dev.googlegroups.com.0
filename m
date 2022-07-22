Return-Path: <kasan-dev+bncBCMIZB7QWENRBZWX5GLAMGQE4VKUAHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D62C757DD74
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 11:20:39 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id a19-20020a19f813000000b0048a7379e38bsf1096849lff.5
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 02:20:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658481639; cv=pass;
        d=google.com; s=arc-20160816;
        b=ElnfNq+++C0pxSnPXGhpRfWQz+EjDwWcEjL2HjPp9USqblDbEJa6xa31hLkffBNxaq
         4ob/NQ0cwyrXRLlOKOTg46k/q5shNRjM2PyqU5VtvcIYCKWoUmVfzlSgVktClYzLu+Df
         6cSmq1HVMIF7N18x/zHeG4MmIhhYbMluWsy3+sQx2260kXvGgUzYhF3PHiAPjv4E0ANZ
         wmKWYuDglOZ33OgwDHKR8tdYgOOO7r+JkArRe5G1aRFEEuoLlI00VSQ4kFR2BGmOlUNV
         4xHb0YAUioUwnAphkiu6DJQNdPjVmMiHkrTXsZjBfCy+ZqgwvkHyjIHvJGnJG4kwqDJJ
         mLig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CbnuoXLLVdxv93vg8e/bnu08qh+Oxf8NVaa9T0Pph8A=;
        b=gKJvtUIrdo5pIh4seKOw4I152UBN3eSo7FXkoldkg122/wwvRNeerJM8T+lxuRHI+B
         Rq9Ln7oTw8lUYgRGWbQhPZcie+h2ll4NabCK11/YriiX63NR3ghd5dvM3hMvBMUZQuA2
         yAG95jQB4FdEfdkkW9RjItEzcTlK7/PJabVl604cxBFBcUbnObKdVxWugBWAJ4VsmfBz
         kWbeCg5siS/wkePjbZQbqsUf6paj+3odyyGWL+VxfRDntuSNZPx2m9ERJLLKlBC5favz
         upDpVueWTUS3NoBHeq1bxbdmdFbTjgYRvDbQpOk+Pai5KpjX/J2jNJdbAfroUOkroyqy
         3F7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HZso6ITt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CbnuoXLLVdxv93vg8e/bnu08qh+Oxf8NVaa9T0Pph8A=;
        b=mhqMOWnwE9tU+fRkvwJkkLH8IoEVq0P8fh2iUiytKPAfGP9vZ6aikkKfe+G/kcuW3w
         RJ1/5MYQYhXYAXlXSPqLPV6VLY366JbX8stMsVK3M8L2uxNunxwTv1qHcraJR6qPj0Sr
         wosmshJB/hkXRxuUUCaAxX+MCknZFXOZn1N+/wwwKregt43WY967i02cVft0v4A4JFeg
         fG/r8Cu5J2lqPulywYTdQ2Th33njxkI+AqAbV/jX0nw6ibzT0JyQOUhbAaKBaL3eBcvi
         Dzn4y43Baxr498FOfMW4KE4oB6id4cJddJ0ylr9aRW7UEbX20gGIyVAWO3/W2kOz1g4B
         DQ7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CbnuoXLLVdxv93vg8e/bnu08qh+Oxf8NVaa9T0Pph8A=;
        b=wGAZsFWsNGTGsNC6vwHatX2D76lAQTrlBll+sW3Nt2eU2Jh1aPJH4TzxynWwJIntQy
         rCd+PCIrfXlqsPaASP3o8dXdry7LhzrjirgplaRHJzKF9TqYYGXs9IfT+gQzk5P6VFOS
         cirZ3Yv1JD1+CaZpRbEx2JUz+jZqXbN2vo7BosW5nyN8K38DyYuT7TspTik0roCjZY7Q
         b2PBFVpwB2O56EGkduAKFj7qIbfDJTYKVkICkZ9VCTbqj49lAkflZbvXkH2Tmjxb/GgP
         J8bXMcW9wKTro7cgsv+/BaKllkcFwRjWK0XCmnyAQPzsXsVSqAoPnOqncsO+0F1c92gi
         GKvw==
X-Gm-Message-State: AJIora/dC+/FsOjsg7eUpbVQINrv8G5JrXUtCIXGSBbV9PW3R0NXpwrl
	C3G1AKZ5SPTJkuBjizoN1+I=
X-Google-Smtp-Source: AGRyM1tfT92FbFNgsKUav4mAo3sTfY1jgdEHp1B0UW92vkXNyYjTj+jmFdvvRXSzkmR8+5wPdKmaiw==
X-Received: by 2002:a05:651c:248:b0:25d:4f99:683d with SMTP id x8-20020a05651c024800b0025d4f99683dmr971374ljn.366.1658481638997;
        Fri, 22 Jul 2022 02:20:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3150:b0:48a:776f:8c2f with SMTP id
 s16-20020a056512315000b0048a776f8c2fls778897lfi.1.-pod-prod-gmail; Fri, 22
 Jul 2022 02:20:37 -0700 (PDT)
X-Received: by 2002:ac2:5b1d:0:b0:48a:718b:d21d with SMTP id v29-20020ac25b1d000000b0048a718bd21dmr1055970lfn.488.1658481637830;
        Fri, 22 Jul 2022 02:20:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658481637; cv=none;
        d=google.com; s=arc-20160816;
        b=ke7elIzlfh9ipVm+xwlILRZQajsPwnusX9bxSGWiH1DAL65CHwkvHNTV9ddIkIeJaK
         tLTIiX+lid/jn5uDhCzeVJchSSaMmuUkr3ikvtLqPisvvUKJYqkm2ujhMcFm+Wgrzlbu
         IXqIsvDOjwgPuc1iah6duPi1Mr4ZaeAvh9chyE6+Srqys25HPQcMGmejmTWgEKrf0Xdj
         WEQW/Tu5soySkdH5G5IC2vOPauW+ngj10sLyAw9nr2NuxG/diFvhybZmxMii5MVQkVBJ
         4QbdFkfyLghqqipl81W9hHgzh1MEbzYnhs52OzHO7uMFt4LGMe6/dKVshpN6RyPfu3YW
         glAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QRgm1i6pUMaVa04XshAEZM9Qyu6OwRtZCN3cy0vmh7k=;
        b=U4bBY1u2F+u+QOsr0+TuvcW+1wxqn2nP2hdpK9DiMhOc6My2C6aFLWP5ydPtJI13Uc
         AsXpos8WNXUfxu3Bj/zoUs2bU5zYOXagRzm1mzsO+h2sU47E9wjr1dcIWwjn9qfI8yQM
         03PSihjZVru4MYPD+8PMEGAYfqmZUUIBEByrDu8TGd2armUgAG2612HuaRtORdUo2+mN
         zYg4GPmni9IICisfdQ4lbJjfQdnG6w82eEigDGzFoJ+YIdDZ3hn7Kh5Y47lFoY10aZ6Q
         4xQUhb+DBGnNrGb25icvrdGhDG4j0CckygxZ6E/y/M+tOf1go7JKlH2e5X9O58b5nvRv
         WusA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=HZso6ITt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id p20-20020a2eb994000000b0025dd92f1e72si194800ljp.1.2022.07.22.02.20.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jul 2022 02:20:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id d17so4574912lfa.12
        for <kasan-dev@googlegroups.com>; Fri, 22 Jul 2022 02:20:37 -0700 (PDT)
X-Received: by 2002:a05:6512:1085:b0:48a:710:6a7b with SMTP id
 j5-20020a056512108500b0048a07106a7bmr930020lfg.417.1658481637244; Fri, 22 Jul
 2022 02:20:37 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-2-elver@google.com>
 <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com> <20220722091044.GC18125@willie-the-truck>
In-Reply-To: <20220722091044.GC18125@willie-the-truck>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jul 2022 11:20:25 +0200
Message-ID: <CACT4Y+ZOXXqxhe4U3ZtQPCj2yrf6Qtjg1q0Kfq8+poAOxGgUew@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=HZso6ITt;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a
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

On Fri, 22 Jul 2022 at 11:10, Will Deacon <will@kernel.org> wrote:
> > [adding Will]
> >
> > On Mon, Jul 04, 2022 at 05:05:01PM +0200, Marco Elver wrote:
> > > Add KUnit test for hw_breakpoint constraints accounting, with various
> > > interesting mixes of breakpoint targets (some care was taken to catch
> > > interesting corner cases via bug-injection).
> > >
> > > The test cannot be built as a module because it requires access to
> > > hw_breakpoint_slots(), which is not inlinable or exported on all
> > > architectures.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > As mentioned on IRC, I'm seeing these tests fail on arm64 when applied atop
> > v5.19-rc7:
> >
> > | TAP version 14
> > | 1..1
> > |     # Subtest: hw_breakpoint
> > |     1..9
> > |     ok 1 - test_one_cpu
> > |     ok 2 - test_many_cpus
> > |     # test_one_task_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > |     Expected IS_ERR(bp) to be false, but is true
> > |     not ok 3 - test_one_task_on_all_cpus
> > |     # test_two_tasks_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > |     Expected IS_ERR(bp) to be false, but is true
> > |     not ok 4 - test_two_tasks_on_all_cpus
> > |     # test_one_task_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > |     Expected IS_ERR(bp) to be false, but is true
> > |     not ok 5 - test_one_task_on_one_cpu
> > |     # test_one_task_mixed: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > |     Expected IS_ERR(bp) to be false, but is true
> > |     not ok 6 - test_one_task_mixed
> > |     # test_two_tasks_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > |     Expected IS_ERR(bp) to be false, but is true
> > |     not ok 7 - test_two_tasks_on_one_cpu
> > |     # test_two_tasks_on_one_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > |     Expected IS_ERR(bp) to be false, but is true
> > |     not ok 8 - test_two_tasks_on_one_all_cpus
> > |     # test_task_on_all_and_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > |     Expected IS_ERR(bp) to be false, but is true
> > |     not ok 9 - test_task_on_all_and_one_cpu
> > | # hw_breakpoint: pass:2 fail:7 skip:0 total:9
> > | # Totals: pass:2 fail:7 skip:0 total:9
> >
> > ... which seems to be becasue arm64 currently forbids per-task
> > breakpoints/watchpoints in hw_breakpoint_arch_parse(), where we have:
> >
> >         /*
> >          * Disallow per-task kernel breakpoints since these would
> >          * complicate the stepping code.
> >          */
> >         if (hw->ctrl.privilege == AARCH64_BREAKPOINT_EL1 && bp->hw.target)
> >                 return -EINVAL;
> >
> > ... which has been the case since day one in commit:
> >
> >   478fcb2cdb2351dc ("arm64: Debugging support")
> >
> > I'm not immediately sure what would be necessary to support per-task kernel
> > breakpoints, but given a lot of that state is currently per-cpu, I imagine it's
> > invasive.
>
> I would actually like to remove HW_BREAKPOINT completely for arm64 as it
> doesn't really work and causes problems for other interfaces such as ptrace
> and kgdb.

Will it be a localized removal of code that will be easy to revert in
future? Or will it touch lots of code here and there?
Let's say we come up with a very important use case for HW_BREAKPOINT
and will need to make it work on arm64 as well in future.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZOXXqxhe4U3ZtQPCj2yrf6Qtjg1q0Kfq8%2BpoAOxGgUew%40mail.gmail.com.
