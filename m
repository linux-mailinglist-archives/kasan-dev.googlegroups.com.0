Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMXS42BAMGQE56K6P3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 60848345B44
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 10:47:31 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id m14sf1414236pgr.9
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 02:47:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616492850; cv=pass;
        d=google.com; s=arc-20160816;
        b=T5T+Dv3lEeq7EbSfmpGYW3oIOJdCTYCGHSqYUDBP2fwu5+sjfjxzPP+na+pZEKx2kO
         rohmtY7FJfGKG2Pv83Ylmfwy+eIrTlDEi+gj9mMZiFM1iY6q/CPK9VMCAGSo7R3Q1n1G
         VuwZNrECVeG61oVqegd3TjwPVWsBBR+GP0jXf9SFoQc7hIFAN8mb6mLtJpmvs5mTfCAy
         0Ea3/ayb9B3TXaaNv6H8Xe6fWa14Pd+fGwEfxlXODQfwKMKKJsUWdjFY3lD5wZOqHpG7
         7cSLk5hcX4Nuga3XY7LKOGEVoQTtXnQF2AOOhyfIoAfHi3My5s5xNdUN4K/uVImR7nmV
         7AUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oU2qWOP5FiF0PmOdP4nvn4ZRMjnJ1vhTkyVgOtEKHnc=;
        b=lLBuIkbOiApK41wknZ3BEMgwjAeNewJCDrLvj4he9B+0I9FXkDcymkgPEHxyZo1SZu
         YaxXh+NyqYlM7Ap3NMIiKl3swEz88Iytr4vtxjy8iIKEIQ6NAhbAaosKrF4jHMrYRQIx
         B7MitcOKQzCD1rYSMiN5IzDmzzIfssKnzmZWM2IEVVLxECRt4ktSEiXrc896pplKQtBJ
         dE6NVpzycuwrRjlEVi9WHCG//EWUFJqKbLkH1sMEKL8Mpbxs3S1+vR27o8/7I/qjcrBu
         LEOjY1bNOut55Mz5l5WABsskN0ecjGHDB/uBFDUEDAjqs2YMQHiqHoo7b3wZMz6l8tJ3
         1ykw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c83oOIai;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oU2qWOP5FiF0PmOdP4nvn4ZRMjnJ1vhTkyVgOtEKHnc=;
        b=oSFWAHnSdoNpjlxMgSCqm1Fjk/LD8ik5IZAgTFBGARluai5ng4nIDQIa7egMUoc1Mk
         jzaxmUQicclNqXU/BkypBl44sbcGfs9hJos27HFeM5A9YKS6ltsizi4jbPupGQ5yFiTA
         C+tl/ShEu4hHG86KkqPOWILBIJpPOHKSa0dy5gA8VXfNaWa1cfJH+bEFNJGO4RhzKFqR
         JZ7ExWxMnaegAjA5zx3A532wVgatxl2n+3C/5XsLUrFCw7deTV2/ckN/1jrjk2UWtr6S
         BLcFH8U4TVLG6doe7pTeqyRKBH1g8+EI+8ANTMXUlFSg/CPXZs0eMg9Ti451qZbe3H6s
         URsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oU2qWOP5FiF0PmOdP4nvn4ZRMjnJ1vhTkyVgOtEKHnc=;
        b=MgAQGrzAmaRSAdRE1D0+wEfLaf4LthXcPwRuCiaakMWFw1jWMg8E37Oej0GeJoHNEv
         JCqjixuN1JVY/v9FKu5jQ/QinBtXEI5vwVV5ojZ8cetQovVMB1f88rHfB5EhLBkx5/2j
         DpiclhxIhTFea2HDHca5cxRtZyq7ElUBtpiqhb41NAR8PAi6azXD2K2bpqF25GSzprWB
         QcQuwlYerF2tEetW8pas21AoXA7zdyYsMmuPdXNfNkexHX2j3CyT/NE0e91PlrmG/4Ya
         OVI8F7pHyE5wLWYIWx4PHyjSihER3qH6K+ssKi6Cl1dca8C36tAJJWRD5Lo76TWhAW6U
         7L+g==
X-Gm-Message-State: AOAM532kxJ6adRU+D2OcVOlmg5GZ3Vh5kjmmG3IklobUjsbvpV7cofUT
	XqwWZVEyb2oPn6GAscPNo7I=
X-Google-Smtp-Source: ABdhPJz2PAI0+q1gbSdTq3gxXn71sNa2AWSpsEE3kdbNhoMHEdDPqAwgpHLKtorErrsAlN35J2GhRA==
X-Received: by 2002:a63:fa4c:: with SMTP id g12mr3291124pgk.205.1616492850108;
        Tue, 23 Mar 2021 02:47:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9acd:: with SMTP id x13ls3488575pfp.1.gmail; Tue, 23 Mar
 2021 02:47:26 -0700 (PDT)
X-Received: by 2002:a63:2318:: with SMTP id j24mr3438017pgj.134.1616492846756;
        Tue, 23 Mar 2021 02:47:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616492846; cv=none;
        d=google.com; s=arc-20160816;
        b=boE2lFqVY8qW3c71leul/DDRep/8Rh40atLrXVht84DV0RWNjvRa1zYCjIH2Mu5wY1
         UBRxNtWwgnTv6ChiP9ScHKSzswCi/dVb4k0YXUXrc5K9zjja9vu3ElMs50LZxFopBa5K
         XO4CYXzoPkCrD+6qrBMIzqFxG/Rfti5uCMNjOGWHLuZpfUXMDVY/e/aUK6QUgE4N8KQN
         8kQ/AxJIbf9ehXCRZTmPvTlwbz5V0+zVLHKX8SrEErM6RmKvUHD2uvhJFIFBHDeZl3c+
         4xhMgF/sUSs9KPgn3/x2/axAo+31D/h4dEZFsuPuvgtG0uzJz8DUsfsu83XWXLDlwqyz
         SkKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hgweAXsQTwePYGvzySvRrmFVPab8jCtXeq0art5Xlzk=;
        b=b5v1YZatn4O4J9QtTYrpPjySxu9fbuuJaUdHfg6Nz3d4y6rSY5ekq496XOxAykIVIg
         2rmf8eURClAFd1UD8FhrZSQ+EccgKkQTNA8FgS/8nf1AsTO0t8jFCPIH/WJbZ5+5/VDx
         i2gSBopFCxDqxwb7axXMiqzuzYYGlGCuSBTMFn3W1U7GLCapzj0XCbhpg4A286U3Ykdf
         Q8Sem/zOjjHae/neDA012wFQHe/DsT3g7N8mDxVaoIXa7k4RznD0EsZrilNK4JWQvK80
         dKg+67De1LcFiZdUJTq8Yhdh9pm214+GkFAyRfFvqYM9ieme8Erv8aSPrB6pvmcCF7qj
         9cIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=c83oOIai;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id y11si130297pju.3.2021.03.23.02.47.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 02:47:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id w21-20020a9d63950000b02901ce7b8c45b4so18857380otk.5
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 02:47:26 -0700 (PDT)
X-Received: by 2002:a05:6830:148c:: with SMTP id s12mr3724534otq.251.1616492846280;
 Tue, 23 Mar 2021 02:47:26 -0700 (PDT)
MIME-Version: 1.0
References: <20210310104139.679618-1-elver@google.com> <20210310104139.679618-9-elver@google.com>
 <YFiamKX+xYH2HJ4E@elver.google.com> <CAP-5=fW8NnLFbnK8UwLuYFzkwk6Yjvxv=LdOpE8qgXbyL6=CCg@mail.gmail.com>
In-Reply-To: <CAP-5=fW8NnLFbnK8UwLuYFzkwk6Yjvxv=LdOpE8qgXbyL6=CCg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Mar 2021 10:47:13 +0100
Message-ID: <CANpmjNN6_jO5vK8fteJ7bEi1gM6Ho2kZxSq9avocM3A5TyFL=g@mail.gmail.com>
Subject: Re: [PATCH RFC v2 8/8] selftests/perf: Add kselftest for remove_on_exec
To: Ian Rogers <irogers@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, linux-fsdevel <linux-fsdevel@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, x86 <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Vince Weaver <vincent.weaver@maine.edu>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=c83oOIai;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Tue, 23 Mar 2021 at 04:10, Ian Rogers <irogers@google.com> wrote:
> On Mon, Mar 22, 2021 at 6:24 AM Marco Elver <elver@google.com> wrote:
> > On Wed, Mar 10, 2021 at 11:41AM +0100, Marco Elver wrote:
> > > Add kselftest to test that remove_on_exec removes inherited events from
> > > child tasks.
> > >
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > To make compatible with more recent libc, we'll need to fixup the tests
> > with the below.
> >
> > Also, I've seen that tools/perf/tests exists, however it seems to be
> > primarily about perf-tool related tests. Is this correct?
> >
> > I'd propose to keep these purely kernel ABI related tests separate, and
> > that way we can also make use of the kselftests framework which will
> > also integrate into various CI systems such as kernelci.org.
>
> Perhaps there is a way to have both? Having the perf tool spot an
> errant kernel feels like a feature. There are also
> tools/lib/perf/tests and Vince Weaver's tests [1]. It is possible to
> run standalone tests from within perf test by having them be executed
> by a shell test.

Thanks for the pointers. Sure, I'd support more additional tests.

But I had another look and it seems the tests in
tools/{perf,lib/perf}/tests do focus on perf-tool or the library
respectively, so adding kernel ABI tests there feels wrong. (If
perf-tool somehow finds use for sigtrap, or remove_on_exec, then
having a perf-tool specific test for those would make sense again.)

The tests at [1] do seem relevant, and its test strategy seems more
extensive, including testing older kernels. Unfortunately it is
out-of-tree, but that's probably because it was started before
kselftest came into existence. But there are probably things that [1]
contains that are not appropriate in-tree.

It's all a bit confusing.

Going forward, if you insist on tests being also added to [1], we can
perhaps mirror some of the kselftest tests there. There's also a
logistical problem with the tests added here, because the tests
require an up-to-date siginfo_t, and they use the kernel's
<asm/siginfo.h> with some trickery. Until libc's siginfo_t is updated,
it probably doesn't make sense to add these tests to [1].

The other question is, would it be possible to also copy some of the
tests in [1] and convert to kselftest, so that they live in-tree and
are tested regularly (CI, ...)?

Because I'd much prefer in-tree tests with little boilerplate, that
are structured with parsable output; in the kernel we have the
kselftest framework for tests with a user space component, and KUnit
for pure in-kernel tests.

Thanks,
-- Marco

> Thanks,
> Ian
>
> [1] https://github.com/deater/perf_event_tests
[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN6_jO5vK8fteJ7bEi1gM6Ho2kZxSq9avocM3A5TyFL%3Dg%40mail.gmail.com.
