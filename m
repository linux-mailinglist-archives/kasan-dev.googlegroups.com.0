Return-Path: <kasan-dev+bncBDAZZCVNSYPBBOHP5GLAMGQE6UHFINY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 58B2357DF5E
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 12:11:06 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 3-20020a05651c00c300b0025d8fcbd063sf895915ljr.16
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jul 2022 03:11:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658484665; cv=pass;
        d=google.com; s=arc-20160816;
        b=vk9FzkFwpp4vwAx47m8uVfQ76s8T4MKk4mXQosUdAoyEPCV8+zf+plr3lewM7a8bM+
         kF6Po/wvpwSgkRiKrXNk2ytVhsHoJmpsVECUDFfs2DSKTNigFKEZLY/bibIe0vJSpml/
         1CLBlHpzgbagY1ecLeLM7QA0xDzcWRmii7u1iE0x26dCgO5STpDb3Y+B88okWX6q+G3x
         6hzCkJNFSSx4/CaMngk3rWLW2kCTenyJQZ6YGYMlhP1AR8X1ltGvznFpb2JhbKAN98uM
         /lTuvTBldr9kJQ/C7v6/s3hrmKoPozCfrr6gstYA7nueWW73J9ToEBHQN/C5blZOIIWS
         qX7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=H4I7QeZqufHhCQflTph+J81UheXR/ZhpI7YQLJFN/kQ=;
        b=eZD8EI1/o6YSddlRoZbbnlSb8hTtXysl0G4yY2hr8E/Qa+1BPfzdmqupkKvjqG2H7/
         XlP1figXN5uCnjQj7lAf6gg103EMhh3hybMpcIwAqnpbzH6YU4kknzrNsDyC3Z2cHyhP
         cA/h8ieeko6oSgtim5NHteN0Rebha3RZXDsmYmZktlAAg6rZG9/uVNJZfg2jBbyD3eSW
         17jDWAxcSLZ+Dlv4p6SBnrGV/uOtwBKDhyc2gIOn85yfeJOu8PJbt1f0deZ2y1WsZgSd
         R42o/IC5gs5oievJp9Bwx159UB/QDoJTHLlp0YwDKinC1/qkip8s2yd3yQRD5Iw7hwX1
         Ns2w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GYwdPrRY;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H4I7QeZqufHhCQflTph+J81UheXR/ZhpI7YQLJFN/kQ=;
        b=UBWJqceedoIgD/iG/EibU09r+W0SyfFQA78qDURP7R/l3i2eLVgFi4IOpuDBsBVe/z
         1v9mLjrbNVxk4l+YiaLzFyTOP+G7iRA8ePxHbXrNt5KOuZp66QuQc5tNW/bKaEht5Sy1
         6DxqwN5uOr5Pg/qvlkhwYRv3QVD7PX/eOoqr5GDCo33rtMLYEWWJTdbjAZubscHSsbsA
         NbX5Nfa+1/5uqwSVk5gqN5uOzSkVe/GgeeFlxunyrv3RQ6q+asrr1zBfhDtoQzv+3u0T
         m8Ra7vxHGJIng2dOxZmhuPkbb02V5xbSwvsjShxY4xdfJsdnYDfFyDVwSADwti3Nw5J2
         JiVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H4I7QeZqufHhCQflTph+J81UheXR/ZhpI7YQLJFN/kQ=;
        b=DSbn/RZvFEnFuEgSni8B6xs5s0g7UxgPMSGO8Ws8+/t3WCc1St9MfDVniWszQE2VUq
         oUOubANhCDDAkpmLe5yy8onIcTk8QGRpPHA0DE1DcD0cffixCplSNNjMWyWmHh1OgwU/
         eC/OxaXkxG/1jvKqOd8+R3Uzsqj1lrYk/QEnKB6asYYLxyLtpqtSNei01JzVY48i93kt
         M0kSKmbN92kMg2Wrip2sDt/5F0JMKm4ZnubBWvzuBU7J7lhZ3XkGWRdcrpYjBWmnHqVc
         9joukS2YP72hVIQ/TfYAK2roqwAWk7NgXVttaymVM0EMig0yhMs4zylbuI8xC1YoNI0G
         0NnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/IqrCweHNlgv2VPqspm4Q5l8URMbX9CFKR5aqbBFr1dUtSlb9I
	X2zbOvhAWWnEHyc9NFNyM/c=
X-Google-Smtp-Source: AGRyM1uU/IeIVKt3YlycGTLge7/NaJm6HUdMX7NiKsngXy7rt+k3tBFnX7KXYWX5Sl7P93qicuiVRA==
X-Received: by 2002:a05:6512:131b:b0:48a:26dd:d823 with SMTP id x27-20020a056512131b00b0048a26ddd823mr1018944lfu.661.1658484665364;
        Fri, 22 Jul 2022 03:11:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:96cd:0:b0:25a:7122:3b89 with SMTP id d13-20020a2e96cd000000b0025a71223b89ls853627ljj.5.-pod-prod-gmail;
 Fri, 22 Jul 2022 03:11:04 -0700 (PDT)
X-Received: by 2002:a2e:b0cb:0:b0:25d:d87b:1afa with SMTP id g11-20020a2eb0cb000000b0025dd87b1afamr982116ljl.479.1658484664016;
        Fri, 22 Jul 2022 03:11:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658484664; cv=none;
        d=google.com; s=arc-20160816;
        b=KFb6w6ol6kUEtTx8zPaV6zqSycpm91t9E7mpjvYJGoZ9NshcatuzOCm8LVlLK/IV1a
         GPKJIsNz0i4G4snMwRBdDNJ8tWgcW2E78SEyZ2wDKyoecEv5o7THp3d/ovq9CnSPFPPi
         CBl5INcimCdNUTqeHcwjeAE45cFTJGL+nhuM+M0ULb08uY+9RdwfOpqQQ0nD8OB+RNnb
         e78jvJfrN5hgTUZ7ry5ezgATMh5en9bwIteaxkGmC7q/kE4WY4u3meI+zGFCMAN6p9Mn
         NCeorTGuDOV3Jl7V5mmKPXEdL52Ai+pvLGp7DYdK8DGEBYStjUjZEYAyDMv4coqRAWUE
         vBXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ggf2BjxoUKXrHVRLrTeghO/b6KVj7KMj7nEdCoi/NnY=;
        b=i1f18jhCnXwpj8EoC98cYo9PhJK1tV42z3/NXEa8+kRqkeGFlK/CkhRGZKJEbhDIYO
         adDBrQ/WgdAyZ+qWL2xMzQVzp+dY8MH0qc9fwdjc2s+jj9xg5Tgo3RcXEZhi12F2UAAo
         6idckDwRWEt+bjjyIgVfUv7cX5u3cfakEVkwS2wZ83hdn/kF0v+S2YXolZFbgORpuBOh
         wxwWLgkZBR1Phl1tDZQXpg92yDR2+ge4n2vz5fOsRPl4e1l4ceQZuttzp4FIHXuwEBVv
         fOHIflasWDmbig3GLcx4b4LzmauqTwsnY47leLAqTF0QNLJKRp70PSRD6ln8JK+ZdHkT
         Vn5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GYwdPrRY;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id s14-20020a056512214e00b00489d1a6dca6si161244lfr.8.2022.07.22.03.11.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jul 2022 03:11:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 2B3B7B827C2;
	Fri, 22 Jul 2022 10:11:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 138D1C341C6;
	Fri, 22 Jul 2022 10:10:57 +0000 (UTC)
Date: Fri, 22 Jul 2022 11:10:54 +0100
From: Will Deacon <will@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linuxppc-dev@lists.ozlabs.org, linux-perf-users@vger.kernel.org,
	x86@kernel.org, linux-sh@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 01/14] perf/hw_breakpoint: Add KUnit test for
 constraints accounting
Message-ID: <20220722101053.GA18284@willie-the-truck>
References: <20220704150514.48816-1-elver@google.com>
 <20220704150514.48816-2-elver@google.com>
 <Ytl9L0Zn1PVuL1cB@FVFF77S0Q05N.cambridge.arm.com>
 <20220722091044.GC18125@willie-the-truck>
 <CACT4Y+ZOXXqxhe4U3ZtQPCj2yrf6Qtjg1q0Kfq8+poAOxGgUew@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZOXXqxhe4U3ZtQPCj2yrf6Qtjg1q0Kfq8+poAOxGgUew@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GYwdPrRY;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Jul 22, 2022 at 11:20:25AM +0200, Dmitry Vyukov wrote:
> On Fri, 22 Jul 2022 at 11:10, Will Deacon <will@kernel.org> wrote:
> > > [adding Will]
> > >
> > > On Mon, Jul 04, 2022 at 05:05:01PM +0200, Marco Elver wrote:
> > > > Add KUnit test for hw_breakpoint constraints accounting, with various
> > > > interesting mixes of breakpoint targets (some care was taken to catch
> > > > interesting corner cases via bug-injection).
> > > >
> > > > The test cannot be built as a module because it requires access to
> > > > hw_breakpoint_slots(), which is not inlinable or exported on all
> > > > architectures.
> > > >
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > >
> > > As mentioned on IRC, I'm seeing these tests fail on arm64 when applied atop
> > > v5.19-rc7:
> > >
> > > | TAP version 14
> > > | 1..1
> > > |     # Subtest: hw_breakpoint
> > > |     1..9
> > > |     ok 1 - test_one_cpu
> > > |     ok 2 - test_many_cpus
> > > |     # test_one_task_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > |     Expected IS_ERR(bp) to be false, but is true
> > > |     not ok 3 - test_one_task_on_all_cpus
> > > |     # test_two_tasks_on_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > |     Expected IS_ERR(bp) to be false, but is true
> > > |     not ok 4 - test_two_tasks_on_all_cpus
> > > |     # test_one_task_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > |     Expected IS_ERR(bp) to be false, but is true
> > > |     not ok 5 - test_one_task_on_one_cpu
> > > |     # test_one_task_mixed: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > |     Expected IS_ERR(bp) to be false, but is true
> > > |     not ok 6 - test_one_task_mixed
> > > |     # test_two_tasks_on_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > |     Expected IS_ERR(bp) to be false, but is true
> > > |     not ok 7 - test_two_tasks_on_one_cpu
> > > |     # test_two_tasks_on_one_all_cpus: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > |     Expected IS_ERR(bp) to be false, but is true
> > > |     not ok 8 - test_two_tasks_on_one_all_cpus
> > > |     # test_task_on_all_and_one_cpu: ASSERTION FAILED at kernel/events/hw_breakpoint_test.c:70
> > > |     Expected IS_ERR(bp) to be false, but is true
> > > |     not ok 9 - test_task_on_all_and_one_cpu
> > > | # hw_breakpoint: pass:2 fail:7 skip:0 total:9
> > > | # Totals: pass:2 fail:7 skip:0 total:9
> > >
> > > ... which seems to be becasue arm64 currently forbids per-task
> > > breakpoints/watchpoints in hw_breakpoint_arch_parse(), where we have:
> > >
> > >         /*
> > >          * Disallow per-task kernel breakpoints since these would
> > >          * complicate the stepping code.
> > >          */
> > >         if (hw->ctrl.privilege == AARCH64_BREAKPOINT_EL1 && bp->hw.target)
> > >                 return -EINVAL;
> > >
> > > ... which has been the case since day one in commit:
> > >
> > >   478fcb2cdb2351dc ("arm64: Debugging support")
> > >
> > > I'm not immediately sure what would be necessary to support per-task kernel
> > > breakpoints, but given a lot of that state is currently per-cpu, I imagine it's
> > > invasive.
> >
> > I would actually like to remove HW_BREAKPOINT completely for arm64 as it
> > doesn't really work and causes problems for other interfaces such as ptrace
> > and kgdb.
> 
> Will it be a localized removal of code that will be easy to revert in
> future? Or will it touch lots of code here and there?
> Let's say we come up with a very important use case for HW_BREAKPOINT
> and will need to make it work on arm64 as well in future.

My (rough) plan is to implement a lower-level abstraction for handling the
underlying hardware resources, so we can layer consumers on top of that
instead of funneling through hw_breakpoint. So if we figure out how to make
bits of hw_breakpoint work on arm64, then it should just go on top.

The main pain point for hw_breakpoint is kernel-side {break,watch}points
and I think there are open design questions about how they should work
on arm64, particularly when considering the interaction with user
watchpoints triggering on uaccess routines and the possibility of hitting
a kernel watchpoint in irq context.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220722101053.GA18284%40willie-the-truck.
