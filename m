Return-Path: <kasan-dev+bncBDV37XP3XYDRBBEO36JAMGQECZG3NOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E23B3500683
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 09:02:29 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id x36-20020a056512132400b0044b07b24746sf1957057lfu.8
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 00:02:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649919749; cv=pass;
        d=google.com; s=arc-20160816;
        b=v9aN/fUjh6AVm4CPkROEniU+8Hob0GZICOuU6ot2F03KuMyfKUyZMMpaQind/ltsIo
         sc7unAwkG0bkMGO1FLF/8+BFy2poYktuUDiKjLdpJMXtXNMMg1JwTFjsgnBTNqDJyK2n
         VOnjaNuuHzjf0fYyIPFK+N5kaWVGHsU1w4WRUdi5QFKpetGT5O+nutK8BojycE1EHwsa
         lRLSiFSJbT+DrJga6D5BauscYvExdFXNf4TC/Uc6tyQ0+9uOrLD6s4MyrJK4FHh9dSs+
         d4RV15eZ8rgvzACe+aDcHixDbygDc5sHZlN+5McfCvEFk6/f81f1TQ9Bmfkn1IZPQr6d
         bL7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TMTDY9wyqCG8prNLZ/5AM5s+5CG9H/QYAdQmmzHw2xA=;
        b=m1z+k/b5DCWS3JY3tf1xafuS4A2WQG++GtZhybC5SE3nQYtW4LkC95vcEBPg3zywCd
         W5IzJQWcq5VF+W/S4j8BvaAmDQE+XKnL+OHpjaigAwSONmXT8cl7dykkpaVSF2iBHtUd
         klg1/0sTPfVZFdGxSC6MGkbr+hotg2mSxK2asoLdSWf2Rqr9kayL6a6UqlrhRK6aAVdJ
         Aqz7Jn7ErrgUk2+0Q8RncuV/Jg7irnmFUPJPOZefBzxPnzOJ+QZq5Z0EjwUZruL0p+v7
         blXjbrtQqofMOI1J728SW0xDykpWAESiAwdMZGrMUoTQZ4j6CJ8EznO/1fgCTnDj1ItI
         fBdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TMTDY9wyqCG8prNLZ/5AM5s+5CG9H/QYAdQmmzHw2xA=;
        b=Eql0u5yaaNKRQdn0JTyNrG+jlHKufHoUvkh8olxwUjlixIE2WtRQ/WEdXFG1qN8ex/
         pFoFqj48s78Q/o74fnKcJD8FxDuMM2mJbtefLZxC7xANBw04FudNl+m+7TQg/3PAJhk1
         AV5y7+bVAPtVT3zDvgq7SoqKop7UyPqYJLF5GT+BBDRWe1WYbE2sPXLG+Cwsig/cMLgS
         82EcbTMpwm6aAIG30kUm+/i2YaOD+qduOwrAwZm+hnthJbQEI5lXdAOVVMwGoCMMK5pY
         d0gSb4DwMmy9Un6+WlhvTUBzMORSb7Hobdv9SQPmDwLA1Nk0iCVIRRez9Ld1nllDy3Fq
         qKKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TMTDY9wyqCG8prNLZ/5AM5s+5CG9H/QYAdQmmzHw2xA=;
        b=DRkJUYMUYcEXfkSetMqeqm2xDG2HqsFy+t5Z+Zzl0FdmR51JX5ImPdzhiDrNWoXFUO
         DCFXcZKcao7934dmfwlocTE3JNpHj5KI2FB9cNIXmMBqqtKTQG6kAaIrboPDNqdrLVfh
         UrAsuj8T6rzQSadXJZ3E99acjsLM3jt1l8ISMph6xbnwaP5fVaeFSAxsnpEP7Gj9Y+JY
         xUBMJ+pVQSQbGU/cho02YmEpX63UjUzIWQ5WFz8b940wGRuM8tQuf7vBhjTKo58vhfMv
         u2ancCzQqoS25nJ7rIoeJqcjP7CF+kuxsGilZgcZbMqe4fJfy9Cx1fSIjDAEQokE/tWb
         N39w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530tPji0vt/hUrhqLqM03cvDkHoT54PS5UUYggaMqps3naXgAghb
	a1648tLrrfE5jM801+25i/U=
X-Google-Smtp-Source: ABdhPJx5PG/LcZ8F6KfyfZOEORPsT5hlvk9IfSRjuQci4HXA/yJiMa1Os4GwswjMHVGu4KFC2NbgQg==
X-Received: by 2002:ac2:4e0c:0:b0:44a:3260:e35d with SMTP id e12-20020ac24e0c000000b0044a3260e35dmr1061744lfr.104.1649919748720;
        Thu, 14 Apr 2022 00:02:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5285:0:b0:44a:94d2:1d8f with SMTP id q5-20020ac25285000000b0044a94d21d8fls3773788lfm.0.gmail;
 Thu, 14 Apr 2022 00:02:27 -0700 (PDT)
X-Received: by 2002:a05:6512:b02:b0:44a:a859:426c with SMTP id w2-20020a0565120b0200b0044aa859426cmr1056067lfu.44.1649919747294;
        Thu, 14 Apr 2022 00:02:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649919747; cv=none;
        d=google.com; s=arc-20160816;
        b=CKZlm1BHeUDjHzII5vGM0vRQoiujvDs1oxJWzaaI6LwoMDlHKaq5QRN10ePQcTsg6Z
         sHpSl1sOrtjKj5K/pMR65As3FAsZ1TwZdG9eqjsEXdkXrMtJ2UfVCMJXadKrVE7D94Zn
         i86wCRew7wrkm5skaxdxV2CB7C2l5g6l8d3r8mBJhVPBlnw7eqPGUN6x/lg/kB/G4sfo
         Iz6BgZ4c7Z9tPIFKw376qT5paJyXu1fs9ZLE5EoI8JqIzSZvDMgZqRdGo67qrfFj1Rzf
         nracWndJl6cDC0PgD0oWleeuULxSF9UzGbn2saaXlK65I7ZPMsi1Y2iI9s4WSDQsBE6Z
         eO7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=7325qqMNL+kiKx4uvLlpmxpWnkspbhRJpTxUJRe84oQ=;
        b=VmM4qKU0sCreZ1dgeYn9enhRlJmJVIj4K7ZIFpHVAuCNC0G9LlVvVIa/ns+nFwY9G6
         hc6kO076H9Fyf8Q3anIVIWJDnV3SImrXBY0m4UthLmOXmxCcn5ujVh1NrSzEn8xmSQsS
         J1DhAH1GUIAu8XpnYSGlEKN7pwlj7Pt5EbRsgtzwAU5pDx/5PXiDCy/k3LX5J5USmyow
         rAC1u1HLQ3qAnS1zqB7rymnF869DdAW+NtphS7vfQ3+njo3BNQx2P3mLoPKZ9v9cGZ2M
         /oIpkF7xEVYPzJ6bkpnTgNGLdnR2rwey4FiJEYkw0VT0nLkz/XEVTpf+g/w7Iil4bBbs
         mynw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e10-20020a2e818a000000b0024c7f087105si221836ljg.8.2022.04.14.00.02.27
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Apr 2022 00:02:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 15C35139F;
	Thu, 14 Apr 2022 00:02:26 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.73.251])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3444A3F70D;
	Thu, 14 Apr 2022 00:02:23 -0700 (PDT)
Date: Thu, 14 Apr 2022 08:02:16 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack
 traces from Shadow Call Stack
Message-ID: <YlfG+LJPz1gRWWUI@FVFF77S0Q05N>
References: <cover.1648049113.git.andreyknvl@google.com>
 <YkV6QG+VtO7b0H7g@FVFF77S0Q05N>
 <YkWg5dCulxknhyZn@FVFF77S0Q05N>
 <CA+fCnZeQ6UnpM9qEQ4q5Y95U3XVwrsD-g7OX=Qxr1U1OR_KCsQ@mail.gmail.com>
 <Yk8wbx7/4+9pMLGE@FVFF77S0Q05N>
 <CA+fCnZcv6PtR5eT-hbJ54hkH7Kr+CUM4DU2S5nbU4Lp2OnG8dQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZcv6PtR5eT-hbJ54hkH7Kr+CUM4DU2S5nbU4Lp2OnG8dQ@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Apr 13, 2022 at 09:28:00PM +0200, Andrey Konovalov wrote:
> On Thu, Apr 7, 2022 at 8:42 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > I'm afraid from local testing (atop v5.18-rc1), with your config, I still can't
> > get anywhere near your figures. I've tried to match toolchain versions with
> > what was in your .config file, so I'm using clang 12.0.0 from the llvm.org
> > binary releases, and binutils from the kernel.org crosstool 11.1.0 release.
> >
> > I took baselines with defconfig and defconfig + SHADOW_CALL_STACK, with console
> > output completely suppressed with 'quiet loglevel=0':
> >
> > | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-defconfig/Image
> > |
> > |  Performance counter stats for
> > |  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> > |  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> > |  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-defconfig/Image -append
> > |  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> > |
> > |        0.512626031 seconds time elapsed                                          ( +-  0.26% )
> > |
> > | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-defconfig+scs/Image
> > |
> > |  Performance counter stats for
> > |  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> > |  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> > |  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-defconfig+scs/Image -append
> > |  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> > |
> > |        0.523245952 seconds time elapsed                                          ( +-  0.18% )
> >
> > Then I tried the same with your config, without your patches:
> >
> > | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image
> > |
> > |  Performance counter stats for
> > |  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> > |  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> > |  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image -append
> > |  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> > |
> > |        1.994692366 seconds time elapsed                                          ( +-  0.05% )
> >
> > Then with your config, without your patches, with the stacktrace hacked out:
> >
> > | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image
> > |
> > |  Performance counter stats for
> > | '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> > | -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> > | /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image
> > | -append loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> > |
> > |        1.861823869 seconds time elapsed                                          ( +-  0.05% )
> >
> > If I use those number to estimate the proportion of time spent stacktracing,
> > with the baseline SCS number discounted to remove the hypervisor+VMM overheads,
> > I get:
> >
> >         (1.994692366 - 0.523245952) - (1.861823869 - 0.523245952)
> >         ---------------------------------------------------------  = 0.09029788358
> >         (1.994692366 - 0.523245952)
> >
> > So roughly 9% when I try to maximize that figure. When actually poking hardware
> > and doing real work, that figure goes down. For example, if just using "quiet":
> >
> > | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image > /dev/null
> > |
> > |  Performance counter stats for
> > | '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> > | -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> > | /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image -append
> > | loglevel=9 earlycon panic=-1 quiet' (50 runs):
> > |
> > |        4.653286475 seconds time elapsed                                          ( +-  0.06% )
> >
> > | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image > /dev/null
> > |
> > |  Performance counter stats for
> > |  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> > |  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> > |  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image
> > |  -append loglevel=9 earlycon panic=-1 quiet' (50 runs):
> > |
> > |        4.585750154 seconds time elapsed                                          ( +-  0.05% )
> >
> > Which gives an estimate of:
> >
> >         (4.653286475 - 0.523245952) - (4.585750154 - 0.523245952)
> >         ---------------------------------------------------------  = 0.01635245964
> >         (4.653286475 - 0.523245952)
> >
> > ... or ~1.6% time spent backtracing:
> >
> > FWIW, applying your patches do show some benefit, but not as drastic as I was
> > expecting:
> >
> > With console output suprressed:
> >
> > | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image
> > |
> > |  Performance counter stats for
> > | '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> > | -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> > | /home/mark/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image
> > | -append loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> > |
> > |        1.920300410 seconds time elapsed                                          ( +-  0.05% )
> >
> > ... down from ~9% to ~4%
> >
> > With console output merely reduced:
> >
> > | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image > /dev/null
> > |
> > |  Performance counter stats for
> > | '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> > | -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> > | /home/mark/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image
> > | -append loglevel=9 earlycon panic=-1 quiet' (50 runs):
> > |
> > |        4.611277833 seconds time elapsed                                          ( +-  0.04% )
> >
> > ... down from 1.6% to 0.6%
> >
> > Given the above I still think we need to understand this a bit better before we
> > consider pursuing the SCS unwinder, given the issues I laid out in my prior mails.
> >
> > My hope is that we can improve the regular unwinder or other code such that
> > this becomes moot. I'm aware of a few things we could try, but given it's very
> > easy to sink a lot of time and effort into this, I'd like to first get some
> > more details, as above.
> 
> Hi Mark,
> 
> I'm about to publish v3, where I'll include a detailed description of
> how I measured the performance.
> 
> Perhaps we see different performance numbers because you're using
> KVM-enabled VM on an Arm host and I'm using QEMU on x86-64 host.

Hold on; are you using QEMU in TCG mode? If so that's in no way representative
of real HW performance, and there are operations it simply cannot make as fast
as HW can (e.g. pointer authentication using the architected QARMA variants).

> Although, it's suspicious that the difference is so drastic.

I'm not surprised at all. Some operations can be *orders of magnitude slower*
under TCG than on real HW even when considered relative to other operations,
and this can drasticaly skew benchmarks. We recently hit a case when PACIASP
and AUTIASP were so slow under TCG mode they appeared to be causing a boot
hang, and we eventually figured out that they were just *very* slow, adding
minutes to the boot time. Richard Henderson added options to QEMU to mitigate
that (either disabling authentication, or using an IMPLEMENTATION DEFINED
algorithm).

The bottom line is that QEMU TCG mode is in no way representative of real-world
performance, and *cannot* be used for benchmarking.

I think we first need to understand *what* is so slow under QEMU TCG mode, and
*why* TCG mode performance matters. I suspect there are other ways we could
avoid this overhead *without* adding another unwinder, but even then we need a
justification for *why* we should care.

> I'll try to get my hands on some Arm hardware in the next few days and do the
> measurements there.
> 
> This new version also will not be making any changes to the entry
> code, as these changes add unwanted additional slowdown. That would be
> great, if you could check the performance impact of v3 with your
> setup.

I'll take a look at the series, but as before I do not think we should add
another unwinder. As above, I *certainly* do not think we should add another
unwinder based on TCG performance.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YlfG%2BLJPz1gRWWUI%40FVFF77S0Q05N.
