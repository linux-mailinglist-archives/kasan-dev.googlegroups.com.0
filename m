Return-Path: <kasan-dev+bncBDV37XP3XYDRB67AXSJAMGQE25GOMHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BF454F8738
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Apr 2022 20:42:04 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id p6-20020a2eb986000000b0024b46246f74sf917378ljp.19
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Apr 2022 11:42:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649356924; cv=pass;
        d=google.com; s=arc-20160816;
        b=tE0+PRraBQmiJvFoQyAGdL0ZkGb9UNEd48UMdCTRpDHok/8gvOg5xiE4U7YrcZ7cnX
         TZAume+9r3d6EGMQpGgKLptD9aYN/CRnAwlUmkxSd8ZROVNIGJwA0uKTNS34If2KHwBv
         poCVGJVYIUN35Vk2WCXs5EJlHYPFrLGFuWvaxEaNNBo79yVfWBv485mTcC68ZbtkZzi4
         9DO3Am2WxGY/4b0vuPAvdjUfb0WwjzzMRYqjXAzezFqLUVKGzS+qqumL6hwfqxm5JVei
         4YKdgZNEriSLZvFrt5jSY53jeuzuO7xfLxphdNZ3eb4UQrOtoJlJ+fnQWuT7bm+Hz0iB
         bDdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MJG9TL/geV/9u7JPOEeIJPhWuy9B+NFn0yMI9Rw8X6U=;
        b=kFF42EY6lYD6A13hhOkSfE1acC6EFpKB/jcECUJi4EW4mALQFHq3q5WoufGpj6NmoI
         A10ybYS1+4unn4e1uUgcYeO0PJdJb9UvrTZaleWhMFsbsCIr+hYoTAKpGDjdT4bQ7K89
         L8T379Jf738+lYErwpsmz+5Ju9K9XseMQXx7LFO8kUqkuQ2gjRvr+nwYCmPV17S8okSW
         VlDHJZTGgjkX8OBMkAKnC5pYSHdQkODWl5M0Hk0DuBYWWxTG67BWO9krqboyIoWzNrRq
         Er9pAoVUFGeDFdaYwwNsRzD5CgkuMuxr1CehRl2KkYZuYxK0w7w6FKTm7oOzry8OfWHQ
         /Ldw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MJG9TL/geV/9u7JPOEeIJPhWuy9B+NFn0yMI9Rw8X6U=;
        b=hv0Y4kmy01XNq//PNrJhLdYiCFte/FqOn89KURyCgMtvZ7bWhL4/EhbgF8BZEqaZqP
         beRANpJafXhyBmqFuu/oBy/PerfpR/aNIQRW240K/52qFJ2fxXt+UOjRFx1VHQko3bkS
         ztbVHhsEwkk5k5E8bpZPARtmiV2PnS7TbeyfL6TkSOvwGnHWjuRQBYjAdl5HwV6oj7ff
         4xCPHNUUrPCxCP0fO4TNm38enKWageiZ1SzULrr8EfjB1LvSQTezj/f8hrkbJNLo3JXB
         8Kpd3tQOaeMndcdukL6wQkaYn7yAmh/6FcMzFfKj/Bijgz7/yaC0q3Qf9ByPvXsGQnfg
         fxdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MJG9TL/geV/9u7JPOEeIJPhWuy9B+NFn0yMI9Rw8X6U=;
        b=aeFWqUr4Z4stBzixzolrHJ9VOjzG1tI5mNDl/heyZxfhVqLmPvhP6JEUKiM3ezG2FC
         O0XxJxwID5B5p2Cb+pCUMJ14RXt+4OlfB17TfsoCMys++tb4mut5BBocL732XSUCbpXh
         6kSFvza4D1HvKc51jRbhwiAiA8pEhDQowW9HRu2OPwo24c4AY836lftI2n2v2cZMT6oG
         4IDbJV8BoG0quNR/KpOv72jd6I8xu03xLiulhAWr40T2rSsuoA/V67bNs/btDbVNAthI
         BZbUzWVfPYWrfHhv6O+DCfebK+4XAty96yfwdgm8u1q6RDzoF7/L4XZ6B5BjjjoLfns/
         8ufA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310iFlDkLFRu9w+CFsu+gHobQOaTWKfRM7mDA9zXOjJ57B51ZJh
	UJ2ChjevYDtdfoEPgJhlk94=
X-Google-Smtp-Source: ABdhPJzJCCiwccH0nfyJsnQruofzTNNFL+IkxWBSfJ11wLmITnUIhLJ0qWnff4Uqly7RmUT0ScsIbA==
X-Received: by 2002:a05:6512:690:b0:44a:351f:9ff5 with SMTP id t16-20020a056512069000b0044a351f9ff5mr10290509lfe.385.1649356923917;
        Thu, 07 Apr 2022 11:42:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:740c:0:b0:249:9fdc:a3b6 with SMTP id p12-20020a2e740c000000b002499fdca3b6ls752799ljc.4.gmail;
 Thu, 07 Apr 2022 11:42:02 -0700 (PDT)
X-Received: by 2002:a05:651c:10a5:b0:24b:4c15:2741 with SMTP id k5-20020a05651c10a500b0024b4c152741mr727157ljn.510.1649356922428;
        Thu, 07 Apr 2022 11:42:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649356922; cv=none;
        d=google.com; s=arc-20160816;
        b=SAor+hhGsKwlQpZNik9VjmbFubEkrW7qRgyv/yQP/xjtRjVB0Xl90Auy0nDBF+0zlZ
         WJJntCPCeebs3N48ty2W0oYWtldAwmvWSw1EUIBDJZg7M0cRVA6i7UUtfj3wjhKF2D7P
         M0318IDYhFBe+szqqUkD6vRMRcvM16vuH2HGx8Mqw5urQ6V0BSq1DTnl0KkzPRMDCmRd
         VhYmT9DnZ2/VX3gnA6XcQfh/gLN6amssujmHTZpCgJeGUXEgLqgOG0NFP44WTM474Rqo
         20n+RZ9ODg46jC29o4iGd9tQRi35APkA9XxLkjrvQmXcHv6VXkmaFJQVQtFyH9PwQYeg
         vdqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=63Tazlq1+era2r+9N80UOtlsAQrD5K7jRU560S7GQ6I=;
        b=uJzeJDa092qhBsMQM+ZzCc6XlwHLu9ia54GIGiF1PSo9thWOODdDe/8fmhiETWK9bv
         7sJ+3ZlJRU/Xgl96VmUuPaDprYFnB/pzQaOqUyrIegm3EG2UlBcan7FHg1FZAh3xJetK
         18rp/o6R560+q+oC7lD9yHv2mF9K17KzUFbxR74ePw8e1S96tBHc0+PMmURkdILElVnV
         +b4/Lbg/K6mh4piVW+WdBF3+Z+6vqKfqt/6UQ3uUftmMFSoreYK6Yc9C2vt4Y3Eucvd1
         D2jx8mU2Y3Lp8mmdw0O71WdhQVdrZmwyacEKyKobPz1JLiGoNFNZV0nqPXyjgZuJY3lE
         ZeOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f43-20020a0565123b2b00b0044ada59207esi871524lfv.12.2022.04.07.11.42.01
        for <kasan-dev@googlegroups.com>;
        Thu, 07 Apr 2022 11:42:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D571D12FC;
	Thu,  7 Apr 2022 11:42:00 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.7.113])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 379703F718;
	Thu,  7 Apr 2022 11:41:58 -0700 (PDT)
Date: Thu, 7 Apr 2022 19:41:51 +0100
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
Message-ID: <Yk8wbx7/4+9pMLGE@FVFF77S0Q05N>
References: <cover.1648049113.git.andreyknvl@google.com>
 <YkV6QG+VtO7b0H7g@FVFF77S0Q05N>
 <YkWg5dCulxknhyZn@FVFF77S0Q05N>
 <CA+fCnZeQ6UnpM9qEQ4q5Y95U3XVwrsD-g7OX=Qxr1U1OR_KCsQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZeQ6UnpM9qEQ4q5Y95U3XVwrsD-g7OX=Qxr1U1OR_KCsQ@mail.gmail.com>
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

On Tue, Apr 05, 2022 at 05:10:02PM +0200, Andrey Konovalov wrote:
> On Thu, Mar 31, 2022 at 2:39 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > I've had a quick look into this, to see what we could do to improve the regular
> > unwinder, but I can't reproduce that 30% number.
> >
> > In local testing the worst can I could get to was 6-13% (with both the
> > stacktrace *and* stackdepot logic hacked out entirely).
> >
> > I'm testing with clang 13.0.0 from the llvm.org binary releases, with defconfig
> > + SHADOW_CALL_STACK + KASAN_<option>, using a very recent snapshot of mainline
> > (commit d888c83fcec75194a8a48ccd283953bdba7b2550). I'm booting a
> > KVM-accelerated QEMU VM on ThunderX2 with "init=/sbin/reboot -- -f" in the
> > kernel bootargs, timing the whole run from the outside with "perf stat --null".
> >
> > The 6% figure is if I count boot as a whole including VM startup and teardown
> > (i.e. an under-estimate of the proportion), the 13% figure is if I subtract a
> > baseline timing from a run without KASAN (i.e. an over-estimate of the
> > proportion).
> 
> I think this is the reason for the limited improvement that you
> observe. If you measure the time throughout VM startup and teardown,
> you include the time required for userspace apps, which is irrelevant.

Yes, that's the case for the 6% figure. However I also mentioned how I
accounted for that to get the 13% figure, which does not include those
irrelevant timings (and is an over-estimate of that proportion).

I think the discrepancy lies elsewhere, e.g. kernel version, boot arguments,
platform (and hence driver / subsystem behaviour), etc.

Can you share any of those details? Are you able to test with a mainline
kernel, e.g. v5.18-rc1?

I have a bunch of numbers below, and I think those imply one of the following:

* In your test setup, there are significantly more allocs/frees for which a
  stacktrace is being recorded. That could be down to the platform you're
  testing on, and the drivers that are in use.

* In your test setup, for some reason, some aspect of the stacktrace is
  signficantly more expensive than in my setup. There's the potential that a
  hardware quirk has some impact here, so knowing which hardware you're testing
  on would be very helpful.

* There is a secondary effect at play. There are a number of potential things
  here (e.g. console accesses, the number of stacktraces taken in interrupt
  context, etc).

I'd like to figure out which (if any) of those apply.

> I measure boot time until a certain point during kernel boot. E.g.,
> with the attached config, I measure the time until test_meminit start
> running.

How exactly are you measuring the point at which test_meminit() starts running?
Are you looking through dmesg, or passing some debug options? I ask because
that doesn't seem to dump anything into dmesg until at least one test has run.

FWIW, I was measuring the kernel boot up-to the point we'd run the userspace
init program, by booting the kernel with:

	init=/sbin/reboot -- -f

... which I think is more representative of the full boot time.

I can instead avoid that by not passing a filesystem and booting with:

	panic=-1

... to trigger an instant reboot when we'd normally mount the filesystem, but
the numbers as similar either way for me.

I've followed the latter approach for my numbers below, since it's easier to
reproduce.

> It takes 6 seconds for the kernel to reach test_meminit as is, and 4
> seconds with kasan_save_stack() commented out. Only commenting out
> __stack_depot_save() gives 5.9 seconds, so stack_trace_save() is the
> slow part.

As above, how are you measuring this?

... and since your config has CONFIG_KASAN_KUNIT_TEST=y, which console
options (e.g. 'quiet', 'loglevel=') are you passing on the kernel command line?

I ask because in my local testing, that options results in a load of test
results being dumped to the console, and the time taken to do so dominates
everything else. Hacking out the stack sampling reduces the amount of data we
log to the console, and this secondary effect reduces boot time.

> > Could you let me know how you're measuring this, and which platform+config
> > you're using?
> 
> I've attached the config that I use. It's essentially defconfig + SCS
> + KASAN + maybe a few other options.
> 
> > I'll have a play with some configs in case there's a pathological
> > configuration, but if you could let me know how/what you're testing that'd be a
> > great help.

I'm afraid from local testing (atop v5.18-rc1), with your config, I still can't
get anywhere near your figures. I've tried to match toolchain versions with
what was in your .config file, so I'm using clang 12.0.0 from the llvm.org
binary releases, and binutils from the kernel.org crosstool 11.1.0 release.

I took baselines with defconfig and defconfig + SHADOW_CALL_STACK, with console
output completely suppressed with 'quiet loglevel=0':

| [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-defconfig/Image               
| 
|  Performance counter stats for
|  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
|  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
|  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-defconfig/Image -append
|  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
| 
|        0.512626031 seconds time elapsed                                          ( +-  0.26% )
| 
| [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-defconfig+scs/Image
| 
|  Performance counter stats for
|  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
|  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
|  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-defconfig+scs/Image -append
|  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
| 
|        0.523245952 seconds time elapsed                                          ( +-  0.18% )

Then I tried the same with your config, without your patches:

| [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image
| 
|  Performance counter stats for
|  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
|  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
|  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image -append
|  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
| 
|        1.994692366 seconds time elapsed                                          ( +-  0.05% )

Then with your config, without your patches, with the stacktrace hacked out:

| [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image            
| 
|  Performance counter stats for
| '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
| -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
| /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image
| -append loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
| 
|        1.861823869 seconds time elapsed                                          ( +-  0.05% )

If I use those number to estimate the proportion of time spent stacktracing,
with the baseline SCS number discounted to remove the hypervisor+VMM overheads,
I get:

	(1.994692366 - 0.523245952) - (1.861823869 - 0.523245952)
        ---------------------------------------------------------  = 0.09029788358
	(1.994692366 - 0.523245952)

So roughly 9% when I try to maximize that figure. When actually poking hardware
and doing real work, that figure goes down. For example, if just using "quiet":

| [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image > /dev/null
| 
|  Performance counter stats for
| '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
| -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
| /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image -append
| loglevel=9 earlycon panic=-1 quiet' (50 runs):
| 
|        4.653286475 seconds time elapsed                                          ( +-  0.06% )

| [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image > /dev/null
| 
|  Performance counter stats for
|  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
|  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
|  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image
|  -append loglevel=9 earlycon panic=-1 quiet' (50 runs):
| 
|        4.585750154 seconds time elapsed                                          ( +-  0.05% )

Which gives an estimate of:

	(4.653286475 - 0.523245952) - (4.585750154 - 0.523245952)
	---------------------------------------------------------  = 0.01635245964
	(4.653286475 - 0.523245952)

... or ~1.6% time spent backtracing:

FWIW, applying your patches do show some benefit, but not as drastic as I was
expecting:

With console output suprressed:

| [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image               
| 
|  Performance counter stats for
| '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
| -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
| /home/mark/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image
| -append loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
| 
|        1.920300410 seconds time elapsed                                          ( +-  0.05% )

... down from ~9% to ~4%

With console output merely reduced:

| [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image > /dev/null
| 
|  Performance counter stats for
| '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
| -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
| /home/mark/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image
| -append loglevel=9 earlycon panic=-1 quiet' (50 runs):
| 
|        4.611277833 seconds time elapsed                                          ( +-  0.04% )

... down from 1.6% to 0.6%

Given the above I still think we need to understand this a bit better before we
consider pursuing the SCS unwinder, given the issues I laid out in my prior mails.

My hope is that we can improve the regular unwinder or other code such that
this becomes moot. I'm aware of a few things we could try, but given it's very
easy to sink a lot of time and effort into this, I'd like to first get some
more details, as above.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yk8wbx7/4%2B9pMLGE%40FVFF77S0Q05N.
