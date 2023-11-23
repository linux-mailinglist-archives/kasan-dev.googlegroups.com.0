Return-Path: <kasan-dev+bncBCMIZB7QWENRBVGR7WVAMGQEZRHW77A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9594D7F622A
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 15:59:34 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-50798a25ebasf604431e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Nov 2023 06:59:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700751574; cv=pass;
        d=google.com; s=arc-20160816;
        b=f0YsbCTbAsUOode+D7OrlQbeu2N1czL0wJRePyr47SMSwj/NMMdRZMz0NeUcZwsKZ1
         /f5Eu425g98HVmliaweRD0IrA45T8vQFLw8E8+2rEm/lETIsXzF+ydgN4686rDc+trgl
         MZwio/pVNk6k7fl/CwaET4kvOVUQRktxNBZFt6FXYEJZxmWPGuGtSNthMGt8epATrmAY
         GrM/FV+uxyZFnu4sRnz3fsM14Gdlq9LLgge1bKffsIrtTGzgJ742m9tMb4rACJ/+yrtE
         GOqx5KH+uyDtBMs/ggMLqnFxNhirrzMJ+I1X2T1tQVpAnRve8ji5Ha3A+T+OlXK3thzp
         SPKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x84Vo7bel6yp20hQOLZ+pHH1hxsgGSRu9B0VYWmJ3Mk=;
        fh=59se6nJDtcYex47OgSMudN5QgKzTg3RchHUAyP7P6Yk=;
        b=LDHAf0x5GTSzuCkz1TJyaCo5GThI3qAzSeTTtRlR9RsKs4xlInAj7diezZ3L2pMe0V
         NkgPRbunclACr9X4ASsjQ/7TRk6pl+AfiMK7lzWWZsH1Um2oDNWSaqqeO5ZMosOg2Rs4
         8FfSCHJxW6EN9yWJanycp8VvNI2s+wYDou5+IR5bw6Ex55F0Ql/DQGoMCKaom9vS4/K8
         8P6r12nSxTHj6G4P3Q2rrju5Y7lS4PtdSkdQ3XR4t/2BXb8GV+C/3EvDwARQhA3vy3QZ
         ++Z3PMwaKgbl2Ap4OibkOvfBSdEUowTHL0dx3z4CZR/PIXblOnV8hbywLiObFet0AQdg
         5m5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eVSjaXjK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700751574; x=1701356374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x84Vo7bel6yp20hQOLZ+pHH1hxsgGSRu9B0VYWmJ3Mk=;
        b=Is5fMgZx/bQmzHpeiw6YchVVuqZrJo2pB5RvdgpnHENyEZJx4sYzccX3xPTFUiM6JU
         8S4JosNIAIRkW8iKx7r7CFQUu/JBfGvQnPfC/uZV6Xya5n6grS1DJAuzESqQMVgIfgiN
         e45FJuSrrmgRj4aKb8Uw6lD5POThmH+qsddGxI/3p75ubtQPjBeYdAZTJ+dtlLeeO5U8
         HD1x/ZCM/JAGyy9rP/uQ+voFJ7fBDZ6GC8SS//xbDGoqPMgOBl+9x7e1lq6333g/bAza
         X8kaV7Oj+5kc9o6E5FZjjKCwt2lnlC0dAfIOwuxRnohmpx0ZPlxIYwtP/r450yGs+f5B
         LYSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700751574; x=1701356374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x84Vo7bel6yp20hQOLZ+pHH1hxsgGSRu9B0VYWmJ3Mk=;
        b=XiHZub6pGtMpGD4PqZuD3IENNfUK7OQf470Lh964qaRZJS0zoulb9rPpYeoPAbqyHH
         SFFYgzy5nVgCIEh1KEZXD7NGV9FTacOTITzdfYA3OSN94jWsqBkrZZF9pgmkXqzPaMXZ
         RcXXhfqHj7mELtNdcWHItOQ6f49PMCmnLJOmDb+UbKd1yq0e6DglznAlcCgDDsGjy2qf
         X39znKcgrw2s9B5LIBofnQ5ZHDiClAi1o2ydSWDGT2B3CLH1WZ40sl11lh+7hdLh1eLK
         nfDLRYHL3pdlLiz6i9ZrpL6morLCfvaBm9P75/rvv2C5SfD8vjXklOUxUj4ZYOKzH0cb
         cHGw==
X-Gm-Message-State: AOJu0Yzx3VW99XZxGvOAyP4U9jJx/XUAMOyTsG14zH4oaNiwPBpUT3Ne
	pD24D1cm4AeNIf1iqKmWCHA=
X-Google-Smtp-Source: AGHT+IHO05oM7zH1C30g16p9t+gaxlk7XfNRTHBu+kxN3/2vGphdoewSBcXRmKWx9RqSh5RPC0rMdA==
X-Received: by 2002:a05:6512:b89:b0:50a:a3a7:488b with SMTP id b9-20020a0565120b8900b0050aa3a7488bmr1183986lfv.18.1700751572637;
        Thu, 23 Nov 2023 06:59:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3da1:b0:507:98a4:993b with SMTP id
 k33-20020a0565123da100b0050798a4993bls67946lfv.1.-pod-prod-00-eu; Thu, 23 Nov
 2023 06:59:31 -0800 (PST)
X-Received: by 2002:a05:6512:e88:b0:50a:a8c1:28ef with SMTP id bi8-20020a0565120e8800b0050aa8c128efmr1076011lfb.18.1700751570545;
        Thu, 23 Nov 2023 06:59:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700751570; cv=none;
        d=google.com; s=arc-20160816;
        b=xfW+uOPIR8zKXp94383YZkkPX2NIJ9zaSmJ+IeceL2zSWBqWoMmcNRCjpCVqIiAEdn
         qI+Bt60uZsoo4P7K+xWeZuRmQomFb0j8aA1MHmHHyI4IBZyfXYgctyxZavQ/Scey3Ego
         iDZ6Tgm5LqFM/ZPOHCRvVPhwvWpPK6aOOEa06r743FBnK8rjQzSQTMfL0dFFo1seokYZ
         c7NzzxNsOWYavx4JVRZYvTEEXa6Mm8ddFWejKlXfLGeY2jx/nOrqz8Pq8VqEcvOoWrWC
         JTAXIaW4m1QIz1Xwa3LzAmlReuDuZ1koNPUgUrDNr3fv8zF1KRUZ7LgATFg6I12hnyjw
         n/ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rjsWntyf3ek48ZMQ86Tl47VHUhxQBToAw1VMl26tGwI=;
        fh=59se6nJDtcYex47OgSMudN5QgKzTg3RchHUAyP7P6Yk=;
        b=LJkjHnYjtxJW1ntL5/1IxpLkAo9GYHVbI9vO8vLczuzchk/swfj0wZhC8cNG43fLtj
         KN9y47ehxpYpMZRjy9NSWBBrxRnNtzap0si19CykUfO17MCr0NdXrZFHDHtN2YwjQHQZ
         6+tf6rypLYBxIIoJ4OkmxHwE5tyLt/ocHRp1AdA/ixFidnchYQJuqNNci/GCiqdWg5XA
         cJtJQdtGtrqQWtyAnwAIOlsdfJ6C3rre2W5eHPnseB9EECV0jso6WNTvuaP9YVVbkh1K
         tD5394BuF7lip8FjuzSk4N4HESUpJw1xo+K6SAn2z3dZ4gMRyFqj2qbCgOL4Ptoe+qSl
         zgcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eVSjaXjK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id f15-20020a05651232cf00b005098ece8aa9si73041lfg.12.2023.11.23.06.59.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Nov 2023 06:59:30 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id 2adb3069b0e04-50aba9b8955so2836e87.1
        for <kasan-dev@googlegroups.com>; Thu, 23 Nov 2023 06:59:30 -0800 (PST)
X-Received: by 2002:a19:ad43:0:b0:504:7b50:ec9a with SMTP id
 s3-20020a19ad43000000b005047b50ec9amr144412lfd.1.1700751569826; Thu, 23 Nov
 2023 06:59:29 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB0752058FAECD2AC1E5E68D7399B3A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+Ya4yTvAmaELJN5st3GJYo1KKzC9qw9sdD0g3jb48O7tg@mail.gmail.com>
 <VI1P193MB075265616010AF82CE201ADD99B1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+ZE8DO1u6NHATXC9tfcVS4diM0LO4r3cQ15HaGHVoFAbQ@mail.gmail.com> <VI1P193MB075296EFE305E5A6C3A4701699B9A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB075296EFE305E5A6C3A4701699B9A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Nov 2023 15:59:17 +0100
Message-ID: <CACT4Y+akBeAOBhyxj4jBmOOS73+yVRJvh0rSXfDV8dt_aAGkwg@mail.gmail.com>
Subject: Re: [RFC PATCH] kasan: Record and report more information
To: Juntong Deng <juntong.deng@outlook.com>, Marco Elver <elver@google.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eVSjaXjK;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130
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

On Thu, 23 Nov 2023 at 11:06, Juntong Deng <juntong.deng@outlook.com> wrote:
>
> On 2023/11/20 19:06, Dmitry Vyukov wrote:
> > On Wed, 15 Nov 2023 at 22:53, Juntong Deng <juntong.deng@outlook.com> wrote:
> >>
> >> On 2023/11/14 15:27, Dmitry Vyukov wrote:
> >>> On Mon, 13 Nov 2023 at 22:17, Juntong Deng <juntong.deng@outlook.com> wrote:
> >>>>
> >>>> Record and report more information to help us find the cause of
> >>>> the bug (for example, bugs caused by subtle race condition).
> >>>>
> >>>> This patch adds recording and showing CPU number and timestamp at
> >>>> allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO), and
> >>>> adds recording and showing timestamp at error occurrence (CPU number
> >>>> is already shown by dump_stack_lvl). The timestamps in the report use
> >>>> the same format and source as printk.
> >>>>
> >>>> In order to record CPU number and timestamp at allocation and free,
> >>>> corresponding members need to be added to the relevant data structures,
> >>>> which may lead to increased memory consumption.
> >>>>
> >>>> In Generic KASAN, members are added to struct kasan_track. Since in
> >>>> most cases, alloc meta is stored in the redzone and free meta is
> >>>> stored in the object or the redzone, memory consumption will not
> >>>> increase much.
> >>>>
> >>>> In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
> >>>> struct kasan_stack_ring_entry. Memory consumption increases as the
> >>>> size of struct kasan_stack_ring_entry increases (this part of the
> >>>> memory is allocated by memblock), but since this is configurable,
> >>>> it is up to the user to choose.
> >>>>
> >>>> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> >>>> ---
> >>>>    lib/Kconfig.kasan      | 11 +++++++++++
> >>>>    mm/kasan/common.c      |  5 +++++
> >>>>    mm/kasan/kasan.h       |  9 +++++++++
> >>>>    mm/kasan/report.c      | 28 ++++++++++++++++++++++------
> >>>>    mm/kasan/report_tags.c | 18 ++++++++++++++++++
> >>>>    mm/kasan/tags.c        | 15 +++++++++++++++
> >>>>    6 files changed, 80 insertions(+), 6 deletions(-)
> >>>>
> >>>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> >>>> index fdca89c05745..d9611564b339 100644
> >>>> --- a/lib/Kconfig.kasan
> >>>> +++ b/lib/Kconfig.kasan
> >>>> @@ -207,4 +207,15 @@ config KASAN_MODULE_TEST
> >>>>             A part of the KASAN test suite that is not integrated with KUnit.
> >>>>             Incompatible with Hardware Tag-Based KASAN.
> >>>>
> >>>> +config KASAN_EXTRA_INFO
> >>>> +       bool "Record and report more information"
> >>>> +       depends on KASAN
> >>>> +       help
> >>>> +         Record and report more information to help us find the cause of
> >>>> +         the bug. The trade-off is potentially increased memory consumption
> >>>> +         (to record more information).
> >>>> +
> >>>> +         Currently the CPU number and timestamp are additionally recorded
> >>>> +         at allocation and free.
> >>>
> >>> Hi Juntong,
> >>>
> >>> Thanks for working on this.
> >>>
> >>
> >>
> >> Thanks for your reply!
> >>
> >>
> >>> As a KASAN developer I understand what this is doing, but I am trying
> >>> to think from a position of a user that does not know details of KASAN
> >>> implementation. From this position it may be useful to say somewhere
> >>> that information is recorded "per heap allocation". Perhaps something
> >>> like:
> >>>
> >>> "Currently the CPU number and timestamp are additionally recorded for
> >>> each heap block at allocation and free time".
> >>
> >>
> >> Yes, I agree, that is a better expression.
> >>
> >>
> >>>
> >>> Also it's unclear what the memory consumption increase is. You say
> >>> "potentially|, so may it not increase at all? If it increases, by how
> >>> much? I obviously want more information, if I can afford it, but I
> >>> can't understand if I can or not based on this description. I would
> >>> assume that this may be a problem only for small/embedded devices.
> >>> Can we provide some ballpark estimation of the memory consumption
> >>> increase? And somehow say that's probably not an issue for larger
> >>> machines?
> >>>
> >>
> >>
> >> How about this expression?
> >>
> >> Currently, in order to record CPU number and timestamp, the data
> >> structure to record allocation and free information will increase
> >> by 12 bytes.
> >>
> >> In Generic KASAN, this affects all allocations less than 32 bytes.
> >> In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
> >> boot parameter increases the memory consumption by
> >> 12 * stack_ring_size bytes.
> >
> > Let's go with this version.
> >
> >
> >>>>    endif # KASAN
> >>>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> >>>> index 256930da578a..7a81566d9d66 100644
> >>>> --- a/mm/kasan/common.c
> >>>> +++ b/mm/kasan/common.c
> >>>> @@ -20,6 +20,7 @@
> >>>>    #include <linux/module.h>
> >>>>    #include <linux/printk.h>
> >>>>    #include <linux/sched.h>
> >>>> +#include <linux/sched/clock.h>
> >>>>    #include <linux/sched/task_stack.h>
> >>>>    #include <linux/slab.h>
> >>>>    #include <linux/stacktrace.h>
> >>>> @@ -50,6 +51,10 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
> >>>>    {
> >>>>           track->pid = current->pid;
> >>>>           track->stack = kasan_save_stack(flags, true);
> >>>> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >>>> +       track->cpu = raw_smp_processor_id();
> >>>> +       track->ts_nsec = local_clock();
> >>>
> >>> What does "local_" mean? Is this clock value comparable across CPUs?
> >>>
> >>
> >>
> >> No, local_clock is the local CPU clock and cannot be used for comparison
> >> across CPUs, I made a mistake here.
> >>
> >> I delved into the clock subsystem of the Linux kernel today and I found
> >> that we have two choices.
> >>
> >> - sched_clock(): based on jiffies, high performance, but on some
> >> hardware, it will drift between CPUs.
> >>
> >> - ktime_get_boot_fast_ns(): based on clocksource, highly accurate,
> >> can be compared between CPUs, but performance is worse (seqlock).
> >>
> >> I tested 100000 calls respectively on my laptop, the average of
> >> sched_clock() is 17ns and the average of ktime_get_boot_fast_ns()
> >> is 25ns.
> >>
> >> ktime_get_boot_fast_ns() takes about 1.5 times as long as sched_clock().
> >>
> >> With Generic KASAN enabled, the average of one memory allocation is
> >> 3512ns on my laptop.
> >>
> >> Personally, I prefer ktime_get_boot_fast_ns() because it is more
> >> accurate and the extra time is insignificant for the time required for
> >> one memory allocation with Generic KASAN enabled.
> >>
> >> But maybe using ktime_get_boot_fast_ns() would have a more serious
> >> impact on small/embedded devices.
> >>
> >> Which do you think is the better choice?
> >
> > I don't have a strong preference.
> >
> > Re drift of sched_clock(), do you mean unsynchronized RDTSC on
> > different cores? I had the impression that RDTSC is synchronized
> > across cores on all recent CPUs/systems.
> >
>
>
> After discussions with Marco Elver, I now think that perhaps continuing
> to use local_clock() is a better option.
>
> The full discussion with Marco Elver can be found at
> https://groups.google.com/g/kasan-dev/c/zmxwYv8wZTg
>
> Because local_clock() is the clock source used by printk and is the
> default clock source for ftrace.
>
> Using local_clock() as the clock source for KASAN reports makes it
> easier to correlate the timestamps of allocations, frees, and errors
> with the timestamps of other events in the system.
>
> This is perhaps more important than being able to accurately compare
> across CPUs.
>
> What do you think?


If other similar tools (kfence, ftrace, printk) use local_clock(),
then it's reasonable to use it in kasan as well.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BakBeAOBhyxj4jBmOOS73%2ByVRJvh0rSXfDV8dt_aAGkwg%40mail.gmail.com.
