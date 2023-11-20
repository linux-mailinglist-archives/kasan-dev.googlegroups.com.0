Return-Path: <kasan-dev+bncBCMIZB7QWENRBY735SVAMGQETM7TZII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id BB2967F114E
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 12:07:16 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-32de9f93148sf2265097f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 03:07:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700478436; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQPgVJNl1RI813kv0+r/w1wbIv0w1pZQ3KY8bIy22LYjx1G8OV4n38BPS1tQCkoPTe
         EIuTn76L1Pcy06P70xTN+YjjnSMl52zPa6bZScd+fNafNo40lOQCVqzQbLfiR0bODVeZ
         XV2P3eVP2m1gULptscs2J6qxcyasnUlMVzK0/BOe2n3sSZsv7emjxXJpO12gteUwx/qN
         J2+vX6GQp0eP6xkHVJ1zpAOvJoTspnZCX+iMnpC1AcuiNB9p/dLe3rwve42p8XmqfpPy
         rWgzkRifJALMjV+8Lq2Ztg1k/nn/RyPAHAeoOzryYZtxggWJE8PUig/cF1Fp8JDFBmvK
         /xeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LF1c/TOZ8R5sqwSIfj2cRYDKyX0aGNPUX50nSIrL7zk=;
        fh=Cxdz3lXx9q85yacnGVuiIilAYWk/9KO8DtHEl0n0w48=;
        b=JlQ/hPC/BlVgfrJBW8I9qmzRjUG0m8d9NJbd0Ewi7LP5htzK8Jl2dN/Qi5Ko1tFJVh
         LjiIiGE1HvPIkLYXYXzXu8HqtqFvrW5FT9P86kD9zpN/OiEBivrA9Sq/GzNReMBbPX5G
         HbmONSbQ3gNHv1LGn1QBG2YkO1WZGpJwB7HjW6lgOFuS+fjvQo9s6QeMagJGbU9rVPMP
         95Uoqp22oUemUKrH2r+21y8GN0BDPdO5RTN03r/yQDwGaCKMrHBIm5PtN6Sug6VNlBmi
         Vg372+NJpi2OZpttDgFwnj3s57PfFL6w8ZZSLdIsG9U+47yQCIL1XVUKdXD0Vutf/TkA
         fliA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KczjqEDe;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700478436; x=1701083236; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LF1c/TOZ8R5sqwSIfj2cRYDKyX0aGNPUX50nSIrL7zk=;
        b=JZC9W9ntj+sX3nHPC3EKakaoaGqjry5X9JvpNSDNQvmlhFU7QnVE3rhcGWmE/cLtMN
         3JiedMXm7M0Sb0e8hji1fIeEpOEZ9oWFShyzCyg3fiT7tLiAugcjEtssRcnN1IWfbbgo
         /ocd+1dE5mOa32VE4BmTSfc6wD7j7ccNlF4E/foDJqgEf3380FQ9GDgps9gCTOkSuQ8Z
         koP/pVLpgMTzQ8jpnlrcaZ96dP6uMQEY1iBZY/s3bB1nTkmZUHM9suRdvR27btSuTyIr
         PVojchXCHlQ/oZSLL/GYZhQEM6a6GyG0yUaGIBHV3AL4HWH40BdvSl6SotTsYhPDug5l
         DiVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700478436; x=1701083236;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LF1c/TOZ8R5sqwSIfj2cRYDKyX0aGNPUX50nSIrL7zk=;
        b=Q8lgmdbCWVHmL+coudaf4eJ7hYPKudVR8EY+P6M19DrbtjTGCMSvV7YkBVqqbx6aqV
         M7Qdz8VNhhRB8kTdRkhqznMs/vver/hI5zP7525EKoDaPH2ILV0X1Hprj7vYAiMLKmoX
         ALLjuIfQQ5lz2qVd9Ai6cM52z/UgI6Yqbc6ZJfkIKwA0+oNKZ7pdC9w8/QJMnyxrgACY
         Ef4+GXS11//o/zB2a7Ot/aAwBEMdGj0wEn/rCbtN4m3GZwAkB8HBvolJVicPD/GFA9fm
         cSBtsFld3aAswD8xLM0C8LS/V8bO3reAskBhAxnHLbC3AND72GUM2aiH2qB7L6bu/iZs
         6t/w==
X-Gm-Message-State: AOJu0Yxz0Lnyw2nkq1lb6o2k8/fnvD26A+0RZx19uub/PS0YbEcfggJd
	tNZTEBSGOtb0ryWhN4086E4=
X-Google-Smtp-Source: AGHT+IESQIxowmv1Nvxri9AeIAh8lfXDYuGSF4iq79bIPODx6uugra9Ot8xIZfUU33S8MdhZXSVC9g==
X-Received: by 2002:adf:f550:0:b0:32f:7fe2:59f with SMTP id j16-20020adff550000000b0032f7fe2059fmr4794103wrp.50.1700478435598;
        Mon, 20 Nov 2023 03:07:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1752:b0:32f:94a5:5738 with SMTP id
 m18-20020a056000175200b0032f94a55738ls1519280wrf.0.-pod-prod-05-eu; Mon, 20
 Nov 2023 03:07:14 -0800 (PST)
X-Received: by 2002:a05:600c:4692:b0:406:5463:3f51 with SMTP id p18-20020a05600c469200b0040654633f51mr5485946wmo.25.1700478433591;
        Mon, 20 Nov 2023 03:07:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700478433; cv=none;
        d=google.com; s=arc-20160816;
        b=P4JSX4/KMdRVrRYzZ0zeJ/nqVVIBNUR+UP6h0WEauGuGLTeznvalLleCzbZ3XJbibA
         ZG0oiaz8Yd1XqxfD2wH9nygJF1EMX7no+T/3a/U3e/5sHE2KvqhGBJ7g8Cf2S/TmYCOt
         YzyUC+c5Z+cPiWdwXhLNavE4Wa4Pu9ebTU2ZEVtTkCuI08Ft19gcIW2Fi+eQGJoGEm60
         2hlnFP6sHmcz+mzgt2DVHkF1ZRGvrOl/7z70ro1WVGJI2Mj5Qey1iq3iKIYYrmuvOiS5
         OjDzRXfXdORJNKUvjEYLGr301DeGnfS3zbzaDiDLg8Fxc+DtG2+A1HTjRrvJiVpLyOz+
         zojQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9X1lEHhnslF3qD6Jz9mSyrwZQeP6F/9h+Bwg9+ejQE4=;
        fh=Cxdz3lXx9q85yacnGVuiIilAYWk/9KO8DtHEl0n0w48=;
        b=Am0lxzyt3/8/AldBdMzIwGFe94zAiKqRH8GbrPr01qWEuUqZBGLvKqY/nbIYkMXwm7
         citwej0EpCmR/yB84XN2XJZFJqUoGWqc8tuc2HocOpjknYOnaiWUI3beK/oglRhv9Coe
         nYlRx2fIQl418ybEDob1nQA9OFVoGa6bppHtSgMK8Tugcrr9ynnKCSJig9rZonjR4h8r
         R6y9PW7m1qOth5tPvFTh/XxFpCKvUSuUy409wpceQhaKuY0PrQTojxOYZHh74JR9XK8s
         tEwpb12F738DdZTHExEuaG5tdsERC6EtjwWfrsSsIPAv26SSFsoNaQGMwCEhOBlh7FFQ
         sONA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KczjqEDe;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id bg22-20020a05600c3c9600b0040a25ec1ce5si667881wmb.0.2023.11.20.03.07.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Nov 2023 03:07:13 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-548db776f6cso3145a12.1
        for <kasan-dev@googlegroups.com>; Mon, 20 Nov 2023 03:07:13 -0800 (PST)
X-Received: by 2002:a05:6402:3886:b0:543:fb17:1a8 with SMTP id
 fd6-20020a056402388600b00543fb1701a8mr399270edb.3.1700478432861; Mon, 20 Nov
 2023 03:07:12 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB0752058FAECD2AC1E5E68D7399B3A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+Ya4yTvAmaELJN5st3GJYo1KKzC9qw9sdD0g3jb48O7tg@mail.gmail.com> <VI1P193MB075265616010AF82CE201ADD99B1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB075265616010AF82CE201ADD99B1A@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Nov 2023 12:06:56 +0100
Message-ID: <CACT4Y+ZE8DO1u6NHATXC9tfcVS4diM0LO4r3cQ15HaGHVoFAbQ@mail.gmail.com>
Subject: Re: [RFC PATCH] kasan: Record and report more information
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=KczjqEDe;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::52e
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

On Wed, 15 Nov 2023 at 22:53, Juntong Deng <juntong.deng@outlook.com> wrote:
>
> On 2023/11/14 15:27, Dmitry Vyukov wrote:
> > On Mon, 13 Nov 2023 at 22:17, Juntong Deng <juntong.deng@outlook.com> wrote:
> >>
> >> Record and report more information to help us find the cause of
> >> the bug (for example, bugs caused by subtle race condition).
> >>
> >> This patch adds recording and showing CPU number and timestamp at
> >> allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO), and
> >> adds recording and showing timestamp at error occurrence (CPU number
> >> is already shown by dump_stack_lvl). The timestamps in the report use
> >> the same format and source as printk.
> >>
> >> In order to record CPU number and timestamp at allocation and free,
> >> corresponding members need to be added to the relevant data structures,
> >> which may lead to increased memory consumption.
> >>
> >> In Generic KASAN, members are added to struct kasan_track. Since in
> >> most cases, alloc meta is stored in the redzone and free meta is
> >> stored in the object or the redzone, memory consumption will not
> >> increase much.
> >>
> >> In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
> >> struct kasan_stack_ring_entry. Memory consumption increases as the
> >> size of struct kasan_stack_ring_entry increases (this part of the
> >> memory is allocated by memblock), but since this is configurable,
> >> it is up to the user to choose.
> >>
> >> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> >> ---
> >>   lib/Kconfig.kasan      | 11 +++++++++++
> >>   mm/kasan/common.c      |  5 +++++
> >>   mm/kasan/kasan.h       |  9 +++++++++
> >>   mm/kasan/report.c      | 28 ++++++++++++++++++++++------
> >>   mm/kasan/report_tags.c | 18 ++++++++++++++++++
> >>   mm/kasan/tags.c        | 15 +++++++++++++++
> >>   6 files changed, 80 insertions(+), 6 deletions(-)
> >>
> >> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> >> index fdca89c05745..d9611564b339 100644
> >> --- a/lib/Kconfig.kasan
> >> +++ b/lib/Kconfig.kasan
> >> @@ -207,4 +207,15 @@ config KASAN_MODULE_TEST
> >>            A part of the KASAN test suite that is not integrated with KUnit.
> >>            Incompatible with Hardware Tag-Based KASAN.
> >>
> >> +config KASAN_EXTRA_INFO
> >> +       bool "Record and report more information"
> >> +       depends on KASAN
> >> +       help
> >> +         Record and report more information to help us find the cause of
> >> +         the bug. The trade-off is potentially increased memory consumption
> >> +         (to record more information).
> >> +
> >> +         Currently the CPU number and timestamp are additionally recorded
> >> +         at allocation and free.
> >
> > Hi Juntong,
> >
> > Thanks for working on this.
> >
>
>
> Thanks for your reply!
>
>
> > As a KASAN developer I understand what this is doing, but I am trying
> > to think from a position of a user that does not know details of KASAN
> > implementation. From this position it may be useful to say somewhere
> > that information is recorded "per heap allocation". Perhaps something
> > like:
> >
> > "Currently the CPU number and timestamp are additionally recorded for
> > each heap block at allocation and free time".
>
>
> Yes, I agree, that is a better expression.
>
>
> >
> > Also it's unclear what the memory consumption increase is. You say
> > "potentially|, so may it not increase at all? If it increases, by how
> > much? I obviously want more information, if I can afford it, but I
> > can't understand if I can or not based on this description. I would
> > assume that this may be a problem only for small/embedded devices.
> > Can we provide some ballpark estimation of the memory consumption
> > increase? And somehow say that's probably not an issue for larger
> > machines?
> >
>
>
> How about this expression?
>
> Currently, in order to record CPU number and timestamp, the data
> structure to record allocation and free information will increase
> by 12 bytes.
>
> In Generic KASAN, this affects all allocations less than 32 bytes.
> In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
> boot parameter increases the memory consumption by
> 12 * stack_ring_size bytes.

Let's go with this version.


> >>   endif # KASAN
> >> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> >> index 256930da578a..7a81566d9d66 100644
> >> --- a/mm/kasan/common.c
> >> +++ b/mm/kasan/common.c
> >> @@ -20,6 +20,7 @@
> >>   #include <linux/module.h>
> >>   #include <linux/printk.h>
> >>   #include <linux/sched.h>
> >> +#include <linux/sched/clock.h>
> >>   #include <linux/sched/task_stack.h>
> >>   #include <linux/slab.h>
> >>   #include <linux/stacktrace.h>
> >> @@ -50,6 +51,10 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
> >>   {
> >>          track->pid = current->pid;
> >>          track->stack = kasan_save_stack(flags, true);
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       track->cpu = raw_smp_processor_id();
> >> +       track->ts_nsec = local_clock();
> >
> > What does "local_" mean? Is this clock value comparable across CPUs?
> >
>
>
> No, local_clock is the local CPU clock and cannot be used for comparison
> across CPUs, I made a mistake here.
>
> I delved into the clock subsystem of the Linux kernel today and I found
> that we have two choices.
>
> - sched_clock(): based on jiffies, high performance, but on some
> hardware, it will drift between CPUs.
>
> - ktime_get_boot_fast_ns(): based on clocksource, highly accurate,
> can be compared between CPUs, but performance is worse (seqlock).
>
> I tested 100000 calls respectively on my laptop, the average of
> sched_clock() is 17ns and the average of ktime_get_boot_fast_ns()
> is 25ns.
>
> ktime_get_boot_fast_ns() takes about 1.5 times as long as sched_clock().
>
> With Generic KASAN enabled, the average of one memory allocation is
> 3512ns on my laptop.
>
> Personally, I prefer ktime_get_boot_fast_ns() because it is more
> accurate and the extra time is insignificant for the time required for
> one memory allocation with Generic KASAN enabled.
>
> But maybe using ktime_get_boot_fast_ns() would have a more serious
> impact on small/embedded devices.
>
> Which do you think is the better choice?

I don't have a strong preference.

Re drift of sched_clock(), do you mean unsynchronized RDTSC on
different cores? I had the impression that RDTSC is synchronized
across cores on all recent CPUs/systems.


> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>   }
> >>
> >>   #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> >> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> >> index 8b06bab5c406..b3899a255aca 100644
> >> --- a/mm/kasan/kasan.h
> >> +++ b/mm/kasan/kasan.h
> >> @@ -187,6 +187,10 @@ static inline bool kasan_requires_meta(void)
> >>   struct kasan_track {
> >>          u32 pid;
> >>          depot_stack_handle_t stack;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       u32 cpu;
> >> +       u64 ts_nsec;
> >
> > This increases the size of meta from 8 to 24 bytes.
> > Can we somehow store the timestamp as 32 bits? Maybe compress the CPU
> > number (it shouldn't be larger than 20 bits?)?
> > I see below we report on microseconds, so we don't low bits of the
> > timestamp as well.
> >
>
>
> Maybe we can use bit field.
>
> struct kasan_track {
>         u32 pid;
>         depot_stack_handle_t stack;
> #ifdef CONFIG_KASAN_EXTRA_INFO
>         u64 cpu:20;
>         u64 ts_sec:22;
>         u64 ts_usec:22;
> #endif /* CONFIG_KASAN_EXTRA_INFO */
> };
>
> For example, 20-bit cpu, 22-bit ts_sec, 22-bit ts_usec, 64 bits
> (8 bytes), and the data structure is 16 bytes in total.

This looks better.
Can't we have a single field for time instead of ts_sec/usec?
Both sched_clock() and ktime_get_boot_fast_ns() return just u64.

> If the data structure becomes 16 bytes, it will not affect objects
> larger than 16 bytes.
>
> But the bit field can only be used in struct kasan_track (Generic),
> and cannot be used in struct kasan_stack_ring_entry (SW_TAGS KASAN
> and HW_TAGS KASAN).
>
> Because we need to use READ_ONCE and WRITE_ONCE to read and write
> struct kasan_stack_ring_entry, but READ_ONCE and WRITE_ONCE cannot
> read or write bit field.

If that's necessary, we could store both values as a single u64 and
the manually pack/unpack.


> > I see there is a deficiency in kasan_cache_create():
> > https://elixir.bootlin.com/linux/latest/source/mm/kasan/generic.c#L412
> >
> > If free_meta does not fit into the object, we add it after the object.
> > But we could overlap it with the object.
> > For example if the object size is 16 bytes and free_meta size is 24
> > bytes, we could increase object size to 24, while currently we
> > increase it to 16+24 = 40.
> > We need to place it after the object only if we have these other cases
> > "(cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor".
> >
> > Currently it affects only kmalloc-8 slab.
> > But with this change it will affect at least kmalloc-16 slab as well.
> >
>
>
> I completely agree that we can use both object space and redzone
> space to store free meta, thereby further reducing the extra memory
> consumption caused by KASAN.
>
> Of course, in this case we need to readjust the offset of the
> alloc meta.
>
> If you agree I can make this change in a separate patch.

This would be good. Thanks.

> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>   };
> >>
> >>   enum kasan_report_type {
> >> @@ -202,6 +206,7 @@ struct kasan_report_info {
> >>          size_t access_size;
> >>          bool is_write;
> >>          unsigned long ip;
> >> +       u64 ts_nsec;
> >>
> >>          /* Filled in by the common reporting code. */
> >>          const void *first_bad_addr;
> >> @@ -278,6 +283,10 @@ struct kasan_stack_ring_entry {
> >>          u32 pid;
> >>          depot_stack_handle_t stack;
> >>          bool is_free;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       u32 cpu;
> >> +       u64 ts_nsec;
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>   };
> >>
> >>   struct kasan_stack_ring {
> >> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> >> index e77facb62900..b6feaf807c08 100644
> >> --- a/mm/kasan/report.c
> >> +++ b/mm/kasan/report.c
> >> @@ -25,6 +25,7 @@
> >>   #include <linux/types.h>
> >>   #include <linux/kasan.h>
> >>   #include <linux/module.h>
> >> +#include <linux/sched/clock.h>
> >>   #include <linux/sched/task_stack.h>
> >>   #include <linux/uaccess.h>
> >>   #include <trace/events/error_report.h>
> >> @@ -242,27 +243,40 @@ static void end_report(unsigned long *flags, const void *addr, bool is_write)
> >>
> >>   static void print_error_description(struct kasan_report_info *info)
> >>   {
> >> +       unsigned long rem_usec = do_div(info->ts_nsec, NSEC_PER_SEC) / 1000;
> >> +
> >>          pr_err("BUG: KASAN: %s in %pS\n", info->bug_type, (void *)info->ip);
> >>
> >>          if (info->type != KASAN_REPORT_ACCESS) {
> >> -               pr_err("Free of addr %px by task %s/%d\n",
> >> -                       info->access_addr, current->comm, task_pid_nr(current));
> >> +               pr_err("Free of addr %px by task %s/%d at %lu.%06lus\n",
> >> +                       info->access_addr, current->comm, task_pid_nr(current),
> >> +                       (unsigned long)info->ts_nsec, rem_usec);
> >>                  return;
> >>          }
> >>
> >>          if (info->access_size)
> >> -               pr_err("%s of size %zu at addr %px by task %s/%d\n",
> >> +               pr_err("%s of size %zu at addr %px by task %s/%d at %lu.%06lus\n",
> >>                          info->is_write ? "Write" : "Read", info->access_size,
> >> -                       info->access_addr, current->comm, task_pid_nr(current));
> >> +                       info->access_addr, current->comm, task_pid_nr(current),
> >> +                       (unsigned long)info->ts_nsec, rem_usec);
> >>          else
> >> -               pr_err("%s at addr %px by task %s/%d\n",
> >> +               pr_err("%s at addr %px by task %s/%d at %lu.%06lus\n",
> >>                          info->is_write ? "Write" : "Read",
> >> -                       info->access_addr, current->comm, task_pid_nr(current));
> >> +                       info->access_addr, current->comm, task_pid_nr(current),
> >> +                       (unsigned long)info->ts_nsec, rem_usec);
> >>   }
> >>
> >>   static void print_track(struct kasan_track *track, const char *prefix)
> >>   {
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       unsigned long rem_usec = do_div(track->ts_nsec, NSEC_PER_SEC) / 1000;
> >> +
> >> +       pr_err("%s by task %u on cpu %d at %lu.%06lus:\n",
> >> +                       prefix, track->pid, track->cpu,
> >> +                       (unsigned long)track->ts_nsec, rem_usec);
> >> +#else
> >>          pr_err("%s by task %u:\n", prefix, track->pid);
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>          if (track->stack)
> >>                  stack_depot_print(track->stack);
> >>          else
> >> @@ -544,6 +558,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
> >>          info.access_size = 0;
> >>          info.is_write = false;
> >>          info.ip = ip;
> >> +       info.ts_nsec = local_clock();
> >>
> >>          complete_report_info(&info);
> >>
> >> @@ -582,6 +597,7 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
> >>          info.access_size = size;
> >>          info.is_write = is_write;
> >>          info.ip = ip;
> >> +       info.ts_nsec = local_clock();
> >>
> >>          complete_report_info(&info);
> >>
> >> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> >> index 8b8bfdb3cfdb..4d62f1b3e11d 100644
> >> --- a/mm/kasan/report_tags.c
> >> +++ b/mm/kasan/report_tags.c
> >> @@ -26,6 +26,18 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
> >>          return "invalid-access";
> >>   }
> >>
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +static void kasan_complete_extra_report_info(struct kasan_track *track,
> >> +                                        struct kasan_stack_ring_entry *entry)
> >> +{
> >> +       u32 cpu = READ_ONCE(entry->cpu);
> >> +       u64 ts_nsec = READ_ONCE(entry->ts_nsec);
> >> +
> >> +       track->cpu = cpu;
> >> +       track->ts_nsec = ts_nsec;
> >> +}
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >> +
> >>   void kasan_complete_mode_report_info(struct kasan_report_info *info)
> >>   {
> >>          unsigned long flags;
> >> @@ -82,6 +94,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
> >>
> >>                          info->free_track.pid = pid;
> >>                          info->free_track.stack = stack;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +                       kasan_complete_extra_report_info(&info->free_track, entry);
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>                          free_found = true;
> >>
> >>                          /*
> >> @@ -97,6 +112,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
> >>
> >>                          info->alloc_track.pid = pid;
> >>                          info->alloc_track.stack = stack;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +                       kasan_complete_extra_report_info(&info->alloc_track, entry);
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>                          alloc_found = true;
> >>
> >>                          /*
> >> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> >> index 7dcfe341d48e..474ce7e8be8b 100644
> >> --- a/mm/kasan/tags.c
> >> +++ b/mm/kasan/tags.c
> >> @@ -13,6 +13,7 @@
> >>   #include <linux/memblock.h>
> >>   #include <linux/memory.h>
> >>   #include <linux/mm.h>
> >> +#include <linux/sched/clock.h>
> >>   #include <linux/static_key.h>
> >>   #include <linux/string.h>
> >>   #include <linux/types.h>
> >> @@ -92,6 +93,17 @@ void __init kasan_init_tags(void)
> >>          }
> >>   }
> >>
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +static void save_extra_info(struct kasan_stack_ring_entry *entry)
> >> +{
> >> +       u32 cpu = raw_smp_processor_id();
> >> +       u64 ts_nsec = local_clock();
> >> +
> >> +       WRITE_ONCE(entry->cpu, cpu);
> >> +       WRITE_ONCE(entry->ts_nsec, ts_nsec);
> >> +}
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >> +
> >>   static void save_stack_info(struct kmem_cache *cache, void *object,
> >>                          gfp_t gfp_flags, bool is_free)
> >>   {
> >> @@ -124,6 +136,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
> >>          WRITE_ONCE(entry->pid, current->pid);
> >>          WRITE_ONCE(entry->stack, stack);
> >>          WRITE_ONCE(entry->is_free, is_free);
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       save_extra_info(entry);
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>
> >>          /*
> >>           * Paired with smp_load_acquire() in kasan_complete_mode_report_info().
> >> --
> >> 2.39.2
> >>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZE8DO1u6NHATXC9tfcVS4diM0LO4r3cQ15HaGHVoFAbQ%40mail.gmail.com.
