Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH757GVAMGQECDBRJNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 089B47F5349
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 23:20:17 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1efa8a172d5sf343472fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Nov 2023 14:20:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700691615; cv=pass;
        d=google.com; s=arc-20160816;
        b=qlFJ3tLwqJ7Jzw87fzyO2E9G/I4LOAGy51jvlxAIP4SpxdO45UNsE7Ck+x8ziUM3Mb
         2a7KqWx+eghDYgB67u7FCysmMhJgZJRpoaFkmSwcdYqPOJR/rOfyqqUzyKgn5wML5CJw
         xjjAjbpTHmhAZ3aadYebk4mZQX4db5rq/XeeOUttZfsPE7vqAa6QBQn7vRH555atJyVk
         jitDO7OLBc/7nREHsQoawvTT/ZjbYCWDWCRM69HXIUWmw5k4TaAmTuo4FvKO+oWwM8yZ
         Aip6LFAQ5bXcabOPuEtddUjHmuS4kTkX846cNV8mWTuW0Ojy1IVRmEtClAsCqZD4u1Zu
         PatA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RcAbFtHKywTcM6WlHa563M4vJ7Tje3AHqBrSmnC+IW4=;
        fh=LubqLcB7navSDf0Nt52CtUnJ6CDCRU0TM1wxMFuJtiQ=;
        b=Fqo8KYhEbeG4bamAxXZ9v1zEvglpX5hCKI0Csb7CM+4+ni1LicKvPvcj9D8rdKT0sN
         YJykyx6l2YAed51UfG5sIi3UPHAHm/c0QBVCuiQCu0tSx4jnsCttkaM+mH7nGAmE2CMz
         zZtqxNM3JimQXOTn+aA/EyrYdm2qOl0d2hIC1GSZDQI93Qq/GzNvs0ImTYKj7RXVl5jJ
         23lZs7sb2tA3+Ug9P3aStvqBnUVQygH9rLP+MLtJMx8fl2JVhndXdZi5RzD/5VdKpOEu
         2MDb00oIxuQyx/4Gp3FbCy85mDebXXDvBUCwYI8fqtji7edZGum20D19QBVxZn54c7gJ
         oo9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p1ZIS9GN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700691615; x=1701296415; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RcAbFtHKywTcM6WlHa563M4vJ7Tje3AHqBrSmnC+IW4=;
        b=RKXvezE7G9Elk7t76rYrO/0sweImgnBV9SQQigA5hYAtGSuJVCa6y69xTY3HEY3+IL
         HjnpIuWcVli+vuc5VW9rRP5Qp+GXCsNL6xoO9ArJbJ3RNBQvV+TO7dsZa2uxOz0dpCkM
         /TSfMQEkAUUigaQzfWkTe6tzIeHaumofEJv0/rYUWiVzF5UPyDlXEO+Xge44h+dZtZKS
         M8vBwMpZmdUnrqqc+SsaJ/8hx4M4zKfzOR+Rgf+dCjq9moc6K+hY2WDcrZdNqAqkYtSY
         JqOOhe9YseyV4qChWBESAvXXlgxNA+5H+rXOtnfyhVIxh7zQzIYP/5KzztgRQwnpuwGr
         nfeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700691615; x=1701296415;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RcAbFtHKywTcM6WlHa563M4vJ7Tje3AHqBrSmnC+IW4=;
        b=XY9T4T/x7xz781OFJCUpiZ98hEOVTrEYumRYEWgb7bm407wLyoL7q6l/Wu/BNS6tqD
         okQeNxQIrwMionuEKZCT+XwEDs45IJSMXT3j6yaMl00HSGrtU/gmgUTXdaAVkvyhLYwQ
         x4MQU20/N4ifjxq+1cZU/3FrU5jI71TbT4XBXYt532/HK9DEP1ZxE5Ap/Y2dS6/OyEE9
         DXkZ+loun93tJfRDaiTGSBk5rM/2KKX/XPUfvc5RmLMURXx8t1A/opQlaylmZCCGS7qZ
         zr2l8QIfzsphk/Kd6BMcB/zwZom0foY9zvrnAIH9ULXmPunMxCDWtgLp5LxGP2OqtxyY
         nIqA==
X-Gm-Message-State: AOJu0YysggyMv0wBb7/32ut4889JFMCtQVrQXBJnODA0ljyhDOEMLXqO
	oQUNrU7HHZMzpSnp6qDDKO8=
X-Google-Smtp-Source: AGHT+IH/E7YARp1FbbSVU/YMFyQ/Hv6dnpwCyf1t/ZVE/394eAt7Zr9x8ecDuS3ppVnu4S620yCDMQ==
X-Received: by 2002:a05:6871:3a2c:b0:1ea:38:8e34 with SMTP id pu44-20020a0568713a2c00b001ea00388e34mr4556084oac.17.1700691615311;
        Wed, 22 Nov 2023 14:20:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5895:0:b0:423:7870:23d5 with SMTP id t21-20020ac85895000000b00423787023d5ls273221qta.2.-pod-prod-04-us;
 Wed, 22 Nov 2023 14:20:14 -0800 (PST)
X-Received: by 2002:a05:620a:1018:b0:778:b068:9c89 with SMTP id z24-20020a05620a101800b00778b0689c89mr3682857qkj.51.1700691614471;
        Wed, 22 Nov 2023 14:20:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700691614; cv=none;
        d=google.com; s=arc-20160816;
        b=Fww0VeukSiYX20KE97aykIX4eJXgwWZp+iXVUGXlwFBJELz4qt1WkZdrSm0zAsHfI+
         xY7MjqAhaCXIw5Hmbz2mq7pgSfIv4hHDXeHBQpN+Ml9Ta1r0ktoDy1zqQDrqbqz1L6rt
         cUED79W8JvuRILVteB4WN9TgNAgGfXINFNytLxPtaQ8PdYwn9ddmYVFbV82KDG+2+evd
         R5FihV9402V9LsoFixqkvTYue5LuHwIOGjI/nXRCoWvCXdrUtcYe3gTg2+8iwE63iEj3
         4QdD8AgTE+GptnGOx6uX78aFH29q/cjjmtYhlSHZFz0deFn44fh6HN6Y/TIcNEhXEUR6
         yr0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PHkAYUggtPd4uMdHb4XHRFzN0AgwRbLCE5uILh47HBE=;
        fh=LubqLcB7navSDf0Nt52CtUnJ6CDCRU0TM1wxMFuJtiQ=;
        b=HsCGjvY78Ep+1LRMrFsvUM8PLXEmcGbXM4wp5LT14I+BuFCGrVVpQtf7axpVs8gj+J
         qgSJoPk1+TowRP+9KHqajuSsfteLIdby+yAqwm6iG0BRgQFlkfJWE4omjpVvAFk6KZXW
         rorfdEgG3xVXM1nsQA5/db8WjlDuSCoA5jrd6JUq53qcLTN1Z13xdyZzjU71vOg+Z2ha
         wCzFemFZ9mATpI3fZOG3QmwbRt9JCmiIkvgeAyCxQef6i3/piNJl6IlVEMGVDTtijRAJ
         LFjctSBAG4EVuEER2hu0q0UWk8eYtoqxTeU1nmH4jMeYHMUut+Pk2nhXS8KcuTnuIbxA
         soKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p1ZIS9GN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa35.google.com (mail-vk1-xa35.google.com. [2607:f8b0:4864:20::a35])
        by gmr-mx.google.com with ESMTPS id dw10-20020a05620a600a00b0077d560a74e3si62906qkb.6.2023.11.22.14.20.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Nov 2023 14:20:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a35 as permitted sender) client-ip=2607:f8b0:4864:20::a35;
Received: by mail-vk1-xa35.google.com with SMTP id 71dfb90a1353d-4ac2c1a4b87so92533e0c.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Nov 2023 14:20:14 -0800 (PST)
X-Received: by 2002:a05:6122:4019:b0:4b0:8de:d09c with SMTP id
 ca25-20020a056122401900b004b008ded09cmr4901290vkb.7.1700691613877; Wed, 22
 Nov 2023 14:20:13 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB0752A2F21C050D701945B62799BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CANpmjNPvDhyEcc0DdxrL8hVd0rZ-J4k95R5M5AwoeSotg-HCVg@mail.gmail.com> <VI1P193MB0752E3CA6B2660860BD3923D99BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB0752E3CA6B2660860BD3923D99BAA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Nov 2023 23:19:35 +0100
Message-ID: <CANpmjNMejg7ekEhuuwdxpzOk5-mO+xn+qEL1qmx8ZVQG9bz_XA@mail.gmail.com>
Subject: Re: [PATCH] kfence: Replace local_clock() with ktime_get_boot_fast_ns()
To: Juntong Deng <juntong.deng@outlook.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p1ZIS9GN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a35 as
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

On Wed, 22 Nov 2023 at 22:36, Juntong Deng <juntong.deng@outlook.com> wrote:
>
> On 2023/11/23 4:35, Marco Elver wrote:
> > On Wed, 22 Nov 2023 at 21:01, Juntong Deng <juntong.deng@outlook.com> wrote:
> >>
> >> The time obtained by local_clock() is the local CPU time, which may
> >> drift between CPUs and is not suitable for comparison across CPUs.
> >>
> >> It is possible for allocation and free to occur on different CPUs,
> >> and using local_clock() to record timestamps may cause confusion.
> >
> > The same problem exists with printk logging.
> >
> >> ktime_get_boot_fast_ns() is based on clock sources and can be used
> >> reliably and accurately for comparison across CPUs.
> >
> > You may be right here, however, the choice of local_clock() was
> > deliberate: it's the same timestamp source that printk uses.
> >
> > Also, on systems where there is drift, the arch selects
> > CONFIG_HAVE_UNSTABLE_SCHED_CLOCK (like on x86) and the drift is
> > generally bounded.
> >
> >> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> >> ---
> >>   mm/kfence/core.c | 2 +-
> >>   1 file changed, 1 insertion(+), 1 deletion(-)
> >>
> >> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> >> index 3872528d0963..041c03394193 100644
> >> --- a/mm/kfence/core.c
> >> +++ b/mm/kfence/core.c
> >> @@ -295,7 +295,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
> >>          track->num_stack_entries = num_stack_entries;
> >>          track->pid = task_pid_nr(current);
> >>          track->cpu = raw_smp_processor_id();
> >> -       track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
> >> +       track->ts_nsec = ktime_get_boot_fast_ns();
> >
> > You have ignored the comment placed here - now it's no longer the same
> > source as printk timestamps. I think not being able to correlate
> > information from KFENCE reports with timestamps in lines from printk
> > is worse.
> >
> > For now, I have to Nack: Unless you can prove that
> > ktime_get_boot_fast_ns() can still be correlated with timestamps from
> > printk timestamps, I think this change only trades one problem for
> > another.
> >
> > Thanks,
> > -- Marco
>
> Honestly, the possibility of accurately matching a message in the printk
> log by the timestamp in the kfence report is very low, since allocation
> and free do not directly correspond to a certain event.

It's about being able to compare the timestamps. I don't want to match
an exact event, but be able to figure out which event happened
before/after an allocation or free, i.e. the logical ordering of
events.

With CONFIG_PRINTK_CALLER we can see the CPU ID in printk lines and
are therefore able to accurately compare printk lines with information
given by KFENCE alloc/free info.

> Since time drifts across CPUs, timestamps may be different even if
> allocation and free can correspond to a certain event.

This is not a problem with CONFIG_PRINTK_CALLER.

> If we really need to find the relevant printk logs by the timestamps in
> the kfence report, all we can do is to look for messages that are within
> a certain time range.
>
> If we are looking for messages in a certain time range, there is not
> much difference between local_clock() and ktime_get_boot_fast_ns().
>
> Also, this patch is in preparation for my next patch.
>
> My next patch is to show the PID, CPU number, and timestamp when the
> error occurred, in this case time drift from different CPUs can
> cause confusion.

It's not quite clear how there's a dependency between this patch and a
later patch, but generally it's good practice to send related patches
as a patch series. That way it's easier to see what the overall
changes are and provide feedback as a whole - as is, it's difficult to
provide feedback.

However, from what you say this information is already given.
dump_stack_print_info() shows this - e.g this bit here is printed by
where the error occurred:

| CPU: 0 PID: 484 Comm: kunit_try_catch Not tainted 5.13.0-rc3+ #7
| Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2
04/01/2014

And if the printk log has timestamps, then these lines are prefixed
with the timestamp where the error occurred.

> For example, use-after-free caused by a subtle race condition, in which
> the time between the free and the error occur will be very close.
>
> Time drift from different CPUs may cause it to appear in the report that
> the error timestamp precedes the free timestamp.

That doesn't matter. I recommend that you go through a hypothetical
debugging scenario:
1. We are not interested in the absolute timings of events, but the
logical ordering between them.

2. The logical ordering of events is inherent from how KFENCE
operates: an error _always_ follows an allocation and/or free. From a
debugging point of view, the timestamps do not have any value here.

3. The timestamps _do_ add value when trying to figure out the logical
ordering between allocation, free, or the erroneous access _with
other_ events in the system. A stream of other events is always shown
in the kernel log (printk). Other streams of events can be obtained
via e.g. ftrace (which also uses local_clock(), see
kernel/trace/trace_clock.c).

So, the timestamp that KFENCE should show is the one that most likely
allows us to deduce the logical ordering with other events in the
system.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMejg7ekEhuuwdxpzOk5-mO%2Bxn%2BqEL1qmx8ZVQG9bz_XA%40mail.gmail.com.
