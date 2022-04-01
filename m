Return-Path: <kasan-dev+bncBCMIZB7QWENRB6WITOJAMGQEJLV3GQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id D6E264EEC76
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Apr 2022 13:39:39 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id l71-20020a1fa24a000000b003433c02e122sf338540vke.12
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Apr 2022 04:39:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648813179; cv=pass;
        d=google.com; s=arc-20160816;
        b=a3L8z5gSKdytnNajltwu97+DqmH7FE2hUZxL/JXjQ8yUnaJY02vy5TbOry+KMx0/Gm
         4OFpmQeErEX1l4U5WZ5VBqyL2IDXTu8K9+ZfZJ5EOkJrJUsNUGUzMrCgpB98InL4Hujt
         yLib/nZFUP6J1WVkqS9Wo6Opbj7B6ARSRAjziJiVjo1l9QlbVakCddXP2Ojy9orGLfmr
         PEx7n/7u4On1p8+mX1KFo388F9OQ9TmuV4jNvdbebbzDwRbj1R3lQDsLthCdzTaLwtqu
         8NJ4RzmklX1WSaRnyHqGuADjjmoWCuPt0zm4z1imbR/HAipz4IKLhBA6mdqKPf5gc7J0
         lcTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WYCtO2VnilwEP3umaGeKePKFvXNf8mpxbIUowjaTubM=;
        b=O+n6vvduitLBlwsWnJMpmwFdJCLa6bT1rMdBLg9j7VR32izhVbvtaV4aJpGfVI57EC
         vM3XxTuOaKugDyIVmCdzHk77plIQwDBbuSyWcn54hc/xHDvSTPRvI4QRrq/8eU9pS225
         Z1AHBbyhcpFbwtSIZ8i0lGRiAqO2/cTP9hvVLQoxzXwpdtHkMWK19UFj4leDMNoWY1yI
         j4qMij/8g3pPrS6aP0A1CwPB92KhPdSngMQIReksy/QpYON6mqqmwI1rTiIGbeq91w40
         dlZ6UfyXagR/U5z2CpJgN1J1w2ePwUv6cRykdeQU5Ns4JgM3m+nCax57DxaXkhgiBn31
         L/4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aoPZa1pn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WYCtO2VnilwEP3umaGeKePKFvXNf8mpxbIUowjaTubM=;
        b=XXpSERrnh5LABJOpmr9AHxlYd43xfSX+ONQhTN+vzD1jcWtIF56dAUTlGUQgX1JLV8
         tbQy57FmFS58bBLVoGX+31hBYmd0xmPvVe1qdRk2wMZtlHPcKr3WpXTe0Z/TO5225Eog
         Lk4/kFt23QzQeMMaehSKdvI/7tYWlrifvX6uSj3bdgSCriJXpsb2fm4+KfAxncjATFhn
         OeT//qjeyVMpREKYzQQiSy+8WKnzZ9hoY9NQ1d43azPjDK7b0tfhY/S9SeoPbD+PSwJK
         sR4ZQu66q2QE/Zqgn8nci8AJhjLzcc9ktIl9fhroOruXh6P9DpSJmptdNQAeSLLbHreM
         /WnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WYCtO2VnilwEP3umaGeKePKFvXNf8mpxbIUowjaTubM=;
        b=5C9S6oO42r1QUU1mq5boJYC0j7y3DGkCTd38DHr3cLV1fx6FRSyjYDSPuPoCuvs2/c
         IYmEKV3iBlFtrSXT3jy6dsNA5v5xuXwjoO6DvGdgtYO18/DBAp2HKRqU3/q4NUf2uzmR
         jC+l3Ig6Cn5jh6I3n4XdZtC3pXPnugl+Cq0UKMf1wHZPHztp2+c0vn34gSSWk48JJGWT
         WN9t5pXkjoopZ9DAKYBEOlEHbHONNd/3pNTOShZX+Y7YtArKYNGZxgsKHNz2lnwmettu
         p+7206nNeZgqSuopuIJUjDRzK7oK49XRclOTZGbdSMcU+OnceY7dsSPKjPrUuN0VgmSc
         BK9A==
X-Gm-Message-State: AOAM530ZwpKf3+mSwQjY5KYIM6MpBh0BSBu55TioLK5yltoXkXLX6gBy
	PTy5PFFGPRZ+zODyc2KW2BQ=
X-Google-Smtp-Source: ABdhPJxdd9TdnF6fdQAT3CKkAH9RH5xgnYn8lLIBEMsnEM45WB3bYP8i0J6dWOUM3v9NPq8xpXbzAg==
X-Received: by 2002:a05:6102:510f:b0:325:a73c:12b9 with SMTP id bm15-20020a056102510f00b00325a73c12b9mr3291107vsb.78.1648813178839;
        Fri, 01 Apr 2022 04:39:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ba18:0:b0:325:ac9d:39ac with SMTP id l24-20020a67ba18000000b00325ac9d39acls468369vsn.7.gmail;
 Fri, 01 Apr 2022 04:39:38 -0700 (PDT)
X-Received: by 2002:a67:442:0:b0:324:d899:86ad with SMTP id 63-20020a670442000000b00324d89986admr3589442vse.59.1648813178388;
        Fri, 01 Apr 2022 04:39:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648813178; cv=none;
        d=google.com; s=arc-20160816;
        b=AKGEAKujSrL6MP5CzobBTCGLA1HzZIGe87vWTh+ypwTjp2+tXcuj0BJvRRSokh8aEG
         mFlRG1KbFdmLYUVjNVtRWrxTSA9Sjl18rE3SBLvoMlITriMvLYZoDcvp0kg7prhcMPs1
         5ZNqt09uRzWcuhpWisdZ0UJImk54bMssXqcHknjI/J8J2nxjE07398x/LpfilvXg+EUc
         U/ohy2NgOa5kV3RmGtE+5EOGsKY1OJ7f2joIhXc3e4KcMiV13WYbmI5htTbVca4z0aRM
         fO/lreY/DsZ+/uIDnSQAJT7+yuDtSihKI92ubAqRmGJ81oanHra1Ra4Z249EoaOMhTYN
         G8EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+8Dv18kj8IAp5BXzcoVdvPm3aoVZ9KkfAIFlQfRSHMc=;
        b=gk4KMoKnl8XlZEIt12pm8qCmhvJxneDa/38t5KIQNFAWzgkNthCFJIisuk6R1bj93z
         aau7pNkqYLZ1ujdoZWwkkPzWwULiEO+OGJtnEY59mz0mq3ZWtXQvQlFuqxewwFiRPYNW
         lkJ8uX9CaSh5Xpaz4Mqj275B3vdq+p7YbW1JQ7RaWZ+2H3+1T3xqHgpIrz1tm2EUiHG8
         ReHHeAVsyXR9osLt9q/1A7g0/KiHsxtvSGr4/8E7NI6v6kW1DGsg+VvtpwN+Tv5stqp8
         he1VFbVZzqJ7/3so9lVtzIKBn7AlhYCX+4fMjfvPceQ+k6nXMeB/fdrVl446YrxNefH5
         adNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aoPZa1pn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oa1-x2b.google.com (mail-oa1-x2b.google.com. [2001:4860:4864:20::2b])
        by gmr-mx.google.com with ESMTPS id ay14-20020a056130030e00b00345c6ac388bsi329692uab.1.2022.04.01.04.39.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Apr 2022 04:39:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::2b as permitted sender) client-ip=2001:4860:4864:20::2b;
Received: by mail-oa1-x2b.google.com with SMTP id 586e51a60fabf-de48295467so2396567fac.2
        for <kasan-dev@googlegroups.com>; Fri, 01 Apr 2022 04:39:38 -0700 (PDT)
X-Received: by 2002:a05:6870:b629:b0:de:a293:bf74 with SMTP id
 cm41-20020a056870b62900b000dea293bf74mr4791423oab.163.1648813176421; Fri, 01
 Apr 2022 04:39:36 -0700 (PDT)
MIME-Version: 1.0
References: <20220401091006.2100058-1-qiang1.zhang@intel.com>
In-Reply-To: <20220401091006.2100058-1-qiang1.zhang@intel.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Apr 2022 13:39:23 +0200
Message-ID: <CACT4Y+Zw7FJ6Rp0+DB_crXJ0rwZHNM9n-z+V2E-e_=87c6ewgg@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix sleeping function called from invalid context
 in PREEMPT_RT
To: Zqiang <qiang1.zhang@intel.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	bigeasy@linutronix.de, akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-rt-users@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aoPZa1pn;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2001:4860:4864:20::2b as
 permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
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

On Fri, 1 Apr 2022 at 11:09, Zqiang <qiang1.zhang@intel.com> wrote:
>
> BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:46
> in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, name: swapper/0
> preempt_count: 1, expected: 0
> ...........
> CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.17.1-rt16-yocto-preempt-rt #22
> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
> BIOS rel-1.15.0-0-g2dd4b9b3f840-prebuilt.qemu.org 04/01/2014
> Call Trace:
> <TASK>
> dump_stack_lvl+0x60/0x8c
> dump_stack+0x10/0x12
>  __might_resched.cold+0x13b/0x173
> rt_spin_lock+0x5b/0xf0
>  ___cache_free+0xa5/0x180
> qlist_free_all+0x7a/0x160
> per_cpu_remove_cache+0x5f/0x70
> smp_call_function_many_cond+0x4c4/0x4f0
> on_each_cpu_cond_mask+0x49/0xc0
> kasan_quarantine_remove_cache+0x54/0xf0
> kasan_cache_shrink+0x9/0x10
> kmem_cache_shrink+0x13/0x20
> acpi_os_purge_cache+0xe/0x20
> acpi_purge_cached_objects+0x21/0x6d
> acpi_initialize_objects+0x15/0x3b
> acpi_init+0x130/0x5ba
> do_one_initcall+0xe5/0x5b0
> kernel_init_freeable+0x34f/0x3ad
> kernel_init+0x1e/0x140
> ret_from_fork+0x22/0x30
>
> When the kmem_cache_shrink() be called, the IPI was triggered, the
> ___cache_free() is called in IPI interrupt context, the local lock
> or spin lock will be acquired. on PREEMPT_RT kernel, these lock is
> replaced with sleepbale rt spin lock, so the above problem is triggered.
> fix it by migrating the release action from the IPI interrupt context
> to the task context on RT kernel.
>
> Signed-off-by: Zqiang <qiang1.zhang@intel.com>
> ---
>  mm/kasan/quarantine.c | 15 ++++++++++++---
>  1 file changed, 12 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 08291ed33e93..c26fa6473119 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -90,6 +90,7 @@ static void qlist_move_all(struct qlist_head *from, struct qlist_head *to)
>   */
>  static DEFINE_PER_CPU(struct qlist_head, cpu_quarantine);
>
> +static DEFINE_PER_CPU(struct qlist_head, cpu_shrink_qlist);
>  /* Round-robin FIFO array of batches. */
>  static struct qlist_head global_quarantine[QUARANTINE_BATCHES];
>  static int quarantine_head;
> @@ -311,12 +312,14 @@ static void qlist_move_cache(struct qlist_head *from,
>  static void per_cpu_remove_cache(void *arg)
>  {
>         struct kmem_cache *cache = arg;
> -       struct qlist_head to_free = QLIST_INIT;
> +       struct qlist_head *to_free;
>         struct qlist_head *q;
>
> +       to_free = this_cpu_ptr(&cpu_shrink_qlist);
>         q = this_cpu_ptr(&cpu_quarantine);
> -       qlist_move_cache(q, &to_free, cache);
> -       qlist_free_all(&to_free, cache);
> +       qlist_move_cache(q, to_free, cache);
> +       if (!IS_ENABLED(CONFIG_PREEMPT_RT))
> +               qlist_free_all(to_free, cache);
>  }
>
>  /* Free all quarantined objects belonging to cache. */
> @@ -324,6 +327,7 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>  {
>         unsigned long flags, i;
>         struct qlist_head to_free = QLIST_INIT;
> +       int cpu;
>
>         /*
>          * Must be careful to not miss any objects that are being moved from
> @@ -334,6 +338,11 @@ void kasan_quarantine_remove_cache(struct kmem_cache *cache)
>          */
>         on_each_cpu(per_cpu_remove_cache, cache, 1);
>
> +       if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
> +               for_each_possible_cpu(cpu)
> +                       qlist_free_all(per_cpu_ptr(&cpu_shrink_qlist, cpu), cache);
> +       }

Hi Zqiang,

This code is not protected by any kind of mutex, right? If so, I think
it can lead to subtle memory corruptions, double-frees and leaks when
several tasks move to/free from cpu_shrink_qlist list.


>         raw_spin_lock_irqsave(&quarantine_lock, flags);
>         for (i = 0; i < QUARANTINE_BATCHES; i++) {
>                 if (qlist_empty(&global_quarantine[i]))

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZw7FJ6Rp0%2BDB_crXJ0rwZHNM9n-z%2BV2E-e_%3D87c6ewgg%40mail.gmail.com.
