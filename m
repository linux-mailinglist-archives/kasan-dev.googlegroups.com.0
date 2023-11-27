Return-Path: <kasan-dev+bncBCMIZB7QWENRBEWHSGVQMGQECPIV6SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id DBD327F9CCD
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 10:38:27 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-50aae89f8fbsf62110e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 01:38:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701077907; cv=pass;
        d=google.com; s=arc-20160816;
        b=aSMXqogNuEkN7+Vi75TMhMSVNaJcYBenKzlLoVpYVSG91Mu20gcVzVKFFemBK6lEYM
         hpE+NoDkhhPQzz/Q3u+CilWIp/iERiz++LpEKGZbx4rWDcmuO8fQy+MqyAH+wdm2VtLO
         8Uw+m8lSWOBL6GAWAbvGw3Qv9EUIlHKN1gUrolLf2qY9gp3+JISl8ZYj/l6yh+pfqVxZ
         CB1WARf1qZEOG+kSVCUYXwd11VGqoUY0SWuHL7Z1aVCO/jo2Rl9xYtRIDYgkxjsU4utJ
         ZY336khJvh852PB57+06xoIdnBuEl/e1n5RbFNO07UOr/D6BLINttjTV8VIZ977iHo4s
         ba6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cbtF9ntUL/UBplH3ulzyG1yK3hVcWEi5FsIAXnPfYs0=;
        fh=Cxdz3lXx9q85yacnGVuiIilAYWk/9KO8DtHEl0n0w48=;
        b=tFhzjX5C71qYY39txhZ4LF4rG91MzFBkpiyXmFzBStyGRrLCMbiZX5TUmpdQCTY89s
         RioMMUKGfuw4BnDxRlHwmBjaiQw3oecdaX62JZRW2msJxvQIZRJjdqN2eZostCb+rRoz
         UWgM5NQ5SBiiD1LebXL1UepfC9ekagV6IRkMjXgogCBoFF5cpsyuHnlg7MSNpUj9ar5A
         xjHUeiZCDdyIk+IRsJz1/VNIMCHIfc5Rfigxqae8vmWH2ABGfeTz004po+z0d4NVBPTr
         IhqtLWBpkYskWALVbDlLarKb/GHQPAWUNpLu8Z1ZD1FADS2iLRr5GRRKUn/DQjkQBPWc
         wDZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pA0emGe+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701077907; x=1701682707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cbtF9ntUL/UBplH3ulzyG1yK3hVcWEi5FsIAXnPfYs0=;
        b=hYZlDpe2mZz2FymvmqOImIj2S2QKWTWjo2hl52NHW3B0vICe0PlpxWGQd5tbxJDWCw
         Q3X54lVBFRAKxi4GhmYosuKdgyGLu7DS5Qj9bqGybz9LPy3vExxLmBQURh0WfD3E7/Mh
         rfAtRtJpOIWD5pJds52NRBPQFYpjpU38VG5aYpqzJZqmNuk3fIkQAchUjOSCV2gnaOJ+
         ZohDzvgXecv9/JKl3iCiZhPj/7wY0jdoVtPQcOPoGy63ExZecCatjImt8wv8p83+QlSR
         kVK7tKVDn4kfh5SAL6+cyCOnOZLL7jGYgb1Lgn0IMVyTCtc9WDDqhOIAP02HitMdnM+e
         jPug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701077907; x=1701682707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cbtF9ntUL/UBplH3ulzyG1yK3hVcWEi5FsIAXnPfYs0=;
        b=ghbsw0egjnSfknwVkS9SB6tdwgkHGJN+yCszUbcolBlskgVlWMQj2sRSHG00MlBzZc
         lSb8isV627nHT+r0v/aIJsw890ZxIgs/FrV7a4U6fRjsuUy8UQz0jYDVBvrz+ygwoPdr
         oqTVQNqXhlEaa1HK9dAFC/QKbBIIiXqQkSh4E0l8CstoLFuSLbYxFb+SCQEN2Mldjkeg
         g/iYuXI0rAzd20aelDS19FMeRC4do7srg5T/wehgT7/M0sSyCRKOkwHrn0/Toqm3xmPf
         gyQDJnNoWeMgznkTBtYlETJ7d/onIbCe7lgPDTPElTF9fF0RBJ3rIb85EMDeVBrcbWJa
         qsyw==
X-Gm-Message-State: AOJu0Yy8RyOLudlIPI2C63PZtXOM6I5XLDciEDWTBSLoWh6RtIrUCQsK
	NTnNVnL+8HrBG46o2YFusUE=
X-Google-Smtp-Source: AGHT+IFp6D90vX5ILdGeLQ5AC633mJ8X+1x1Ja+Pa8jR9VLMk4PgOUrySwxqkDZplHu7fEzEczkAGg==
X-Received: by 2002:a05:6512:3e16:b0:502:a55e:fec0 with SMTP id i22-20020a0565123e1600b00502a55efec0mr432129lfv.6.1701077906547;
        Mon, 27 Nov 2023 01:38:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c91:b0:50a:aa81:3d95 with SMTP id
 h17-20020a0565123c9100b0050aaa813d95ls236355lfv.2.-pod-prod-09-eu; Mon, 27
 Nov 2023 01:38:24 -0800 (PST)
X-Received: by 2002:a05:6512:32a7:b0:507:a5e2:7c57 with SMTP id q7-20020a05651232a700b00507a5e27c57mr6958988lfe.18.1701077904574;
        Mon, 27 Nov 2023 01:38:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701077904; cv=none;
        d=google.com; s=arc-20160816;
        b=00Qr/ysmwlMbU6ElVSLbi0vIrdFpLb+C1NNZP1xK/fCB7uUS2cW85xCNj6EX4oOGry
         +Xoi+stvNNkOtMB/3cvfuN4zdiuh8hJWXeky+F7L/Pq+4IqyZhKjpfJfUxyG9p6lZF3G
         N5OakplVKNWDYRvTZbIEa4Q+OjPJUPyLbaLRu8t75fUAg3PXHNBRYAdTOb/9t8SgY3ge
         nf+/KhY9MxR5EfOBtCnTZgDdCcBNvoZzm4hbJ2q8000QQy5R1YCEcc1tUHjBO27If2zI
         j3M2zMCnGq86+4Ltb0rdNqHxADhnaGEDfgd3Lt/jnW4ARE7FZkDW84kSTbT8zLrXg7s6
         c02g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yXbJLlN8zN8yxyWwSZeLI9CkhU0ZX6ImmCRBdSzQVgU=;
        fh=Cxdz3lXx9q85yacnGVuiIilAYWk/9KO8DtHEl0n0w48=;
        b=lNCokzomgsMLzRftdg5UgRndbVR+ozDQT6fy6XLFW7EHhGoF7rZGFMukzCOmBHXQGz
         5ucbElsmiW+XIx47lAzE6lMwQQTGZmHYqbaH1NgBAgYDnveW1ZYDsQRvLoicT76tp3Uz
         Os0ylvqNWof4vHXH/MR/GAb5evR5nZMr0rJEWyEHpev3yrr29S+dOfUA6UASGDvdgeYI
         icvbaWhZiO7u477LzeBb6Y9Q0ZxrqJwBgnlpG6XMRWLGkN2BKYvbaNYuzufBu/yf20xW
         j5WU4oV2GAxPxiR2UelrsaPj9p32sVcHfFQVhq2gTlJ2EaSaSUGv4y5TWifr6h+qleCq
         yTAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pA0emGe+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id g41-20020a0565123ba900b005056618eed7si472474lfv.4.2023.11.27.01.38.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Nov 2023 01:38:24 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-50babb66dedso3392e87.0
        for <kasan-dev@googlegroups.com>; Mon, 27 Nov 2023 01:38:24 -0800 (PST)
X-Received: by 2002:a05:6512:281a:b0:50a:b7b3:19cd with SMTP id
 cf26-20020a056512281a00b0050ab7b319cdmr456358lfb.5.1701077903951; Mon, 27 Nov
 2023 01:38:23 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB07529BC28E5B333A8526BEBD99BEA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
 <CACT4Y+aVjKTxTamnybC9gS7uvSodYjvHst9obo=GjJ_km-_pdw@mail.gmail.com> <VI1P193MB0752C5B781EC2A351EDF62CC99BDA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB0752C5B781EC2A351EDF62CC99BDA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 27 Nov 2023 10:38:11 +0100
Message-ID: <CACT4Y+YDnXD3SeordJ8X6tQO+7nr5VuWVrJ-DUi3BXac0zdVxw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Record and report more information
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pA0emGe+;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::132
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

On Mon, 27 Nov 2023 at 10:35, Juntong Deng <juntong.deng@outlook.com> wrote:
>
> On 2023/11/27 12:34, Dmitry Vyukov wrote:
> > On Sun, 26 Nov 2023 at 23:25, Juntong Deng <juntong.deng@outlook.com> wrote:
> >>
> >> Record and report more information to help us find the cause of the
> >> bug and to help us correlate the error with other system events.
> >>
> >> This patch adds recording and showing CPU number and timestamp at
> >> allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO). The
> >> timestamps in the report use the same format and source as printk.
> >>
> >> Error occurrence timestamp is already implicit in the printk log,
> >> and CPU number is already shown by dump_stack_lvl, so there is no
> >> need to add it.
> >>
> >> In order to record CPU number and timestamp at allocation and free,
> >> corresponding members need to be added to the relevant data structures,
> >> which will lead to increased memory consumption.
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
> >> V1 -> V2: Use bit field to reduce memory consumption. Add more detailed
> >> config help. Cancel printing of redundant error occurrence timestamp.
> >>
> >>   lib/Kconfig.kasan      | 21 +++++++++++++++++++++
> >>   mm/kasan/common.c      | 10 ++++++++++
> >>   mm/kasan/kasan.h       | 10 ++++++++++
> >>   mm/kasan/report.c      |  6 ++++++
> >>   mm/kasan/report_tags.c | 16 ++++++++++++++++
> >>   mm/kasan/tags.c        | 17 +++++++++++++++++
> >>   6 files changed, 80 insertions(+)
> >>
> >> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> >> index 935eda08b1e1..8653f5c38be7 100644
> >> --- a/lib/Kconfig.kasan
> >> +++ b/lib/Kconfig.kasan
> >> @@ -207,4 +207,25 @@ config KASAN_MODULE_TEST
> >>            A part of the KASAN test suite that is not integrated with KUnit.
> >>            Incompatible with Hardware Tag-Based KASAN.
> >>
> >> +config KASAN_EXTRA_INFO
> >> +       bool "Record and report more information"
> >> +       depends on KASAN
> >> +       help
> >> +         Record and report more information to help us find the cause of the
> >> +         bug and to help us correlate the error with other system events.
> >> +
> >> +         Currently, the CPU number and timestamp are additionally
> >> +         recorded for each heap block at allocation and free time, and
> >> +         8 bytes will be added to each metadata structure that records
> >> +         allocation or free information.
> >> +
> >> +         In Generic KASAN, each kmalloc-8 and kmalloc-16 object will add
> >> +         16 bytes of additional memory consumption, and each kmalloc-32
> >> +         object will add 8 bytes of additional memory consumption, not
> >> +         affecting other larger objects.
> >> +
> >> +         In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
> >> +         boot parameter, it will add 8 * stack_ring_size bytes of additional
> >> +         memory consumption.
> >> +
> >>   endif # KASAN
> >> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> >> index b5d8bd26fced..2f0884c762b7 100644
> >> --- a/mm/kasan/common.c
> >> +++ b/mm/kasan/common.c
> >> @@ -20,6 +20,7 @@
> >>   #include <linux/module.h>
> >>   #include <linux/printk.h>
> >>   #include <linux/sched.h>
> >> +#include <linux/sched/clock.h>
> >>   #include <linux/sched/task_stack.h>
> >>   #include <linux/slab.h>
> >>   #include <linux/stackdepot.h>
> >> @@ -49,6 +50,15 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
> >>
> >>   void kasan_set_track(struct kasan_track *track, gfp_t flags)
> >>   {
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       u32 cpu = raw_smp_processor_id();
> >> +       u64 ts_nsec = local_clock();
> >> +       unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
> >> +
> >> +       track->cpu = cpu;
> >> +       track->ts_sec = ts_nsec;
> >> +       track->ts_usec = rem_usec;
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>          track->pid = current->pid;
> >>          track->stack = kasan_save_stack(flags,
> >>                          STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
> >> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> >> index b29d46b83d1f..2a37baa4ce2f 100644
> >> --- a/mm/kasan/kasan.h
> >> +++ b/mm/kasan/kasan.h
> >> @@ -187,6 +187,11 @@ static inline bool kasan_requires_meta(void)
> >>   struct kasan_track {
> >>          u32 pid;
> >>          depot_stack_handle_t stack;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       u64 cpu:20;
> >> +       u64 ts_sec:22;
> >> +       u64 ts_usec:22;
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>   };
> >>
> >>   enum kasan_report_type {
> >> @@ -278,6 +283,11 @@ struct kasan_stack_ring_entry {
> >>          u32 pid;
> >>          depot_stack_handle_t stack;
> >>          bool is_free;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       u64 cpu:20;
> >> +       u64 ts_sec:22;
> >> +       u64 ts_usec:22;
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>   };
> >>
> >>   struct kasan_stack_ring {
> >> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> >> index e77facb62900..8cd8f6e5cf24 100644
> >> --- a/mm/kasan/report.c
> >> +++ b/mm/kasan/report.c
> >> @@ -262,7 +262,13 @@ static void print_error_description(struct kasan_report_info *info)
> >>
> >>   static void print_track(struct kasan_track *track, const char *prefix)
> >>   {
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       pr_err("%s by task %u on cpu %d at %u.%06us:\n",
> >> +                       prefix, track->pid, track->cpu,
> >> +                       track->ts_sec, track->ts_usec);
> >> +#else
> >>          pr_err("%s by task %u:\n", prefix, track->pid);
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>          if (track->stack)
> >>                  stack_depot_print(track->stack);
> >>          else
> >> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> >> index 55154743f915..bf895b1d2dc2 100644
> >> --- a/mm/kasan/report_tags.c
> >> +++ b/mm/kasan/report_tags.c
> >> @@ -27,6 +27,16 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
> >>          return "invalid-access";
> >>   }
> >>
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +static void kasan_complete_extra_report_info(struct kasan_track *track,
> >> +                                        struct kasan_stack_ring_entry *entry)
> >> +{
> >> +       track->cpu = entry->cpu;
> >> +       track->ts_sec = entry->ts_sec;
> >> +       track->ts_usec = entry->ts_usec;
> >> +}
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >> +
> >>   void kasan_complete_mode_report_info(struct kasan_report_info *info)
> >>   {
> >>          unsigned long flags;
> >> @@ -73,6 +83,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
> >>
> >>                          info->free_track.pid = entry->pid;
> >>                          info->free_track.stack = entry->stack;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +                       kasan_complete_extra_report_info(&info->free_track, entry);
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>                          free_found = true;
> >>
> >>                          /*
> >> @@ -88,6 +101,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
> >>
> >>                          info->alloc_track.pid = entry->pid;
> >>                          info->alloc_track.stack = entry->stack;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +                       kasan_complete_extra_report_info(&info->alloc_track, entry);
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>                          alloc_found = true;
> >>
> >>                          /*
> >> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> >> index 739ae997463d..c172e115b9bb 100644
> >> --- a/mm/kasan/tags.c
> >> +++ b/mm/kasan/tags.c
> >> @@ -13,6 +13,7 @@
> >>   #include <linux/memblock.h>
> >>   #include <linux/memory.h>
> >>   #include <linux/mm.h>
> >> +#include <linux/sched/clock.h>
> >>   #include <linux/stackdepot.h>
> >>   #include <linux/static_key.h>
> >>   #include <linux/string.h>
> >> @@ -93,6 +94,19 @@ void __init kasan_init_tags(void)
> >>          }
> >>   }
> >>
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +static void save_extra_info(struct kasan_stack_ring_entry *entry)
> >> +{
> >> +       u32 cpu = raw_smp_processor_id();
> >> +       u64 ts_nsec = local_clock();
> >> +       unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
> >> +
> >> +       entry->cpu = cpu;
> >> +       entry->ts_sec = ts_nsec;
> >> +       entry->ts_usec = rem_usec;
> >
> > I would timestamp as a single field in all structs and convert it to
> > sec/usec only when we print it. It would make all initialization and
> > copying shorter. E.g. this function can be just:
> >
> >         entry->cpu = raw_smp_processor_id();
> >         entry->timestamp = local_clock() / 1024;
> >
> > Dividing by 1024 is much faster and gives roughly the same precision.
> > This can be unscaled during reporting:
> >
> >         u64 sec = entry->timestamp * 1024;
> >         unsigned long usec = do_div(sec, NSEC_PER_SEC) / 1000;
> >
> > But otherwise the patch looks good to me.
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> >
>
>
> I think it would be better to use left shift and right shift because
> dropping the last 3 bits would not affect the microsecond part and
> would not affect the precision at all.
>
> In addition, 44 bits are enough to store the maximum value of the
> displayable time 99999.999999 (5-bit seconds + 6-bit microseconds).
>
> 010110101111001100010000011110100011111111111111 (99999.999999) >> 3
> = 10110101111001100010000011110100011111111111 (44 bits)
>
> I will send the V3 patch.

Agree.
Modern compilers are smart enough to turn division/multiplication by
pow-2 const into necessary shift, so we may not obfuscate the code.


> >> +}
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >> +
> >>   static void save_stack_info(struct kmem_cache *cache, void *object,
> >>                          gfp_t gfp_flags, bool is_free)
> >>   {
> >> @@ -128,6 +142,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
> >>          entry->pid = current->pid;
> >>          entry->stack = stack;
> >>          entry->is_free = is_free;
> >> +#ifdef CONFIG_KASAN_EXTRA_INFO
> >> +       save_extra_info(entry);
> >> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> >>
> >>          entry->ptr = object;
> >>
> >> --
> >> 2.39.2
> >>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYDnXD3SeordJ8X6tQO%2B7nr5VuWVrJ-DUi3BXac0zdVxw%40mail.gmail.com.
