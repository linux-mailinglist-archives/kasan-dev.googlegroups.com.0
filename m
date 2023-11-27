Return-Path: <kasan-dev+bncBCMIZB7QWENRBXNYSCVQMGQEFTCEI4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C0B37F9864
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 05:34:40 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-50aa6b1bea6sf3634829e87.1
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Nov 2023 20:34:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701059679; cv=pass;
        d=google.com; s=arc-20160816;
        b=iUNUi7cMUmcVtb6NB+aDST+YAKgGTNpiU4KfyaBdVVvSoHnUOoQLWcW3O29DIfN7C2
         cOw5Wk4dD5f7JAEU7NqHuDyjEi4lLypCdG7AoU7q3R4ZIO2TE/gaGRI7A5QAya317X/u
         ltqgdjAsE3IjtWsS+FsB0LvymkqPgV5MeKDIuiOdAmfeNZOd56sGWyJd9928A6q39oQ1
         PtWBW7fjfejNwiu7Jc6Tcv9F7k4Wg+I90o3sPFdKeSIYAa/dkU8/ll1fNOhkheZKWfm9
         vxFYjZwa0Vl5BYUEmk4k4w7V4RLiyN8UH50B26tMTOX7bIy7zNf+Admmz8JyL20fOppI
         SfHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Czg08R3e3e88RmDfIiFdxa7tflvGbDbkeSnB8lYQWyg=;
        fh=Cxdz3lXx9q85yacnGVuiIilAYWk/9KO8DtHEl0n0w48=;
        b=cGwyg3vz6gTPR0ojrSb4XFsYcEzQ8ZwebdwTrUMzozi7EMvWFMLKLSJaWBJYKTen2K
         aIPg1KK9GzjSBeKXOxnVGHwXYSX9T57SBTA3YTWxWWyJGFIGE/WgZ5iWKrW23ORvJqbp
         oBoact2jtgRdYFFjjTYoqRi9/OvxKwR7kMEerLOm1ZbCgQI2s+SVkI/vinzDuYu5+NbG
         VqEogXGq+7gGsLOirMFwgixS6ntavxplayL3QbU07VdJ9Dn3UQBx0KvpNM2o/VpOyihP
         3K5ebLfVrkP6BrxFVOfioyKvkinaYVpMU4tuVXaETqi5CIm9uqRhC6yI6GHbvWLYY6Rk
         FzFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UOwwO4W2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701059679; x=1701664479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Czg08R3e3e88RmDfIiFdxa7tflvGbDbkeSnB8lYQWyg=;
        b=khEjej0U8YGSGbxQCjoQ0QeR8g1gZki5Q69sVWOeq/rrR5YU3opGVJu+P++c7UDVNz
         8USXH08u8jAPOCPaUUOB7jnr6zzZz2n4RTOD/GI87BHv4Ln6grxAhBa1yCMbntVj3Ca/
         Wb0PR0zqTZu/jg5za0AvwbT7h+hQRXPehfUIRV2C9NaSd9a8EwoJmoCMRF3nUfsgIE7e
         uxt/TJ9nFzgIp+xLIjyRmS+hfTsoMa3TdON4byXpJXvLII9HPWJskcRpK9dPxHUb7oI0
         8atLEOrR0tMNbax//pt5iYnCpzJko6H29/SRf6U2E6Gpwwv5U4Bx+LZmS72ymuyQ0VAy
         Gydg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701059679; x=1701664479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Czg08R3e3e88RmDfIiFdxa7tflvGbDbkeSnB8lYQWyg=;
        b=w15C8wOXLgDzYF6rfmG1cHUVSShYgvKKuwor1uLDC9njN7p0qcbed6VsH2TL3XnJof
         4O1U5WcRBBNIWfjJCTKaGhyzjcpOwJNOms97+L9WXh+ECcqPrcK6+OzEQba8fekh7k6g
         CvvpchStBVhYnZEEVERq601fZSFf9FrL6fEp/0V48jWUAoRp31NbqVPDbN22GpXPz8UN
         J9LPG2bgcmvZ9Ywj6ZWLIUrzTobL+Zx+3Bu+m2L8ROWOTr3EgekZopHrD1IUVChx0LpM
         KrSgiftdJPuPUgK/5xTd/i+nukkyat8gC2fT14YQxbBjq7+RD7AN3UmKmnUCWfPvwMXd
         c/HQ==
X-Gm-Message-State: AOJu0Yyho8sjPjgjU3w/7C17bdFqKCkHAXiLpVf/QMKjI6NyzaR3pKGW
	DYJUNh46FP2fnRLLopwqTQougA==
X-Google-Smtp-Source: AGHT+IGix2v5N3q3sgrYFYWFfKKdQxPsq58O0ftplXMVJg/C63Bb4UlVTdk8YkNtSTWKYnqrN0KluA==
X-Received: by 2002:a05:6512:239e:b0:50a:763f:ecf1 with SMTP id c30-20020a056512239e00b0050a763fecf1mr9477470lfv.12.1701059678113;
        Sun, 26 Nov 2023 20:34:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ca7:b0:4f9:5599:26a with SMTP id
 h39-20020a0565123ca700b004f95599026als447376lfv.2.-pod-prod-08-eu; Sun, 26
 Nov 2023 20:34:36 -0800 (PST)
X-Received: by 2002:ac2:532f:0:b0:509:e5a4:2af2 with SMTP id f15-20020ac2532f000000b00509e5a42af2mr6887084lfh.49.1701059676138;
        Sun, 26 Nov 2023 20:34:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701059676; cv=none;
        d=google.com; s=arc-20160816;
        b=U2OwUWufxPe9s4Y/vz+qWuhK1DzakYMSIZheztZ6gSVAEEfUzEXFmIrDR7GRF3h1xG
         YAzKKG7HWJeUE+zHaeb+PP7bxSqBc7oAhY9jUE4JcKyLAP/JmvFimTC376XVCiCzSIl+
         gFI0gO3TT35vVMnRiOWq7IS8FsOtzQ/vEDgC7ATvA0XN+E0lAsFTrnX/bQjV+ssxcVBm
         Yg10mlqmIcVggmPLvW6pEs6rzvBALJopyzQUIVCUa5SugdlZJNXVdCBmPmycq1z3Gk8F
         PU3B2AHD6xKk5un2C9NLcbxoh4nAwnA98DO/HpCnDDZcqJP5K2u+XB1NyUBlyuw6hcfP
         IiDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IXbKy2pJw1weWM2AUX6qsAkpX0IgEY8LocF0NM/epjw=;
        fh=Cxdz3lXx9q85yacnGVuiIilAYWk/9KO8DtHEl0n0w48=;
        b=C137mIhODAyF/sJtZtzCicFOqOfSqMz5rQ0vx7emiUKcajjIraBOghmCZH7NkJpIfn
         ULfdpsDYkMbBaCqom2T2QLo72eetA/uRumgxwZbdg688JqqSTqqY2IXuWpAtvKG6Npmc
         fl3UUDYcA//pwHH8zil8pIeemBO7S5yVUUFFJtm7WtkqVDPMfC3NwnXuHPp3tlPnJEb3
         /CIrFgvDuOHKIWqrbkzErECQZ6JDIKYevFg4RmMarpJiqZ+/TS7W3MmdY/vI8ciVGPML
         4A+Oc1XM6R9R39ume2yokJGjOpbFo3Ylk/a668DA8WPnGOSn2ObktkbMDbjoeDdxTWlK
         Ga+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UOwwO4W2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id dw27-20020a0565122c9b00b0050446001e0bsi430970lfb.3.2023.11.26.20.34.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 26 Nov 2023 20:34:36 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-50ba8177c9fso3614e87.1
        for <kasan-dev@googlegroups.com>; Sun, 26 Nov 2023 20:34:36 -0800 (PST)
X-Received: by 2002:a05:6512:239e:b0:501:a2b9:6046 with SMTP id
 c30-20020a056512239e00b00501a2b96046mr452354lfv.7.1701059675534; Sun, 26 Nov
 2023 20:34:35 -0800 (PST)
MIME-Version: 1.0
References: <VI1P193MB07529BC28E5B333A8526BEBD99BEA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
In-Reply-To: <VI1P193MB07529BC28E5B333A8526BEBD99BEA@VI1P193MB0752.EURP193.PROD.OUTLOOK.COM>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 27 Nov 2023 05:34:22 +0100
Message-ID: <CACT4Y+aVjKTxTamnybC9gS7uvSodYjvHst9obo=GjJ_km-_pdw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Record and report more information
To: Juntong Deng <juntong.deng@outlook.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-kernel-mentees@lists.linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UOwwO4W2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e
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

On Sun, 26 Nov 2023 at 23:25, Juntong Deng <juntong.deng@outlook.com> wrote:
>
> Record and report more information to help us find the cause of the
> bug and to help us correlate the error with other system events.
>
> This patch adds recording and showing CPU number and timestamp at
> allocation and free (controlled by CONFIG_KASAN_EXTRA_INFO). The
> timestamps in the report use the same format and source as printk.
>
> Error occurrence timestamp is already implicit in the printk log,
> and CPU number is already shown by dump_stack_lvl, so there is no
> need to add it.
>
> In order to record CPU number and timestamp at allocation and free,
> corresponding members need to be added to the relevant data structures,
> which will lead to increased memory consumption.
>
> In Generic KASAN, members are added to struct kasan_track. Since in
> most cases, alloc meta is stored in the redzone and free meta is
> stored in the object or the redzone, memory consumption will not
> increase much.
>
> In SW_TAGS KASAN and HW_TAGS KASAN, members are added to
> struct kasan_stack_ring_entry. Memory consumption increases as the
> size of struct kasan_stack_ring_entry increases (this part of the
> memory is allocated by memblock), but since this is configurable,
> it is up to the user to choose.
>
> Signed-off-by: Juntong Deng <juntong.deng@outlook.com>
> ---
> V1 -> V2: Use bit field to reduce memory consumption. Add more detailed
> config help. Cancel printing of redundant error occurrence timestamp.
>
>  lib/Kconfig.kasan      | 21 +++++++++++++++++++++
>  mm/kasan/common.c      | 10 ++++++++++
>  mm/kasan/kasan.h       | 10 ++++++++++
>  mm/kasan/report.c      |  6 ++++++
>  mm/kasan/report_tags.c | 16 ++++++++++++++++
>  mm/kasan/tags.c        | 17 +++++++++++++++++
>  6 files changed, 80 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 935eda08b1e1..8653f5c38be7 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -207,4 +207,25 @@ config KASAN_MODULE_TEST
>           A part of the KASAN test suite that is not integrated with KUnit.
>           Incompatible with Hardware Tag-Based KASAN.
>
> +config KASAN_EXTRA_INFO
> +       bool "Record and report more information"
> +       depends on KASAN
> +       help
> +         Record and report more information to help us find the cause of the
> +         bug and to help us correlate the error with other system events.
> +
> +         Currently, the CPU number and timestamp are additionally
> +         recorded for each heap block at allocation and free time, and
> +         8 bytes will be added to each metadata structure that records
> +         allocation or free information.
> +
> +         In Generic KASAN, each kmalloc-8 and kmalloc-16 object will add
> +         16 bytes of additional memory consumption, and each kmalloc-32
> +         object will add 8 bytes of additional memory consumption, not
> +         affecting other larger objects.
> +
> +         In SW_TAGS KASAN and HW_TAGS KASAN, depending on the stack_ring_size
> +         boot parameter, it will add 8 * stack_ring_size bytes of additional
> +         memory consumption.
> +
>  endif # KASAN
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index b5d8bd26fced..2f0884c762b7 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -20,6 +20,7 @@
>  #include <linux/module.h>
>  #include <linux/printk.h>
>  #include <linux/sched.h>
> +#include <linux/sched/clock.h>
>  #include <linux/sched/task_stack.h>
>  #include <linux/slab.h>
>  #include <linux/stackdepot.h>
> @@ -49,6 +50,15 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags)
>
>  void kasan_set_track(struct kasan_track *track, gfp_t flags)
>  {
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       u32 cpu = raw_smp_processor_id();
> +       u64 ts_nsec = local_clock();
> +       unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
> +
> +       track->cpu = cpu;
> +       track->ts_sec = ts_nsec;
> +       track->ts_usec = rem_usec;
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>         track->pid = current->pid;
>         track->stack = kasan_save_stack(flags,
>                         STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index b29d46b83d1f..2a37baa4ce2f 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -187,6 +187,11 @@ static inline bool kasan_requires_meta(void)
>  struct kasan_track {
>         u32 pid;
>         depot_stack_handle_t stack;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       u64 cpu:20;
> +       u64 ts_sec:22;
> +       u64 ts_usec:22;
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>  };
>
>  enum kasan_report_type {
> @@ -278,6 +283,11 @@ struct kasan_stack_ring_entry {
>         u32 pid;
>         depot_stack_handle_t stack;
>         bool is_free;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       u64 cpu:20;
> +       u64 ts_sec:22;
> +       u64 ts_usec:22;
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>  };
>
>  struct kasan_stack_ring {
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index e77facb62900..8cd8f6e5cf24 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -262,7 +262,13 @@ static void print_error_description(struct kasan_report_info *info)
>
>  static void print_track(struct kasan_track *track, const char *prefix)
>  {
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       pr_err("%s by task %u on cpu %d at %u.%06us:\n",
> +                       prefix, track->pid, track->cpu,
> +                       track->ts_sec, track->ts_usec);
> +#else
>         pr_err("%s by task %u:\n", prefix, track->pid);
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>         if (track->stack)
>                 stack_depot_print(track->stack);
>         else
> diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
> index 55154743f915..bf895b1d2dc2 100644
> --- a/mm/kasan/report_tags.c
> +++ b/mm/kasan/report_tags.c
> @@ -27,6 +27,16 @@ static const char *get_common_bug_type(struct kasan_report_info *info)
>         return "invalid-access";
>  }
>
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +static void kasan_complete_extra_report_info(struct kasan_track *track,
> +                                        struct kasan_stack_ring_entry *entry)
> +{
> +       track->cpu = entry->cpu;
> +       track->ts_sec = entry->ts_sec;
> +       track->ts_usec = entry->ts_usec;
> +}
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> +
>  void kasan_complete_mode_report_info(struct kasan_report_info *info)
>  {
>         unsigned long flags;
> @@ -73,6 +83,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>
>                         info->free_track.pid = entry->pid;
>                         info->free_track.stack = entry->stack;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +                       kasan_complete_extra_report_info(&info->free_track, entry);
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>                         free_found = true;
>
>                         /*
> @@ -88,6 +101,9 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
>
>                         info->alloc_track.pid = entry->pid;
>                         info->alloc_track.stack = entry->stack;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +                       kasan_complete_extra_report_info(&info->alloc_track, entry);
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>                         alloc_found = true;
>
>                         /*
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 739ae997463d..c172e115b9bb 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -13,6 +13,7 @@
>  #include <linux/memblock.h>
>  #include <linux/memory.h>
>  #include <linux/mm.h>
> +#include <linux/sched/clock.h>
>  #include <linux/stackdepot.h>
>  #include <linux/static_key.h>
>  #include <linux/string.h>
> @@ -93,6 +94,19 @@ void __init kasan_init_tags(void)
>         }
>  }
>
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +static void save_extra_info(struct kasan_stack_ring_entry *entry)
> +{
> +       u32 cpu = raw_smp_processor_id();
> +       u64 ts_nsec = local_clock();
> +       unsigned long rem_usec = do_div(ts_nsec, NSEC_PER_SEC) / 1000;
> +
> +       entry->cpu = cpu;
> +       entry->ts_sec = ts_nsec;
> +       entry->ts_usec = rem_usec;

I would timestamp as a single field in all structs and convert it to
sec/usec only when we print it. It would make all initialization and
copying shorter. E.g. this function can be just:

       entry->cpu = raw_smp_processor_id();
       entry->timestamp = local_clock() / 1024;

Dividing by 1024 is much faster and gives roughly the same precision.
This can be unscaled during reporting:

       u64 sec = entry->timestamp * 1024;
       unsigned long usec = do_div(sec, NSEC_PER_SEC) / 1000;

But otherwise the patch looks good to me.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> +}
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
> +
>  static void save_stack_info(struct kmem_cache *cache, void *object,
>                         gfp_t gfp_flags, bool is_free)
>  {
> @@ -128,6 +142,9 @@ static void save_stack_info(struct kmem_cache *cache, void *object,
>         entry->pid = current->pid;
>         entry->stack = stack;
>         entry->is_free = is_free;
> +#ifdef CONFIG_KASAN_EXTRA_INFO
> +       save_extra_info(entry);
> +#endif /* CONFIG_KASAN_EXTRA_INFO */
>
>         entry->ptr = object;
>
> --
> 2.39.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaVjKTxTamnybC9gS7uvSodYjvHst9obo%3DGjJ_km-_pdw%40mail.gmail.com.
