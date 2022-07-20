Return-Path: <kasan-dev+bncBDPPFIEASMFBBXWD4CLAMGQEC7GDCYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F36257BA9A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:40:14 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id e5-20020adfa445000000b0021e45ff3413sf706209wra.14
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:40:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331614; cv=pass;
        d=google.com; s=arc-20160816;
        b=U16JIx8/hepewaiwBNdM4jRCmtcQnn02kls5rpOwRh2S3snx6bqAo4oyC7FcHLOSfm
         64JTE5TSqj2RVgr24UfRGo47vsuwD+t0vlYLGFbPFO1fIK+IOOfOxO+oxG4tSSJUSdeI
         8hrG1qdNS86LWQ+SBa0KL7PHcQVLtXeVaOa2VkO91gN6ivef+0bC6uxwIteqil6N9gTw
         1FChKhR9Vjd+pGUzZDXzex4IqavB8w6rNFWSbL3kCVuJ4ScII0YjzickrS3HXCQKoWmo
         BFr7rG2Q+Rxx/+PzEMwSVYLzoDJpeYDQ6J5Mch44hnSkb8FvogBG/Hj5LditVzg8DGn8
         azwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NqKhBIr/UWkTDhLY1SlXTURP52N2g2GAciZNa2tjVIs=;
        b=i8mE9I8kzGjOU2wMrevIyWcF1iWw7VRRw45PTXJy82Y2JQSt0kQoJHGpYw8lDMWhy8
         KpHlWSo34LgeCgf6QMxWK8s2X6Bhqbq6ka/IFekVBuTiDYR+ZXu7THffb7xF+BASWI5z
         1nB8dvgcWWFg8teHz4gUO06Hf4/IQLRwL6bPDNoneBO64qeNlWvySQlSbO72bu56s3Re
         KtujfYwKymfHmUAVCWRWDNr9Jl4w+J1EfWuMld3dl959DI0dEftKrSbLzS5NThSxKCcA
         3yRzoERNzCMYuujqpL0Q2D5/stwdGBaYcOO1+lUuBDkyWLwqkKe69MbxDnYrmo7Nzad+
         NEeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fL48WuRK;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NqKhBIr/UWkTDhLY1SlXTURP52N2g2GAciZNa2tjVIs=;
        b=V6lfvo1Gg4TIS3Y4I7XSh7DJJ6N5ayG/IRE8SOkm53rDKXE6GFDWCzGALfWzvRWFP6
         ik7XlevdDtTVpx+QtmEIkwkcayvBEKETkjO8MehUE9RB5vOQ1KiKushyAi14B38iBPeZ
         dOoKVXDhwy21cViYpqUrSxAgqHefUVvWef6VHx2ehuxJTy+whXJJ/vE8Uv23iY4Exr5F
         Lm9U0nhf32VhSLUgGm4gmTetr9OhX0QoAbABkcRk9t0DmZV8R6wytYOxUGgVh/RT4ZQt
         hXiLSp+MeaLclC5o4N38XL+j2J/S9G8SE3OhA5+HWVPGCC1vD922FVsocArTAO3iIhT0
         KXhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NqKhBIr/UWkTDhLY1SlXTURP52N2g2GAciZNa2tjVIs=;
        b=hdzmdsHeaf8AgUa6Wt0vZY15MKPxnxFHNfERxxY5rdljQ3IrV0P/71CzrFrmBvnKXg
         0jujrOrJfahB1xV8QshnmC32PoRsshf2IBxyaAp+rdxsy1x3g7wJrbQnQ3JjIZJ0obZ0
         a6YLaCtZQWX/0LcN9FqNlH3XKgrh+O8etElb73oqZOyh4/cwmz5ytHxTDsLm3byFWR80
         oSyQlm6Qhyj6d2uHoO9QkP97H6r6V5+q2zeJmo/o1OkDt2B6xmGnhJKVwSfPshHyeUS6
         RerKvopfTRZ3n01j7cYq5PWuBPeIEwkRxAy6sAGmd9vd/NkGwY4BfrD36MyL8A+0b+pQ
         kSpA==
X-Gm-Message-State: AJIora+gVEM9LJeXCVkY9/EhzyeUkHWL8y3XVNq7jvVxQOf9RROKxxqb
	k4mI0AHjtLd4O/Vef+ffQxM=
X-Google-Smtp-Source: AGRyM1trTtTl1zTSbh3xiExCMNQy+/Memd+tMXHQ638h0RWE0CAw6AMsbNBeikOm5GY9P4oH8AdNKQ==
X-Received: by 2002:a1c:f019:0:b0:3a3:1116:1727 with SMTP id a25-20020a1cf019000000b003a311161727mr4523495wmb.71.1658331614296;
        Wed, 20 Jul 2022 08:40:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f415:0:b0:397:d1d5:9b4e with SMTP id z21-20020a1cf415000000b00397d1d59b4els928401wma.3.-pod-control-gmail;
 Wed, 20 Jul 2022 08:40:13 -0700 (PDT)
X-Received: by 2002:a05:600c:4e8f:b0:3a1:8b21:ebbc with SMTP id f15-20020a05600c4e8f00b003a18b21ebbcmr4514258wmq.149.1658331613454;
        Wed, 20 Jul 2022 08:40:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331613; cv=none;
        d=google.com; s=arc-20160816;
        b=xBe03K6QGz/YYh0WF1my7NGt10QoFGQxP4DyJwaYxmnAxv4aZUavW7iGp8VfD7Jr8Z
         CMXQ3UncNQaevz5TTnPs4JRdnS7tRvcgL4TS3RUd7iR+Y+bKV2z5St9Wiv56ElLPwbii
         M4y5LlVZbwOcbLJyFPKRk5/Y90AimmX1WfyotEHCKUdeVE0QWS77HFSwOXPj49C8WnKB
         AQYrGFqsWmlWgXC2U3MeCA/qrVxTnXxI/xOrlZhuikcBXE90BNbWvTFt8NU2LEDBjd5/
         qbzAADFB0dOD37ng1t2ProTH/0bz+//3U3xYOHygxHp/6QiwVf2wDlG8oNOCp7yLSfr/
         gGag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BfOYEoaq+RNfeRfiK+P7IRpz2zKNnjNtUDOpewE84TE=;
        b=LuqsjlExNhYWSYgCytGcaY7jfM0eDeASaw2A0QYfP1P2V/VZ5r1J+w/iFpgjxKKlfd
         xNFmavon7w9R3tCvtGeYnzrSMQb36jpfxsDR7JN6Z+BtPnuoEFajw1OXJ9B9q6r915GS
         h40H3F8MnmLTBxzcTaMgbCq78P6EYWpH90PBJSlsiztwEaVVnHPWb03Ps7dy2NqQbOU2
         FoS4X2eTWVtlMZTH3a56jIzbJP9yR4zHrItB2+CCAONBxOEh7WwOJID3zPfawQs0PVyb
         KHHjbDpOUSV7EKF/EhL6yaxy4NdNln2MONfsS4jT/GSrHof9Tznh5Q7vsQPqBjzkxvr+
         sx5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fL48WuRK;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id q19-20020a7bce93000000b003a2ca59af2dsi104016wmj.1.2022.07.20.08.40.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:40:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id n185so11100962wmn.4
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:40:13 -0700 (PDT)
X-Received: by 2002:a7b:ce13:0:b0:3a3:102c:23d3 with SMTP id
 m19-20020a7bce13000000b003a3102c23d3mr4361425wmc.67.1658331612893; Wed, 20
 Jul 2022 08:40:12 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-13-elver@google.com>
In-Reply-To: <20220704150514.48816-13-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:40:00 -0700
Message-ID: <CAP-5=fUK6HfWPLLHtFszEdkv_EVuoxgW88jj7xtpRHM8OGSBmg@mail.gmail.com>
Subject: Re: [PATCH v3 12/14] perf/hw_breakpoint: Introduce bp_slots_histogram
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fL48WuRK;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::335
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Jul 4, 2022 at 8:07 AM Marco Elver <elver@google.com> wrote:
>
> Factor out the existing `atomic_t count[N]` into its own struct called
> 'bp_slots_histogram', to generalize and make its intent clearer in
> preparation of reusing elsewhere. The basic idea of bucketing "total
> uses of N slots" resembles a histogram, so calling it such seems most
> intuitive.
>
> No functional change.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

> ---
> v3:
> * Also warn in bp_slots_histogram_add() if count goes below 0.
>
> v2:
> * New patch.
> ---
>  kernel/events/hw_breakpoint.c | 96 +++++++++++++++++++++++------------
>  1 file changed, 63 insertions(+), 33 deletions(-)
>
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index 229c6f4fae75..03ebecf048c0 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -36,19 +36,27 @@
>  #include <linux/slab.h>
>
>  /*
> - * Constraints data
> + * Datastructure to track the total uses of N slots across tasks or CPUs;
> + * bp_slots_histogram::count[N] is the number of assigned N+1 breakpoint slots.
>   */
> -struct bp_cpuinfo {
> -       /* Number of pinned cpu breakpoints in a cpu */
> -       unsigned int    cpu_pinned;
> -       /* tsk_pinned[n] is the number of tasks having n+1 breakpoints */
> +struct bp_slots_histogram {
>  #ifdef hw_breakpoint_slots
> -       atomic_t        tsk_pinned[hw_breakpoint_slots(0)];
> +       atomic_t count[hw_breakpoint_slots(0)];
>  #else
> -       atomic_t        *tsk_pinned;
> +       atomic_t *count;
>  #endif
>  };
>
> +/*
> + * Per-CPU constraints data.
> + */
> +struct bp_cpuinfo {
> +       /* Number of pinned CPU breakpoints in a CPU. */
> +       unsigned int                    cpu_pinned;
> +       /* Histogram of pinned task breakpoints in a CPU. */
> +       struct bp_slots_histogram       tsk_pinned;
> +};
> +
>  static DEFINE_PER_CPU(struct bp_cpuinfo, bp_cpuinfo[TYPE_MAX]);
>
>  static struct bp_cpuinfo *get_bp_info(int cpu, enum bp_type_idx type)
> @@ -159,6 +167,18 @@ static inline int hw_breakpoint_slots_cached(int type)
>         return __nr_bp_slots[type];
>  }
>
> +static __init bool
> +bp_slots_histogram_alloc(struct bp_slots_histogram *hist, enum bp_type_idx type)
> +{
> +       hist->count = kcalloc(hw_breakpoint_slots_cached(type), sizeof(*hist->count), GFP_KERNEL);
> +       return hist->count;
> +}
> +
> +static __init void bp_slots_histogram_free(struct bp_slots_histogram *hist)
> +{
> +       kfree(hist->count);
> +}
> +
>  static __init int init_breakpoint_slots(void)
>  {
>         int i, cpu, err_cpu;
> @@ -170,8 +190,7 @@ static __init int init_breakpoint_slots(void)
>                 for (i = 0; i < TYPE_MAX; i++) {
>                         struct bp_cpuinfo *info = get_bp_info(cpu, i);
>
> -                       info->tsk_pinned = kcalloc(__nr_bp_slots[i], sizeof(atomic_t), GFP_KERNEL);
> -                       if (!info->tsk_pinned)
> +                       if (!bp_slots_histogram_alloc(&info->tsk_pinned, i))
>                                 goto err;
>                 }
>         }
> @@ -180,7 +199,7 @@ static __init int init_breakpoint_slots(void)
>  err:
>         for_each_possible_cpu(err_cpu) {
>                 for (i = 0; i < TYPE_MAX; i++)
> -                       kfree(get_bp_info(err_cpu, i)->tsk_pinned);
> +                       bp_slots_histogram_free(&get_bp_info(err_cpu, i)->tsk_pinned);
>                 if (err_cpu == cpu)
>                         break;
>         }
> @@ -189,6 +208,34 @@ static __init int init_breakpoint_slots(void)
>  }
>  #endif
>
> +static inline void
> +bp_slots_histogram_add(struct bp_slots_histogram *hist, int old, int val)
> +{
> +       const int old_idx = old - 1;
> +       const int new_idx = old_idx + val;
> +
> +       if (old_idx >= 0)
> +               WARN_ON(atomic_dec_return_relaxed(&hist->count[old_idx]) < 0);
> +       if (new_idx >= 0)
> +               WARN_ON(atomic_inc_return_relaxed(&hist->count[new_idx]) < 0);
> +}
> +
> +static int
> +bp_slots_histogram_max(struct bp_slots_histogram *hist, enum bp_type_idx type)
> +{
> +       for (int i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
> +               const int count = atomic_read(&hist->count[i]);
> +
> +               /* Catch unexpected writers; we want a stable snapshot. */
> +               ASSERT_EXCLUSIVE_WRITER(hist->count[i]);
> +               if (count > 0)
> +                       return i + 1;
> +               WARN(count < 0, "inconsistent breakpoint slots histogram");
> +       }
> +
> +       return 0;
> +}
> +
>  #ifndef hw_breakpoint_weight
>  static inline int hw_breakpoint_weight(struct perf_event *bp)
>  {
> @@ -205,13 +252,11 @@ static inline enum bp_type_idx find_slot_idx(u64 bp_type)
>  }
>
>  /*
> - * Report the maximum number of pinned breakpoints a task
> - * have in this cpu
> + * Return the maximum number of pinned breakpoints a task has in this CPU.
>   */
>  static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>  {
> -       atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
> -       int i;
> +       struct bp_slots_histogram *tsk_pinned = &get_bp_info(cpu, type)->tsk_pinned;
>
>         /*
>          * At this point we want to have acquired the bp_cpuinfo_sem as a
> @@ -219,14 +264,7 @@ static unsigned int max_task_bp_pinned(int cpu, enum bp_type_idx type)
>          * toggle_bp_task_slot() to tsk_pinned, and we get a stable snapshot.
>          */
>         lockdep_assert_held_write(&bp_cpuinfo_sem);
> -
> -       for (i = hw_breakpoint_slots_cached(type) - 1; i >= 0; i--) {
> -               ASSERT_EXCLUSIVE_WRITER(tsk_pinned[i]); /* Catch unexpected writers. */
> -               if (atomic_read(&tsk_pinned[i]) > 0)
> -                       return i + 1;
> -       }
> -
> -       return 0;
> +       return bp_slots_histogram_max(tsk_pinned, type);
>  }
>
>  /*
> @@ -300,8 +338,7 @@ max_bp_pinned_slots(struct perf_event *bp, enum bp_type_idx type)
>  static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
>                                 enum bp_type_idx type, int weight)
>  {
> -       atomic_t *tsk_pinned = get_bp_info(cpu, type)->tsk_pinned;
> -       int old_idx, new_idx;
> +       struct bp_slots_histogram *tsk_pinned = &get_bp_info(cpu, type)->tsk_pinned;
>
>         /*
>          * If bp->hw.target, tsk_pinned is only modified, but not used
> @@ -311,14 +348,7 @@ static void toggle_bp_task_slot(struct perf_event *bp, int cpu,
>          * bp_cpuinfo_sem as a writer to stabilize tsk_pinned's value.
>          */
>         lockdep_assert_held_read(&bp_cpuinfo_sem);
> -
> -       old_idx = task_bp_pinned(cpu, bp, type) - 1;
> -       new_idx = old_idx + weight;
> -
> -       if (old_idx >= 0)
> -               atomic_dec(&tsk_pinned[old_idx]);
> -       if (new_idx >= 0)
> -               atomic_inc(&tsk_pinned[new_idx]);
> +       bp_slots_histogram_add(tsk_pinned, task_bp_pinned(cpu, bp, type), weight);
>  }
>
>  /*
> @@ -768,7 +798,7 @@ bool hw_breakpoint_is_used(void)
>                                 return true;
>
>                         for (int slot = 0; slot < hw_breakpoint_slots_cached(type); ++slot) {
> -                               if (atomic_read(&info->tsk_pinned[slot]))
> +                               if (atomic_read(&info->tsk_pinned.count[slot]))
>                                         return true;
>                         }
>                 }
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfUK6HfWPLLHtFszEdkv_EVuoxgW88jj7xtpRHM8OGSBmg%40mail.gmail.com.
