Return-Path: <kasan-dev+bncBCMIZB7QWENRBG5X3CMAMGQE4XAV3BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id ED1235AD6E9
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 17:54:04 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id o23-20020ac25e37000000b0049475eb7a25sf1923865lfg.20
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 08:54:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662393244; cv=pass;
        d=google.com; s=arc-20160816;
        b=gutA9xRuVjqM7ojBvkyTI7dsWwKsDtZZFWgghFLkT4dNUdAbrhfr0XgeOSMxSD1GPk
         0OLSdDgPVzWOgXhb+hm04CSyiYZLKI/ZVTekBSMQkAGGucv32zazsZYxaMzuZbTRUb8v
         joEwgyrsHjSBsRnglYmE4TgrQLQHODKMXk2CibkXfilFAnv3V/SSBgiV4vTj+RsyqLCY
         NEFNHI7Cunhj+pR21Uqcxjj+4Z9JN2IafRDVoEQf0voc0UxD4Q7X6edfnWdgreYLweP6
         pJF2RQG4LQgYqProcpiLTsAiUgZGvL+a7/IeY2IzSUgkgnEjdsuCQesmMeG6lV5xIe8s
         izIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+rQczjOt7s0Idgmn8wMaYIkua2Ce6VQSEx2tGa5YY8U=;
        b=gLyq1rkgWt5GgoZqK7yRu1UFTjgrwyhq8/aDNjCPoDoliJlPJCq3w3Ki6N7Ke7tgXC
         dW7tMnquPF8BtrueQfOZqjxxNnGAHVeshpdaZFURHDu2v2nwKxnb4rRgjxAC2PeThWGR
         KN9IRgUypsn6oKzfCUcfknCHq21ta9h3juJb95a2Ms1jOBOByK3XeEicaVkLBrFHlCJG
         wpPRFM1szWC9sP2IUBeDnPqBXq9D5+G+oOkO3MK7PZYa7EbjfA+Vp8i3I1ME9b18KCZY
         Rj5Wkhpe+TvFFvB+/iTYnHYyzX81m2vR7IH3yrYl+9oNtd5n30ieb7TdayC50DuSSSSW
         w//g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EvKjans9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=+rQczjOt7s0Idgmn8wMaYIkua2Ce6VQSEx2tGa5YY8U=;
        b=eBNNxiXmhs30a0JuBgtCcClNevReeQlxWkY/sSoShs2VWpZyqJ4L17bPJ/R0p6QYdo
         NO0h/ZDKLdppGvObWOpJGJHYx+G/S/0eCMvyz995bEjpCQLCEOE7UrGo+15KIXXN0Hsk
         CZ+o5AMdvb6sephb/kUjwYBxN6VxG4U2LqylpIiRUcOE7h4Ghba6Cqqk8WY7cx6wm7ok
         OrlTTWBAxgeFZKvFXR5NHo3RAohjDcjH2wNRy2KcJQ+prHPdRo/eLb+pnS6VeMccEmzo
         dsQ6CG3nVnm9LlLZYf/cyPCysq/UCy/CLEVEz6spBtyvpF/ZB81sjS0LzxQ0PUkG32BJ
         yfrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=+rQczjOt7s0Idgmn8wMaYIkua2Ce6VQSEx2tGa5YY8U=;
        b=h2hxrY7x/WpJNF+ywi/JNAqd1K4xS/lmtAUBKsHYy7yLURAau7kaJPE8mX/s8Vogwo
         KNVHU8kxIrUJKRiZOuvwXih097ZvO2akcJ2SbYbpi8gitsuMAPJaDPbp3S17quUWXm+v
         CvgwJ1rg1th8uVu8g3e9J2BfjUlO8wJ6Wkj0puyKdxo7FQo3zxSy1jzp1yWpQzqxIrIA
         9Cepm7xUabRPFrma18krbtVW5grGCydoHqSNtnrDbneXPHjd3boRtFnM2Qq9Og2xB2IX
         NVjEhwLbmMzWVytoQ5MCdwfU2QY5KH9XWhbr5CLQ3DWKImqIplrazjpscEYqJuY5/hKF
         rDog==
X-Gm-Message-State: ACgBeo34V6TzFjn5HULS1VlFfGW2huqC73nT27McHQPSx1hNyDwO6H5K
	KjfKToEPCa2jIN1Lc7ra5Io=
X-Google-Smtp-Source: AA6agR5WTrt/xayoYos+NuMmGmwZkjazJkh4xsEjE2FqOIyQJDGq9lim5+XMtqI5BY4axsCHf3XVkw==
X-Received: by 2002:a05:6512:1293:b0:494:9bf8:d71e with SMTP id u19-20020a056512129300b004949bf8d71emr7244901lfs.558.1662393244300;
        Mon, 05 Sep 2022 08:54:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3fa:b0:494:799f:170 with SMTP id
 n26-20020a05651203fa00b00494799f0170ls5090677lfq.0.-pod-prod-gmail; Mon, 05
 Sep 2022 08:54:03 -0700 (PDT)
X-Received: by 2002:a05:6512:687:b0:494:9733:61fa with SMTP id t7-20020a056512068700b00494973361famr8482697lfe.591.1662393242913;
        Mon, 05 Sep 2022 08:54:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662393242; cv=none;
        d=google.com; s=arc-20160816;
        b=tnceTdz2d261i79ONnPDFCGsVMiryw0ROB/f7aCC2V9yGwe4/+vmWoVhIuAvdog/ND
         gPGpFkdFLXcdS6vZnOJp1uh6K/HZ8MomQuYOWIEf5OQPjLavctCDRjyOrP8OHwCIA5o4
         orPm4qxoZQe9+C5EcjyL04VAOtgTOersc59JiubbMxr9TUK8YwEXgYzdhBvgzEgmRYfL
         k/Jl6FNe6Bf+H5jkI6xmqts8R5RPFZpwS7NeyTVfLpN5kBXRPP8wHPPxGUlcxy2cf1jn
         XC9OEXJfOUqkUMKlyhO7IATE2ukgv2UJLH/DslG11+csGVB5EXm+ErlZX1VFvea9CZiE
         pTfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=axcq0cGN9BhyHQpt/85tTBoyR2tAVPcLTBqmW6py4bI=;
        b=shS4FKpmOfCKYqfZOfVIzqyOKeVi870Dh4zNa9QuK74wsXbEqtWy8zfh5mfQAqlizL
         A4r6CnE/CDuvjo/bbXZFYRI55Tzajw9xK0c3lB8r43c0+UYb7kuoSymSyHdZHPb3zqRy
         vh8XpXuFC+Ds84ZFth8k1ck2tuZm4+wZf5p9bKyDrCcGqSKXyY906unxbQXNDWhCuoJv
         miWYKhA1CRxOA0dTtrlumdez/2qmiv7LaHCzwgr/sdEnnhHR4PpD9tdM1m/V1h5CR/GY
         larq/VSml7x0ViBussYHM2nGHvD0sOSIFA4Zmn0ROHillG//6gClsgVnoy0hOhDB3du3
         EmUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EvKjans9;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id w18-20020a05651234d200b00492d8e5069csi354295lfr.9.2022.09.05.08.54.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 08:54:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id q7so13673722lfu.5
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 08:54:02 -0700 (PDT)
X-Received: by 2002:a05:6512:118b:b0:492:e3c4:a164 with SMTP id
 g11-20020a056512118b00b00492e3c4a164mr17965949lfr.598.1662393242431; Mon, 05
 Sep 2022 08:54:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220902100057.404817-1-elver@google.com>
In-Reply-To: <20220902100057.404817-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Sep 2022 17:53:50 +0200
Message-ID: <CACT4Y+ZCzoK9+3qKOzXSHvZ5cfaXpYXbBL+R9bicapOuRpUNFQ@mail.gmail.com>
Subject: Re: [PATCH] perf: Allow restricted kernel breakpoints on user addresses
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@kernel.org>, 
	Namhyung Kim <namhyung@kernel.org>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EvKjans9;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
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

On Fri, 2 Sept 2022 at 12:01, Marco Elver <elver@google.com> wrote:
>
> Allow the creation of restricted breakpoint perf events that also fire
> in the kernel (!exclude_kernel), if:
>
>   1. No sample information is requested; samples may contain IPs,
>      registers, or other information that may disclose kernel addresses.
>
>   2. The breakpoint (viz. data watchpoint) is on a user address.
>
> The rules constrain the allowable perf events such that no sensitive
> kernel information can be disclosed.
>
> Despite no explicit kernel information disclosure, the following
> questions may need answers:
>
>  1. Is obtaining information that the kernel accessed a particular
>     user's known memory location revealing new information?
>     Given the kernel's user space ABI, there should be no "surprise
>     accesses" to user space memory in the first place.
>
>  2. Does causing breakpoints on user memory accesses by the kernel
>     potentially impact timing in a sensitive way?
>     Since hardware breakpoints trigger regardless of the state of
>     perf_event_attr::exclude_kernel, but are filtered in the perf
>     subsystem, this possibility already exists independent of the
>     proposed change.

I don't see how this gives userspace any new information.
As you noted userspace already should know what userspace addresses
kernel accesses. Additionally since the breakpoint fires anyway (just
filtered out), the fact of it firing should be easily recoverable from
the timing side-channel already. So:

Acked-by: Dmitry Vyukov <dvyukov@google.com>


> Signed-off-by: Marco Elver <elver@google.com>
> ---
>
> Changelog
> ~~~~~~~~~
>
> v1:
> * Rebase.
>
> RFC: https://lkml.kernel.org/r/20220601093502.364142-1-elver@google.com
> ---
>  include/linux/perf_event.h |  8 +-------
>  kernel/events/core.c       | 38 ++++++++++++++++++++++++++++++++++++++
>  2 files changed, 39 insertions(+), 7 deletions(-)
>
> diff --git a/include/linux/perf_event.h b/include/linux/perf_event.h
> index a784e055002e..907b0e3f1318 100644
> --- a/include/linux/perf_event.h
> +++ b/include/linux/perf_event.h
> @@ -1367,13 +1367,7 @@ static inline int perf_is_paranoid(void)
>         return sysctl_perf_event_paranoid > -1;
>  }
>
> -static inline int perf_allow_kernel(struct perf_event_attr *attr)
> -{
> -       if (sysctl_perf_event_paranoid > 1 && !perfmon_capable())
> -               return -EACCES;
> -
> -       return security_perf_event_open(attr, PERF_SECURITY_KERNEL);
> -}
> +extern int perf_allow_kernel(struct perf_event_attr *attr);
>
>  static inline int perf_allow_cpu(struct perf_event_attr *attr)
>  {
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 2621fd24ad26..75f5705b6892 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -3176,6 +3176,12 @@ static int perf_event_modify_attr(struct perf_event *event,
>                 return -EOPNOTSUPP;
>         }
>
> +       if (!event->attr.exclude_kernel) {
> +               err = perf_allow_kernel(attr);
> +               if (err)
> +                       return err;
> +       }
> +
>         WARN_ON_ONCE(event->ctx->parent_ctx);
>
>         mutex_lock(&event->child_mutex);
> @@ -12037,6 +12043,38 @@ perf_check_permission(struct perf_event_attr *attr, struct task_struct *task)
>         return is_capable || ptrace_may_access(task, ptrace_mode);
>  }
>
> +/*
> + * Check if unprivileged users are allowed to set up breakpoints on user
> + * addresses that also count when the kernel accesses them.
> + */
> +static bool perf_allow_kernel_breakpoint(struct perf_event_attr *attr)
> +{
> +       if (attr->type != PERF_TYPE_BREAKPOINT)
> +               return false;
> +
> +       /*
> +        * The sample may contain IPs, registers, or other information that may
> +        * disclose kernel addresses or timing information. Disallow any kind of
> +        * additional sample information.
> +        */
> +       if (attr->sample_type)
> +               return false;
> +
> +       /*
> +        * Only allow kernel breakpoints on user addresses.
> +        */
> +       return access_ok((void __user *)(unsigned long)attr->bp_addr, attr->bp_len);
> +}
> +
> +int perf_allow_kernel(struct perf_event_attr *attr)
> +{
> +       if (sysctl_perf_event_paranoid > 1 && !perfmon_capable() &&
> +           !perf_allow_kernel_breakpoint(attr))
> +               return -EACCES;
> +
> +       return security_perf_event_open(attr, PERF_SECURITY_KERNEL);
> +}
> +
>  /**
>   * sys_perf_event_open - open a performance event, associate it to a task/cpu
>   *
> --
> 2.37.2.789.g6183377224-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZCzoK9%2B3qKOzXSHvZ5cfaXpYXbBL%2BR9bicapOuRpUNFQ%40mail.gmail.com.
