Return-Path: <kasan-dev+bncBCMIZB7QWENRBY4L2WAQMGQEOSC456I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F4D932305B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 19:13:57 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id u1sf21452139ybu.14
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 10:13:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614104036; cv=pass;
        d=google.com; s=arc-20160816;
        b=djkKuxcnwM2VZSOFtgdUhJ3YrtmpKeHusQEPuNaF8s9A+MIVnaCRWNO4nzejpb+n5M
         43jRFEV+xOGV2O9CE9KWCjASfbwHc0GuAlZYuLCaMFfFFD5GY2qwrUxc0I9c9/pMQSUZ
         ToDq6fi2++UYK9EkT+6w+pMa2Qz152FLr0cHBk24rxDuHSx+GGBg9pZDEsyh+CyHk1U5
         G8mqMWXZo/GgxrJ7IXzgwd9dnqU9Ho0CPI6/lBh9uWcIrf9hmWsmRFS1BybI63D46b0L
         W63H6BF++zZspT0J3IFM+zmp1UkRYhlpJeWXR9q1vXYgjG5dklDxFCaeewujJjRhNidP
         FXCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yu1IIpJysE37ldxIcehlh6Kl2w5Ro8z3L1MICszJc0k=;
        b=bXFTK/U4XrhRUZZVTmMtGaroSmdMEV5063JwIymAfq9tcowXAH3kMujIFHb6Q+uX3I
         cj5rYgLMFyITGXrnGEEWBSxY+B6VLK74aa7G5oIrhWGDnxqwujMpyBJ3wdVWfMRvBYIJ
         DwxcJUW01a2erGK/SLQ/fuElzqVpb6M+w9LRnbxX8V2ZbC+mI1SYVcc/pufrgwX+0ey/
         X8qIyft1eG9rWf1VRWBFJUBa7o9EsZNuPjINb3uMwAmirvecCq4lWrBpeL+1EZr/ZGMH
         r6rttaXvpLdY6kKIo9cnaeEyfK/0spY5Sw7OBwq//EjL568tfH1+7BExmOzNmesZSjcF
         /7Aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FMcvcTOt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yu1IIpJysE37ldxIcehlh6Kl2w5Ro8z3L1MICszJc0k=;
        b=myPeEsKwQZgWEzL3hht1Zb3IqOS5XiPVZHH8mtI50i4n0YqJd4BJPTsU5Ez8YcMGjO
         VkgHH80ZTedoAeIeSMYqAjCFycak0iAFYGmYNbLK37fMOVsy26RZmtUe17g/evrzzpd1
         ML9nRtTfl2XvvOg1KTvzHHkbTAFTXuepF4LgRu3bPHupfz4Ob2bjB1Ng9GYw6FIECfys
         tarfXCfZKAIpZ0ELubtQZNagEx+/mTvufj3u/zS0evEzNFjNBpJb51KRkot17mAHOoZe
         gDc/gyhXNywmFdCl1C2PD93QePX6rHHUbBivdYQ5/OkiDm4K0OZ9Nlw9beiQ6kdXNWqA
         TMaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yu1IIpJysE37ldxIcehlh6Kl2w5Ro8z3L1MICszJc0k=;
        b=seYWAYAJZA3H9uqcQN6CYvY5XAAl+wviZkvWel94LQzWOiJJvd42L7NGYyUbRNHXNT
         lHezckzLYAuSNnCMpL3DbClPdqpL2Mv7HA5RjS4L0j1kYyzAZ2NjmwrfhMwjGTdFgQoY
         EVLLIIk0igj5B4d/OVTK7Ltcmar1d4OUhBikKErNNh9WvFYZ+OSnCURRWe/tZJffCJq0
         Xq47V7SkPaGKAsqJ7Z4qaRdagQaotyx4eeEqzHCkK7ZJxy8KUaFJS36/yaM7Lilt7Vqj
         ddX+v+Tb6RSCdtpuPGeoYgY95XkR1gfzXLcKga2sDzARGBlj1qskJnS5d27xw3N6Qdd7
         Gnjg==
X-Gm-Message-State: AOAM533FQEJRh/g7B7emgV22WoAbKHgNzNk4pv099a0ww8Ivp4yg/rtL
	DrjltCPFTUnPgivcQed+qtY=
X-Google-Smtp-Source: ABdhPJxuwhrfe7T7GUX0ImqfVa+5smW5kW9JbUErZeXFUtFyJN6y0BUvjbsVCItQoE519DKkAV/4nQ==
X-Received: by 2002:a25:cc43:: with SMTP id l64mr19431815ybf.283.1614104035992;
        Tue, 23 Feb 2021 10:13:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5bc2:: with SMTP id p185ls3221740ybb.7.gmail; Tue, 23
 Feb 2021 10:13:55 -0800 (PST)
X-Received: by 2002:a25:d17:: with SMTP id 23mr12531878ybn.387.1614104035526;
        Tue, 23 Feb 2021 10:13:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614104035; cv=none;
        d=google.com; s=arc-20160816;
        b=CtREqJZQsiWtQEufy4EmX/5FeP26eNacRi7NSeOtvlDyCDPVXjch4j+surF7vPxTHf
         AM3THYq8WjNKJWhNEWB1UFe6jj44aPm0xY5RMvYHjeBBwmUYHFuUu3rKvvqziJJNLFNd
         7kDDgZFaz8Y6rlXP/9BbOUCHUywWfABqNvcsHBkVDmx787qDAbP+RfnJsfOA6CpLROpH
         1q+RR6NpyPihshZuSQ4cm5/Sqg93h4MMhO9ONl7omrXIrm5ibe7HQSBXdTiOh1dExk6z
         n86kme44ocqv+77XWaLxhTWpz78R8L8GtVbViOVYIwM0x+DmEAt0138yHR3MrRydnCc9
         R66A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=64chh81MrDhbGsEgUYAQK1O320WsxsfdzdSvZe/81Lc=;
        b=kyv8AFt4j6Bcub71QILG5mirizCUzD3ugj+0i/5gC7pl6gt4tDBJ02ASOC5Y3fm8ql
         Hw8y/ypOPOemzEN8f72xDAs3uG+4jDcRNDFmNNPmdxKN1to5Rs9cT5r17sNwqR2cOFz9
         sTwIcnmfYGOMzMtypcs2sWDWcZWaBU11waK9rcMbs8tSQCN2Yp8TNL/0EFpE5RNmaFUQ
         /TAAGn3ZA1BhbNYnCCY6se99DsqJ8EAsh/bJXbiWx26cqtxLEubw3UGT/SFiUYK+Smbg
         jsZbdvqv4MEPm/TMWYEsYYHdIwOv8RGQ75kdk2vfa3znuVD9RHViOgW8PU+8cjh+wcXh
         kUcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FMcvcTOt;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id s44si1560664ybi.3.2021.02.23.10.13.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 10:13:55 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id k8so7769566qvm.6
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 10:13:55 -0800 (PST)
X-Received: by 2002:a0c:8304:: with SMTP id j4mr26498875qva.18.1614104034885;
 Tue, 23 Feb 2021 10:13:54 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-4-elver@google.com>
In-Reply-To: <20210223143426.2412737-4-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 19:13:42 +0100
Message-ID: <CACT4Y+byoqr4UjNcYO-VMRZorqVxGyZmQb==pJXiQ0WjqwXvhg@mail.gmail.com>
Subject: Re: [PATCH RFC 3/4] perf/core: Add support for SIGTRAP on perf events
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, 
	Matt Morehouse <mascasa@google.com>, Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FMcvcTOt;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b
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

On Tue, Feb 23, 2021 at 3:34 PM Marco Elver <elver@google.com> wrote:
>
> Adds bit perf_event_attr::sigtrap, which can be set to cause events to
> send SIGTRAP (with si_code TRAP_PERF) to the task where the event
> occurred. To distinguish perf events and allow user space to decode
> si_perf (if set), the event type is set in si_errno.
>
> The primary motivation is to support synchronous signals on perf events
> in the task where an event (such as breakpoints) triggered.
>
> Link: https://lore.kernel.org/lkml/YBv3rAT566k+6zjg@hirez.programming.kicks-ass.net/
> Suggested-by: Peter Zijlstra <peterz@infradead.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/uapi/linux/perf_event.h |  3 ++-
>  kernel/events/core.c            | 21 +++++++++++++++++++++
>  2 files changed, 23 insertions(+), 1 deletion(-)
>
> diff --git a/include/uapi/linux/perf_event.h b/include/uapi/linux/perf_event.h
> index ad15e40d7f5d..b9cc6829a40c 100644
> --- a/include/uapi/linux/perf_event.h
> +++ b/include/uapi/linux/perf_event.h
> @@ -389,7 +389,8 @@ struct perf_event_attr {
>                                 cgroup         :  1, /* include cgroup events */
>                                 text_poke      :  1, /* include text poke events */
>                                 build_id       :  1, /* use build id in mmap2 events */
> -                               __reserved_1   : 29;
> +                               sigtrap        :  1, /* send synchronous SIGTRAP on event */
> +                               __reserved_1   : 28;
>
>         union {
>                 __u32           wakeup_events;    /* wakeup every n events */
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 37a8297be164..8718763045fd 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -6288,6 +6288,17 @@ void perf_event_wakeup(struct perf_event *event)
>         }
>  }
>
> +static void perf_sigtrap(struct perf_event *event)
> +{
> +       struct kernel_siginfo info;
> +
> +       clear_siginfo(&info);
> +       info.si_signo = SIGTRAP;
> +       info.si_code = TRAP_PERF;
> +       info.si_errno = event->attr.type;
> +       force_sig_info(&info);
> +}
> +
>  static void perf_pending_event_disable(struct perf_event *event)
>  {
>         int cpu = READ_ONCE(event->pending_disable);
> @@ -6297,6 +6308,13 @@ static void perf_pending_event_disable(struct perf_event *event)
>
>         if (cpu == smp_processor_id()) {
>                 WRITE_ONCE(event->pending_disable, -1);
> +
> +               if (event->attr.sigtrap) {
> +                       atomic_inc(&event->event_limit); /* rearm event */

We send the signal to the current task. Can this fire outside of the
current task context? E.g. in interrupt/softirq/etc? And then we will
send the signal to the current task. Watchpoint can be set to
userspace address and then something asynchronous (some IO completion)
that does not belong to this task access the userspace address (is
this possible?). But watchpoints can also be set to kernel addresses,
then another context can definitely access it.
(1) can this happen? maybe perf context is somehow disabled when !in_task()?
(2) if yes, what is the desired behavior?




> +                       perf_sigtrap(event);
> +                       return;
> +               }
> +
>                 perf_event_disable_local(event);
>                 return;
>         }
> @@ -11325,6 +11343,9 @@ perf_event_alloc(struct perf_event_attr *attr, int cpu,
>
>         event->state            = PERF_EVENT_STATE_INACTIVE;
>
> +       if (event->attr.sigtrap)
> +               atomic_set(&event->event_limit, 1);
> +
>         if (task) {
>                 event->attach_state = PERF_ATTACH_TASK;
>                 /*
> --
> 2.30.0.617.g56c4b15f3c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbyoqr4UjNcYO-VMRZorqVxGyZmQb%3D%3DpJXiQ0WjqwXvhg%40mail.gmail.com.
