Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HP3S4QMGQEE4LOQMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 65DC29CDDF6
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 13:00:43 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2ea0c9dfe34sf1403020a91.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 04:00:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731672041; cv=pass;
        d=google.com; s=arc-20240605;
        b=WRXmAyjvX2XSir8nW/mJwZ5f4MRv81LwN6kFQR85sNHOcwnVIgYC/n6kCxcJmTz9Am
         +kSjyMElZxsxeo+vY1LLz79uTxhR4muj5ssmZCEhYGMPns1w4xPCxU9NImLaN5y0uZCa
         E6Ld0h1mcMlONWlJgZ5/DJcNWXGtBbSbo4NztQFputWvTbLlXt7w14EbeuAepcE0cFEY
         l02P7+TFOzrx/wuL8lk/URMAFYkhyi89eS54OcTe8tMYgKoRhw4hlw1nQWzK3Dj29p5c
         /IFQo2+S8LLScDYYQu1Wpqn7XD+KcbuUKPoL0h+SCZ829jn/pnWpZ1CXl1x3KnszNgWD
         Yhkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=W7v+1UBsJedKR/vyLoluMhBVMobiGIqPqb4sjJkEdww=;
        fh=292C9I5wx42ichQyvwYkEkfJVGwrydvDOf8jcofrVrQ=;
        b=gtUB/BLd6expWcNM+UcNHdnXunDvgodpjGGllJnsqpteK2P+5EbE9Y1vnvzUnZrsVZ
         /Vt6VGddBkWNpF+mfQyyUNEx9OA5vHflah/hTgzvf3sh5q+ik+wJRADHX/1cYIa1ZVCz
         wru7yYm5dizd23tMK2iCHMzT04+4WbRmb/Zfq9uL8EhZy86svV2Tz2G0NMXdionAgbn9
         pPzwQZm1oiJmT9KEe1zIl07J5SOQDD11u1WewU2DMzdkDp9u2XSZR5vRCCkcDpMLaqCZ
         cOb0cfPiML1urfkuv3ed/o6K/A0NVymHEl+y78p3svy+39b/bDI/ExOiytqoBbcSDoFm
         8aZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xt+Pxcnd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731672041; x=1732276841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=W7v+1UBsJedKR/vyLoluMhBVMobiGIqPqb4sjJkEdww=;
        b=MOeGQRvLDPMLV7xnh0bpHyzIP8BjqKs6uKp2JdGTj6xrowV7BP5AjLb1gbYW1xsA9v
         OVZrxhiMmKrLEcmQqZwaJ23jc7SzF+91dMSENuzGJO2wOqTcjo3ArvDZL5DWD1Fydtmc
         HAMlb98W+FNG6Q04P6jhsWUA/qC+trbjZ6X7Dlrditguzl2YVKnCyrk0UDoIPIoZnnvY
         TdKzq2WXDxMCLlmZoypdTqZTd9n35W+V/U0aHl0tOLkIrQNcTWIKVJXp7paU8jI2zZKj
         HcES2jVLAu1j2/uyN13D1a5TPfuweAzsgbthTCVE7aaTHvyZoL6B4z2G++Mk3jG7HZ5O
         D0PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731672041; x=1732276841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W7v+1UBsJedKR/vyLoluMhBVMobiGIqPqb4sjJkEdww=;
        b=gYpEUo0kcW7vUSTm0weZzAEzgxiqpu+Qr4TQcBdiNiJLQlt16e+RTyPOZT5arHZJr7
         h2Eo/WYR3axzMFj/Auo76Xbiy6hQwUJQhB2ubtHqwkmVa3qb1VLXPi3RKHiQBja1fnvD
         4Hx7rcvvxnoDRoCTymCNXDwNR7bG7pFELdrdId4ROpjxJoTzyxxSjlUvZ3LKgJopNlbF
         PC1hzLMvaXpHRDHLZkYO3VRum6ksLYJGh8NnONXpFclL0rNE4c3Wp1hSKe+8b1lruENv
         zZ8NuFnOF9WkxQN5PrdaZRT+lBAvNz5CaZ+MdUbNu+IQ0YrH5f53YYuYG4ce1JWMCX2n
         8jaQ==
X-Forwarded-Encrypted: i=2; AJvYcCU43EffT7OXjL8SKPWBtGZ2sblwsDXr/W/gcdCsU7lgddUSXNK+Ofa4oisI4hNoI8Ym32qvxg==@lfdr.de
X-Gm-Message-State: AOJu0YxRZMIoXfFveMd60016Pm2u5GnNCb4+41R/afAftHw7P1ps5g41
	ki1GXB/0H+L9l7SnAeB3r1XTA5+PpR+OAXG/Ep36KticqUBytPmI
X-Google-Smtp-Source: AGHT+IE8ClWvAw0Y5nvkJRmBj3FpvU5sqwzB5XXDRW1Q1rNbX9jaTauG4GptIhaum1nf94V90HHJGQ==
X-Received: by 2002:a17:90a:d88e:b0:2e0:921a:3383 with SMTP id 98e67ed59e1d1-2ea154dad91mr2741674a91.1.1731672040624;
        Fri, 15 Nov 2024 04:00:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1c08:b0:2e9:b4a5:8590 with SMTP id
 98e67ed59e1d1-2ea005bb27els1252175a91.1.-pod-prod-01-us; Fri, 15 Nov 2024
 04:00:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU3/oVIKW48wA/+6CHrHqepFhtJ0Mm+S6rSxlSsgyPFxYfHOh/aKw3lWAgfbtfZjHiF8DjtY24AQiM=@googlegroups.com
X-Received: by 2002:a17:90b:4c92:b0:2e2:b937:eeae with SMTP id 98e67ed59e1d1-2ea154dae5dmr2972729a91.5.1731672037977;
        Fri, 15 Nov 2024 04:00:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731672037; cv=none;
        d=google.com; s=arc-20240605;
        b=QyiV3bxw8AYRIOqseYXk7zMWiI3AYYDlcgQ9O9sXrF3CCNpZ9GeMWu6/r9ZieB4t65
         MQVgKSNenzbUuw9t0GIegI2HqL7Cl3/iHb3LZA61Uyb73kMk7oc4yRFnMkoR1grZtvDy
         OiqcNktOWq3ZF9OA7gzBslOSG9xSUMCQ8NeYHWxQxApm+65Iq1A1qTKJEaG5t+fAfous
         wfhjdWx+HH6E9gVrUv0fDUKYUJbDLy4c2OSUm17m8GSfAfsHyfh7CbyF7SeCzOvgpbKa
         o+2vTLIkKfhhGsbs7oqbk6FaTaqbyTudbJHj3PYVl9nEUEE6wMawS0g1zVDuUB7DoEcm
         EDTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KlGdhGP6WA+spFDXddhwm5CPfAlGC4n5EQHyhAQX98w=;
        fh=8FwH1pmKX8+6Dz2+//ShdDQrtXwKXrCW7Pk2u7N9Wlo=;
        b=WcB8dEG+/0eW5zDLbMIxr+W5znpbS9y+BE8tU4uOb1sCdpoSweQCvwdAGyB139l6Xk
         54vIPvnLeeW5wLTr/NkgzQJiYxY7ZM3VWpdo3nlZRpu0C6RqGJfReybNpqbQporbtnuT
         PVf1RhA/JxhzRUcQEJGO5kvBmZ7Qcoi1hQzAne/i+Dy0HghkDpsDEIw5vFIydrcPaa7q
         3rvC6+a25nkekcbO7yVyuoG2EFjql6BV4zun9WR42OThFMQROOtpeSD3KK5RU6JQHhjV
         8DSF5hRFjLRmM2ZurA61AuNpBVoXd3nVUk9d7AU8lnJL7L496W7o+1wOjdg91Vs0lgl8
         f7PA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xt+Pxcnd;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2ea024be90esi255471a91.2.2024.11.15.04.00.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2024 04:00:37 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-2ea1c455d0eso275511a91.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2024 04:00:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWBe9dDo0PDxwAcr7WNccmpvRTT9r5q3hC1D8s56yuacKm0xjuRq7mjLJoHJ4pK5QPV4MXYwAVgqfo=@googlegroups.com
X-Received: by 2002:a17:90b:3a81:b0:2d8:e7db:9996 with SMTP id
 98e67ed59e1d1-2ea154f9cabmr2767715a91.13.1731672037347; Fri, 15 Nov 2024
 04:00:37 -0800 (PST)
MIME-Version: 1.0
References: <20241108113455.2924361-1-elver@google.com>
In-Reply-To: <20241108113455.2924361-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Nov 2024 13:00:00 +0100
Message-ID: <CANpmjNPuXxa3=SDZ_0uQ+ez2Tis96C2B-nE4NJSvCs4LBjjQgA@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] tracing: Add task_prctl_unknown tracepoint
To: elver@google.com, Steven Rostedt <rostedt@goodmis.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Masami Hiramatsu <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>, 
	linux-kernel@vger.kernel.org, linux-trace-kernel@vger.kernel.org, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xt+Pxcnd;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1029 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, 8 Nov 2024 at 12:35, Marco Elver <elver@google.com> wrote:
>
> prctl() is a complex syscall which multiplexes its functionality based
> on a large set of PR_* options. Currently we count 64 such options. The
> return value of unknown options is -EINVAL, and doesn't distinguish from
> known options that were passed invalid args that also return -EINVAL.
>
> To understand if programs are attempting to use prctl() options not yet
> available on the running kernel, provide the task_prctl_unknown
> tracepoint.
>
> Note, this tracepoint is in an unlikely cold path, and would therefore
> be suitable for continuous monitoring (e.g. via perf_event_open).
>
> While the above is likely the simplest usecase, additionally this
> tracepoint can help unlock some testing scenarios (where probing
> sys_enter or sys_exit causes undesirable performance overheads):
>
>   a. unprivileged triggering of a test module: test modules may register a
>      probe to be called back on task_prctl_unknown, and pick a very large
>      unknown prctl() option upon which they perform a test function for an
>      unprivileged user;
>
>   b. unprivileged triggering of an eBPF program function: similar
>      as idea (a).
>
> Example trace_pipe output:
>
>   test-380     [001] .....    78.142904: task_prctl_unknown: option=1234 arg2=101 arg3=102 arg4=103 arg5=104
>
> Signed-off-by: Marco Elver <elver@google.com>

Steven, unless there are any further objections, would you be able to
take this through the tracing tree?

Many thanks!

> ---
> v3:
> * Remove "comm".
>
> v2:
> * Remove "pid" in trace output (suggested by Steven).
> ---
>  include/trace/events/task.h | 37 +++++++++++++++++++++++++++++++++++++
>  kernel/sys.c                |  3 +++
>  2 files changed, 40 insertions(+)
>
> diff --git a/include/trace/events/task.h b/include/trace/events/task.h
> index 47b527464d1a..209d315852fb 100644
> --- a/include/trace/events/task.h
> +++ b/include/trace/events/task.h
> @@ -56,6 +56,43 @@ TRACE_EVENT(task_rename,
>                 __entry->newcomm, __entry->oom_score_adj)
>  );
>
> +/**
> + * task_prctl_unknown - called on unknown prctl() option
> + * @option:    option passed
> + * @arg2:      arg2 passed
> + * @arg3:      arg3 passed
> + * @arg4:      arg4 passed
> + * @arg5:      arg5 passed
> + *
> + * Called on an unknown prctl() option.
> + */
> +TRACE_EVENT(task_prctl_unknown,
> +
> +       TP_PROTO(int option, unsigned long arg2, unsigned long arg3,
> +                unsigned long arg4, unsigned long arg5),
> +
> +       TP_ARGS(option, arg2, arg3, arg4, arg5),
> +
> +       TP_STRUCT__entry(
> +               __field(        int,            option)
> +               __field(        unsigned long,  arg2)
> +               __field(        unsigned long,  arg3)
> +               __field(        unsigned long,  arg4)
> +               __field(        unsigned long,  arg5)
> +       ),
> +
> +       TP_fast_assign(
> +               __entry->option = option;
> +               __entry->arg2 = arg2;
> +               __entry->arg3 = arg3;
> +               __entry->arg4 = arg4;
> +               __entry->arg5 = arg5;
> +       ),
> +
> +       TP_printk("option=%d arg2=%ld arg3=%ld arg4=%ld arg5=%ld",
> +                 __entry->option, __entry->arg2, __entry->arg3, __entry->arg4, __entry->arg5)
> +);
> +
>  #endif
>
>  /* This part must be outside protection */
> diff --git a/kernel/sys.c b/kernel/sys.c
> index 4da31f28fda8..b366cef102ec 100644
> --- a/kernel/sys.c
> +++ b/kernel/sys.c
> @@ -75,6 +75,8 @@
>  #include <asm/io.h>
>  #include <asm/unistd.h>
>
> +#include <trace/events/task.h>
> +
>  #include "uid16.h"
>
>  #ifndef SET_UNALIGN_CTL
> @@ -2785,6 +2787,7 @@ SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
>                 error = RISCV_SET_ICACHE_FLUSH_CTX(arg2, arg3);
>                 break;
>         default:
> +               trace_task_prctl_unknown(option, arg2, arg3, arg4, arg5);
>                 error = -EINVAL;
>                 break;
>         }
> --
> 2.47.0.277.g8800431eea-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPuXxa3%3DSDZ_0uQ%2Bez2Tis96C2B-nE4NJSvCs4LBjjQgA%40mail.gmail.com.
