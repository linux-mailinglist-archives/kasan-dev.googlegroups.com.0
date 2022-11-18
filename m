Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBMH3WNQMGQEYBRHG3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6499F62EF96
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 09:34:15 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id a1-20020a056902056100b006e6f103d4c1sf3984461ybt.23
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:34:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668760454; cv=pass;
        d=google.com; s=arc-20160816;
        b=hpF7yHETNtHrCUyZ/GzX65NWg4AYinRq3Z8kH8oVMLHuFz77O4/2KfHdzQp+njUbr7
         PDjsGetxq3lIfD9rDkLeWItpUxnEg2GUo/ZInJct2+QgUKAXfLs5TXv2ex+YmBaMua7R
         iX9NcDzfP/PiD7AzASfTMSA+r0gH83TXD9RWimPjZ4iotIYiNoryFxVXHvY+umvUP6iC
         i/VOIxZXf0FFA4wt4YfvPfGLkwbyS2SpE5Z2fr3O7RHTatYn6HftJAQe5If8MTF7mPj3
         FvcJQ2Dwnrd+p4nEpcWRm4ih4tbOD+jrE/09laGE61W/0Kcja0IcnhVGLftXnsjRY9nb
         /ZUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=udoPpjMSPPfRIfyhskyPv50JK53YpPqpjsqZqwOXmSk=;
        b=GsI91oUdcwOblv+JLJaB+jwvpkRmDQxshVADfBNRUB1IyscWfacPt78W2BAUKNJSRL
         Ac5OAXAqP4j4wbnKrKyvw7jGzGVfhBnxeMX+lchyL9QWs7tV2YfLdhzkzIWIDwBaLBR3
         dutKAOxIiU9FghzO7kE+u9HdaOs7jvDCLx0n0bbY90u4r27E/MFcuN34QOdN0HyeYzia
         oO2KOHxE/hSoWEyOAA4qvPv3MzPpgvQbMm9GE26UyuG3mhPe2/cIeTzEQgbJovE9vFCO
         Ke7mX2YvSy77UWAmTkyWwBAGH9nsWm3bZpwgtcRuDdCvY9R9unzlO5az/3GDuIgYBaAk
         T2bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="p/97bDSM";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=udoPpjMSPPfRIfyhskyPv50JK53YpPqpjsqZqwOXmSk=;
        b=Nh6Dt/vFXp3J8uG+w9CpvFPY2Jws2FwQdhvorOG+XZ6zPt2siiRnbQB1dFSAVP2vwE
         qEjj0CtdIcTXevoV9LsqxueQjKSzQ0OD81V1EWYEz7/IgQiBCgd2Tz4aEd7muCrbvzc5
         PjUs2F49Z02fsbdeQsf26tvh+C1sIluuZCqhqajDP53y2FSnA/gcvSZgKUBDiJQg88Qt
         3wNOVNPGWu0Lj74rlKX99JKAI/nnYE7VDmVHh/mUbYbSz33YW0BREnZUApJS6O1/i/Fh
         4hjEGCJDhtA1rLfNSv5emapAOSuhAH/OsN6mVqDH32MQ5548cbbWizJ0R3B6HHgih/ad
         YlRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=udoPpjMSPPfRIfyhskyPv50JK53YpPqpjsqZqwOXmSk=;
        b=XCiX/x/tZWhuN7mms9ayDNYD2VTEl0UM+SlbOFnx2WjDfX/RZkZ0y30GC2q3UrV3XF
         t67gjVQrK76LNZRFpuI73FPT5Ys/aXcJw4yeAD54l+1uLBOe37ttgOHU+grL+rtIBK1S
         LwBcNgsUWB3Poj+zqRocwQ5uGjzZHuZudLiCMLsrQJSNiSTv16rgc87L505tp4obgodZ
         6TcWAQglZwzHQkkbO9PD8tRrkFq0otjcCUB7EVDRSeLELXm67uoHmxDmgrEIInxHh25j
         j/TRrvtlKFG7NCxekrrbnoKOJgIt1dxCpJo6p+zcw9PP6dkzN1T2Dp9BJCW5oBjG4zXV
         oreQ==
X-Gm-Message-State: ANoB5plh+L0CdhMlU8uAvvKH5xEUAuiLGcU3nHxwpHMXBmjNR0h6IZLj
	DB6ppjd9GrMnXa9iWAswcOw=
X-Google-Smtp-Source: AA0mqf7KlG+VcBTar8euMAAokLm0jEbKwsCM8MqaPIK8HpzL7IHH9KocfZPnRMhqB4P6WCpBxm8v4g==
X-Received: by 2002:a0d:ed01:0:b0:377:6b75:bcb0 with SMTP id w1-20020a0ded01000000b003776b75bcb0mr5514170ywe.407.1668760454127;
        Fri, 18 Nov 2022 00:34:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b289:0:b0:6e6:d92d:cb with SMTP id k9-20020a25b289000000b006e6d92d00cbls2707139ybj.1.-pod-prod-gmail;
 Fri, 18 Nov 2022 00:34:13 -0800 (PST)
X-Received: by 2002:a5b:b:0:b0:6d1:e501:396c with SMTP id a11-20020a5b000b000000b006d1e501396cmr5786144ybp.318.1668760453442;
        Fri, 18 Nov 2022 00:34:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668760453; cv=none;
        d=google.com; s=arc-20160816;
        b=w/SRKdRw9sJwykjXl/iKrsDHR67ZTZ+uU2AgasPcTIxccaaGgrhP1ZO6Nsxab9OxPG
         oBkHMm0bFQsBUewm4AG89bSj56CebF3JLDRECLDZhd5M4cI+63eaBP8N+aARFSE1W7BR
         etskY5h1dreYraFPpjcDCMKfRJmBcZdqit71Xv8WUdWiBltEBbinpWq484S4G9Nzgyww
         3M7f7MNgSc82Q2FOLeyuqEc0OgMi33XcNgYpPzET3q2EMH9kMOyGT+54e3iiCvyfpmPx
         OscCyhKNcNGB6BxODccN3uAhuLOEYrAXskvf3DIE9aMdPwz1J2xr5ilhttGUmfVhVPsT
         4sfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wyrIZGrkRGaBx3SBlr53l5QP2brkzSvBi6iVTIgs8bA=;
        b=rT3SJ3hl52XqZhoROdFBDjL3uAglifiai0B6MFid0N6AO/P3qXhf2Kn1wji4WM014F
         IjAflwJlLRDuJiT73w31qGNV/YTI+GGfNpXMm8PwnWJqNslBV1Z4GYw+MiYXi5NbRzQZ
         EbsrS0IAjJIdebDhr0e7+nWxX6QdXHkGoUR1O6BqJ+XiAdKrHdhJFbVbpz1/fDTH1Udi
         c8Y/WxTiJ3UAxyxQCgTAkpeT/23XH0NvNm5p8i1UYEnfRN3NBWubqguycYCO+kWnwx3W
         5VCr6w/07AegXTO7v76EKCaI8pOIkngaD8qfqc0X6wUCBCdb+tWG7OHCDKkLi3kxmkMo
         s7bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="p/97bDSM";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id i84-20020a819157000000b0036c251a1626si104314ywg.4.2022.11.18.00.34.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Nov 2022 00:34:13 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-3691e040abaso42928687b3.9
        for <kasan-dev@googlegroups.com>; Fri, 18 Nov 2022 00:34:13 -0800 (PST)
X-Received: by 2002:a81:1717:0:b0:36f:c0f7:856f with SMTP id
 23-20020a811717000000b0036fc0f7856fmr5472096ywx.4.1668760453041; Fri, 18 Nov
 2022 00:34:13 -0800 (PST)
MIME-Version: 1.0
References: <20221117233838.give.484-kees@kernel.org> <20221117234328.594699-4-keescook@chromium.org>
In-Reply-To: <20221117234328.594699-4-keescook@chromium.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Nov 2022 09:33:36 +0100
Message-ID: <CANpmjNN2oHP0xLhPG9TboqcXFxdvhE9Hh6qKa0xPGnyFyGDRQg@mail.gmail.com>
Subject: Re: [PATCH v3 4/6] panic: Consolidate open-coded panic_on_warn checks
To: Kees Cook <keescook@chromium.org>
Cc: Jann Horn <jannh@google.com>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, David Gow <davidgow@google.com>, 
	tangmeng <tangmeng@uniontech.com>, Shuah Khan <skhan@linuxfoundation.org>, 
	Petr Mladek <pmladek@suse.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, "Guilherme G. Piccoli" <gpiccoli@igalia.com>, 
	Tiezhu Yang <yangtiezhu@loongson.cn>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Luis Chamberlain <mcgrof@kernel.org>, Seth Jenkins <sethjenkins@google.com>, 
	Greg KH <gregkh@linuxfoundation.org>, Linus Torvalds <torvalds@linuxfoundation.org>, 
	Andy Lutomirski <luto@kernel.org>, "Eric W. Biederman" <ebiederm@xmission.com>, Arnd Bergmann <arnd@arndb.de>, 
	Jonathan Corbet <corbet@lwn.net>, Baolin Wang <baolin.wang@linux.alibaba.com>, 
	"Jason A. Donenfeld" <Jason@zx2c4.com>, Eric Biggers <ebiggers@google.com>, Huang Ying <ying.huang@intel.com>, 
	Anton Vorontsov <anton@enomsg.org>, Mauro Carvalho Chehab <mchehab+huawei@kernel.org>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="p/97bDSM";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112e as
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

On Fri, 18 Nov 2022 at 00:43, Kees Cook <keescook@chromium.org> wrote:
>
> Several run-time checkers (KASAN, UBSAN, KFENCE, KCSAN, sched) roll
> their own warnings, and each check "panic_on_warn". Consolidate this
> into a single function so that future instrumentation can be added in
> a single location.
>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Ingo Molnar <mingo@redhat.com>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: Juri Lelli <juri.lelli@redhat.com>
> Cc: Vincent Guittot <vincent.guittot@linaro.org>
> Cc: Dietmar Eggemann <dietmar.eggemann@arm.com>
> Cc: Steven Rostedt <rostedt@goodmis.org>
> Cc: Ben Segall <bsegall@google.com>
> Cc: Mel Gorman <mgorman@suse.de>
> Cc: Daniel Bristot de Oliveira <bristot@redhat.com>
> Cc: Valentin Schneider <vschneid@redhat.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: David Gow <davidgow@google.com>
> Cc: tangmeng <tangmeng@uniontech.com>
> Cc: Jann Horn <jannh@google.com>
> Cc: Shuah Khan <skhan@linuxfoundation.org>
> Cc: Petr Mladek <pmladek@suse.com>
> Cc: "Paul E. McKenney" <paulmck@kernel.org>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-mm@kvack.org
> Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
> Signed-off-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/panic.h | 1 +
>  kernel/kcsan/report.c | 3 +--
>  kernel/panic.c        | 9 +++++++--
>  kernel/sched/core.c   | 3 +--
>  lib/ubsan.c           | 3 +--
>  mm/kasan/report.c     | 4 ++--
>  mm/kfence/report.c    | 3 +--
>  7 files changed, 14 insertions(+), 12 deletions(-)
>
> diff --git a/include/linux/panic.h b/include/linux/panic.h
> index c7759b3f2045..979b776e3bcb 100644
> --- a/include/linux/panic.h
> +++ b/include/linux/panic.h
> @@ -11,6 +11,7 @@ extern long (*panic_blink)(int state);
>  __printf(1, 2)
>  void panic(const char *fmt, ...) __noreturn __cold;
>  void nmi_panic(struct pt_regs *regs, const char *msg);
> +void check_panic_on_warn(const char *origin);
>  extern void oops_enter(void);
>  extern void oops_exit(void);
>  extern bool oops_may_print(void);
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> index 67794404042a..e95ce7d7a76e 100644
> --- a/kernel/kcsan/report.c
> +++ b/kernel/kcsan/report.c
> @@ -492,8 +492,7 @@ static void print_report(enum kcsan_value_change value_change,
>         dump_stack_print_info(KERN_DEFAULT);
>         pr_err("==================================================================\n");
>
> -       if (panic_on_warn)
> -               panic("panic_on_warn set ...\n");
> +       check_panic_on_warn("KCSAN");
>  }
>
>  static void release_report(unsigned long *flags, struct other_info *other_info)
> diff --git a/kernel/panic.c b/kernel/panic.c
> index d843d036651e..cfa354322d5f 100644
> --- a/kernel/panic.c
> +++ b/kernel/panic.c
> @@ -201,6 +201,12 @@ static void panic_print_sys_info(bool console_flush)
>                 ftrace_dump(DUMP_ALL);
>  }
>
> +void check_panic_on_warn(const char *origin)
> +{
> +       if (panic_on_warn)
> +               panic("%s: panic_on_warn set ...\n", origin);
> +}
> +
>  /**
>   *     panic - halt the system
>   *     @fmt: The text string to print
> @@ -619,8 +625,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
>         if (regs)
>                 show_regs(regs);
>
> -       if (panic_on_warn)
> -               panic("panic_on_warn set ...\n");
> +       check_panic_on_warn("kernel");
>
>         if (!regs)
>                 dump_stack();
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index 5800b0623ff3..285ef8821b4f 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -5729,8 +5729,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
>                 pr_err("Preemption disabled at:");
>                 print_ip_sym(KERN_ERR, preempt_disable_ip);
>         }
> -       if (panic_on_warn)
> -               panic("scheduling while atomic\n");
> +       check_panic_on_warn("scheduling while atomic");
>
>         dump_stack();
>         add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
> diff --git a/lib/ubsan.c b/lib/ubsan.c
> index 36bd75e33426..60c7099857a0 100644
> --- a/lib/ubsan.c
> +++ b/lib/ubsan.c
> @@ -154,8 +154,7 @@ static void ubsan_epilogue(void)
>
>         current->in_ubsan--;
>
> -       if (panic_on_warn)
> -               panic("panic_on_warn set ...\n");
> +       check_panic_on_warn("UBSAN");
>  }
>
>  void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index df3602062bfd..cc98dfdd3ed2 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -164,8 +164,8 @@ static void end_report(unsigned long *flags, void *addr)
>                                        (unsigned long)addr);
>         pr_err("==================================================================\n");
>         spin_unlock_irqrestore(&report_lock, *flags);
> -       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
> -               panic("panic_on_warn set ...\n");
> +       if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
> +               check_panic_on_warn("KASAN");
>         if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
>                 panic("kasan.fault=panic set ...\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 7e496856c2eb..110c27ca597d 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -268,8 +268,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
>
>         lockdep_on();
>
> -       if (panic_on_warn)
> -               panic("panic_on_warn set ...\n");
> +       check_panic_on_warn("KFENCE");
>
>         /* We encountered a memory safety error, taint the kernel! */
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_STILL_OK);
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN2oHP0xLhPG9TboqcXFxdvhE9Hh6qKa0xPGnyFyGDRQg%40mail.gmail.com.
