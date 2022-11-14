Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIFCZCNQMGQEDSK72PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4777D6279B6
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 10:57:54 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id bm2-20020a05620a198200b006fa6eeee4a9sf10668909qkb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 01:57:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668419873; cv=pass;
        d=google.com; s=arc-20160816;
        b=QG30JpBu9XrnT/YhGM613HpjHyxe5zlfvQreueYDvDxYb0fsNYvm5S94ZJyxDLHums
         7I5T82DugDAWj4zw2meViGorQztqBfAqJsBucq8HQpa7AUUql5JuvkhfGsV3lOwJeuQp
         8i+QXgGhjOuBF+X8CQIYkTXGQL06EIfAirVBx5+7Ljr0D3uu0+VcvbBtsXwiKc2J81w/
         th2DhOWgig+kbEOg0+3Hig0VmCp6YA2GKt1KmafIYAMZeuQ0175+d/IALN0JJ+WhmklT
         Uu1buYIJOouzpZCGcEbSV8/MzbPGZvgah0w/hDBHKcN8IkPZNsAqbA2JZFH0xUMFxInB
         mvow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6j+OkvgXuq5Lr8pmOOTRzep9OH2fAw/6CXcSclPrlIU=;
        b=UiZNnfd9lNxt5uGuYKfO+7sL/esQqGb3dxL0JyiuDvB7k4UBK3Hz8cDmoFW3pDHFrd
         jVDIErpobgDuV1juBAYSgU58DLsTAgfwygykefsiBHk7E/iyiomI08Nbc3bL8OLQeKjE
         zpm40O0bourPaS6/S6AFcKcD9iAsxDUVZ5Nbqc/TyQaAgC+dJZv2JUxLc7G3qjYOEn5A
         G1CTS+Cdnp31+m6f5ePe0W0BkwVj4mrqg14E/0cWy9eVsYktxAlM0IZ0Z5mZMQ4q/RZc
         FMTfVIqAmLW2bazNRB83LqtYhzstxEbQh297LrRzwsGOE9peAbOP4z+6y4ZZ6D/rsx+V
         fV0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=caH5zcwk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6j+OkvgXuq5Lr8pmOOTRzep9OH2fAw/6CXcSclPrlIU=;
        b=FsoAQW8weHqVd05zFveEYtT7bwH82e+P58mDlrfZWni3V6CZSwRCWrP9era6HH3+MY
         MLH0tHyWQ2OfYy+YI6Kvg5HVo1Uo5/qJ1O8Cvnz10P+mF880Qg5quT8+JcVQOIvcGddU
         5y4BbUkenkMee+WLCKZc/Ogiu9jrx/UCiWVM2UZX/GF3Kw2xshla+MvOnqxJWrdQuwS6
         oXvi6DB5X//DKs9/+mONzztfj1RKhkvQgqO/2bOhkA3ws0LMcNgzS1VlEmk4dKg/jUBQ
         Cb2ZMXexwHTSRzjzcnL9hkp7BzZ0TTBKPNDL4Pq2O7rnzzWOyMEQkrMptncPKNm+Dc5L
         uHmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=6j+OkvgXuq5Lr8pmOOTRzep9OH2fAw/6CXcSclPrlIU=;
        b=X/uM6OlCCwQ4FRpWW99aiDzkhiB6XO1kqspkizqQGvheSMp4kYRc73d5bmmHU6fHiZ
         WbmCSoMUqiVm9GoTDlgao+mJd66e61+dU0FpnUs4+hCk2dzuiGs3hkG3mqNOvVGMJKHa
         umrKTv6+ttIiSCNpSkBk+jUsdgX9ABy3m93N/JRDGZwxFr+76/F7T4UlKynYwF+GvnGy
         akdeyZyOW+YMd+J0G7+3iJBzsfr7n++zI3S/sCspaG7cFVhEsNKudqDNl7slsp02YGMm
         V/sjNpPF5PTzbfHXpxLyXVoWoOxpRt1fD891kXbcGEzLEDA0HaAuk/huINx2Odq/f+sE
         pRWw==
X-Gm-Message-State: ANoB5pnfiMWRMydcYaNlnMkJpJpDjWZ25G+gV+wYejGJR3RUrZkC4ixM
	fP3znQ1XKOHlNOy/Bd01WSY=
X-Google-Smtp-Source: AA0mqf7TCMNH8hv28gKTtU1stfV3LXbYgMDgckNL86zPKw/qPhUx5starMC22uIRDTvKIjfS6I7opw==
X-Received: by 2002:a37:6558:0:b0:6fa:432f:298a with SMTP id z85-20020a376558000000b006fa432f298amr10561785qkb.159.1668419872823;
        Mon, 14 Nov 2022 01:57:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f445:0:b0:4b9:d85c:f017 with SMTP id h5-20020a0cf445000000b004b9d85cf017ls5019863qvm.11.-pod-prod-gmail;
 Mon, 14 Nov 2022 01:57:52 -0800 (PST)
X-Received: by 2002:ad4:4bad:0:b0:4b3:f2d7:683f with SMTP id i13-20020ad44bad000000b004b3f2d7683fmr11894863qvw.102.1668419872304;
        Mon, 14 Nov 2022 01:57:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668419872; cv=none;
        d=google.com; s=arc-20160816;
        b=R3bbu1Kowx9bzQTCe/C0d3iEbSr/gUbP53AZDjT1GWcOgWfcGt2OVaot4OzBG8ztBB
         69kqvjlk6YuOjAEKxGiIgBxzvkAcxTVTSefGcNFl6H0sFhsga+vH7E0fFHQwXmyd1YDo
         BzKaPHg2HSTiujRVhTTyE7drL4LTVc3qMLvqK3tzGsIufwI2Bw3FL6mj0KupyQYU/Dan
         Y/TZthJuuXNjpNtfZykw67PHZ1Gk8TwIUXh7O9uAwkt8TjrvYrMmxzzyiOzrJ5Y4nrGx
         lIIQFBRZVQWfHpatOcKTC2qoGHQ2v1RB8Y6sp1RZU/4AYww5D9d6tRErR3/9gDfViWeN
         /5ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RH2+m7K5zmlE9wCFpvve3I5Fi8RQASbgvvHyRX4D28g=;
        b=MDK3psMHw0EQAY7vzGXUMJphNEGxLF11wugv5QAAjaOkVJs4vYId/yFEY8UPpPJHNC
         Dr5BCxJXVPX5OwGSMnePtFguJbPNx2DgfK5ipBhyTgVhuz5yMUQpH8aIXRyo4wwT6qom
         e9A3SKNkw03haHWvykQtoX/jWCcUYS+uQf8juHPUUCRb/GFc0XKgU7m04KRUBL9nbwSv
         CLqoyvphJW9sOlee5dUCiutP1UkS3Gll1tXEXMAVVEO8DAp9WlK62XyewvrDTKXGany6
         hPQbF+jc3m+8rwzuvKzMehFKdF97XPufMwCvSytkP+XH4AqsMHFEywypuKoUgo7hjOSb
         9p9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=caH5zcwk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id h25-20020ac87779000000b003a50aea46d7si428483qtu.3.2022.11.14.01.57.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 01:57:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-37063f855e5so101116107b3.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 01:57:52 -0800 (PST)
X-Received: by 2002:a81:4949:0:b0:36a:a52e:fe48 with SMTP id
 w70-20020a814949000000b0036aa52efe48mr12368442ywa.267.1668419871793; Mon, 14
 Nov 2022 01:57:51 -0800 (PST)
MIME-Version: 1.0
References: <20221109194404.gonna.558-kees@kernel.org> <20221109200050.3400857-4-keescook@chromium.org>
In-Reply-To: <20221109200050.3400857-4-keescook@chromium.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Nov 2022 10:57:15 +0100
Message-ID: <CANpmjNNrYDNrRR8i+8xAFnmSjZ0Rdp-P14Sf9d+dadfsik18QA@mail.gmail.com>
Subject: Re: [PATCH v2 4/6] panic: Consolidate open-coded panic_on_warn checks
To: Kees Cook <keescook@chromium.org>
Cc: Jann Horn <jannh@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, 
	Daniel Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@redhat.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Luis Chamberlain <mcgrof@kernel.org>, 
	David Gow <davidgow@google.com>, tangmeng <tangmeng@uniontech.com>, 
	Petr Mladek <pmladek@suse.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, "Guilherme G. Piccoli" <gpiccoli@igalia.com>, 
	Tiezhu Yang <yangtiezhu@loongson.cn>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Greg KH <gregkh@linuxfoundation.org>, Linus Torvalds <torvalds@linuxfoundation.org>, 
	Seth Jenkins <sethjenkins@google.com>, Andy Lutomirski <luto@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, Arnd Bergmann <arnd@arndb.de>, Jonathan Corbet <corbet@lwn.net>, 
	Baolin Wang <baolin.wang@linux.alibaba.com>, "Jason A. Donenfeld" <Jason@zx2c4.com>, 
	Eric Biggers <ebiggers@google.com>, Huang Ying <ying.huang@intel.com>, 
	Anton Vorontsov <anton@enomsg.org>, Mauro Carvalho Chehab <mchehab+huawei@kernel.org>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=caH5zcwk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
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

On Wed, 9 Nov 2022 at 21:00, Kees Cook <keescook@chromium.org> wrote:
>
> Several run-time checkers (KASAN, UBSAN, KFENCE, KCSAN, sched) roll
> their own warnings, and each check "panic_on_warn". Consolidate this
> into a single function so that future instrumentation can be added in
> a single location.
>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
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
> Cc: Luis Chamberlain <mcgrof@kernel.org>
> Cc: David Gow <davidgow@google.com>
> Cc: tangmeng <tangmeng@uniontech.com>
> Cc: Jann Horn <jannh@google.com>
> Cc: Petr Mladek <pmladek@suse.com>
> Cc: "Paul E. McKenney" <paulmck@kernel.org>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
> Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-mm@kvack.org
> Signed-off-by: Kees Cook <keescook@chromium.org>
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
> index c7759b3f2045..1702aeb74927 100644
> --- a/include/linux/panic.h
> +++ b/include/linux/panic.h
> @@ -11,6 +11,7 @@ extern long (*panic_blink)(int state);
>  __printf(1, 2)
>  void panic(const char *fmt, ...) __noreturn __cold;
>  void nmi_panic(struct pt_regs *regs, const char *msg);
> +void check_panic_on_warn(const char *reason);
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
> index 129936511380..3afd234767bc 100644
> --- a/kernel/panic.c
> +++ b/kernel/panic.c
> @@ -201,6 +201,12 @@ static void panic_print_sys_info(bool console_flush)
>                 ftrace_dump(DUMP_ALL);
>  }
>
> +void check_panic_on_warn(const char *reason)
> +{
> +       if (panic_on_warn)
> +               panic("%s: panic_on_warn set ...\n", reason);
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

What is the reason "kernel" in this context? The real reason is a WARN
- so would the reason "WARNING" be more intuitive?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNrYDNrRR8i%2B8xAFnmSjZ0Rdp-P14Sf9d%2Bdadfsik18QA%40mail.gmail.com.
