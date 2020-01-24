Return-Path: <kasan-dev+bncBCMIZB7QWENRBHNHVPYQKGQEFX5S6PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BED11481D3
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2020 12:23:11 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id d6sf1168683pjs.6
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2020 03:23:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579864989; cv=pass;
        d=google.com; s=arc-20160816;
        b=XD5W/gcnRL9jlqTLhUYDa623nrnM7JQ5Oy1zHFr+SzKdwwgop6V8SPGdTCmLBe4Jh0
         ushZ7k22UEzUFGbJFjpRLi5WcrGXrhQ3M3ml57Sa0+Y5nrOVXATckZOmMbGwYwUzRk1d
         7PRMiR+eVPyMjUOcio8tBbney0eObyl/SJLaLqeBBDg7lwiKVsEZTREbKPa0cYANwGbq
         Av3IH4BP60ukKePOGXJo2pmyd8l3hJkqKJk9rzDUeFi+l7kMhgnzh9g59ytS6GT5kL2L
         L42tz86TCbaZOvysqvTNvEWQGT/h9LnJzbUbPr2bIRBheq6ozHNT4Swxzph1QdqvZv/p
         eHZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EKTmKghCDhB8+IlY06Qt0+T6fRzrs0tps0p+7BDgO1Y=;
        b=Xv/uCioRU5hS95B3sIBNkmY9ttXTSNLzwpmnXbU8XaEhmOmISMtwEwdKgirXhe32ud
         RRyqJ6izxLbdLRyZd65L3xaeRM0j8AqSGdiCIfirvfN6ARhgDNEGYLpsAg28NMgAuFx1
         P/OV173m37zZup3/VlUMCsUVqnN7kyiNVgAaV0lV+kzD0EFz42TVvFDXsHpCB0toub95
         PfHThhk4SYfToUstfuR+Has0JUGUY7MAR/H51DYOq4Xb7GUrHNGxoZFlD0WO1AafxKy7
         uC4Te3xxCvvTUoKH1nofw8gpRg88VaPEBX002DUX9FcQw8658TLN2/T5O/H2Q6oEvfKX
         Y96g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tBdd9AOg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EKTmKghCDhB8+IlY06Qt0+T6fRzrs0tps0p+7BDgO1Y=;
        b=VZUDkEclcIszP1v40xMKjB7/oAtOsacsd21Ok6dXjKdNDkl2lyBfJp+292JJOSC76x
         X8iPvwscEbUD8bb7ONYBxahJBWiBsWEcLbC0L9+b4QtH2EwxoM0mJVEFwa+TQLjv6Lch
         Zh4Zoes0Ay7tneKT/vG39YJ6FiAIsxC6uOec8wZuZ9FYIrfGBF44XaZb/mJjOCV+Nm4c
         zOhDe74MUPEQQQb2nQuRyQzQl1raPGwFNLFPx1A2cFE+5wBPp6rxRwlJjKDp9LRuAvHn
         60xU9lIbky9riU0rBFPmbQdz9rfT+9GinppNfreTOGX/UqEgjIzArbrf9HSVH1ibjet+
         fNNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EKTmKghCDhB8+IlY06Qt0+T6fRzrs0tps0p+7BDgO1Y=;
        b=Y7evjUO8hZVStR4tLcce0TJaaXeQ3KZd3CoYmhhI2F1cNUaBLJy7oXAVrjRDbl8rPo
         hoBPYMgP+HeLIFY7SmvFFvy6x3auaCFwKJg8YhUalBkQgCK7nMd3eUQJvB06+TS38UwR
         W1uRUMjfl6yfpMbyml4CwvzBBCw29FPyXttIBsJ6iKtTEwKDiZe86/0e7mslYlUp02sk
         aNutZvoAezaoshiA1H3uI4REWQ/69pfLO5oQPzXLAlxzqzVCOlxLrzlk7p9yAcX4Rt1f
         f+5rqsAzcJ6unoYvQqLAl3/EPcZswTEHvzomNDxNYA+p7YTjp0yPQeIFJM2C889MDcKT
         HqoA==
X-Gm-Message-State: APjAAAX4ragnEQSoJKH4WEjU8MkjGy1QjjL3/2gLPvgG1jiqfEcH/qR+
	zzoKRDn9and9embpMCW3GrM=
X-Google-Smtp-Source: APXvYqzQu3ZbWxH7iHnD7AK9N0ZHcW/gKlKV5c4NYTtKyCYbpDN2kKf+5SaqPqY5x7ea7byYs1mAOw==
X-Received: by 2002:a17:90a:3745:: with SMTP id u63mr1938371pjb.123.1579864989481;
        Fri, 24 Jan 2020 03:23:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb88:: with SMTP id m8ls651590pls.6.gmail; Fri, 24
 Jan 2020 03:23:09 -0800 (PST)
X-Received: by 2002:a17:902:8485:: with SMTP id c5mr3121026plo.330.1579864989011;
        Fri, 24 Jan 2020 03:23:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579864989; cv=none;
        d=google.com; s=arc-20160816;
        b=rfRRWCFjHJVTzow+2wU5PUntUNtb8oBy9E4Pc7aovY6Dykb/An7/Dh5lGWKrmPxzfm
         UXafpc8y79PgFnsHmXxTMmr4oAWh+JfTzpiI/lKqucbyP2cjE6M5npw/rCIfL9OHVAib
         K0Z0/T4z8x/CE0WZQJkVnqpE8K+/pQWmOV3JP6hlg4kMR5lAMzKPwEGNw+tN91ADR/d/
         KbWIsOSfxVo2xlTx/oQZ0EilFkxD+u7ntBjGxdDRjmGcMg9469+V3HVhNHXhdYTiVB35
         OicNP8MjBc0kMT1vHbN3qpylhpZXwjoLDp/w8C9AoJYhlpnQTS5TYZmpnwfZoeIEG2ZQ
         uwsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hwzQ3VCUqoiQqyG2DwDT1s000avPDz+MSypapI5GJkU=;
        b=0siu34RPYXX0nobHQjCOeKd5nPwVJ/BsgntIMmJNJUGh6NqiUY7/YpUSCiPb4zkZTE
         IE+rYxB1H067DUxA2oqRuWNWgMxDw6L20PN1jA3O1JtA3atgFwOC1xbr+rz0O5bmw0b2
         x2GOjtZnhKETnYWdUHDCgX1Sj+/XBjrBppm9glBL9qAw+MHteq7eKp54icp+kF4UjGmv
         x6IsuCzYM0JaohqRwKQTUE9Efj7kygv+yEazlODy5RQna3ocKAXI6WGB1jtrnS8iUR8Y
         55BfeEpwx7ZzyUhxViDsDdzs6wVmfJTtesG1VCkIJGFpIkeu4iNJkDWJdxf7hCrZtMyN
         gOTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tBdd9AOg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id r18si264772pfc.2.2020.01.24.03.23.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jan 2020 03:23:09 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id x1so703010qvr.8
        for <kasan-dev@googlegroups.com>; Fri, 24 Jan 2020 03:23:08 -0800 (PST)
X-Received: by 2002:a05:6214:1103:: with SMTP id e3mr2207642qvs.159.1579864987764;
 Fri, 24 Jan 2020 03:23:07 -0800 (PST)
MIME-Version: 1.0
References: <20200121160512.70887-1-elver@google.com>
In-Reply-To: <20200121160512.70887-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Jan 2020 12:22:56 +0100
Message-ID: <CACT4Y+aRk5=7UoPb9zmDm5XL9CcJDv9YnzndjXYtt+3FKd8maw@mail.gmail.com>
Subject: Re: [PATCH v2 1/5] include/linux: Add instrumented.h infrastructure
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Al Viro <viro@zeniv.linux.org.uk>, 
	Daniel Axtens <dja@axtens.net>, Christophe Leroy <christophe.leroy@c-s.fr>, 
	Michael Ellerman <mpe@ellerman.id.au>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Ingo Molnar <mingo@kernel.org>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Daniel Borkmann <daniel@iogearbox.net>, 
	Kees Cook <keescook@chromium.org>, cyphar@cyphar.com, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tBdd9AOg;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Tue, Jan 21, 2020 at 5:05 PM 'Marco Elver' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> This adds instrumented.h, which provides generic wrappers for memory
> access instrumentation that the compiler cannot emit for various
> sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> future this will also include KMSAN instrumentation.
>
> Note that, copy_{to,from}_user should use special instrumentation, since
> we should be able to instrument both source and destination memory
> accesses if both are kernel memory.
>
> The current patch only instruments the memory access where the address
> is always in kernel space, however, both may in fact be kernel addresses
> when a compat syscall passes an argument allocated in the kernel to a
> real syscall. In a future change, both KASAN and KCSAN should check both
> addresses in such cases, as well as KMSAN will make use of both
> addresses. [It made more sense to provide the completed function
> signature, rather than updating it and changing all locations again at a
> later time.]

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Marco Elver <elver@google.com>
> Acked-by: Alexander Potapenko <glider@google.com>
> ---
> v2:
> * Simplify header, since we currently do not need pre/post user-copy
>   distinction.
> * Make instrument_copy_{to,from}_user function arguments match
>   copy_{to,from}_user and update rationale in commit message.
> ---
>  include/linux/instrumented.h | 109 +++++++++++++++++++++++++++++++++++
>  1 file changed, 109 insertions(+)
>  create mode 100644 include/linux/instrumented.h
>
> diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> new file mode 100644
> index 000000000000..43e6ea591975
> --- /dev/null
> +++ b/include/linux/instrumented.h
> @@ -0,0 +1,109 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +/*
> + * This header provides generic wrappers for memory access instrumentation that
> + * the compiler cannot emit for: KASAN, KCSAN.
> + */
> +#ifndef _LINUX_INSTRUMENTED_H
> +#define _LINUX_INSTRUMENTED_H
> +
> +#include <linux/compiler.h>
> +#include <linux/kasan-checks.h>
> +#include <linux/kcsan-checks.h>
> +#include <linux/types.h>
> +
> +/**
> + * instrument_read - instrument regular read access
> + *
> + * Instrument a regular read access. The instrumentation should be inserted
> + * before the actual read happens.
> + *
> + * @ptr address of access
> + * @size size of access
> + */
> +static __always_inline void instrument_read(const volatile void *v, size_t size)
> +{
> +       kasan_check_read(v, size);
> +       kcsan_check_read(v, size);
> +}
> +
> +/**
> + * instrument_write - instrument regular write access
> + *
> + * Instrument a regular write access. The instrumentation should be inserted
> + * before the actual write happens.
> + *
> + * @ptr address of access
> + * @size size of access
> + */
> +static __always_inline void instrument_write(const volatile void *v, size_t size)
> +{
> +       kasan_check_write(v, size);
> +       kcsan_check_write(v, size);
> +}
> +
> +/**
> + * instrument_atomic_read - instrument atomic read access
> + *
> + * Instrument an atomic read access. The instrumentation should be inserted
> + * before the actual read happens.
> + *
> + * @ptr address of access
> + * @size size of access
> + */
> +static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
> +{
> +       kasan_check_read(v, size);
> +       kcsan_check_atomic_read(v, size);
> +}
> +
> +/**
> + * instrument_atomic_write - instrument atomic write access
> + *
> + * Instrument an atomic write access. The instrumentation should be inserted
> + * before the actual write happens.
> + *
> + * @ptr address of access
> + * @size size of access
> + */
> +static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
> +{
> +       kasan_check_write(v, size);
> +       kcsan_check_atomic_write(v, size);
> +}
> +
> +/**
> + * instrument_copy_to_user - instrument reads of copy_to_user
> + *
> + * Instrument reads from kernel memory, that are due to copy_to_user (and
> + * variants). The instrumentation must be inserted before the accesses.
> + *
> + * @to destination address
> + * @from source address
> + * @n number of bytes to copy
> + */
> +static __always_inline void
> +instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
> +{
> +       kasan_check_read(from, n);
> +       kcsan_check_read(from, n);
> +}
> +
> +/**
> + * instrument_copy_from_user - instrument writes of copy_from_user
> + *
> + * Instrument writes to kernel memory, that are due to copy_from_user (and
> + * variants). The instrumentation should be inserted before the accesses.
> + *
> + * @to destination address
> + * @from source address
> + * @n number of bytes to copy
> + */
> +static __always_inline void
> +instrument_copy_from_user(const void *to, const void __user *from, unsigned long n)
> +{
> +       kasan_check_write(to, n);
> +       kcsan_check_write(to, n);
> +}
> +
> +#endif /* _LINUX_INSTRUMENTED_H */
> --
> 2.25.0.341.g760bfbb309-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121160512.70887-1-elver%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaRk5%3D7UoPb9zmDm5XL9CcJDv9YnzndjXYtt%2B3FKd8maw%40mail.gmail.com.
