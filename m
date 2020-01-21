Return-Path: <kasan-dev+bncBCMIZB7QWENRBJ7MTPYQKGQEESVK7YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B2F6143D8B
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 14:01:29 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id v2sf1507975pgv.6
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 05:01:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579611687; cv=pass;
        d=google.com; s=arc-20160816;
        b=UL6pC6Vd7DYviZRnFqIv6AssgMK6ie0Y+E1rY04m/3bIuUiNQTo49aShN4IhSs+iYq
         zQ1TX2s6+qOFYbrNI1tFPV+uXixLC0E4Y/Sp61BFn2WUCfRjM/US6GLZdDullcwriLSR
         4mLiWi3YM51qh94fj/pp+PMjgNNK4a+lINEJIPjGQbRHChBUDV5zEKe2g82A0X0vUQ/N
         Vc5+WTo4jCJOZEt+IKMSuhvyFN9cugmgaA8tGDH3bXyvsoufOvJTKHeJWX7/TlApiqvv
         0ypUHysRmQccT70T4U0jmyQ6NOcC97Vkvq2UkkdhaBiQWCDHfWWU+ziuuJWPZXpWDSCw
         uCFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dCtia8W47Vg4EG5DsyEXkswACo/vwLoIOZAKerUPurk=;
        b=K0TvTVjCnfypuQblvqYDk2GRwvX16TlufXQKSzaJzPTy8nE/d4aLXcIiD10G5MtxFI
         THdWTvhMNWHMvv8ySpv/OWx4m7hL4SzoY+kuGHJuBqnpNvVybB0PmN5rOz9+mdglNO1p
         aHjbz6DCEcs5JYyl/iFJEcPDQwLeTD0X7/Il3a7Qo2ZrSaqtMVQx12Ji/PPcdPk2JBTu
         QyUT2YLDcf9sCgX+Vd+Hw0bslyZujNGhpZXsgBP0xf2BT1AErsS+taV5f7lnpWK7qm3E
         rdR7OFuwZ8SNgHvetG0xEXG73AobFlPVdrLi/xEurdEqc3KvIUQdw1QCZsDG4LDxk8FE
         ZJZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FCqcb4yg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dCtia8W47Vg4EG5DsyEXkswACo/vwLoIOZAKerUPurk=;
        b=hKanw3E8WeOuW32iK6+YIbSdVxTtYl/MIGD0OKNefnxNtwtH1J0tEfdDHi1dUQheXF
         II4kkSNcmNrJjVqulZtgUSs4RJOoQCJuCNJkghEfUoUUbC70mHlzEGEk/FKPu7crlGgx
         n2Mi4lOGLxvYDfkDBIuNXOmOa48U2xFZR16IaZzfJxXcBoI7Y8piIyxS6hWHO9hLrmdC
         MBhbvJp2zHMLuoWnKKq5+L7dIDJZ14LxMrRThQwBtJ6BXY74jvT0UZm1+XO2k5egCgMU
         mEMg8RYM6TQ5IaHjymaTiMtoY1OKrz7vnV9jYm/DSC4wpkkI5KmsAJ2HsIOViKQpwaPI
         NBQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dCtia8W47Vg4EG5DsyEXkswACo/vwLoIOZAKerUPurk=;
        b=tMGOdqDcPa5MmVGbP53mTw0nSFN8JREhUmB+vFeWU3+z6kS/UI03vx6mPwoXqpJkfb
         1/4CYVGJttJcsu+Jl7YhjWjIJZGnQETVeO6aP9OXmwTvbB4pq51nl2CtVH92hjGDzMk8
         J/aj1lCNDnVF8v0GIUhf54hazUx/iHo9cBv5R1zF+uIIKPtaqJD+2YbQlmJCKggxMEu6
         di2bLD9/mbnLVUht1TilbS5NybMWRo3iQYEXE6qeqpi9CWsc99jaqd8s8LggcclbWzTa
         urStaQhROXGMB9txL5WU83J+BADoL81NwKZ1bT/6WxBIvz7Lh9+knwCKLdDAo8nha8Vb
         Uiug==
X-Gm-Message-State: APjAAAUZsk/5Voixmj+/kmIoq0dUQBVkNUuO1Jh+JkMR0JsL9gY1rr01
	fgMEBOlk0B64FI4GxhoYvNw=
X-Google-Smtp-Source: APXvYqxBb/wSbIT0P7XpwWNB0n3mTfYGdOpncucEtt/YUo3GY0SXYFqBWsX1T5guqHAucxLC9cCiDg==
X-Received: by 2002:a17:90b:f06:: with SMTP id br6mr5134726pjb.125.1579611687551;
        Tue, 21 Jan 2020 05:01:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8505:: with SMTP id bj5ls7799097plb.11.gmail; Tue,
 21 Jan 2020 05:01:27 -0800 (PST)
X-Received: by 2002:a17:90a:2729:: with SMTP id o38mr5414622pje.45.1579611687136;
        Tue, 21 Jan 2020 05:01:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579611687; cv=none;
        d=google.com; s=arc-20160816;
        b=HEhUEAaIrUR3tIzlPhWoUWrsyCAMWoa4uRXTjKd7rCQlI5jnrI9NGFyjuw/82Nugc0
         BpUkpXnDGBa6f1Da1zop1lKL01UsmfrxLnSAqqpBklCR+Ci+qUYAIsInaBzNT6mQEbJP
         dc2s6nH0HWhKWbVcesVY+5acdHWPpw7OKqstniKNUiQET0+X64CBB4+D32jcgHGT8sWA
         P9Jc2ra4jCkEgoqHFO1ZvR60BpOLl2tacTrbUtp38FQtAb0gWFfNhI5wqtN2FRKpBeS+
         wt0AQkcstzC6BJVFPU7FiEJ6dvOXI0D86Uv0jOGqw8Oe6fV6lEGHSEI/8X4INq1WV7US
         R7Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z9x75RFBujs35vp0kR9dshO1qIssZRWX2b+4uOymJ80=;
        b=nf0XmtqNQGHq/xBHvwPfj82Ivk6ycVJa0kQX72xCrRdyU69JpX6jdPvyTFEqiPDpmf
         DIgkl257pVdlMctW6VBjZQeQju8R09HOcU7bW2/MqqeSu4s0V+4bQyy776VxoNQ3Siog
         y8aS3zDX8nmbUmhAmtra8CIReCeLeKqDMAj8bjOyBtJ8Vu22LVcB0g7ahSSAXsxB3wk3
         gTlUWCVyJTETklESo4jn4jgA7fBmw5+DkFwHnZ6t53xZgODhb7iTqKwKTZyumHBHbDyn
         ny1+r0dP3uV2TjWUX6kzLpju5w79ZtzLkjwRg/tkKBe4frCN7Yv89dtuOMf8YMEs6dsg
         M5LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FCqcb4yg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id k1si1762230pgj.0.2020.01.21.05.01.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 05:01:27 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id l14so1349080qvu.12
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 05:01:27 -0800 (PST)
X-Received: by 2002:ad4:5a53:: with SMTP id ej19mr4652000qvb.34.1579611685771;
 Tue, 21 Jan 2020 05:01:25 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
In-Reply-To: <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Jan 2020 14:01:13 +0100
Message-ID: <CACT4Y+bjAn0g980ZCxCn4MkgCsg7KrA69CExCeJZ63eRON5fXw@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Al Viro <viro@zeniv.linux.org.uk>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	Michael Ellerman <mpe@ellerman.id.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Daniel Borkmann <daniel@iogearbox.net>, cyphar@cyphar.com, 
	Kees Cook <keescook@chromium.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FCqcb4yg;       spf=pass
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

On Mon, Jan 20, 2020 at 3:45 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
> >
> > This adds instrumented.h, which provides generic wrappers for memory
> > access instrumentation that the compiler cannot emit for various
> > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > future this will also include KMSAN instrumentation.
> >
> > Note that, copy_{to,from}_user require special instrumentation,
> > providing hooks before and after the access, since we may need to know
> > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > also relevant in future for KMSAN).
> >
> > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> >  1 file changed, 153 insertions(+)
> >  create mode 100644 include/linux/instrumented.h
> >
> > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > new file mode 100644
> > index 000000000000..9f83c8520223
> > --- /dev/null
> > +++ b/include/linux/instrumented.h
> > @@ -0,0 +1,153 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +/*
> > + * This header provides generic wrappers for memory access instrumentation that
> > + * the compiler cannot emit for: KASAN, KCSAN.
> > + */
> > +#ifndef _LINUX_INSTRUMENTED_H
> > +#define _LINUX_INSTRUMENTED_H
> > +
> > +#include <linux/compiler.h>
> > +#include <linux/kasan-checks.h>
> > +#include <linux/kcsan-checks.h>
> > +#include <linux/types.h>
> > +
> > +/**
> > + * instrument_read - instrument regular read access
> > + *
> > + * Instrument a regular read access. The instrumentation should be inserted
> > + * before the actual read happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
>
> Based on offline discussion, that's what we add for KMSAN:
>
> > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_read(v, size);
> > +       kcsan_check_read(v, size);
>
> KMSAN: nothing
>
> > +}
> > +
> > +/**
> > + * instrument_write - instrument regular write access
> > + *
> > + * Instrument a regular write access. The instrumentation should be inserted
> > + * before the actual write happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
> > +static __always_inline void instrument_write(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_write(v, size);
> > +       kcsan_check_write(v, size);
>
> KMSAN: nothing
>
> > +}
> > +
> > +/**
> > + * instrument_atomic_read - instrument atomic read access
> > + *
> > + * Instrument an atomic read access. The instrumentation should be inserted
> > + * before the actual read happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
> > +static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_read(v, size);
> > +       kcsan_check_atomic_read(v, size);
>
> KMSAN: nothing
>
> > +}
> > +
> > +/**
> > + * instrument_atomic_write - instrument atomic write access
> > + *
> > + * Instrument an atomic write access. The instrumentation should be inserted
> > + * before the actual write happens.
> > + *
> > + * @ptr address of access
> > + * @size size of access
> > + */
> > +static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
> > +{
> > +       kasan_check_write(v, size);
> > +       kcsan_check_atomic_write(v, size);
>
> KMSAN: nothing
>
> > +}
> > +
> > +/**
> > + * instrument_copy_to_user_pre - instrument reads of copy_to_user
> > + *
> > + * Instrument reads from kernel memory, that are due to copy_to_user (and
> > + * variants).
> > + *
> > + * The instrumentation must be inserted before the accesses. At this point the
> > + * actual number of bytes accessed is not yet known.
> > + *
> > + * @dst destination address
> > + * @size maximum access size
> > + */
> > +static __always_inline void
> > +instrument_copy_to_user_pre(const volatile void *src, size_t size)
> > +{
> > +       /* Check before, to warn before potential memory corruption. */
> > +       kasan_check_read(src, size);
>
> KMSAN: check that (src,size) is initialized
>
> > +}
> > +
> > +/**
> > + * instrument_copy_to_user_post - instrument reads of copy_to_user
> > + *
> > + * Instrument reads from kernel memory, that are due to copy_to_user (and
> > + * variants).
> > + *
> > + * The instrumentation must be inserted after the accesses. At this point the
> > + * actual number of bytes accessed should be known.
> > + *
> > + * @dst destination address
> > + * @size maximum access size
> > + * @left number of bytes left that were not copied
> > + */
> > +static __always_inline void
> > +instrument_copy_to_user_post(const volatile void *src, size_t size, size_t left)
> > +{
> > +       /* Check after, to avoid false positive if memory was not accessed. */
> > +       kcsan_check_read(src, size - left);
>
> KMSAN: nothing

One detail I noticed for KMSAN is that kmsan_copy_to_user has a
special case when @to address is in kernel-space (compat syscalls
doing tricky things), in that case it only copies metadata. We can't
handle this with existing annotations.


 * actually copied to ensure there was no information leak. If @to belongs to
 * the kernel space (which is possible for compat syscalls), KMSAN just copies
 * the metadata.
 */
void kmsan_copy_to_user(const void *to, const void *from, size_t
to_copy, size_t left);


> > +}
> > +
> > +/**
> > + * instrument_copy_from_user_pre - instrument writes of copy_from_user
> > + *
> > + * Instrument writes to kernel memory, that are due to copy_from_user (and
> > + * variants).
> > + *
> > + * The instrumentation must be inserted before the accesses. At this point the
> > + * actual number of bytes accessed is not yet known.
> > + *
> > + * @dst destination address
> > + * @size maximum access size
> > + */
> > +static __always_inline void
> > +instrument_copy_from_user_pre(const volatile void *dst, size_t size)
> > +{
> > +       /* Check before, to warn before potential memory corruption. */
> > +       kasan_check_write(dst, size);
>
> KMSAN: nothing
>
> > +}
> > +
> > +/**
> > + * instrument_copy_from_user_post - instrument writes of copy_from_user
> > + *
> > + * Instrument writes to kernel memory, that are due to copy_from_user (and
> > + * variants).
> > + *
> > + * The instrumentation must be inserted after the accesses. At this point the
> > + * actual number of bytes accessed should be known.
> > + *
> > + * @dst destination address
> > + * @size maximum access size
> > + * @left number of bytes left that were not copied
> > + */
> > +static __always_inline void
> > +instrument_copy_from_user_post(const volatile void *dst, size_t size, size_t left)
> > +{
> > +       /* Check after, to avoid false positive if memory was not accessed. */
> > +       kcsan_check_write(dst, size - left);
>
> KMSAN: mark (dst, size-left) as initialized
>
> > +}
> > +
> > +#endif /* _LINUX_INSTRUMENTED_H */
> > --
> > 2.25.0.341.g760bfbb309-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbjAn0g980ZCxCn4MkgCsg7KrA69CExCeJZ63eRON5fXw%40mail.gmail.com.
