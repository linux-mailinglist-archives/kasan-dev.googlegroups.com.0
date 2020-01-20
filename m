Return-Path: <kasan-dev+bncBCMIZB7QWENRBEXVS3YQKGQEG367Q4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 19A1A142DA7
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:35:00 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id v2sf19334003pgv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:35:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579530898; cv=pass;
        d=google.com; s=arc-20160816;
        b=UKPR82pvrI8WN32DSSICuTdk/4njKdmlvubzvhsRL5LCLAvMpnGF3ea+z0qfs9YYBY
         Y1acthAhTyP0KPu+eucVh/dVUVBXdDflwXFcuJECS1fSCoc48DoBm1kJIbMp7ag4/yC4
         xKyUQmKqxB2E1BHN2wzqNTfqde/tTBHAwG1Gicx8Ger3jCg3Mq6LDvejXZVzG3xk0Nfi
         4H/MOsaoLdhGhiYm8VJXRs69Pz3RTCzVq6Nl9oFyN8pSf2ycFTk/w/BxUxy9ym5dFPKG
         cwCPlnVI1YsJDq5XxonL2xn5yHobTj7AJZuoTv7ooVQ3rY5uWyhwmaZDZPUCDJIDuKHe
         Iq3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gguTH8S9dtLJJug4gNDjzxYA0w1rFzlRz/kaxHotLxw=;
        b=wIakgCG+XYN/KCRIkKwIPF1y5aE/igsjgPU1fGPzfNDz1QgnWe2QgEJ3s7I6nOz1+r
         1I+2cPwMIkLZkzHLUXLVfKcTmFFGzaKVgoubN8tL+aaESIBDLNntLbEtu1OO5QDMf9JK
         Z/YT6kpVFQg9eWrvZetfsGwRJyN6ogdhjgpNn60TMXzDVKFmuxitqKCzP031B3np41VR
         GEg3uPJZI762yZrTGrUH7DrohEYGGmOWGqyb+VlThJU7EWrG173Sno0og20LG5F5jWSE
         et3JGVyRdkLE47T2Ztd/OCN71D+EDEPGTyOmi1Obwo5W+CSzTjRMAJY4DSSLVqM/c7I/
         MBnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FJupk/tj";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gguTH8S9dtLJJug4gNDjzxYA0w1rFzlRz/kaxHotLxw=;
        b=c4YMU5j45Ey9sfFIB1XQwI/wR1aQE8VVAheBnKFRYWAkfLBdO7N1hCGdJaVAbHT1J+
         +avii9IbJ8rAQe2ekOQjpPzhfZMiJHCZWOgyD6ild1Ch7GggB63jz48ihqYXBSi9UfBQ
         Hb5M6A7rXpEMq0Bs4tpGbDyiFTxdP8bmpu0usNbe4NXxJLcm1iSuFpIIkPZJduIGqBKe
         Zrl+XAyGfCvRa5Z9mRUZaCwmw8AgdAx86BwKZojGJlVAhQ8pzAoLvjU2sEo1j484WaUK
         2pWHhyTFaNOvLOkozsaiQtNpb6QCMwCTIZe3HbWJfj/n8IR5A0HAlc57X7WfbaEppHOk
         fnsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gguTH8S9dtLJJug4gNDjzxYA0w1rFzlRz/kaxHotLxw=;
        b=mi4+bq4vCn1lXJzL3exYBgnREtsWlvbkOz9JqQ12u1KaUf2cKhWFSG24rH+xtmdWnc
         ybYj6evzf4X0XlXaT/v1YJHOFWHXtNcIHtuGN3YTsFYX3CIakwjzO+21vobgHfdZUG48
         +vGFUTKaVFxmIMNSnEqsx7eh9ykl+jNQi+Ut0cPQGdi2vzGkPEdngINAfAltN3j0ZbiA
         NFpwRPhZDlkfcmTc9Fb21c4elhZOVnxKEU/GdgqiI9KHSOXEdeMxCdMcqw6nVz6HW45U
         LFu8PxOOOhCSx1gZCUL/4oFWmrpztEd1vBpgiGHzdBHDX4Ym67t45BiqwS8FmtXZpRco
         BrRQ==
X-Gm-Message-State: APjAAAW/6tV9rOgE6GS+mRDp0L0z1N4bjkf/7Vh0db9g8MmHfrrjcpCG
	MCJbRBu+tyiyhfLsH8vLqM8=
X-Google-Smtp-Source: APXvYqxMTav04JQIvvyLQmpANiFshdlk0FDguzwmAZTBX2rac426RLmlJr3ngPH8LzIUqYzXp8wu8A==
X-Received: by 2002:a17:902:242:: with SMTP id 60mr15194966plc.240.1579530898710;
        Mon, 20 Jan 2020 06:34:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6483:: with SMTP id y125ls10615498pfb.9.gmail; Mon, 20
 Jan 2020 06:34:58 -0800 (PST)
X-Received: by 2002:a63:4e05:: with SMTP id c5mr4988664pgb.281.1579530898255;
        Mon, 20 Jan 2020 06:34:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579530898; cv=none;
        d=google.com; s=arc-20160816;
        b=m735YvTSzOm92n22X9tA9fsaq8P+SfQYnzsbkrbw3oDDNCuplDOypnPvPPAud52V4Y
         2PRHXnrSeJZWstcs4k0lshPDP5Z+WCQgRDtPlhF2Wv1yfdvEBbBncpjSFzLGAmf7WB/R
         WovHwpBYS48NNxt/O3WtTbaBWCboB9OnRyQRvhKnsvi6HMhoTSyL/qow62n7gZUTMTLn
         SV+GYZt+0cwPU7u4oQybDSDQ4APUuBHU3hPtulGmNQHXinDEL1Qm5+bwpDgf4FNg+Wqj
         BvzTrE5/197gP5hVzmq3pGzD6gMikKChbtyq0Zl57yyIY+I+eCN4jP3N4z2efg928mXf
         3Z1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2RrHqMcOCPUU5FqgQCKkNsIxL0qLg6y6IPiTMnVNNc4=;
        b=xlgDlOnI9TwZab6cDopdfTMID8+XnzUWrzAgA/bNlour1KZH6wFA5kHB+063ZXnDrj
         5z3K4IrOcLLjcuL7Sxf3Ya699HnxGIWLu2eW3CBvH5YwrNNviHvGsbbLcLNgjEKku4J2
         0RVFslhZHW5bwMkmxIuEjDlUx+NTOkB0/ghz4lbuoBewVlRRWuaVgilTtV/Hu8Fiqc3E
         KiJXZcTi0rO6JQo0lsOYaUTWmjRQwW/4l6X2V/ftjpH/6xOXcANzU2xxMctRF/aAmh5P
         4CDPiiRyFPxI/Z7pgxDtP7qPUU69aL+kYTtohJIM8aP8XEYz6JYAj+ZIo2uT2oIdFOuL
         S7JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="FJupk/tj";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id m11si392025pjb.0.2020.01.20.06.34.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:34:58 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id 5so27808368qtz.1
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:34:58 -0800 (PST)
X-Received: by 2002:aed:2465:: with SMTP id s34mr20721986qtc.158.1579530897534;
 Mon, 20 Jan 2020 06:34:57 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com>
In-Reply-To: <20200120141927.114373-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 15:34:45 +0100
Message-ID: <CACT4Y+ajkjCzv2adupX9oVKjNppn-AKsGkGqLMExwjHXG37Lxw@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
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
 header.i=@google.com header.s=20161025 header.b="FJupk/tj";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Mon, Jan 20, 2020 at 3:19 PM Marco Elver <elver@google.com> wrote:
>
> This adds instrumented.h, which provides generic wrappers for memory
> access instrumentation that the compiler cannot emit for various
> sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> future this will also include KMSAN instrumentation.
>
> Note that, copy_{to,from}_user require special instrumentation,
> providing hooks before and after the access, since we may need to know
> the actual bytes accessed (currently this is relevant for KCSAN, and is
> also relevant in future for KMSAN).

How will KMSAN instrumentation look like?

> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
>  1 file changed, 153 insertions(+)
>  create mode 100644 include/linux/instrumented.h
>
> diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> new file mode 100644
> index 000000000000..9f83c8520223
> --- /dev/null
> +++ b/include/linux/instrumented.h
> @@ -0,0 +1,153 @@
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
> + * instrument_copy_to_user_pre - instrument reads of copy_to_user
> + *
> + * Instrument reads from kernel memory, that are due to copy_to_user (and
> + * variants).
> + *
> + * The instrumentation must be inserted before the accesses. At this point the
> + * actual number of bytes accessed is not yet known.
> + *
> + * @dst destination address
> + * @size maximum access size
> + */
> +static __always_inline void
> +instrument_copy_to_user_pre(const volatile void *src, size_t size)
> +{
> +       /* Check before, to warn before potential memory corruption. */
> +       kasan_check_read(src, size);
> +}
> +
> +/**
> + * instrument_copy_to_user_post - instrument reads of copy_to_user
> + *
> + * Instrument reads from kernel memory, that are due to copy_to_user (and
> + * variants).
> + *
> + * The instrumentation must be inserted after the accesses. At this point the
> + * actual number of bytes accessed should be known.
> + *
> + * @dst destination address
> + * @size maximum access size
> + * @left number of bytes left that were not copied
> + */
> +static __always_inline void
> +instrument_copy_to_user_post(const volatile void *src, size_t size, size_t left)
> +{
> +       /* Check after, to avoid false positive if memory was not accessed. */
> +       kcsan_check_read(src, size - left);

Why don't we check the full range?
Kernel intending to copy something racy to user already looks like a
bug to me, even if user-space has that page unmapped. User-space can
always make the full range succeed. What am I missing?


> +}
> +
> +/**
> + * instrument_copy_from_user_pre - instrument writes of copy_from_user
> + *
> + * Instrument writes to kernel memory, that are due to copy_from_user (and
> + * variants).
> + *
> + * The instrumentation must be inserted before the accesses. At this point the
> + * actual number of bytes accessed is not yet known.
> + *
> + * @dst destination address
> + * @size maximum access size
> + */
> +static __always_inline void
> +instrument_copy_from_user_pre(const volatile void *dst, size_t size)
> +{
> +       /* Check before, to warn before potential memory corruption. */
> +       kasan_check_write(dst, size);
> +}
> +
> +/**
> + * instrument_copy_from_user_post - instrument writes of copy_from_user
> + *
> + * Instrument writes to kernel memory, that are due to copy_from_user (and
> + * variants).
> + *
> + * The instrumentation must be inserted after the accesses. At this point the
> + * actual number of bytes accessed should be known.
> + *
> + * @dst destination address
> + * @size maximum access size
> + * @left number of bytes left that were not copied
> + */
> +static __always_inline void
> +instrument_copy_from_user_post(const volatile void *dst, size_t size, size_t left)
> +{
> +       /* Check after, to avoid false positive if memory was not accessed. */
> +       kcsan_check_write(dst, size - left);
> +}
> +
> +#endif /* _LINUX_INSTRUMENTED_H */
> --
> 2.25.0.341.g760bfbb309-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BajkjCzv2adupX9oVKjNppn-AKsGkGqLMExwjHXG37Lxw%40mail.gmail.com.
