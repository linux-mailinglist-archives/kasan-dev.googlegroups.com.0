Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA6DTXAAMGQE7HFOO4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BB275A96454
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 11:29:41 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2c70bdbbb1bsf3857998fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 02:29:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745314180; cv=pass;
        d=google.com; s=arc-20240605;
        b=WSQvaJRcTM/ihQOb9jk7z3k62Zu5CxBYzsY90pBB1H2hl0s/BFaJpv9+aM0j5hjrIo
         dM/F4p8hI61RwNLH9HfFuuxGNR4oCaXmea5rxBDkOstbjpUQyDu1qGHncVDfnwTrgXen
         incpfzliB2us7LQpxkGfDpjA1E2CnWQkrj8fse062P0pL+GIzk+F/ZaaB2lLHRXSYIjo
         Nb0rtRYXRjgjxAsE2jGm8Tv8nmdaP+p+LWKJXp8jpRO1PVsWRg0QP5K5iROaxQIUtxMi
         NIjYtnhXZzbbfD6dbWfXmTXo6UoDvO4suHfL+F2xEq+yrJE3UQ3Y8LkUw4yPy0crBXGL
         3FUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=i4YMZUP0VV31Tayu5lPSBFezXct/YyRVfpEl38hOxDU=;
        fh=aYHQfbpt2OpUQz5L6Derfn5AGmd3OM8ChZY4H+W5aCQ=;
        b=UEnHDdboIOY5HVULMS0rNTPaPbnYasSBAh6rliEgQjUjg89j3yKyRNnnUWDGcEZzlO
         b/wNaKNWPNiBnu+FjyN4y+Vwh42hX2d4tT0yXpND8Cl9Emj2r0LL9araHs/Y2uLBsuqO
         ZZfzc/ZwwTGCz+LZhPXL9D6ytibFzEypnSmkUtlXrnGv8XAbNvp6s+1PwHkXR4ESfQzU
         ZjOUlBjnU21tJ6lGZajwq9K+CMkG8hKMZE8pD2+NhBNJDdd1lWKGvSsUq2GSgPBYQnvu
         eLPHam9ZMe0UwzOywY9CetCRBD36jJYrEilnGXS+ndkp1fyU0nwVVoqdAo0gVMT9GYhk
         xNaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p6UaDOaW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745314180; x=1745918980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i4YMZUP0VV31Tayu5lPSBFezXct/YyRVfpEl38hOxDU=;
        b=nriJHiSmA27k4R/eN4BGoP+LdMVVDcXhpABCHD5ukH0aDYUuIs37qJ/rQWPPr6BrAi
         Y9sOXHxO+s7Z1f0cmosAVZoV80gHPxesn0c6SjJawhbYZ3dpEm6+JanYFFm8WfBfDYlV
         Kj50kEBpFs9og0ljkaKHAmBZjx87KFHQg+Iy7wLmgMGQzJNS+CTBlrISkxw/ot127WuI
         kh7/3mTzOdoKIchh4PMMRqPcUH7Ur8FvpPXFM/6kZrFSkX3R3JOvjN9dpT9lmrqnWBKh
         HZxOy1lqtwcDO/flT1sLp1qMZs5AW9jiZ2xXp7HOrjWTLGtD2CLTCaghaDX7ECkGfryw
         1TZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745314180; x=1745918980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=i4YMZUP0VV31Tayu5lPSBFezXct/YyRVfpEl38hOxDU=;
        b=NCcFuFGidkcM9fZErvEyvOJy6jhsFuG55AtdCZ+roU4ogvA5gI6toSFn+tF/JuPrXk
         3jMTohO8dHPuRd4OT9iZeczP+U28tx65x33j8K/8MNlLwWqe/HuIjTr2qqZDVZjABCAg
         wNHftdMPAmoxpLt8pyfmrKUdkO99pj0QntLz/ZsWc+ALA6AvJk1qABWeT+tjwdCYOk7a
         cs+whpY6xxyOpCHSd6GZDqAWtfD8Z4jq7MleLK6lXtF0gEfpViYjA92CTpgk7YyUFIqS
         f2s4/ojZvOx6ha73cjFg3SRhqdC6Ph9iqQ2IxCB0wWmfjwrKvhmM4eb4u3U6vKRdRYd/
         SqSg==
X-Forwarded-Encrypted: i=2; AJvYcCUUssx2MKmIKBwF/3pwGQldippmQBDKvBLAw4/BeR98F9F/FaLqwF4tgb3/ll3oX+aL20gNdA==@lfdr.de
X-Gm-Message-State: AOJu0Yz0ZHGuczSqiHaNqSaYgCbxZgDqViNN2C+kEQ08Yl7tGr2FLUsH
	XX6OQLrRLVt5sMMXkwIXLW/KGUeA5FJOUoWWRiAvEfRXhp7LU0dP
X-Google-Smtp-Source: AGHT+IHTyTxiS8qDdOZCnVPAg4jW1LhuqsJpnHxYZBaZw8tN1zyO4yJYOGYSvBPqdhGt3aVaSJ3K+g==
X-Received: by 2002:a05:6871:200a:b0:29d:c764:f873 with SMTP id 586e51a60fabf-2d526d55093mr8936598fac.31.1745314180130;
        Tue, 22 Apr 2025 02:29:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALcUzJ9qA4rFq0z0AStrIyAJWIWnA6hga2r9Jz5rEHHQQ==
Received: by 2002:a05:6871:8001:b0:2c2:d749:9156 with SMTP id
 586e51a60fabf-2d4eb985470ls465437fac.0.-pod-prod-05-us; Tue, 22 Apr 2025
 02:29:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+xAggLolJV3urNvI2soFY0zd8zagrY54XsO8c9cifzn1YzLe5cfvbuBveGFuJZiHIo16ktOJ7Si8=@googlegroups.com
X-Received: by 2002:a05:6871:e00d:b0:2c1:51f7:e648 with SMTP id 586e51a60fabf-2d526e10ed6mr9719969fac.35.1745314179100;
        Tue, 22 Apr 2025 02:29:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745314179; cv=none;
        d=google.com; s=arc-20240605;
        b=kr6RLAy0VGmh34KI/MYtf/rHqzLqjFIe4UI9o1rDZStg5Aj7TaR1DKDL8zRthM3H80
         sP6ShGrVrwXvasSzZOpOUdv5HS9PXjY8UX5N7vzUltOTCET2hr8weo1YXKLLzHKH4Oeu
         AnLRg+ahpwqn+8lE+KPnz7Ix896+mRkT/THoFPEtsBl4IxSNnYWd+MYIhzYd7y1EcIys
         yXxtwgor43iu6R3ZdlywMTS5B6FYEXq0o5rHX6pli+ihMhM0lM8+13BFwc/Ct6IXt02s
         +9v0qW5wdtIc0DuzC9UYaGjxKg5Qfv1YuSoh1Wd2fiQLEylBYP9GG+Utj0syEJHB1Jwf
         e1Sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C2Xf4pmHwFxMcvAGykvpxOXuajpaq44nsmGp86t0OmA=;
        fh=Iw3K48DKX0djA/1lkdyYIXkBdpWqvhKkk4SwzyFY/MA=;
        b=SAwMa0nXz3MmU4upIyV8+mrIzVFYnPgt2s8z/ty2jL6Fsbd2iqNKTnO3Q4QrMJG/r1
         FPcOerNZqMhn9GJVEYyMUzPgXjkkngECvy6kRiUeowaFTmwbAru3LvrNAKRV2N5bCJ92
         3eKaTFg4uOS/iLVzsiOfPDlEWWMJSvICykdR6KNoBvgg0X0Oz6vn0hIDXGcm+w0iGLj+
         wPl1Bfwx3Twrnxo5Pc2P2jkd/RcKsyEbhyEMLLzHRF/Xc5VvveItqd2/WSMs/qXj9NsU
         NSfWtebNoIqnkfN5SIpUk6NDdiUC11SLKYGK8oGlpt/tIwZE9CLNkSr1RAwxm9bAZ/U1
         yXnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p6UaDOaW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2d52175ee7dsi234782fac.4.2025.04.22.02.29.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Apr 2025 02:29:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id 98e67ed59e1d1-3012a0c8496so3655235a91.2
        for <kasan-dev@googlegroups.com>; Tue, 22 Apr 2025 02:29:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXXHcJjpaCT2rYmiT6Dd4EAl3yeShQw5bER70M/Puy741pQJWJAcH+EuqDj1V8ThUrF2g1w+cbQj1Q=@googlegroups.com
X-Gm-Gg: ASbGncscNNYqXNhZkPCkQqF8XJDPTwfTKZ5mw0X5soEF6Hzra8Coo0h7PPDBaaYclpY
	QPWebUjA8mK9IOpKPPYl90OxbeogBWYBPQngNSEeEwVSGUd+V9nrvS1SQoAAVXWdUwIYUTrXtDr
	B28EOHxekC8ome0s/meWdzThvaGp7pZckVHV32w06avywEhSNCi6FySQ==
X-Received: by 2002:a17:90b:5646:b0:2ee:f80c:6889 with SMTP id
 98e67ed59e1d1-3087bcc8a9dmr24296447a91.33.1745314178289; Tue, 22 Apr 2025
 02:29:38 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-6-glider@google.com>
In-Reply-To: <20250416085446.480069-6-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Apr 2025 11:29:01 +0200
X-Gm-Features: ATxdqUHRzEwfGkMe4bHdQJyW3hQZgIGBenSuXDct-VznZp1AxsAqbX5joH81qQw
Message-ID: <CANpmjNM=AAtiXeDHgG+ec48=xwBTzphG3rpJZ3krpG2Hd1FixQ@mail.gmail.com>
Subject: Re: [PATCH 5/7] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p6UaDOaW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102e as
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

On Wed, 16 Apr 2025 at 10:55, Alexander Potapenko <glider@google.com> wrote:
>
> ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
> in the presence of CONFIG_KCOV_ENABLE_GUARDS.
>
> The buffer shared with the userspace is divided in two parts, one holding
> a bitmap, and the other one being the trace. The single parameter of
> ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
> bitmap.
>
> Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
> pointer to a unique guard variable. Upon the first call of each hook,
> the guard variable is initialized with a unique integer, which is used to
> map those hooks to bits in the bitmap. In the new coverage collection mode,
> the kernel first checks whether the bit corresponding to a particular hook
> is set, and then, if it is not, the PC is written into the trace buffer,
> and the bit is set.
>
> Note: when CONFIG_KCOV_ENABLE_GUARDS is disabled, ioctl(KCOV_UNIQUE_ENABLE)
> returns -ENOTSUPP, which is consistent with the existing kcov code.
>
> Also update the documentation.

Do you have performance measurements (old vs. new mode) that can be
included in this commit description?

> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  Documentation/dev-tools/kcov.rst |  43 +++++++++++
>  include/linux/kcov-state.h       |   8 ++
>  include/linux/kcov.h             |   2 +
>  include/uapi/linux/kcov.h        |   1 +
>  kernel/kcov.c                    | 129 +++++++++++++++++++++++++++----
>  5 files changed, 170 insertions(+), 13 deletions(-)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index 6611434e2dd24..271260642d1a6 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -137,6 +137,49 @@ mmaps coverage buffer, and then forks child processes in a loop. The child
>  processes only need to enable coverage (it gets disabled automatically when
>  a thread exits).
>
> +Unique coverage collection
> +---------------------------
> +
> +Instead of collecting raw PCs, KCOV can deduplicate them on the fly.
> +This mode is enabled by the ``KCOV_UNIQUE_ENABLE`` ioctl (only available if
> +``CONFIG_KCOV_ENABLE_GUARDS`` is on).
> +
> +.. code-block:: c
> +
> +       /* Same includes and defines as above. */
> +       #define KCOV_UNIQUE_ENABLE              _IOW('c', 103, unsigned long)

Here it's _IOW.

> +       #define BITMAP_SIZE                     (4<<10)
> +
> +       /* Instead of KCOV_ENABLE, enable unique coverage collection. */
> +       if (ioctl(fd, KCOV_UNIQUE_ENABLE, BITMAP_SIZE))
> +               perror("ioctl"), exit(1);
> +       /* Reset the coverage from the tail of the ioctl() call. */
> +       __atomic_store_n(&cover[BITMAP_SIZE], 0, __ATOMIC_RELAXED);
> +       memset(cover, 0, BITMAP_SIZE * sizeof(unsigned long));
> +
> +       /* Call the target syscall call. */
> +       /* ... */
> +
> +       /* Read the number of collected PCs. */
> +       n = __atomic_load_n(&cover[BITMAP_SIZE], __ATOMIC_RELAXED);
> +       /* Disable the coverage collection. */
> +       if (ioctl(fd, KCOV_DISABLE, 0))
> +               perror("ioctl"), exit(1);
> +
> +Calling ``ioctl(fd, KCOV_UNIQUE_ENABLE, bitmap_size)`` carves out ``bitmap_size``
> +words from those allocated by ``KCOV_INIT_TRACE`` to keep an opaque bitmap that
> +prevents the kernel from storing the same PC twice. The remaining part of the
> +trace is used to collect PCs, like in other modes (this part must contain at
> +least two words, like when collecting non-unique PCs).
> +
> +The mapping between a PC and its position in the bitmap is persistent during the
> +kernel lifetime, so it is possible for the callers to directly use the bitmap
> +contents as a coverage signal (like when fuzzing userspace with AFL).
> +
> +In order to reset the coverage between the runs, the user needs to rewind the
> +trace (by writing 0 into the first word past ``bitmap_size``) and wipe the whole
> +bitmap.
> +
>  Comparison operands collection
>  ------------------------------
>
> diff --git a/include/linux/kcov-state.h b/include/linux/kcov-state.h
> index 6e576173fd442..26e275fe90684 100644
> --- a/include/linux/kcov-state.h
> +++ b/include/linux/kcov-state.h
> @@ -26,6 +26,14 @@ struct kcov_state {
>                 /* Buffer for coverage collection, shared with the userspace. */
>                 unsigned long *trace;
>
> +               /* Size of the bitmap (in bits). */
> +               unsigned int bitmap_size;
> +               /*
> +                * Bitmap for coverage deduplication, shared with the
> +                * userspace.
> +                */
> +               unsigned long *bitmap;
> +
>                 /*
>                  * KCOV sequence number: incremented each time kcov is
>                  * reenabled, used by kcov_remote_stop(), see the comment there.
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 7ec2669362fd1..41eebcd3ab335 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -10,6 +10,7 @@ struct task_struct;
>  #ifdef CONFIG_KCOV
>
>  enum kcov_mode {
> +       KCOV_MODE_INVALID = -1,
>         /* Coverage collection is not enabled yet. */
>         KCOV_MODE_DISABLED = 0,
>         /* KCOV was initialized, but tracing mode hasn't been chosen yet. */
> @@ -23,6 +24,7 @@ enum kcov_mode {
>         KCOV_MODE_TRACE_CMP = 3,
>         /* The process owns a KCOV remote reference. */
>         KCOV_MODE_REMOTE = 4,
> +       KCOV_MODE_TRACE_UNIQUE_PC = 5,
>  };
>
>  #define KCOV_IN_CTXSW (1 << 30)
> diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
> index ed95dba9fa37e..fe1695ddf8a06 100644
> --- a/include/uapi/linux/kcov.h
> +++ b/include/uapi/linux/kcov.h
> @@ -22,6 +22,7 @@ struct kcov_remote_arg {
>  #define KCOV_ENABLE                    _IO('c', 100)
>  #define KCOV_DISABLE                   _IO('c', 101)
>  #define KCOV_REMOTE_ENABLE             _IOW('c', 102, struct kcov_remote_arg)
> +#define KCOV_UNIQUE_ENABLE             _IOR('c', 103, unsigned long)

_IOR? The unsigned long arg is copied to the kernel, so this should be
_IOW, right?

>  enum {
>         /*
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 7b726fd761c1b..dea25c8a53b52 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -29,6 +29,10 @@
>
>  #include <asm/setup.h>
>
> +#ifdef CONFIG_KCOV_ENABLE_GUARDS
> +atomic_t kcov_guard_max_index = ATOMIC_INIT(1);
> +#endif
> +
>  #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
>
>  /* Number of 64-bit words written per one comparison: */
> @@ -161,8 +165,7 @@ static __always_inline bool in_softirq_really(void)
>         return in_serving_softirq() && !in_hardirq() && !in_nmi();
>  }
>
> -static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
> -                                   struct task_struct *t)
> +static notrace enum kcov_mode get_kcov_mode(struct task_struct *t)
>  {
>         unsigned int mode;
>
> @@ -172,7 +175,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
>          * coverage collection section in a softirq.
>          */
>         if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
> -               return false;
> +               return KCOV_MODE_INVALID;
>         mode = READ_ONCE(t->kcov_state.mode);
>         /*
>          * There is some code that runs in interrupts but for which
> @@ -182,7 +185,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
>          * kcov_start().
>          */
>         barrier();
> -       return mode == needed_mode;
> +       return mode;
>  }
>
>  static notrace unsigned long canonicalize_ip(unsigned long ip)
> @@ -201,7 +204,7 @@ static void sanitizer_cov_write_subsequent(unsigned long *trace, int size,
>
>         if (likely(pos < size)) {
>                 /*
> -                * Some early interrupt code could bypass check_kcov_mode() check
> +                * Some early interrupt code could bypass get_kcov_mode() check
>                  * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
>                  * raised between writing pc and updating pos, the pc could be
>                  * overitten by the recursive __sanitizer_cov_trace_pc().
> @@ -220,7 +223,7 @@ static void sanitizer_cov_write_subsequent(unsigned long *trace, int size,
>  #ifndef CONFIG_KCOV_ENABLE_GUARDS
>  void notrace __sanitizer_cov_trace_pc(void)
>  {
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> +       if (get_kcov_mode(current) != KCOV_MODE_TRACE_PC)
>                 return;
>
>         sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> @@ -229,14 +232,73 @@ void notrace __sanitizer_cov_trace_pc(void)
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
>  #else
> +
> +DEFINE_PER_CPU(u32, saved_index);
> +/*
> + * Assign an index to a guard variable that does not have one yet.
> + * For an unlikely case of a race with another task executing the same basic
> + * block, we store the unused index in a per-cpu variable.
> + * In an even less likely case the current task may lose a race and get
> + * rescheduled onto a CPU that already has a saved index, discarding that index.
> + * This will result in an unused hole in the bitmap, but such events should have
> + * minor impact on the overall memory consumption.
> + */
> +static __always_inline u32 init_pc_guard(u32 *guard)
> +{
> +       /* If the current CPU has a saved free index, use it. */
> +       u32 index = this_cpu_xchg(saved_index, 0);
> +       u32 old_guard;
> +
> +       if (likely(!index))
> +               /*
> +                * Allocate a new index. No overflow is possible, because 2**32
> +                * unique basic blocks will take more space than the max size
> +                * of the kernel text segment.
> +                */
> +               index = atomic_inc_return(&kcov_guard_max_index) - 1;
> +
> +       /*
> +        * Make sure another task is not initializing the same guard
> +        * concurrently.
> +        */
> +       old_guard = cmpxchg(guard, 0, index);
> +       if (unlikely(old_guard)) {
> +               /* We lost the race, save the index for future use. */
> +               this_cpu_write(saved_index, index);
> +               return old_guard;
> +       }
> +       return index;
> +}
> +
>  void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
>  {
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
> -               return;
> +       u32 pc_index;
> +       enum kcov_mode mode = get_kcov_mode(current);
>
> -       sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> -                                      current->kcov_state.s.trace_size,
> -                                      canonicalize_ip(_RET_IP_));
> +       switch (mode) {
> +       case KCOV_MODE_TRACE_UNIQUE_PC:
> +               pc_index = READ_ONCE(*guard);
> +               if (unlikely(!pc_index))
> +                       pc_index = init_pc_guard(guard);

This is an unlikely branch, yet init_pc_guard is __always_inline. Can
we somehow make it noinline? I know objtool will complain, but besides
the cosmetic issues, doing noinline and just giving it a better name
("kcov_init_pc_guard") and adding that to objtool whilelist will be
better for codegen.

> +
> +               /*
> +                * Use the bitmap for coverage deduplication. We assume both
> +                * s.bitmap and s.trace are non-NULL.
> +                */
> +               if (likely(pc_index < current->kcov_state.s.bitmap_size))
> +                       if (test_and_set_bit(pc_index,
> +                                            current->kcov_state.s.bitmap))
> +                               return;
> +               /* If the PC is new, write it to the trace. */
> +               fallthrough;
> +       case KCOV_MODE_TRACE_PC:
> +               sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
> +                                              current->kcov_state.s.trace_size,
> +                                              canonicalize_ip(_RET_IP_));
> +               break;
> +       default:
> +               return;
> +       }
>  }
>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
>
> @@ -255,7 +317,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>         u64 *trace;
>
>         t = current;
> -       if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
> +       if (get_kcov_mode(t) != KCOV_MODE_TRACE_CMP)
>                 return;
>
>         ip = canonicalize_ip(ip);
> @@ -374,7 +436,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
>         /* Cache in task struct for performance. */
>         t->kcov_state.s = state->s;
>         barrier();
> -       /* See comment in check_kcov_mode(). */
> +       /* See comment in get_kcov_mode(). */
>         WRITE_ONCE(t->kcov_state.mode, state->mode);
>  }
>
> @@ -408,6 +470,10 @@ static void kcov_reset(struct kcov *kcov)
>         kcov->state.mode = KCOV_MODE_INIT;
>         kcov->remote = false;
>         kcov->remote_size = 0;
> +       kcov->state.s.trace = kcov->state.s.area;
> +       kcov->state.s.trace_size = kcov->state.s.size;
> +       kcov->state.s.bitmap = NULL;
> +       kcov->state.s.bitmap_size = 0;
>         kcov->state.s.sequence++;
>  }
>
> @@ -594,6 +660,41 @@ static inline bool kcov_check_handle(u64 handle, bool common_valid,
>         return false;
>  }
>
> +static long kcov_handle_unique_enable(struct kcov *kcov,
> +                                     unsigned long bitmap_words)
> +{
> +       struct task_struct *t = current;
> +
> +       if (!IS_ENABLED(CONFIG_KCOV_ENABLE_GUARDS))
> +               return -ENOTSUPP;
> +       if (kcov->state.mode != KCOV_MODE_INIT || !kcov->state.s.area)
> +               return -EINVAL;
> +       if (kcov->t != NULL || t->kcov != NULL)
> +               return -EBUSY;
> +
> +       /*
> +        * Cannot use zero-sized bitmap, also the bitmap must leave at least two
> +        * words for the trace.
> +        */
> +       if ((!bitmap_words) || (bitmap_words >= (kcov->state.s.size - 1)))
> +               return -EINVAL;
> +
> +       kcov->state.s.bitmap_size = bitmap_words * sizeof(unsigned long) * 8;
> +       kcov->state.s.bitmap = kcov->state.s.area;
> +       kcov->state.s.trace_size = kcov->state.s.size - bitmap_words;
> +       kcov->state.s.trace =
> +               ((unsigned long *)kcov->state.s.area + bitmap_words);
> +
> +       kcov_fault_in_area(kcov);
> +       kcov->state.mode = KCOV_MODE_TRACE_UNIQUE_PC;
> +       kcov_start(t, kcov, &kcov->state);
> +       kcov->t = t;
> +       /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
> +       kcov_get(kcov);
> +
> +       return 0;
> +}
> +
>  static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                              unsigned long arg)
>  {
> @@ -627,6 +728,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
>                 kcov_get(kcov);
>                 return 0;
> +       case KCOV_UNIQUE_ENABLE:
> +               return kcov_handle_unique_enable(kcov, arg);
>         case KCOV_DISABLE:
>                 /* Disable coverage for the current task. */
>                 unused = arg;
> --
> 2.49.0.604.gff1f9ca942-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM%3DAAtiXeDHgG%2Bec48%3DxwBTzphG3rpJZ3krpG2Hd1FixQ%40mail.gmail.com.
