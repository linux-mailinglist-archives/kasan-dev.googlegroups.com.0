Return-Path: <kasan-dev+bncBCMIZB7QWENRBYGXULCAMGQE27EDZNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 586E1B14CBD
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 13:09:22 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-45624f0be48sf25872055e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 04:09:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753787362; cv=pass;
        d=google.com; s=arc-20240605;
        b=a7+qxuSuzF8xkjG5m4RLjv0kFZrwxtP1vYCx0Jv1xM+EZ3MbfumurFrWPL0Mvuvwg1
         Nlrcqhn3PW70UnP7U8v4VgkGb4gkb6LryXtNo4mx3PfyM+pNFpwPU6SGrUjrYfrEUFTG
         pz4/f8kchFtwr5ATenUCUQHcbj/qkp2HYbbgeEEw3t1/c49+DwnO2DXdtZBZII6GiI9m
         4InXp3tPWI7t/dOYh+m1cUFd/H5Ke+nUng21S2you7xqw0+/K9JzxKA6NdiTwnjQIEop
         Oce/ms2MJwplAcajGIQUOyJfl7aQvj5ocYFGmLaT13vYnsrmwCrR8iRow5Mi631JeUkc
         rH/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f+/2TE017TaD291Juo555HhVb0XDr6UFgvaltVVwaCo=;
        fh=dKo3EEXGbgg9ZrwvahMueqofSlBLE5ZimaiaTazmgwY=;
        b=Oyv3AcprktVLiICXiV+QzKy+QEA+ydx8kyqpnWZwQhF/uCRWGbh1EHy2RR5Eiv9c9s
         WlOapJxmaaDTY3TPGL1kKL8mKod42sV46Hzsbp8W2Kd/KT0zbVcu7uRk1J4qMc+O+XOe
         Vnkx7U1CvL0iocZHgAIgeekYO7W2oec5AgJMbDQRKKzsVbI72hGqafCgy9VJRL5K0T+2
         lSbFUgJIFT63OJEpN+3lr90vZnlZIXswkJ9nJI2WTrHHhQFJ6rBKQ0HRwaQs5gFzoZOO
         TnDLcXJhgj5a7HqiASIQH4Mgvo2JxtvjIG+tXCNtDhqmihRUlITBGlbp9jmmegZY9o6y
         3RBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T0m933xL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753787361; x=1754392161; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=f+/2TE017TaD291Juo555HhVb0XDr6UFgvaltVVwaCo=;
        b=u7uzKf4AFih/HtME+XDIl/gJzlWB4CEepfxGlBE7M3sOI6aMZP2ollbzDEZrDPC6Hp
         DBD+Ahtn55k/q5qoRJ94jRd4P6cpZ/kjvfILwgrKNGeRFJC1faLNLcidMg2WwVTTul+o
         4QedN9bQv7bCsaf68A3ZtPq44OA6/CacU8j8LYJ/96TtletGTrS/tkYnJR4vaoDIwvKC
         IpYtFQVtoRhcLfQleZKirr93fAO6LA0DjSzEcznY4G/ByLjeU+pd4UNWaJ/sWRoCZxSh
         Zrq8g/B7d7WnNAqc6ph7MmbxkTH2njdircKeASR6w+ULVKqZbcDF7pj1wkjcqxm1u8E7
         1Z6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753787362; x=1754392162;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f+/2TE017TaD291Juo555HhVb0XDr6UFgvaltVVwaCo=;
        b=t2VsSVEpzQ/EqdUF2xfpIwv0Tbpr7Zz+/ijJJNLCDV5OX10G7xBHxGRqRdordKPrzK
         bvkZlF6IKym0dyIjS+yQpRdNE3hX7h6cH4MoEvU9Vj9qnN+TYv2HXiHayhuQT1r8Jouq
         UfkX/Gua1xGVdf1gdQi3tG+JqAEdwupK/FrWhSond/IyafB6GSAgACMcU0Fx0VM0we5x
         FPQRQ3bLMFLfWWpyk+Hsy6dJzxoYmK85TPfRrEO0BRRani/kvHcIW/g8UmgO1Di6Z1oy
         6IOiKt8XFH4U1u+mLwfLfIt52KgJHqjHQP4IvAulOy/BWS3lymOauKlXYRVnhrlQGwl2
         WHqA==
X-Forwarded-Encrypted: i=2; AJvYcCV3ufMlrNwRC6ztGeuyE433N1jhjSiOtZrsYzLrzquO+uYegIyO29w6WDtbcbCAKHpsk723ng==@lfdr.de
X-Gm-Message-State: AOJu0YzEo2BVvbnqcfIvv/7PVCaQvKwZvTMMVteyOe20GAslr2CVcSd5
	KM/2kCSvEMLytXN01e7c9VWxCwTcRmeNG3Haqy3GfssZtwiJnjcmIIiw
X-Google-Smtp-Source: AGHT+IGFgzYJx4Zo2l1V1YkmF8//WFhL2lmwoFwFD3F9yFwzqZ9ZnvI/jpW0ykSn0v0fr6l76vjIgQ==
X-Received: by 2002:a5d:5d0d:0:b0:3b7:8ac1:5e30 with SMTP id ffacd0b85a97d-3b78ac161c4mr4684005f8f.52.1753787361309;
        Tue, 29 Jul 2025 04:09:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcbt+MFMg52eI9xGaPrZW24jBblnVzGioFbcXFukENq0w==
Received: by 2002:a05:6000:230f:b0:3b6:db:74a4 with SMTP id
 ffacd0b85a97d-3b76e3a2b6cls2622546f8f.1.-pod-prod-01-eu; Tue, 29 Jul 2025
 04:09:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUs2PZQPdL9zHKxuBgNCR9RoCGQguUTM8epprMk+6nZPAVhU6VYGfnz/MLAG6sC5xozeUwZob8KxA4=@googlegroups.com
X-Received: by 2002:a05:6000:290d:b0:3b5:f93a:bcc with SMTP id ffacd0b85a97d-3b77675be5amr11335024f8f.35.1753787358440;
        Tue, 29 Jul 2025 04:09:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753787358; cv=none;
        d=google.com; s=arc-20240605;
        b=JAQRQM9i0Fm7rku8gm+Iz9Vm183vI/J104LRNjS3UimOhBspwykLTlStiOxlTZG2Wg
         Oq5ghOErhfIg6HrNMKEKpAIB+W5dzChyidaRpBRIniWbFuoyFNbIHp/qnRTNEtAJHgw9
         mFEa2Fjb516lVFbcZgla3NzsYRbl5s2syXskDqTWIvj5L4gNq4mZV6v8gUH6QKg2lFU+
         DsN4bzgIjrgWd+8ksFF40VuhGdFmSIXAra8LS2zuz62MuVPrnPFFgEupLYkkzX4FiAPE
         VYFHH/iXwsGol0sNVjXLV8Uz+5a/c0sa8sZd1/6VYgXKNOLL4beeAdjF0OdXIlcXsNuu
         Ov+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=m1Ngu8YHQrtXHt/o2iZDBt2xiRJgE6ESwrQcRS4m+Ho=;
        fh=y2KtRndDG5mjiDStZ+OjtYvdQ4bsjSemBGEkcVkc5NM=;
        b=jIXfSFPMDk6nHoneivkVsWjvd8PnRAYVdRlqHDvNh/Wb+hLruDqvaaaTw4gMfgtZnn
         L+2Ht8H7/OffyW2vEOnMmqUegESXqGYIgiCVrM/vHIUhE87sVhYjVrl0JSTfHX2Q/+YI
         G0MqHMGz2H4P3Pk6Ht/hb2l3mugDrNuSLwRTzCDE0zkCBMU/EhykLmgcQGtxlvFnlhEI
         HcC4pOFpdBTw6pbKQdYAUCI2kto6avY2w7RAIRoD0ngjiXrLOA/uve84+ympxWab125W
         170LRjK4NODst30sUV8MoxoJ/KiHSyFIHF8tI2qNtFST5/Mu7yGs4z1D0c82HrTgC2fR
         NTig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T0m933xL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b778ee1bedsi23490f8f.5.2025.07.29.04.09.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 04:09:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id 38308e7fff4ca-32b5931037eso44364301fa.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 04:09:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLQoQnCz3veeKIzsYwp9I8ik0Y8VtPotzluMyqbVL0vKCcYLdcLnDBdyO5paSLV/+2CDa1QdZzRFo=@googlegroups.com
X-Gm-Gg: ASbGncvl4Gw3y5dxeJbDs60OiabSk2rAMXSjFkqf8nnvGwS4JaWUm/Ozq9HzdyUolG+
	YixoNun+/Fzz26l/DByhcH6ePwhuwjbmg+SVNbtVQV3MoeWuiuB3UQE05vjflXkLPjWYvEDm6By
	YG+VzZIdf4FsKdryhalqt1KMXRC6BRcGQLyu4QFMy1Thy1Xr0Fyqld4n4ASQSDZL5vA+/PyG06X
	6m4Dvo+iUNMT6ypaCC4rL6A04SgDfHzs1zibg==
X-Received: by 2002:a2e:bea5:0:b0:32a:66e6:9ffe with SMTP id
 38308e7fff4ca-331ee7d3804mr47485341fa.21.1753787356936; Tue, 29 Jul 2025
 04:09:16 -0700 (PDT)
MIME-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com> <20250728152548.3969143-4-glider@google.com>
In-Reply-To: <20250728152548.3969143-4-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 13:09:05 +0200
X-Gm-Features: Ac12FXzCmhc07C6QzxlrscE4np9DutG_RGPHH85CmK1kWrz6rOLnHVAWcLgXiB4
Message-ID: <CACT4Y+bAp2YLh8hXwnDiVuq9HqoKEU9wFJSDZe5-kWYnnKk=qA@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] kcov: factor out struct kcov_state
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=T0m933xL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::230
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 28 Jul 2025 at 17:26, Alexander Potapenko <glider@google.com> wrote:
>
> Group several kcov-related fields (area, size, sequence) that are
> stored in various structures, into `struct kcov_state`, so that
> these fields can be easily passed around and manipulated.
> Note that now the spinlock in struct kcov applies to every member
> of struct kcov_state, including the sequence number.
>
> This prepares us for the upcoming change that will introduce more
> kcov state.
>
> Also update the MAINTAINERS entry: add include/linux/kcov_types.h,
> add myself as kcov reviewer.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v3:
>  - fix comments by Dmitry Vyukov:
>    - adjust a comment in sched.h
>    - fix incorrect parameters passed to kcov_start()
>
> v2:
>  - add myself to kcov MAINTAINERS
>  - rename kcov-state.h to kcov_types.h
>  - update the description
>  - do not move mode into struct kcov_state
>  - use '{ }' instead of '{ 0 }'
>
> Change-Id: If225682ea2f6e91245381b3270de16e7ea40df39
> ---
>  MAINTAINERS                |   2 +
>  include/linux/kcov.h       |   2 +-
>  include/linux/kcov_types.h |  22 ++++++++
>  include/linux/sched.h      |  13 +----
>  kernel/kcov.c              | 112 ++++++++++++++++---------------------
>  5 files changed, 77 insertions(+), 74 deletions(-)
>  create mode 100644 include/linux/kcov_types.h
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index c0b444e5fd5ad..6906eb9d88dae 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13008,11 +13008,13 @@ F:    include/linux/kcore.h
>  KCOV
>  R:     Dmitry Vyukov <dvyukov@google.com>
>  R:     Andrey Konovalov <andreyknvl@gmail.com>
> +R:     Alexander Potapenko <glider@google.com>
>  L:     kasan-dev@googlegroups.com
>  S:     Maintained
>  B:     https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
>  F:     Documentation/dev-tools/kcov.rst
>  F:     include/linux/kcov.h
> +F:     include/linux/kcov_types.h
>  F:     include/uapi/linux/kcov.h
>  F:     kernel/kcov.c
>  F:     scripts/Makefile.kcov
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 75a2fb8b16c32..2b3655c0f2278 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -2,7 +2,7 @@
>  #ifndef _LINUX_KCOV_H
>  #define _LINUX_KCOV_H
>
> -#include <linux/sched.h>
> +#include <linux/kcov_types.h>
>  #include <uapi/linux/kcov.h>
>
>  struct task_struct;
> diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
> new file mode 100644
> index 0000000000000..53b25b6f0addd
> --- /dev/null
> +++ b/include/linux/kcov_types.h
> @@ -0,0 +1,22 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef _LINUX_KCOV_STATE_H
> +#define _LINUX_KCOV_STATE_H
> +
> +#ifdef CONFIG_KCOV
> +/* See kernel/kcov.c for more details. */
> +struct kcov_state {
> +       /* Size of the area (in long's). */
> +       unsigned int size;
> +
> +       /* Buffer for coverage collection, shared with the userspace. */
> +       void *area;
> +
> +       /*
> +        * KCOV sequence number: incremented each time kcov is reenabled, used
> +        * by kcov_remote_stop(), see the comment there.
> +        */
> +       int sequence;
> +};
> +#endif /* CONFIG_KCOV */
> +
> +#endif /* _LINUX_KCOV_STATE_H */
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index aa9c5be7a6325..7901fece5aba3 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -42,6 +42,7 @@
>  #include <linux/restart_block.h>
>  #include <uapi/linux/rseq.h>
>  #include <linux/seqlock_types.h>
> +#include <linux/kcov_types.h>
>  #include <linux/kcsan.h>
>  #include <linux/rv.h>
>  #include <linux/uidgid_types.h>
> @@ -1516,16 +1517,11 @@ struct task_struct {
>  #endif /* CONFIG_TRACING */
>
>  #ifdef CONFIG_KCOV
> -       /* See kernel/kcov.c for more details. */
> -
>         /* Coverage collection mode enabled for this task (0 if disabled): */
>         unsigned int                    kcov_mode;
>
> -       /* Size of the kcov_area: */
> -       unsigned int                    kcov_size;
> -
> -       /* Buffer for coverage collection: */
> -       void                            *kcov_area;
> +       /* KCOV buffer state for this task. */
> +       struct kcov_state               kcov_state;
>
>         /* KCOV descriptor wired with this task or NULL: */
>         struct kcov                     *kcov;
> @@ -1533,9 +1529,6 @@ struct task_struct {
>         /* KCOV common handle for remote coverage collection: */
>         u64                             kcov_handle;
>
> -       /* KCOV sequence number: */
> -       int                             kcov_sequence;
> -
>         /* Collect coverage from softirq context: */
>         unsigned int                    kcov_softirq;
>  #endif
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 187ba1b80bda1..5170f367c8a1b 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -23,6 +23,7 @@
>  #include <linux/debugfs.h>
>  #include <linux/uaccess.h>
>  #include <linux/kcov.h>
> +#include <linux/kcov_types.h>
>  #include <linux/refcount.h>
>  #include <linux/log2.h>
>  #include <asm/setup.h>
> @@ -53,24 +54,17 @@ struct kcov {
>          *  - each code section for remote coverage collection
>          */
>         refcount_t              refcount;
> -       /* The lock protects mode, size, area and t. */
> +       /* The lock protects mode, state and t. */
>         spinlock_t              lock;
>         enum kcov_mode          mode;
> -       /* Size of arena (in long's). */
> -       unsigned int            size;
> -       /* Coverage buffer shared with user space. */
> -       void                    *area;
> +       struct kcov_state       state;
> +
>         /* Task for which we collect coverage, or NULL. */
>         struct task_struct      *t;
>         /* Collecting coverage from remote (background) threads. */
>         bool                    remote;
>         /* Size of remote area (in long's). */
>         unsigned int            remote_size;
> -       /*
> -        * Sequence is incremented each time kcov is reenabled, used by
> -        * kcov_remote_stop(), see the comment there.
> -        */
> -       int                     sequence;
>  };
>
>  struct kcov_remote_area {
> @@ -92,11 +86,9 @@ struct kcov_percpu_data {
>         void                    *irq_area;
>         local_lock_t            lock;
>
> -       unsigned int            saved_mode;
> -       unsigned int            saved_size;
> -       void                    *saved_area;
> +       enum kcov_mode          saved_mode;
>         struct kcov             *saved_kcov;
> -       int                     saved_sequence;
> +       struct kcov_state       saved_state;
>  };
>
>  static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
> @@ -217,10 +209,10 @@ void notrace __sanitizer_cov_trace_pc(void)
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
>                 return;
>
> -       area = t->kcov_area;
> +       area = t->kcov_state.area;
>         /* The first 64-bit word is the number of subsequent PCs. */
>         pos = READ_ONCE(area[0]) + 1;
> -       if (likely(pos < t->kcov_size)) {
> +       if (likely(pos < t->kcov_state.size)) {
>                 /* Previously we write pc before updating pos. However, some
>                  * early interrupt code could bypass check_kcov_mode() check
>                  * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
> @@ -250,10 +242,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>
>         /*
>          * We write all comparison arguments and types as u64.
> -        * The buffer was allocated for t->kcov_size unsigned longs.
> +        * The buffer was allocated for t->kcov_state.size unsigned longs.
>          */
> -       area = (u64 *)t->kcov_area;
> -       max_pos = t->kcov_size * sizeof(unsigned long);
> +       area = (u64 *)t->kcov_state.area;
> +       max_pos = t->kcov_state.size * sizeof(unsigned long);
>
>         count = READ_ONCE(area[0]);
>
> @@ -354,15 +346,13 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
>  #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
>
>  static void kcov_start(struct task_struct *t, struct kcov *kcov,
> -                       unsigned int size, void *area, enum kcov_mode mode,
> -                       int sequence)
> +                      enum kcov_mode mode, struct kcov_state *state)
>  {
> -       kcov_debug("t = %px, size = %u, area = %px\n", t, size, area);
> +       kcov_debug("t = %px, size = %u, area = %px\n", t, state->size,
> +                  state->area);
>         t->kcov = kcov;
>         /* Cache in task struct for performance. */
> -       t->kcov_size = size;
> -       t->kcov_area = area;
> -       t->kcov_sequence = sequence;
> +       t->kcov_state = *state;
>         /* See comment in check_kcov_mode(). */
>         barrier();
>         WRITE_ONCE(t->kcov_mode, mode);
> @@ -373,14 +363,14 @@ static void kcov_stop(struct task_struct *t)
>         WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
>         barrier();
>         t->kcov = NULL;
> -       t->kcov_size = 0;
> -       t->kcov_area = NULL;
> +       t->kcov_state.size = 0;
> +       t->kcov_state.area = NULL;
>  }
>
>  static void kcov_task_reset(struct task_struct *t)
>  {
>         kcov_stop(t);
> -       t->kcov_sequence = 0;
> +       t->kcov_state.sequence = 0;
>         t->kcov_handle = 0;
>  }
>
> @@ -396,7 +386,7 @@ static void kcov_reset(struct kcov *kcov)
>         kcov->mode = KCOV_MODE_INIT;
>         kcov->remote = false;
>         kcov->remote_size = 0;
> -       kcov->sequence++;
> +       kcov->state.sequence++;
>  }
>
>  static void kcov_remote_reset(struct kcov *kcov)
> @@ -436,7 +426,7 @@ static void kcov_put(struct kcov *kcov)
>  {
>         if (refcount_dec_and_test(&kcov->refcount)) {
>                 kcov_remote_reset(kcov);
> -               vfree(kcov->area);
> +               vfree(kcov->state.area);
>                 kfree(kcov);
>         }
>  }
> @@ -493,8 +483,8 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>         unsigned long flags;
>
>         spin_lock_irqsave(&kcov->lock, flags);
> -       size = kcov->size * sizeof(unsigned long);
> -       if (kcov->area == NULL || vma->vm_pgoff != 0 ||
> +       size = kcov->state.size * sizeof(unsigned long);
> +       if (kcov->state.area == NULL || vma->vm_pgoff != 0 ||
>             vma->vm_end - vma->vm_start != size) {
>                 res = -EINVAL;
>                 goto exit;
> @@ -502,7 +492,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>         spin_unlock_irqrestore(&kcov->lock, flags);
>         vm_flags_set(vma, VM_DONTEXPAND);
>         for (off = 0; off < size; off += PAGE_SIZE) {
> -               page = vmalloc_to_page(kcov->area + off);
> +               page = vmalloc_to_page(kcov->state.area + off);
>                 res = vm_insert_page(vma, vma->vm_start + off, page);
>                 if (res) {
>                         pr_warn_once("kcov: vm_insert_page() failed\n");
> @@ -523,7 +513,7 @@ static int kcov_open(struct inode *inode, struct file *filep)
>         if (!kcov)
>                 return -ENOMEM;
>         kcov->mode = KCOV_MODE_DISABLED;
> -       kcov->sequence = 1;
> +       kcov->state.sequence = 1;
>         refcount_set(&kcov->refcount, 1);
>         spin_lock_init(&kcov->lock);
>         filep->private_data = kcov;
> @@ -558,10 +548,10 @@ static int kcov_get_mode(unsigned long arg)
>  static void kcov_fault_in_area(struct kcov *kcov)
>  {
>         unsigned long stride = PAGE_SIZE / sizeof(unsigned long);
> -       unsigned long *area = kcov->area;
> +       unsigned long *area = kcov->state.area;
>         unsigned long offset;
>
> -       for (offset = 0; offset < kcov->size; offset += stride)
> +       for (offset = 0; offset < kcov->state.size; offset += stride)
>                 READ_ONCE(area[offset]);
>  }
>
> @@ -600,7 +590,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                  * at task exit or voluntary by KCOV_DISABLE. After that it can
>                  * be enabled for another task.
>                  */
> -               if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
> +               if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
>                         return -EINVAL;
>                 t = current;
>                 if (kcov->t != NULL || t->kcov != NULL)
> @@ -610,8 +600,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                         return mode;
>                 kcov_fault_in_area(kcov);
>                 kcov->mode = mode;
> -               kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
> -                               kcov->sequence);
> +               kcov_start(t, kcov, mode, &kcov->state);
>                 kcov->t = t;
>                 /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
>                 kcov_get(kcov);
> @@ -628,7 +617,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 kcov_put(kcov);
>                 return 0;
>         case KCOV_REMOTE_ENABLE:
> -               if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
> +               if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
>                         return -EINVAL;
>                 t = current;
>                 if (kcov->t != NULL || t->kcov != NULL)
> @@ -722,8 +711,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>                         vfree(area);
>                         return -EBUSY;
>                 }
> -               kcov->area = area;
> -               kcov->size = size;
> +               kcov->state.area = area;
> +               kcov->state.size = size;
>                 kcov->mode = KCOV_MODE_INIT;
>                 spin_unlock_irqrestore(&kcov->lock, flags);
>                 return 0;
> @@ -821,10 +810,8 @@ static void kcov_remote_softirq_start(struct task_struct *t)
>         mode = READ_ONCE(t->kcov_mode);
>         barrier();
>         if (kcov_mode_enabled(mode)) {
> +               data->saved_state = t->kcov_state;
>                 data->saved_mode = mode;
> -               data->saved_size = t->kcov_size;
> -               data->saved_area = t->kcov_area;
> -               data->saved_sequence = t->kcov_sequence;
>                 data->saved_kcov = t->kcov;
>                 kcov_stop(t);
>         }
> @@ -835,13 +822,9 @@ static void kcov_remote_softirq_stop(struct task_struct *t)
>         struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
>
>         if (data->saved_kcov) {
> -               kcov_start(t, data->saved_kcov, data->saved_size,
> -                               data->saved_area, data->saved_mode,
> -                               data->saved_sequence);
> -               data->saved_mode = 0;
> -               data->saved_size = 0;
> -               data->saved_area = NULL;
> -               data->saved_sequence = 0;
> +               kcov_start(t, data->saved_kcov, data->saved_mode,
> +                          &data->saved_state);
> +               data->saved_state = (struct kcov_state){};
>                 data->saved_kcov = NULL;
>         }
>  }
> @@ -850,12 +833,12 @@ void kcov_remote_start(u64 handle)
>  {
>         struct task_struct *t = current;
>         struct kcov_remote *remote;
> +       struct kcov_state state;
> +       enum kcov_mode mode;
> +       unsigned long flags;
> +       unsigned int size;
>         struct kcov *kcov;
> -       unsigned int mode;
>         void *area;
> -       unsigned int size;
> -       int sequence;
> -       unsigned long flags;
>
>         if (WARN_ON(!kcov_check_handle(handle, true, true, true)))
>                 return;
> @@ -900,7 +883,7 @@ void kcov_remote_start(u64 handle)
>          * KCOV_DISABLE / kcov_remote_reset().
>          */
>         mode = kcov->mode;
> -       sequence = kcov->sequence;
> +       state.sequence = kcov->state.sequence;
>         if (in_task()) {
>                 size = kcov->remote_size;
>                 area = kcov_remote_area_get(size);
> @@ -923,12 +906,14 @@ void kcov_remote_start(u64 handle)
>
>         /* Reset coverage size. */
>         *(u64 *)area = 0;
> +       state.area = area;
> +       state.size = size;
>
>         if (in_serving_softirq()) {
>                 kcov_remote_softirq_start(t);
>                 t->kcov_softirq = 1;
>         }
> -       kcov_start(t, kcov, size, area, mode, sequence);
> +       kcov_start(t, kcov, mode, &state);
>
>         local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>
> @@ -1027,9 +1012,9 @@ void kcov_remote_stop(void)
>         }
>
>         kcov = t->kcov;
> -       area = t->kcov_area;
> -       size = t->kcov_size;
> -       sequence = t->kcov_sequence;
> +       area = t->kcov_state.area;
> +       size = t->kcov_state.size;
> +       sequence = t->kcov_state.sequence;
>
>         kcov_stop(t);
>         if (in_serving_softirq()) {
> @@ -1042,8 +1027,9 @@ void kcov_remote_stop(void)
>          * KCOV_DISABLE could have been called between kcov_remote_start()
>          * and kcov_remote_stop(), hence the sequence check.
>          */
> -       if (sequence == kcov->sequence && kcov->remote)
> -               kcov_move_area(kcov->mode, kcov->area, kcov->size, area);
> +       if (sequence == kcov->state.sequence && kcov->remote)
> +               kcov_move_area(kcov->mode, kcov->state.area, kcov->state.size,
> +                              area);
>         spin_unlock(&kcov->lock);
>
>         if (in_task()) {
> --
> 2.50.1.470.g6ba607880d-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbAp2YLh8hXwnDiVuq9HqoKEU9wFJSDZe5-kWYnnKk%3DqA%40mail.gmail.com.
