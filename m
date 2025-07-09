Return-Path: <kasan-dev+bncBCMIZB7QWENRBAMEXLBQMGQEXLUVCIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id BE5D4AFEC94
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jul 2025 16:51:46 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-6077af4c313sf24867a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 07:51:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752072706; cv=pass;
        d=google.com; s=arc-20240605;
        b=FpOUZ3/7hem7f1uUsFX96VfmKNt8nTJESk7JqarGVe7WqMGNKVCUhArkqOwSzRsCs5
         le3ITjKdgX7KrkMHZO3luMmmH014LSKrgIaTD6ODXGIlRq66aPxFjQ6d7JWqZ4jXJI2D
         kp9ujW0pzLO1xj0sxPmuF1EhhZLgn1mYmUlqYPv6X6l7t940jq7mWQe9KJD6ngD2yFu5
         hG5q5ywhGbaUhKgM8SBXLxh1wZwZ/V+iQSNRng/e8ZzU+mxdgllyNsZj42QugNz6G4yw
         P2OPrle4krcISWMzLm+XY57N8QH7WHl2Nrbahwpt9BYtjk2W/peIZGTDodMMS+xVE74w
         G+Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jvfArKNQXEFQcUU+3xLXJgqkAUskjgV/IRBgeU6KJG0=;
        fh=ckcz+89rzvMEn7e10K7Z+7It1gupW99Rb6BqTcvR6lk=;
        b=VRtG9F8wnbgXYITxFXg7lERW4yM7XpLpYDEJ5Fa4W0HoHzrPaIpRt7+RdiNVrWLyeS
         Jku8fs2d1d98x8PrP9bPeq9yOvDTpHzCIG7T8NyF0sgjyDZMIzaXecakV5pd4yna2G0a
         9Wew1Lqz6N5N9YU4KIhoYkuonTAjLg5B7QnqfCoK6yrTRDDS4kimbu2GCFlpGrAJzA9n
         3aC2cjKTaozm/5pV7NBikHd3YHy6/cn3VvoTbP/IPOMqnmw+re5f4Utfy+9F2nSGHWub
         T91QijNu2z8lqcSrX3OLT2eDAQiCRYvuhXpIxJAjfZLhAUHI01VPnT180+THxpYzuAdM
         bjWg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="KJJ6/2JX";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752072706; x=1752677506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jvfArKNQXEFQcUU+3xLXJgqkAUskjgV/IRBgeU6KJG0=;
        b=tWij5dacFyiBYuAtJWKCH4xnpxzBAOjeGRzaVwc7CSmZySv3oEJNCvBAXgCwagOk4C
         B54uR9bbAQuKJBm7s90RJBv5Fe4FwyW3JgWOPNu0usD1O9uekiTW4T+b1XM358ZLbGLt
         jYTmutZi0OMEZFpYMOkLUHheBbCRdUL9eXvNoSge2i8UmD8aD1kHAlsP0uE93OAy1y78
         M+T+qMsnvap82WhWj60BG5V41NtCJfRTDPDqYUBFUENF9Vg+ly1xs+ylLJLKnewluwSC
         dYCjj6/yL6yUa91aqMkRFJXE9+nYIENb6hAloL1JRd/vJTByOG8VDlE9iBiwbZGnPnUf
         N4ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752072706; x=1752677506;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jvfArKNQXEFQcUU+3xLXJgqkAUskjgV/IRBgeU6KJG0=;
        b=Ny9cgDwJTmWNPrztj0WpTOEctkmt3+DzBCKkIq0pyGSvxqCuA/slPa9VUroWdBO2ZP
         ZYADST35SXjeRg/Vhdyx5+JkkVC2BmNt1UyMJ9/t4g6g0pj7MuA+WpEB7/i0OD6UTMlT
         4DNxDbIocPlu/7wI4XQZhHVpT2xEusC1dnTq+Jl+LHnBtx0/bKKD5oPM/g8z4ahAQw4L
         bKEphaTCfwv82tSK6JvxVWkXQI32WPgch+IyZ6QNKUHawwbd20AIGYhG4OkUlfm8JT4l
         RoFCaDXAdvZZ4GHYy5hDxvnCDsPGwaB17VvMl6qxfTkd1eCMicnwkB88j/X2C6k+dZKb
         gNLA==
X-Forwarded-Encrypted: i=2; AJvYcCXPw1RMfgw5igwq1Fo15Re3oS51Ob8tlrGXNs5/kzQeHqkNE30I3NZ5NcNPMRV/HeuA5w2SKA==@lfdr.de
X-Gm-Message-State: AOJu0YyzGXj/Rbnf3DWBbosdpkJm9SGnTfdZhiDT1FGmt0jXaoscEp6n
	6yc46NtcHai5tI5deDwsg82PEfXAKnoZ8Jr54ae15XIXjhzG+nJBSRmX
X-Google-Smtp-Source: AGHT+IGpG1h9bAapZOli+/qrkodeyJUF+6ejeIEvLvg6Q9KYXbzI4xU9/xgYmXBobRXWdriAYdS1cg==
X-Received: by 2002:a05:6402:5d1:b0:60c:5853:5b54 with SMTP id 4fb4d7f45d1cf-6104bf84b43mr7404076a12.14.1752072705852;
        Wed, 09 Jul 2025 07:51:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcvAJhv+v+djLH4+JI0EVvetclZA3K1AN0+uWUalI7yBQ==
Received: by 2002:a05:6402:3506:b0:60c:3a73:a638 with SMTP id
 4fb4d7f45d1cf-60fdb4fb324ls4142252a12.0.-pod-prod-00-eu; Wed, 09 Jul 2025
 07:51:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuy9/7+ra6qyDHyVYh5/PTKNcrBlHnB8Vs8BPaV4KJUZFHGff2kbBIF3eBjiueXAfxCP4i9cvkNT0=@googlegroups.com
X-Received: by 2002:a05:6402:50d2:b0:604:64ba:6a9a with SMTP id 4fb4d7f45d1cf-6104bf791b9mr6633499a12.9.1752072702871;
        Wed, 09 Jul 2025 07:51:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752072702; cv=none;
        d=google.com; s=arc-20240605;
        b=Gxcxcd1bb29KpjzVGIZ6+/cAXV4GmfYUllE195GwR2uoQeka2+F/zCZCyCEqzsy4/3
         peNrWyPR8+FjYvjXanagQLXnoWZPWixWzQ2OIKnATEqK0PSeJvvzQBWNrNZ4aIy+saw8
         0SctP4LAXQMXD99KJDRpnGIpRkWMSIgqvskH1MU4rTBiykBbnMCJ4p+3d9MKkCGYjp/N
         2D5xc5CwdK3s5RPaSbwjt9j3598QDbtVPXl5vgwYBrAbUSvIx87lmzgZsfed9+OavFOV
         BYHVmB/dl1vIp014MpTcht2Ui1ZL4/6nMiYt5GQD7p/noEGhnxTxxZoNCv+8rTSEvXj1
         O94A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ue1/xT5pDROcZS9h0MgFGuLvd+Wg3Ps4S8/5lspnVMk=;
        fh=gLNdylc3+DpOjew+zlPQdLshXUk9iB+ir6JJwBSHac8=;
        b=YjRUaKD3L9NYl6jxudqJ/4HIXGXEOBYyNPWBe2x4uOlG1TmUgxUDJDXvutaQz4ib1h
         9zHi5ECtsfH9dpG4Kn0qbdUAskQy/usPumLbtMmmh/q2cGDYMyI4K51eEMZ0+od84eHQ
         6k+xNp1NkNP2LCTCsOcpf94hUE5sEv1PVO/+RMsLAfyYPVs2nvUrmMbYXnxZs4X2stHg
         Kdm8DgqHvoFe/gvxKt9SqbbeIh1Wlfg2NoqQowUAFiGCD1wlLatsw71QjKPN67I8IInt
         aL2EFEpxrl8ceLLARcHYFMy6GPhcy1xHwzeQFZiFc7WIUOj6lQrYrwSluGto1bm/rmk2
         60xQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="KJJ6/2JX";
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-60fca655a62si396169a12.1.2025.07.09.07.51.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Jul 2025 07:51:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id 2adb3069b0e04-553d2eb03a0so1230549e87.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Jul 2025 07:51:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKmi0b0W6+6Ccgt6XL4mBoUbhTwrdSeCj4MOxdQ/FFd+EIQyb1S4c5PTl/5JTN/wKXOW4YhYeVZ7c=@googlegroups.com
X-Gm-Gg: ASbGncunosUePTMnkSEqvnQq9CZf38fGMXlOYcuLiL6vkGHJ0P/+TmVW9Pr4cJL8/Mo
	Em9XUF9Ekc4Buna/tvIvoDo3WheTkInPgEdzx8gl5WP1ttHa0MeR8VYKAMU3+XRt0R7TwIEqMUQ
	OVJqDUuY8m1V4AEPlUAIZ9bseBVFvPtzfD1dR2c0OyYv75FIzt5ytDQSKu3quEtHnCh2lwOB6Xi
	WXp
X-Received: by 2002:a05:6512:b17:b0:553:2154:7bcc with SMTP id
 2adb3069b0e04-557f8a38c96mr2519409e87.20.1752072701711; Wed, 09 Jul 2025
 07:51:41 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-5-glider@google.com>
In-Reply-To: <20250626134158.3385080-5-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Jul 2025 16:51:30 +0200
X-Gm-Features: Ac12FXxWQeUH5t8Fsxxq3ANWwclp9-zzaoVRHYdhnBoLFAp-5XNZYll4a-gJtcM
Message-ID: <CACT4Y+aqcDyxkBE5JaFFNGP_UjBfwwx-Wj3EONnHdhadTGYdDw@mail.gmail.com>
Subject: Re: [PATCH v2 04/11] kcov: factor out struct kcov_state
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
 header.i=@google.com header.s=20230601 header.b="KJJ6/2JX";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12a
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

On Thu, 26 Jun 2025 at 15:42, Alexander Potapenko <glider@google.com> wrote:
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
> Also update the MAINTAINERS entry: add include/linux/kcov_types..h,
> add myself as kcov reviewer.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> Change-Id: If225682ea2f6e91245381b3270de16e7ea40df39
>
> v2:
>  - add myself to kcov MAINTAINERS
>  - rename kcov-state.h to kcov_types.h
>  - update the description
>  - do not move mode into struct kcov_state
>  - use '{ }' instead of '{ 0 }'
> ---
>  MAINTAINERS                |   2 +
>  include/linux/kcov.h       |   2 +-
>  include/linux/kcov_types.h |  22 +++++++
>  include/linux/sched.h      |  13 +----
>  kernel/kcov.c              | 115 ++++++++++++++++---------------------
>  5 files changed, 78 insertions(+), 76 deletions(-)
>  create mode 100644 include/linux/kcov_types.h
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index dd844ac8d9107..5bbc78b0fa6ed 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -12823,11 +12823,13 @@ F:    include/linux/kcore.h
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
> index 932b4face1005..0e425c3524b86 100644
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
> index f96ac19828934..68af8d6eaee3a 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -42,6 +42,7 @@
>  #include <linux/restart_block.h>
>  #include <uapi/linux/rseq.h>
>  #include <linux/seqlock_types.h>
> +#include <linux/kcov_types.h>
>  #include <linux/kcsan.h>
>  #include <linux/rv.h>
>  #include <linux/livepatch_sched.h>
> @@ -1512,16 +1513,11 @@ struct task_struct {
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
> +       /* kcov buffer state for this task. */

For consistency: s/kcov/KCOV/

> +       struct kcov_state               kcov_state;
>
>         /* KCOV descriptor wired with this task or NULL: */
>         struct kcov                     *kcov;
> @@ -1529,9 +1525,6 @@ struct task_struct {
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
> index 0dd42b78694c9..ff7f118644f49 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -13,6 +13,7 @@
>  #include <linux/init.h>
>  #include <linux/jiffies.h>
>  #include <linux/kcov.h>
> +#include <linux/kcov_types.h>
>  #include <linux/kmsan-checks.h>
>  #include <linux/log2.h>
>  #include <linux/mm.h>
> @@ -54,24 +55,17 @@ struct kcov {
>          *  - each code section for remote coverage collection
>          */
>         refcount_t refcount;
> -       /* The lock protects mode, size, area and t. */
> +       /* The lock protects state and t. */
>         spinlock_t lock;
>         enum kcov_mode mode;
> -       /* Size of arena (in long's). */
> -       unsigned int size;
> -       /* Coverage buffer shared with user space. */
> -       void *area;
> +       struct kcov_state state;
> +
>         /* Task for which we collect coverage, or NULL. */
>         struct task_struct *t;
>         /* Collecting coverage from remote (background) threads. */
>         bool remote;
>         /* Size of remote area (in long's). */
>         unsigned int remote_size;
> -       /*
> -        * Sequence is incremented each time kcov is reenabled, used by
> -        * kcov_remote_stop(), see the comment there.
> -        */
> -       int sequence;
>  };
>
>  struct kcov_remote_area {
> @@ -92,12 +86,9 @@ static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
>  struct kcov_percpu_data {
>         void *irq_area;
>         local_lock_t lock;
> -
> -       unsigned int saved_mode;
> -       unsigned int saved_size;
> -       void *saved_area;
> +       enum kcov_mode saved_mode;
>         struct kcov *saved_kcov;
> -       int saved_sequence;
> +       struct kcov_state saved_state;
>  };
>
>  static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
> @@ -219,10 +210,10 @@ void notrace __sanitizer_cov_trace_pc(void)
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
> @@ -252,10 +243,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
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
> @@ -356,17 +347,15 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
>  #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
>
>  static void kcov_start(struct task_struct *t, struct kcov *kcov,
> -                      unsigned int size, void *area, enum kcov_mode mode,
> -                      int sequence)
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
> -       /* See comment in check_kcov_mode(). */
> +       t->kcov_state = *state;
>         barrier();
> +       /* See comment in check_kcov_mode(). */
>         WRITE_ONCE(t->kcov_mode, mode);
>  }
>
> @@ -375,14 +364,14 @@ static void kcov_stop(struct task_struct *t)
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
> @@ -398,7 +387,7 @@ static void kcov_reset(struct kcov *kcov)
>         kcov->mode = KCOV_MODE_INIT;
>         kcov->remote = false;
>         kcov->remote_size = 0;
> -       kcov->sequence++;
> +       kcov->state.sequence++;
>  }
>
>  static void kcov_remote_reset(struct kcov *kcov)
> @@ -438,7 +427,7 @@ static void kcov_put(struct kcov *kcov)
>  {
>         if (refcount_dec_and_test(&kcov->refcount)) {
>                 kcov_remote_reset(kcov);
> -               vfree(kcov->area);
> +               vfree(kcov->state.area);
>                 kfree(kcov);
>         }
>  }
> @@ -495,8 +484,8 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
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
> @@ -504,7 +493,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>         spin_unlock_irqrestore(&kcov->lock, flags);
>         vm_flags_set(vma, VM_DONTEXPAND);
>         for (off = 0; off < size; off += PAGE_SIZE) {
> -               page = vmalloc_to_page(kcov->area + off);
> +               page = vmalloc_to_page(kcov->state.area + off);
>                 res = vm_insert_page(vma, vma->vm_start + off, page);
>                 if (res) {
>                         pr_warn_once("kcov: vm_insert_page() failed\n");
> @@ -525,7 +514,7 @@ static int kcov_open(struct inode *inode, struct file *filep)
>         if (!kcov)
>                 return -ENOMEM;
>         kcov->mode = KCOV_MODE_DISABLED;
> -       kcov->sequence = 1;
> +       kcov->state.sequence = 1;
>         refcount_set(&kcov->refcount, 1);
>         spin_lock_init(&kcov->lock);
>         filep->private_data = kcov;
> @@ -560,10 +549,10 @@ static int kcov_get_mode(unsigned long arg)
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
> @@ -602,7 +591,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                  * at task exit or voluntary by KCOV_DISABLE. After that it can
>                  * be enabled for another task.
>                  */
> -               if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
> +               if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
>                         return -EINVAL;
>                 t = current;
>                 if (kcov->t != NULL || t->kcov != NULL)
> @@ -612,8 +601,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                         return mode;
>                 kcov_fault_in_area(kcov);
>                 kcov->mode = mode;
> -               kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
> -                          kcov->sequence);
> +               kcov_start(t, kcov, mode, &kcov->state);
>                 kcov->t = t;
>                 /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
>                 kcov_get(kcov);
> @@ -630,7 +618,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 kcov_put(kcov);
>                 return 0;
>         case KCOV_REMOTE_ENABLE:
> -               if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
> +               if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
>                         return -EINVAL;
>                 t = current;
>                 if (kcov->t != NULL || t->kcov != NULL)
> @@ -725,8 +713,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
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
> @@ -825,10 +813,8 @@ static void kcov_remote_softirq_start(struct task_struct *t)
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
> @@ -839,13 +825,9 @@ static void kcov_remote_softirq_stop(struct task_struct *t)
>         struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
>
>         if (data->saved_kcov) {
> -               kcov_start(t, data->saved_kcov, data->saved_size,
> -                          data->saved_area, data->saved_mode,
> -                          data->saved_sequence);
> -               data->saved_mode = 0;
> -               data->saved_size = 0;
> -               data->saved_area = NULL;
> -               data->saved_sequence = 0;
> +               kcov_start(t, data->saved_kcov, t->kcov_mode,

We used to pass data->saved_mode, now we pass t->kcov_mode.
Are they the same here? This makes me a bit nervous.

> +                          &data->saved_state);
> +               data->saved_state = (struct kcov_state){};
>                 data->saved_kcov = NULL;
>         }
>  }
> @@ -854,12 +836,12 @@ void kcov_remote_start(u64 handle)
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
> @@ -904,7 +886,7 @@ void kcov_remote_start(u64 handle)
>          * KCOV_DISABLE / kcov_remote_reset().
>          */
>         mode = kcov->mode;
> -       sequence = kcov->sequence;
> +       state.sequence = kcov->state.sequence;
>         if (in_task()) {
>                 size = kcov->remote_size;
>                 area = kcov_remote_area_get(size);
> @@ -927,12 +909,14 @@ void kcov_remote_start(u64 handle)
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
> +       kcov_start(t, kcov, t->kcov_mode, &state);

We used to pass kcov->mode here, now it's t->kcov_mode.
Are they the same here? I would prefer to restore the current version,
if there is no specific reason to change it.

>
>         local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>  }
> @@ -1030,9 +1014,9 @@ void kcov_remote_stop(void)
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
> @@ -1045,8 +1029,9 @@ void kcov_remote_stop(void)
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
> 2.50.0.727.gbf7dc18ff4-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaqcDyxkBE5JaFFNGP_UjBfwwx-Wj3EONnHdhadTGYdDw%40mail.gmail.com.
