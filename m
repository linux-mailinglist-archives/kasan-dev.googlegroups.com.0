Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIW7QTAAMGQEMQMAPFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id AB8CBA922ED
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 18:43:16 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-736b2a25d9fsf760911b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 09:43:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744908195; cv=pass;
        d=google.com; s=arc-20240605;
        b=EL26T+cdcVLuCu2BUhMSEBQclsHViHwTGCkF+v0Gax9yUbxpHsbSRngUj9bbjUvXVU
         XCgRjRZLWeX1OLRbJnBmomyYCwSnixJlSOb8IlhO88hHzVJmgxoDTrOFgaMzliEU9Lu/
         BpV7fFPLQ743cNsk1uEEjxR6fOfS51sKe728e7/+K8kYfr1eyYQKmzg1n9CbWJmpaeYv
         XM+yECwI6ocrm43T+8x+A2xawkuWDIVIf805fe72SD8FNHA33fle/zLmg+M2ie7bE13H
         YLKkEx5PgNdoZnNdMg4tqyVuTlEYy0abQXAZ4I8SG3hoi1NwZQALA9l/jlJxZp+A6YHx
         mifQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rGTvEFcXsHGzYKpV+pZ2d/Pz7Vsr5ioKC6CY4NvgYPo=;
        fh=LbizfQHQ76nYMT9aKvXlf/mNH8LVYykngxsENYjj1/A=;
        b=KsLN/f4ZznFp6vJ1dJQ4k4hrdQpcOguMFWdQJ04aiadtmRg84IydzLgI6/dB2p10se
         Z9j7nFjrPpzgGuVZXQDG7kBxAuC2eq/wVs1snzIOIOgZvRb2/8zMdmVuclcCkNLZRr65
         6+eRSzC36swD8fsOVl6+uCSl7Hm+zf/Kn7HfLrnyEFSg3kVKb0yMkybbq8kaMuH9R2qO
         pG81mwU4HMu2u8OLCc2rglFmRC5LR7PxxqTazQzaGPGkxSyWkZBFOuVJIC0oh7U3Wmcc
         9RFzL7cKqD+rvwQYuzKtsLEM4xvzMFARyXGLbw3wKyVWuJxcDzoUAcZ3Buc5CWxB087+
         4ciQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rYHK88wG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744908195; x=1745512995; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rGTvEFcXsHGzYKpV+pZ2d/Pz7Vsr5ioKC6CY4NvgYPo=;
        b=R3EDSqiZmYQlFBKTetnwI4h+AhzFjTzO6WDS8ZnspFKfe+HuwI0H05cRt5wrow99NE
         xW9YhjkP9PqxCQKq8Z4NEnjx5nXpGk3u616fhfm6BnZXAtpxmn7S70na34elHP2J9FLG
         l7mdLFYQQUMdjN+CRhiqadHwBh6+2KGJDD/N/gRGYy5BbIU9fByfxLrSmzSzKoqU9Ywh
         KxIOhgzV0dkPRpHtr00CjbYD/+2ufCGDWBpnsQAj87ERTGNYf7gOZ99CLp55ebV606Pu
         BHPt8+T4vJruYC5JTpQTcuJlap48prO0CfeOgHMEB6HBaiV5l6Sk09oNKQjUNNrnZN4F
         fb+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744908195; x=1745512995;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rGTvEFcXsHGzYKpV+pZ2d/Pz7Vsr5ioKC6CY4NvgYPo=;
        b=fg3zFlo2WFKhbSTsIMBu2/T/CiTsFcQGUO5RtkG5XOpiJM+5E9QvkyWLTHhrZlai9S
         WbMYXfMx1BvAigegSv47KIcdsr85XsWJG+gTTLFgG2g6+ihzqpu2lLxfNOzMt+fp94ql
         XCs2U4DymYys8uyKEITIRzgKFqMdecNKqclrUSwLXEGLi7cdA7ShrXMerUMUbYptgW6m
         MKm43lpuywzDXgINtEnWsZ1NEaqkLBl74uJwkNd89GjjuZv976PN0Xdm/eLqeN7ivs65
         BJksfhX7eu2J4EuCYrCXMhg0KGPVDSCbiAbsT2Yq2XXplYGHj+kgoTgtAmRlDSk/AkYW
         TPoA==
X-Forwarded-Encrypted: i=2; AJvYcCUkW7H0jTmu5U/YQhojgFdor50IVMS1yxCANF6teO4hdJifKp9MndvjBrwBeKRVbopaCJxx4Q==@lfdr.de
X-Gm-Message-State: AOJu0Yw6V5rgLHqNMBaudoVbomPk6bBRAwZ+SaKoxZf4G3FqWh8EFglR
	IpVl959HdFXGRvJjkLfxXxCNIEkDZRAwJSZQTGXLreVrzsxfnva7
X-Google-Smtp-Source: AGHT+IFIHJid+/SvxBu4StgoEjmiaBtiBWJAWqNQ6dFvdnnCpYfzKlCcNoprWq+UD0KMLAVtdZP5eQ==
X-Received: by 2002:a05:6a00:a89:b0:736:53c5:33ba with SMTP id d2e1a72fcca58-73c267e5e05mr7766158b3a.16.1744908194907;
        Thu, 17 Apr 2025 09:43:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAImMcUWtPnzSl1K15ekXZdbGhfhZ73ZD8qdzkEVeYp/Ow==
Received: by 2002:a05:6a00:2e1b:b0:728:f8a6:8599 with SMTP id
 d2e1a72fcca58-73c327c4556ls1082990b3a.0.-pod-prod-09-us; Thu, 17 Apr 2025
 09:43:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVEfgzZvFScnjljDzuyoK5Ooj250q48ofWwxt8A2vQlEfPx6rQ0mq+2kAx+xB8KPfj/iV3gz4Q6eEc=@googlegroups.com
X-Received: by 2002:a17:90b:2c86:b0:2ee:f550:3848 with SMTP id 98e67ed59e1d1-30863d1d966mr10192619a91.5.1744908193346;
        Thu, 17 Apr 2025 09:43:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744908193; cv=none;
        d=google.com; s=arc-20240605;
        b=ldwpLfBJo8c7Bqb2YZ1+tkugmnHzYM2IfHbWuiew6n8Y/xzapTb/iYUGyl6GqWew0f
         KwGQTVwYMfgilAxVYz096BG75wrWUomUntGUrH/tSUWcCGSGjrxjK0rXz8vZzEEgFm36
         azmkfsnUZP9eCr4Bb/9AClOtlKoB/KtnsEUMpDXeVCO9qLqju2axqNCMuzxRhfe02bTw
         cRjpTqnJ2+Si1QDUhAKHpTg3cfc4i+wDz7vmMWiZjhy302GsEUZ16u9tKeupSskpGwqI
         rvQN0utxC95HLVKkpVfquNeNNHxdzKUr5MjAjNMQ1I3j1SvAWYlOs4jFTiHqUVH1m+iy
         VFug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pbom+8ANhnMZ5gDkO1zh4zRzQoDxtP4idpcMELMXUZA=;
        fh=t0SN341uwVoC0OC4pqkmu7fOr0+EnEWNZ8BdPHXcdjk=;
        b=PSnGdB/iREFnOFQN0cRp1728EtmhVm7rP0MTd2sWra0zT7f4PLRujEWV8KLvMNNM29
         7OD/o0QlxhmlPpTs5jYUrXOhAuT65u0YCT++JkwgcpmF+FqltXlVlPhUNDKQ97VAMd/Q
         mZUgzL78ZZWxSm+2DxxzeRgkpzfY78H/2CM79dF9xom4XLurH+I2z3JeAea9ltNiEyQE
         nrLC90rUzIbYDBnTxgCKrpDL6C4noHoCBLB6PweW2keUL9Aqxhep+sO2DKp8kFaWSc9Z
         zay3mHh51ue8CO39miwZ3Oti9YX658EsRrS3IJJD3fluJiFek8L5uStK/QUzPJ3TzbXY
         osoA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rYHK88wG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-308611c3808si169534a91.1.2025.04.17.09.43.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Apr 2025 09:43:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 41be03b00d2f7-af59c920d32so732059a12.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Apr 2025 09:43:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXpfOl1Ox6zzFFQqhgc4YjXBs5Pc8Hum/wZ6Xo+EGP2rt0oDLDluqPSH1ZvzOvrfMMTpmiJfrkhV34=@googlegroups.com
X-Gm-Gg: ASbGncu885ieUZ+e9bskdVi9J2WtCRQSNOnTAbsz2LsOTrKZ+BCVU1BA283zPyEyCnI
	OoZ/Ch+DEVXhx/n+E3KRYbq6iFNCto+uNDF2h/ZofcAMi2Ncvo8pKALb5H0/RfOrq3kcUTYxp8y
	KFVu3uvYrhEByNi8Bt/1hc67RcS60+PLqR9GgpbsTWsKbV8BTNoj22LxOIgwU+G6xk
X-Received: by 2002:a17:90b:5690:b0:2fe:e0a9:49d4 with SMTP id
 98e67ed59e1d1-30863d1fdf8mr9888691a91.2.1744908192602; Thu, 17 Apr 2025
 09:43:12 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-3-glider@google.com>
In-Reply-To: <20250416085446.480069-3-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Apr 2025 18:42:36 +0200
X-Gm-Features: ATxdqUHzj5n_H17ifrYT0vGHqYz-ppt1LiMGG9s8wUvapIfp7C_kKJAIwN8rb7E
Message-ID: <CANpmjNNCf+ep-1-jZV9GURy7UkVX5CJF7sE_sGXV8KWoL6QPtQ@mail.gmail.com>
Subject: Re: [PATCH 2/7] kcov: factor out struct kcov_state
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
 header.i=@google.com header.s=20230601 header.b=rYHK88wG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::532 as
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
> Group several kcov-related fields (area, size, mode, sequence) that
> are stored in various structures, into `struct kcov_state`, so that
> these fields can be easily passed around and manipulated.
>
> This prepares us for the upcoming change that will introduce more
> kcov state.
>
> Also update the MAINTAINERS entry.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  MAINTAINERS                |   1 +
>  include/linux/kcov-state.h |  31 ++++++++

Looking at <linux/sched.h>, a lot of the headers introduced to factor
out types are called "foo_types.h", so this probably should be
"kcov_types.h".

>  include/linux/kcov.h       |  14 ++--
>  include/linux/sched.h      |  16 +---
>  kernel/kcov.c              | 149 ++++++++++++++++---------------------
>  5 files changed, 106 insertions(+), 105 deletions(-)
>  create mode 100644 include/linux/kcov-state.h
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 00e94bec401e1..2f9bea40d9760 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -12511,6 +12511,7 @@ L:      kasan-dev@googlegroups.com
>  S:     Maintained
>  B:     https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
>  F:     Documentation/dev-tools/kcov.rst
> +F:     include/linux/kcov-state.h
>  F:     include/linux/kcov.h
>  F:     include/uapi/linux/kcov.h
>  F:     kernel/kcov.c
> diff --git a/include/linux/kcov-state.h b/include/linux/kcov-state.h
> new file mode 100644
> index 0000000000000..4c4688d01c616
> --- /dev/null
> +++ b/include/linux/kcov-state.h
> @@ -0,0 +1,31 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef _LINUX_KCOV_STATE_H
> +#define _LINUX_KCOV_STATE_H
> +
> +#ifdef CONFIG_KCOV
> +struct kcov_state {
> +       /* See kernel/kcov.c for more details. */
> +       /*
> +        * Coverage collection mode enabled for this task (0 if disabled).
> +        * This field is used for synchronization, so it is kept outside of
> +        * the below struct.
> +        */
> +       unsigned int mode;
> +

It'd be nice to have a comment why the below is in an anon struct "s"
- AFAIK it's to be able to copy it around easily.

However, thinking about it more, why does "mode" have to be in
"kcov_state"? Does it logically make sense?
We also have this inconsistency where before we had the instance in
"struct kcov" be "enum kcov_mode", and the one in task_struct be
"unsigned int". Now they're both unsigned int - which I'm not sure is
better.

Could we instead do this:
- keep "mode" outside the struct (a bit more duplication, but I think
it's clearer)
- move enum kcov_mode to kcov_types.h
- define all instances of "mode" consistently as "enum kcov_mode"
- make kcov_state just contain what is now in "kcov_state::s", and
effectively get rid of the nested "s"

> +       struct {
> +               /* Size of the area (in long's). */
> +               unsigned int size;
> +
> +               /* Buffer for coverage collection, shared with the userspace. */
> +               void *area;
> +
> +               /*
> +                * KCOV sequence number: incremented each time kcov is
> +                * reenabled, used by kcov_remote_stop(), see the comment there.
> +                */
> +               int sequence;
> +       } s;
> +};
> +#endif /* CONFIG_KCOV */
> +
> +#endif /* _LINUX_KCOV_STATE_H */
> diff --git a/include/linux/kcov.h b/include/linux/kcov.h
> index 932b4face1005..e1f7d793c1cb3 100644
> --- a/include/linux/kcov.h
> +++ b/include/linux/kcov.h
> @@ -2,7 +2,7 @@
>  #ifndef _LINUX_KCOV_H
>  #define _LINUX_KCOV_H
>
> -#include <linux/sched.h>
> +#include <linux/kcov-state.h>
>  #include <uapi/linux/kcov.h>
>
>  struct task_struct;
> @@ -30,14 +30,14 @@ enum kcov_mode {
>  void kcov_task_init(struct task_struct *t);
>  void kcov_task_exit(struct task_struct *t);
>
> -#define kcov_prepare_switch(t)                   \
> -       do {                                     \
> -               (t)->kcov_mode |= KCOV_IN_CTXSW; \
> +#define kcov_prepare_switch(t)                         \
> +       do {                                           \
> +               (t)->kcov_state.mode |= KCOV_IN_CTXSW; \
>         } while (0)
>
> -#define kcov_finish_switch(t)                     \
> -       do {                                      \
> -               (t)->kcov_mode &= ~KCOV_IN_CTXSW; \
> +#define kcov_finish_switch(t)                           \
> +       do {                                            \
> +               (t)->kcov_state.mode &= ~KCOV_IN_CTXSW; \
>         } while (0)
>
>  /* See Documentation/dev-tools/kcov.rst for usage details. */
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 9c15365a30c08..70077ad51083c 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -42,6 +42,7 @@
>  #include <linux/restart_block.h>
>  #include <uapi/linux/rseq.h>
>  #include <linux/seqlock_types.h>
> +#include <linux/kcov-state.h>
>  #include <linux/kcsan.h>
>  #include <linux/rv.h>
>  #include <linux/livepatch_sched.h>
> @@ -1485,26 +1486,13 @@ struct task_struct {
>  #endif /* CONFIG_TRACING */
>
>  #ifdef CONFIG_KCOV
> -       /* See kernel/kcov.c for more details. */
> -
> -       /* Coverage collection mode enabled for this task (0 if disabled): */
> -       unsigned int                    kcov_mode;
> -
> -       /* Size of the kcov_area: */
> -       unsigned int                    kcov_size;
> -
> -       /* Buffer for coverage collection: */
> -       void                            *kcov_area;
> -
> +       struct kcov_state               kcov_state;
>         /* KCOV descriptor wired with this task or NULL: */
>         struct kcov                     *kcov;
>
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
> index 7cc6123c2baa4..8fcbca236bec5 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -13,6 +13,7 @@
>  #include <linux/init.h>
>  #include <linux/jiffies.h>
>  #include <linux/kcov.h>
> +#include <linux/kcov-state.h>
>  #include <linux/kmsan-checks.h>
>  #include <linux/log2.h>
>  #include <linux/mm.h>
> @@ -54,24 +55,16 @@ struct kcov {
>          *  - each code section for remote coverage collection
>          */
>         refcount_t refcount;
> -       /* The lock protects mode, size, area and t. */
> +       /* The lock protects state and t. */

Unlike previously, this implies it also protects "s.sequence" now.
(Aside: as-is this will also make annotating it with __guarded_by
rather difficult.)

>         spinlock_t lock;
> -       enum kcov_mode mode;
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
> @@ -92,12 +85,8 @@ static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
>  struct kcov_percpu_data {
>         void *irq_area;
>         local_lock_t lock;
> -
> -       unsigned int saved_mode;
> -       unsigned int saved_size;
> -       void *saved_area;
>         struct kcov *saved_kcov;
> -       int saved_sequence;
> +       struct kcov_state saved_state;
>  };
>
>  static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) = {
> @@ -184,7 +173,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
>          */
>         if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
>                 return false;
> -       mode = READ_ONCE(t->kcov_mode);
> +       mode = READ_ONCE(t->kcov_state.mode);
>         /*
>          * There is some code that runs in interrupts but for which
>          * in_interrupt() returns false (e.g. preempt_schedule_irq()).
> @@ -219,10 +208,10 @@ void notrace __sanitizer_cov_trace_pc(void)
>         if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
>                 return;
>
> -       area = t->kcov_area;
> +       area = t->kcov_state.s.area;
>         /* The first 64-bit word is the number of subsequent PCs. */
>         pos = READ_ONCE(area[0]) + 1;
> -       if (likely(pos < t->kcov_size)) {
> +       if (likely(pos < t->kcov_state.s.size)) {
>                 /* Previously we write pc before updating pos. However, some
>                  * early interrupt code could bypass check_kcov_mode() check
>                  * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
> @@ -252,10 +241,10 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
>
>         /*
>          * We write all comparison arguments and types as u64.
> -        * The buffer was allocated for t->kcov_size unsigned longs.
> +        * The buffer was allocated for t->kcov_state.size unsigned longs.
>          */
> -       area = (u64 *)t->kcov_area;
> -       max_pos = t->kcov_size * sizeof(unsigned long);
> +       area = (u64 *)t->kcov_state.s.area;
> +       max_pos = t->kcov_state.s.size * sizeof(unsigned long);
>
>         count = READ_ONCE(area[0]);
>
> @@ -356,33 +345,31 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_switch);
>  #endif /* ifdef CONFIG_KCOV_ENABLE_COMPARISONS */
>
>  static void kcov_start(struct task_struct *t, struct kcov *kcov,
> -                      unsigned int size, void *area, enum kcov_mode mode,
> -                      int sequence)
> +                      struct kcov_state *state)
>  {
> -       kcov_debug("t = %px, size = %u, area = %px\n", t, size, area);
> +       kcov_debug("t = %px, size = %u, area = %px\n", t, state->s.size,
> +                  state->s.area);
>         t->kcov = kcov;
>         /* Cache in task struct for performance. */
> -       t->kcov_size = size;
> -       t->kcov_area = area;
> -       t->kcov_sequence = sequence;
> -       /* See comment in check_kcov_mode(). */
> +       t->kcov_state.s = state->s;
>         barrier();
> -       WRITE_ONCE(t->kcov_mode, mode);
> +       /* See comment in check_kcov_mode(). */
> +       WRITE_ONCE(t->kcov_state.mode, state->mode);
>  }
>
>  static void kcov_stop(struct task_struct *t)
>  {
> -       WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
> +       WRITE_ONCE(t->kcov_state.mode, KCOV_MODE_DISABLED);
>         barrier();
>         t->kcov = NULL;
> -       t->kcov_size = 0;
> -       t->kcov_area = NULL;
> +       t->kcov_state.s.size = 0;
> +       t->kcov_state.s.area = NULL;
>  }
>
>  static void kcov_task_reset(struct task_struct *t)
>  {
>         kcov_stop(t);
> -       t->kcov_sequence = 0;
> +       t->kcov_state.s.sequence = 0;
>         t->kcov_handle = 0;
>  }
>
> @@ -395,10 +382,10 @@ void kcov_task_init(struct task_struct *t)
>  static void kcov_reset(struct kcov *kcov)
>  {
>         kcov->t = NULL;
> -       kcov->mode = KCOV_MODE_INIT;
> +       kcov->state.mode = KCOV_MODE_INIT;
>         kcov->remote = false;
>         kcov->remote_size = 0;
> -       kcov->sequence++;
> +       kcov->state.s.sequence++;
>  }
>
>  static void kcov_remote_reset(struct kcov *kcov)
> @@ -438,7 +425,7 @@ static void kcov_put(struct kcov *kcov)
>  {
>         if (refcount_dec_and_test(&kcov->refcount)) {
>                 kcov_remote_reset(kcov);
> -               vfree(kcov->area);
> +               vfree(kcov->state.s.area);
>                 kfree(kcov);
>         }
>  }
> @@ -495,8 +482,8 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>         unsigned long flags;
>
>         spin_lock_irqsave(&kcov->lock, flags);
> -       size = kcov->size * sizeof(unsigned long);
> -       if (kcov->area == NULL || vma->vm_pgoff != 0 ||
> +       size = kcov->state.s.size * sizeof(unsigned long);
> +       if (kcov->state.s.area == NULL || vma->vm_pgoff != 0 ||
>             vma->vm_end - vma->vm_start != size) {
>                 res = -EINVAL;
>                 goto exit;
> @@ -504,7 +491,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
>         spin_unlock_irqrestore(&kcov->lock, flags);
>         vm_flags_set(vma, VM_DONTEXPAND);
>         for (off = 0; off < size; off += PAGE_SIZE) {
> -               page = vmalloc_to_page(kcov->area + off);
> +               page = vmalloc_to_page(kcov->state.s.area + off);
>                 res = vm_insert_page(vma, vma->vm_start + off, page);
>                 if (res) {
>                         pr_warn_once("kcov: vm_insert_page() failed\n");
> @@ -524,8 +511,8 @@ static int kcov_open(struct inode *inode, struct file *filep)
>         kcov = kzalloc(sizeof(*kcov), GFP_KERNEL);
>         if (!kcov)
>                 return -ENOMEM;
> -       kcov->mode = KCOV_MODE_DISABLED;
> -       kcov->sequence = 1;
> +       kcov->state.mode = KCOV_MODE_DISABLED;
> +       kcov->state.s.sequence = 1;
>         refcount_set(&kcov->refcount, 1);
>         spin_lock_init(&kcov->lock);
>         filep->private_data = kcov;
> @@ -560,10 +547,10 @@ static int kcov_get_mode(unsigned long arg)
>  static void kcov_fault_in_area(struct kcov *kcov)
>  {
>         unsigned long stride = PAGE_SIZE / sizeof(unsigned long);
> -       unsigned long *area = kcov->area;
> +       unsigned long *area = kcov->state.s.area;
>         unsigned long offset;
>
> -       for (offset = 0; offset < kcov->size; offset += stride)
> +       for (offset = 0; offset < kcov->state.s.size; offset += stride)
>                 READ_ONCE(area[offset]);
>  }
>
> @@ -602,7 +589,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                  * at task exit or voluntary by KCOV_DISABLE. After that it can
>                  * be enabled for another task.
>                  */
> -               if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
> +               if (kcov->state.mode != KCOV_MODE_INIT || !kcov->state.s.area)
>                         return -EINVAL;
>                 t = current;
>                 if (kcov->t != NULL || t->kcov != NULL)
> @@ -611,9 +598,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 if (mode < 0)
>                         return mode;
>                 kcov_fault_in_area(kcov);
> -               kcov->mode = mode;
> -               kcov_start(t, kcov, kcov->size, kcov->area, kcov->mode,
> -                          kcov->sequence);
> +               kcov->state.mode = mode;
> +               kcov_start(t, kcov, &kcov->state);
>                 kcov->t = t;
>                 /* Put either in kcov_task_exit() or in KCOV_DISABLE. */
>                 kcov_get(kcov);
> @@ -630,7 +616,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 kcov_put(kcov);
>                 return 0;
>         case KCOV_REMOTE_ENABLE:
> -               if (kcov->mode != KCOV_MODE_INIT || !kcov->area)
> +               if (kcov->state.mode != KCOV_MODE_INIT || !kcov->state.s.area)
>                         return -EINVAL;
>                 t = current;
>                 if (kcov->t != NULL || t->kcov != NULL)
> @@ -642,9 +628,9 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
>                 if ((unsigned long)remote_arg->area_size >
>                     LONG_MAX / sizeof(unsigned long))
>                         return -EINVAL;
> -               kcov->mode = mode;
> +               kcov->state.mode = mode;
>                 t->kcov = kcov;
> -               t->kcov_mode = KCOV_MODE_REMOTE;
> +               t->kcov_state.mode = KCOV_MODE_REMOTE;
>                 kcov->t = t;
>                 kcov->remote = true;
>                 kcov->remote_size = remote_arg->area_size;
> @@ -719,14 +705,14 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
>                 if (area == NULL)
>                         return -ENOMEM;
>                 spin_lock_irqsave(&kcov->lock, flags);
> -               if (kcov->mode != KCOV_MODE_DISABLED) {
> +               if (kcov->state.mode != KCOV_MODE_DISABLED) {
>                         spin_unlock_irqrestore(&kcov->lock, flags);
>                         vfree(area);
>                         return -EBUSY;
>                 }
> -               kcov->area = area;
> -               kcov->size = size;
> -               kcov->mode = KCOV_MODE_INIT;
> +               kcov->state.s.area = area;
> +               kcov->state.s.size = size;
> +               kcov->state.mode = KCOV_MODE_INIT;
>                 spin_unlock_irqrestore(&kcov->lock, flags);
>                 return 0;
>         case KCOV_REMOTE_ENABLE:
> @@ -822,13 +808,11 @@ static void kcov_remote_softirq_start(struct task_struct *t)
>         struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
>         unsigned int mode;
>
> -       mode = READ_ONCE(t->kcov_mode);
> +       mode = READ_ONCE(t->kcov_state.mode);
>         barrier();
>         if (kcov_mode_enabled(mode)) {
> -               data->saved_mode = mode;
> -               data->saved_size = t->kcov_size;
> -               data->saved_area = t->kcov_area;
> -               data->saved_sequence = t->kcov_sequence;
> +               data->saved_state.s = t->kcov_state.s;
> +               data->saved_state.mode = mode;
>                 data->saved_kcov = t->kcov;
>                 kcov_stop(t);
>         }
> @@ -839,13 +823,8 @@ static void kcov_remote_softirq_stop(struct task_struct *t)
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
> +               kcov_start(t, data->saved_kcov, &data->saved_state);
> +               data->saved_state = (struct kcov_state){ 0 };

Unsure how the compiler optimizes this (does it create a temporary and
then assigns it?). Maybe just memset is clearer.


>                 data->saved_kcov = NULL;
>         }
>  }
> @@ -854,12 +833,11 @@ void kcov_remote_start(u64 handle)
>  {
>         struct task_struct *t = current;
>         struct kcov_remote *remote;
> +       struct kcov_state state;
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
> @@ -872,8 +850,8 @@ void kcov_remote_start(u64 handle)
>          * Check that kcov_remote_start() is not called twice in background
>          * threads nor called by user tasks (with enabled kcov).
>          */
> -       mode = READ_ONCE(t->kcov_mode);
> -       if (WARN_ON(in_task() && kcov_mode_enabled(mode))) {
> +       state.mode = READ_ONCE(t->kcov_state.mode);
> +       if (WARN_ON(in_task() && kcov_mode_enabled(state.mode))) {
>                 local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>                 return;
>         }
> @@ -903,8 +881,8 @@ void kcov_remote_start(u64 handle)
>          * Read kcov fields before unlock to prevent races with
>          * KCOV_DISABLE / kcov_remote_reset().
>          */
> -       mode = kcov->mode;
> -       sequence = kcov->sequence;
> +       state.mode = kcov->state.mode;
> +       state.s.sequence = kcov->state.s.sequence;
>         if (in_task()) {
>                 size = kcov->remote_size;
>                 area = kcov_remote_area_get(size);
> @@ -927,12 +905,14 @@ void kcov_remote_start(u64 handle)
>
>         /* Reset coverage size. */
>         *(u64 *)area = 0;
> +       state.s.area = area;
> +       state.s.size = size;
>
>         if (in_serving_softirq()) {
>                 kcov_remote_softirq_start(t);
>                 t->kcov_softirq = 1;
>         }
> -       kcov_start(t, kcov, size, area, mode, sequence);
> +       kcov_start(t, kcov, &state);
>
>         local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
>  }
> @@ -1009,7 +989,7 @@ void kcov_remote_stop(void)
>
>         local_lock_irqsave(&kcov_percpu_data.lock, flags);
>
> -       mode = READ_ONCE(t->kcov_mode);
> +       mode = READ_ONCE(t->kcov_state.mode);
>         barrier();
>         if (!kcov_mode_enabled(mode)) {
>                 local_unlock_irqrestore(&kcov_percpu_data.lock, flags);
> @@ -1030,9 +1010,9 @@ void kcov_remote_stop(void)
>         }
>
>         kcov = t->kcov;
> -       area = t->kcov_area;
> -       size = t->kcov_size;
> -       sequence = t->kcov_sequence;
> +       area = t->kcov_state.s.area;
> +       size = t->kcov_state.s.size;
> +       sequence = t->kcov_state.s.sequence;
>
>         kcov_stop(t);
>         if (in_serving_softirq()) {
> @@ -1045,8 +1025,9 @@ void kcov_remote_stop(void)
>          * KCOV_DISABLE could have been called between kcov_remote_start()
>          * and kcov_remote_stop(), hence the sequence check.
>          */
> -       if (sequence == kcov->sequence && kcov->remote)
> -               kcov_move_area(kcov->mode, kcov->area, kcov->size, area);
> +       if (sequence == kcov->state.s.sequence && kcov->remote)
> +               kcov_move_area(kcov->state.mode, kcov->state.s.area,
> +                              kcov->state.s.size, area);
>         spin_unlock(&kcov->lock);
>
>         if (in_task()) {
> @@ -1089,10 +1070,10 @@ static void __init selftest(void)
>          * potentially traced functions in this region.
>          */
>         start = jiffies;
> -       current->kcov_mode = KCOV_MODE_TRACE_PC;
> +       current->kcov_state.mode = KCOV_MODE_TRACE_PC;
>         while ((jiffies - start) * MSEC_PER_SEC / HZ < 300)
>                 ;
> -       current->kcov_mode = 0;
> +       current->kcov_state.mode = 0;
>         pr_err("done running self test\n");
>  }
>  #endif
> --
> 2.49.0.604.gff1f9ca942-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNCf%2Bep-1-jZV9GURy7UkVX5CJF7sE_sGXV8KWoL6QPtQ%40mail.gmail.com.
