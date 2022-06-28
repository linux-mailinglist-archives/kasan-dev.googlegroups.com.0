Return-Path: <kasan-dev+bncBCMIZB7QWENRBZ5H5SKQMGQERK2UAAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1609A55E56A
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 16:44:56 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id p6-20020a05600c358600b003a0483b3c2esf3832522wmq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 07:44:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656427495; cv=pass;
        d=google.com; s=arc-20160816;
        b=vPvoXiYU4AciV2ZESBSDOeJhKMnAGG2A8tc2qK7eMpvJKIgkoh1nWYjvv0UVnn1uLB
         LfZh1tRU/mx9ObnCvHcIXsmOQu1SH07KgbclVHanHAre2dzCYvphlGHOBokrUI6ZPLV7
         r2LdAInAWdltuVTXVpQurAYd6gzEk9CWdraRtS3jMETDSDJ1A1stQ1ldTIWfABE+Zfhg
         Wy+0IsTz3w1lYRgOj4P4P2BMCa67VRJPl001g8H8nzLPoi+Kg5VpGFjunE+XTv/Z/Q+e
         T9psM16C2tl9roc+ZWSHZ0UxisRPHXsM/odSlKf1mc9tMrXWbL8zuQYAXSRi9BOmLc/t
         7vfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5yRiJJHFJqFdUrmIUC8Rv4VKiaCR+O1OaCcAN9RD+h8=;
        b=YUe3Uggcn781RQ5Pqw2s0VrxchZpMzptI0N4bPlaiaVL/Fc7Yyu8QuIxK5i+M2FrIQ
         w9f5DyNAUyY4q4en900j2EQeYZIKbDhPlHVq+vBs9f5gpYbC/RM910U0UM7lVw2OsXL2
         5ZpoEPlnGz80UvsGHe/kH8fgBrfynb50KGdXAgOwo6JGa7fck5Gtx9y4E5aGqQKvuVX2
         EdUVYKS6flEN0tC3h0AgrXTnodREqDSwss8Df7fEljln+IYvCg948DxdjggmihvoSQID
         omCFiYpogJn9Km37UMqM+K2wcBAYXJJyAhYOIvC9RSFGD2ZXF0lFuizkRZZH8clIF4Tj
         4vrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ht86O9eM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yRiJJHFJqFdUrmIUC8Rv4VKiaCR+O1OaCcAN9RD+h8=;
        b=AgPO7hI/gcRkxeDDHI6UeNxDYpRgqW/LJ/0NYYVN98PB+P2ISyamnYOngCvkFrsBip
         zfLPe2s/YgWIbVy1Yv8n3s0NiQaLuV+1gwMKVqVX7qj1iqcy1+0NVLLnvh9ke04ykLbr
         d8szG+KdEk3swPi+j10I7MOwyzwV8xkwKKBxiTUeGSwFjQWZVLmGIMoacqANpZFW8OqB
         u9HTJpyyLCIwUQjLiQpE4Q18oz+ZDTPOGBhEMOJYJVF1FeAEwEhP/C8ktVmd/PHOLn7l
         uW0Mbk7KOgxLmircoXZcvXvsY63716XdenEmbKuInw0MeaFpv5rVSWCEs2cjlWlF6lDj
         NXYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yRiJJHFJqFdUrmIUC8Rv4VKiaCR+O1OaCcAN9RD+h8=;
        b=HfEhtbIVA7YQehWXXIK5z3eX04fchFq/XzM6LA10wH72uwmfLDfuq+2fWLwt2QRHXV
         jL5jZKQWFW3SFN3Z3RywRIALWbffNXXYDiFF5J1g1ztLYS0pMCmH5xxw8Y9/G2pREww1
         qeF9YoqFx72sZGJoeGvdM7+3s/2KXqqqDcotRlcNzNZXTC3A8Sc2NHxqDkMhFlm6XQLo
         vumTGJyJE/HvA3x0hbKTzAP9m/hqbZgGceTP9fmZXZ23B4JgnH9hNhpiXLahCC/prSb2
         2GyeTJoHcgVpiCO35jhUQ5LsDmbB8vLncU8AydjQNJcY0LwhCoOSMdmqwiepGlbvCoq6
         mrSA==
X-Gm-Message-State: AJIora9JvsPZvlaqZPVVKQi69eOrhfrlnsF7bW7rHGHDc6H40ffuh76D
	5HgCDTx5/QoKUc6X8BGLMAI=
X-Google-Smtp-Source: AGRyM1sS2NLs6Qb7mqrmuI8cX7xOkaA0ZOd7IQ2E/0gAXY8gxm7eZjzFYunRULohPsbalOAE6QV8jg==
X-Received: by 2002:a1c:2902:0:b0:3a0:2a05:c639 with SMTP id p2-20020a1c2902000000b003a02a05c639mr22738117wmp.31.1656427495624;
        Tue, 28 Jun 2022 07:44:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e19:b0:3a0:5669:1a91 with SMTP id
 ay25-20020a05600c1e1900b003a056691a91ls769715wmb.3.canary-gmail; Tue, 28 Jun
 2022 07:44:54 -0700 (PDT)
X-Received: by 2002:a1c:7517:0:b0:3a0:2d36:4dcc with SMTP id o23-20020a1c7517000000b003a02d364dccmr27290750wmc.21.1656427494639;
        Tue, 28 Jun 2022 07:44:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656427494; cv=none;
        d=google.com; s=arc-20160816;
        b=nXiIWCGxYEKMLOZKC0o5fh6Ma60d1OBnzw8MynQVw/Eyro2g4+MufTEyk7i/2sfz6m
         12xKZm6Qy7+JfWTtvTAWNSqrM/I5OWTrh0VxM0UcQh6YR118uC+kE3PxaoNwDMH8HLzu
         R2UIXJnaLTMgT5bRZRrB92qysDJgkVUH02YVSCk3+SyBr9CkQTg+x7QtM0bZBMtJPv0S
         Lj3Y4GODVoh0aLIeDAjtNIhKVKfNDUQDRIu37SPtuvUTr33hqMuqlKueGurCyIRWWvxA
         EiFEiwOTBl71LvA4YsQ27jXHaBvIqvidjue8EhbRcZMQPtpwhr+gn/72XER6vCfpNJs/
         TQxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xYNtEachczg7r/XXNrPpniIU6MTplkzQm/H7US5uhak=;
        b=Z1QPpKIFXe3DuBqpMi/wutK3HI+K/f0Yrq+3wFaMn4ohPCtObC8CVBNvG9Yc1IWE2x
         IFQ0w1M77gaYDlYTIcAJvnYv4yaHX3swKRgB2mZlp+eL+buDjkYmzzZ4TRHu0cH0Apw+
         vHkt9V3nyK85DLPllL3G5BkLtk0kU2McOmPgYfoev4WEmqz9zJhWD9GbO1TRxsJeuOY7
         XRSegKdwN/2heq1TpmkcYQjYIzH0f+ghJ8qp8B2hZqgBEmCo10a/gADDnpqzEQ+RvfrJ
         jiOmNko/YlXmrmgQdcpOX+i67x2lrh3iZAjz0F9CDE3HKSDm2Wlw819Pr5/ppger0+R3
         W4rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ht86O9eM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id l187-20020a1c25c4000000b003a050f3073asi79486wml.4.2022.06.28.07.44.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 07:44:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id by38so15162215ljb.10
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 07:44:54 -0700 (PDT)
X-Received: by 2002:a2e:8ec9:0:b0:25a:754d:db39 with SMTP id
 e9-20020a2e8ec9000000b0025a754ddb39mr9908848ljl.4.1656427492555; Tue, 28 Jun
 2022 07:44:52 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-10-elver@google.com>
In-Reply-To: <20220628095833.2579903-10-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 16:44:41 +0200
Message-ID: <CACT4Y+bzcWQUspDws-rKJNcOxceg-XOQzunuwsQBuPH5KMqJXA@mail.gmail.com>
Subject: Re: [PATCH v2 09/13] locking/percpu-rwsem: Add percpu_is_write_locked()
 and percpu_is_read_locked()
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ht86O9eM;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c
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

On Tue, 28 Jun 2022 at 11:59, Marco Elver <elver@google.com> wrote:
>
> Implement simple accessors to probe percpu-rwsem's locked state:
> percpu_is_write_locked(), percpu_is_read_locked().
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> v2:
> * New patch.
> ---
>  include/linux/percpu-rwsem.h  | 6 ++++++
>  kernel/locking/percpu-rwsem.c | 6 ++++++
>  2 files changed, 12 insertions(+)
>
> diff --git a/include/linux/percpu-rwsem.h b/include/linux/percpu-rwsem.h
> index 5fda40f97fe9..36b942b67b7d 100644
> --- a/include/linux/percpu-rwsem.h
> +++ b/include/linux/percpu-rwsem.h
> @@ -121,9 +121,15 @@ static inline void percpu_up_read(struct percpu_rw_semaphore *sem)
>         preempt_enable();
>  }
>
> +extern bool percpu_is_read_locked(struct percpu_rw_semaphore *);
>  extern void percpu_down_write(struct percpu_rw_semaphore *);
>  extern void percpu_up_write(struct percpu_rw_semaphore *);
>
> +static inline bool percpu_is_write_locked(struct percpu_rw_semaphore *sem)
> +{
> +       return atomic_read(&sem->block);
> +}
> +
>  extern int __percpu_init_rwsem(struct percpu_rw_semaphore *,
>                                 const char *, struct lock_class_key *);
>
> diff --git a/kernel/locking/percpu-rwsem.c b/kernel/locking/percpu-rwsem.c
> index 5fe4c5495ba3..213d114fb025 100644
> --- a/kernel/locking/percpu-rwsem.c
> +++ b/kernel/locking/percpu-rwsem.c
> @@ -192,6 +192,12 @@ EXPORT_SYMBOL_GPL(__percpu_down_read);
>         __sum;                                                          \
>  })
>
> +bool percpu_is_read_locked(struct percpu_rw_semaphore *sem)
> +{
> +       return per_cpu_sum(*sem->read_count) != 0;
> +}
> +EXPORT_SYMBOL_GPL(percpu_is_read_locked);
> +
>  /*
>   * Return true if the modular sum of the sem->read_count per-CPU variable is
>   * zero.  If this sum is zero, then it is stable due to the fact that if any
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbzcWQUspDws-rKJNcOxceg-XOQzunuwsQBuPH5KMqJXA%40mail.gmail.com.
