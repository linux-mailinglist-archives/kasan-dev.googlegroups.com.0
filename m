Return-Path: <kasan-dev+bncBDPPFIEASMFBBAGC4CLAMGQEVZWOI5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BCDB357BA7B
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 17:36:33 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id t2-20020a19dc02000000b0048a097cd904sf6974407lfg.17
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 08:36:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658331393; cv=pass;
        d=google.com; s=arc-20160816;
        b=vao4jR6gU/UeKIfjdJmpt1Zin5IXxKh0R1R7LNsQVOlL2iH+LJ+t7FjB/KEi94fcMA
         gbOW25QMKxE4BZe+ln84KO9/7P9nKHuHE6Paz+x14qjrUGzVqVS7FgzpW18gdjTXdujq
         lYuhA+vKJMWHNtBfpdbjitoM6fkDPS6Y7wdDpjhn5HQDmGmphoy7CbwCl4Xw+lIAih/t
         CW3mXxMB8yAymDQNNHYVERtmDPw9PDmrWkYy+7MjZWIZQ1AWdWJECKXDGaItXeR53eSt
         /84fcXnIdGRoPc3Zap0RhK/YZXybd7m7YDNhQxCNaLscfz1qgSUZAZZ9Sczzh/17mhaF
         3cww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WcqaC0CcViqTTrrH+EtOKe+hUjt6fLWTYETfuF/CYSo=;
        b=haXm/nv0YY4b5/DPpZwTild16LbOfVhKKaGank05TJtymf+SQN0Ri4hbHPnBDMF4PZ
         k+mLT2YfOSR4/lEveABMvek06wtlZMjpp5q4cxCXmHHrEJWDV5ErZ/K3DQ/pORoIUBc/
         jmi+Pq9Ovks1kVxzghijC/7RpzIqt43aHWDz8ZYNfhTzOt7xW+BuT3RXpRHRiqPkQ7sW
         sMAyA2o1OWSBR5TIuW19rCdBwdLXQ5HQ56nTX0KksIxJMivl/2DEsbjLbRhhRkFuDkr9
         alhfM8etOunLVetNHHsIHexDOH+X6j+lY+EKnvXB3XACKXwuCA9tC3vHPX0xkXwaFPdB
         pf5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DYrPq68G;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WcqaC0CcViqTTrrH+EtOKe+hUjt6fLWTYETfuF/CYSo=;
        b=RWmVqdEa6YIzn+EoeYZ7/xeu5zohelVAB2bT4PeyuQUGBCisYoxYUlBqE95VLtfLJB
         zGBb0o+qa8qq74deG8sFv1E1no7uyQhBKIjE+4ZaOmNfbwG5QlKbtZTEu/mkGewv7cxN
         kE2uf84XC7gn3gpSie+HREQ7NNsVjodJXKKmgwuiD+wmQTkPPSISXPVZrRoMcymn+1MB
         bqAzzB7/Gs5576k7VSyyR8ePsoDf8dMzpPtzMFN6fX9RsvLl/xm7oqe/6BMyTa+/Y/bb
         fOqSWNbpxuHs59NhflCBkDns+2sbcpNKAvLvY63pQfNtVJSWLBCd5rL33Ex0s01y3edG
         eL4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WcqaC0CcViqTTrrH+EtOKe+hUjt6fLWTYETfuF/CYSo=;
        b=22aFQDQ5+wjj/2sjtd63mEA/O25WZGvmhxBSM67tEXEhcD0x76oqOBS4vH44Yx44lq
         XNraj/mDuvRidcdpXDgXiwL4LvPbEpv0QG7RhlfesVbAswbgguPBtwDRApLrtut6piT2
         ZJiFc3NIlDF11/csbGGYMxDfviCTSve+5hKICR8ic6MpQ1Di1p9Ep++Jo75Us5zXFvEA
         gG5I8tVLV8pTQ9VY+C0BszePRb8busZGTaaxA9m+7EGhM0UIXqkw+AhjrgzCqv+GBVVT
         Jp7NDUc+AePNm+4+b2LhBeFX37FwI59GYKQ0MUCdZaLdkU1zKDq+SeXCux5EKKL7PAYe
         zBCg==
X-Gm-Message-State: AJIora8E7ueAoH/Gn00y9s0HTSKHC0Uf5/AOIf2TGM9+WYg1VXYd78/k
	9bCcQ+yuaBmzARoMymn6APc=
X-Google-Smtp-Source: AGRyM1t7CRjBc0EgHltDvmz6UowJXYNXUiPVH5VFSNzy0yGwPM0m2p+bwrI7KYLzo0KSOkfKM+KMTw==
X-Received: by 2002:a05:6512:3052:b0:48a:37ad:1462 with SMTP id b18-20020a056512305200b0048a37ad1462mr9665118lfb.463.1658331392928;
        Wed, 20 Jul 2022 08:36:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3495:b0:489:c695:d51d with SMTP id
 v21-20020a056512349500b00489c695d51dls90747lfr.1.-pod-prod-gmail; Wed, 20 Jul
 2022 08:36:31 -0700 (PDT)
X-Received: by 2002:a05:6512:2216:b0:489:48b6:f8cd with SMTP id h22-20020a056512221600b0048948b6f8cdmr18580744lfu.267.1658331391728;
        Wed, 20 Jul 2022 08:36:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658331391; cv=none;
        d=google.com; s=arc-20160816;
        b=0+IHKwWejEqFnvZRXYnfCeLyggmH/wUMO8nOm8wMnF9Cjuf7S3UtTLEHC8nHMJdJRc
         6Zk+CGa1RdnKK36KcmO09ORxVTufrkEIIRIQBOPZICFLuER+/FFx2hHFv7TTuwo/colZ
         zmWKnN3YcVRIvYhbn3CFV2rSPawUBg1L0IxjE4CrsRJQWdLbSrl96SjD6ZBfc4BZfsFD
         G2b/J1Y6E3Zt8ffY1VJImTtWouLskROi7RFkqfvyzlk1OI1Cm/0SDAdzxNmcm4+dRPtm
         q/TQmcFgFydag2iYp4B4AQr7ULP7Wod5AnMUVpEkOUUIJ2uOTsFGwmJzXsll0iIF6d9O
         PCsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zFzxx0z8pNKG8GQJAfngz4sVC9qlk18q5vOjkBqe41U=;
        b=QhY65HWwnRVDauPhiIzadAfTfhBHWWoElk552DbnJoPLFerjjpAgzzP94EIAtuADL4
         s1HCXfpN58c5MVd4NwiRHGCGHX3zowpSPpNlMOQrjtIOaAl1b0/j3j35exFriAB2r0Dw
         oyp9rOgbZ3xndASAeNItvF2nXF5ogD1yI1b7NKpxwY9Xlfz+bTDPvTT5hzcV8Ke/Sp+h
         5GZCYIvCrXyQPCsLizst+O8uUotpebSJBAmCUSUXrMjdnBLFr1coETOzBETRxiKohWlC
         W94tK3oYDFNGIwFyz6KKxIjUrWDBxJxDvU8LtX4TA2f8yF1prL5/XAfMjDYHffBYXs2L
         9CWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DYrPq68G;
       spf=pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::336 as permitted sender) smtp.mailfrom=irogers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id p9-20020a2eba09000000b0025dc37aabf7si246993lja.3.2022.07.20.08.36.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Jul 2022 08:36:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::336 as permitted sender) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id f24-20020a1cc918000000b003a30178c022so1591603wmb.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Jul 2022 08:36:31 -0700 (PDT)
X-Received: by 2002:a05:600c:2854:b0:3a3:1551:d7d with SMTP id
 r20-20020a05600c285400b003a315510d7dmr4199687wmb.174.1658331391068; Wed, 20
 Jul 2022 08:36:31 -0700 (PDT)
MIME-Version: 1.0
References: <20220704150514.48816-1-elver@google.com> <20220704150514.48816-11-elver@google.com>
In-Reply-To: <20220704150514.48816-11-elver@google.com>
From: "'Ian Rogers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Jul 2022 08:36:18 -0700
Message-ID: <CAP-5=fX7DoS0eDk=FS14CRjU_UPinH2+0+uD1JPXFMtrb7o1eA@mail.gmail.com>
Subject: Re: [PATCH v3 10/14] locking/percpu-rwsem: Add percpu_is_write_locked()
 and percpu_is_read_locked()
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: irogers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DYrPq68G;       spf=pass
 (google.com: domain of irogers@google.com designates 2a00:1450:4864:20::336
 as permitted sender) smtp.mailfrom=irogers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Ian Rogers <irogers@google.com>
Reply-To: Ian Rogers <irogers@google.com>
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

On Mon, Jul 4, 2022 at 8:07 AM Marco Elver <elver@google.com> wrote:
>
> Implement simple accessors to probe percpu-rwsem's locked state:
> percpu_is_write_locked(), percpu_is_read_locked().
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Acked-by: Ian Rogers <irogers@google.com>

Thanks,
Ian

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAP-5%3DfX7DoS0eDk%3DFS14CRjU_UPinH2%2B0%2BuD1JPXFMtrb7o1eA%40mail.gmail.com.
