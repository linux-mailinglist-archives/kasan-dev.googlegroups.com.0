Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYF5ZO6QMGQEU33VHUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 16F06A37BC4
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 08:01:58 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2fc0bc05c00sf12954454a91.2
        for <lists+kasan-dev@lfdr.de>; Sun, 16 Feb 2025 23:01:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739775716; cv=pass;
        d=google.com; s=arc-20240605;
        b=fAAaWF+XfG1DniVkPdfHFM2CLrAUh/OIlqa7SyxYcFoi0yCd9NQMHRAjhwlwPg9LM8
         zTD4QRFIGdYb/yUmb6DvnzzXiImig2HuDppyCj3WPfGzLbsrW0V7HZuXrs4wR6QBDm4y
         zwGNF6rd2pLQ6OguMzCrfuaDf1EdAkVjfwTaQ/3gMxDOMxGsp4aiKnYyb0HWGFNBpLpr
         abrtR8fpQGdyAUNvRUDQxUM7w77/SSdrIHMkosQJ6dlyF6TISVtzInPOA365hXX0herc
         /07V812EHV4wY9Wt3PCOsly/Ai2U2zTIzjK9Nr8EiH26D9jwm1Av1WAB0BfX7YRuuSUh
         1QNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cE9p67iPPcdvngFg8F0NnO4wIsaGiVjbwR2T3hJfcPA=;
        fh=Yn1yFo5qAacVQSFEatq+zoaqdrZbsrCzdFscrBceux8=;
        b=IDv0IhQKagsW44GwbSkEaBp/aX1Da1Wgjr/ZPXgObs/Eqj0nN1QLyyAM/B7ebbFAxl
         t4Jl1/L7Vb6gYefbNf0OEwM6RcASLna5zIhBx1pa+X1atmDuUWMWnbwPsQsqIQ89dpt3
         3l9WMp2QXWFu8blAlSDUbu6TAaH5o7X4MmTHiTUXFcCPhliNpCQ9Th97uENVTrtevz0I
         JJqy0BQsMxLQg9sCDi1ydCSiZ4wNUU0UH8HpI7x7t1/dvzzvcR8FMZ5Y2LCUrvmG62fM
         abTaNaHCrs3m0vBLCWPo6XrqqrAKvGgCkhfOe9yin59zt2O/2s2hyZ8cLkF7UyqQCOKm
         SZ5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k6fhf0jo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739775716; x=1740380516; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cE9p67iPPcdvngFg8F0NnO4wIsaGiVjbwR2T3hJfcPA=;
        b=fBVQYjjXb5eBWiVWMGdA/Ymk3foA2OkJqSjVQns4nmodSGyE1qcMGUJWQvktjlaDDI
         ioM0YDGpLTGpjAKrqnGSp2V5+mT33cjg8lR7bnEv2gr0bWC/Gz06RAulA6TGP97AGiC8
         VTwO2wdGyDXibr8DlA73xx/NIyaj8xjlBCMTQq628jJaxKVJ5zqoagbFsBi4cG5vk261
         mICh1wcbYbi0sxY8IqCAqMogcmhZ67iuePPOR1TARzaixFeLMVvAMHJQiEO22ly2Kyy0
         JFJAhNiPrEfqZmUDxPb69+MaB3FgHI5uS6zoT0MzVmCu00LfNaFF0rbyQLluyS6aWue3
         QEbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739775716; x=1740380516;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cE9p67iPPcdvngFg8F0NnO4wIsaGiVjbwR2T3hJfcPA=;
        b=DyNlTTm9oJL5yWFvtW5US8eKs8yQqybHoYLlJBuNDSd8sEfJssZCWz71rcMIAEHeX6
         OWkPXrRzBRWIX6L1slpnxUGL1V20HN66lzS8WRVCWT65qNeWtfjTVJsts1s1tThwZeRr
         qdfzOqttX4H5DTYwEKrinvwAyn6dOglWcPu3y8ajjyeOPc1v0of0hm0NVxIMS1/4AjE0
         gj3Q/00WtJ9d9USQB+CAeJ/FPgFiLI75pJGdqdDqsuj1Cz7UmJvNivx1esWTgBZ3sYqa
         CqDUcyqVf+F7338yTtgv142MWlEaeYj5A+bNvMD47Ocx7vyCtQTX7xHQHLaYmaqK3WrB
         8tIg==
X-Forwarded-Encrypted: i=2; AJvYcCVCfzY7tA9qk7KQxrof0Ycter8ZbixhjWpXVjXVNNUneu3EnlC0gm78SsHZBAIAi34zSrd3mw==@lfdr.de
X-Gm-Message-State: AOJu0Yyay0WdU8DcHchsGpPleJrRhxEHKV6wzU6Fhn5k7w03ScgmdO4A
	qMvmmIJGwWPHr2Z/RyPEuN/IPWXi1iw9Oxr9vUKyogNYkos2Pznp
X-Google-Smtp-Source: AGHT+IE5dBNLnxd9t20u4NUbRJKAFT9n88R/WOej1VX+tjQnHzREu+DmtdW3JYrP+tDlDQ8JofiAtg==
X-Received: by 2002:a17:90b:3812:b0:2f4:434d:c7ed with SMTP id 98e67ed59e1d1-2fc40f1f83cmr15298317a91.16.1739775713206;
        Sun, 16 Feb 2025 23:01:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGQCHZK06lixMhQxvnol+yIcevU6fkafIccsy73kAqg9Q==
Received: by 2002:a17:90b:4d91:b0:2ee:edae:763 with SMTP id
 98e67ed59e1d1-2fc0d5742d3ls1867693a91.0.-pod-prod-06-us; Sun, 16 Feb 2025
 23:01:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUfbBF+4RtinLIlXi1xs6uzjniis1I3ZBfSgK7vvvpqxsnRZzMcH5O3DsCn7RhfcyWIE+9UDf6+lzk=@googlegroups.com
X-Received: by 2002:a17:90b:3e83:b0:2f5:63a:44f9 with SMTP id 98e67ed59e1d1-2fc410405demr10306502a91.23.1739775711720;
        Sun, 16 Feb 2025 23:01:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739775711; cv=none;
        d=google.com; s=arc-20240605;
        b=gT8mEeAcgxQBQwxtgwbOnMn2HzCFC1MrjJzD5QWRmnP65HcyJANvbRsZPedLCL9Yfx
         SgmhaXofvfkA6/BU8SofOxGe43CinweCLIiraCSmdPG9Re9u797yePqorLfuweOEfLzP
         bD0yidrt8NMPovf0+j2ijOn+NBFubEVWWAPSC9a0Q7QmcNlrB4DJRANP3Nr6/qXSUJZh
         OPazV1S9DnlIW+AqypGNkimp3BtST5YMEVP250x650z8+0mY8sQB7leUe7u1d+93Fd+U
         /jSx61WGMDsNC0vBPFurdW9ypds2hxLhYeg8WvaUcdJVbaqvSKrlsJGZSyYaLowY9520
         CjsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u49MZ7ckUjks0G4rUJJF3Jdne3nRn7VDLa3q0SficI4=;
        fh=gwb+NCeZeVUfrzGBkQIWBnWkUIddioDpj1hvvdsMYL8=;
        b=CoXm49uDdCIGtrHcbvCrOtCRK0t99y0W1EvEN2GX1+9AUrvyVD6SBGDNJwIWQV+bGt
         HLCSPT9E2RJ9ZCvu/50EOQ+8ym4vc4wRAgPRjMqF6EjJluHHmv+I0/jQjfJE6yV/kknv
         F+ptG+vys7tX4/0ph7B3ilvfwa7nXsBSt/Md29b+FXq4BBbB2KMvXqMaNByVUMF6Mtj1
         Nm2/F/sWCzkr6ENthUwCN6UjvVlnsQw+67Rzwwr+pwbEDCcfOHpRxO6MsO+Umfih/yA+
         oVwq/i+4+OZdXS84EHh5Ue1g9yBRBxPVdCo1bHDCRnzR79d9MgLfNrw9JzkQw6/0lORm
         mBYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=k6fhf0jo;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2faa4b0e10dsi1770326a91.0.2025.02.16.23.01.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 16 Feb 2025 23:01:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-21c2f1b610dso101478535ad.0
        for <kasan-dev@googlegroups.com>; Sun, 16 Feb 2025 23:01:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUzx0RPYsCq6tP7qZIRqTmayX+sdY3951rXfFMSRbn56zREo+d2YhH8AiRM3Z0+rub7chotijDIp8c=@googlegroups.com
X-Gm-Gg: ASbGncv4wKHucDEWvgcAlcHOgJdHDgbjgIYxt31Rdjg/fV7y2hbnWTPHu/4CHax1Ga3
	44EnbaBqJvpbdtoiR9pySrSby3uamoEyUlhoqn3H7od6nIWaUSnWZEBXV4hH4b0rxLgRaRwnUfO
	9sX8hwVKqLIZ20XlDMtuvt98EE4hV0
X-Received: by 2002:a17:902:fc4e:b0:21f:71b4:d2aa with SMTP id
 d9443c01a7336-22103efeebcmr156092895ad.5.1739775711051; Sun, 16 Feb 2025
 23:01:51 -0800 (PST)
MIME-Version: 1.0
References: <20250213200228.1993588-1-longman@redhat.com> <20250213200228.1993588-4-longman@redhat.com>
In-Reply-To: <20250213200228.1993588-4-longman@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 17 Feb 2025 08:00:00 +0100
X-Gm-Features: AWEUYZmwE5--6gxi63zdBnPmPq2kP11LV4_YCuAvaNLPtiVGpigxkVLu7uW9PZs
Message-ID: <CANpmjNPRZNTX2BKufHU16ybfcCvDaJmOSgihP7d0r9bgNZtGaQ@mail.gmail.com>
Subject: Re: [PATCH v4 3/4] locking/lockdep: Disable KASAN instrumentation of lockdep.c
To: Waiman Long <longman@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will.deacon@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=k6fhf0jo;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as
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

On Thu, 13 Feb 2025 at 21:02, Waiman Long <longman@redhat.com> wrote:
>
> Both KASAN and LOCKDEP are commonly enabled in building a debug kernel.
> Each of them can significantly slow down the speed of a debug kernel.
> Enabling KASAN instrumentation of the LOCKDEP code will further slow
> thing down.
>
> Since LOCKDEP is a high overhead debugging tool, it will never get
> enabled in a production kernel. The LOCKDEP code is also pretty mature
> and is unlikely to get major changes. There is also a possibility of
> recursion similar to KCSAN.
>
> To evaluate the performance impact of disabling KASAN instrumentation
> of lockdep.c, the time to do a parallel build of the Linux defconfig
> kernel was used as the benchmark. Two x86-64 systems (Skylake & Zen 2)
> and an arm64 system were used as test beds. Two sets of non-RT and RT
> kernels with similar configurations except mainly CONFIG_PREEMPT_RT
> were used for evaulation.
>
> For the Skylake system:
>
>   Kernel                        Run time            Sys time
>   ------                        --------            --------
>   Non-debug kernel (baseline)   0m47.642s             4m19.811s
>
>   [CONFIG_KASAN_INLINE=y]
>   Debug kernel                  2m11.108s (x2.8)     38m20.467s (x8.9)
>   Debug kernel (patched)        1m49.602s (x2.3)     31m28.501s (x7.3)
>   Debug kernel
>   (patched + mitigations=off)   1m30.988s (x1.9)     26m41.993s (x6.2)
>
>   RT kernel (baseline)          0m54.871s             7m15.340s
>
>   [CONFIG_KASAN_INLINE=n]
>   RT debug kernel               6m07.151s (x6.7)    135m47.428s (x18.7)
>   RT debug kernel (patched)     3m42.434s (x4.1)     74m51.636s (x10.3)
>   RT debug kernel
>   (patched + mitigations=off)   2m40.383s (x2.9)     57m54.369s (x8.0)
>
>   [CONFIG_KASAN_INLINE=y]
>   RT debug kernel               3m22.155s (x3.7)     77m53.018s (x10.7)
>   RT debug kernel (patched)     2m36.700s (x2.9)     54m31.195s (x7.5)
>   RT debug kernel
>   (patched + mitigations=off)   2m06.110s (x2.3)     45m49.493s (x6.3)
>
> For the Zen 2 system:
>
>   Kernel                        Run time            Sys time
>   ------                        --------            --------
>   Non-debug kernel (baseline)   1m42.806s            39m48.714s
>
>   [CONFIG_KASAN_INLINE=y]
>   Debug kernel                  4m04.524s (x2.4)    125m35.904s (x3.2)
>   Debug kernel (patched)        3m56.241s (x2.3)    127m22.378s (x3.2)
>   Debug kernel
>   (patched + mitigations=off)   2m38.157s (x1.5)     92m35.680s (x2.3)
>
>   RT kernel (baseline)           1m51.500s           14m56.322s
>
>   [CONFIG_KASAN_INLINE=n]
>   RT debug kernel               16m04.962s (x8.7)   244m36.463s (x16.4)
>   RT debug kernel (patched)      9m09.073s (x4.9)   129m28.439s (x8.7)
>   RT debug kernel
>   (patched + mitigations=off)    3m31.662s (x1.9)    51m01.391s (x3.4)
>
> For the arm64 system:
>
>   Kernel                        Run time            Sys time
>   ------                        --------            --------
>   Non-debug kernel (baseline)   1m56.844s             8m47.150s
>   Debug kernel                  3m54.774s (x2.0)     92m30.098s (x10.5)
>   Debug kernel (patched)        3m32.429s (x1.8)     77m40.779s (x8.8)
>
>   RT kernel (baseline)           4m01.641s           18m16.777s
>
>   [CONFIG_KASAN_INLINE=n]
>   RT debug kernel               19m32.977s (x4.9)   304m23.965s (x16.7)
>   RT debug kernel (patched)     16m28.354s (x4.1)   234m18.149s (x12.8)
>
> Turning the mitigations off doesn't seems to have any noticeable impact
> on the performance of the arm64 system. So the mitigation=off entries
> aren't included.
>
> For the x86 CPUs, cpu mitigations has a much bigger
> impact on performance, especially the RT debug kernel with
> CONFIG_KASAN_INLINE=n. The SRSO mitigation in Zen 2 has an especially
> big impact on the debug kernel. It is also the majority of the slowdown
> with mitigations on. It is because the patched ret instruction slows
> down function returns. A lot of helper functions that are normally
> compiled out or inlined may become real function calls in the debug
> kernel.
>
> With CONFIG_KASAN_INLINE=n, the KASAN instrumentation inserts a
> lot of __asan_loadX*() and __kasan_check_read() function calls to memory
> access portion of the code. The lockdep's __lock_acquire() function,
> for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
> added with KASAN instrumentation. Of course, the actual numbers may vary
> depending on the compiler used and the exact version of the lockdep code.
>
> With the Skylake test system, the parallel kernel build times reduction
> of the RT debug kernel with this patch are:
>
>  CONFIG_KASAN_INLINE=n: -37%
>  CONFIG_KASAN_INLINE=y: -22%
>
> The time reduction is less with CONFIG_KASAN_INLINE=y, but it is still
> significant.
>
> Setting CONFIG_KASAN_INLINE=y can result in a significant performance
> improvement. The major drawback is a significant increase in the size
> of kernel text. In the case of vmlinux, its text size increases from
> 45997948 to 67606807. That is a 47% size increase (about 21 Mbytes). The
> size increase of other kernel modules should be similar.
>
> With the newly added rtmutex and lockdep lock events, the relevant
> event counts for the test runs with the Skylake system were:
>
>   Event type            Debug kernel    RT debug kernel
>   ----------            ------------    ---------------
>   lockdep_acquire       1,968,663,277   5,425,313,953
>   rtlock_slowlock            -            401,701,156
>   rtmutex_slowlock           -                139,672
>
> The __lock_acquire() calls in the RT debug kernel are x2.8 times of the
> non-RT debug kernel with the same workload. Since the __lock_acquire()
> function is a big hitter in term of performance slowdown, this makes
> the RT debug kernel much slower than the non-RT one. The average lock
> nesting depth is likely to be higher in the RT debug kernel too leading
> to longer execution time in the __lock_acquire() function.
>
> As the small advantage of enabling KASAN instrumentation to catch
> potential memory access error in the lockdep debugging tool is probably
> not worth the drawback of further slowing down a debug kernel, disable
> KASAN instrumentation in the lockdep code to allow the debug kernels
> to regain some performance back, especially for the RT debug kernels.
>
> Signed-off-by: Waiman Long <longman@redhat.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  kernel/locking/Makefile | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> index 0db4093d17b8..a114949eeed5 100644
> --- a/kernel/locking/Makefile
> +++ b/kernel/locking/Makefile
> @@ -5,7 +5,8 @@ KCOV_INSTRUMENT         := n
>
>  obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
>
> -# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
> +# Avoid recursion lockdep -> sanitizer -> ... -> lockdep & improve performance.
> +KASAN_SANITIZE_lockdep.o := n
>  KCSAN_SANITIZE_lockdep.o := n
>
>  ifdef CONFIG_FUNCTION_TRACER
> --
> 2.48.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPRZNTX2BKufHU16ybfcCvDaJmOSgihP7d0r9bgNZtGaQ%40mail.gmail.com.
