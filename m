Return-Path: <kasan-dev+bncBDW2JDUY5AORBAGTZW6QMGQE65CPOYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id A7D27A38A16
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 17:53:22 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-54531871ec8sf1395260e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 08:53:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739811202; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZJVLe/P1RjR5wJ1SAnxb0ClZKlVCaj3MnPOiE5YskmTC6XeiuV71isFB+fnoavj1lY
         TXrwhxTfUivEuFGTuUH3skG6hR0nxLlr1KrN0q9x6TWW+2M6+Q6IS8kMo/sMLNY2EMg2
         iy35Z4ueUIyYUKxk86De8nQ3v6q5qAaVn4REbprlpNEbu+1IAXDaas9cmvjlYAT+z6yD
         GJWzl4KUOsxbQbbN9dn/+J94Gdg0iB6I3y5uGYGIwfctyf3mvuLKxDjOENPkGpL+q6vm
         EbKiKvtoayoeURn8qucUe72K6jsra6/zeRSBiJze3f8VVrWnCDPmmhpJxM/wzWaEhJaN
         flHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=vHpY1xFt83PWWftTreTSeJvumdmd4PMh92XrbQANj7s=;
        fh=39mxOZru+WV7FYI4OuBa7/CFsJad+HS20ym43//Im98=;
        b=efuIr7//99FefDydGCjW293wMm7ilKGXc4pFAAMVRR/oRcpTUtNUKMHtRStLoGMIRQ
         JwBv398w0C/9F3uMXrP84wEVKLB4Jr171pCYHeFUbo71x4fw/vIb8bt1uL0RsOlfBbLm
         IKs/Z+fDFgJ01yX6YIY91zLnycjIs97Mq2LX2kQZJ0OfzqZMoymnXYsUtbtA7lQ//PV/
         TPuh/4Aq9+U6fOPN09S5vCnwPeNUP9Np+hU4fS9VuKZvF5a7wrIZdN3MOVxi/HwbrVSg
         zcOuL+l+iaDtJWIZg8JGJi8PILQw8VGkALcFSGRlA41Ji8XOzBlnvrCfzKJVCquNlpY8
         pT7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bysoTY36;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739811202; x=1740416002; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vHpY1xFt83PWWftTreTSeJvumdmd4PMh92XrbQANj7s=;
        b=wFoGYLDNYfwhsugAED1fO2b9DrzmRbRD5oqUXENhlaCW/8dOEXnvXtRlwAg5aOa0iO
         yhfjSjzlKWpcwXCZU+AWeraV/YzMWQZHGPfcNPOsPb1jYaslcscqqUuaoJgM4az04B1w
         zNqHHQNGgxUncF24bG0qNnHgep+X/b7ICeVFh785oEdcg3wnhq33rN5HO+/J/qurFUq1
         QcwfS/u14NeEHtnfIPDhGKyYDKpEFUzH54tavdrwzReNVZEfvyyJ2ru5/j5jCOUXxihO
         CDG9Ml6n9n6UDA/URBPKYC+eYZCO281Jewij9jUEku0nqnHcL2AZKd3MemLDOHk9rSRL
         WRzg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739811202; x=1740416002; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vHpY1xFt83PWWftTreTSeJvumdmd4PMh92XrbQANj7s=;
        b=ELqWyB3Rg/1vkPa4Hjys5WZzW/NGm4fWgiftCkmOEWDi+gSn8PrLAqCtkg5ZnHPwy4
         D1zUsWjI+6Rw/CK3gqatrci77Tg76V+iKeISFnaW9j9K7M0q2BIdWj40VUVsStVIqTvh
         xMhxrgZC0eiX2+AXaRb5TmvESIt8xaBsyQARol9+VxgIN8Sy9gvwKPopS7BVLtBThbrC
         0ksRn5DmQ3dDGFFMW0X9i15izz5mBAU09tDH62aX1GZw5z4vigzqvHcpyBICJBVgJlhY
         2kKu5mODrgrW7pbuRsqy1hQVYe7Ivzx1fMdAlgaQNDHF9StgHlKkRZ+b5295EX4jOvzt
         tKEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739811202; x=1740416002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vHpY1xFt83PWWftTreTSeJvumdmd4PMh92XrbQANj7s=;
        b=dertZe9Wqf5UWXsfpiatRw7E1S+0dIu9NEnXVon/dZoqbBF52ceefEY24CBM7Hra0U
         +TWovgoZ8PlbmIsz1tU7DBQB7WnY+o8ggg2yeATl9tvRYbIT123g3oIAYkF7e92BmqhF
         X/6wfdrEU2WxtzdHOP7ETQAKs2JDwKKgamayI6aSB4KNgp7EGkY0pI4pEOWN6FQQ0wSO
         2EObri5x6mYXJE+A6x5bwxo+PJhArQthxu/w0ZiRyytA1eDsdYA4hsqLp9gGcQcTxsXn
         ajFGyQkC9xhM6Fdq2mzUk4hRTuRJ0KehEOXgZyjvv2Eup2csssFiKzZ2xfA82t5sr+Jl
         57tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW5PPdrUzQinz3KFltXksORdpwYBdfEsXDzu3tvKqYQFK0MmjfuNhl4Vge/oI6rM4TQ4xmn8Q==@lfdr.de
X-Gm-Message-State: AOJu0YyPvCTe8TR1ImIEh7uxORt7CgyHDXMfYiYPJizFQfY7yPhzN0M5
	ceJ8MbyZP9D1I4Ye8qaNtSKbKgcjQPQLfoQJbghEEmpXmniNUym7
X-Google-Smtp-Source: AGHT+IHvLvZPlTrw8DX5FiXQpqyttiNgcaxOCDwtB+TzUTKnlUMbuSmorFCJvCZqg1LiMfmuB9BJTg==
X-Received: by 2002:a19:2d11:0:b0:546:27f0:21a7 with SMTP id 2adb3069b0e04-54627f02773mr569186e87.49.1739811200894;
        Mon, 17 Feb 2025 08:53:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHF7rWYjSTbeRTCnZRObOwRMigE+4I9z5jV0DPMtt0s0A==
Received: by 2002:a05:6512:b12:b0:546:2202:f742 with SMTP id
 2adb3069b0e04-5462202f9f0ls192271e87.0.-pod-prod-02-eu; Mon, 17 Feb 2025
 08:53:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWqNbXNrvPNeduSfLz0xxcq0R6ccWdnzzGzW2C1WCmvJyYqJRjEirZPMgdEUvvObPqCEXcmXUcW6dA=@googlegroups.com
X-Received: by 2002:a05:6512:b27:b0:545:6b4:68c2 with SMTP id 2adb3069b0e04-5452fe8f93emr2946896e87.47.1739811198410;
        Mon, 17 Feb 2025 08:53:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739811198; cv=none;
        d=google.com; s=arc-20240605;
        b=YA2go2e7xaPCPjyfdCEtuXLg9msSkcZn+FmvV/x91PaBozZlvcS2IVyYy96kJeXp0+
         RZg42Fy/KSbZC8cBbzHNqeDnr7uICD3tOGJltSgSjapMngDYVau8aXOMfVGRzgyb7jPh
         y2J2upiZuq3R8mcy4wJ5hUaQWyTndK/5YX42oKcn+EQdm2WNn0WANGt9yKu+UAyeECFD
         zRGHCI5iEbRSUz/T890GTFKKcnJuFi1jQtP2/EjezKQJ6AoXMNqYBT9yBS3/oNjs+dsc
         9CSjoLIVtU2TgpWXJCc/KsAbjJFQADrCJVwy0/37hTlvNO/KLFfzWuxfbDkbk5ic2SHc
         j91w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=yvdJf21GoegasY6n8lXzZm394g3OkhBN6ZsY04z9+Pw=;
        fh=WEDCJY/E+1edxEpBf0m1jZYEk5Dj/XLLCwldQaofZno=;
        b=CCa4SyCdfrVVPe/lyLJPc1eTAfFeALuMdjr+n8fKv4tpmK6a4f+GYjrAHQrCEBkPmt
         yHF11O8O6NHRGEe9nhwYprn6JM5+EuwwY5z4XxjjYkwGoMwLmVRpRhPNRkSI3efY9nAk
         vOrVlDok4i53C8onUaLPKFxqN2rahtNjoVy4OeZdr8E9rgZR/Mvku75rkuQ+uNmyTiKo
         mtTEG4HesqHGO/EWl3mQevrw2qrVybd4yIqsdSj+vhjWCda0Qs97pxQhuKPY/8vzdpIf
         SsHh8X9D8bf9yEnfcz74HnPlliM+dhE4qy6w0AoELa3XYaqL+x8hMpB5pMAuEDFl7yma
         oZaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bysoTY36;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30924cb0b76si1427431fa.7.2025.02.17.08.53.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Feb 2025 08:53:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-38f325ddbc2so1974209f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Feb 2025 08:53:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV6BSC+Qm/ZOXuHh6Vdj6mlNBn6wMJJ6XTJ/9JMNgMiEVRCflJcr7YEPavOg/jhAOpQtx0wA2reCZw=@googlegroups.com
X-Gm-Gg: ASbGncvJCDx03g+rg4wyG4YC+MShgxtPmFO3RrCJalpVjAPxveoXqTlOBbil67MxsfS
	MVviGzx+oHUsUU974/xq5Mw1qiWrdVbKWsvX1NlCFlXDRO8R9FEfLb50Ipd7z200WTp7s8pzJjG
	I=
X-Received: by 2002:a05:6000:1a88:b0:38f:3471:71c8 with SMTP id
 ffacd0b85a97d-38f34717a8cmr10059788f8f.3.1739811197535; Mon, 17 Feb 2025
 08:53:17 -0800 (PST)
MIME-Version: 1.0
References: <20250213200228.1993588-1-longman@redhat.com> <20250213200228.1993588-4-longman@redhat.com>
In-Reply-To: <20250213200228.1993588-4-longman@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 17 Feb 2025 17:53:06 +0100
X-Gm-Features: AWEUYZmYEqdFvZotG9KZbJIqLDLclnjk8BpXBPWYIm83Fr2d3AreoXDFZwNNHf4
Message-ID: <CA+fCnZfaCGhZiHPm1wRMLv7oPsvZ-_dvR33mgYEtLY_ss+g4DQ@mail.gmail.com>
Subject: Re: [PATCH v4 3/4] locking/lockdep: Disable KASAN instrumentation of lockdep.c
To: Waiman Long <longman@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will.deacon@arm.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bysoTY36;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Feb 13, 2025 at 9:02=E2=80=AFPM Waiman Long <longman@redhat.com> wr=
ote:
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
>   [CONFIG_KASAN_INLINE=3Dy]
>   Debug kernel                  2m11.108s (x2.8)     38m20.467s (x8.9)
>   Debug kernel (patched)        1m49.602s (x2.3)     31m28.501s (x7.3)
>   Debug kernel
>   (patched + mitigations=3Doff)   1m30.988s (x1.9)     26m41.993s (x6.2)
>
>   RT kernel (baseline)          0m54.871s             7m15.340s
>
>   [CONFIG_KASAN_INLINE=3Dn]
>   RT debug kernel               6m07.151s (x6.7)    135m47.428s (x18.7)
>   RT debug kernel (patched)     3m42.434s (x4.1)     74m51.636s (x10.3)
>   RT debug kernel
>   (patched + mitigations=3Doff)   2m40.383s (x2.9)     57m54.369s (x8.0)
>
>   [CONFIG_KASAN_INLINE=3Dy]
>   RT debug kernel               3m22.155s (x3.7)     77m53.018s (x10.7)
>   RT debug kernel (patched)     2m36.700s (x2.9)     54m31.195s (x7.5)
>   RT debug kernel
>   (patched + mitigations=3Doff)   2m06.110s (x2.3)     45m49.493s (x6.3)
>
> For the Zen 2 system:
>
>   Kernel                        Run time            Sys time
>   ------                        --------            --------
>   Non-debug kernel (baseline)   1m42.806s            39m48.714s
>
>   [CONFIG_KASAN_INLINE=3Dy]
>   Debug kernel                  4m04.524s (x2.4)    125m35.904s (x3.2)
>   Debug kernel (patched)        3m56.241s (x2.3)    127m22.378s (x3.2)
>   Debug kernel
>   (patched + mitigations=3Doff)   2m38.157s (x1.5)     92m35.680s (x2.3)
>
>   RT kernel (baseline)           1m51.500s           14m56.322s
>
>   [CONFIG_KASAN_INLINE=3Dn]
>   RT debug kernel               16m04.962s (x8.7)   244m36.463s (x16.4)
>   RT debug kernel (patched)      9m09.073s (x4.9)   129m28.439s (x8.7)
>   RT debug kernel
>   (patched + mitigations=3Doff)    3m31.662s (x1.9)    51m01.391s (x3.4)
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
>   [CONFIG_KASAN_INLINE=3Dn]
>   RT debug kernel               19m32.977s (x4.9)   304m23.965s (x16.7)
>   RT debug kernel (patched)     16m28.354s (x4.1)   234m18.149s (x12.8)
>
> Turning the mitigations off doesn't seems to have any noticeable impact
> on the performance of the arm64 system. So the mitigation=3Doff entries
> aren't included.
>
> For the x86 CPUs, cpu mitigations has a much bigger
> impact on performance, especially the RT debug kernel with
> CONFIG_KASAN_INLINE=3Dn. The SRSO mitigation in Zen 2 has an especially
> big impact on the debug kernel. It is also the majority of the slowdown
> with mitigations on. It is because the patched ret instruction slows
> down function returns. A lot of helper functions that are normally
> compiled out or inlined may become real function calls in the debug
> kernel.
>
> With CONFIG_KASAN_INLINE=3Dn, the KASAN instrumentation inserts a
> lot of __asan_loadX*() and __kasan_check_read() function calls to memory
> access portion of the code. The lockdep's __lock_acquire() function,
> for instance, has 66 __asan_loadX*() and 6 __kasan_check_read() calls
> added with KASAN instrumentation. Of course, the actual numbers may vary
> depending on the compiler used and the exact version of the lockdep code.
>
> With the Skylake test system, the parallel kernel build times reduction
> of the RT debug kernel with this patch are:
>
>  CONFIG_KASAN_INLINE=3Dn: -37%
>  CONFIG_KASAN_INLINE=3Dy: -22%
>
> The time reduction is less with CONFIG_KASAN_INLINE=3Dy, but it is still
> significant.
>
> Setting CONFIG_KASAN_INLINE=3Dy can result in a significant performance
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
> ---
>  kernel/locking/Makefile | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> index 0db4093d17b8..a114949eeed5 100644
> --- a/kernel/locking/Makefile
> +++ b/kernel/locking/Makefile
> @@ -5,7 +5,8 @@ KCOV_INSTRUMENT         :=3D n
>
>  obj-y +=3D mutex.o semaphore.o rwsem.o percpu-rwsem.o
>
> -# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
> +# Avoid recursion lockdep -> sanitizer -> ... -> lockdep & improve perfo=
rmance.
> +KASAN_SANITIZE_lockdep.o :=3D n
>  KCSAN_SANITIZE_lockdep.o :=3D n
>
>  ifdef CONFIG_FUNCTION_TRACER
> --
> 2.48.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfaCGhZiHPm1wRMLv7oPsvZ-_dvR33mgYEtLY_ss%2Bg4DQ%40mail.gmail.com.
