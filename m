Return-Path: <kasan-dev+bncBCMIZB7QWENRB24X727QMGQEAPAE2GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E7560A8B72A
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 12:52:28 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-54991f28058sf2965821e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 03:52:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744800748; cv=pass;
        d=google.com; s=arc-20240605;
        b=eXlrVC+BEXEMmKzJH1QtAGH/bpKxCIrNUE9xdOsioW8/mK/7P/HgbgJOFoI/nnxuOD
         OzkgCFdK4RPbHMxgcx1aFDn7ev61lQ6GR4jrJ1EjjEoa1XjToXh6FzCq0/EaG8d/mVCo
         4/n8rRkzLS4bpulkKC4MzJF1O13TMuZ+L7BNOtn4lMzBiDrtSj8Mt7X5a0QEDt/x2d86
         NzIiIzS/87RlXFjbj7tHLh+VgYbUZwUzkceaOoKl7PWnZhi2M0/sqeXfCRwdunY09nlc
         yhkyEosYNCQhsD8v+HIATkKIeikEnLh7lRPgvRdq625ouESS8hQPSgGca1phAUybt3Yo
         B5TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JKQF14jGkzj1qlCdEO8IWZ0Y0Y3utfEOJ2d216DWUZs=;
        fh=4ObmAdemEXbjtMj8JWg5ek9Q+s2NFPn5d50EV2NyPS0=;
        b=fu51C3ZQ1F9vVwTzBdQfkhUthByBiQyfzHZbBNzd0ABH/I5Bglo5QO+A4ZrsGa6NyL
         zHEwYfW0ZfCaAkRsXRIEdSYvjzLo4JZ19wmOShFotvirlo+tJ7vLp1C+iSLw+FbBFj9B
         qsr6Mp/eeZBsYUrqrHz3dKWquTSbHk69MgFoV0gVuP8cA+RgAu3AgYsJKNp5mKN0A/jX
         jvnP2xB4AD4yP0gZMi5rEB8nsWrE5r8mnDKFT1IBUqM/DbXvlsb6DiNuRNMdxZdoEXOd
         N//tjfvaXZUpaDH3Gsp9IlW2yzXuKmiabwLFkpg5ad3aIBLY8sB2DZz7m7Xzitr0DFGz
         VQDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J9resjlU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744800748; x=1745405548; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JKQF14jGkzj1qlCdEO8IWZ0Y0Y3utfEOJ2d216DWUZs=;
        b=qg+EGbH6acqZriblNjelsEsH+7ZvmOvruT8UhQe6hESUh04DwvzfLvksbtC3IPFeUJ
         rP4o107JPVUfL1F7DSgdEZFe7l4gfPEOTH2gIfsfzit/z9cNs5ISMFRIe60cgOhY6rhC
         bHzGX2zVXtlOJkA1CRjurindRZxeETLEPx6bdVyhf/nuxqLafBw3IumgWfNglN3lPRd/
         kuDGscxSl1WzDRzQIZPL3gLhVT60glz1GuCfoVqJCajIKQN9jc9aAnY2HCp0XhELB4qe
         wrii9AfFQlNrk+PfMbL/rowB65JnmZBaoMQJhTewONT0O0zdrQIft64xaeHLgBflDdrZ
         mP0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744800748; x=1745405548;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JKQF14jGkzj1qlCdEO8IWZ0Y0Y3utfEOJ2d216DWUZs=;
        b=I3U2iCMLXFLS03xdRtCDKcZA+cnEYxqFKOIXuY6AyFgXP+vbHRlY5Q28trJMfl2nlu
         NILcqcpSGzqtzdRQQdwLf+DvRLX/g/d7FJhsHkkKLFv/LbxSf69+Qqu0PiLawZrboiHW
         9EWMfJPM88VbtwwFN3t9HtVjANqk7liiOqoKC5cfzgaFaExMgbMLMkAvoWCiZwMUe3NM
         Qqt5Agi814EnAm64vbwyaqy8BqpAJ640WHY3qRoKoCE04ex8f0gcVawl9z0y0M0/NdWz
         JzWjmAWGRkTMyxKOdwmKoQ5xrC7stDVyhuyNn6fvc07BUp7kPQBUu3U8XjbqQEuqjsNN
         dZfA==
X-Forwarded-Encrypted: i=2; AJvYcCUeyoP88AihO4yecheVYkZLcBCuNd3xZ414fvBFYCcDjpMJxKb6Qt1UxS7k7ySR8E3NywmhpQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx08xvjt0oU9k2wj6jL4P2XL6S20f+xqxPZimvXhqehQBtq/laj
	vrHsgTYWVwhnyApuP+0trbzZm0Su0pe9dIAH3HRkn5vQwqNOuURw
X-Google-Smtp-Source: AGHT+IGIIxfUjQZPse9kz2W97pJqb5EvTjoub2VfJEnYm9YA5EoqXzxhaZxPJrMGdJ+4hBW+iaNBUQ==
X-Received: by 2002:a05:6512:2247:b0:549:916b:e665 with SMTP id 2adb3069b0e04-54d64a92272mr436794e87.1.1744800747723;
        Wed, 16 Apr 2025 03:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAI1cEH4+L2tZuvhDqitHuovRqCIg8r4WCpn6xZTz0g6kQ==
Received: by 2002:a05:6512:3f02:b0:549:947f:24bf with SMTP id
 2adb3069b0e04-54c56d3694cls452228e87.1.-pod-prod-03-eu; Wed, 16 Apr 2025
 03:52:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXHQkJRsnV/WUuqAhFyvU4e5kEDketCRdGcp73NgCtXyewYurZOR8x/ygJTHZ/Ht/S2qSNA9LUgK+Q=@googlegroups.com
X-Received: by 2002:a05:6512:b1c:b0:549:8e5e:9d8e with SMTP id 2adb3069b0e04-54d647a87a7mr442463e87.0.1744800744746;
        Wed, 16 Apr 2025 03:52:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744800744; cv=none;
        d=google.com; s=arc-20240605;
        b=hPp//UUGGgUtR09Weyd6E41gQdaODFRpY7xrKIyu1ZB1cdURY+N15m2wwgAVk/LuIa
         T677Jqv9Sqxk4bWSy6qmjx2s8lX6X+9TvRJNRuTAV/o0oVMmbiLOboNuJ2Heq3db7XTm
         gbRb4AWCWL4dCzOa9LJkxORc30EgHtzoX8pn17bEwa5oPEiC/bge9TTuMHZCYQd4T9EP
         CD+v7kogA8fJy/frGjT0Lihu04xgMfE6+L2/AU+VfaFO/wqcoTyx23IR97PsuFExsG1m
         /Pvb4nyH23m/AH7GM+FqwMSMP9YxNcMXnqIJD8kTZKEd36065MeBOmUCTuWPZe8o7wmU
         Qa1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ezteQ2riofZ7Hrj5BXFbLyhRNWueJY/Se/hzX4W8NVQ=;
        fh=CQhf1C6kY3Tv4sh9lAK8uPdm3xpIcgMvDzjWm4hitk4=;
        b=M1sBUOte4rZE/evyi/4S00/QsdMz3prn1Pm1NDYCJKdafVsRUm8eW+XyO4e52+S72i
         7GMe9fRnjNrZVigoBQAKjMAejCQXXzMmGbIjjVKyZuxZryoMMEyBSUnkqAJoDD8itVIc
         k7Uis89jvmdPiYcQ/KpgH69BiSgQ8cHEYJiaUYIp0hwfSR8CT9+Wl5rFpFqjEHDxDDF4
         wgiK41wxPtG+zAJ4ouU5MTtrhMptHhsO8rFtuo4b4m5dG9/doJFz49AvGDPRQXiw36gy
         WE8EU88PHe2OUcz3ZckPJd8chPkuwKo1OasJw8qvbJlLlbFoKLAjsP3Ptgykb5qE5M45
         whPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J9resjlU;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-310815c534csi64131fa.7.2025.04.16.03.52.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 03:52:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 38308e7fff4ca-30c091b54aaso59247701fa.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 03:52:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVn205qg5xdbwDg540xK/1+HcLXSFDehSYZks2XmbT84NMPQV1Q0hRinSXWa3rK4XdYF8N1cG2R3wE=@googlegroups.com
X-Gm-Gg: ASbGncsCIvsYihiJ3F0hdjjQL8oDFgLQceubsgRa6t6IVqLxzHT/6sXiRUQlaUbMF6W
	iflXfj5jXifXFUHZZfKTFhCdoV5gNbclkR4W+WiWhLsg2Z4NaZzb71NR/7blOFMdGzQNLcGtWr2
	kX4TeBGRNyujkOHAtq81k4oDfHCwTNz4J5oB3HkBcWOPQ4y7AthpxJBKc=
X-Received: by 2002:a05:651c:1988:b0:30c:7a7:e87c with SMTP id
 38308e7fff4ca-3107f73cfdfmr3673361fa.35.1744800744089; Wed, 16 Apr 2025
 03:52:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
In-Reply-To: <20250416085446.480069-1-glider@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Apr 2025 12:52:12 +0200
X-Gm-Features: ATxdqUHO84ZMKC02-TwodTZhg_pM7vWiRGycrQw7cTn0S02O05yX6np4vLAohn8
Message-ID: <CACT4Y+b06RBSgcxooStVLoUVZRR=_L3Pxo6Ozp45s8brw1Ybfg@mail.gmail.com>
Subject: Re: [PATCH 0/7] RFC: coverage deduplication for KCOV
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
 header.i=@google.com header.s=20230601 header.b=J9resjlU;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::229
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

On Wed, 16 Apr 2025 at 10:54, Alexander Potapenko <glider@google.com> wrote:
>
> As mentioned by Joey Jiao in [1], the current kcov implementation may
> suffer from certain syscalls overflowing the userspace coverage buffer.
>
> According to our measurements, among 24 syzkaller instances running
> upstream Linux, 5 had a coverage overflow in at least 50% of executed
> programs. The median percentage of programs with overflows across those 24
> instances was 8.8%.
>
> One way to mitigate this problem is to increase the size of the kcov buffer
> in the userspace application using kcov. But right now syzkaller already
> uses 4Mb per each of up to 32 threads to store the coverage, and increasing
> it further would result in reduction in the number of executors on a single
> machine.  Replaying the same program with an increased buffer size in the
> case of overflow would also lead to fewer executions being possible.
>
> When executing a single system call, excessive coverage usually stems from
> loops, which write the same PCs into the output buffer repeatedly. Although
> collecting precise traces may give us some insights into e.g. the number of
> loop iterations and the branches being taken, the fuzzing engine does not
> take advantage of these signals, and recording only unique PCs should be
> just as practical.
>
> In [1] Joey Jiao suggested using a hash table to deduplicate the coverage
> signal on the kernel side. While being universally applicable to all types
> of data collected by kcov, this approach adds another layer of complexity,
> requiring dynamically growing the map. Another problem is potential hash
> collisions, which can as well lead to lost coverage. Hash maps are also
> unavoidably sparse, which potentially requires more memory.

The hashmap probably can compare values for equality to avoid losing
coverage, but the real problem is that it allocates and can't work in
interrupts, etc.

> The approach proposed in this patch series is to assign a unique (and
> almost) sequential ID to each of the coverage callbacks in the kernel. Then
> we carve out a fixed-sized bitmap from the userspace trace buffer, and on
> every callback invocation we:
>
> - obtain the callback_ID;
> - if bitmap[callback_ID] is set, append the PC to the trace buffer;
> - set bitmap[callback_ID] to true.
>
> LLVM's -fsanitize-coverage=trace-pc-guard replaces every coverage callback
> in the kernel with a call to
> __sanitizer_cov_trace_pc_guard(&guard_variable) , where guard_variable is a
> 4-byte global that is unique for the callsite.
>
> This allows us to lazily allocate sequential numbers just for the callbacks
> that have actually been executed, using a lock-free algorithm.
>
> This patch series implements a new config, CONFIG_KCOV_ENABLE_GUARDS, which
> utilizes the mentioned LLVM flag for coverage instrumentation. In addition
> to the existing coverage collection modes, it introduces
> ioctl(KCOV_UNIQUE_ENABLE), which splits the existing kcov buffer into the
> bitmap and the trace part for a particular fuzzing session, and collects
> only unique coverage in the trace buffer.
>
> To reset the coverage between runs, it is now necessary to set trace[0] to
> 0 AND clear the entire bitmap. This is still considered feasible, based on
> the experimental results below.
>
> The current design does not address the deduplication of KCOV_TRACE_CMP
> comparisons; however, the number of kcov overflows during the hints
> collection process is insignificant compared to the overflows of
> KCOV_TRACE_PC.
>
> In addition to the mentioned changes, this patch adds support for
> R_X86_64_REX_GOTPCRELX to objtool and arch/x86/kernel/module.c.  It turned
> out that Clang leaves such relocations in the linked modules for the
> __start___sancov_guards and __stop___sancov_guards symbols. Because
> resolving them does not require a .got section, it can be done at module
> load time.
>
> Experimental results.
>
> We've conducted an experiment running syz-testbed [3] on 10 syzkaller
> instances for 24 hours.  Out of those 10 instances, 5 were enabling the
> kcov_deduplicate flag from [4], which makes use of the KCOV_UNIQUE_ENABLE
> ioctl, reserving 4096 words (262144 bits) for the bitmap and leaving 520192
> words for the trace collection.
>
> Below are the average stats from the runs.
>
> kcov_deduplicate=false:
>   corpus: 52176
>   coverage: 302658
>   cover overflows: 225288
>   comps overflows: 491
>   exec total: 1417829
>   max signal: 318894
>
> kcov_deduplicate=true:
>   corpus: 52581
>   coverage: 304344
>   cover overflows: 986
>   comps overflows: 626
>   exec total: 1484841
>   max signal: 322455
>
> [1] https://lore.kernel.org/linux-arm-kernel/20250114-kcov-v1-5-004294b931a2@quicinc.com/T/
> [2] https://clang.llvm.org/docs/SanitizerCoverage.html
> [3] https://github.com/google/syzkaller/tree/master/tools/syz-testbed
> [4] https://github.com/ramosian-glider/linux/pull/7
>
>
> Alexander Potapenko (7):
>   kcov: apply clang-format to kcov code
>   kcov: factor out struct kcov_state
>   kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
>   kcov: add `trace` and `trace_size` to `struct kcov_state`
>   kcov: add ioctl(KCOV_UNIQUE_ENABLE)
>   x86: objtool: add support for R_X86_64_REX_GOTPCRELX
>   mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
>
>  Documentation/dev-tools/kcov.rst  |  43 +++
>  MAINTAINERS                       |   1 +
>  arch/x86/include/asm/elf.h        |   1 +
>  arch/x86/kernel/module.c          |   8 +
>  arch/x86/kernel/vmlinux.lds.S     |   1 +
>  arch/x86/um/asm/elf.h             |   1 +
>  include/asm-generic/vmlinux.lds.h |  14 +-
>  include/linux/kcov-state.h        |  46 +++
>  include/linux/kcov.h              |  60 ++--
>  include/linux/sched.h             |  16 +-
>  include/uapi/linux/kcov.h         |   1 +
>  kernel/kcov.c                     | 453 +++++++++++++++++++-----------
>  lib/Kconfig.debug                 |  16 ++
>  mm/kasan/generic.c                |  18 ++
>  mm/kasan/kasan.h                  |   2 +
>  scripts/Makefile.kcov             |   4 +
>  scripts/module.lds.S              |  23 ++
>  tools/objtool/arch/x86/decode.c   |   1 +
>  tools/objtool/check.c             |   1 +
>  19 files changed, 508 insertions(+), 202 deletions(-)
>  create mode 100644 include/linux/kcov-state.h
>
> --
> 2.49.0.604.gff1f9ca942-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb06RBSgcxooStVLoUVZRR%3D_L3Pxo6Ozp45s8brw1Ybfg%40mail.gmail.com.
