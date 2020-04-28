Return-Path: <kasan-dev+bncBCMIZB7QWENRBTUEUH2QKGQECUR2FCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id D50E61BC1AB
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Apr 2020 16:48:47 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id r5sf2666427pji.9
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Apr 2020 07:48:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588085326; cv=pass;
        d=google.com; s=arc-20160816;
        b=zv5nSs7p7ZbMI8ieDr3HOxRpXdWSV1WFy9QdKhReZfMA03WUbUJTdEv2MzXs3Cqj7i
         tSRwk79AR1jdOS/FuTnOnWQiYr6kBUpcu4ySMnX4yS6Oxu8AnfelrqrZ3QrFcJAylrII
         c7Aqa9piBzW/xsgUL1pkIZrh5cjPzNW0BzKB446N64lVVplQH4bAoknYqGW6QiltFYQW
         eEsOeYVUgE8ZDsR4+lt3J32VrDZAN305nJqLFbagA3t6sQ1mMgKGVWSJT89VMOb50tBr
         4v47isGbpXL7q6xAkHHv9yGMq4tV/fN9R80Gb0Orm3TIOfFbTsQXXG7JwSVOcKA7dw2Q
         TAcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x7G6yTctXOgMtwEQULLUQSSH0zvWTZBqsb9ZnqSvT7c=;
        b=vfirHr0Y11t6F9nkEEPmBV3MB110UGhsFPTSeYhYhEW+Oy1ADaHPhRCWix9I9GZu34
         ty2HGQeSOklNESvdkyIRANu8uDk5lDsJJtx/gLit7J6uzUY27gjNhBRpQ0FO8THhWblL
         1DvjuUObJeoe3PELMv4PuLFLeQUvj1sLDf3zwC3Wzwg0ySlwZ+2EYoW1+MQvC6ilAjql
         AnDk6388fBCz+Tl4N+izLXlH60jniCuvduFsCJGQv7fWS+F46NkgAIFMekUiu3ZpRygp
         5U3TaixOR0R5aGPcCMQj784zd24VwZDsD0F+M24Q9+EeYvUQAtt2dkm5K023Vz97zGNW
         5VtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wSmxZPFT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x7G6yTctXOgMtwEQULLUQSSH0zvWTZBqsb9ZnqSvT7c=;
        b=GSS5v3BiEKWnlK+tBUyJ9F/O24mqMOGOMpB3hxVDM8AsKpvmVDHXgOPoeuO40ced4B
         +Y6ZzD9swmaD/nQui1O4AQnfnFbLnkjzvPaxNhbEI4v9LOf+dhApeeo2Uf/P65DV0oej
         BziqoKoRQx+xxcBPicw+TT4g+So7HNlHOHclNU3yxw2KXVAxGNC1clIRDcAcmmUnYua8
         4GA0Sb0gcv9PfUNkwyy4cURWhp3heKJCsRvyOn11yUnWlKBsUmOs39XFrLlkt6wkXQ+G
         WqT+MUKjpD8e4DcqAWimZBGE/2apppMk8ko1jvug6H7OBjJkyB6T0NMmm7iajb3TVtBT
         46OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x7G6yTctXOgMtwEQULLUQSSH0zvWTZBqsb9ZnqSvT7c=;
        b=W1iszaDI4II3QaWwoIMoXR+9/yel19Gl4V+Hg09cmumBQQvT1fVh05JrLzKBwZ/u75
         fzXIjmIATGF2TJVYOwJmZxUOREhht608OuAL1aLiK27G+4+Z+RVrbxkToPgPPeC1KDUO
         ncGWy6UOtwsi+WiiKg1+twk0b3XiJDG8zeD7MeCKl2iMWuGt60qBwb8KuO+EDDaM1j2X
         mlAE8SDjSRRmPwEKKM8eGXRWBqA0Qsil2eYDNNHOLxfYaHTEM6gAivByFswcvxIn/WPt
         e9cf0zpOyDqNkcbOuHZbClTvm+t68xQX2pNnqtu04HKHPRcdqL+9ZiImB+HuQUvwMd45
         80SQ==
X-Gm-Message-State: AGi0PuYYC6J221ETQSqbMtZs7YcS28aE21XuGQ9DW8P6CUtHmILHns3G
	uPzjp3VUqbfu57cj4zk7rRs=
X-Google-Smtp-Source: APiQypKpP1YAMceGg1u3uaV1VEpEfpBEm3Hf2yiLDIR08MR0HSkpXDvlH5W2Aze3DlzVBU7593wD6Q==
X-Received: by 2002:a63:b11:: with SMTP id 17mr11373649pgl.3.1588085326141;
        Tue, 28 Apr 2020 07:48:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:c31a:: with SMTP id v26ls18569123pfg.2.gmail; Tue, 28
 Apr 2020 07:48:45 -0700 (PDT)
X-Received: by 2002:a65:58c4:: with SMTP id e4mr29539610pgu.61.1588085325546;
        Tue, 28 Apr 2020 07:48:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588085325; cv=none;
        d=google.com; s=arc-20160816;
        b=rzwceHZ6B0xntNbDPZhFPa2xq4AoTIoQFO3yEyAT3rJeg+qVmqZ4mjhtXocbhESvXa
         5cvROifguv9V9/xuCUT3ZsHMPLuH5oWlgYCi06+sufZBpb7IHV3yJWw+sxLDzLi2Vuhp
         vFMlakwRfsEeD8LT1fZvvPwMeYvKD6pbXvQjLJWy8jENNM1qs5qe6OOgyAvhlWQfLbVU
         qi/aPI9Hh2ZLTb2PpNuv+b244PnHViNpUijRTTPjQXKtZkVDtV/3EdB4nTctYP5MLo7Y
         /Z20MHDNO71MCy+ldKEpvCr5wJI8B+yRqQMeKWOjqW2IZVfo3HlJXV0LWjMhLYxZPii+
         2r9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q/euA+pdLT/4vQLOCz8RuKATKabfepVnoAsuSjojGlw=;
        b=TfAliU/Kn7b3dhc30WtlFa/MU8Lr3MlHjddqTzCD2JkHDS4vsfr7nuMuQjOFocMWtk
         JMTG7gdiuVyZrsvoRcPaSxms9JvfDUJ9tGTkJZMHNeNZJgZ4j5/iGbEeeA+8l5/6lRsU
         YlWxUP1bZQp+JhpuJZ6zg1v9qvv7U227aXb/9xjeTuAdUs1IOA9RUo81WnFQ+0Pkddku
         /AHyNqbHxvTdpYysrQS9hYuKdzW9WXldKnxCtVQVKg+zf/PfoZD76r1TXRdr3J4PZ0Eh
         w6rljP12FaFmaj5tqj0DZAmTl9Z17JgxcKkK/tyPb1j6DSqi59W109xwiM/5M0YITi/O
         fJQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wSmxZPFT;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id x5si116621pjo.0.2020.04.28.07.48.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Apr 2020 07:48:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id x12so16926414qts.9
        for <kasan-dev@googlegroups.com>; Tue, 28 Apr 2020 07:48:45 -0700 (PDT)
X-Received: by 2002:ac8:5209:: with SMTP id r9mr27491102qtn.57.1588085324010;
 Tue, 28 Apr 2020 07:48:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200423154250.10973-1-elver@google.com>
In-Reply-To: <20200423154250.10973-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Apr 2020 16:48:31 +0200
Message-ID: <CACT4Y+arbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA@mail.gmail.com>
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: Marco Elver <elver@google.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>, Jakub Jelinek <jakub@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wSmxZPFT;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Thu, Apr 23, 2020 at 5:43 PM Marco Elver <elver@google.com> wrote:
>
> Add support to optionally emit different instrumentation for accesses to
> volatile variables. While the default TSAN runtime likely will never
> require this feature, other runtimes for different environments that
> have subtly different memory models or assumptions may require
> distinguishing volatiles.
>
> One such environment are OS kernels, where volatile is still used in
> various places for various reasons, and often declare volatile to be
> "safe enough" even in multi-threaded contexts. One such example is the
> Linux kernel, which implements various synchronization primitives using
> volatile (READ_ONCE(), WRITE_ONCE()). Here the Kernel Concurrency
> Sanitizer (KCSAN) [1], is a runtime that uses TSAN instrumentation but
> otherwise implements a very different approach to race detection from
> TSAN.
>
> While in the Linux kernel it is generally discouraged to use volatiles
> explicitly, the topic will likely come up again, and we will eventually
> need to distinguish volatile accesses [2]. The other use-case is
> ignoring data races on specially marked variables in the kernel, for
> example bit-flags (here we may hide 'volatile' behind a different name
> such as 'no_data_race').
>
> [1] https://github.com/google/ktsan/wiki/KCSAN
> [2] https://lkml.kernel.org/r/CANpmjNOfXNE-Zh3MNP=-gmnhvKbsfUfTtWkyg_=VqTxS4nnptQ@mail.gmail.com


Hi Jakub,

FWIW this is:

Acked-by: Dmitry Vyukov <dvuykov@google.com>

We just landed a similar change to llvm:
https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814

Do you have any objections?
Yes, I know volatile is not related to threading :) But 5 years we
have a similar patch for gcc for another race detector prototype:
https://gist.github.com/xairy/862ba3260348efe23a37decb93aa79e9
So this is not the first time this comes up.

Thanks




> 2020-04-23  Marco Elver  <elver@google.com>
>
> gcc/
>         * params.opt: Define --param=tsan-distinguish-volatile=[0,1].
>         * sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
>         builtin for volatile instrumentation of reads/writes.
>         (BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
>         (BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
>         (BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
>         (BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
>         (BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
>         (BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
>         (BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
>         (BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
>         (BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
>         * tsan.c (get_memory_access_decl): Argument if access is
>         volatile. If param tsan-distinguish-volatile is non-zero, and
>         access if volatile, return volatile instrumentation decl.
>         (instrument_expr): Check if access is volatile.
>
> gcc/testsuite/
>         * c-c++-common/tsan/volatile.c: New test.
> ---
>  gcc/ChangeLog                              | 19 +++++++
>  gcc/params.opt                             |  4 ++
>  gcc/sanitizer.def                          | 21 ++++++++
>  gcc/testsuite/ChangeLog                    |  4 ++
>  gcc/testsuite/c-c++-common/tsan/volatile.c | 62 ++++++++++++++++++++++
>  gcc/tsan.c                                 | 53 ++++++++++++------
>  6 files changed, 146 insertions(+), 17 deletions(-)
>  create mode 100644 gcc/testsuite/c-c++-common/tsan/volatile.c
>
> diff --git a/gcc/ChangeLog b/gcc/ChangeLog
> index 5f299e463db..aa2bb98ae05 100644
> --- a/gcc/ChangeLog
> +++ b/gcc/ChangeLog
> @@ -1,3 +1,22 @@
> +2020-04-23  Marco Elver  <elver@google.com>
> +
> +       * params.opt: Define --param=tsan-distinguish-volatile=[0,1].
> +       * sanitizer.def (BUILT_IN_TSAN_VOLATILE_READ1): Define new
> +       builtin for volatile instrumentation of reads/writes.
> +       (BUILT_IN_TSAN_VOLATILE_READ2): Likewise.
> +       (BUILT_IN_TSAN_VOLATILE_READ4): Likewise.
> +       (BUILT_IN_TSAN_VOLATILE_READ8): Likewise.
> +       (BUILT_IN_TSAN_VOLATILE_READ16): Likewise.
> +       (BUILT_IN_TSAN_VOLATILE_WRITE1): Likewise.
> +       (BUILT_IN_TSAN_VOLATILE_WRITE2): Likewise.
> +       (BUILT_IN_TSAN_VOLATILE_WRITE4): Likewise.
> +       (BUILT_IN_TSAN_VOLATILE_WRITE8): Likewise.
> +       (BUILT_IN_TSAN_VOLATILE_WRITE16): Likewise.
> +       * tsan.c (get_memory_access_decl): Argument if access is
> +       volatile. If param tsan-distinguish-volatile is non-zero, and
> +       access if volatile, return volatile instrumentation decl.
> +       (instrument_expr): Check if access is volatile.
> +
>  2020-04-23  Srinath Parvathaneni  <srinath.parvathaneni@arm.com>
>
>         * config/arm/arm_mve.h (__arm_vbicq_n_u16): Modify function parameter's
> diff --git a/gcc/params.opt b/gcc/params.opt
> index 4aec480798b..9b564bb046c 100644
> --- a/gcc/params.opt
> +++ b/gcc/params.opt
> @@ -908,6 +908,10 @@ Stop reverse growth if the reverse probability of best edge is less than this th
>  Common Joined UInteger Var(param_tree_reassoc_width) Param Optimization
>  Set the maximum number of instructions executed in parallel in reassociated tree.  If 0, use the target dependent heuristic.
>
> +-param=tsan-distinguish-volatile=
> +Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRange(0, 1) Param
> +Emit special instrumentation for accesses to volatiles.
> +
>  -param=uninit-control-dep-attempts=
>  Common Joined UInteger Var(param_uninit_control_dep_attempts) Init(1000) IntegerRange(1, 65536) Param Optimization
>  Maximum number of nested calls to search for control dependencies during uninitialized variable analysis.
> diff --git a/gcc/sanitizer.def b/gcc/sanitizer.def
> index 11eb6467eba..a32715ddb92 100644
> --- a/gcc/sanitizer.def
> +++ b/gcc/sanitizer.def
> @@ -214,6 +214,27 @@ DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_READ_RANGE, "__tsan_read_range",
>  DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_WRITE_RANGE, "__tsan_write_range",
>                       BT_FN_VOID_PTR_PTRMODE, ATTR_NOTHROW_LEAF_LIST)
>
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ1, "__tsan_volatile_read1",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ2, "__tsan_volatile_read2",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ4, "__tsan_volatile_read4",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ8, "__tsan_volatile_read8",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ16, "__tsan_volatile_read16",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE1, "__tsan_volatile_write1",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE2, "__tsan_volatile_write2",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE4, "__tsan_volatile_write4",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE8, "__tsan_volatile_write8",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile_write16",
> +                     BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
> +
>  DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_ATOMIC8_LOAD,
>                       "__tsan_atomic8_load",
>                       BT_FN_I1_CONST_VPTR_INT, ATTR_NOTHROW_LEAF_LIST)
> diff --git a/gcc/testsuite/ChangeLog b/gcc/testsuite/ChangeLog
> index 245c1512c76..f1d3e236b86 100644
> --- a/gcc/testsuite/ChangeLog
> +++ b/gcc/testsuite/ChangeLog
> @@ -1,3 +1,7 @@
> +2020-04-23  Marco Elver  <elver@google.com>
> +
> +       * c-c++-common/tsan/volatile.c: New test.
> +
>  2020-04-23  Jakub Jelinek  <jakub@redhat.com>
>
>         PR target/94707
> diff --git a/gcc/testsuite/c-c++-common/tsan/volatile.c b/gcc/testsuite/c-c++-common/tsan/volatile.c
> new file mode 100644
> index 00000000000..d51d1e3ce8d
> --- /dev/null
> +++ b/gcc/testsuite/c-c++-common/tsan/volatile.c
> @@ -0,0 +1,62 @@
> +/* { dg-additional-options "--param=tsan-distinguish-volatile=1" } */
> +
> +#include <assert.h>
> +#include <stdint.h>
> +#include <stdio.h>
> +
> +int32_t Global4;
> +volatile int32_t VolatileGlobal4;
> +volatile int64_t VolatileGlobal8;
> +
> +static int nvolatile_reads;
> +static int nvolatile_writes;
> +
> +#ifdef __cplusplus
> +extern "C" {
> +#endif
> +
> +__attribute__((no_sanitize_thread))
> +void __tsan_volatile_read4(void *addr) {
> +  assert(addr == &VolatileGlobal4);
> +  nvolatile_reads++;
> +}
> +__attribute__((no_sanitize_thread))
> +void __tsan_volatile_write4(void *addr) {
> +  assert(addr == &VolatileGlobal4);
> +  nvolatile_writes++;
> +}
> +__attribute__((no_sanitize_thread))
> +void __tsan_volatile_read8(void *addr) {
> +  assert(addr == &VolatileGlobal8);
> +  nvolatile_reads++;
> +}
> +__attribute__((no_sanitize_thread))
> +void __tsan_volatile_write8(void *addr) {
> +  assert(addr == &VolatileGlobal8);
> +  nvolatile_writes++;
> +}
> +
> +#ifdef __cplusplus
> +}
> +#endif
> +
> +__attribute__((no_sanitize_thread))
> +static void check() {
> +  assert(nvolatile_reads == 4);
> +  assert(nvolatile_writes == 4);
> +}
> +
> +int main() {
> +  Global4 = 1;
> +
> +  VolatileGlobal4 = 1;
> +  Global4 = VolatileGlobal4;
> +  VolatileGlobal4 = 1 + VolatileGlobal4;
> +
> +  VolatileGlobal8 = 1;
> +  Global4 = (int32_t)VolatileGlobal8;
> +  VolatileGlobal8 = 1 + VolatileGlobal8;
> +
> +  check();
> +  return 0;
> +}
> diff --git a/gcc/tsan.c b/gcc/tsan.c
> index 8d22a776377..04e92559584 100644
> --- a/gcc/tsan.c
> +++ b/gcc/tsan.c
> @@ -52,25 +52,41 @@ along with GCC; see the file COPYING3.  If not see
>     void __tsan_read/writeX (void *addr);  */
>
>  static tree
> -get_memory_access_decl (bool is_write, unsigned size)
> +get_memory_access_decl (bool is_write, unsigned size, bool volatilep)
>  {
>    enum built_in_function fcode;
>
> -  if (size <= 1)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE1
> -                    : BUILT_IN_TSAN_READ1;
> -  else if (size <= 3)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE2
> -                    : BUILT_IN_TSAN_READ2;
> -  else if (size <= 7)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE4
> -                    : BUILT_IN_TSAN_READ4;
> -  else if (size <= 15)
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE8
> -                    : BUILT_IN_TSAN_READ8;
> +  if (param_tsan_distinguish_volatile && volatilep)
> +    {
> +      if (size <= 1)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE1
> +            : BUILT_IN_TSAN_VOLATILE_READ1;
> +      else if (size <= 3)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE2
> +            : BUILT_IN_TSAN_VOLATILE_READ2;
> +      else if (size <= 7)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE4
> +            : BUILT_IN_TSAN_VOLATILE_READ4;
> +      else if (size <= 15)
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE8
> +            : BUILT_IN_TSAN_VOLATILE_READ8;
> +      else
> +        fcode = is_write ? BUILT_IN_TSAN_VOLATILE_WRITE16
> +            : BUILT_IN_TSAN_VOLATILE_READ16;
> +    }
>    else
> -    fcode = is_write ? BUILT_IN_TSAN_WRITE16
> -                    : BUILT_IN_TSAN_READ16;
> +    {
> +      if (size <= 1)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE1 : BUILT_IN_TSAN_READ1;
> +      else if (size <= 3)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE2 : BUILT_IN_TSAN_READ2;
> +      else if (size <= 7)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE4 : BUILT_IN_TSAN_READ4;
> +      else if (size <= 15)
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE8 : BUILT_IN_TSAN_READ8;
> +      else
> +        fcode = is_write ? BUILT_IN_TSAN_WRITE16 : BUILT_IN_TSAN_READ16;
> +    }
>
>    return builtin_decl_implicit (fcode);
>  }
> @@ -204,8 +220,11 @@ instrument_expr (gimple_stmt_iterator gsi, tree expr, bool is_write)
>        g = gimple_build_call (builtin_decl, 2, expr_ptr, size_int (size));
>      }
>    else if (rhs == NULL)
> -    g = gimple_build_call (get_memory_access_decl (is_write, size),
> -                          1, expr_ptr);
> +    {
> +      builtin_decl = get_memory_access_decl (is_write, size,
> +                                             TREE_THIS_VOLATILE(expr));
> +      g = gimple_build_call (builtin_decl, 1, expr_ptr);
> +    }
>    else
>      {
>        builtin_decl = builtin_decl_implicit (BUILT_IN_TSAN_VPTR_UPDATE);
> --
> 2.26.1.301.g55bc3eb7cb9-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BarbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA%40mail.gmail.com.
