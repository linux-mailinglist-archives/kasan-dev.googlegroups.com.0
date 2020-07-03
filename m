Return-Path: <kasan-dev+bncBCMIZB7QWENRB2EE7X3QKGQEMXXRQ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id DF463213BE3
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Jul 2020 16:36:25 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id t23sf19687476iog.21
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Jul 2020 07:36:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593786985; cv=pass;
        d=google.com; s=arc-20160816;
        b=i5hqm+P3I4giJvaP4MBEYALpRCcr7IWuQgWhtKJPNnAfzrGZoSlViqG+wbyuljL8fq
         sQG8iIQ1EFfc5nHZ5+7CaZDiE4W+p+NpxJsF4lmOEEhF0HRQRWUw5PRXsAX+oRLymSPC
         l88aOEtN8QQaLcr5/yxJwgUPxFFqRxojM4ZvB1PVUK1x5pFX25XIcE2w9Y8NvCAem10f
         z6NhbHvOuWLtrKmfLg03g8Uxb0/UCsUhf1M+J1zcnb3bFfNo/MOmkK807egYdoxIz/Ar
         1j7xf31tohGNzgJYzqpLOCyMkev1zDKyZT5VOnD0CvlV4o53LGYAqo8Pw5JumXA3s0kJ
         adiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HRM17vWOmEr6wIaOJCd9zGsj6cZ3Lq84CT5zqHxzfHI=;
        b=T7wVE3M1lL6SnctKnJus/ltGe2KBfMQhHvz+rSYbxq8paeuRU1jfKzsZzHpXgJBwsH
         l3v77HniB/8GOrvO/AYcYfDqboROm+ZwFswngDVv5WAi3IYUr1Myc0fetBHuAKhYKSFY
         LdaO9LZI8BKbMG5xsSW2pePdjZ3SXI3HobXOTgBElcJdDJs9vm2F/6xTH8QXUYIzc8ur
         kYtrpuDr6NdJ2ugyszI339yvUT6de3PRInOmWNoncLqHtHBON+bySGF1V3s/JnmkHee/
         EMP/ZGjCbuS9sALONI14VAc9v9xmy+1QbdYFxUwtgniO8fAWrKe0QY1Q18E8T9YkFA1K
         ps/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ua3/jOaY";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HRM17vWOmEr6wIaOJCd9zGsj6cZ3Lq84CT5zqHxzfHI=;
        b=i77miZ8WRJLXT/CrQnb9B5nNQGKNiDncYMj/oWHZyHCyPSU4m74bOF2T9EVRqrw865
         ZzPq/PYZPQhm2rFFW5BYJ0Gwwanng3j6XiWotIgfK60v1SQenkIW33BmeC/x1KGPT8N9
         UtD+/N2xWO7lV6vL2BJDndgHn7vExVWmX+5pQHoqBNh9/HmFh8oA8JzkIVbAz0ObVmSD
         KIXiF3NusLJ5hyT7PDUJUcM5rQNuFe9cvJ5aS7I/zuRV10Q0bGLwmzYjOx0gKxmn4qu5
         5vVwyiAWQI4lunSB4XUFCQzcZLG8SfXsSJCBwg0tJfqHVsVpaO545GCfXKYTgDSngWrt
         zTRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HRM17vWOmEr6wIaOJCd9zGsj6cZ3Lq84CT5zqHxzfHI=;
        b=grV/dhdbe6mz3uHW3nKl1ICHbaDskdkIqPqad/rdtudPcDYhVNxBbKS6DqZJpzHePt
         lICYR3froJaQ6TJBDuy5LRjaEzJgbMvLFy9b84W4akACuZ+HTViE71e7wJ2TIxyol/lI
         RdmY+30tgw71PNdX1IMTEDJLIxTJJPghjv4Ysf3Qlb5aeTJ5SSpnZtGIKoMYjnV4Mg2O
         p1pwTFtvsmkjsLXKpVHiNzRPPfdPVAg5UXERgNico72VVT0TVRkWEzq4iuhq3BcWtOWs
         5Bun/DnbVhvbAwQ2aZvKhGhmAGLw372sYVsZYd53r9XwtWZbuLUQO0iusWQwWDcAo2lp
         yozg==
X-Gm-Message-State: AOAM5338sCuCJbqnVT+KfP1hVJ651DEzWJMeFgAe0GmtUkp5c1amzsFC
	oFFfIDmyipSb56DGdQf3czo=
X-Google-Smtp-Source: ABdhPJy+YQcgP4xuV0X8098wjJVRwgLXRh2VDxnBAZcc12e2EVRGBzhvXOgN0/+1w7/H4JOHeQc+/w==
X-Received: by 2002:a05:6602:45:: with SMTP id z5mr12544389ioz.112.1593786984816;
        Fri, 03 Jul 2020 07:36:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9a89:: with SMTP id c9ls2654476ill.7.gmail; Fri, 03 Jul
 2020 07:36:24 -0700 (PDT)
X-Received: by 2002:a92:5a05:: with SMTP id o5mr12382432ilb.237.1593786984531;
        Fri, 03 Jul 2020 07:36:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593786984; cv=none;
        d=google.com; s=arc-20160816;
        b=wTzeCa8uA2rUQ58q4j463aoqIzO79p3g7BA/S0RsYIoWfonKx16KR70OjbkgcihS/Y
         KEqtiAShhZNuHddwFrkm8NoAqiBvVXa4QCOY3Yieh+J/qZ+jsLcLhpHoHeR2niSLckDY
         BgVoTbc7VdYoJxI80a3snFm3fOtJrdhW7SrsGWoMWmloN71o5YdkNV/yMvRyHi1WQEOr
         QX+B1Ec4MoT4tZw0WS5+yMz9X1/ShgxeP1jPZUEfn+lDOLpQYKLuOWoeqeMvAmYjDsvF
         e0MBlD8kdyM51/NHpljAGWmUnOQqi8JJ7NBxyUY94VUBzWbeKmTkg9fa4H+bfBVnw+0S
         3aFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C0p6+MkcMCuJnYjdDnNybQAxnSXPvknTUY7McNjJwwE=;
        b=mQl2v6vv6bm4jthMutqej+tacccdaZ3l4my3pbBK4wzcLuuIuMIf1NQPS/R+Z4qEGW
         lnh1Mkgipi4tmif/urNaaP10BfAueKw4EuDOOXkXZlAmEHVwOnzZRAvEZX2NBFZF9eJM
         0aPwnkUaPedxx/l7id5CniKwm+OASHWL5/wZ//SjRE3SNZ8UGkfvEDMgRexYtbPxAnso
         f8D4p8pB3y/DME6PmRmbjGflP94aMeTB+GWid1wnZbCMCYnFHyxKINdnnuv65eVstuba
         qpGaEBuqsziD7QOGsMZVqmEO3Plcmd/EA+bc7YeEgd60mIbjhKnaBpfS33YAbHSRu8Us
         TJcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ua3/jOaY";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id q80si740852iod.0.2020.07.03.07.36.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Jul 2020 07:36:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id q198so28946441qka.2
        for <kasan-dev@googlegroups.com>; Fri, 03 Jul 2020 07:36:24 -0700 (PDT)
X-Received: by 2002:a37:7682:: with SMTP id r124mr17230924qkc.43.1593786983628;
 Fri, 03 Jul 2020 07:36:23 -0700 (PDT)
MIME-Version: 1.0
References: <20200703134031.3298135-1-elver@google.com>
In-Reply-To: <20200703134031.3298135-1-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Jul 2020 16:36:11 +0200
Message-ID: <CACT4Y+YoicOtXEGsV9fJwfA7PpQY0sKbyWq1gY27P-oaXDJ3RA@mail.gmail.com>
Subject: Re: [PATCH 1/3] kcsan: Add support for atomic builtins
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ua3/jOaY";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Fri, Jul 3, 2020 at 3:40 PM Marco Elver <elver@google.com> wrote:
>
> Some architectures (currently e.g. s390 partially) implement atomics
> using the compiler's atomic builtins (__atomic_*, __sync_*). To support
> enabling KCSAN on such architectures in future, or support experimental
> use of these builtins, implement support for them.
>
> We should also avoid breaking KCSAN kernels due to use (accidental or
> otherwise) of atomic builtins in drivers, as has happened in the past:
> https://lkml.kernel.org/r/5231d2c0-41d9-6721-e15f-a7eedf3ce69e@infradead.org
>
> The instrumentation is subtly different from regular reads/writes: TSAN
> instrumentation replaces the use of atomic builtins with a call into the
> runtime, and the runtime's job is to also execute the desired atomic
> operation. We rely on the __atomic_* compiler builtins, available with
> all KCSAN-supported compilers, to implement each TSAN atomic
> instrumentation function.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/kcsan/core.c | 110 ++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 110 insertions(+)
>
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index d803765603fb..6843169da759 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -856,3 +856,113 @@ void __tsan_init(void)
>  {
>  }
>  EXPORT_SYMBOL(__tsan_init);
> +
> +/*
> + * Instrumentation for atomic builtins (__atomic_*, __sync_*).
> + *
> + * Normal kernel code _should not_ be using them directly, but some
> + * architectures may implement some or all atomics using the compilers'
> + * builtins.
> + *
> + * Note: If an architecture decides to fully implement atomics using the
> + * builtins, because they are implicitly instrumented by KCSAN (and KASAN,
> + * etc.), implementing the ARCH_ATOMIC interface (to get instrumentation via
> + * atomic-instrumented) is no longer necessary.
> + *
> + * TSAN instrumentation replaces atomic accesses with calls to any of the below
> + * functions, whose job is to also execute the operation itself.
> + */
> +
> +#define DEFINE_TSAN_ATOMIC_LOAD_STORE(bits)                                                        \
> +       u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder);                      \
> +       u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
> +       {                                                                                          \
> +               check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);                      \
> +               return __atomic_load_n(ptr, memorder);                                             \
> +       }                                                                                          \
> +       EXPORT_SYMBOL(__tsan_atomic##bits##_load);                                                 \
> +       void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder);                   \
> +       void __tsan_atomic##bits##_store(u##bits *ptr, u##bits v, int memorder)                    \
> +       {                                                                                          \
> +               check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
> +               __atomic_store_n(ptr, v, memorder);                                                \
> +       }                                                                                          \
> +       EXPORT_SYMBOL(__tsan_atomic##bits##_store)
> +
> +#define DEFINE_TSAN_ATOMIC_RMW(op, bits, suffix)                                                   \
> +       u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder);                 \
> +       u##bits __tsan_atomic##bits##_##op(u##bits *ptr, u##bits v, int memorder)                  \
> +       {                                                                                          \
> +               check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
> +               return __atomic_##op##suffix(ptr, v, memorder);                                    \
> +       }                                                                                          \
> +       EXPORT_SYMBOL(__tsan_atomic##bits##_##op)
> +
> +/*
> + * Note: CAS operations are always classified as write, even in case they
> + * fail. We cannot perform check_access() after a write, as it might lead to
> + * false positives, in cases such as:
> + *
> + *     T0: __atomic_compare_exchange_n(&p->flag, &old, 1, ...)
> + *
> + *     T1: if (__atomic_load_n(&p->flag, ...)) {
> + *             modify *p;
> + *             p->flag = 0;
> + *         }
> + *
> + * The only downside is that, if there are 3 threads, with one CAS that
> + * succeeds, another CAS that fails, and an unmarked racing operation, we may
> + * point at the wrong CAS as the source of the race. However, if we assume that
> + * all CAS can succeed in some other execution, the data race is still valid.
> + */
> +#define DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strength, weak)                                           \
> +       int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
> +                                                             u##bits val, int mo, int fail_mo);   \
> +       int __tsan_atomic##bits##_compare_exchange_##strength(u##bits *ptr, u##bits *exp,          \
> +                                                             u##bits val, int mo, int fail_mo)    \
> +       {                                                                                          \
> +               check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
> +               return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
> +       }                                                                                          \
> +       EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_##strength)
> +
> +#define DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)                                                       \
> +       u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
> +                                                          int mo, int fail_mo);                   \
> +       u##bits __tsan_atomic##bits##_compare_exchange_val(u##bits *ptr, u##bits exp, u##bits val, \
> +                                                          int mo, int fail_mo)                    \
> +       {                                                                                          \
> +               check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC); \
> +               __atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
> +               return exp;                                                                        \
> +       }                                                                                          \
> +       EXPORT_SYMBOL(__tsan_atomic##bits##_compare_exchange_val)
> +
> +#define DEFINE_TSAN_ATOMIC_OPS(bits)                                                               \
> +       DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);                                                       \
> +       DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);                                                \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits, );                                                 \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits, );                                                 \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits, );                                                 \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits, );                                                  \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits, );                                                 \
> +       DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits, );                                                \
> +       DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);                                               \
> +       DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);                                                 \
> +       DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits)
> +
> +DEFINE_TSAN_ATOMIC_OPS(8);
> +DEFINE_TSAN_ATOMIC_OPS(16);
> +DEFINE_TSAN_ATOMIC_OPS(32);
> +DEFINE_TSAN_ATOMIC_OPS(64);
> +
> +void __tsan_atomic_thread_fence(int memorder);
> +void __tsan_atomic_thread_fence(int memorder)
> +{
> +       __atomic_thread_fence(memorder);
> +}
> +EXPORT_SYMBOL(__tsan_atomic_thread_fence);
> +
> +void __tsan_atomic_signal_fence(int memorder);
> +void __tsan_atomic_signal_fence(int memorder) { }
> +EXPORT_SYMBOL(__tsan_atomic_signal_fence);
> --
> 2.27.0.212.ge8ba1cc988-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYoicOtXEGsV9fJwfA7PpQY0sKbyWq1gY27P-oaXDJ3RA%40mail.gmail.com.
