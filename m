Return-Path: <kasan-dev+bncBCMIZB7QWENRBGGLYDWQKGQEZYIPULY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D66EE1745
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2019 12:04:09 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id x17sf3367106ill.7
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2019 03:04:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571825048; cv=pass;
        d=google.com; s=arc-20160816;
        b=Iz7zDrKJ97y2uhOX0mGJAm6HXEL7Iw2yFdL5HUExgdMnLrO/aLq23CWu5Ihhg1vZFv
         ILRgBx2zB0QwoC5xVU6ATiEb0njb3s7w9RtnorY2c+H1BxTDgKHGF0W2c6Hqw1957EXP
         rGJc2rGotR+jg3hCG5GJNGSWsF0MMIUZjgeeibMlT4g38C7gL5Al+wwTRSyft1SyGWow
         /MWy+o2GBNDa6gr1JQ7GTISmvwUMYB5HEWIqIdYhRFEX14pS8EK/dQkhNZ1uKk7hwrhZ
         raZD2RkyrwaCWkTgi/9VIMT1JTeDH3w4zJ5W0S9174PAw/NYw10jnnxPjuRwYj/li+Lm
         PHfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wg3d3Z9YJCxC+mpKpizWLYQzqZtvlVRVvF+/H3f3QA0=;
        b=gN43cUP4BwPr6PcClxDm2fk2VaI+NR53IIFAkaCrgXV7fTCZmo8CFcLn6MAm+bIujk
         v1bl73AO+QZJOCylSc+yP9aUQLiugq3jxlYJTT5mB6HZadTMov/YWrdUzB8hn7gLk5xb
         31sWcYP+hWYlzCcFV4E57WIMK2DSWPJpKYfQYLlWAWHZfrGtXFpxg+T1q23FIjKWDkZp
         Ntj/+IuOMjXGn3FbbtT+QNTBwKcLa4f7lGjTlJW4H190En0BdSSoz3E2tlDyzDZdxg5z
         EkNRBLVFHodS89+PaMNUjwQjnD8rNzwjSVBKO9UtS0j280D42PC+h22ijiopco6KiZxw
         Ddjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XsWT2i98;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wg3d3Z9YJCxC+mpKpizWLYQzqZtvlVRVvF+/H3f3QA0=;
        b=QJxyA7ARV7h1yDN9J0cgQqO+knC9z56sFaVLMQwrwA7nU06Zj7k7LGikzDJUuCR+lC
         X0Iz/R9Q/8V0A99Ixgf2tNhwk69/KyhYsPcuUGUFhsNQONaezjopGjwYskq+Z/IV63cn
         7ZcL2JKejfmQ0Xi088JESJXGwkP/fIU+oN6CUrl2sOaitrZerNCq6qadAyKitml0k388
         3VANyuRp9tA9XmoBMEkPCFJVJZ0To3Pm9KwclOHrcrlx5HK20AcKjNukF/tK35o0bQux
         hYFJpHCpNp+SaCZmn5GtX8gNZVopqdbHiADpv5UO1DtIVv7kMa5cF97p1CEQsTPNCYO6
         JSdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wg3d3Z9YJCxC+mpKpizWLYQzqZtvlVRVvF+/H3f3QA0=;
        b=seZqkQE2KDqIquNLJhIAAJHFLF9enW5BytlSBczjvQlyJLnGCkWCUcg+P6n0g5lYg7
         FyWWL5pHIUJ9qOxIM5gb0SdUFU2sOm7AUhJXpNWjeHaKe92E/Q0QhyepHCnPbILZEWeK
         hy+iwc8N9aa7msrhSGk4nn0zOqOXnySqHMR3Trz9FsUA/gYJ/TN3tcs7m9CYfu6JXe11
         lCMUL4yIykN5aiB15nTGfjMe68NOs2/cKQt8K9bnAEvVPDCs/H1AJjlZjfZ/qmLpPIVv
         TiOChAav467INeqPZ70CkaudtEay8KPNRjTDqHL1aKQU4o1YwKfnu7EN8VIertCNumM7
         CUcQ==
X-Gm-Message-State: APjAAAXNbcDJu1zN9gIFHZ4Ie6MtUk5+UczMK2HRCqJW2SWINrBkVYTx
	tkGwXlD92hV9XIKfNy/XyfE=
X-Google-Smtp-Source: APXvYqzJ2JGwd/qtK9Vw0OiLfimHImqjiGB9Kgh0jZP21KW0zw/lPLDQ+UX0jF1D42uT6XzPO3b4LA==
X-Received: by 2002:a92:9ecd:: with SMTP id s74mr35918412ilk.188.1571825048255;
        Wed, 23 Oct 2019 03:04:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:ce44:: with SMTP id y4ls123370jar.4.gmail; Wed, 23 Oct
 2019 03:04:07 -0700 (PDT)
X-Received: by 2002:a02:bb85:: with SMTP id g5mr8676075jan.7.1571825047701;
        Wed, 23 Oct 2019 03:04:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571825047; cv=none;
        d=google.com; s=arc-20160816;
        b=HhdtcMlgzjJmZHKGOxxTcOSPWKc65KNsZC1leRRyRct8Iy2XCdYi7dkQgOL5y5rGYq
         5Z1U1D3Je/rifUesIgSILVKf1v5aNiEJ2r4x5zSbhWdaE+haorqn4teIYLPrK4PQi4r6
         zvN+dPqf0tCyDdpISur9xp0VDKtOxQM+jd93z9gjVxt/VZ9mvic56hiFKiYT73oLpHo8
         85Av3Xt9sdPL5V9GNNmFVbwBF4lOZLKQe5ALj9SEAA3OjFTdIblED+HDNf3B8ZVJlAnU
         mjQo6mGr+/3jdkUAmDuSkQqU/9RE+NU26BACoXHcaRMOX765Npn4gR1QTtG2g8YAgLww
         hXxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QqJ0ldaufIlp0tBsU24y0T/9/yH5Bcql27IM5W7jZoM=;
        b=sqFtp1A/yD1bdP7CJ0QDCCD1tKIxVMKQlqQJjcx6JS1UgQxL5lh2SxCIrqqOT9TCZI
         jD1ePFTGvefE+yGIpYh9CoKD+SQq8j8nz7KGIxb2w/IKgWDNFXEPMu5qWlFRGhl+0ywa
         B4hPexdDUGLcN2xJNrQCM1Y8V0Hbvq1WArTOT3qrlgfJx/OGbEVaNGlk9cgO+8Y91g0o
         QOd/UNajdpfUcW8+ifGz1vUxEMG6ZiLRBs6G1OtaNruO6S+g7YnShN6CEXxJqqapajCN
         eaGlsuvu7InAbi1/ece48rbXEu6Ib0I8Oww6md+vV/fvBfArx9moeuVQ0xzNH/goNryM
         xCLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XsWT2i98;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id f5si141513iof.4.2019.10.23.03.04.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Oct 2019 03:04:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id w2so19202090qkf.2
        for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2019 03:04:07 -0700 (PDT)
X-Received: by 2002:a05:620a:16a6:: with SMTP id s6mr6839274qkj.407.1571825045656;
 Wed, 23 Oct 2019 03:04:05 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-2-elver@google.com>
In-Reply-To: <20191017141305.146193-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 23 Oct 2019 12:03:53 +0200
Message-ID: <CACT4Y+bTY6EWhv3Q=BDee6Db=uxqxfNgifLDNRmOmpdH6=hUGQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/8] kcsan: Add Kernel Concurrency Sanitizer infrastructure
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Luc Maranget <luc.maranget@inria.fr>, Mark Rutland <mark.rutland@arm.com>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	"open list:KERNEL BUILD + fi..." <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XsWT2i98;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Thu, Oct 17, 2019 at 4:13 PM Marco Elver <elver@google.com> wrote:
> --- a/init/main.c
> +++ b/init/main.c
> @@ -93,6 +93,7 @@
>  #include <linux/rodata_test.h>
>  #include <linux/jump_label.h>
>  #include <linux/mem_encrypt.h>
> +#include <linux/kcsan.h>
>
>  #include <asm/io.h>
>  #include <asm/bugs.h>
> @@ -779,6 +780,7 @@ asmlinkage __visible void __init start_kernel(void)
>         acpi_subsystem_init();
>         arch_post_acpi_subsys_init();
>         sfi_init_late();
> +       kcsan_init();
>
>         /* Do the rest non-__init'ed, we're now alive */
>         arch_call_rest_init();
> diff --git a/kernel/Makefile b/kernel/Makefile
> index daad787fb795..74ab46e2ebd1 100644
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -102,6 +102,7 @@ obj-$(CONFIG_TRACEPOINTS) += trace/
>  obj-$(CONFIG_IRQ_WORK) += irq_work.o
>  obj-$(CONFIG_CPU_PM) += cpu_pm.o
>  obj-$(CONFIG_BPF) += bpf/
> +obj-$(CONFIG_KCSAN) += kcsan/
>
>  obj-$(CONFIG_PERF_EVENTS) += events/
>
> diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> new file mode 100644
> index 000000000000..c25f07062d26
> --- /dev/null
> +++ b/kernel/kcsan/Makefile
> @@ -0,0 +1,14 @@
> +# SPDX-License-Identifier: GPL-2.0
> +KCSAN_SANITIZE := n
> +KCOV_INSTRUMENT := n
> +
> +CFLAGS_REMOVE_kcsan.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_atomic.o = $(CC_FLAGS_FTRACE)
> +
> +CFLAGS_kcsan.o = $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> +CFLAGS_core.o = $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> +CFLAGS_atomic.o = $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> +
> +obj-y := kcsan.o core.o atomic.o debugfs.o report.o
> +obj-$(CONFIG_KCSAN_SELFTEST) += test.o
> diff --git a/kernel/kcsan/atomic.c b/kernel/kcsan/atomic.c
> new file mode 100644
> index 000000000000..dd44f7d9e491
> --- /dev/null
> +++ b/kernel/kcsan/atomic.c
> @@ -0,0 +1,21 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#include <linux/jiffies.h>
> +
> +#include "kcsan.h"
> +
> +/*
> + * List all volatile globals that have been observed in races, to suppress
> + * data-race reports between accesses to these variables.
> + *
> + * For now, we assume that volatile accesses of globals are as strong as atomic
> + * accesses (READ_ONCE, WRITE_ONCE cast to volatile). The situation is still not
> + * entirely clear, as on some architectures (Alpha) READ_ONCE/WRITE_ONCE do more
> + * than cast to volatile. Eventually, we hope to be able to remove this
> + * function.
> + */
> +bool kcsan_is_atomic(const volatile void *ptr)
> +{
> +       /* only jiffies for now */
> +       return ptr == &jiffies;
> +}
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> new file mode 100644
> index 000000000000..bc8d60b129eb
> --- /dev/null
> +++ b/kernel/kcsan/core.c
> @@ -0,0 +1,428 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#include <linux/atomic.h>
> +#include <linux/bug.h>
> +#include <linux/delay.h>
> +#include <linux/export.h>
> +#include <linux/init.h>
> +#include <linux/percpu.h>
> +#include <linux/preempt.h>
> +#include <linux/random.h>
> +#include <linux/sched.h>
> +#include <linux/uaccess.h>
> +
> +#include "kcsan.h"
> +#include "encoding.h"
> +
> +/*
> + * Helper macros to iterate slots, starting from address slot itself, followed
> + * by the right and left slots.
> + */
> +#define CHECK_NUM_SLOTS (1 + 2 * KCSAN_CHECK_ADJACENT)
> +#define SLOT_IDX(slot, i)                                                      \
> +       ((slot + (((i + KCSAN_CHECK_ADJACENT) % CHECK_NUM_SLOTS) -             \
> +                 KCSAN_CHECK_ADJACENT)) %                                     \
> +        KCSAN_NUM_WATCHPOINTS)
> +
> +bool kcsan_enabled;
> +
> +/* Per-CPU kcsan_ctx for interrupts */
> +static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
> +       .disable = 0,
> +       .atomic_next = 0,
> +       .atomic_region = 0,
> +       .atomic_region_flat = 0,
> +};
> +
> +/*
> + * Watchpoints, with each entry encoded as defined in encoding.h: in order to be
> + * able to safely update and access a watchpoint without introducing locking
> + * overhead, we encode each watchpoint as a single atomic long. The initial
> + * zero-initialized state matches INVALID_WATCHPOINT.
> + */
> +static atomic_long_t watchpoints[KCSAN_NUM_WATCHPOINTS];
> +
> +/*
> + * Instructions skipped counter; see should_watch().
> + */
> +static DEFINE_PER_CPU(unsigned long, kcsan_skip);
> +
> +static inline atomic_long_t *find_watchpoint(unsigned long addr, size_t size,
> +                                            bool expect_write,
> +                                            long *encoded_watchpoint)
> +{
> +       const int slot = watchpoint_slot(addr);
> +       const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
> +       atomic_long_t *watchpoint;
> +       unsigned long wp_addr_masked;
> +       size_t wp_size;
> +       bool is_write;
> +       int i;
> +
> +       for (i = 0; i < CHECK_NUM_SLOTS; ++i) {
> +               watchpoint = &watchpoints[SLOT_IDX(slot, i)];
> +               *encoded_watchpoint = atomic_long_read(watchpoint);
> +               if (!decode_watchpoint(*encoded_watchpoint, &wp_addr_masked,
> +                                      &wp_size, &is_write))
> +                       continue;
> +
> +               if (expect_write && !is_write)
> +                       continue;
> +
> +               /* Check if the watchpoint matches the access. */
> +               if (matching_access(wp_addr_masked, wp_size, addr_masked, size))
> +                       return watchpoint;
> +       }
> +
> +       return NULL;
> +}
> +
> +static inline atomic_long_t *insert_watchpoint(unsigned long addr, size_t size,
> +                                              bool is_write)
> +{
> +       const int slot = watchpoint_slot(addr);
> +       const long encoded_watchpoint = encode_watchpoint(addr, size, is_write);
> +       atomic_long_t *watchpoint;
> +       int i;
> +
> +       for (i = 0; i < CHECK_NUM_SLOTS; ++i) {
> +               long expect_val = INVALID_WATCHPOINT;
> +
> +               /* Try to acquire this slot. */
> +               watchpoint = &watchpoints[SLOT_IDX(slot, i)];
> +               if (atomic_long_try_cmpxchg_relaxed(watchpoint, &expect_val,
> +                                                   encoded_watchpoint))
> +                       return watchpoint;
> +       }
> +
> +       return NULL;
> +}
> +
> +/*
> + * Return true if watchpoint was successfully consumed, false otherwise.
> + *
> + * This may return false if:
> + *
> + *     1. another thread already consumed the watchpoint;
> + *     2. the thread that set up the watchpoint already removed it;
> + *     3. the watchpoint was removed and then re-used.
> + */
> +static inline bool try_consume_watchpoint(atomic_long_t *watchpoint,
> +                                         long encoded_watchpoint)
> +{
> +       return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint,
> +                                              CONSUMED_WATCHPOINT);
> +}
> +
> +/*
> + * Return true if watchpoint was not touched, false if consumed.
> + */
> +static inline bool remove_watchpoint(atomic_long_t *watchpoint)
> +{
> +       return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) !=
> +              CONSUMED_WATCHPOINT;
> +}
> +
> +static inline struct kcsan_ctx *get_ctx(void)
> +{
> +       /*
> +        * In interrupt, use raw_cpu_ptr to avoid unnecessary checks, that would
> +        * also result in calls that generate warnings in uaccess regions.
> +        */
> +       return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
> +}
> +
> +static inline bool is_atomic(const volatile void *ptr)
> +{
> +       struct kcsan_ctx *ctx = get_ctx();
> +
> +       if (unlikely(ctx->atomic_next > 0)) {
> +               --ctx->atomic_next;
> +               return true;
> +       }
> +       if (unlikely(ctx->atomic_region > 0 || ctx->atomic_region_flat))
> +               return true;
> +
> +       return kcsan_is_atomic(ptr);
> +}
> +
> +static inline bool should_watch(const volatile void *ptr)
> +{
> +       /*
> +        * Never set up watchpoints when memory operations are atomic.
> +        *
> +        * We need to check this first, because: 1) atomics should not count
> +        * towards skipped instructions below, and 2) to actually decrement
> +        * kcsan_atomic_next for each atomic.
> +        */
> +       if (is_atomic(ptr))
> +               return false;
> +
> +       /*
> +        * We use a per-CPU counter, to avoid excessive contention; there is
> +        * still enough non-determinism for the precise instructions that end up
> +        * being watched to be mostly unpredictable. Using a PRNG like
> +        * prandom_u32() turned out to be too slow.
> +        */
> +       return (this_cpu_inc_return(kcsan_skip) %
> +               CONFIG_KCSAN_WATCH_SKIP_INST) == 0;
> +}
> +
> +static inline bool is_enabled(void)
> +{
> +       return READ_ONCE(kcsan_enabled) && get_ctx()->disable == 0;
> +}
> +
> +static inline unsigned int get_delay(void)
> +{
> +       unsigned int max_delay = in_task() ? CONFIG_KCSAN_UDELAY_MAX_TASK :
> +                                            CONFIG_KCSAN_UDELAY_MAX_INTERRUPT;
> +       return IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
> +                      ((prandom_u32() % max_delay) + 1) :
> +                      max_delay;
> +}
> +
> +/* === Public interface ===================================================== */
> +
> +void __init kcsan_init(void)
> +{
> +       BUG_ON(!in_task());
> +
> +       kcsan_debugfs_init();
> +       kcsan_enable_current();
> +#ifdef CONFIG_KCSAN_EARLY_ENABLE
> +       /*
> +        * We are in the init task, and no other tasks should be running.
> +        */
> +       WRITE_ONCE(kcsan_enabled, true);
> +#endif
> +}
> +
> +/* === Exported interface =================================================== */
> +
> +void kcsan_disable_current(void)
> +{
> +       ++get_ctx()->disable;
> +}
> +EXPORT_SYMBOL(kcsan_disable_current);
> +
> +void kcsan_enable_current(void)
> +{
> +       if (get_ctx()->disable-- == 0) {
> +               kcsan_disable_current(); /* restore to 0 */
> +               kcsan_disable_current();
> +               WARN(1, "mismatching %s", __func__);
> +               kcsan_enable_current();
> +       }
> +}
> +EXPORT_SYMBOL(kcsan_enable_current);
> +
> +void kcsan_begin_atomic(bool nest)
> +{
> +       if (nest)
> +               ++get_ctx()->atomic_region;
> +       else
> +               get_ctx()->atomic_region_flat = true;
> +}
> +EXPORT_SYMBOL(kcsan_begin_atomic);
> +
> +void kcsan_end_atomic(bool nest)
> +{
> +       if (nest) {
> +               if (get_ctx()->atomic_region-- == 0) {
> +                       kcsan_begin_atomic(true); /* restore to 0 */
> +                       kcsan_disable_current();
> +                       WARN(1, "mismatching %s", __func__);
> +                       kcsan_enable_current();
> +               }
> +       } else {
> +               get_ctx()->atomic_region_flat = false;
> +       }
> +}
> +EXPORT_SYMBOL(kcsan_end_atomic);
> +
> +void kcsan_atomic_next(int n)
> +{
> +       get_ctx()->atomic_next = n;
> +}
> +EXPORT_SYMBOL(kcsan_atomic_next);
> +
> +bool __kcsan_check_watchpoint(const volatile void *ptr, size_t size,
> +                             bool is_write)
> +{
> +       atomic_long_t *watchpoint;
> +       long encoded_watchpoint;
> +       unsigned long flags;
> +       enum kcsan_report_type report_type;
> +
> +       if (unlikely(!is_enabled()))
> +               return false;
> +
> +       /*
> +        * Avoid user_access_save in fast-path here: find_watchpoint is safe
> +        * without user_access_save, as the address that ptr points to is only
> +        * used to check if a watchpoint exists; ptr is never dereferenced.
> +        */
> +       watchpoint = find_watchpoint((unsigned long)ptr, size, !is_write,
> +                                    &encoded_watchpoint);
> +       if (watchpoint == NULL)
> +               return true;
> +
> +       flags = user_access_save();
> +       if (!try_consume_watchpoint(watchpoint, encoded_watchpoint)) {
> +               /*
> +                * The other thread may not print any diagnostics, as it has
> +                * already removed the watchpoint, or another thread consumed
> +                * the watchpoint before this thread.
> +                */
> +               kcsan_counter_inc(kcsan_counter_report_races);
> +               report_type = kcsan_report_race_check_race;
> +       } else {
> +               report_type = kcsan_report_race_check;
> +       }
> +
> +       /* Encountered a data-race. */
> +       kcsan_counter_inc(kcsan_counter_data_races);
> +       kcsan_report(ptr, size, is_write, raw_smp_processor_id(), report_type);
> +
> +       user_access_restore(flags);
> +       return false;
> +}
> +EXPORT_SYMBOL(__kcsan_check_watchpoint);
> +
> +void __kcsan_setup_watchpoint(const volatile void *ptr, size_t size,
> +                             bool is_write)
> +{
> +       atomic_long_t *watchpoint;
> +       union {
> +               u8 _1;
> +               u16 _2;
> +               u32 _4;
> +               u64 _8;
> +       } expect_value;
> +       bool is_expected = true;
> +       unsigned long ua_flags = user_access_save();
> +       unsigned long irq_flags;
> +
> +       if (!should_watch(ptr))
> +               goto out;
> +
> +       if (!check_encodable((unsigned long)ptr, size)) {
> +               kcsan_counter_inc(kcsan_counter_unencodable_accesses);
> +               goto out;
> +       }
> +
> +       /*
> +        * Disable interrupts & preemptions to avoid another thread on the same
> +        * CPU accessing memory locations for the set up watchpoint; this is to
> +        * avoid reporting races to e.g. CPU-local data.
> +        *
> +        * An alternative would be adding the source CPU to the watchpoint
> +        * encoding, and checking that watchpoint-CPU != this-CPU. There are
> +        * several problems with this:
> +        *   1. we should avoid stealing more bits from the watchpoint encoding
> +        *      as it would affect accuracy, as well as increase performance
> +        *      overhead in the fast-path;
> +        *   2. if we are preempted, but there *is* a genuine data-race, we
> +        *      would *not* report it -- since this is the common case (vs.
> +        *      CPU-local data accesses), it makes more sense (from a data-race
> +        *      detection PoV) to simply disable preemptions to ensure as many
> +        *      tasks as possible run on other CPUs.
> +        */
> +       local_irq_save(irq_flags);
> +
> +       watchpoint = insert_watchpoint((unsigned long)ptr, size, is_write);
> +       if (watchpoint == NULL) {
> +               /*
> +                * Out of capacity: the size of `watchpoints`, and the frequency
> +                * with which `should_watch()` returns true should be tweaked so
> +                * that this case happens very rarely.
> +                */
> +               kcsan_counter_inc(kcsan_counter_no_capacity);
> +               goto out_unlock;
> +       }
> +
> +       kcsan_counter_inc(kcsan_counter_setup_watchpoints);
> +       kcsan_counter_inc(kcsan_counter_used_watchpoints);
> +
> +       /*
> +        * Read the current value, to later check and infer a race if the data
> +        * was modified via a non-instrumented access, e.g. from a device.
> +        */
> +       switch (size) {
> +       case 1:
> +               expect_value._1 = READ_ONCE(*(const u8 *)ptr);
> +               break;
> +       case 2:
> +               expect_value._2 = READ_ONCE(*(const u16 *)ptr);
> +               break;
> +       case 4:
> +               expect_value._4 = READ_ONCE(*(const u32 *)ptr);
> +               break;
> +       case 8:
> +               expect_value._8 = READ_ONCE(*(const u64 *)ptr);
> +               break;
> +       default:
> +               break; /* ignore; we do not diff the values */
> +       }
> +
> +#ifdef CONFIG_KCSAN_DEBUG
> +       kcsan_disable_current();
> +       pr_err("KCSAN: watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
> +              is_write ? "write" : "read", size, ptr,
> +              watchpoint_slot((unsigned long)ptr),
> +              encode_watchpoint((unsigned long)ptr, size, is_write));
> +       kcsan_enable_current();
> +#endif
> +
> +       /*
> +        * Delay this thread, to increase probability of observing a racy
> +        * conflicting access.
> +        */
> +       udelay(get_delay());
> +
> +       /*
> +        * Re-read value, and check if it is as expected; if not, we infer a
> +        * racy access.
> +        */
> +       switch (size) {
> +       case 1:
> +               is_expected = expect_value._1 == READ_ONCE(*(const u8 *)ptr);
> +               break;
> +       case 2:
> +               is_expected = expect_value._2 == READ_ONCE(*(const u16 *)ptr);
> +               break;
> +       case 4:
> +               is_expected = expect_value._4 == READ_ONCE(*(const u32 *)ptr);
> +               break;
> +       case 8:
> +               is_expected = expect_value._8 == READ_ONCE(*(const u64 *)ptr);
> +               break;
> +       default:
> +               break; /* ignore; we do not diff the values */
> +       }
> +
> +       /* Check if this access raced with another. */
> +       if (!remove_watchpoint(watchpoint)) {
> +               /*
> +                * No need to increment 'race' counter, as the racing thread
> +                * already did.
> +                */
> +               kcsan_report(ptr, size, is_write, smp_processor_id(),
> +                            kcsan_report_race_setup);
> +       } else if (!is_expected) {
> +               /* Inferring a race, since the value should not have changed. */
> +               kcsan_counter_inc(kcsan_counter_races_unknown_origin);
> +#ifdef CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> +               kcsan_report(ptr, size, is_write, smp_processor_id(),
> +                            kcsan_report_race_unknown_origin);
> +#endif
> +       }
> +
> +       kcsan_counter_dec(kcsan_counter_used_watchpoints);
> +out_unlock:
> +       local_irq_restore(irq_flags);
> +out:
> +       user_access_restore(ua_flags);
> +}
> +EXPORT_SYMBOL(__kcsan_setup_watchpoint);
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> new file mode 100644
> index 000000000000..6ddcbd185f3a
> --- /dev/null
> +++ b/kernel/kcsan/debugfs.c
> @@ -0,0 +1,225 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#include <linux/atomic.h>
> +#include <linux/bsearch.h>
> +#include <linux/bug.h>
> +#include <linux/debugfs.h>
> +#include <linux/init.h>
> +#include <linux/kallsyms.h>
> +#include <linux/mm.h>
> +#include <linux/seq_file.h>
> +#include <linux/sort.h>
> +#include <linux/string.h>
> +#include <linux/uaccess.h>
> +
> +#include "kcsan.h"
> +
> +/*
> + * Statistics counters.
> + */
> +static atomic_long_t counters[kcsan_counter_count];
> +
> +/*
> + * Addresses for filtering functions from reporting. This list can be used as a
> + * whitelist or blacklist.
> + */
> +static struct {
> +       unsigned long *addrs; /* array of addresses */
> +       size_t size; /* current size */
> +       int used; /* number of elements used */
> +       bool sorted; /* if elements are sorted */
> +       bool whitelist; /* if list is a blacklist or whitelist */
> +} report_filterlist = {
> +       .addrs = NULL,
> +       .size = 8, /* small initial size */
> +       .used = 0,
> +       .sorted = false,
> +       .whitelist = false, /* default is blacklist */
> +};
> +static DEFINE_SPINLOCK(report_filterlist_lock);
> +
> +static const char *counter_to_name(enum kcsan_counter_id id)
> +{
> +       switch (id) {
> +       case kcsan_counter_used_watchpoints:
> +               return "used_watchpoints";
> +       case kcsan_counter_setup_watchpoints:
> +               return "setup_watchpoints";
> +       case kcsan_counter_data_races:
> +               return "data_races";
> +       case kcsan_counter_no_capacity:
> +               return "no_capacity";
> +       case kcsan_counter_report_races:
> +               return "report_races";
> +       case kcsan_counter_races_unknown_origin:
> +               return "races_unknown_origin";
> +       case kcsan_counter_unencodable_accesses:
> +               return "unencodable_accesses";
> +       case kcsan_counter_encoding_false_positives:
> +               return "encoding_false_positives";
> +       case kcsan_counter_count:
> +               BUG();
> +       }
> +       return NULL;
> +}
> +
> +void kcsan_counter_inc(enum kcsan_counter_id id)
> +{
> +       atomic_long_inc(&counters[id]);
> +}
> +
> +void kcsan_counter_dec(enum kcsan_counter_id id)
> +{
> +       atomic_long_dec(&counters[id]);
> +}
> +
> +static int cmp_filterlist_addrs(const void *rhs, const void *lhs)
> +{
> +       const unsigned long a = *(const unsigned long *)rhs;
> +       const unsigned long b = *(const unsigned long *)lhs;
> +
> +       return a < b ? -1 : a == b ? 0 : 1;
> +}
> +
> +bool kcsan_skip_report(unsigned long func_addr)
> +{
> +       unsigned long symbolsize, offset;
> +       unsigned long flags;
> +       bool ret = false;
> +
> +       if (!kallsyms_lookup_size_offset(func_addr, &symbolsize, &offset))
> +               return false;
> +       func_addr -= offset; /* get function start */
> +
> +       spin_lock_irqsave(&report_filterlist_lock, flags);
> +       if (report_filterlist.used == 0)
> +               goto out;
> +
> +       /* Sort array if it is unsorted, and then do a binary search. */
> +       if (!report_filterlist.sorted) {
> +               sort(report_filterlist.addrs, report_filterlist.used,
> +                    sizeof(unsigned long), cmp_filterlist_addrs, NULL);
> +               report_filterlist.sorted = true;
> +       }
> +       ret = !!bsearch(&func_addr, report_filterlist.addrs,
> +                       report_filterlist.used, sizeof(unsigned long),
> +                       cmp_filterlist_addrs);
> +       if (report_filterlist.whitelist)
> +               ret = !ret;
> +
> +out:
> +       spin_unlock_irqrestore(&report_filterlist_lock, flags);
> +       return ret;
> +}
> +
> +static void set_report_filterlist_whitelist(bool whitelist)
> +{
> +       unsigned long flags;
> +
> +       spin_lock_irqsave(&report_filterlist_lock, flags);
> +       report_filterlist.whitelist = whitelist;
> +       spin_unlock_irqrestore(&report_filterlist_lock, flags);
> +}
> +
> +static void insert_report_filterlist(const char *func)
> +{
> +       unsigned long flags;
> +       unsigned long addr = kallsyms_lookup_name(func);
> +
> +       if (!addr) {
> +               pr_err("KCSAN: could not find function: '%s'\n", func);
> +               return;
> +       }
> +
> +       spin_lock_irqsave(&report_filterlist_lock, flags);
> +
> +       if (report_filterlist.addrs == NULL)
> +               report_filterlist.addrs = /* initial allocation */
> +                       kvmalloc_array(report_filterlist.size,
> +                                      sizeof(unsigned long), GFP_KERNEL);
> +       else if (report_filterlist.used == report_filterlist.size) {
> +               /* resize filterlist */
> +               unsigned long *new_addrs;
> +
> +               report_filterlist.size *= 2;
> +               new_addrs = kvmalloc_array(report_filterlist.size,
> +                                          sizeof(unsigned long), GFP_KERNEL);
> +               memcpy(new_addrs, report_filterlist.addrs,
> +                      report_filterlist.used * sizeof(unsigned long));
> +               kvfree(report_filterlist.addrs);
> +               report_filterlist.addrs = new_addrs;
> +       }
> +
> +       /* Note: deduplicating should be done in userspace. */
> +       report_filterlist.addrs[report_filterlist.used++] =
> +               kallsyms_lookup_name(func);
> +       report_filterlist.sorted = false;
> +
> +       spin_unlock_irqrestore(&report_filterlist_lock, flags);
> +}
> +
> +static int show_info(struct seq_file *file, void *v)
> +{
> +       int i;
> +       unsigned long flags;
> +
> +       /* show stats */
> +       seq_printf(file, "enabled: %i\n", READ_ONCE(kcsan_enabled));
> +       for (i = 0; i < kcsan_counter_count; ++i)
> +               seq_printf(file, "%s: %ld\n", counter_to_name(i),
> +                          atomic_long_read(&counters[i]));
> +
> +       /* show filter functions, and filter type */
> +       spin_lock_irqsave(&report_filterlist_lock, flags);
> +       seq_printf(file, "\n%s functions: %s\n",
> +                  report_filterlist.whitelist ? "whitelisted" : "blacklisted",
> +                  report_filterlist.used == 0 ? "none" : "");
> +       for (i = 0; i < report_filterlist.used; ++i)
> +               seq_printf(file, " %ps\n", (void *)report_filterlist.addrs[i]);
> +       spin_unlock_irqrestore(&report_filterlist_lock, flags);
> +
> +       return 0;
> +}
> +
> +static int debugfs_open(struct inode *inode, struct file *file)
> +{
> +       return single_open(file, show_info, NULL);
> +}
> +
> +static ssize_t debugfs_write(struct file *file, const char __user *buf,
> +                            size_t count, loff_t *off)
> +{
> +       char kbuf[KSYM_NAME_LEN];
> +       char *arg;
> +       int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
> +
> +       if (copy_from_user(kbuf, buf, read_len))
> +               return -EINVAL;
> +       kbuf[read_len] = '\0';
> +       arg = strstrip(kbuf);
> +
> +       if (!strncmp(arg, "on", sizeof("on") - 1))
> +               WRITE_ONCE(kcsan_enabled, true);
> +       else if (!strncmp(arg, "off", sizeof("off") - 1))
> +               WRITE_ONCE(kcsan_enabled, false);
> +       else if (!strncmp(arg, "whitelist", sizeof("whitelist") - 1))
> +               set_report_filterlist_whitelist(true);
> +       else if (!strncmp(arg, "blacklist", sizeof("blacklist") - 1))
> +               set_report_filterlist_whitelist(false);
> +       else if (arg[0] == '!')
> +               insert_report_filterlist(&arg[1]);
> +       else
> +               return -EINVAL;
> +
> +       return count;
> +}
> +
> +static const struct file_operations debugfs_ops = { .read = seq_read,
> +                                                   .open = debugfs_open,
> +                                                   .write = debugfs_write,
> +                                                   .release = single_release };
> +
> +void __init kcsan_debugfs_init(void)
> +{
> +       debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
> +}
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> new file mode 100644
> index 000000000000..8f9b1ce0e59f
> --- /dev/null
> +++ b/kernel/kcsan/encoding.h
> @@ -0,0 +1,94 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef _MM_KCSAN_ENCODING_H
> +#define _MM_KCSAN_ENCODING_H
> +
> +#include <linux/bits.h>
> +#include <linux/log2.h>
> +#include <linux/mm.h>
> +
> +#include "kcsan.h"
> +
> +#define SLOT_RANGE PAGE_SIZE
> +#define INVALID_WATCHPOINT 0
> +#define CONSUMED_WATCHPOINT 1
> +
> +/*
> + * The maximum useful size of accesses for which we set up watchpoints is the
> + * max range of slots we check on an access.
> + */
> +#define MAX_ENCODABLE_SIZE (SLOT_RANGE * (1 + KCSAN_CHECK_ADJACENT))
> +
> +/*
> + * Number of bits we use to store size info.
> + */
> +#define WATCHPOINT_SIZE_BITS bits_per(MAX_ENCODABLE_SIZE)
> +/*
> + * This encoding for addresses discards the upper (1 for is-write + SIZE_BITS);
> + * however, most 64-bit architectures do not use the full 64-bit address space.
> + * Also, in order for a false positive to be observable 2 things need to happen:
> + *
> + *     1. different addresses but with the same encoded address race;
> + *     2. and both map onto the same watchpoint slots;
> + *
> + * Both these are assumed to be very unlikely. However, in case it still happens
> + * happens, the report logic will filter out the false positive (see report.c).
> + */
> +#define WATCHPOINT_ADDR_BITS (BITS_PER_LONG - 1 - WATCHPOINT_SIZE_BITS)
> +
> +/*
> + * Masks to set/retrieve the encoded data.
> + */
> +#define WATCHPOINT_WRITE_MASK BIT(BITS_PER_LONG - 1)
> +#define WATCHPOINT_SIZE_MASK                                                   \
> +       GENMASK(BITS_PER_LONG - 2, BITS_PER_LONG - 2 - WATCHPOINT_SIZE_BITS)
> +#define WATCHPOINT_ADDR_MASK                                                   \
> +       GENMASK(BITS_PER_LONG - 3 - WATCHPOINT_SIZE_BITS, 0)
> +
> +static inline bool check_encodable(unsigned long addr, size_t size)
> +{
> +       return size <= MAX_ENCODABLE_SIZE;
> +}
> +
> +static inline long encode_watchpoint(unsigned long addr, size_t size,
> +                                    bool is_write)
> +{
> +       return (long)((is_write ? WATCHPOINT_WRITE_MASK : 0) |
> +                     (size << WATCHPOINT_ADDR_BITS) |
> +                     (addr & WATCHPOINT_ADDR_MASK));
> +}
> +
> +static inline bool decode_watchpoint(long watchpoint,
> +                                    unsigned long *addr_masked, size_t *size,
> +                                    bool *is_write)
> +{
> +       if (watchpoint == INVALID_WATCHPOINT ||
> +           watchpoint == CONSUMED_WATCHPOINT)
> +               return false;
> +
> +       *addr_masked = (unsigned long)watchpoint & WATCHPOINT_ADDR_MASK;
> +       *size = ((unsigned long)watchpoint & WATCHPOINT_SIZE_MASK) >>
> +               WATCHPOINT_ADDR_BITS;
> +       *is_write = !!((unsigned long)watchpoint & WATCHPOINT_WRITE_MASK);
> +
> +       return true;
> +}
> +
> +/*
> + * Return watchpoint slot for an address.
> + */
> +static inline int watchpoint_slot(unsigned long addr)
> +{
> +       return (addr / PAGE_SIZE) % KCSAN_NUM_WATCHPOINTS;
> +}
> +
> +static inline bool matching_access(unsigned long addr1, size_t size1,
> +                                  unsigned long addr2, size_t size2)
> +{
> +       unsigned long end_range1 = addr1 + size1 - 1;
> +       unsigned long end_range2 = addr2 + size2 - 1;
> +
> +       return addr1 <= end_range2 && addr2 <= end_range1;
> +}
> +
> +#endif /* _MM_KCSAN_ENCODING_H */
> diff --git a/kernel/kcsan/kcsan.c b/kernel/kcsan/kcsan.c
> new file mode 100644
> index 000000000000..45cf2fffd8a0
> --- /dev/null
> +++ b/kernel/kcsan/kcsan.c
> @@ -0,0 +1,86 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +/*
> + * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
> + * see Documentation/dev-tools/kcsan.rst.
> + */
> +
> +#include <linux/export.h>
> +
> +#include "kcsan.h"
> +
> +/*
> + * KCSAN uses the same instrumentation that is emitted by supported compilers
> + * for Thread Sanitizer (TSAN).
> + *
> + * When enabled, the compiler emits instrumentation calls (the functions
> + * prefixed with "__tsan" below) for all loads and stores that it generated;
> + * inline asm is not instrumented.
> + */
> +
> +#define DEFINE_TSAN_READ_WRITE(size)                                           \
> +       void __tsan_read##size(void *ptr)                                      \
> +       {                                                                      \
> +               __kcsan_check_read(ptr, size);                                 \
> +       }                                                                      \
> +       EXPORT_SYMBOL(__tsan_read##size);                                      \
> +       void __tsan_write##size(void *ptr)                                     \
> +       {                                                                      \
> +               __kcsan_check_write(ptr, size);                                \
> +       }                                                                      \
> +       EXPORT_SYMBOL(__tsan_write##size)
> +
> +DEFINE_TSAN_READ_WRITE(1);
> +DEFINE_TSAN_READ_WRITE(2);
> +DEFINE_TSAN_READ_WRITE(4);
> +DEFINE_TSAN_READ_WRITE(8);
> +DEFINE_TSAN_READ_WRITE(16);
> +
> +/*
> + * Not all supported compiler versions distinguish aligned/unaligned accesses,
> + * but e.g. recent versions of Clang do.
> + */
> +#define DEFINE_TSAN_UNALIGNED_READ_WRITE(size)                                 \
> +       void __tsan_unaligned_read##size(void *ptr)                            \
> +       {                                                                      \
> +               __kcsan_check_read(ptr, size);                                 \
> +       }                                                                      \
> +       EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
> +       void __tsan_unaligned_write##size(void *ptr)                           \
> +       {                                                                      \
> +               __kcsan_check_write(ptr, size);                                \
> +       }                                                                      \
> +       EXPORT_SYMBOL(__tsan_unaligned_write##size)
> +
> +DEFINE_TSAN_UNALIGNED_READ_WRITE(2);
> +DEFINE_TSAN_UNALIGNED_READ_WRITE(4);
> +DEFINE_TSAN_UNALIGNED_READ_WRITE(8);
> +DEFINE_TSAN_UNALIGNED_READ_WRITE(16);
> +
> +void __tsan_read_range(void *ptr, size_t size)
> +{
> +       __kcsan_check_read(ptr, size);
> +}
> +EXPORT_SYMBOL(__tsan_read_range);
> +
> +void __tsan_write_range(void *ptr, size_t size)
> +{
> +       __kcsan_check_write(ptr, size);
> +}
> +EXPORT_SYMBOL(__tsan_write_range);
> +
> +/*
> + * The below are not required KCSAN, but can still be emitted by the compiler.
> + */
> +void __tsan_func_entry(void *call_pc)
> +{
> +}
> +EXPORT_SYMBOL(__tsan_func_entry);
> +void __tsan_func_exit(void)
> +{
> +}
> +EXPORT_SYMBOL(__tsan_func_exit);
> +void __tsan_init(void)
> +{
> +}
> +EXPORT_SYMBOL(__tsan_init);
> diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
> new file mode 100644
> index 000000000000..429479b3041d
> --- /dev/null
> +++ b/kernel/kcsan/kcsan.h
> @@ -0,0 +1,140 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef _MM_KCSAN_KCSAN_H
> +#define _MM_KCSAN_KCSAN_H
> +
> +#include <linux/kcsan.h>
> +
> +/*
> + * Total number of watchpoints. An address range maps into a specific slot as
> + * specified in `encoding.h`. Although larger number of watchpoints may not even
> + * be usable due to limited thread count, a larger value will improve
> + * performance due to reducing cache-line contention.
> + */
> +#define KCSAN_NUM_WATCHPOINTS 64
> +
> +/*
> + * The number of adjacent watchpoints to check; the purpose is 2-fold:
> + *
> + *     1. the address slot is already occupied, check if any adjacent slots are
> + *        free;
> + *     2. accesses that straddle a slot boundary due to size that exceeds a
> + *        slot's range may check adjacent slots if any watchpoint matches.
> + *
> + * Note that accesses with very large size may still miss a watchpoint; however,
> + * given this should be rare, this is a reasonable trade-off to make, since this
> + * will avoid:
> + *
> + *     1. excessive contention between watchpoint checks and setup;
> + *     2. larger number of simultaneous watchpoints without sacrificing
> + *        performance.
> + */
> +#define KCSAN_CHECK_ADJACENT 1
> +
> +/*
> + * Globally enable and disable KCSAN.
> + */
> +extern bool kcsan_enabled;
> +
> +/*
> + * Helper that returns true if access to ptr should be considered as an atomic
> + * access, even though it is not explicitly atomic.
> + */
> +bool kcsan_is_atomic(const volatile void *ptr);
> +
> +/*
> + * Initialize debugfs file.
> + */
> +void kcsan_debugfs_init(void);
> +
> +enum kcsan_counter_id {
> +       /*
> +        * Number of watchpoints currently in use.
> +        */
> +       kcsan_counter_used_watchpoints,
> +
> +       /*
> +        * Total number of watchpoints set up.
> +        */
> +       kcsan_counter_setup_watchpoints,
> +
> +       /*
> +        * Total number of data-races.
> +        */
> +       kcsan_counter_data_races,
> +
> +       /*
> +        * Number of times no watchpoints were available.
> +        */
> +       kcsan_counter_no_capacity,
> +
> +       /*
> +        * A thread checking a watchpoint raced with another checking thread;
> +        * only one will be reported.
> +        */
> +       kcsan_counter_report_races,
> +
> +       /*
> +        * Observed data value change, but writer thread unknown.
> +        */
> +       kcsan_counter_races_unknown_origin,
> +
> +       /*
> +        * The access cannot be encoded to a valid watchpoint.
> +        */
> +       kcsan_counter_unencodable_accesses,
> +
> +       /*
> +        * Watchpoint encoding caused a watchpoint to fire on mismatching
> +        * accesses.
> +        */
> +       kcsan_counter_encoding_false_positives,
> +
> +       kcsan_counter_count, /* number of counters */
> +};
> +
> +/*
> + * Increment/decrement counter with given id; avoid calling these in fast-path.
> + */
> +void kcsan_counter_inc(enum kcsan_counter_id id);
> +void kcsan_counter_dec(enum kcsan_counter_id id);
> +
> +/*
> + * Returns true if data-races in the function symbol that maps to addr (offsets
> + * are ignored) should *not* be reported.
> + */
> +bool kcsan_skip_report(unsigned long func_addr);
> +
> +enum kcsan_report_type {
> +       /*
> +        * The thread that set up the watchpoint and briefly stalled was
> +        * signalled that another thread triggered the watchpoint, and thus a
> +        * race was encountered.
> +        */
> +       kcsan_report_race_setup,
> +
> +       /*
> +        * A thread encountered a watchpoint for the access, therefore a race
> +        * was encountered.
> +        */
> +       kcsan_report_race_check,
> +
> +       /*
> +        * A thread encountered a watchpoint for the access, but the other
> +        * racing thread can no longer be signaled that a race occurred.
> +        */
> +       kcsan_report_race_check_race,
> +
> +       /*
> +        * No other thread was observed to race with the access, but the data
> +        * value before and after the stall differs.
> +        */
> +       kcsan_report_race_unknown_origin,
> +};
> +/*
> + * Print a race report from thread that encountered the race.
> + */
> +void kcsan_report(const volatile void *ptr, size_t size, bool is_write,
> +                 int cpu_id, enum kcsan_report_type type);
> +
> +#endif /* _MM_KCSAN_KCSAN_H */
> diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
> new file mode 100644
> index 000000000000..517db539e4e7
> --- /dev/null
> +++ b/kernel/kcsan/report.c
> @@ -0,0 +1,306 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#include <linux/kernel.h>
> +#include <linux/preempt.h>
> +#include <linux/printk.h>
> +#include <linux/sched.h>
> +#include <linux/spinlock.h>
> +#include <linux/stacktrace.h>
> +
> +#include "kcsan.h"
> +#include "encoding.h"
> +
> +/*
> + * Max. number of stack entries to show in the report.
> + */
> +#define NUM_STACK_ENTRIES 16
> +
> +/*
> + * Other thread info: communicated from other racing thread to thread that set
> + * up the watchpoint, which then prints the complete report atomically. Only
> + * need one struct, as all threads should to be serialized regardless to print
> + * the reports, with reporting being in the slow-path.
> + */
> +static struct {
> +       const volatile void *ptr;
> +       size_t size;
> +       bool is_write;
> +       int task_pid;
> +       int cpu_id;
> +       unsigned long stack_entries[NUM_STACK_ENTRIES];
> +       int num_stack_entries;
> +} other_info = { .ptr = NULL };
> +
> +static DEFINE_SPINLOCK(other_info_lock);
> +static DEFINE_SPINLOCK(report_lock);
> +
> +static bool set_or_lock_other_info(unsigned long *flags,
> +                                  const volatile void *ptr, size_t size,
> +                                  bool is_write, int cpu_id,
> +                                  enum kcsan_report_type type)
> +{
> +       if (type != kcsan_report_race_check && type != kcsan_report_race_setup)
> +               return true;
> +
> +       for (;;) {
> +               spin_lock_irqsave(&other_info_lock, *flags);
> +
> +               switch (type) {
> +               case kcsan_report_race_check:
> +                       if (other_info.ptr != NULL) {
> +                               /* still in use, retry */
> +                               break;
> +                       }
> +                       other_info.ptr = ptr;
> +                       other_info.size = size;
> +                       other_info.is_write = is_write;
> +                       other_info.task_pid =
> +                               in_task() ? task_pid_nr(current) : -1;
> +                       other_info.cpu_id = cpu_id;
> +                       other_info.num_stack_entries = stack_trace_save(
> +                               other_info.stack_entries, NUM_STACK_ENTRIES, 1);
> +                       /*
> +                        * other_info may now be consumed by thread we raced
> +                        * with.
> +                        */
> +                       spin_unlock_irqrestore(&other_info_lock, *flags);
> +                       return false;
> +
> +               case kcsan_report_race_setup:
> +                       if (other_info.ptr == NULL)
> +                               break; /* no data available yet, retry */
> +
> +                       /*
> +                        * First check if matching based on how watchpoint was
> +                        * encoded.
> +                        */
> +                       if (!matching_access((unsigned long)other_info.ptr &
> +                                                    WATCHPOINT_ADDR_MASK,
> +                                            other_info.size,
> +                                            (unsigned long)ptr &
> +                                                    WATCHPOINT_ADDR_MASK,
> +                                            size))
> +                               break; /* mismatching access, retry */
> +
> +                       if (!matching_access((unsigned long)other_info.ptr,
> +                                            other_info.size,
> +                                            (unsigned long)ptr, size)) {
> +                               /*
> +                                * If the actual accesses to not match, this was
> +                                * a false positive due to watchpoint encoding.
> +                                */
> +                               other_info.ptr = NULL; /* mark for reuse */
> +                               kcsan_counter_inc(
> +                                       kcsan_counter_encoding_false_positives);
> +                               spin_unlock_irqrestore(&other_info_lock,
> +                                                      *flags);
> +                               return false;
> +                       }
> +
> +                       /*
> +                        * Matching access: keep other_info locked, as this
> +                        * thread uses it to print the full report; unlocked in
> +                        * end_report.
> +                        */
> +                       return true;
> +
> +               default:
> +                       BUG();
> +               }
> +
> +               spin_unlock_irqrestore(&other_info_lock, *flags);
> +       }
> +}
> +
> +static void start_report(unsigned long *flags, enum kcsan_report_type type)
> +{
> +       switch (type) {
> +       case kcsan_report_race_setup:
> +               /* irqsaved already via other_info_lock */
> +               spin_lock(&report_lock);
> +               break;
> +
> +       case kcsan_report_race_unknown_origin:
> +               spin_lock_irqsave(&report_lock, *flags);
> +               break;
> +
> +       default:
> +               BUG();
> +       }
> +}
> +
> +static void end_report(unsigned long *flags, enum kcsan_report_type type)
> +{
> +       switch (type) {
> +       case kcsan_report_race_setup:
> +               other_info.ptr = NULL; /* mark for reuse */
> +               spin_unlock(&report_lock);
> +               spin_unlock_irqrestore(&other_info_lock, *flags);
> +               break;
> +
> +       case kcsan_report_race_unknown_origin:
> +               spin_unlock_irqrestore(&report_lock, *flags);
> +               break;
> +
> +       default:
> +               BUG();
> +       }
> +}
> +
> +static const char *get_access_type(bool is_write)
> +{
> +       return is_write ? "write" : "read";
> +}
> +
> +/* Return thread description: in task or interrupt. */
> +static const char *get_thread_desc(int task_id)
> +{
> +       if (task_id != -1) {
> +               static char buf[32]; /* safe: protected by report_lock */
> +
> +               snprintf(buf, sizeof(buf), "task %i", task_id);
> +               return buf;
> +       }
> +       return in_nmi() ? "NMI" : "interrupt";
> +}
> +
> +/* Helper to skip KCSAN-related functions in stack-trace. */
> +static int get_stack_skipnr(unsigned long stack_entries[], int num_entries)
> +{
> +       char buf[64];
> +       int skip = 0;
> +
> +       for (; skip < num_entries; ++skip) {
> +               snprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
> +               if (!strnstr(buf, "csan_", sizeof(buf)) &&
> +                   !strnstr(buf, "tsan_", sizeof(buf)) &&
> +                   !strnstr(buf, "_once_size", sizeof(buf))) {
> +                       break;
> +               }
> +       }
> +       return skip;
> +}
> +
> +/* Compares symbolized strings of addr1 and addr2. */
> +static int sym_strcmp(void *addr1, void *addr2)
> +{
> +       char buf1[64];
> +       char buf2[64];
> +
> +       snprintf(buf1, sizeof(buf1), "%pS", addr1);
> +       snprintf(buf2, sizeof(buf2), "%pS", addr2);
> +       return strncmp(buf1, buf2, sizeof(buf1));
> +}
> +
> +/*
> + * Returns true if a report was generated, false otherwise.
> + */
> +static bool print_summary(const volatile void *ptr, size_t size, bool is_write,
> +                         int cpu_id, enum kcsan_report_type type)
> +{
> +       unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
> +       int num_stack_entries =
> +               stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
> +       int skipnr = get_stack_skipnr(stack_entries, num_stack_entries);
> +       int other_skipnr;
> +
> +       /* Check if the top stackframe is in a blacklisted function. */
> +       if (kcsan_skip_report(stack_entries[skipnr]))
> +               return false;
> +       if (type == kcsan_report_race_setup) {
> +               other_skipnr = get_stack_skipnr(other_info.stack_entries,
> +                                               other_info.num_stack_entries);
> +               if (kcsan_skip_report(other_info.stack_entries[other_skipnr]))
> +                       return false;
> +       }
> +
> +       /* Print report header. */
> +       pr_err("==================================================================\n");
> +       switch (type) {
> +       case kcsan_report_race_setup: {
> +               void *this_fn = (void *)stack_entries[skipnr];
> +               void *other_fn = (void *)other_info.stack_entries[other_skipnr];
> +               int cmp;
> +
> +               /*
> +                * Order functions lexographically for consistent bug titles.
> +                * Do not print offset of functions to keep title short.
> +                */
> +               cmp = sym_strcmp(other_fn, this_fn);
> +               pr_err("BUG: KCSAN: data-race in %ps / %ps\n",
> +                      cmp < 0 ? other_fn : this_fn,
> +                      cmp < 0 ? this_fn : other_fn);
> +       } break;
> +
> +       case kcsan_report_race_unknown_origin:
> +               pr_err("BUG: KCSAN: data-race in %pS\n",
> +                      (void *)stack_entries[skipnr]);
> +               break;
> +
> +       default:
> +               BUG();
> +       }
> +
> +       pr_err("\n");
> +
> +       /* Print information about the racing accesses. */
> +       switch (type) {
> +       case kcsan_report_race_setup:
> +               pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> +                      get_access_type(other_info.is_write), other_info.ptr,
> +                      other_info.size, get_thread_desc(other_info.task_pid),
> +                      other_info.cpu_id);
> +
> +               /* Print the other thread's stack trace. */
> +               stack_trace_print(other_info.stack_entries + other_skipnr,
> +                                 other_info.num_stack_entries - other_skipnr,
> +                                 0);
> +
> +               pr_err("\n");
> +               pr_err("%s to 0x%px of %zu bytes by %s on cpu %i:\n",
> +                      get_access_type(is_write), ptr, size,
> +                      get_thread_desc(in_task() ? task_pid_nr(current) : -1),
> +                      cpu_id);
> +               break;
> +
> +       case kcsan_report_race_unknown_origin:
> +               pr_err("race at unknown origin, with %s to 0x%px of %zu bytes by %s on cpu %i:\n",
> +                      get_access_type(is_write), ptr, size,
> +                      get_thread_desc(in_task() ? task_pid_nr(current) : -1),
> +                      cpu_id);
> +               break;
> +
> +       default:
> +               BUG();
> +       }
> +       /* Print stack trace of this thread. */
> +       stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
> +                         0);
> +
> +       /* Print report footer. */
> +       pr_err("\n");
> +       pr_err("Reported by Kernel Concurrency Sanitizer on:\n");
> +       dump_stack_print_info(KERN_DEFAULT);
> +       pr_err("==================================================================\n");
> +
> +       return true;
> +}
> +
> +void kcsan_report(const volatile void *ptr, size_t size, bool is_write,
> +                 int cpu_id, enum kcsan_report_type type)
> +{
> +       unsigned long flags = 0;
> +
> +       if (type == kcsan_report_race_check_race)
> +               return;
> +
> +       kcsan_disable_current();
> +       if (set_or_lock_other_info(&flags, ptr, size, is_write, cpu_id, type)) {
> +               start_report(&flags, type);
> +               if (print_summary(ptr, size, is_write, cpu_id, type) &&
> +                   panic_on_warn)
> +                       panic("panic_on_warn set ...\n");
> +               end_report(&flags, type);
> +       }
> +       kcsan_enable_current();
> +}
> diff --git a/kernel/kcsan/test.c b/kernel/kcsan/test.c
> new file mode 100644
> index 000000000000..68c896a24529
> --- /dev/null
> +++ b/kernel/kcsan/test.c
> @@ -0,0 +1,117 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#include <linux/init.h>
> +#include <linux/kernel.h>
> +#include <linux/printk.h>
> +#include <linux/random.h>
> +#include <linux/types.h>
> +
> +#include "encoding.h"
> +
> +#define ITERS_PER_TEST 2000
> +
> +/* Test requirements. */
> +static bool test_requires(void)
> +{
> +       /* random should be initialized */
> +       return prandom_u32() + prandom_u32() != 0;
> +}
> +
> +/* Test watchpoint encode and decode. */
> +static bool test_encode_decode(void)
> +{
> +       int i;
> +
> +       for (i = 0; i < ITERS_PER_TEST; ++i) {
> +               size_t size = prandom_u32() % MAX_ENCODABLE_SIZE + 1;
> +               bool is_write = prandom_u32() % 2;
> +               unsigned long addr;
> +
> +               prandom_bytes(&addr, sizeof(addr));
> +               if (WARN_ON(!check_encodable(addr, size)))
> +                       return false;
> +
> +               /* encode and decode */
> +               {
> +                       const long encoded_watchpoint =
> +                               encode_watchpoint(addr, size, is_write);
> +                       unsigned long verif_masked_addr;
> +                       size_t verif_size;
> +                       bool verif_is_write;
> +
> +                       /* check special watchpoints */
> +                       if (WARN_ON(decode_watchpoint(
> +                                   INVALID_WATCHPOINT, &verif_masked_addr,
> +                                   &verif_size, &verif_is_write)))
> +                               return false;
> +                       if (WARN_ON(decode_watchpoint(
> +                                   CONSUMED_WATCHPOINT, &verif_masked_addr,
> +                                   &verif_size, &verif_is_write)))
> +                               return false;
> +
> +                       /* check decoding watchpoint returns same data */
> +                       if (WARN_ON(!decode_watchpoint(
> +                                   encoded_watchpoint, &verif_masked_addr,
> +                                   &verif_size, &verif_is_write)))
> +                               return false;
> +                       if (WARN_ON(verif_masked_addr !=
> +                                   (addr & WATCHPOINT_ADDR_MASK)))
> +                               goto fail;
> +                       if (WARN_ON(verif_size != size))
> +                               goto fail;
> +                       if (WARN_ON(is_write != verif_is_write))
> +                               goto fail;
> +
> +                       continue;
> +fail:
> +                       pr_err("%s fail: %s %zu bytes @ %lx -> encoded: %lx -> %s %zu bytes @ %lx\n",
> +                              __func__, is_write ? "write" : "read", size,
> +                              addr, encoded_watchpoint,
> +                              verif_is_write ? "write" : "read", verif_size,
> +                              verif_masked_addr);
> +                       return false;
> +               }
> +       }
> +
> +       return true;
> +}
> +
> +static bool test_matching_access(void)
> +{
> +       if (WARN_ON(!matching_access(10, 1, 10, 1)))
> +               return false;
> +       if (WARN_ON(!matching_access(10, 2, 11, 1)))
> +               return false;
> +       if (WARN_ON(!matching_access(10, 1, 9, 2)))
> +               return false;
> +       if (WARN_ON(matching_access(10, 1, 11, 1)))
> +               return false;
> +       if (WARN_ON(matching_access(9, 1, 10, 1)))
> +               return false;
> +       return true;
> +}
> +
> +static int __init kcsan_selftest(void)
> +{
> +       int passed = 0;
> +       int total = 0;
> +
> +#define RUN_TEST(do_test)                                                      \
> +       do {                                                                   \
> +               ++total;                                                       \
> +               if (do_test())                                                 \
> +                       ++passed;                                              \
> +               else                                                           \
> +                       pr_err("KCSAN selftest: " #do_test " failed");         \
> +       } while (0)
> +
> +       RUN_TEST(test_requires);
> +       RUN_TEST(test_encode_decode);
> +       RUN_TEST(test_matching_access);
> +
> +       pr_info("KCSAN selftest: %d/%d tests passed\n", passed, total);
> +       if (passed != total)
> +               panic("KCSAN selftests failed");
> +       return 0;
> +}
> +postcore_initcall(kcsan_selftest);
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 93d97f9b0157..35accd1d93de 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -2086,6 +2086,8 @@ source "lib/Kconfig.kgdb"
>
>  source "lib/Kconfig.ubsan"
>
> +source "lib/Kconfig.kcsan"
> +
>  config ARCH_HAS_DEVMEM_IS_ALLOWED
>         bool
>
> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> new file mode 100644
> index 000000000000..3e1f1acfb24b
> --- /dev/null
> +++ b/lib/Kconfig.kcsan
> @@ -0,0 +1,88 @@
> +# SPDX-License-Identifier: GPL-2.0-only
> +
> +config HAVE_ARCH_KCSAN
> +       bool
> +
> +menuconfig KCSAN
> +       bool "KCSAN: watchpoint-based dynamic data-race detector"
> +       depends on HAVE_ARCH_KCSAN && !KASAN && STACKTRACE
> +       default n
> +       help
> +         Kernel Concurrency Sanitizer is a dynamic data-race detector, which
> +         uses a watchpoint-based sampling approach to detect races.

It can make sense to provide a reference to the doc with full details here.

> +if KCSAN
> +
> +config KCSAN_SELFTEST
> +       bool "KCSAN: perform short selftests on boot"

All of these configs are already inside of KCSAN submenu, so it's not
necessary to prefix all of them with "KCSAN:".

> +       default y
> +       help
> +         Run KCSAN selftests on boot. On test failure, causes kernel to panic.
> +
> +config KCSAN_EARLY_ENABLE
> +       bool "KCSAN: early enable"
> +       default y
> +       help
> +         If KCSAN should be enabled globally as soon as possible. KCSAN can
> +         later be enabled/disabled via debugfs.
> +
> +config KCSAN_UDELAY_MAX_TASK
> +       int "KCSAN: maximum delay in microseconds (for tasks)"
> +       default 80
> +       help
> +         For tasks, the max. microsecond delay after setting up a watchpoint.
> +
> +config KCSAN_UDELAY_MAX_INTERRUPT
> +       int "KCSAN: maximum delay in microseconds (for interrupts)"
> +       default 20
> +       help
> +         For interrupts, the max. microsecond delay after setting up a watchpoint.
> +
> +config KCSAN_DELAY_RANDOMIZE
> +       bool "KCSAN: randomize delays"
> +       default y
> +       help
> +         If delays should be randomized; if false, the chosen delay is simply
> +         the maximum values defined above.
> +
> +config KCSAN_WATCH_SKIP_INST
> +       int "KCSAN: watchpoint instruction skip"
> +       default 2000
> +       help
> +         The number of per-CPU memory operations to skip watching, before
> +         another watchpoint is set up; in other words, 1 in
> +         KCSAN_WATCH_SKIP_INST per-CPU memory operations are used to set up a
> +         watchpoint. A smaller value results in more aggressive race
> +         detection, whereas a larger value improves system performance at the
> +         cost of missing some races.
> +
> +config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
> +       bool "KCSAN: report races of unknown origin"
> +       default y
> +       help
> +         If KCSAN should report races where only one access is known, and the
> +         conflicting access is of unknown origin. This type of race is
> +         reported if it was only possible to infer a race due to a data-value
> +         change while an access is being delayed on a watchpoint.
> +
> +config KCSAN_IGNORE_ATOMICS
> +       bool "KCSAN: do not instrument marked atomic accesses"
> +       default n
> +       help
> +         If enabled, never instruments marked atomic accesses. This results in
> +         not reporting data-races where one access is atomic and the other is
> +         a plain access.
> +
> +config KCSAN_PLAIN_WRITE_PRETEND_ONCE
> +       bool "KCSAN: pretend plain writes are WRITE_ONCE"
> +       default n
> +       help
> +         This option makes KCSAN pretend that all plain writes are WRITE_ONCE.
> +         This option should only be used to prune initial data-races found in
> +         existing code.
> +
> +config KCSAN_DEBUG
> +       bool "Debugging of KCSAN internals"
> +       default n
> +
> +endif # KCSAN
> diff --git a/lib/Makefile b/lib/Makefile
> index c5892807e06f..778ab704e3ad 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -24,6 +24,9 @@ KASAN_SANITIZE_string.o := n
>  CFLAGS_string.o := $(call cc-option, -fno-stack-protector)
>  endif
>
> +# Used by KCSAN while enabled, avoid recursion.
> +KCSAN_SANITIZE_random32.o := n
> +
>  lib-y := ctype.o string.o vsprintf.o cmdline.o \
>          rbtree.o radix-tree.o timerqueue.o xarray.o \
>          idr.o extable.o \
> diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
> new file mode 100644
> index 000000000000..caf1111a28ae
> --- /dev/null
> +++ b/scripts/Makefile.kcsan
> @@ -0,0 +1,6 @@
> +# SPDX-License-Identifier: GPL-2.0
> +ifdef CONFIG_KCSAN
> +
> +CFLAGS_KCSAN := -fsanitize=thread
> +
> +endif # CONFIG_KCSAN
> diff --git a/scripts/Makefile.lib b/scripts/Makefile.lib
> index 179d55af5852..0e78abab7d83 100644
> --- a/scripts/Makefile.lib
> +++ b/scripts/Makefile.lib
> @@ -152,6 +152,16 @@ _c_flags += $(if $(patsubst n%,, \
>         $(CFLAGS_KCOV))
>  endif
>
> +#
> +# Enable ConcurrencySanitizer flags for kernel except some files or directories
> +# we don't want to check (depends on variables KCSAN_SANITIZE_obj.o, KCSAN_SANITIZE)
> +#
> +ifeq ($(CONFIG_KCSAN),y)
> +_c_flags += $(if $(patsubst n%,, \
> +       $(KCSAN_SANITIZE_$(basetarget).o)$(KCSAN_SANITIZE)y), \
> +       $(CFLAGS_KCSAN))
> +endif
> +
>  # $(srctree)/$(src) for including checkin headers from generated source files
>  # $(objtree)/$(obj) for including generated headers from checkin source files
>  ifeq ($(KBUILD_EXTMOD),)
> --
> 2.23.0.866.gb869b98d4c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbTY6EWhv3Q%3DBDee6Db%3DuxqxfNgifLDNRmOmpdH6%3DhUGQ%40mail.gmail.com.
