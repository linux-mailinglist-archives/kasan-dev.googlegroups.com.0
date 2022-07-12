Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJPJWWLAMGQE5PX72BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F4D1571AFD
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 15:18:31 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id i8-20020a056e021d0800b002dc704e34a5sf4337851ila.13
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 06:18:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657631910; cv=pass;
        d=google.com; s=arc-20160816;
        b=S7kbspnFSGltzLx9Eptv5GERlacNS+8vItGzccUmiaZmL+Fx0fK+bl2JFNb+yROVvz
         M34Vy7vD9vIfkwN4rjLR8HUkNfBha9PHbgW31LAIJl/Jxh8Hfn2ULHc2oECKD3aje0/7
         Wl45ANIQCT6mDapkCRXpHYy3F/3J8HBvUD9M3b6OH2ObBRN7hhw1TCmM7YPgeO88cp6B
         XRHvfki+h+8arpQLitPLDdksFRLih46CGIBhfqWwxG3z1jWNaLxZdeKfqX7/RF0fuB22
         0jkIZnlozYTuiX6Q3o9a7WCeWqPzKTp5GGtyrbEia54nGYO+UUXQ+WobW5pIuH6uwgqp
         iEMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vdLk0ILMvzLKMcG4n4IU6JvhjeM6RyQJjiJKvxSfa9A=;
        b=pUQtuenbB2pQm2BovrjVmMEjcbp22j96rUhThWxIryvv5YsYe+om92x6Xb+eRUSTVA
         Km8PB1FgWhknuQRPqNRVDOxlSaTFQe1SbjzWDKvlbp65kGVc2x7E8H/benOspZF3gEM7
         29V6SEauxFDgXFxHYsuDnBJwriu334wjavkZt3GvSW0xONKZu4/3sdI5DecIXivMBoH3
         hsa9s174rloDZ2bUUWLlof6KmfqGaz/8xf0Lf/F8tBhWdeVBzhp0RqGzkS9mAYSKZcZX
         fRCIe/ZZMwZ/LHpfylA2qmLKT37L4JNl28FCYhCPBzFKuwsvwrSx5/Gi59pGty/ob3Q4
         vYyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fBcmdT6+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vdLk0ILMvzLKMcG4n4IU6JvhjeM6RyQJjiJKvxSfa9A=;
        b=G/4erXZdjTKJjLALozLGCc0ksP4Go1veRJ/P1kYaFiuKpTefx3Oib9zSCxpyhyMfJX
         Nt6KScT/N0tBcATDHmIW55UAmaKaT5o8YTyQAA8o3ZRfXq6c7s4UHQpYSjSUtQ9bbXIQ
         P6hEDmErVQ6e639sAfCXmzHlVrSntvcRGrFknVOXYHsf0WPBSIBeHw1G8+vRYQ8bCNWH
         6+G8Abg2cmCHuTsiT5mhP5Cj1GKbKfQdhOypDQ8/gIAaT83a6/mUn3S71ur3kuwjhBiB
         sgjcYJd8/8C0vSK1v/hGofglNAtzGhJrbaV+MCLgD53o+PODtxY3QY+gfMtloaf86Kun
         XF1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vdLk0ILMvzLKMcG4n4IU6JvhjeM6RyQJjiJKvxSfa9A=;
        b=z3qC2SAtzZCWxIW2XjBy08D1vS0UfjasiePAepCGLMiijA29N8z8PMgUB/FJdC6gzy
         lFzmvUqAH5FH4Ilzm8XVUpCFYSb5onYCdp/m3encoezNsr2k/nRfZlVSXCYKN8jL12UU
         6EjdVsA0oEU94iVC6HxhChRCYKQ9hIImu5hEXKUjW0SkFTMzae2/BqjldJMpYQbXF2fN
         NDULzNb2tMygxo87IjBl0A2AVUG0XCicnEPq9D5ewKUu6+MskMjyX5rwdnDpGtm/b52b
         o2YGYOa7thjt8F075k2e77WCAGiD6qlmDxOsI1CP0HFPL7tVUkAVA5N29W9nRC1kGmIR
         spSw==
X-Gm-Message-State: AJIora87WrwpqWQCtMTx13i6n748R6AArzUFiyW7YMb3zadE9krvJVN9
	CpjPXg4P8fKCtDnZkpfc8qc=
X-Google-Smtp-Source: AGRyM1uSOGFfBBuGIeOce5DgqeprFworKVG9ZTKzm6zvPjZ9mZSKlomV0gvJ1t91ua8ASrxVs7F8Xg==
X-Received: by 2002:a05:6e02:1b8d:b0:2dc:73d4:f2ad with SMTP id h13-20020a056e021b8d00b002dc73d4f2admr7651388ili.156.1657631910124;
        Tue, 12 Jul 2022 06:18:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3711:b0:33c:9eec:3773 with SMTP id
 k17-20020a056638371100b0033c9eec3773ls445545jav.10.gmail; Tue, 12 Jul 2022
 06:18:29 -0700 (PDT)
X-Received: by 2002:a05:6638:f95:b0:314:58f9:5896 with SMTP id h21-20020a0566380f9500b0031458f95896mr12977447jal.228.1657631909221;
        Tue, 12 Jul 2022 06:18:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657631909; cv=none;
        d=google.com; s=arc-20160816;
        b=Z+e+WJTFYKiLQ+uR1sdYcs+U6kT1F9Q2aGpSryQvURCr4Y6MZIbTW2ee9pWGzy9ScI
         uL7xcntQ+Uv40nkfFjoDV7QFKgsHZmZlzTDNOrEz0vQzzx/1nKyLQmDyeNVaiyF6SyK2
         bJAashwp+piddP2me8vf6EzLqEfUbDp6EXsURdnPuEo7RrHKu80dQq6fawGjelaGM+B8
         EddoOMc2DkYg67/B0Bb/EIkQlcPfUXwk2WNxmxk/+kU+HBiZ+ME5TA5kmgHIjJPnnryU
         vEL686cI59bXmEMB+gh6HMHE4sJgAXppX5QAFxd0OaZUSi2KZmtfQxL8bvmn0eIJhL1M
         xhJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yN+yeyjG1qKP+1Pj2TR7+x/fenSy0T+ddQvCTNkV1Ls=;
        b=0tOijk9t2vjmpF0C6qKTwehAPljjmKu64d5io4bKNJa8g7xkVKw5DpeSDSIsTqxLTm
         OOBkZsVKQe4HegMHR45QPes6H/290+BFCNjyKvAmv3nVpjhLIarrKq5iK/AbC0vRw7n6
         mzqBB9Mkf2lCuuOjdjckDTzBrPYh7oZf4cfYxwKsWY0aomZwPoXhlTH+6z/F+9YLzTdT
         PDvexYeBYJ6lHwKDJtTZ/Q7K2GxUBwQtjNQ6k8RVB9nnexaG7bj+A802VFPkBvK6AH9/
         BMr0CFQSzmx7tlWUiQZ2jhdQyeT4/ranpIZRuncTlgSEat5MXLumdg+dSaG5A5L1amFk
         2GdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=fBcmdT6+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id b13-20020a056e020c8d00b002da79182b3fsi269681ile.2.2022.07.12.06.18.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 06:18:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-31c8a1e9e33so80556137b3.5
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 06:18:29 -0700 (PDT)
X-Received: by 2002:a81:4685:0:b0:31c:1bd1:56c7 with SMTP id
 t127-20020a814685000000b0031c1bd156c7mr24638722ywa.333.1657631908790; Tue, 12
 Jul 2022 06:18:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-17-glider@google.com>
In-Reply-To: <20220701142310.2188015-17-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 15:17:52 +0200
Message-ID: <CANpmjNOM8RdTPF_JeoiJahkLPPj6jH2s=hyTOSQpXzTBSDqeAQ@mail.gmail.com>
Subject: Re: [PATCH v4 16/45] kmsan: handle task creation and exiting
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=fBcmdT6+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, 1 Jul 2022 at 16:24, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Tell KMSAN that a new task is created, so the tool creates a backing
> metadata structure for that task.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v2:
>  -- move implementation of kmsan_task_create() and kmsan_task_exit() here
>
> v4:
>  -- change sizeof(type) to sizeof(*ptr)
>
> Link: https://linux-review.googlesource.com/id/I0f41c3a1c7d66f7e14aabcfdfc7c69addb945805
> ---
>  include/linux/kmsan.h | 17 +++++++++++++++++
>  kernel/exit.c         |  2 ++
>  kernel/fork.c         |  2 ++
>  mm/kmsan/core.c       | 10 ++++++++++
>  mm/kmsan/hooks.c      | 19 +++++++++++++++++++
>  mm/kmsan/kmsan.h      |  2 ++
>  6 files changed, 52 insertions(+)
>
> diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> index fd76cea338878..b71e2032222e9 100644
> --- a/include/linux/kmsan.h
> +++ b/include/linux/kmsan.h
> @@ -16,6 +16,7 @@
>
>  struct page;
>  struct kmem_cache;
> +struct task_struct;
>
>  #ifdef CONFIG_KMSAN
>
> @@ -42,6 +43,14 @@ struct kmsan_ctx {
>         bool allow_reporting;
>  };
>
> +void kmsan_task_create(struct task_struct *task);
> +
> +/**
> + * kmsan_task_exit() - Notify KMSAN that a task has exited.
> + * @task: task about to finish.
> + */
> +void kmsan_task_exit(struct task_struct *task);
> +
>  /**
>   * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
>   * @page:  struct page pointer returned by alloc_pages().
> @@ -163,6 +172,14 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
>
>  #else
>
> +static inline void kmsan_task_create(struct task_struct *task)
> +{
> +}
> +
> +static inline void kmsan_task_exit(struct task_struct *task)
> +{
> +}
> +
>  static inline int kmsan_alloc_page(struct page *page, unsigned int order,
>                                    gfp_t flags)
>  {
> diff --git a/kernel/exit.c b/kernel/exit.c
> index f072959fcab7f..1784b7a741ddd 100644
> --- a/kernel/exit.c
> +++ b/kernel/exit.c
> @@ -60,6 +60,7 @@
>  #include <linux/writeback.h>
>  #include <linux/shm.h>
>  #include <linux/kcov.h>
> +#include <linux/kmsan.h>
>  #include <linux/random.h>
>  #include <linux/rcuwait.h>
>  #include <linux/compat.h>
> @@ -741,6 +742,7 @@ void __noreturn do_exit(long code)
>         WARN_ON(tsk->plug);
>
>         kcov_task_exit(tsk);
> +       kmsan_task_exit(tsk);
>
>         coredump_task_exit(tsk);
>         ptrace_event(PTRACE_EVENT_EXIT, code);
> diff --git a/kernel/fork.c b/kernel/fork.c
> index 9d44f2d46c696..6dfca6f00ec82 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -37,6 +37,7 @@
>  #include <linux/fdtable.h>
>  #include <linux/iocontext.h>
>  #include <linux/key.h>
> +#include <linux/kmsan.h>
>  #include <linux/binfmts.h>
>  #include <linux/mman.h>
>  #include <linux/mmu_notifier.h>
> @@ -1026,6 +1027,7 @@ static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
>         tsk->worker_private = NULL;
>
>         kcov_task_init(tsk);
> +       kmsan_task_create(tsk);
>         kmap_local_fork(tsk);
>
>  #ifdef CONFIG_FAULT_INJECTION
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index 16fb8880a9c6d..7eabed03ed10b 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -44,6 +44,16 @@ bool kmsan_enabled __read_mostly;
>   */
>  DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
>
> +void kmsan_internal_task_create(struct task_struct *task)
> +{
> +       struct kmsan_ctx *ctx = &task->kmsan_ctx;
> +       struct thread_info *info = current_thread_info();
> +
> +       __memset(ctx, 0, sizeof(*ctx));
> +       ctx->allow_reporting = true;
> +       kmsan_internal_unpoison_memory(info, sizeof(*info), false);
> +}
> +
>  void kmsan_internal_poison_memory(void *address, size_t size, gfp_t flags,
>                                   unsigned int poison_flags)
>  {
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 052e17b7a717d..43a529569053d 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -26,6 +26,25 @@
>   * skipping effects of functions like memset() inside instrumented code.
>   */
>
> +void kmsan_task_create(struct task_struct *task)
> +{
> +       kmsan_enter_runtime();
> +       kmsan_internal_task_create(task);
> +       kmsan_leave_runtime();
> +}
> +EXPORT_SYMBOL(kmsan_task_create);
> +
> +void kmsan_task_exit(struct task_struct *task)
> +{
> +       struct kmsan_ctx *ctx = &task->kmsan_ctx;
> +
> +       if (!kmsan_enabled || kmsan_in_runtime())
> +               return;
> +
> +       ctx->allow_reporting = false;
> +}
> +EXPORT_SYMBOL(kmsan_task_exit);

Why are these EXPORT_SYMBOL? Will they be used from some kernel module?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOM8RdTPF_JeoiJahkLPPj6jH2s%3DhyTOSQpXzTBSDqeAQ%40mail.gmail.com.
