Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSUOUWLQMGQEMQ7OXIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 89808587F36
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 17:48:26 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id n19-20020a05600c3b9300b003a314062cf4sf774520wms.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 08:48:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659455306; cv=pass;
        d=google.com; s=arc-20160816;
        b=S5QQ3ymnHQ01OeHlF79Nn8kOokA4pI2FWbPRG+xh1X5hpDGftAFH8R9HvxQ0vGKFhQ
         LoZ5mUZrJkAj6NSecaOBYaqBI5LYIzvu+hCLS74WMDEHVq+4a/aHw+8UQrEcoqx5YDWD
         SMLKpHrOtyCX8L0T7/f3ahHfot2leRauIobsWPn9pNlVTe0Tp4DufWoY+mtp8VBPzxTR
         1+kXseJUDao+N4JAA+bNE89LqbUB/7UwZ2Kq647GqxDHvIu4+2kqjc1FMcGra9wrOabF
         6jJ2bZawcx0wSoqBaiqpwnHGNEM+fs+Gdp9yQb+aXYq0VSnyPaBu2mzIohO0a+Iup6a4
         gfQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=44PNyZNpR41ZIsE7m2kVUEq1+/VLfKvU66S8Q0jp/RE=;
        b=iqO1kaytvgV0DdV7HBejO50VIWUfQC6bzJoadUyp532HFJobADqUjGvWV8+IEhBPkJ
         i6aX9EpKbrOq0tlRr6gtxHqCZBQpMjeeX56/jQhmCJcy+PVgSWqT06k8/QqTKNeni0rj
         HEX9wFjLDMICKIiA8Y9Xs8CvK4jHZy6G+/BnRBXkJv+IY0qBCLYU0bVx88/Cn7zDXvCl
         gB1M1svOK0drk1GShZeTwSA5Ys9oPsXJn28iSxidbP57eOUURfIb8VX6PRX/Fiw1iz5A
         O3eeyJZt02gqXU89dH94rGunSDvfygj7ZU0NliqIixaNSH+CXxzUXDP4ASydCM1rOEX3
         Z0MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=k0qIjj7C;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=44PNyZNpR41ZIsE7m2kVUEq1+/VLfKvU66S8Q0jp/RE=;
        b=HGr0vGwbuoO2NrXaf3HJygcOrksH+rYrx/cGsTozcpkJ7EL6CBrpykABi/Ep6kJi+F
         2N5AoCVfFMYeoI0GXcqDOH7zC6SjtuCs/E3tZviki3rPKlRqWU8+g6SaWIqObWFqPwjp
         ofYZ78xuMxwg7fZvlwHLZVZYLg3GfwbnFOmyUhWoGulF4ZECrWcSCUNb4g9laGchjh2k
         VEH/ihDJCMZrVovUDIdIOy2mxCg9HJQ2VrDgJHQWl0woO5EXf6TWeRcWzwYJvnifrg8V
         pKGzAnf/CjnAba0/gMRpsyUArEfNgmCAHkpyYi6TkIWOdEB0jK2bJkyv5SMS9aT0cEX1
         g1Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=44PNyZNpR41ZIsE7m2kVUEq1+/VLfKvU66S8Q0jp/RE=;
        b=vDmZONfrns9n1WTNY1ZJIa4nfJu0wlJFslCEDQBzuS8+xj3r0oNt1WrLiTasVjumEl
         n6gztECDv2C1pToqD+5AErsePHNfEuQhaanAZ1Ylmt+LgJe0kI39AxgZWkDnExKs8Wh2
         XlHQN7dHjXZZywZqq6mCTNTKsb98RGjAM9eob2QGaTSXzPAojB2GLXsFO8HEEOiRlbQb
         qHEnOtW9AYDIKXznQSeKkXOoRd3xj1bJx6ui9Ph7LvrtHLN9kvATWsvBjr8RP4CQ0rVw
         08hmfDYXpErCorsxfyEsEEA3hZea9NRHg/4Quqv9gZju0v7cgiZ7Pc3xymgLWxjFhof0
         OLnQ==
X-Gm-Message-State: ACgBeo1sSur5fSosx1aJvkwbwoAwOjSJT2/qiIovUKosywEOza08gD/K
	zWEdjRsKv4VvGmMh6MdoW2c=
X-Google-Smtp-Source: AA6agR6vsZgYCH5buei0yux01Sz84wxSwRtEz4+0XGITUQRPQlsMXDGZRAcQ5w05xZCdI5sId+t80w==
X-Received: by 2002:a05:600c:1e1d:b0:3a4:f0b1:dd0b with SMTP id ay29-20020a05600c1e1d00b003a4f0b1dd0bmr70448wmb.138.1659455306223;
        Tue, 02 Aug 2022 08:48:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:253:b0:21d:a0b5:24ab with SMTP id
 m19-20020a056000025300b0021da0b524abls17895281wrz.1.-pod-prod-gmail; Tue, 02
 Aug 2022 08:48:24 -0700 (PDT)
X-Received: by 2002:a05:6000:2cc:b0:21e:e8c1:2704 with SMTP id o12-20020a05600002cc00b0021ee8c12704mr14538376wry.378.1659455304629;
        Tue, 02 Aug 2022 08:48:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659455304; cv=none;
        d=google.com; s=arc-20160816;
        b=wMO6YHSpkGhL/WuxL//h/ZlJTRQxpIXhEOp56vPRg/t5uckC+XyyVZAh8zzJhDFprg
         JSrINC7cl9xyYdOq3Hx/b7L3XYXV2s3T9oMp6GanLF9K1cBRjuA9o367l5qR6qv+plfE
         VYSMiHAZFxm00v/6Qjys/C0QV649QXQ6jK6rHGGNRRXIEC4BqJfNpSp4H55PKXdcuorD
         E+g6UirRUVE2Xzw8w7G7QBZVnTIdT2nyojoq5jAVKxpnZd3rrSNWJOOKnBbI8AtUh0o5
         fKqeCOMiJwC4GxZ9xLorDVtczxSncbw8l1XbViXy+nXo/+tbh7RmbOLv6P/G29Fl9+2n
         a9QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=At7GobCcr6Y9heni/Yduc1l7sWHbyaA1znBRmpamTcU=;
        b=Jt7vd4LkISwOKEH8kETsOFOuL5az7y9Rh6TGcccc5uPq++bNRzjpRmlMYXkLs4RPmN
         Mysm4rcgqUo4H3f7qxi+vDDoLFxZ+DfzcVfh0Fjt5xIzolhTMGYHVYBhFYw0VC5HrQ4R
         b0rx4ODs/3NDBnpDPElax8ePigtJNy/IHi0aOiDQVuTTOQIQUckcovdpqVzN/RdmXs/A
         cfZq3LuYpnAETW5x67IXRnKNrY5eIJ673foKD3k1YwVBxHqeZKRNwqLotBGHTb4ZI/Pr
         7fQ/9jNnQuqE4KCdxlWmPBtMN7L2m++FruK7XxRGxtiyfHbZrFkbQ61u7W5vH9KJrKwj
         60Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=k0qIjj7C;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id n23-20020a7bc5d7000000b003a03ade6826si749877wmk.0.2022.08.02.08.48.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 08:48:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id l22so18440463wrz.7
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 08:48:24 -0700 (PDT)
X-Received: by 2002:a05:6000:2c1:b0:220:5f91:62de with SMTP id
 o1-20020a05600002c100b002205f9162demr8238093wry.715.1659455304037; Tue, 02
 Aug 2022 08:48:24 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-17-glider@google.com>
 <CANpmjNOM8RdTPF_JeoiJahkLPPj6jH2s=hyTOSQpXzTBSDqeAQ@mail.gmail.com>
In-Reply-To: <CANpmjNOM8RdTPF_JeoiJahkLPPj6jH2s=hyTOSQpXzTBSDqeAQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 17:47:47 +0200
Message-ID: <CAG_fn=Xu+sGe-6Yv9J8LDScOP-eBze4iNqCsyY2igirHKPCt7g@mail.gmail.com>
Subject: Re: [PATCH v4 16/45] kmsan: handle task creation and exiting
To: Marco Elver <elver@google.com>
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
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=k0qIjj7C;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::432 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jul 12, 2022 at 3:18 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 Jul 2022 at 16:24, 'Alexander Potapenko' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Tell KMSAN that a new task is created, so the tool creates a backing
> > metadata structure for that task.
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> > v2:
> >  -- move implementation of kmsan_task_create() and kmsan_task_exit() here
> >
> > v4:
> >  -- change sizeof(type) to sizeof(*ptr)
> >
> > Link: https://linux-review.googlesource.com/id/I0f41c3a1c7d66f7e14aabcfdfc7c69addb945805
> > ---
> >  include/linux/kmsan.h | 17 +++++++++++++++++
> >  kernel/exit.c         |  2 ++
> >  kernel/fork.c         |  2 ++
> >  mm/kmsan/core.c       | 10 ++++++++++
> >  mm/kmsan/hooks.c      | 19 +++++++++++++++++++
> >  mm/kmsan/kmsan.h      |  2 ++
> >  6 files changed, 52 insertions(+)
> >
> > diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> > index fd76cea338878..b71e2032222e9 100644
> > --- a/include/linux/kmsan.h
> > +++ b/include/linux/kmsan.h
> > @@ -16,6 +16,7 @@
> >
> >  struct page;
> >  struct kmem_cache;
> > +struct task_struct;
> >
> >  #ifdef CONFIG_KMSAN
> >
> > @@ -42,6 +43,14 @@ struct kmsan_ctx {
> >         bool allow_reporting;
> >  };
> >
> > +void kmsan_task_create(struct task_struct *task);
> > +
> > +/**
> > + * kmsan_task_exit() - Notify KMSAN that a task has exited.
> > + * @task: task about to finish.
> > + */
> > +void kmsan_task_exit(struct task_struct *task);
> > +
> >  /**
> >   * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
> >   * @page:  struct page pointer returned by alloc_pages().
> > @@ -163,6 +172,14 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end);
> >
> >  #else
> >
> > +static inline void kmsan_task_create(struct task_struct *task)
> > +{
> > +}
> > +
> > +static inline void kmsan_task_exit(struct task_struct *task)
> > +{
> > +}
> > +
> >  static inline int kmsan_alloc_page(struct page *page, unsigned int order,
> >                                    gfp_t flags)
> >  {
> > diff --git a/kernel/exit.c b/kernel/exit.c
> > index f072959fcab7f..1784b7a741ddd 100644
> > --- a/kernel/exit.c
> > +++ b/kernel/exit.c
> > @@ -60,6 +60,7 @@
> >  #include <linux/writeback.h>
> >  #include <linux/shm.h>
> >  #include <linux/kcov.h>
> > +#include <linux/kmsan.h>
> >  #include <linux/random.h>
> >  #include <linux/rcuwait.h>
> >  #include <linux/compat.h>
> > @@ -741,6 +742,7 @@ void __noreturn do_exit(long code)
> >         WARN_ON(tsk->plug);
> >
> >         kcov_task_exit(tsk);
> > +       kmsan_task_exit(tsk);
> >
> >         coredump_task_exit(tsk);
> >         ptrace_event(PTRACE_EVENT_EXIT, code);
> > diff --git a/kernel/fork.c b/kernel/fork.c
> > index 9d44f2d46c696..6dfca6f00ec82 100644
> > --- a/kernel/fork.c
> > +++ b/kernel/fork.c
> > @@ -37,6 +37,7 @@
> >  #include <linux/fdtable.h>
> >  #include <linux/iocontext.h>
> >  #include <linux/key.h>
> > +#include <linux/kmsan.h>
> >  #include <linux/binfmts.h>
> >  #include <linux/mman.h>
> >  #include <linux/mmu_notifier.h>
> > @@ -1026,6 +1027,7 @@ static struct task_struct *dup_task_struct(struct task_struct *orig, int node)
> >         tsk->worker_private = NULL;
> >
> >         kcov_task_init(tsk);
> > +       kmsan_task_create(tsk);
> >         kmap_local_fork(tsk);
> >
> >  #ifdef CONFIG_FAULT_INJECTION
> > diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> > index 16fb8880a9c6d..7eabed03ed10b 100644
> > --- a/mm/kmsan/core.c
> > +++ b/mm/kmsan/core.c
> > @@ -44,6 +44,16 @@ bool kmsan_enabled __read_mostly;
> >   */
> >  DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
> >
> > +void kmsan_internal_task_create(struct task_struct *task)
> > +{
> > +       struct kmsan_ctx *ctx = &task->kmsan_ctx;
> > +       struct thread_info *info = current_thread_info();
> > +
> > +       __memset(ctx, 0, sizeof(*ctx));
> > +       ctx->allow_reporting = true;
> > +       kmsan_internal_unpoison_memory(info, sizeof(*info), false);
> > +}
> > +
> >  void kmsan_internal_poison_memory(void *address, size_t size, gfp_t flags,
> >                                   unsigned int poison_flags)
> >  {
> > diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> > index 052e17b7a717d..43a529569053d 100644
> > --- a/mm/kmsan/hooks.c
> > +++ b/mm/kmsan/hooks.c
> > @@ -26,6 +26,25 @@
> >   * skipping effects of functions like memset() inside instrumented code.
> >   */
> >
> > +void kmsan_task_create(struct task_struct *task)
> > +{
> > +       kmsan_enter_runtime();
> > +       kmsan_internal_task_create(task);
> > +       kmsan_leave_runtime();
> > +}
> > +EXPORT_SYMBOL(kmsan_task_create);
> > +
> > +void kmsan_task_exit(struct task_struct *task)
> > +{
> > +       struct kmsan_ctx *ctx = &task->kmsan_ctx;
> > +
> > +       if (!kmsan_enabled || kmsan_in_runtime())
> > +               return;
> > +
> > +       ctx->allow_reporting = false;
> > +}
> > +EXPORT_SYMBOL(kmsan_task_exit);
>
> Why are these EXPORT_SYMBOL? Will they be used from some kernel module?

You're right, most of them will not. Will fix.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXu%2BsGe-6Yv9J8LDScOP-eBze4iNqCsyY2igirHKPCt7g%40mail.gmail.com.
