Return-Path: <kasan-dev+bncBCMIZB7QWENRBEMPZL2QKGQEUR5BPJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 264AF1C6D78
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 11:46:59 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id d7sf794250ooi.12
        for <lists+kasan-dev@lfdr.de>; Wed, 06 May 2020 02:46:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588758418; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rclyo3KPMZKTcnNo/OgO1w850NyAuRi5whC+Pry9mEYKb3qYx2Ngkm5G/htYRQhqov
         WXwBkJFk5nY0cZgT9TEhZhBPmpj9gGtKs69/HHKqbsZASKspAJB70UfxBl6E7JyHEmt6
         OF5Okw2wVkQMHcg5lmk/dqbUE+B/MN+vHFxERR6hkCofRrJJ4EpNPMj+zvDHvXc91XCn
         QnXrF6ei9mS+N/GxXKF0+eOKASwtP56eh1v7CZBsJQHefU4Ebk1/472RfLqGWGgkR5QO
         Ab6O1ezdS3ZvFLQDj8zMf+Qh0P6lqbf4BUJRDlUdwBziTE8DCMwfAeYkeI+d2Ioo40jZ
         u0FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=MbPGXtBLWg37vlFsVdDioyDfSBSFS1DaMeA+//EiTE8=;
        b=wZdfYBzKqk7EAgVT788zx81f3PqmH5nkENzR+RUlUjouvM6W6zKNvhlBqR6O/RqTDX
         4oKmFCKrQdAdFFq2MdXcAlqfyJR6TLRF75S6c+ZSWRbMYQ7QYVuS6Pz74KVGLEomS14C
         iYMFBCW5rVY2rbbA37E6aHALerogMksrFjCSv7pkmtfjwmQx8T/NHHt4C1bkGnM3sxxM
         6pHbpqD21VSOEX1E0ZG0Y9SRLPyTDgEw5QkW96LX49YO+ohLPBHkdKokvjbhx2JqgZ46
         qxEs1jx/rvuZikixcdQolO/5m3eV533Rah8cCNn+KZ4ZiJhIqLBGh7adcPg+bJM4fs0M
         /fSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r2QvspJv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MbPGXtBLWg37vlFsVdDioyDfSBSFS1DaMeA+//EiTE8=;
        b=h/YTw65l0kWZ6gyJmsBPCJYvGmvxEZKCr541fLNaiyBfPsoxK+XjL8J3n4OQBaSNIQ
         AYRV0QAeRRe/Cdr1F69Ub4jGM/W3m3MUeLXDVbxXeCITVAY2mw7cFa1UxId1G/srxhwW
         YZCRT0TqT3bGWJ+2FpaLsDNu7TjSJvaijnQ0Ryi/0QXmLcl/HDLdB/UDfrrON2mPk8Ze
         SFMmZ7YhjIF8ptzaKV35OvLL5G1QJOddbLroBJMVqa+4koMGTXn06FGtTt4MaWqwpYeT
         pXQP2Bem7sj7b2Ub0U6PCOIMD1RGvN4Zov60d7U585fZxop198KSnrpmjlKaLY1VN8cW
         3QKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MbPGXtBLWg37vlFsVdDioyDfSBSFS1DaMeA+//EiTE8=;
        b=ItO2GJOdFjpPK2gaH7K7EaMojYi9Ytaq16Mm+rw9bwNvqwK1KZrKk78gU9j+UXRyw+
         i0592P1j+Zskg0/JPb7Ys8hEjEtkBK+KCOsMTAnMyQbN8O1zO+1wXfiC2zTcP7sbHP1B
         ys//yadmU2Vs7U494b4ykpSjetOUuswrozSG/sIyAKKhhRd9U6wDzqxy6ZYmnojmacbQ
         05s77VEwvowcjc+0AsymQp276dalyiN2IF3hNt8BDajblFOGnDMqCC7j0g/iWDFkfElw
         6VSsRAZzD19Dg8nvCU8drX87k4KxTrWmvbG0Dy7bwS5AaBz+aG32jJEkdIP4ijAySXYB
         1OPA==
X-Gm-Message-State: AGi0PuZr41DXGdWQvuc0GB+UZcUGmDL2GWkMTvCNn0mGnquQYl1uSsrM
	oWZUcDZv8xhid2R40o0X2tM=
X-Google-Smtp-Source: APiQypIYIt4jpeeXLz6ORJG7p/bI4i/zkGi6u1ZLzlQvGdAc4OLRBvKpzVwFvhvdAZm65q+1qOcBBQ==
X-Received: by 2002:a4a:7011:: with SMTP id r17mr6486723ooc.17.1588758418015;
        Wed, 06 May 2020 02:46:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:30bc:: with SMTP id g28ls253865ots.4.gmail; Wed, 06
 May 2020 02:46:57 -0700 (PDT)
X-Received: by 2002:a05:6830:154c:: with SMTP id l12mr5970148otp.120.1588758417534;
        Wed, 06 May 2020 02:46:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588758417; cv=none;
        d=google.com; s=arc-20160816;
        b=l7c4CWL/tZp93t8KRZKAXFyA5B0ea6GIngj2l2IuR0UbGaQzZ9MS+o/gVU79bVpA0S
         WLJff2WBB1hzpw+3mjG/x9NPSuTWxo0ImTsXR1aEntHWU8uQmAl6oZbf0oOXMBc2OBYV
         04OAXcXZ3pJ8RhEeBDAgtfpYblvbkMk2u4bdeDtqMqDII4BhD9Jw2Hzg2q4pr+p/DFXm
         8eG7o4fGygtA/YR4F9u8Lcx/wWWoq3OpcxkHl8QZw7CKeKBvaint5nCjIB2Ato8d7Qhg
         mxro7ydQwGx5Us1Bb9uLhTOrpYKL1oCuO3ICQaRDRqMIBjlEkP5uKy4nn1pmk1PMqHct
         iYkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hQDZDB87ZUXhKCgcvIzYKrqSoBdqgJ7jZ3dXjUfyxD0=;
        b=T9lMHn1h1tjw4EJYhg36c47BpbOmYC/0sV31BN89mhoa9eWpNrq+04sVRz2BEzTJLH
         7Y8bBzW7fervkWcQ8CWTZ3FElwMlJlk5/TrHKazH6NkepFmSm38Cvt0zxv++ghbJNi7N
         To6GKNeoB6s/b/E3hpT+w1y5kNYkR79/plLZYsZQ40bjc4llGiyeUeLphzonQov6kIDW
         UsopdL1j6Rn2A+n6aBeQyN8aPotU0aRoQy5tiTvDa6P2Yb9b5UI5HAIAxbY7UR4/2MxO
         6JhY/zsGuIjVvoAYB7wJ+jOtEYSVnp0y5fUo9w8WFw+T6lQqrhQGRX+mxE8x/9F1JRIY
         /3dA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=r2QvspJv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id c15si133489oto.0.2020.05.06.02.46.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 May 2020 02:46:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id i68so806274qtb.5
        for <kasan-dev@googlegroups.com>; Wed, 06 May 2020 02:46:57 -0700 (PDT)
X-Received: by 2002:ac8:5209:: with SMTP id r9mr6854313qtn.57.1588758416707;
 Wed, 06 May 2020 02:46:56 -0700 (PDT)
MIME-Version: 1.0
References: <20200506052046.14451-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200506052046.14451-1-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 May 2020 11:46:45 +0200
Message-ID: <CACT4Y+beyYmoTn8GR_Y_Ca5XypxpRac-9ttu=zTtS-J-BYTfMA@mail.gmail.com>
Subject: Re: [PATCH 1/3] rcu/kasan: record and print call_rcu() call stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=r2QvspJv;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Wed, May 6, 2020 at 7:21 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> When call_rcu() is called, we store the call_rcu() call stack into
> slub alloc meta-data, so that KASAN report prints call_rcu() information.
>
> We add new KASAN_RCU_STACK_RECORD configuration option. It will record
> first and last call_rcu() call stack and KASAN report will print two
> call_rcu() call stack.
>
> This option doesn't increase the cost of memory consumption. Because
> we don't enlarge struct kasan_alloc_meta size.
> - add two call_rcu() call stack into kasan_alloc_meta, size is 8 bytes.
> - remove free track from kasan_alloc_meta, size is 8 bytes.
>
> [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Josh Triplett <josh@joshtriplett.org>
> Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
> Cc: Lai Jiangshan <jiangshanlai@gmail.com>
> Cc: Joel Fernandes <joel@joelfernandes.org>
> ---
>  include/linux/kasan.h |  7 +++++++
>  kernel/rcu/tree.c     |  4 ++++
>  lib/Kconfig.kasan     | 11 +++++++++++
>  mm/kasan/common.c     | 23 +++++++++++++++++++++++
>  mm/kasan/kasan.h      | 12 ++++++++++++
>  mm/kasan/report.c     | 33 +++++++++++++++++++++++++++------
>  6 files changed, 84 insertions(+), 6 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 31314ca7c635..5eeece6893cd 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -96,6 +96,12 @@ size_t kasan_metadata_size(struct kmem_cache *cache);
>  bool kasan_save_enable_multi_shot(void);
>  void kasan_restore_multi_shot(bool enabled);
>
> +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> +void kasan_record_callrcu(void *ptr);

The issue also mentions workqueue and timer stacks.
Have you considered supporting them as well? What was your motivation
for doing only rcu?

Looking at the first report for "workqueue use-after-free":
https://syzkaller.appspot.com/bug?extid=9cba1e478f91aad39876
This is exactly the same situation as for call_rcu, just a workqueue
is used to invoke a callback that frees the object.

If you don't want to do all at the same time, I would at least
name/branch everything inside of KASAN more generally (I think in the
issue I called it "aux" (auxiliary), or maybe something like
"additional"). But then call this kasan_record_aux_stack() only from
rcu for now. But then later we can separately decide and extend to
other callers.
It just feels wrong to have KASAN over-specialized for rcu only in this way.
And I think if the UAF is really caused by call_rcu callback, then it
sill will be recorded as last stack most of the time because rcu
callbacks are invoked relatively fast and there should not be much
else happening with the object since it's near end of life already.




> +#else
> +static inline void kasan_record_callrcu(void *ptr) {}
> +#endif
> +
>  #else /* CONFIG_KASAN */
>
>  static inline void kasan_unpoison_shadow(const void *address, size_t size) {}
> @@ -165,6 +171,7 @@ static inline void kasan_remove_zero_shadow(void *start,
>
>  static inline void kasan_unpoison_slab(const void *ptr) { }
>  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
> +static inline void kasan_record_callrcu(void *ptr) {}
>
>  #endif /* CONFIG_KASAN */
>
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index 06548e2ebb72..145c79becf7b 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -57,6 +57,7 @@
>  #include <linux/slab.h>
>  #include <linux/sched/isolation.h>
>  #include <linux/sched/clock.h>
> +#include <linux/kasan.h>
>  #include "../time/tick-internal.h"
>
>  #include "tree.h"
> @@ -2694,6 +2695,9 @@ __call_rcu(struct rcu_head *head, rcu_callback_t func)
>                 trace_rcu_callback(rcu_state.name, head,
>                                    rcu_segcblist_n_cbs(&rdp->cblist));
>
> +       if (IS_ENABLED(CONFIG_KASAN_RCU_STACK_RECORD))

The if is not necessary, this function is no-op when not enabled.

> +               kasan_record_callrcu(head);
> +
>         /* Go handle any RCU core processing required. */
>         if (IS_ENABLED(CONFIG_RCU_NOCB_CPU) &&
>             unlikely(rcu_segcblist_is_offloaded(&rdp->cblist))) {
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 81f5464ea9e1..022934049cc2 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -158,6 +158,17 @@ config KASAN_VMALLOC
>           for KASAN to detect more sorts of errors (and to support vmapped
>           stacks), but at the cost of higher memory usage.
>
> +config KASAN_RCU_STACK_RECORD
> +       bool "Record and print call_rcu() call stack"
> +       depends on KASAN_GENERIC
> +       help
> +         By default, the KASAN report doesn't print call_rcu() call stack.
> +         It is very difficult to analyze memory issues(e.g., use-after-free).
> +
> +         Enabling this option will print first and last call_rcu() call stack.
> +         It doesn't enlarge slub alloc meta-data size, so it doesn't increase
> +         the cost of memory consumption.
> +
>  config TEST_KASAN
>         tristate "Module for testing KASAN for bug detection"
>         depends on m && KASAN
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2906358e42f0..32d422bdf127 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -299,6 +299,29 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>         return (void *)object + cache->kasan_info.free_meta_offset;
>  }
>
> +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> +void kasan_record_callrcu(void *addr)
> +{
> +       struct page *page = kasan_addr_to_page(addr);
> +       struct kmem_cache *cache;
> +       struct kasan_alloc_meta *alloc_info;
> +       void *object;
> +
> +       if (!(page && PageSlab(page)))
> +               return;
> +
> +       cache = page->slab_cache;
> +       object = nearest_obj(cache, page, addr);
> +       alloc_info = get_alloc_info(cache, object);
> +
> +       if (!alloc_info->rcu_free_stack[0])
> +               /* record first call_rcu() call stack */
> +               alloc_info->rcu_free_stack[0] = save_stack(GFP_NOWAIT);
> +       else
> +               /* record last call_rcu() call stack */
> +               alloc_info->rcu_free_stack[1] = save_stack(GFP_NOWAIT);
> +}
> +#endif
>
>  static void kasan_set_free_info(struct kmem_cache *cache,
>                 void *object, u8 tag)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8f37199d885..adc105b9cd07 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -96,15 +96,27 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> +#define BYTES_PER_WORD 4
> +#define KASAN_NR_RCU_FREE_STACKS 2
> +#else /* CONFIG_KASAN_RCU_STACK_RECORD */
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>  #define KASAN_NR_FREE_STACKS 5
>  #else
>  #define KASAN_NR_FREE_STACKS 1
>  #endif
> +#endif /* CONFIG_KASAN_RCU_STACK_RECORD */
>
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
> +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> +       /* call_rcu() call stack is stored into kasan_alloc_meta.
> +        * free stack is stored into freed object.
> +        */
> +       depot_stack_handle_t rcu_free_stack[KASAN_NR_RCU_FREE_STACKS];
> +#else
>         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> +#endif
>  #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
>         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>         u8 free_track_idx;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 80f23c9da6b0..7aaccc70b65b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -105,9 +105,13 @@ static void end_report(unsigned long *flags)
>         kasan_enable_current();
>  }
>
> -static void print_track(struct kasan_track *track, const char *prefix)
> +static void print_track(struct kasan_track *track, const char *prefix,
> +                                               bool is_callrcu)
>  {
> -       pr_err("%s by task %u:\n", prefix, track->pid);
> +       if (is_callrcu)
> +               pr_err("%s:\n", prefix);
> +       else
> +               pr_err("%s by task %u:\n", prefix, track->pid);
>         if (track->stack) {
>                 unsigned long *entries;
>                 unsigned int nr_entries;
> @@ -159,8 +163,22 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>                 (void *)(object_addr + cache->object_size));
>  }
>
> +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> +static void kasan_print_rcu_free_stack(struct kasan_alloc_meta *alloc_info)
> +{
> +       struct kasan_track free_track;
> +
> +       free_track.stack  = alloc_info->rcu_free_stack[0];
> +       print_track(&free_track, "First call_rcu() call stack", true);
> +       pr_err("\n");
> +       free_track.stack  = alloc_info->rcu_free_stack[1];
> +       print_track(&free_track, "Last call_rcu() call stack", true);
> +       pr_err("\n");
> +}
> +#endif
> +
>  static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> -               void *object, u8 tag)
> +               void *object, u8 tag, const void *addr)
>  {
>         struct kasan_alloc_meta *alloc_meta;
>         int i = 0;
> @@ -187,11 +205,14 @@ static void describe_object(struct kmem_cache *cache, void *object,
>         if (cache->flags & SLAB_KASAN) {
>                 struct kasan_track *free_track;
>
> -               print_track(&alloc_info->alloc_track, "Allocated");
> +               print_track(&alloc_info->alloc_track, "Allocated", false);
>                 pr_err("\n");
> -               free_track = kasan_get_free_track(cache, object, tag);
> -               print_track(free_track, "Freed");
> +               free_track = kasan_get_free_track(cache, object, tag, addr);
> +               print_track(free_track, "Freed", false);
>                 pr_err("\n");
> +#ifdef CONFIG_KASAN_RCU_STACK_RECORD
> +               kasan_print_rcu_free_stack(alloc_info);
> +#endif
>         }
>
>         describe_object_addr(cache, object, addr);
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200506052046.14451-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbeyYmoTn8GR_Y_Ca5XypxpRac-9ttu%3DzTtS-J-BYTfMA%40mail.gmail.com.
