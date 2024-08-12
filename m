Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQH5422QMGQERCFSAQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 976BF94E814
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 09:50:26 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1fc52d3c76esf42052875ad.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 00:50:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723449025; cv=pass;
        d=google.com; s=arc-20160816;
        b=I/n7RHGMsgtzKgflK8dXNp2Dz8Z5fiwMWA+7hfUiQ67FIq15FGAlYlqnyUSSFipRVj
         LJpHLvYs85+3TSDlXljRsNl5kBYGzX4tv9Vfcdmt3ITgIQWRPBoIxhT42FLQtWhU1AqJ
         YlR6awGlMBVDjwZKZ1s56Sr+8B6lJT9MQ53CSNAhDz6/0WWTG/MoZKCi2sjhRFV2DGrz
         xgGXqzxrLkdykh5HqZehttKGNEpeK9eFyK52QhWcJP0OgkOzDNUgKL7ZaI330FUpvxM2
         rxDuAPN1C1Nf8F6YezqUr4yC+wQBYOYfhx15KsdPg82jd+XHQzlrSKTrXuT9+JxY+UPp
         v6PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3z0/9bTXAxAOfBrzXd8ROiyPRq0B56gWKZNWlVsBd8A=;
        fh=UANw4DlpwNKLtF6fbSa8yWvdhZj8k0I2gfv0biYNaVk=;
        b=CZ4kgsHRhPZYuMSSx4tqKvrY6NCViwtIJWZpSfIcLuT1gl2EZcSTEegYPKsuwk/9Xp
         b1u8BdnXZAkGReP5JBMYyxOD98qpTB50o7re0pGxo8XQiOQiRulvmJyNaHckL/48rUvd
         mAvvvPzNNb3UCGLOV0D6OR24r2KTi1L8DXzXKl9EkiXCdxjcgZciC2ZhnA2qAPH0jpJU
         UI/1oaWAsPdZ18xfhMYRxphTGvgqSsmHbDiSQw3XkOFruHx37rcrTMD5Mm/ptpGVyFEg
         xRR6/+zcCvTm0DA3bqFghn2rxZUTrl1X+U0HlmHNngQfzwhWiXOz2l4dgy5kUOGaCIEn
         k4hA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xkFZmTC3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723449025; x=1724053825; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3z0/9bTXAxAOfBrzXd8ROiyPRq0B56gWKZNWlVsBd8A=;
        b=J657HQtiQ0vwQLp2Sv+P+lVflRpAPYXy0xQIdF2M5n0mtfMDtFzYBrjse3aOCFV/Ia
         s2emxm5eYRywBn3Q0kb9RSzjtw9iPTtXuhuZ9dxqBOgC478i0tNh1S1OUUP0a08itmFK
         t8XuSas0MZC6UNRlAB+QXDLGSlAQLE1+Abvrv709dSR9kO1aO552jQhwQoQrpqBKeX7T
         AZ/v1uZbEtBDJeeYJEsoZHxcsQgxUMiAU5WDYx3/azCVPzM7l2ZLYdArMyBYybZPNnwI
         SFPA9LgC2MbfbzBASQ64/9Ml1ORYZsAcCXIf47tktAbBCMUO1QTrAuc8DOAS+J8lnpjq
         HpFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723449025; x=1724053825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3z0/9bTXAxAOfBrzXd8ROiyPRq0B56gWKZNWlVsBd8A=;
        b=a1puVmiMCEdQqIqRo97HtYMrpVBNphKZjG5YClk2IQsKWDgzJhgzeHw7e51PzBOPoY
         lZm8rMQqrYJQPPDV0GGOIikm4IycKMV7Zfbwm6ZfHNr55fdn0Ezjue9xpw9cGqZi2y4D
         h00xm79BjB73UL5R88IXHaXd+HKDcPjJ3mW+GcsGtWvoeNIVxgVrqwbSvao8wlV++V3m
         M8WEVXPKnX0nLBOQiTN8qY92Aa3fAhM2PxqeMK9s7bkZjYFronlxd+gc93dlkI9XacVF
         /Zg0XTGmcl5gjPyXoE83d+vyUGjQwuzD3YPP5nhXqrF4wC4Nf/gOo//VJloXMpYgfVaH
         XFsg==
X-Forwarded-Encrypted: i=2; AJvYcCXGI/3dZo/wkKykMnQx8gIHk/aAzPAys2VAtXtPm/A/XGMGMUQPk4aSqGrciiCj/mzjC+BZAWRqDDwW24JRKx4tCCkEyhL+Ig==
X-Gm-Message-State: AOJu0YzZbfzTD7HRSRA9UQCDClH7X9vH5ToKxGlKdZQ7ZZmHdxfH1G8/
	8F4AFzgncooA7re18Hg/inAKPH/pg8X8hSwx9jY6HmK3wCXtrgx2
X-Google-Smtp-Source: AGHT+IG8fHAfBP15Uax9III+UKMtGd8OgW1UxuHHYe7tYjI9E3IyjnHEQjqi2Q2hXBtTLQhcuQVtdg==
X-Received: by 2002:a17:902:ec86:b0:200:9535:cf13 with SMTP id d9443c01a7336-200ae4ba6d1mr68726605ad.1.1723449024704;
        Mon, 12 Aug 2024 00:50:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:db07:b0:1fe:d72d:13f9 with SMTP id
 d9443c01a7336-2009062f9a8ls9296745ad.2.-pod-prod-02-us; Mon, 12 Aug 2024
 00:50:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUoYRQaKoI9ELOpo6wwhiHLQztQVp9/XDarE47j8H82l1YgMmmvxtnHVUl0DNL5Czm/e9hL390IH+c10CstAJ0OYEj6BbZ0mArOlA==
X-Received: by 2002:a17:902:db0e:b0:1fd:8eaf:eaad with SMTP id d9443c01a7336-200ae55c3fcmr83740915ad.32.1723449023226;
        Mon, 12 Aug 2024 00:50:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723449023; cv=none;
        d=google.com; s=arc-20160816;
        b=J2mdYDJsl0Oyu4vfXYlxkByR7yYcK8P7wzkNZTH+xn0+VkZYZ1x4uWSFS6ZWp7KSsY
         I9VYNHkLGw0kIWDgaHlspub6QXwY++MaIsFXpsb+iWdVF2v5YA3x/uHKggRhD+AayxWU
         c7CALp2HMmEHak8P6LHdsWaM9VIItnrkgpB173xNwIb55V2JfkyPxnEYopQWvh2oVnog
         o0AFN/ON5QF/5/qQTzthwNrOwswSroVy8ggzXGPtJuQwUpZVaEE/Xe44ruUHIZfcJIsF
         nIfgBHTrH+5gQgXC5ZMDwQ37zNU6BoPlN5jUPWXi2zPE2skBHYtROFy4DNt+KDXiPlmS
         1fNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jNeSHIzdgWmMCemefh68BQT/5kHreTgtwMQZzfT5sLM=;
        fh=x5K5qDvGOwdC50/rWicnpQ26N2jwqJ5GrMewiGtnjOs=;
        b=du0Hay0c897jVri5ngD6A4a3ePcCQulnQZC+uMHbjMD+35lbhuwEXXzDD06BlVxVSK
         NCuQIFF2Db/ewqIUbtSS3LxklnFC1e9GN7l4W+gtaUrnOYeZDH46/BI1Aha/5cRmcR37
         F4JWmYX6MvEDSTMZQuISk7BuZ7rSOtkrWzjQGJdz6abo/9IgBELjwVXSqBAYxExjz9jD
         N0LyTcfIACn/kXxE0ReCY457C6O/0xg817/U3K5rMLoFHNRJjICv5co8ImThFKlqDWnU
         2JRIQGtmfbQrQwuFUVG57uGwW3q94LVkn90OQZZ7J62jFAbq1VIsyCvyd58NveMlrtpG
         TbGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xkFZmTC3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vk1-xa29.google.com (mail-vk1-xa29.google.com. [2607:f8b0:4864:20::a29])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-200bb99863esi1880055ad.8.2024.08.12.00.50.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Aug 2024 00:50:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as permitted sender) client-ip=2607:f8b0:4864:20::a29;
Received: by mail-vk1-xa29.google.com with SMTP id 71dfb90a1353d-4f6b612fad4so1322229e0c.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Aug 2024 00:50:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW3bQnVBMnll1bcNyCJZU5PszdWM24ul8RXcCt0dMwuLKrDNlsJnGathVpzsR+nakkoR7PgYfR34X9xjG5sRuez2bHv+rmkVfvtVQ==
X-Received: by 2002:a05:6122:3d0b:b0:4ef:5b2c:df41 with SMTP id
 71dfb90a1353d-4f913064ca6mr11172513e0c.9.1723449021974; Mon, 12 Aug 2024
 00:50:21 -0700 (PDT)
MIME-Version: 1.0
References: <20240812065947.6104-1-dtcccc@linux.alibaba.com>
In-Reply-To: <20240812065947.6104-1-dtcccc@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Aug 2024 09:49:45 +0200
Message-ID: <CANpmjNPT5nm7vMiBXgf2b2EuCcyfM2hNKP=Cro0Vjo9qngS5aw@mail.gmail.com>
Subject: Re: [PATCH] kfence: Save freeing stack trace at calling time instead
 of freeing time
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xkFZmTC3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a29 as
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

On Mon, 12 Aug 2024 at 09:00, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
>
> For kmem_cache with SLAB_TYPESAFE_BY_RCU, the freeing trace stack at
> calling kmem_cache_free() is more useful. While the following stack is
> meaningless and provides no help:
>   freed by task 46 on cpu 0 at 656.840729s:
>    rcu_do_batch+0x1ab/0x540
>    nocb_cb_wait+0x8f/0x260
>    rcu_nocb_cb_kthread+0x25/0x80
>    kthread+0xd2/0x100
>    ret_from_fork+0x34/0x50
>    ret_from_fork_asm+0x1a/0x30
>
> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
> ---
> I'm not sure whether we should keep KFENCE_OBJECT_FREED info remained
> (maybe the exact free time can be helpful?). But add a new kfence_track
> will cost more memory, so I prefer to reuse free_track and drop the info
> when when KFENCE_OBJECT_RCU_FREEING -> KFENCE_OBJECT_FREED.

I think the current version is fine. In the SLAB_TYPESAFE_BY_RCU cases
it would always print the stack trace of RCU internals, so it's never
really useful (as you say above).

Have you encountered a bug where you were debugging a UAF like this?
If not, what prompted you to send this patch?

Did you run the KFENCE test suite?

> ---
>  mm/kfence/core.c   | 35 ++++++++++++++++++++++++++---------
>  mm/kfence/kfence.h |  1 +
>  mm/kfence/report.c |  7 ++++---
>  3 files changed, 31 insertions(+), 12 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index c5cb54fc696d..89469d4f2d95 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -269,6 +269,13 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
>         return pageaddr;
>  }
>
> +static bool kfence_obj_inuse(const struct kfence_metadata *meta)

Other tiny helpers add "inline" so that the compiler is more likely to
inline this. In optimized kernels it should do so by default, but with
some heavily instrumented kernels we need to lower the inlining
threshold - adding "inline" does that.

Also, note we have KFENCE_OBJECT_UNUSED state, so the
kfence_obj_inuse() helper name would suggest to me that it's all other
states.

If the object is being freed with RCU, it is still technically
allocated and _usable_ until the next RCU grace period. So maybe
kfence_obj_allocated() is a more accurate name?

> +{
> +       enum kfence_object_state state = READ_ONCE(meta->state);
> +
> +       return state == KFENCE_OBJECT_ALLOCATED || state == KFENCE_OBJECT_RCU_FREEING;
> +}
> +
>  /*
>   * Update the object's metadata state, including updating the alloc/free stacks
>   * depending on the state transition.
> @@ -278,10 +285,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
>                       unsigned long *stack_entries, size_t num_stack_entries)
>  {
>         struct kfence_track *track =
> -               next == KFENCE_OBJECT_FREED ? &meta->free_track : &meta->alloc_track;
> +               next == KFENCE_OBJECT_ALLOCATED ? &meta->alloc_track : &meta->free_track;
>
>         lockdep_assert_held(&meta->lock);
>
> +       /* Stack has been saved when calling rcu, skip. */
> +       if (READ_ONCE(meta->state) == KFENCE_OBJECT_RCU_FREEING)
> +               goto out;
> +
>         if (stack_entries) {
>                 memcpy(track->stack_entries, stack_entries,
>                        num_stack_entries * sizeof(stack_entries[0]));
> @@ -297,6 +308,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
>         track->cpu = raw_smp_processor_id();
>         track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
>
> +out:
>         /*
>          * Pairs with READ_ONCE() in
>          *      kfence_shutdown_cache(),
> @@ -502,7 +514,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>
>         raw_spin_lock_irqsave(&meta->lock, flags);
>
> -       if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
> +       if (!kfence_obj_inuse(meta) || meta->addr != (unsigned long)addr) {
>                 /* Invalid or double-free, bail out. */
>                 atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
>                 kfence_report_error((unsigned long)addr, false, NULL, meta,
> @@ -780,7 +792,7 @@ static void kfence_check_all_canary(void)
>         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
>                 struct kfence_metadata *meta = &kfence_metadata[i];
>
> -               if (meta->state == KFENCE_OBJECT_ALLOCATED)
> +               if (kfence_obj_inuse(meta))
>                         check_canary(meta);
>         }
>  }
> @@ -1006,12 +1018,11 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>                  * the lock will not help, as different critical section
>                  * serialization will have the same outcome.
>                  */
> -               if (READ_ONCE(meta->cache) != s ||
> -                   READ_ONCE(meta->state) != KFENCE_OBJECT_ALLOCATED)
> +               if (READ_ONCE(meta->cache) != s || !kfence_obj_inuse(meta))
>                         continue;
>
>                 raw_spin_lock_irqsave(&meta->lock, flags);
> -               in_use = meta->cache == s && meta->state == KFENCE_OBJECT_ALLOCATED;
> +               in_use = meta->cache == s && kfence_obj_inuse(meta);
>                 raw_spin_unlock_irqrestore(&meta->lock, flags);
>
>                 if (in_use) {
> @@ -1145,6 +1156,7 @@ void *kfence_object_start(const void *addr)
>  void __kfence_free(void *addr)
>  {
>         struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
> +       unsigned long flags;

This flags variable does not need to be scoped for the whole function.
It can just be scoped within the if-branch where it's needed (at least
I don't see other places besides there where it's used).

>  #ifdef CONFIG_MEMCG
>         KFENCE_WARN_ON(meta->obj_exts.objcg);
> @@ -1154,9 +1166,14 @@ void __kfence_free(void *addr)
>          * the object, as the object page may be recycled for other-typed
>          * objects once it has been freed. meta->cache may be NULL if the cache
>          * was destroyed.
> +        * Save the stack trace here. It is more useful.

"It is more useful." adds no value to the comment.

I would say something like: "Save the stack trace here so that reports
show where the user freed the object."

>          */
> -       if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
> +       if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU))) {
> +               raw_spin_lock_irqsave(&meta->lock, flags);
> +               metadata_update_state(meta, KFENCE_OBJECT_RCU_FREEING, NULL, 0);
> +               raw_spin_unlock_irqrestore(&meta->lock, flags);
>                 call_rcu(&meta->rcu_head, rcu_guarded_free);
> +       }

Wrong if-else style. Turn the whole thing into

if (...) {
   ...
} else {
  kfence_guarded_free(...);
}

So it looks balanced.

>         else
>                 kfence_guarded_free(addr, meta, false);
>  }
> @@ -1182,14 +1199,14 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
>                 int distance = 0;
>
>                 meta = addr_to_metadata(addr - PAGE_SIZE);
> -               if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
> +               if (meta && kfence_obj_inuse(meta)) {
>                         to_report = meta;
>                         /* Data race ok; distance calculation approximate. */
>                         distance = addr - data_race(meta->addr + meta->size);
>                 }
>
>                 meta = addr_to_metadata(addr + PAGE_SIZE);
> -               if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
> +               if (meta && kfence_obj_inuse(meta)) {
>                         /* Data race ok; distance calculation approximate. */
>                         if (!to_report || distance > data_race(meta->addr) - addr)
>                                 to_report = meta;
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index db87a05047bd..dfba5ea06b01 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -38,6 +38,7 @@
>  enum kfence_object_state {
>         KFENCE_OBJECT_UNUSED,           /* Object is unused. */
>         KFENCE_OBJECT_ALLOCATED,        /* Object is currently allocated. */
> +       KFENCE_OBJECT_RCU_FREEING,      /* Object was allocated, and then being freed by rcu. */
>         KFENCE_OBJECT_FREED,            /* Object was allocated, and then freed. */
>  };
>
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index 73a6fe42845a..451991a3a8f2 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -114,7 +114,8 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
>
>         /* Timestamp matches printk timestamp format. */
>         seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago):\n",
> -                      show_alloc ? "allocated" : "freed", track->pid,
> +                      show_alloc ? "allocated" : meta->state == KFENCE_OBJECT_RCU_FREEING ?
> +                      "rcu freeing" : "freed", track->pid,
>                        track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
>                        (unsigned long)interval_nsec, rem_interval_nsec / 1000);
>
> @@ -149,7 +150,7 @@ void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *met
>
>         kfence_print_stack(seq, meta, true);
>
> -       if (meta->state == KFENCE_OBJECT_FREED) {
> +       if (meta->state == KFENCE_OBJECT_FREED || meta->state == KFENCE_OBJECT_RCU_FREEING) {
>                 seq_con_printf(seq, "\n");
>                 kfence_print_stack(seq, meta, false);
>         }
> @@ -318,7 +319,7 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>         kpp->kp_slab_cache = meta->cache;
>         kpp->kp_objp = (void *)meta->addr;
>         kfence_to_kp_stack(&meta->alloc_track, kpp->kp_stack);
> -       if (meta->state == KFENCE_OBJECT_FREED)
> +       if (meta->state == KFENCE_OBJECT_FREED || meta->state == KFENCE_OBJECT_RCU_FREEING)
>                 kfence_to_kp_stack(&meta->free_track, kpp->kp_free_stack);
>         /* get_stack_skipnr() ensures the first entry is outside allocator. */
>         kpp->kp_ret = kpp->kp_stack[0];
> --
> 2.39.3
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812065947.6104-1-dtcccc%40linux.alibaba.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPT5nm7vMiBXgf2b2EuCcyfM2hNKP%3DCro0Vjo9qngS5aw%40mail.gmail.com.
