Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJVH6G2QMGQEE5MYDBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 314C69514CD
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 08:50:16 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4501f17051esf81722271cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 23:50:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723618215; cv=pass;
        d=google.com; s=arc-20160816;
        b=HVDRU86P7SYKJgdDtp0xfQNemRIvwyT4Xm+wjfmprUM1xsCo1YsTcRsvGymEPXD6GZ
         +aItL1W1PrOOvlMgdDeTkmkT2f4ul4lcRvnJQL/5ttUi9DsBYxdH7pzIjvDsYTTWsqNS
         TDvVGbOGJnts93AI8xXn8cwXWa63Te7XN9Tl8LnF5+b+VygzGabdY0vuyeTu/OO7YRLQ
         etl6PZeU7aQuFnLVKglqbxUdKIqK2wBI5nsavhfQ70w3WmaQeFbTpTKk/KwRiWKn8Z4B
         vYWKEvm44RE/kEvZ7y7Ibv1wN1qqpTGTxhNyC/Jd4bSQOYRNDwtcz1GnCV0/VzsCt0r9
         qvuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zO/Bz6XuBcNLfJYJ2YgNJesRAtfH5ElSnKMKg76dwiA=;
        fh=Yh45L33Wb88kCd16mof0A2OpR7CtUb6UgLJ+eqCDioY=;
        b=DSpP4h2uA40FxUll8fGV5Z/Js1BtRmhVuftahi1ArF193OWcDfav3igALT8NBgCWu8
         HPJjcHtnKSS1lY1Lb+VclLcdTsjkydYaPv9UqpZ38SHKIg5lXSv8kkCcG77X3qSSX4NU
         DsvXMGX5u4hz0/ZCdlXNuyUcCsPltWUjW7YfgeoRrtrR0w2rAYLfGhAgSy+IuVJOiz8O
         PriqX++wBTjBueFBVGqWaLEcWwROkLPny/5xX1NFURQgJbQzbPHfbs3QgB7IcCeqzo0d
         m5vPokNeksNQoMs7uUTcIBW8Ho0aKX6nxi4e24aWrf/GgxlDlcLI+DBkoqs3ni/t9jp/
         SiCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vgGHKvP/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723618215; x=1724223015; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zO/Bz6XuBcNLfJYJ2YgNJesRAtfH5ElSnKMKg76dwiA=;
        b=s5Es7uldwulS/cRIhVXl+orMz4VewanGZaVxu3QR2fAIlLRNsGf5Phpktrw0TfiQzk
         0b4BsIzFCsjA8zrL59E2+Saha+q3bmVc2sb+6Fi5RtKgo5lTiYl8/Y5piTyheUvTcIkB
         J/1kJMoGjDODZkfHqWB3JDtrXn3BUxwyYgaEQQ5z9elzSnNUwEFeFzh6DKgCsTS2LPdp
         145lTI48lD+8Aetg4jNnoTPCko7jY65IEeHxyZ9oFWY4WJjSMfObAq58LXOhNRhi/skC
         uBNfANTfSz1wgKIYQ03ODbU6NAGTyiZ3t6YV9D+e48vj4+/XiurXvnP1QgtLUsqz1Xhk
         Pt2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723618215; x=1724223015;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zO/Bz6XuBcNLfJYJ2YgNJesRAtfH5ElSnKMKg76dwiA=;
        b=vd4WwLiWJYKGzBdkUA7sKbC3pIizABM+miohht2FMiOKurqmifhsK7CpbawLpQ1/CQ
         hO6nNWbI+Pu9BgJvw2NGOeGJldr/EOdQdtuz0GCDbTMZ2zKEzCL0wAWA6eS23N16utJd
         L+xi6i8CnksT6VXhmHlCB8vnR7i4Ui5seaeI3C+MBjFmr872R78/BDy4yol9otzu4MJL
         mX0AaWRHSF/KxuM2YGb13BrSlSoCzdI/VOaKBc9r7y9ROVER5EqKCrskW2NVUkkCEllN
         euwWOGaiTu6FltW7OShjodoWEc92EvmShx0rRGhW+18Rv4w5sw0PUBkNU/T5UP7CaFyf
         GXyA==
X-Forwarded-Encrypted: i=2; AJvYcCV8tLg9aXMLJpEvRFehalFIv5RT4OVPdXanAJVUP9X53qG0egFi4gP6gXo+euzxrehXPii18l+zRqzV5GweWJyBzD7JZArz+g==
X-Gm-Message-State: AOJu0Yybi6U1ZWpnviRCrWhEnsINpob1MKppT0cYNXktk6GhIkklg42B
	PIetJ8iJrG5qNnH7TldbICJkWajLtkJuABuz6few2wmAeV7pvJmm
X-Google-Smtp-Source: AGHT+IFDgjtTXStvXloHuwlAtLKK+Dra1OkRdWHTPL7z7JEc+DAobSN5iUJC9I1kMlhFMXIRxPM/3Q==
X-Received: by 2002:a05:622a:1149:b0:441:3bf6:d5cb with SMTP id d75a77b69052e-4535ba79254mr17310951cf.6.1723618214800;
        Tue, 13 Aug 2024 23:50:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1890:b0:44b:e6db:de28 with SMTP id
 d75a77b69052e-451d12fb088ls94895511cf.2.-pod-prod-04-us; Tue, 13 Aug 2024
 23:50:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDNxhkkgE1BRwSGF4I5Gq9M+ozIOInh1mk4IFtQ9lL9hScoH8CRrK8xHt9kQoLJsNrjGFxMUaA3SQXN98bt6p3Mmoj/oLCnKr8gw==
X-Received: by 2002:a05:620a:1aa6:b0:7a2:a1d:c0f7 with SMTP id af79cd13be357-7a4ee32e8e7mr241222185a.16.1723618214206;
        Tue, 13 Aug 2024 23:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723618214; cv=none;
        d=google.com; s=arc-20160816;
        b=SXUO4zwEGYEySN4OaQSktvryAGGIOFaIozEgEI38iEi+Zr5Gw9IRAtWGU1dNNR9+05
         E9eZeczFSdPH7AsisTJoKeI+NHJNNfInIwU345wCxW+Gm375lCMh+0eZbCnwR1CCW3Bn
         /bZYaouf2E3qmaveuXwJB6Z7NrzdyVc3UdPcije6nzFbUlud5q2I7Uin20zJUbUf6Dbp
         P4WC/acqL4859I7pEkM0VXkLDPQx/pXk+gEgBOqpImhjyryI8y5fvUGwpd+C40HfVcBH
         kV9byHye1PQ8Gflfmas7qH+8+3LunC5zvQTE7C30OiF5ffcdalbTk8EtjbVFatdYNRVJ
         e6uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kGYIVRMx7xSAnTXSGLiynA60xaTatAN/kEWNV4u5Zsk=;
        fh=K9YRT2pBvOAlTkgRs5DZWzf0zH+W3Z5LMABlj7ewdgo=;
        b=VEogcEyk6VIfrTO/qk+lEhiySyNcfjTGW9OD+0AZnYor9IG6pPndKmrhcJR1Eq/MU2
         yAf/w14tOznWsuPHZZwTMGlHmzchQY0T9bMJWF64/BqvMBcfVnjoyNaji0ulZEBQfBdN
         xWXpjW60L3gMemN1apQi7W3lBL4q/S3O9tweh5UpLGFK54/h1El4wnc/rTf8/8SuXSw2
         BlvqU12CALvRj+gKN9XD44DvzyRdjRIphcts3GlVmo1itVZRx+aXEJPSf0UHVrpXD7xQ
         8kQohpO1d1T8doGpwqMhhBMvQGg1Fq77KUoyLLRZw13vc533h8Pw7+9sED5ogDAgN4yx
         8FKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="vgGHKvP/";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x931.google.com (mail-ua1-x931.google.com. [2607:f8b0:4864:20::931])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a4c7e0f8afsi42771685a.6.2024.08.13.23.50.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Aug 2024 23:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as permitted sender) client-ip=2607:f8b0:4864:20::931;
Received: by mail-ua1-x931.google.com with SMTP id a1e0cc1a2514c-825809a4decso2322527241.0
        for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2024 23:50:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXIOVp9cqfoea7opGZT/nGSmaHvKUXRHR4kY34fQ1tWMj3P7obJ/9xaC9baC7QoMCmOeyiJeTLDe2lJ8tX+Q0VUMNTzexaOsypMzQ==
X-Received: by 2002:a05:6102:e06:b0:493:de37:b3ef with SMTP id
 ada2fe7eead31-49759913349mr2343105137.13.1723618213265; Tue, 13 Aug 2024
 23:50:13 -0700 (PDT)
MIME-Version: 1.0
References: <20240812095517.2357-1-dtcccc@linux.alibaba.com>
In-Reply-To: <20240812095517.2357-1-dtcccc@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Aug 2024 08:49:37 +0200
Message-ID: <CANpmjNMm3CkfW=BPWR3w37Dfo=MFReD9wxHejDy4=ibwhe33yA@mail.gmail.com>
Subject: Re: [PATCH v2] kfence: Save freeing stack trace at calling time
 instead of freeing time
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="vgGHKvP/";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::931 as
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

On Mon, 12 Aug 2024 at 11:55, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
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

Reviewed-by: Marco Elver <elver@google.com>

Thanks for the patch!

> ---
> v2:
> Rename and inline tiny helper kfence_obj_allocated().
> Improve code style and comments.
>
> v1: https://lore.kernel.org/all/20240812065947.6104-1-dtcccc@linux.alibaba.com/
> ---
>  mm/kfence/core.c   | 39 +++++++++++++++++++++++++++++----------
>  mm/kfence/kfence.h |  1 +
>  mm/kfence/report.c |  7 ++++---
>  3 files changed, 34 insertions(+), 13 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index c3ef7eb8d4dc..67fc321db79b 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -273,6 +273,13 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
>         return pageaddr;
>  }
>
> +static inline bool kfence_obj_allocated(const struct kfence_metadata *meta)
> +{
> +       enum kfence_object_state state = READ_ONCE(meta->state);
> +
> +       return state == KFENCE_OBJECT_ALLOCATED || state == KFENCE_OBJECT_RCU_FREEING;
> +}
> +
>  /*
>   * Update the object's metadata state, including updating the alloc/free stacks
>   * depending on the state transition.
> @@ -282,10 +289,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
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
> @@ -301,6 +312,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
>         track->cpu = raw_smp_processor_id();
>         track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
>
> +out:
>         /*
>          * Pairs with READ_ONCE() in
>          *      kfence_shutdown_cache(),
> @@ -506,7 +518,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>
>         raw_spin_lock_irqsave(&meta->lock, flags);
>
> -       if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
> +       if (!kfence_obj_allocated(meta) || meta->addr != (unsigned long)addr) {
>                 /* Invalid or double-free, bail out. */
>                 atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
>                 kfence_report_error((unsigned long)addr, false, NULL, meta,
> @@ -784,7 +796,7 @@ static void kfence_check_all_canary(void)
>         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
>                 struct kfence_metadata *meta = &kfence_metadata[i];
>
> -               if (meta->state == KFENCE_OBJECT_ALLOCATED)
> +               if (kfence_obj_allocated(meta))
>                         check_canary(meta);
>         }
>  }
> @@ -1010,12 +1022,11 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>                  * the lock will not help, as different critical section
>                  * serialization will have the same outcome.
>                  */
> -               if (READ_ONCE(meta->cache) != s ||
> -                   READ_ONCE(meta->state) != KFENCE_OBJECT_ALLOCATED)
> +               if (READ_ONCE(meta->cache) != s || !kfence_obj_allocated(meta))
>                         continue;
>
>                 raw_spin_lock_irqsave(&meta->lock, flags);
> -               in_use = meta->cache == s && meta->state == KFENCE_OBJECT_ALLOCATED;
> +               in_use = meta->cache == s && kfence_obj_allocated(meta);
>                 raw_spin_unlock_irqrestore(&meta->lock, flags);
>
>                 if (in_use) {
> @@ -1160,11 +1171,19 @@ void __kfence_free(void *addr)
>          * the object, as the object page may be recycled for other-typed
>          * objects once it has been freed. meta->cache may be NULL if the cache
>          * was destroyed.
> +        * Save the stack trace here so that reports show where the user freed
> +        * the object.
>          */
> -       if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
> +       if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU))) {
> +               unsigned long flags;
> +
> +               raw_spin_lock_irqsave(&meta->lock, flags);
> +               metadata_update_state(meta, KFENCE_OBJECT_RCU_FREEING, NULL, 0);
> +               raw_spin_unlock_irqrestore(&meta->lock, flags);
>                 call_rcu(&meta->rcu_head, rcu_guarded_free);
> -       else
> +       } else {
>                 kfence_guarded_free(addr, meta, false);
> +       }
>  }
>
>  bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs *regs)
> @@ -1188,14 +1207,14 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
>                 int distance = 0;
>
>                 meta = addr_to_metadata(addr - PAGE_SIZE);
> -               if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
> +               if (meta && kfence_obj_allocated(meta)) {
>                         to_report = meta;
>                         /* Data race ok; distance calculation approximate. */
>                         distance = addr - data_race(meta->addr + meta->size);
>                 }
>
>                 meta = addr_to_metadata(addr + PAGE_SIZE);
> -               if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
> +               if (meta && kfence_obj_allocated(meta)) {
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812095517.2357-1-dtcccc%40linux.alibaba.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMm3CkfW%3DBPWR3w37Dfo%3DMFReD9wxHejDy4%3Dibwhe33yA%40mail.gmail.com.
