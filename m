Return-Path: <kasan-dev+bncBAABBCMC462QMGQEL2FM45I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9608394E824
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 10:00:12 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1fc6ac9a4aasf44921935ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 01:00:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723449610; cv=pass;
        d=google.com; s=arc-20160816;
        b=tw0xnPYHb8JmUDWHpJXCFg4ZsKkIu58gZoDQcUwjtLoah1qjRZDnALgkPRnnosg6kW
         vo5MsSx0TB+cpcPh/yvfCavx7XV2AeDwes4GEP+uP3QySalaGI8gkk2IeykjNBkmzWvh
         QnbTBILHFVbhDpp+7ODnbm9iOHtUAcPj5H3lofdVKncxTMkiRYIp74zw6Ix9ybm54X84
         nYWgoZK23B+Ih2MsWnGO6+nXgy4drrx7BQqZQ7a7bzZv0uwdV31EoXw9DZbbe2dXUVEv
         jryRFrOzbcSz6iLI9S5NnJFkbxPQoKhp5nXkCUfS8MsarfpmLtOMSFzYol2LTOtZPipH
         z+1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=FlkNJrCddLIBg5vltMyF9v0wIbCb4a2Vjj5HMwgSPqc=;
        fh=/ReOCScioXg81DGThB11tiFZ7AiAOuWJ0VXb+McnlDA=;
        b=JfvcseP6hB369YzIAdnR5ehdyLa5YCpe+0+/BjHzyu+o0egpV1bSHQHdWYPcnRdA4J
         izLtq6Me9J8sFPOMW0efaVp/FqHGr0nZtrj7oaT6XDQrLYN3cr3PEla9IURGIWLZwRwv
         wgkkOzvi2SFM/gOLjHXRdNrN7iOdVO8LeWje9s/S+GSB//EyACiIqtzlfWsk7JvKzB04
         hNHMagtXUSdNFkllR5jHFXcAaATqF35ReXoN9xAPiFFUDouitLYNeUA2q44Qvh1uixT6
         2b1OHY8+I9xgUT27HmvbZeDIH/dcsZBdyXsYmoy+nyyZyYrcwqe+D6KkrG/CUnWNFgce
         qwhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=ty31G37+;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.98 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723449610; x=1724054410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FlkNJrCddLIBg5vltMyF9v0wIbCb4a2Vjj5HMwgSPqc=;
        b=LW2UfOR1iPANfl27wcTolKE5Oyr6A7hJhC+yQ1ROUTfHH7LHKXxtCJbRT5obDmkTIz
         aKb0fDju9EvSpkRW9blRysaoyM83lNLCSYG9PHuyu7KS1z5TU7ivMyftbgHXhX2g2VdI
         gz9YBdUHiBfzh4HqH/3p5ji17UTnmP9GgnDIHasCjykogM4FXzWKxz3WMeBydyKEuKJq
         n9RD0thCBPS8x5Pkzu8fNZDG4AxlDwuwN4s8Yg8N0GwA0a7ioa4xR/S8+GoqumcfxmCb
         JQ6qLihpfVv9/zozXfwsQhCenPnSn98m8fKswX8Lf0xWSuVsNmrxr6JEe9dWONuAd7K4
         Iwug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723449610; x=1724054410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FlkNJrCddLIBg5vltMyF9v0wIbCb4a2Vjj5HMwgSPqc=;
        b=nPkfPRy8MSPNXJDeDrupVh9ugfxteTOc+jhYj+sgU6W37jWrIJPkjk+sG4GgBzOVmy
         7OoZSeKvNHhtdENALepmQr+ka81bs3RzGnppvhS1Jbr3MxTvsrmQUoiaQpuWhmHFJWK3
         MAm28zco8ikdIv90Z/KEq8R9N35E3+O/0MWaQB70d9cyFv4MbxWWx9bWAARZgpSImvz5
         cfHm5I8jQ8nx3KmYiJqsTdN2n7uaKy+SGGSFu1BrmfrfzM+RyyurvF49eIeIhqwtOu1T
         QIz52Xjf0YOrptidz3IWRcLiXMByXWkwLfIp37Se56ctG3oOGxll+Zw0+xZOTgg28CpE
         vTPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+gatxLlJvNHy4+jvszY42t5ttUMUesZ+jq92uT0gPDeZMcv+WIYkjkUP4X6/6jgHk3yUTvg==@lfdr.de
X-Gm-Message-State: AOJu0Yy+W/O5Rl81stUYl9IYQEa/KiCAOKoH4KKEydBwrV81Mgzithwq
	dgdl3ZAgfisydnDIiJ9INlPKgk0lyOhz6uWZ+9JgqM/PKnf43Uk9
X-Google-Smtp-Source: AGHT+IGFET+njefnRmxQHntIHalxhU5D9p/UjHOaKxtf89UYQHUhPuIupMcH7/pcfgykXcX8S+W5TQ==
X-Received: by 2002:a17:902:ec89:b0:1fd:9b96:32f5 with SMTP id d9443c01a7336-200ae55f06bmr118686865ad.31.1723449609454;
        Mon, 12 Aug 2024 01:00:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:db07:b0:1fa:81bc:f4f6 with SMTP id
 d9443c01a7336-2009063facels30119755ad.2.-pod-prod-03-us; Mon, 12 Aug 2024
 01:00:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjxHqOCsaMkO0vm2rx9ACuj0Lcpu9EWrsmvio7/Qa3CT5+b/BehIhtQt1fK8OZ4R8FZdCBKKfGFMU=@googlegroups.com
X-Received: by 2002:a05:6a21:38b:b0:1be:c4bb:6f31 with SMTP id adf61e73a8af0-1c89fe99b59mr11697852637.18.1723449608225;
        Mon, 12 Aug 2024 01:00:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723449608; cv=none;
        d=google.com; s=arc-20160816;
        b=j5YCn+ihglPdDyaQajPVNuhAZMUVxmj9St5yQFwCO2J6LrqxfANlkb8XEZhus7lsNj
         5Cl3R2N4i93wBRpUNxnb+DWXhLgpH6mK8qa69coH9lWEhNvKXdqa+H6OXse3DGPJFIHm
         5lUuikDr7YkMzRUkQlJIErX5LoP41yUhMU5yPsg8YH6pafQ9R9eRRDOldnl3VNKDrKh+
         EgoaLyOvcCqs1IgzMihX/Wpghx+l1xCxO88FSOpCpupWGhBoH0qQLImV3OZJjzEYGEGu
         h9c3ENQZz1ehvSCkmQfSdjMp0EKb606qKP7g/C/ZKHfpZk934lKn8f/znDDN5morajwg
         yTSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=F8QjTcNkTYwR3QaJrDLOWR/4DZgIIKZr5o7qbqN+Pjw=;
        fh=DCcJIpPH+xPeS85r+DPxy3EXJIAjvwU95VgvuX+SHyI=;
        b=HZOcjk1A1+rZmkgkORlKiWEnr4GajyGeaOhm82UCKDIqkH9Xo99Bu7Zt1dMHvLb7zh
         MnSgzhPhpJLsqPd+x9qrmbkqWfZR/xBKxWIQy1HVj/AltU1A+qkvHibvEckSDCu8Yazv
         h4C0EmoaD4GanUvIs+E0qdXldXhtjtWSkP6tlS/1iBbSHLFg2x2LBzbhIlqz8jdbKBg8
         KLxCjAzxNgfikAXpdDvGhPmb0Es34dgXWFnRu5TKSrPKGETevwdQLr3mb8vN6gZJ+Zpx
         l2oY8U4TDXlUoommt2ah5Ux/N3n/NqP2awWlIyWeuy5NBvld0ln4u3nqllr5L/d/yc87
         HBFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.alibaba.com header.s=default header.b=ty31G37+;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.98 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
Received: from out30-98.freemail.mail.aliyun.com (out30-98.freemail.mail.aliyun.com. [115.124.30.98])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-200bb69634bsi1651955ad.0.2024.08.12.01.00.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Aug 2024 01:00:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.98 as permitted sender) client-ip=115.124.30.98;
Received: from 30.97.49.58(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0WCbyGqV_1723449602)
          by smtp.aliyun-inc.com;
          Mon, 12 Aug 2024 16:00:03 +0800
Message-ID: <673dba4d-7d45-4e2e-8d2f-b969be0732c1@linux.alibaba.com>
Date: Mon, 12 Aug 2024 16:00:02 +0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kfence: Save freeing stack trace at calling time instead
 of freeing time
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20240812065947.6104-1-dtcccc@linux.alibaba.com>
 <CANpmjNPT5nm7vMiBXgf2b2EuCcyfM2hNKP=Cro0Vjo9qngS5aw@mail.gmail.com>
From: Tianchen Ding <dtcccc@linux.alibaba.com>
In-Reply-To: <CANpmjNPT5nm7vMiBXgf2b2EuCcyfM2hNKP=Cro0Vjo9qngS5aw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.alibaba.com header.s=default header.b=ty31G37+;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates
 115.124.30.98 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.alibaba.com
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

On 2024/8/12 15:49, Marco Elver wrote:
> On Mon, 12 Aug 2024 at 09:00, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
>>
>> For kmem_cache with SLAB_TYPESAFE_BY_RCU, the freeing trace stack at
>> calling kmem_cache_free() is more useful. While the following stack is
>> meaningless and provides no help:
>>    freed by task 46 on cpu 0 at 656.840729s:
>>     rcu_do_batch+0x1ab/0x540
>>     nocb_cb_wait+0x8f/0x260
>>     rcu_nocb_cb_kthread+0x25/0x80
>>     kthread+0xd2/0x100
>>     ret_from_fork+0x34/0x50
>>     ret_from_fork_asm+0x1a/0x30
>>
>> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>
>> ---
>> I'm not sure whether we should keep KFENCE_OBJECT_FREED info remained
>> (maybe the exact free time can be helpful?). But add a new kfence_track
>> will cost more memory, so I prefer to reuse free_track and drop the info
>> when when KFENCE_OBJECT_RCU_FREEING -> KFENCE_OBJECT_FREED.
> 
> I think the current version is fine. In the SLAB_TYPESAFE_BY_RCU cases
> it would always print the stack trace of RCU internals, so it's never
> really useful (as you say above).
> 
> Have you encountered a bug where you were debugging a UAF like this?

Yes. We are debugging a UAF about struct anon_vma in an old kernel. (finally we 
found this may be related to commit 2555283eb40d)

struct anon_vma has SLAB_TYPESAFE_BY_RCU, so we found the freeing stack is useless.

> If not, what prompted you to send this patch?
> 
> Did you run the KFENCE test suite?

Yes. All passed.

> 
>> ---
>>   mm/kfence/core.c   | 35 ++++++++++++++++++++++++++---------
>>   mm/kfence/kfence.h |  1 +
>>   mm/kfence/report.c |  7 ++++---
>>   3 files changed, 31 insertions(+), 12 deletions(-)
>>
>> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
>> index c5cb54fc696d..89469d4f2d95 100644
>> --- a/mm/kfence/core.c
>> +++ b/mm/kfence/core.c
>> @@ -269,6 +269,13 @@ static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *m
>>          return pageaddr;
>>   }
>>
>> +static bool kfence_obj_inuse(const struct kfence_metadata *meta)
> 
> Other tiny helpers add "inline" so that the compiler is more likely to
> inline this. In optimized kernels it should do so by default, but with
> some heavily instrumented kernels we need to lower the inlining
> threshold - adding "inline" does that.
> 
> Also, note we have KFENCE_OBJECT_UNUSED state, so the
> kfence_obj_inuse() helper name would suggest to me that it's all other
> states.
> 
> If the object is being freed with RCU, it is still technically
> allocated and _usable_ until the next RCU grace period. So maybe
> kfence_obj_allocated() is a more accurate name?
> 
>> +{
>> +       enum kfence_object_state state = READ_ONCE(meta->state);
>> +
>> +       return state == KFENCE_OBJECT_ALLOCATED || state == KFENCE_OBJECT_RCU_FREEING;
>> +}
>> +
>>   /*
>>    * Update the object's metadata state, including updating the alloc/free stacks
>>    * depending on the state transition.
>> @@ -278,10 +285,14 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
>>                        unsigned long *stack_entries, size_t num_stack_entries)
>>   {
>>          struct kfence_track *track =
>> -               next == KFENCE_OBJECT_FREED ? &meta->free_track : &meta->alloc_track;
>> +               next == KFENCE_OBJECT_ALLOCATED ? &meta->alloc_track : &meta->free_track;
>>
>>          lockdep_assert_held(&meta->lock);
>>
>> +       /* Stack has been saved when calling rcu, skip. */
>> +       if (READ_ONCE(meta->state) == KFENCE_OBJECT_RCU_FREEING)
>> +               goto out;
>> +
>>          if (stack_entries) {
>>                  memcpy(track->stack_entries, stack_entries,
>>                         num_stack_entries * sizeof(stack_entries[0]));
>> @@ -297,6 +308,7 @@ metadata_update_state(struct kfence_metadata *meta, enum kfence_object_state nex
>>          track->cpu = raw_smp_processor_id();
>>          track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
>>
>> +out:
>>          /*
>>           * Pairs with READ_ONCE() in
>>           *      kfence_shutdown_cache(),
>> @@ -502,7 +514,7 @@ static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool z
>>
>>          raw_spin_lock_irqsave(&meta->lock, flags);
>>
>> -       if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
>> +       if (!kfence_obj_inuse(meta) || meta->addr != (unsigned long)addr) {
>>                  /* Invalid or double-free, bail out. */
>>                  atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
>>                  kfence_report_error((unsigned long)addr, false, NULL, meta,
>> @@ -780,7 +792,7 @@ static void kfence_check_all_canary(void)
>>          for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
>>                  struct kfence_metadata *meta = &kfence_metadata[i];
>>
>> -               if (meta->state == KFENCE_OBJECT_ALLOCATED)
>> +               if (kfence_obj_inuse(meta))
>>                          check_canary(meta);
>>          }
>>   }
>> @@ -1006,12 +1018,11 @@ void kfence_shutdown_cache(struct kmem_cache *s)
>>                   * the lock will not help, as different critical section
>>                   * serialization will have the same outcome.
>>                   */
>> -               if (READ_ONCE(meta->cache) != s ||
>> -                   READ_ONCE(meta->state) != KFENCE_OBJECT_ALLOCATED)
>> +               if (READ_ONCE(meta->cache) != s || !kfence_obj_inuse(meta))
>>                          continue;
>>
>>                  raw_spin_lock_irqsave(&meta->lock, flags);
>> -               in_use = meta->cache == s && meta->state == KFENCE_OBJECT_ALLOCATED;
>> +               in_use = meta->cache == s && kfence_obj_inuse(meta);
>>                  raw_spin_unlock_irqrestore(&meta->lock, flags);
>>
>>                  if (in_use) {
>> @@ -1145,6 +1156,7 @@ void *kfence_object_start(const void *addr)
>>   void __kfence_free(void *addr)
>>   {
>>          struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
>> +       unsigned long flags;
> 
> This flags variable does not need to be scoped for the whole function.
> It can just be scoped within the if-branch where it's needed (at least
> I don't see other places besides there where it's used).
> 
>>   #ifdef CONFIG_MEMCG
>>          KFENCE_WARN_ON(meta->obj_exts.objcg);
>> @@ -1154,9 +1166,14 @@ void __kfence_free(void *addr)
>>           * the object, as the object page may be recycled for other-typed
>>           * objects once it has been freed. meta->cache may be NULL if the cache
>>           * was destroyed.
>> +        * Save the stack trace here. It is more useful.
> 
> "It is more useful." adds no value to the comment.
> 
> I would say something like: "Save the stack trace here so that reports
> show where the user freed the object."
> 
>>           */
>> -       if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU)))
>> +       if (unlikely(meta->cache && (meta->cache->flags & SLAB_TYPESAFE_BY_RCU))) {
>> +               raw_spin_lock_irqsave(&meta->lock, flags);
>> +               metadata_update_state(meta, KFENCE_OBJECT_RCU_FREEING, NULL, 0);
>> +               raw_spin_unlock_irqrestore(&meta->lock, flags);
>>                  call_rcu(&meta->rcu_head, rcu_guarded_free);
>> +       }
> 
> Wrong if-else style. Turn the whole thing into
> 
> if (...) {
>     ...
> } else {
>    kfence_guarded_free(...);
> }
> 
> So it looks balanced.
> 
>>          else
>>                  kfence_guarded_free(addr, meta, false);
>>   }
>> @@ -1182,14 +1199,14 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
>>                  int distance = 0;
>>
>>                  meta = addr_to_metadata(addr - PAGE_SIZE);
>> -               if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
>> +               if (meta && kfence_obj_inuse(meta)) {
>>                          to_report = meta;
>>                          /* Data race ok; distance calculation approximate. */
>>                          distance = addr - data_race(meta->addr + meta->size);
>>                  }
>>
>>                  meta = addr_to_metadata(addr + PAGE_SIZE);
>> -               if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
>> +               if (meta && kfence_obj_inuse(meta)) {
>>                          /* Data race ok; distance calculation approximate. */
>>                          if (!to_report || distance > data_race(meta->addr) - addr)
>>                                  to_report = meta;
>> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
>> index db87a05047bd..dfba5ea06b01 100644
>> --- a/mm/kfence/kfence.h
>> +++ b/mm/kfence/kfence.h
>> @@ -38,6 +38,7 @@
>>   enum kfence_object_state {
>>          KFENCE_OBJECT_UNUSED,           /* Object is unused. */
>>          KFENCE_OBJECT_ALLOCATED,        /* Object is currently allocated. */
>> +       KFENCE_OBJECT_RCU_FREEING,      /* Object was allocated, and then being freed by rcu. */
>>          KFENCE_OBJECT_FREED,            /* Object was allocated, and then freed. */
>>   };
>>
>> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
>> index 73a6fe42845a..451991a3a8f2 100644
>> --- a/mm/kfence/report.c
>> +++ b/mm/kfence/report.c
>> @@ -114,7 +114,8 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
>>
>>          /* Timestamp matches printk timestamp format. */
>>          seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago):\n",
>> -                      show_alloc ? "allocated" : "freed", track->pid,
>> +                      show_alloc ? "allocated" : meta->state == KFENCE_OBJECT_RCU_FREEING ?
>> +                      "rcu freeing" : "freed", track->pid,
>>                         track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
>>                         (unsigned long)interval_nsec, rem_interval_nsec / 1000);
>>
>> @@ -149,7 +150,7 @@ void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *met
>>
>>          kfence_print_stack(seq, meta, true);
>>
>> -       if (meta->state == KFENCE_OBJECT_FREED) {
>> +       if (meta->state == KFENCE_OBJECT_FREED || meta->state == KFENCE_OBJECT_RCU_FREEING) {
>>                  seq_con_printf(seq, "\n");
>>                  kfence_print_stack(seq, meta, false);
>>          }
>> @@ -318,7 +319,7 @@ bool __kfence_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *sla
>>          kpp->kp_slab_cache = meta->cache;
>>          kpp->kp_objp = (void *)meta->addr;
>>          kfence_to_kp_stack(&meta->alloc_track, kpp->kp_stack);
>> -       if (meta->state == KFENCE_OBJECT_FREED)
>> +       if (meta->state == KFENCE_OBJECT_FREED || meta->state == KFENCE_OBJECT_RCU_FREEING)
>>                  kfence_to_kp_stack(&meta->free_track, kpp->kp_free_stack);
>>          /* get_stack_skipnr() ensures the first entry is outside allocator. */
>>          kpp->kp_ret = kpp->kp_stack[0];
>> --
>> 2.39.3
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812065947.6104-1-dtcccc%40linux.alibaba.com.

Thanks for your comments. I'll fix them and send v2 later.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/673dba4d-7d45-4e2e-8d2f-b969be0732c1%40linux.alibaba.com.
