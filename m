Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4756K4QMGQES7QT2KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 419979D2B1B
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 17:38:13 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-6ea33140094sf74714707b3.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 08:38:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732034291; cv=pass;
        d=google.com; s=arc-20240605;
        b=K60Uz0LhIugcbYLORp2Na1kuIl3O8QOA+BY4ixDsx6Rb/Eh9y89jrnDRIFyHhVnPaV
         1djFv2bm/NxwHwIsl1iYaWv/lvThL77pOgAACeAWmuC5fepG/S0hIdmjrH4AXil7dt93
         ciJ30xHR9rteQeHDL5LoAJ6TV0XBQvvi3IkrJVd9j11vTNhFMue505jkZKLlIFATPBFx
         X1GFrtueWBDdKaho4Nd/cBXF0/YJbpPiwDthrZXrhdZLcpP5gVMRNRjZFQPwRwkJjYj3
         ZenBeQKi3dxZGdGHYq5w2j03YN3fpS/S7Lt8Fi6Eh7pVBC8yV5MubyGT52CoRHXCVjR6
         XGqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7vo8y3Eb7I1XPrPV7/bg28lF2uR5TY/kFp/KtjiN5eo=;
        fh=loGa3YqZcqrfwYq4WgAyq4goDOZuntWjxEwmJUubQMA=;
        b=eAkTHAFfqbMUZURJ7PZ+MU3SHSeCJCelB71NeheyodYLvEHn03qH9Kth/lwYduYU1m
         23/vVCGidvZsaWkJagxkD0fDUtiSfYHyqG1OAL7zbToWeXaGL4Dsk1UYwC1u4y0+w+kv
         LVOuZf2+K70SEgHxnDx5/nYSMPfNdKjjRLZSfHGv+rAbMJk9nn45u6oLQvtka1XGW1A6
         4n88BiGt0HbCU0tOp7tXL+ABMBvbaPEIpo/oDCAOq9Mfc/PQ/Ayv8wZjYW2/bdzYIlXM
         4hLEF6z+rJdHh3ahsYthHb4R0eyLEFKBJVZH9a8EuNluVO+CHjeUm5dU/zV991ASWTwJ
         sksA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JSRQY8jE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732034291; x=1732639091; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7vo8y3Eb7I1XPrPV7/bg28lF2uR5TY/kFp/KtjiN5eo=;
        b=o3E20lZGUn2La2SNm2/tfW/JamZe8l4HC41WjtUKo9P4+KjjUiKMZFYmjrHstOGotv
         N0i5FEoaL2thwiqOhWq8Fv47goFtcFghMiDbqbz6y4nShswt0GmaAcCiRDFTgnf8bIdf
         nxPymVXX38IJ9l5EwlRW5/lgtQpDrkX5C9dqHNO4/kV+RaAldwUkPVSGBhQPFv/kwSSF
         lwW8X9NtHCPNG25LHCzX7/ytZLd++FygvVG1ZL7v7civ/p6gdE123klwdMJt8MCgcdpj
         0SnalcgK/T9lKkYQe88wLf9CBGJ26T8tQoCzuZdL4w0VEZJ2vEV06xZ+7XY4I4p3++Vv
         oX1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732034291; x=1732639091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7vo8y3Eb7I1XPrPV7/bg28lF2uR5TY/kFp/KtjiN5eo=;
        b=qXLg+3rbNkZXTUOCFVfdNhj2eT2ripdnQbSFAAIDRSpUcX6pM5kLNebAFRnf4Jag38
         mpcoPMgmFVxAvSZ39HVmLB4RJlbBxIpqx00bx49fnSPjVrY/6hQJw4+c9q7f89edBuh/
         6+Xc7gdgjXbXE32o78ThHoaPdDNPTzrNaVeCnVePzGMSAYG6PycRwaFeYGw6kcx9B//5
         Re/ImXx1YFiUT1EH4Baw2dBch/8UCTVv1YrlobGGDDFr3AnPUdg9LVLR8pXcYxvjyMkS
         sWCIZuqo0u5+JlK9zzyxiGcACNrEozI3H67DwbvlhYkfvj74Nq7XjBmnASeK0MU8I3s9
         9LNA==
X-Forwarded-Encrypted: i=2; AJvYcCWL4JGa7lgYwm95uhDMX8lV4OuFVlUs9YStGarx81MlyqxuI5lON94lFMaXdZkpFhjdV5/qRA==@lfdr.de
X-Gm-Message-State: AOJu0Yzl8Kcr3wnTTh9joNmSlf6wHFZGHoqC5YwbbaXus+uJnfrJZO8m
	/eKACeVtIJ/pCri361k7loZDMtxItbKaanR2qWZtNHEEr0Sdei7P
X-Google-Smtp-Source: AGHT+IHhF+7qN9rVcj1aIzCPrrC9ElO2HkSYdb2VcvCZ/dWT6H0YW6jQRN8mR4rZGXbJK4F68IGjdg==
X-Received: by 2002:a05:6902:1207:b0:e38:b399:5918 with SMTP id 3f1490d57ef6-e38b39a2136mr4438098276.5.1732034291473;
        Tue, 19 Nov 2024 08:38:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:154b:b0:e30:84f1:999f with SMTP id
 3f1490d57ef6-e3825ae92a4ls625919276.0.-pod-prod-02-us; Tue, 19 Nov 2024
 08:38:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWW4Af5asUpnown6ocfc77WBW8wGK4gb2jo4RrKiIwjsP8VcSMCJnGi4x/0aUgQuF9+abqm3bt9OqU=@googlegroups.com
X-Received: by 2002:a05:6902:709:b0:e38:b4f4:da7c with SMTP id 3f1490d57ef6-e38b4f4db3fmr3599327276.7.1732034290169;
        Tue, 19 Nov 2024 08:38:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732034290; cv=none;
        d=google.com; s=arc-20240605;
        b=R5PzgDOkqGj4r56mizUYhcNb3V2DJfv0F8b+9hvV5kIb3c9ibHKcVZCZFmRABTyR7u
         SSQyqopi6dquMqOWs0RAXMRMR7ZQTBqEQnJQIoaDIEZ7J6gzouf7hiSb2XypF73zLqJu
         a6sdoEn9Kb7kwUziv4bpl78p3bmvcueqt8zKTx/58jQgBI3BL3PBinqni+CyjBpXdcqb
         roEJSPa6bGPriqZU4/nV18wBKMc60+8apt2fnYVP2Gt2JxMnoaM/ffWX87ZNUl/RpKtx
         4kqsR0UWpL4s5lN4TGa48eWnwnNQAwsoLjTa56KuzAgSCE8s4koYGVeuIdEt1fyApc2U
         d2Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tsi76Pj99/LFVNHPqhU6HGDCzJfL0N7wlXitIphx0zw=;
        fh=XDLvzXyi6sTAN+Q+GjruAF3IKnZ8+8WICqsxZF6m9oE=;
        b=KAsHPtk15eeMneu9G58k/1/MJJkIhB98WS6DcaQOlrCcfnw4HNAMqZhSIgWmMcyNtx
         Vyfv+g36Ka7eSmPoD7LRo1Cnvye/LYKSr9IWeP1gk0349Kanj5F91Vrs8cSHRQlPqEBe
         4oWmpIg9N3I0P+bEHpZ+zDgmOZFYhj6eTnMsZha+bKktSZzwLsdlrKEVyXLi35Vxul19
         JUUqFGo/Cn2z30rxH2Bc2+whoKy4v9PstubB0BIpZNWoyqjVD50yXPB/1HYN+ddRZqDg
         ISyigH6iD3iP4GlUzwiR5Mp7OsIgxNdwwCQRIhj3+LGPlx/2hNYLnxFxOKRAPSb7KHoa
         HnwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JSRQY8jE;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-46392b9328bsi937431cf.1.2024.11.19.08.38.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2024 08:38:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-723f37dd76cso3849980b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2024 08:38:10 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVC+IKuhwyXsST3vlDZrXO4Fqtj4U2C2dW7M+ANec0L2nxZxL/lz2edML4bUTX0b3oB8hEIpHrg/2A=@googlegroups.com
X-Received: by 2002:a05:6a00:1390:b0:724:592d:aa5f with SMTP id
 d2e1a72fcca58-72476c4c25amr21755898b3a.19.1732034289334; Tue, 19 Nov 2024
 08:38:09 -0800 (PST)
MIME-Version: 1.0
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com> <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz> <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com> <20241119155701.GYennzPF@linutronix.de>
In-Reply-To: <20241119155701.GYennzPF@linutronix.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Nov 2024 17:37:33 +0100
Message-ID: <CANpmjNNEBpb8E=zQtD4mAM4VaqTVbabvMKuWpSd+prVrK=mmGw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Remove kasan_record_aux_stack_noalloc().
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Peter Zijlstra <peterz@infradead.org>, Vlastimil Babka <vbabka@suse.cz>, 
	syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>, 
	Liam.Howlett@oracle.com, akpm@linux-foundation.org, jannh@google.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lorenzo.stoakes@oracle.com, 
	syzkaller-bugs@googlegroups.com, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Waiman Long <longman@redhat.com>, dvyukov@google.com, 
	vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org, 
	neeraj.upadhyay@kernel.org, joel@joelfernandes.org, josh@joshtriplett.org, 
	boqun.feng@gmail.com, urezki@gmail.com, rostedt@goodmis.org, 
	mathieu.desnoyers@efficios.com, jiangshanlai@gmail.com, 
	qiang.zhang1211@gmail.com, mingo@redhat.com, juri.lelli@redhat.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, 
	mgorman@suse.de, vschneid@redhat.com, tj@kernel.org, cl@linux.com, 
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com, 
	Thomas Gleixner <tglx@linutronix.de>, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, 
	rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=JSRQY8jE;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::435 as
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

On Tue, 19 Nov 2024 at 16:57, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> From: Peter Zijlstra <peterz@infradead.org>

The patch title is misleading - it might suggest the opposite of what
it's doing. I think this might be clearer:

"kasan: Make kasan_record_aux_stack_noalloc() the default behaviour"

Which is also more or less what you say below.

> kasan_record_aux_stack_noalloc() was introduced to record a stack trace
> without allocating memory in the process. It has been added to callers
> which were invoked while a raw_spinlock_t was held.
> More and more callers were identified and changed over time. Is it a
> good thing to have this while functions try their best to do a
> locklessly setup? The only downside of having kasan_record_aux_stack()
> not allocate any memory is that we end up without a stacktrace if
> stackdepot runs out of memory and at the same stacktrace was not
> recorded before. Marco Elver said in
>         https://lore.kernel.org/all/20210913112609.2651084-1-elver@google.com/
> that this is rare.
>
> Make the kasan_record_aux_stack_noalloc() behaviour default as
> kasan_record_aux_stack().
>
> [bigeasy: Dressed the diff as patch. ]
>
> Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/67275485.050a0220.3c8d68.0a37.GAE@google.com
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Reviewed-by: Marco Elver <elver@google.com>

As I wrote in https://lore.kernel.org/all/CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com/:

> I'd be in favor, it simplifies things. And stack depot should be
> able to replenish its pool sufficiently in the "non-aux" cases
> i.e. regular allocations. Worst case we fail to record some
> aux stacks, but I think that's only really bad if there's a bug
> around one of these allocations. In general the probabilities
> of this being a regression are extremely small [...]

Good riddance.

Thanks,
-- Marco

> ---
>
> Didn't add a Fixes tag, didn't want to put
>    7cb3007ce2da2 ("kasan: generic: introduce kasan_record_aux_stack_noalloc()")
>
> there.
>
>  include/linux/kasan.h     |  2 --
>  include/linux/task_work.h |  3 ---
>  kernel/irq_work.c         |  2 +-
>  kernel/rcu/tiny.c         |  2 +-
>  kernel/rcu/tree.c         |  4 ++--
>  kernel/sched/core.c       |  2 +-
>  kernel/task_work.c        | 14 +-------------
>  kernel/workqueue.c        |  2 +-
>  mm/kasan/generic.c        | 14 ++------------
>  mm/slub.c                 |  2 +-
>  10 files changed, 10 insertions(+), 37 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 00a3bf7c0d8f0..1a623818e8b39 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -488,7 +488,6 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>  void kasan_cache_shrink(struct kmem_cache *cache);
>  void kasan_cache_shutdown(struct kmem_cache *cache);
>  void kasan_record_aux_stack(void *ptr);
> -void kasan_record_aux_stack_noalloc(void *ptr);
>
>  #else /* CONFIG_KASAN_GENERIC */
>
> @@ -506,7 +505,6 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
>  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
>  static inline void kasan_record_aux_stack(void *ptr) {}
> -static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
>
>  #endif /* CONFIG_KASAN_GENERIC */
>
> diff --git a/include/linux/task_work.h b/include/linux/task_work.h
> index 2964171856e00..0646804860ff1 100644
> --- a/include/linux/task_work.h
> +++ b/include/linux/task_work.h
> @@ -19,9 +19,6 @@ enum task_work_notify_mode {
>         TWA_SIGNAL,
>         TWA_SIGNAL_NO_IPI,
>         TWA_NMI_CURRENT,
> -
> -       TWA_FLAGS = 0xff00,
> -       TWAF_NO_ALLOC = 0x0100,
>  };
>
>  static inline bool task_work_pending(struct task_struct *task)
> diff --git a/kernel/irq_work.c b/kernel/irq_work.c
> index 2f4fb336dda17..73f7e1fd4ab4d 100644
> --- a/kernel/irq_work.c
> +++ b/kernel/irq_work.c
> @@ -147,7 +147,7 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
>         if (!irq_work_claim(work))
>                 return false;
>
> -       kasan_record_aux_stack_noalloc(work);
> +       kasan_record_aux_stack(work);
>
>         preempt_disable();
>         if (cpu != smp_processor_id()) {
> diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
> index b3b3ce34df631..4b3f319114650 100644
> --- a/kernel/rcu/tiny.c
> +++ b/kernel/rcu/tiny.c
> @@ -250,7 +250,7 @@ EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
>  void kvfree_call_rcu(struct rcu_head *head, void *ptr)
>  {
>         if (head)
> -               kasan_record_aux_stack_noalloc(ptr);
> +               kasan_record_aux_stack(ptr);
>
>         __kvfree_call_rcu(head, ptr);
>  }
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index b1f883fcd9185..7eae9bd818a90 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -3083,7 +3083,7 @@ __call_rcu_common(struct rcu_head *head, rcu_callback_t func, bool lazy_in)
>         }
>         head->func = func;
>         head->next = NULL;
> -       kasan_record_aux_stack_noalloc(head);
> +       kasan_record_aux_stack(head);
>         local_irq_save(flags);
>         rdp = this_cpu_ptr(&rcu_data);
>         lazy = lazy_in && !rcu_async_should_hurry();
> @@ -3807,7 +3807,7 @@ void kvfree_call_rcu(struct rcu_head *head, void *ptr)
>                 return;
>         }
>
> -       kasan_record_aux_stack_noalloc(ptr);
> +       kasan_record_aux_stack(ptr);
>         success = add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
>         if (!success) {
>                 run_page_cache_worker(krcp);
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index a1c353a62c568..3717360a940d2 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -10485,7 +10485,7 @@ void task_tick_mm_cid(struct rq *rq, struct task_struct *curr)
>                 return;
>
>         /* No page allocation under rq lock */
> -       task_work_add(curr, work, TWA_RESUME | TWAF_NO_ALLOC);
> +       task_work_add(curr, work, TWA_RESUME);
>  }
>
>  void sched_mm_cid_exit_signals(struct task_struct *t)
> diff --git a/kernel/task_work.c b/kernel/task_work.c
> index c969f1f26be58..d1efec571a4a4 100644
> --- a/kernel/task_work.c
> +++ b/kernel/task_work.c
> @@ -55,26 +55,14 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
>                   enum task_work_notify_mode notify)
>  {
>         struct callback_head *head;
> -       int flags = notify & TWA_FLAGS;
>
> -       notify &= ~TWA_FLAGS;
>         if (notify == TWA_NMI_CURRENT) {
>                 if (WARN_ON_ONCE(task != current))
>                         return -EINVAL;
>                 if (!IS_ENABLED(CONFIG_IRQ_WORK))
>                         return -EINVAL;
>         } else {
> -               /*
> -                * Record the work call stack in order to print it in KASAN
> -                * reports.
> -                *
> -                * Note that stack allocation can fail if TWAF_NO_ALLOC flag
> -                * is set and new page is needed to expand the stack buffer.
> -                */
> -               if (flags & TWAF_NO_ALLOC)
> -                       kasan_record_aux_stack_noalloc(work);
> -               else
> -                       kasan_record_aux_stack(work);
> +               kasan_record_aux_stack(work);
>         }
>
>         head = READ_ONCE(task->task_works);
> diff --git a/kernel/workqueue.c b/kernel/workqueue.c
> index 9949ffad8df09..65b8314b2d538 100644
> --- a/kernel/workqueue.c
> +++ b/kernel/workqueue.c
> @@ -2180,7 +2180,7 @@ static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
>         debug_work_activate(work);
>
>         /* record the work call stack in order to print it in KASAN reports */
> -       kasan_record_aux_stack_noalloc(work);
> +       kasan_record_aux_stack(work);
>
>         /* we own @work, set data and link */
>         set_work_pwq(work, pwq, extra_flags);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 6310a180278b6..b18b5944997f8 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -521,7 +521,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
>                         sizeof(struct kasan_free_meta) : 0);
>  }
>
> -static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
> +void kasan_record_aux_stack(void *addr)
>  {
>         struct slab *slab = kasan_addr_to_slab(addr);
>         struct kmem_cache *cache;
> @@ -538,17 +538,7 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>                 return;
>
>         alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> -       alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
> -}
> -
> -void kasan_record_aux_stack(void *addr)
> -{
> -       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
> -}
> -
> -void kasan_record_aux_stack_noalloc(void *addr)
> -{
> -       return __kasan_record_aux_stack(addr, 0);
> +       alloc_meta->aux_stack[0] = kasan_save_stack(0, 0);
>  }
>
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> diff --git a/mm/slub.c b/mm/slub.c
> index 5b832512044e3..b8c4bf3fe0d07 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2300,7 +2300,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
>                          * We have to do this manually because the rcu_head is
>                          * not located inside the object.
>                          */
> -                       kasan_record_aux_stack_noalloc(x);
> +                       kasan_record_aux_stack(x);
>
>                         delayed_free->object = x;
>                         call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
> --
> 2.45.2
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNEBpb8E%3DzQtD4mAM4VaqTVbabvMKuWpSd%2BprVrK%3DmmGw%40mail.gmail.com.
