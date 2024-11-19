Return-Path: <kasan-dev+bncBCPILY4NUAFBBZXW6K4QMGQESG3WSVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 740D69D2AC0
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 17:23:06 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4608a1a8d3esf114938751cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 08:23:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732033382; cv=pass;
        d=google.com; s=arc-20240605;
        b=XAqIc0tRysJvfuCNPajgZkD8AV/2ZRq7QobN57o0dlPCBg+mP70a0C18s6TwA8xUy+
         UU+eFqX16Ulu5OSt/w3iZASyNrrtDGYZAxi2MjAbmK8JSuJKyWprFvJghhINuv/4HXeb
         tD+XXLiyHrIpGw0KT5P+4XEMgGzUM+nlcXl3+ONNuT52mPRjCFH04/T5sAXURHDatby3
         fixzSvFdY3kSI9RC7rJTK2XFZbsRmbnf0zG57LRGOXKQdCQloOKZglORwJ198Oa+xsVs
         TRJVLzf5vNYOpnG2TbhvJUtgphqRMeAvZN6LY8JjA4zAEnFdUn+37wVQutZbG4jjTGmj
         V8Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:sender:dkim-signature;
        bh=bApWJH08vgjSE5W+5oSzDqvOkwVhmZLcTDt6mFxQAEI=;
        fh=ZqjZme4smIuNh8sG9Dvzux0sGIwwzmzvGNDOyeefO38=;
        b=TJelIfTFuYl88rDawApVHzExPu1ZX15d8bZEtPtdzcqdGTBCGpTgd/AKi7ZfvIes+r
         GPId76E3nnCZgsRZDIptNl85zhnSYuhtwmF4rrJMYwUwpmmzSQT31l4pp6ILh/wW5evF
         clxaGmpxbxo7fHYiv4jJocmrYmXkkeJa7Xl0yLCLxOI+CJdnwgemIo68SvrAeDujt6Md
         ZIpZvlMH0xq6ZjHeTc/nbIV5EURD0BZdK9iQ2NvPAnnK5rzNTOYdsdl29P2/tdQPG0vR
         VPzH3wjjftQ/J+m10oi4/ntjALmtI4LEwhXyc9RnR/725WoT3hof2ftD5Q8d4slUQwds
         UEZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TUT4XGjl;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732033382; x=1732638182; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=bApWJH08vgjSE5W+5oSzDqvOkwVhmZLcTDt6mFxQAEI=;
        b=rGbScz20UIDDJ3EzP+PGp2+vCAxHQocQmdzwKnEjnoxhc8uEK05Fs9d67D4+tBLKZJ
         cl70+OLlmdCZMpqWD5br8fzEbG3hwNsQU4UT923R6/k3G6m92kyhRsIGFalSoNxXld+z
         vPBUMjVJt7NTheCGUCfuQQqVl96N/9oyovssSScjrIwPBK1joHysO+CyPNV9o3p2qyBR
         q9TczD1TzgLgVZUe5Zz7ja8Ht7uqmQWGxd4ynUOdI/hVr1IV5NBibcwfHCEi3Gvc93ra
         Com60rLhXXV2n6Z1Vb9e9O6N/H5hldIZckdfbsrs89pe12eF5a1hCEhw1IPsoyiy890L
         8Q+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732033382; x=1732638182;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bApWJH08vgjSE5W+5oSzDqvOkwVhmZLcTDt6mFxQAEI=;
        b=sdNpaXv5gkOgu569yNApoCwjnEPdf0IOLurb+JFItqokLvcIkACd1W8Ipf6j0MSWq8
         ubPsYm+gAhy9TGL18qWztya38GzOV/uIHAR2XTRgCDl8pODJc+xviZoeBVZjXkVQh9si
         9USR+oY3RZX6Y2gKRIubpd0IVi1FX4mF43GvzPSEuVyiOvRnT5lNTtEF/P9xsGvPRCuK
         ZPsYgudaaFSETKJ4tOlN60k4xRabblAdg65YHFRcUpKD8TC4Ipg0m/DXJglqGOZ+xdXN
         JmGENjMI306EjiahHqQwzRwxcIO79YyCBlxINuYNBpVGEJiOcLic9Vnf79Fl7x+PXvWs
         J8TQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU9NeRq6CfplN+dU3eOnXcyzEo6kDIHpWyAixY+OLerhj4GLTiqPxIT7nDKg79HrYg00tao7Q==@lfdr.de
X-Gm-Message-State: AOJu0YzwsVWyYLJzGbJhuuCS6PTUhR3jeSkZERJk7xxc4WyYFV4VvJYN
	cjgYo/i/w/VkJ6wrq6yerFZ5PuEeforxIICa274QEZ03fvd0EMA4
X-Google-Smtp-Source: AGHT+IGUGfht1RUiTouek0FZl5bDmZeqDw6EZGJ1iWvY+E/U+5UgxaB1+pWXu16BJPKSgwpGeaPUIw==
X-Received: by 2002:a05:622a:5918:b0:458:1e37:f82 with SMTP id d75a77b69052e-46392df3aa2mr60429941cf.18.1732033382313;
        Tue, 19 Nov 2024 08:23:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:c7:b0:440:38e6:c194 with SMTP id
 d75a77b69052e-46356fee4dals20958311cf.2.-pod-prod-00-us; Tue, 19 Nov 2024
 08:23:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUIA3S+3p5NhmCTOeq/UOAP2+EIa4/Cj0dXPzheBRYDvXED5ADNlV4woCZ7C2Q0rBI7wS9oZo1GQm8=@googlegroups.com
X-Received: by 2002:a05:622a:4c8c:b0:463:4be4:b03f with SMTP id d75a77b69052e-46392d6cbffmr71306451cf.11.1732033381480;
        Tue, 19 Nov 2024 08:23:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732033381; cv=none;
        d=google.com; s=arc-20240605;
        b=lHOphaagxzGCeDbzeRCBWX8NPbzrF6ijHhkGZyA367XvKDxMRXkBaVhql+vFLSc4GW
         jy3Rkn7vaySabmlm7lNyUCB80F6pUW2WOazSzPIZ3wsyJEzTmpA4+o8DOExrvCQ8Z8Vl
         TafKPzg4y9eCBb3XCYsTr1gmBPfY9+d9zz1/VvyhnC4DDssXc4ratbjY9+Zr4KQqZPPl
         feGAuo4ydIlsam2gqC5yk0xIrHtxN9og7MCYXiN4HYeYl7pgf39VYmwfVdwy9ov+fwOs
         Lt7vluza8W4J94Qk1VyNfwgB0L8SHm6278q23cyfWRz0V1sXmVQcAuFMs6CjSGL8C+lB
         THGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:references
         :cc:to:subject:user-agent:mime-version:date:message-id:from
         :dkim-signature;
        bh=suWdsjJ5WnUgZV8pnJXIYBOLHIoG3Gy/626N1DpjAyk=;
        fh=Vqu+ysMUr1+KFAlGy0eM9Q/7OYW7XkG1DufrxDi2iSg=;
        b=cKpN6Jg0kfPExySGDvE2h8NfyYJaur8knQwbxNW44PRYDcQaYAuwasQbj3AzquWvWa
         ygmBGp2n5nZz7BrwaJI+yqYM0gQrsWgnnWNyXYWp8hlU2cuuL2iYuwpyhawSRtRNS2Lq
         xkcnAn/lBl7JW1JWzXwMkH8cTHE8VY8IurhEC/W43R62Um/IY4+TSteoiU6uhGYkx/Sq
         2xKpWUYCgugp4ovo96a0rg9XMD2RlqpOEyaGLp36JO5P++68kbUqALK8pxPASfVglclv
         xqxxcXsmhuxN4MTjoJxX3JbCmOmMZjhqREh5dWHzPHj8etjs/RPTpJb+UtSRu6ZI4bnI
         q7LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TUT4XGjl;
       spf=pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-46392c52d2esi1061701cf.4.2024.11.19.08.23.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2024 08:23:01 -0800 (PST)
Received-SPF: pass (google.com: domain of llong@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-io1-f70.google.com (mail-io1-f70.google.com
 [209.85.166.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-46-BUorsOLBMbiV4d7vZcYzYg-1; Tue, 19 Nov 2024 11:23:00 -0500
X-MC-Unique: BUorsOLBMbiV4d7vZcYzYg-1
X-Mimecast-MFC-AGG-ID: BUorsOLBMbiV4d7vZcYzYg
Received: by mail-io1-f70.google.com with SMTP id ca18e2360f4ac-83e5dd390bfso504858539f.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2024 08:22:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWrrJkiPH2LAtR8PJy/mSs0X6Py/rFPVJLN1DuXsYHl/n0UPsj01yvH7ja1AKNP8KU3i0xOPn0ZNYI=@googlegroups.com
X-Received: by 2002:a05:6e02:1526:b0:3a7:645f:6152 with SMTP id e9e14a558f8ab-3a77744e30cmr33621895ab.8.1732033379162;
        Tue, 19 Nov 2024 08:22:59 -0800 (PST)
X-Received: by 2002:a05:6e02:1526:b0:3a7:645f:6152 with SMTP id e9e14a558f8ab-3a77744e30cmr33621435ab.8.1732033378760;
        Tue, 19 Nov 2024 08:22:58 -0800 (PST)
Received: from ?IPV6:2601:188:ca00:a00:f844:fad5:7984:7bd7? ([2601:188:ca00:a00:f844:fad5:7984:7bd7])
        by smtp.gmail.com with ESMTPSA id e9e14a558f8ab-3a77ffe8df6sm1870915ab.72.2024.11.19.08.22.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2024 08:22:58 -0800 (PST)
From: Waiman Long <llong@redhat.com>
Message-ID: <95194abd-1ec6-4db3-9f83-4d482b2fac50@redhat.com>
Date: Tue, 19 Nov 2024 11:22:54 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kasan: Remove kasan_record_aux_stack_noalloc().
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
 syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
 Liam.Howlett@oracle.com, akpm@linux-foundation.org, jannh@google.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
 Andrey Konovalov <andreyknvl@gmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, dvyukov@google.com,
 vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org,
 neeraj.upadhyay@kernel.org, joel@joelfernandes.org, josh@joshtriplett.org,
 boqun.feng@gmail.com, urezki@gmail.com, rostedt@goodmis.org,
 mathieu.desnoyers@efficios.com, jiangshanlai@gmail.com,
 qiang.zhang1211@gmail.com, mingo@redhat.com, juri.lelli@redhat.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com,
 mgorman@suse.de, vschneid@redhat.com, tj@kernel.org, cl@linux.com,
 penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
 Thomas Gleixner <tglx@linutronix.de>, roman.gushchin@linux.dev,
 42.hyeyoo@gmail.com, rcu@vger.kernel.org
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
 <20241119155701.GYennzPF@linutronix.de>
In-Reply-To: <20241119155701.GYennzPF@linutronix.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: y3km8cflfC4KdHL3GrlMfqM8BRJ-v4Q9U8eQ7-Esdew_1732033379
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: llong@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TUT4XGjl;
       spf=pass (google.com: domain of llong@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=llong@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 11/19/24 10:57 AM, Sebastian Andrzej Siewior wrote:
> From: Peter Zijlstra <peterz@infradead.org>
>
> kasan_record_aux_stack_noalloc() was introduced to record a stack trace
> without allocating memory in the process. It has been added to callers
> which were invoked while a raw_spinlock_t was held.
> More and more callers were identified and changed over time. Is it a
> good thing to have this while functions try their best to do a
> locklessly setup? The only downside of having kasan_record_aux_stack()
> not allocate any memory is that we end up without a stacktrace if
> stackdepot runs out of memory and at the same stacktrace was not
> recorded before. Marco Elver said in
> 	https://lore.kernel.org/all/20210913112609.2651084-1-elver@google.com/
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
> ---
>
> Didn't add a Fixes tag, didn't want to put
>     7cb3007ce2da2 ("kasan: generic: introduce kasan_record_aux_stack_noalloc()")
>
> there.

Right now task_work_add() is the only caller of 
kasan_record_aux_stack(). So it essentially make all its callers use the 
noalloc version of kasan_record_aux_stack().

Acked-by: Waiman Long <longman@redhat.com>

>   include/linux/kasan.h     |  2 --
>   include/linux/task_work.h |  3 ---
>   kernel/irq_work.c         |  2 +-
>   kernel/rcu/tiny.c         |  2 +-
>   kernel/rcu/tree.c         |  4 ++--
>   kernel/sched/core.c       |  2 +-
>   kernel/task_work.c        | 14 +-------------
>   kernel/workqueue.c        |  2 +-
>   mm/kasan/generic.c        | 14 ++------------
>   mm/slub.c                 |  2 +-
>   10 files changed, 10 insertions(+), 37 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 00a3bf7c0d8f0..1a623818e8b39 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -488,7 +488,6 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>   void kasan_cache_shrink(struct kmem_cache *cache);
>   void kasan_cache_shutdown(struct kmem_cache *cache);
>   void kasan_record_aux_stack(void *ptr);
> -void kasan_record_aux_stack_noalloc(void *ptr);
>   
>   #else /* CONFIG_KASAN_GENERIC */
>   
> @@ -506,7 +505,6 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
>   static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>   static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
>   static inline void kasan_record_aux_stack(void *ptr) {}
> -static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
>   
>   #endif /* CONFIG_KASAN_GENERIC */
>   
> diff --git a/include/linux/task_work.h b/include/linux/task_work.h
> index 2964171856e00..0646804860ff1 100644
> --- a/include/linux/task_work.h
> +++ b/include/linux/task_work.h
> @@ -19,9 +19,6 @@ enum task_work_notify_mode {
>   	TWA_SIGNAL,
>   	TWA_SIGNAL_NO_IPI,
>   	TWA_NMI_CURRENT,
> -
> -	TWA_FLAGS = 0xff00,
> -	TWAF_NO_ALLOC = 0x0100,
>   };
>   
>   static inline bool task_work_pending(struct task_struct *task)
> diff --git a/kernel/irq_work.c b/kernel/irq_work.c
> index 2f4fb336dda17..73f7e1fd4ab4d 100644
> --- a/kernel/irq_work.c
> +++ b/kernel/irq_work.c
> @@ -147,7 +147,7 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
>   	if (!irq_work_claim(work))
>   		return false;
>   
> -	kasan_record_aux_stack_noalloc(work);
> +	kasan_record_aux_stack(work);
>   
>   	preempt_disable();
>   	if (cpu != smp_processor_id()) {
> diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
> index b3b3ce34df631..4b3f319114650 100644
> --- a/kernel/rcu/tiny.c
> +++ b/kernel/rcu/tiny.c
> @@ -250,7 +250,7 @@ EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
>   void kvfree_call_rcu(struct rcu_head *head, void *ptr)
>   {
>   	if (head)
> -		kasan_record_aux_stack_noalloc(ptr);
> +		kasan_record_aux_stack(ptr);
>   
>   	__kvfree_call_rcu(head, ptr);
>   }
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index b1f883fcd9185..7eae9bd818a90 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -3083,7 +3083,7 @@ __call_rcu_common(struct rcu_head *head, rcu_callback_t func, bool lazy_in)
>   	}
>   	head->func = func;
>   	head->next = NULL;
> -	kasan_record_aux_stack_noalloc(head);
> +	kasan_record_aux_stack(head);
>   	local_irq_save(flags);
>   	rdp = this_cpu_ptr(&rcu_data);
>   	lazy = lazy_in && !rcu_async_should_hurry();
> @@ -3807,7 +3807,7 @@ void kvfree_call_rcu(struct rcu_head *head, void *ptr)
>   		return;
>   	}
>   
> -	kasan_record_aux_stack_noalloc(ptr);
> +	kasan_record_aux_stack(ptr);
>   	success = add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
>   	if (!success) {
>   		run_page_cache_worker(krcp);
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index a1c353a62c568..3717360a940d2 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -10485,7 +10485,7 @@ void task_tick_mm_cid(struct rq *rq, struct task_struct *curr)
>   		return;
>   
>   	/* No page allocation under rq lock */
> -	task_work_add(curr, work, TWA_RESUME | TWAF_NO_ALLOC);
> +	task_work_add(curr, work, TWA_RESUME);
>   }
>   
>   void sched_mm_cid_exit_signals(struct task_struct *t)
> diff --git a/kernel/task_work.c b/kernel/task_work.c
> index c969f1f26be58..d1efec571a4a4 100644
> --- a/kernel/task_work.c
> +++ b/kernel/task_work.c
> @@ -55,26 +55,14 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
>   		  enum task_work_notify_mode notify)
>   {
>   	struct callback_head *head;
> -	int flags = notify & TWA_FLAGS;
>   
> -	notify &= ~TWA_FLAGS;
>   	if (notify == TWA_NMI_CURRENT) {
>   		if (WARN_ON_ONCE(task != current))
>   			return -EINVAL;
>   		if (!IS_ENABLED(CONFIG_IRQ_WORK))
>   			return -EINVAL;
>   	} else {
> -		/*
> -		 * Record the work call stack in order to print it in KASAN
> -		 * reports.
> -		 *
> -		 * Note that stack allocation can fail if TWAF_NO_ALLOC flag
> -		 * is set and new page is needed to expand the stack buffer.
> -		 */
> -		if (flags & TWAF_NO_ALLOC)
> -			kasan_record_aux_stack_noalloc(work);
> -		else
> -			kasan_record_aux_stack(work);
> +		kasan_record_aux_stack(work);
>   	}
>   
>   	head = READ_ONCE(task->task_works);
> diff --git a/kernel/workqueue.c b/kernel/workqueue.c
> index 9949ffad8df09..65b8314b2d538 100644
> --- a/kernel/workqueue.c
> +++ b/kernel/workqueue.c
> @@ -2180,7 +2180,7 @@ static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
>   	debug_work_activate(work);
>   
>   	/* record the work call stack in order to print it in KASAN reports */
> -	kasan_record_aux_stack_noalloc(work);
> +	kasan_record_aux_stack(work);
>   
>   	/* we own @work, set data and link */
>   	set_work_pwq(work, pwq, extra_flags);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 6310a180278b6..b18b5944997f8 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -521,7 +521,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
>   			sizeof(struct kasan_free_meta) : 0);
>   }
>   
> -static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
> +void kasan_record_aux_stack(void *addr)
>   {
>   	struct slab *slab = kasan_addr_to_slab(addr);
>   	struct kmem_cache *cache;
> @@ -538,17 +538,7 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
>   		return;
>   
>   	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
> -	alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
> -}
> -
> -void kasan_record_aux_stack(void *addr)
> -{
> -	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
> -}
> -
> -void kasan_record_aux_stack_noalloc(void *addr)
> -{
> -	return __kasan_record_aux_stack(addr, 0);
> +	alloc_meta->aux_stack[0] = kasan_save_stack(0, 0);
>   }
>   
>   void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
> diff --git a/mm/slub.c b/mm/slub.c
> index 5b832512044e3..b8c4bf3fe0d07 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2300,7 +2300,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
>   			 * We have to do this manually because the rcu_head is
>   			 * not located inside the object.
>   			 */
> -			kasan_record_aux_stack_noalloc(x);
> +			kasan_record_aux_stack(x);
>   
>   			delayed_free->object = x;
>   			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/95194abd-1ec6-4db3-9f83-4d482b2fac50%40redhat.com.
