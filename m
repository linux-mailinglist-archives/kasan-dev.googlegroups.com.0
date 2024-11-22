Return-Path: <kasan-dev+bncBCKLNNXAXYFBBUGSQK5AMGQEPEGKRHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A3DF9D6194
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 16:54:57 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-38242c5b4ffsf1234275f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2024 07:54:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732290897; cv=pass;
        d=google.com; s=arc-20240605;
        b=JMXRAvQPFJiPB6MmCKFC/O7MJVD6Js28TMExtWvNdeYKNAx1wwJuYLkEvLm7kbPsAU
         YD5Ce75uCpaymI+mNmpPjZzNodsHqKYEI6WHxdcrEthKljPPD/OgFb637hIqdogUNeqg
         yF1RGOV1JiZPdtsDDK/zEdPPGf+BYN0deV4kTHxsp3//Cz+li3GE7njqqthI38nFdMNh
         NQjZKOIFongqGdnOorF3/tHMzdPKOAZarutaVBBYDNhdVGBdZ2jOXWph1zwp4K59viVa
         Utga2drKRDZXjeEatFEKu2Rj/DPWocFCwOJ6EPYk5SqwFwEVU89fG42KP0xhHQJEIawu
         +/7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=bOdQ8jdDYax1PJZm3yNmEr4etz6T5H3k98FLWUiNp7I=;
        fh=OuKWRnKyCbSNckTRp5NWQD2RPMkyfdRbw7fq+5aLKGY=;
        b=XIaqijbcAkXFt2yR24g4sn/aBxlWjF00V0H4Vzd/Zn9wjij7T9w6iv9Iig+C8ftyx5
         1CRjU4aAJPJvvg82/eaVtHJNbiR+0TNkqNmB8blm1gZyiSQDKdvRdHJkrgb9MwPeqlMW
         n9G1uAtfHr505mYDRWEk5ov7gtEL5I+2+nLa3ZosUVs82+h4Bfn+isHldKZ3KNrtj1yp
         bN/wHAFfEP50vypgm/tVF+H9lnD3/wMw8lN6jxRErtASIZNR065z1rTmjB2o26tqaM7W
         q3RTWqQGB1qFwbw9g1kmhwF9ArBrk8uuOxXM/VLyUr+1K05r+UcAbxCOD2Og6FL3sGke
         rmkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=dE3cTHlA;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=c1juVXva;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732290897; x=1732895697; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=bOdQ8jdDYax1PJZm3yNmEr4etz6T5H3k98FLWUiNp7I=;
        b=fAjpGkErPXUGwFixb64EvEtTxLmdPTHqYwjtUY99xcuT7MGLDeRnn6wlxlJKUeg/9w
         QsFSBEutl8cMdpBlpJUOiyB6ODNE49JxAZq0XzBe1MZWUtqmg+ZinEVHv4xwXMO1j/PA
         41ZgPFOM0crScS/QczzONiooiG+I24rQBR3TJDDWi8HJ0LkY2gfa3YtP2DZ8nbK+tQut
         wxXZTBQdFKAy5b9Fjg7xbsjkep4sKyTZW0B6XUzEwF5G9wWR/filZcMOnwj4gReylLAx
         w7n3K3PMam87kQWHCbbswC/ogX5O80u3uqcpUpozu/Cg5zTankNpUG89j+RTHU7jw8mn
         6irQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732290897; x=1732895697;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bOdQ8jdDYax1PJZm3yNmEr4etz6T5H3k98FLWUiNp7I=;
        b=g58NhvKOvcaKKMbdBjnxeuX2kWFTH7RrrpI6j7J7Ucfj2uNrK0P6y/M+aDZf8d1dCZ
         ESqxinIjfDroDz3Lg6cILSKbjB4l9qS51z06VbnZPmIZRnsJuv29+y4J7zUJM7te0foq
         ldxeNU30sA/rIwkr09jKw/eleR4OC5x+f2xBe6vY3QXfQF4jsDHtJcnq2QSEHM/l6hxi
         Pw6xzzB/2FMKRB6T2u3+7TbvkVtSq/wN4P79/LGwRbJwGO6nnPMFj6KKbJNjQgZLWRIW
         0vwCKX0HLDhrfv/gMtjg3mKE/en67N/mnaw0hSm8Nz2FJ6uqR287gddjuyhvFdN8/vaG
         KZ7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVPDtNjNnl0wTIO7SMblIjXkyFADsm0DspFRcN1Xd69dIn42ZTn0H41mQu/Cmkw2+CK1ZY/A==@lfdr.de
X-Gm-Message-State: AOJu0Yyi4rM/jZVxwWQtTonlIbqiP+62qXB7aj5kYf5cq2ja9lApZ6si
	gOEl3ynT8VvVB1XrI7RNZauM+0yIQH+kWSEtnQUucwI6814ddao4
X-Google-Smtp-Source: AGHT+IHU+0+9F2seAx5TsDA6lvqv/hh3qTIKcC0g52kDh+N7iBbdAj5YC2N5cmZ+rQaILUZ1OInPtg==
X-Received: by 2002:a05:6000:1fad:b0:382:4aa0:e727 with SMTP id ffacd0b85a97d-38260bcb828mr2928817f8f.40.1732290896384;
        Fri, 22 Nov 2024 07:54:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4608:b0:42c:af5b:facc with SMTP id
 5b1f17b1804b1-433c5df509cls7672975e9.1.-pod-prod-07-eu; Fri, 22 Nov 2024
 07:54:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVN7Gnyi2XLwVeEvMGmAtOa+YusPOLPoULRIxfBc9xSB4wfseCKlNM8Hw1+wK83LkhD5Dh8DKSdlXE=@googlegroups.com
X-Received: by 2002:a05:600c:348b:b0:42c:c003:edd1 with SMTP id 5b1f17b1804b1-433ce41ce4emr35339455e9.10.1732290893871;
        Fri, 22 Nov 2024 07:54:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732290893; cv=none;
        d=google.com; s=arc-20240605;
        b=TOxoKwCy2eB6YNL0xVYI6wP7OY2h2AD0q8sdPkmsbboKMq66od2gPvq/ewl7fx/AmD
         FKIZ86r8eZrnEFqZVA7I1/33jJJMq4jjiEJySYv266U9SIpktCFOH6SIypGyY+F/82+2
         qVUqjD/oxgUp77GmH4sOtdy2z8bLo4m59VMePT/QED78xCcq6WeMGMMkxs1ag/PwXNDo
         hj8mlbQbyro9wFl8hoTlzjGjLFmcGUF42exjm7fHfMmzs01t6C8U+P3n1VLyTFTzkW/o
         lDWnYTDSE5atFz1/6NRt13ZPj0tnOTKQbkf+c/NNkyV/DJh2spD6iMAIpy4tLTBj9BGD
         aYwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:dkim-signature:date;
        bh=ZbQPnVZqE+G9GCldWBdvS97jPY1ZKwkWnp4Cqk0q/4c=;
        fh=Sy27l84g7ApLB4stBl/+5gX3Mk2fYSw44gFdqB9/Ok0=;
        b=DqFhF/yN2/VTsGNd03L2uaDEGJXmYEQ3qkp48iSYrUpOVX4ayICnhT4Ke4tBaNjXDW
         UWQ4FjBs0Iva3GR1gQR5xlRbeNecyZvnLxRsM+4Oz15/O6XS1d/3JfwM3Q7GJU2e637Z
         13xLc4YuqzQXd+SuEd3heIsEYZLl9HFWrj40pcUzqIYsSbZoxSJ3vHwCjoNr5e4auN0P
         +tgSIgqEAryWTkmWr/PwSIIh/2NxvM1NguUohTMX+8n6FkPXHGSToZFJqdum5oL4Lo1D
         ZZ+veywfYZBTJBl0t5XoVrS/xrNhUo9xPn3jXMeMYYaPsGzUoLbjXfhVKzD0egQTTXsj
         QC5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=dE3cTHlA;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=c1juVXva;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43366cba3e4si3294065e9.1.2024.11.22.07.54.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Nov 2024 07:54:53 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Fri, 22 Nov 2024 16:54:51 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
	Liam.Howlett@oracle.com, akpm@linux-foundation.org,
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Waiman Long <longman@redhat.com>, dvyukov@google.com,
	vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org,
	neeraj.upadhyay@kernel.org, joel@joelfernandes.org,
	josh@joshtriplett.org, boqun.feng@gmail.com, urezki@gmail.com,
	rostedt@goodmis.org, mathieu.desnoyers@efficios.com,
	jiangshanlai@gmail.com, qiang.zhang1211@gmail.com, mingo@redhat.com,
	juri.lelli@redhat.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
	vschneid@redhat.com, tj@kernel.org, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	Thomas Gleixner <tglx@linutronix.de>, roman.gushchin@linux.dev,
	42.hyeyoo@gmail.com, rcu@vger.kernel.org
Subject: [PATCH v2] kasan: Make kasan_record_aux_stack_noalloc() the default
 behaviour
Message-ID: <20241122155451.Mb2pmeyJ@linutronix.de>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
 <20241119155701.GYennzPF@linutronix.de>
 <CA+fCnZfzJcbEy0Qmn5GPzPUx9diR+3qw+4ukHa2j5xzzQMF8Kw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfzJcbEy0Qmn5GPzPUx9diR+3qw+4ukHa2j5xzzQMF8Kw@mail.gmail.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=dE3cTHlA;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=c1juVXva;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

From: Peter Zijlstra <peterz@infradead.org>

kasan_record_aux_stack_noalloc() was introduced to record a stack trace
without allocating memory in the process. It has been added to callers
which were invoked while a raw_spinlock_t was held.
More and more callers were identified and changed over time. Is it a
good thing to have this while functions try their best to do a
locklessly setup? The only downside of having kasan_record_aux_stack()
not allocate any memory is that we end up without a stacktrace if
stackdepot runs out of memory and at the same stacktrace was not
recorded before To quote Marco Elver from
   https://lore.kernel.org/all/CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jt=
bof9nVQ@mail.gmail.com/

| I'd be in favor, it simplifies things. And stack depot should be
| able to replenish its pool sufficiently in the "non-aux" cases
| i.e. regular allocations. Worst case we fail to record some
| aux stacks, but I think that's only really bad if there's a bug
| around one of these allocations. In general the probabilities
| of this being a regression are extremely small [...]

Make the kasan_record_aux_stack_noalloc() behaviour default as
kasan_record_aux_stack().

[bigeasy: Dressed the diff as patch. ]

Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/67275485.050a0220.3c8d68.0a37.GAE@googl=
e.com
Acked-by: Waiman Long <longman@redhat.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Fixes: 7cb3007ce2da2 ("kasan: generic: introduce kasan_record_aux_stack_noa=
lloc()")
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
v1=E2=80=A6v2:
  - Renamed the patch as per Marco.
  - Added comment to kasan_record_aux_stack() as per Andrey.
  - Added fixes tag since Waiman that it is the only user.
  - Added Marco's quote from the mail to the commit description.

 include/linux/kasan.h     |  2 --
 include/linux/task_work.h |  3 ---
 kernel/irq_work.c         |  2 +-
 kernel/rcu/tiny.c         |  2 +-
 kernel/rcu/tree.c         |  4 ++--
 kernel/sched/core.c       |  2 +-
 kernel/task_work.c        | 14 +-------------
 kernel/workqueue.c        |  2 +-
 mm/kasan/generic.c        | 18 ++++++------------
 mm/slub.c                 |  2 +-
 10 files changed, 14 insertions(+), 37 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 00a3bf7c0d8f0..1a623818e8b39 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -488,7 +488,6 @@ void kasan_cache_create(struct kmem_cache *cache, unsig=
ned int *size,
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
-void kasan_record_aux_stack_noalloc(void *ptr);
=20
 #else /* CONFIG_KASAN_GENERIC */
=20
@@ -506,7 +505,6 @@ static inline void kasan_cache_create(struct kmem_cache=
 *cache,
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
-static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
=20
 #endif /* CONFIG_KASAN_GENERIC */
=20
diff --git a/include/linux/task_work.h b/include/linux/task_work.h
index 2964171856e00..0646804860ff1 100644
--- a/include/linux/task_work.h
+++ b/include/linux/task_work.h
@@ -19,9 +19,6 @@ enum task_work_notify_mode {
 	TWA_SIGNAL,
 	TWA_SIGNAL_NO_IPI,
 	TWA_NMI_CURRENT,
-
-	TWA_FLAGS =3D 0xff00,
-	TWAF_NO_ALLOC =3D 0x0100,
 };
=20
 static inline bool task_work_pending(struct task_struct *task)
diff --git a/kernel/irq_work.c b/kernel/irq_work.c
index 2f4fb336dda17..73f7e1fd4ab4d 100644
--- a/kernel/irq_work.c
+++ b/kernel/irq_work.c
@@ -147,7 +147,7 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
 	if (!irq_work_claim(work))
 		return false;
=20
-	kasan_record_aux_stack_noalloc(work);
+	kasan_record_aux_stack(work);
=20
 	preempt_disable();
 	if (cpu !=3D smp_processor_id()) {
diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
index b3b3ce34df631..4b3f319114650 100644
--- a/kernel/rcu/tiny.c
+++ b/kernel/rcu/tiny.c
@@ -250,7 +250,7 @@ EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
 void kvfree_call_rcu(struct rcu_head *head, void *ptr)
 {
 	if (head)
-		kasan_record_aux_stack_noalloc(ptr);
+		kasan_record_aux_stack(ptr);
=20
 	__kvfree_call_rcu(head, ptr);
 }
diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index b1f883fcd9185..7eae9bd818a90 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -3083,7 +3083,7 @@ __call_rcu_common(struct rcu_head *head, rcu_callback=
_t func, bool lazy_in)
 	}
 	head->func =3D func;
 	head->next =3D NULL;
-	kasan_record_aux_stack_noalloc(head);
+	kasan_record_aux_stack(head);
 	local_irq_save(flags);
 	rdp =3D this_cpu_ptr(&rcu_data);
 	lazy =3D lazy_in && !rcu_async_should_hurry();
@@ -3807,7 +3807,7 @@ void kvfree_call_rcu(struct rcu_head *head, void *ptr=
)
 		return;
 	}
=20
-	kasan_record_aux_stack_noalloc(ptr);
+	kasan_record_aux_stack(ptr);
 	success =3D add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
 	if (!success) {
 		run_page_cache_worker(krcp);
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index a1c353a62c568..3717360a940d2 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -10485,7 +10485,7 @@ void task_tick_mm_cid(struct rq *rq, struct task_st=
ruct *curr)
 		return;
=20
 	/* No page allocation under rq lock */
-	task_work_add(curr, work, TWA_RESUME | TWAF_NO_ALLOC);
+	task_work_add(curr, work, TWA_RESUME);
 }
=20
 void sched_mm_cid_exit_signals(struct task_struct *t)
diff --git a/kernel/task_work.c b/kernel/task_work.c
index c969f1f26be58..d1efec571a4a4 100644
--- a/kernel/task_work.c
+++ b/kernel/task_work.c
@@ -55,26 +55,14 @@ int task_work_add(struct task_struct *task, struct call=
back_head *work,
 		  enum task_work_notify_mode notify)
 {
 	struct callback_head *head;
-	int flags =3D notify & TWA_FLAGS;
=20
-	notify &=3D ~TWA_FLAGS;
 	if (notify =3D=3D TWA_NMI_CURRENT) {
 		if (WARN_ON_ONCE(task !=3D current))
 			return -EINVAL;
 		if (!IS_ENABLED(CONFIG_IRQ_WORK))
 			return -EINVAL;
 	} else {
-		/*
-		 * Record the work call stack in order to print it in KASAN
-		 * reports.
-		 *
-		 * Note that stack allocation can fail if TWAF_NO_ALLOC flag
-		 * is set and new page is needed to expand the stack buffer.
-		 */
-		if (flags & TWAF_NO_ALLOC)
-			kasan_record_aux_stack_noalloc(work);
-		else
-			kasan_record_aux_stack(work);
+		kasan_record_aux_stack(work);
 	}
=20
 	head =3D READ_ONCE(task->task_works);
diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 9949ffad8df09..65b8314b2d538 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -2180,7 +2180,7 @@ static void insert_work(struct pool_workqueue *pwq, s=
truct work_struct *work,
 	debug_work_activate(work);
=20
 	/* record the work call stack in order to print it in KASAN reports */
-	kasan_record_aux_stack_noalloc(work);
+	kasan_record_aux_stack(work);
=20
 	/* we own @work, set data and link */
 	set_work_pwq(work, pwq, extra_flags);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 6310a180278b6..2242249c2d50d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -521,7 +521,11 @@ size_t kasan_metadata_size(struct kmem_cache *cache, b=
ool in_object)
 			sizeof(struct kasan_free_meta) : 0);
 }
=20
-static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags=
)
+/*
+ * This function avoids dynamic memory allocations and thus can be called =
from
+ * contexts that do not allow allocating memory.
+ */
+void kasan_record_aux_stack(void *addr)
 {
 	struct slab *slab =3D kasan_addr_to_slab(addr);
 	struct kmem_cache *cache;
@@ -538,17 +542,7 @@ static void __kasan_record_aux_stack(void *addr, depot=
_flags_t depot_flags)
 		return;
=20
 	alloc_meta->aux_stack[1] =3D alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] =3D kasan_save_stack(0, depot_flags);
-}
-
-void kasan_record_aux_stack(void *addr)
-{
-	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
-}
-
-void kasan_record_aux_stack_noalloc(void *addr)
-{
-	return __kasan_record_aux_stack(addr, 0);
+	alloc_meta->aux_stack[0] =3D kasan_save_stack(0, 0);
 }
=20
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t f=
lags)
diff --git a/mm/slub.c b/mm/slub.c
index 5b832512044e3..b8c4bf3fe0d07 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2300,7 +2300,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bo=
ol init,
 			 * We have to do this manually because the rcu_head is
 			 * not located inside the object.
 			 */
-			kasan_record_aux_stack_noalloc(x);
+			kasan_record_aux_stack(x);
=20
 			delayed_free->object =3D x;
 			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
--=20
2.45.2

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0241122155451.Mb2pmeyJ%40linutronix.de.
