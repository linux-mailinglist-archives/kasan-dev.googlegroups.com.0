Return-Path: <kasan-dev+bncBDW2JDUY5AORBZWR6O4QMGQEII2EOUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 720329D2EE6
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 20:37:12 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3824ab6674esf591604f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 11:37:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732045032; cv=pass;
        d=google.com; s=arc-20240605;
        b=R1pBM+qEaTrhyTamAWf+hDtw3xyE0NGqaPBI4YHoitbQCFMz48a5fzCKvLblfnZSfV
         JofNgw0PvH5ptOThL8h/SWRRjMHz+tjU2RQXm4ZGeuXXvxBdBCqy3F8v6aQyvpoQBVY+
         5FQ8jf2ulxCAuIPaiTh4sAdQR1XXqma9s+hL9zs6sybPK7VIi3bswxz7o8j2Bu8qf/4T
         sdTGGatKLVAZFHvcf03874XTJ57nnwO4fV6Mistt1KfwZ7hObsyAL0ZsBOP4C9G9ucUa
         BYqw/KJq9VFlaj3f2BJAfPSzr/WK1ZnFMCVuSkCr8QulksGGbyWmcinlWCbS/i681hGw
         W+Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/kE4AlJvO/nUP11127vKF7pHyoULHauhaX440Avd6yk=;
        fh=zNRENcmglS0ERMegp4Of3m+L9Rj0Xfaqz/bv5Bk+MWU=;
        b=jXyzCPc7CjPaOKqowQn5X9yoktL2mkTCs98XtIz7P2wPGlkyFh7vZSrkHMNtWsFRBF
         fSyqX1BEXLcWIPA5viUH4gqPWrQh4FkwBvyw5RFgq1EJnh7pwbzfyZEGOkNt8Ogt3fvF
         Qcj2ZpzFgRYAC0HQjPujwanw88h0h4k2pKWreQ8Kf8MX8T4Dbsv7bf8nu36O5MV7hRm8
         dW8xQzMrfSf+utcpEYKi75lUbwseH2aejt/P2ff8HHMY8RD2cLK9gKe3ejk5lWDIbIAm
         IagVNzSSUpwvIUAZnGb+NCaosebrSybkw7iWLUVdOLvsHqkXz345ImRuBWN3pt4sQh2i
         Cmsg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HR04FMqC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732045032; x=1732649832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/kE4AlJvO/nUP11127vKF7pHyoULHauhaX440Avd6yk=;
        b=BOtr8GIfcxyGi8GzZDSlUiOWYfxakfvvlAf4gg7GBDsHMldBN0Agj3xD/Z8yU0mJCm
         Pnvy9WBCthZFWBTVux90QIX4zD1Uhq6t/MaB4J+/8TQ9t0PkFvQK5fS5l5BIbtNuY1LQ
         BcrNO8/VQvJ7WR1JpVjj3cCUWef/Auusw8XN9DbWUbQxuaPMvB3OemXXl9AHw1SR7BXc
         R33g+16phl8fbXPV1s74P8RgzUt4YjEggRAKhZfGh9NieaXPtE5R5Ifud/4powQracMd
         oBOdvElfyppudoL7/9Vm6+4lWjX4kbGQmvzgy47V73ei7Xdrwdc7VKppZ3xI+b5tfjBe
         zM1Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1732045032; x=1732649832; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/kE4AlJvO/nUP11127vKF7pHyoULHauhaX440Avd6yk=;
        b=ealV/23PsJrR8i5WOU4TJJKfoBj+D3xsjGdt41j1VoY3m4kcH/8zPUgIUi4+hWO2OM
         YcdL196uucSYMZ8ednGf30DkQw7gpLneY5NvYRa9es1shpZZlDvAFhGkLiz0fmw/HFsr
         Bebg70V0M+673Qh7bfV76MrK16Epp9F1fc0YNnIW3xoiSfIdvcon9zwEji+xdzIAlsFb
         LUk8GFwGbKZEmHZ7j420GfwpMrizH/ZNuSrwoy/3OGcy2nrnx0nkpD/L6c8Vnr8s1LGo
         AAy7AfrTG+bWrE539MtlbCyJOSfPRXJ0k2hXVplgObInfMeNKOhYQemT99mes90MJA0B
         TZDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732045032; x=1732649832;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/kE4AlJvO/nUP11127vKF7pHyoULHauhaX440Avd6yk=;
        b=pyBXyN53uxjGTCLdhiY9mBmgaKUjUa/7Y6V+rYckjXjMOWls0BPCs/m8cwFGpdqPNl
         4TA/wgXFQnrAGBy1BtQRHK/OHi78/KsKhY+NpwhX5HrSVeVKUl0jNRND+/y/tpKFjp51
         MyWZlTdxQblO2wzhF3WWpilJer0TYL8z7tJdKzsXvUPYEzhUJNbTG3AIFp6JDivn1qaX
         WukcHSnq9EPU6F21t6AvqSY3zxYWpXWIeShqk7/PG4PYqBg68Usyna9tf7zTyvuctzUY
         JUp1cQ0RIgQ+FI9XTfLTyJ8qhEaDePm6tP4uCJBJXBZXF0Rn7J7XBy/GkhY3hZTJiXWm
         4PtQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVlTOaNveQPwFlwX8skYtosXicA4IOB7e2sg24cMqOAkJgCCROi0f/vdr8DltH8BBGGIrmetA==@lfdr.de
X-Gm-Message-State: AOJu0YxwXGjlx7hFv8ItrnrCa/Kz5OOBczqXLjyRaDFMdIkHQe+kl+K3
	LYCiTQAjNLXPp+Zjo3z7EwO0ZKlMGGdadYmhHl1oqBZ/1cdzMQE7
X-Google-Smtp-Source: AGHT+IGIBSA9q+HrJlA1yITFR61O1fTP0T1+oZnFigq3dtqN2198nLHyCoXR+PcULDNAGNfW19kekA==
X-Received: by 2002:a05:6000:4026:b0:382:3c7b:9ae with SMTP id ffacd0b85a97d-38254ae54a3mr26939f8f.16.1732045031115;
        Tue, 19 Nov 2024 11:37:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:15d1:b0:431:11e7:f13b with SMTP id
 5b1f17b1804b1-432f54091b4ls6152695e9.2.-pod-prod-07-eu; Tue, 19 Nov 2024
 11:37:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXbU5dEPAJ6J9yq60tDY928rdXgBPfPLo1Re05sfFE4F8GTpTEzkqyzdZYhpqQoYPPM9N6iiADtkOI=@googlegroups.com
X-Received: by 2002:a05:600c:1548:b0:431:7ca6:57b1 with SMTP id 5b1f17b1804b1-4334f022101mr1094305e9.32.1732045028920;
        Tue, 19 Nov 2024 11:37:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732045028; cv=none;
        d=google.com; s=arc-20240605;
        b=cLVgMJdmAkRibZ6FVf4dwFNCUd5aopDdEIdDiIaNt50pGxzzUH5xSyZ9J40+j9D5rZ
         XdnlmKrOn9M4sYdn5m07M0z76pkhL9mWMNSLUINDaZejH9GGR6owtOP6qPRixzyQVSyj
         7KuuknPyGXzSgUSS9/pNYi95ae5o9yEZ2BqtIok5ULcRjBEAVu1CRHuUwjz4fcR1vX5m
         HKEjIPOdv7fh93yEW0clqkd8aaFrE2iO1wC91lwtXLDCeTFWtwDdvyP92UHo50p7eNta
         4u4X4pEAQtGTtSvCEC+sP+GsUc+nlOMzMpXDTLEtlYudSpbb4fItjEJYJEnAsamHYsWY
         No1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=GdOKblGV+cU/H2wS4BCTlQ23goHv8tshPrwSMll3Yd8=;
        fh=yZ6j2OL1qAcHHh8juhyVT1pEmPYxV61NAVsbvU/X8Vs=;
        b=JgxzYAT9uD/i2l1GzCu7Ag5iQEBgkXQ9WvbyjaU51b7tuzaJSH2vTZkJQptap84cBa
         J/mxI99tHY33eY5qZb6sAbfsXTnqKH7mRw5ew33sdCIusy37O8GhFLv6F2bTT73nLgud
         eVLa/MmJ95zRYfXBswFw4FOS71kSwpb4uLWCTlpcFcGolMhWiBSB+qyFxDwWywZXzwu9
         I5tq1fnhgD65lpDbREOHHyPDG6UkxOLTWaNlmjcYLlKc/CseS5OKO33h33JNfU2q8uRL
         udoZDHnXxEn7KC4QkvF9qmEq9A7M0EW55kk7oJVzZDbl/T6eW6JXL7JZyHEnmu3nXoAl
         2KzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HR04FMqC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432dac1119dsi2484145e9.2.2024.11.19.11.37.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2024 11:37:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-4315e62afe0so12322905e9.1;
        Tue, 19 Nov 2024 11:37:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVCuW9YrV/bifsJnJsyvR8BCFXIEOifukUOWBei3cIMncZz+o7db8fOODvpHXAhuZ3uPzWdgOnS5Jc3MrAAoiY=@googlegroups.com, AJvYcCVvTUCznqgG2MwwP1QEj9mtVOkCzGKIy3ewZR64D9xhzGG/DvLCC/E4seMYC4VsV+CLtARKabJDOQk=@googlegroups.com
X-Received: by 2002:a05:6000:2805:b0:382:2ba9:9d65 with SMTP id
 ffacd0b85a97d-38254afb065mr13810f8f.31.1732045028095; Tue, 19 Nov 2024
 11:37:08 -0800 (PST)
MIME-Version: 1.0
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com> <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz> <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com> <20241119155701.GYennzPF@linutronix.de>
In-Reply-To: <20241119155701.GYennzPF@linutronix.de>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 19 Nov 2024 20:36:56 +0100
Message-ID: <CA+fCnZfzJcbEy0Qmn5GPzPUx9diR+3qw+4ukHa2j5xzzQMF8Kw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Remove kasan_record_aux_stack_noalloc().
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Vlastimil Babka <vbabka@suse.cz>, 
	syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>, 
	Liam.Howlett@oracle.com, akpm@linux-foundation.org, jannh@google.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, lorenzo.stoakes@oracle.com, 
	syzkaller-bugs@googlegroups.com, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Waiman Long <longman@redhat.com>, dvyukov@google.com, vincenzo.frascino@arm.com, 
	paulmck@kernel.org, frederic@kernel.org, neeraj.upadhyay@kernel.org, 
	joel@joelfernandes.org, josh@joshtriplett.org, boqun.feng@gmail.com, 
	urezki@gmail.com, rostedt@goodmis.org, mathieu.desnoyers@efficios.com, 
	jiangshanlai@gmail.com, qiang.zhang1211@gmail.com, mingo@redhat.com, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	bsegall@google.com, mgorman@suse.de, vschneid@redhat.com, tj@kernel.org, 
	cl@linux.com, penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com, 
	Thomas Gleixner <tglx@linutronix.de>, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, 
	rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HR04FMqC;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Nov 19, 2024 at 4:57=E2=80=AFPM Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
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
>         https://lore.kernel.org/all/20210913112609.2651084-1-elver@google=
.com/
> that this is rare.
>
> Make the kasan_record_aux_stack_noalloc() behaviour default as
> kasan_record_aux_stack().
>
> [bigeasy: Dressed the diff as patch. ]
>
> Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com
> Closes: https://lore.kernel.org/all/67275485.050a0220.3c8d68.0a37.GAE@goo=
gle.com
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> ---
>
> Didn't add a Fixes tag, didn't want to put
>    7cb3007ce2da2 ("kasan: generic: introduce kasan_record_aux_stack_noall=
oc()")
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
> @@ -488,7 +488,6 @@ void kasan_cache_create(struct kmem_cache *cache, uns=
igned int *size,
>  void kasan_cache_shrink(struct kmem_cache *cache);
>  void kasan_cache_shutdown(struct kmem_cache *cache);
>  void kasan_record_aux_stack(void *ptr);
> -void kasan_record_aux_stack_noalloc(void *ptr);
>
>  #else /* CONFIG_KASAN_GENERIC */
>
> @@ -506,7 +505,6 @@ static inline void kasan_cache_create(struct kmem_cac=
he *cache,
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
> -       TWA_FLAGS =3D 0xff00,
> -       TWAF_NO_ALLOC =3D 0x0100,
>  };
>
>  static inline bool task_work_pending(struct task_struct *task)
> diff --git a/kernel/irq_work.c b/kernel/irq_work.c
> index 2f4fb336dda17..73f7e1fd4ab4d 100644
> --- a/kernel/irq_work.c
> +++ b/kernel/irq_work.c
> @@ -147,7 +147,7 @@ bool irq_work_queue_on(struct irq_work *work, int cpu=
)
>         if (!irq_work_claim(work))
>                 return false;
>
> -       kasan_record_aux_stack_noalloc(work);
> +       kasan_record_aux_stack(work);
>
>         preempt_disable();
>         if (cpu !=3D smp_processor_id()) {
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
> @@ -3083,7 +3083,7 @@ __call_rcu_common(struct rcu_head *head, rcu_callba=
ck_t func, bool lazy_in)
>         }
>         head->func =3D func;
>         head->next =3D NULL;
> -       kasan_record_aux_stack_noalloc(head);
> +       kasan_record_aux_stack(head);
>         local_irq_save(flags);
>         rdp =3D this_cpu_ptr(&rcu_data);
>         lazy =3D lazy_in && !rcu_async_should_hurry();
> @@ -3807,7 +3807,7 @@ void kvfree_call_rcu(struct rcu_head *head, void *p=
tr)
>                 return;
>         }
>
> -       kasan_record_aux_stack_noalloc(ptr);
> +       kasan_record_aux_stack(ptr);
>         success =3D add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
>         if (!success) {
>                 run_page_cache_worker(krcp);
> diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> index a1c353a62c568..3717360a940d2 100644
> --- a/kernel/sched/core.c
> +++ b/kernel/sched/core.c
> @@ -10485,7 +10485,7 @@ void task_tick_mm_cid(struct rq *rq, struct task_=
struct *curr)
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
> @@ -55,26 +55,14 @@ int task_work_add(struct task_struct *task, struct ca=
llback_head *work,
>                   enum task_work_notify_mode notify)
>  {
>         struct callback_head *head;
> -       int flags =3D notify & TWA_FLAGS;
>
> -       notify &=3D ~TWA_FLAGS;
>         if (notify =3D=3D TWA_NMI_CURRENT) {
>                 if (WARN_ON_ONCE(task !=3D current))
>                         return -EINVAL;
>                 if (!IS_ENABLED(CONFIG_IRQ_WORK))
>                         return -EINVAL;
>         } else {
> -               /*
> -                * Record the work call stack in order to print it in KAS=
AN
> -                * reports.
> -                *
> -                * Note that stack allocation can fail if TWAF_NO_ALLOC f=
lag
> -                * is set and new page is needed to expand the stack buff=
er.
> -                */
> -               if (flags & TWAF_NO_ALLOC)
> -                       kasan_record_aux_stack_noalloc(work);
> -               else
> -                       kasan_record_aux_stack(work);
> +               kasan_record_aux_stack(work);
>         }
>
>         head =3D READ_ONCE(task->task_works);
> diff --git a/kernel/workqueue.c b/kernel/workqueue.c
> index 9949ffad8df09..65b8314b2d538 100644
> --- a/kernel/workqueue.c
> +++ b/kernel/workqueue.c
> @@ -2180,7 +2180,7 @@ static void insert_work(struct pool_workqueue *pwq,=
 struct work_struct *work,
>         debug_work_activate(work);
>
>         /* record the work call stack in order to print it in KASAN repor=
ts */
> -       kasan_record_aux_stack_noalloc(work);
> +       kasan_record_aux_stack(work);
>
>         /* we own @work, set data and link */
>         set_work_pwq(work, pwq, extra_flags);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 6310a180278b6..b18b5944997f8 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -521,7 +521,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache, =
bool in_object)
>                         sizeof(struct kasan_free_meta) : 0);
>  }
>
> -static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_fla=
gs)

Could you add a comment here that notes the usage, something like:

"This function avoids dynamic memory allocations and thus can be
called from contexts that do not allow allocating memory."

> +void kasan_record_aux_stack(void *addr)
>  {
>         struct slab *slab =3D kasan_addr_to_slab(addr);
>         struct kmem_cache *cache;
> @@ -538,17 +538,7 @@ static void __kasan_record_aux_stack(void *addr, dep=
ot_flags_t depot_flags)
>                 return;
>
>         alloc_meta->aux_stack[1] =3D alloc_meta->aux_stack[0];
> -       alloc_meta->aux_stack[0] =3D kasan_save_stack(0, depot_flags);
> -}
> -
> -void kasan_record_aux_stack(void *addr)
> -{
> -       return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC)=
;
> -}
> -
> -void kasan_record_aux_stack_noalloc(void *addr)
> -{
> -       return __kasan_record_aux_stack(addr, 0);
> +       alloc_meta->aux_stack[0] =3D kasan_save_stack(0, 0);
>  }
>
>  void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t=
 flags)
> diff --git a/mm/slub.c b/mm/slub.c
> index 5b832512044e3..b8c4bf3fe0d07 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2300,7 +2300,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, =
bool init,
>                          * We have to do this manually because the rcu_he=
ad is
>                          * not located inside the object.
>                          */
> -                       kasan_record_aux_stack_noalloc(x);
> +                       kasan_record_aux_stack(x);
>
>                         delayed_free->object =3D x;
>                         call_rcu(&delayed_free->head, slab_free_after_rcu=
_debug);
> --
> 2.45.2
>

Otherwise,

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfzJcbEy0Qmn5GPzPUx9diR%2B3qw%2B4ukHa2j5xzzQMF8Kw%40mail.gmail.com.
