Return-Path: <kasan-dev+bncBDW2JDUY5AORBFO446FAMGQEGLDDZQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 15EBF42032A
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 19:53:27 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id 4-20020a620504000000b0044be2cfac9bsf6432249pff.0
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 10:53:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633283605; cv=pass;
        d=google.com; s=arc-20160816;
        b=IQJi0rAhVauVqjx2PeiksUPPtfXsrR0HNSpfvLPmHp1xE55VbgRu6XjcvgDuqPkLOR
         v2oQDxMLDhOZxgmjUaSdHrV38cnQ+hy1i7xyp1rcHFGUD00c5JLUfeF4UTaGXRIFmpJ5
         oKNEZQDCoT+wZErGTLz22c65jlAkECzHO3A0c81YpwNOJ8Q2mgAxxQGEw8lao2/77Gjq
         8ZHEriC2jWtgEctEhe7h33AkmbMVeAo8WxzQ37NPCMB66hF/Te57M+lcu/c+UqK4DRF+
         QdtlHzCm85znRrnsgKm+sudPT83jxJ5JTQ6y4nhcbLFNVU1SkvP3UFmBjUFSQoYw88Rk
         y03A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ZVTTE7nsZmoiAZs1zZvkrLifttoQDGSgbY3/dEc8dC0=;
        b=Q6lJNuOQB2wCumRoAgDOuXRZphqE4ljMT1yuyzIOs/vZejkobvpPQsQbzie/OTrCB+
         mAhXrVuD3Tea12MVZTKbAylup1e8Fwt5JSqhvW9cReY5ag6XQNG26fVoIyEUymEfAWCL
         rC2oiK3Vm7t2xlkAMG7X9Jvsc9hEJwB9crKqlyL9OfhO48Wkt3kVip/LMaIWBiHirkwz
         HbNAhO+IlMG+m6C/Q2ZHMHyhfim28+lPIIMiWET821ajrbd2madVMz3JUZvqZgVHmWq6
         +nvl9OUgk6Dh2jo0vnqkvYibWLlaeKKQ9dQyIfhx+F+GlOwqgxPWaIdhgts7Pex2XVab
         oTYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Oz0X13K4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZVTTE7nsZmoiAZs1zZvkrLifttoQDGSgbY3/dEc8dC0=;
        b=bA7iXq9GueLOSBFwZZEIW/+NWPs6T97P6TFJCHUSSmwafo8x0n4nntcFMu6Q+Yzsxd
         Gh71DbMecQGVh/hPCAokFoV4VnLDC0j6tbO0xSDQVPq5bc+77WvscFUkiI8CIcNoiuCJ
         6thp6jS0wEu3Af7SyckrBv7MVy6dyWjEoePIRpaUrFus/JDxeYzD/cSUMh2fRW5vOalE
         SNgVS/CBo8bER2JSxdZ4JhdEOylKiapB45hXUKLze4QG6gJo0FcPc3Zi9E8olUZDETcn
         WDBhxlWJpmgCpY7nMOrMzKltsYdBJbZxElGLaAGhBY97J1lYFprEDOzA81zeHxA2kcjc
         iZEw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZVTTE7nsZmoiAZs1zZvkrLifttoQDGSgbY3/dEc8dC0=;
        b=aQJkmgcUO0TzNDIeNaQXi+8FOEIbWxsmSNTsUreFqCRA8lmbh1XdJM8rswphwIcRh1
         AuxUAx7byDAv8TgvsnY6V+o1sOk95nPh83V2NSuip28AJX946N6e15og9IsPzRsdEJkv
         XTj8RVl3yX4NNtI+IcNcHZ4mx1HmvhJz7CH7OBGmOigcHNxH+W0EmPxLpXaaqBlfmo5s
         ax88YEJseOhQernZID7ga/NAMqbfryiUeBPdxa8EX92j+qwUm4lI6hw0/A25p5NiuHoP
         EU+KnvAj6tBXDeI4vZ6Z92eguCvCRL7MLE/OuYaApRqCVhN6qU/IlO6ZOTsfwJ3hjjIN
         7JJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZVTTE7nsZmoiAZs1zZvkrLifttoQDGSgbY3/dEc8dC0=;
        b=06TjJTQP+X+564BGqcMOQxwiPb0rkXiKtl/h2udip+Rm5T8/QUyEAZF3rhKHRhuVmt
         FkA88RyYILcBCUN92hp9yT+3XQEePeucM8BUg7Hsm0tnWwMDffHwKROUi5GZ3jgd/r5a
         3G5rtt9IDp5bEVz0XlJlDyhkDUz1L4yynPyA2YnXwysNGp7RvwfPbllqq0y2AbpS/elU
         lUWUuXr4b3WxhPGdxE3Q17HZ8dzzKvMwuJH2Wxl2cCp2EVWBV/lTHIp79osGnM8cWDvH
         BeVS2MQUteJlE7WcQcosvgV70Edja75asU1I+K6i5WbLdZUiUUWJRUZ0m+bnh0Z0MrMh
         ADHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ezL6yGUN8iMeHMW6vUpEbql+xb6GwwO5WIDZe5s3Izm/ELHst
	WXDJamZ7lLyyBJnWEMv5tCM=
X-Google-Smtp-Source: ABdhPJxBnoDBg8MMHETzopy6hbZeUpCuvA/MQyLqJqJcbdFNtjN6a0FhPloouZmA5XHKs87JfMNAGQ==
X-Received: by 2002:a17:902:8488:b029:129:97e8:16e7 with SMTP id c8-20020a1709028488b029012997e816e7mr19595207plo.39.1633283605704;
        Sun, 03 Oct 2021 10:53:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e80a:: with SMTP id u10ls1665051plg.5.gmail; Sun, 03
 Oct 2021 10:53:25 -0700 (PDT)
X-Received: by 2002:a17:902:8f97:b0:13e:469b:8a34 with SMTP id z23-20020a1709028f9700b0013e469b8a34mr19445662plo.10.1633283605179;
        Sun, 03 Oct 2021 10:53:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633283605; cv=none;
        d=google.com; s=arc-20160816;
        b=ymqVwVrWMFy1Jf445kbSY8M8Q9F6uMuiePFJ6/KifvLCt+cOM6lbHCqLbGtEARGa8M
         UmwPfnIjPMIaKOAlfYlPqb8CT0HoyVooPklvtyGzRVCXUjcTlcNQDqiLOYTqSCH5Yng3
         jvf0FnCS4IUgcBwvAf9Av9A8XVVn2sdrOCWaKs4DkJYiPBkxkYsusE4zGsA+7b3IQImW
         eeB0+LHeEMvTCtrN//jbNlz+ntu5lR/ezvukUsfINv+Za6AH6VQ4uU6h4F8pnZiQeFcs
         6PRA/GvzImnGpri2632KX77HFCeC1j0hubUWb8N3ve7omuJMbOuvrKYciiT1zU6TvLya
         xFUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oeR+JF91jA1RQ/aOGCMv9JGlVQuVQcLbc+E39kT+rCw=;
        b=A5xeJEjPaNKvgy7AjctSyrqNURF94J9nK162uqCIYzIseVF2UZLHGJ8Bt9yqpp8joc
         vqZOlHQSA79Bci4kxj5v6H/OJWtZQ/BdplQWJjOYTEdGlpZ83FHV+Qt3eRIPwk/yzWKr
         ZHjDzUo8dX8f/DVs0FdQ7tksnjm1cDKorzCGKY7fo3N6AvZFt7IPgY72EBEOcN19ulsz
         1uJNbnhfBFWEPSN2kZperSgNXUVy/6pwvNW2730k5q/+X13KrUgiiDub0ZC/8yqJcKjW
         kDF+78GOysX7PRjKDOCYQC5Y6wRoexNLRqckpcE3m68+xhVzYDNzsFCE4eJkqMn92Dow
         7hNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Oz0X13K4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id y2si824724pjp.2.2021.10.03.10.53.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 10:53:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id h20so15925745ilj.13
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 10:53:25 -0700 (PDT)
X-Received: by 2002:a05:6e02:bf1:: with SMTP id d17mr2423631ilu.81.1633283604964;
 Sun, 03 Oct 2021 10:53:24 -0700 (PDT)
MIME-Version: 1.0
References: <20210913112609.2651084-1-elver@google.com>
In-Reply-To: <20210913112609.2651084-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 19:53:14 +0200
Message-ID: <CA+fCnZdvSmTguF_uKQTHgQK=QZhx7RHF-j_YaRGSPHvvqEU2cw@mail.gmail.com>
Subject: Re: [PATCH v2 0/6] stackdepot, kasan, workqueue: Avoid expanding
 stackdepot slabs when holding raw_spin_lock
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <skhan@linuxfoundation.org>, 
	Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Oz0X13K4;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Sep 13, 2021 at 1:26 PM Marco Elver <elver@google.com> wrote:
>
> Shuah Khan reported [1]:
>
>  | When CONFIG_PROVE_RAW_LOCK_NESTING=y and CONFIG_KASAN are enabled,
>  | kasan_record_aux_stack() runs into "BUG: Invalid wait context" when
>  | it tries to allocate memory attempting to acquire spinlock in page
>  | allocation code while holding workqueue pool raw_spinlock.
>  |
>  | There are several instances of this problem when block layer tries
>  | to __queue_work(). Call trace from one of these instances is below:
>  |
>  |     kblockd_mod_delayed_work_on()
>  |       mod_delayed_work_on()
>  |         __queue_delayed_work()
>  |           __queue_work() (rcu_read_lock, raw_spin_lock pool->lock held)
>  |             insert_work()
>  |               kasan_record_aux_stack()
>  |                 kasan_save_stack()
>  |                   stack_depot_save()
>  |                     alloc_pages()
>  |                       __alloc_pages()
>  |                         get_page_from_freelist()
>  |                           rm_queue()
>  |                             rm_queue_pcplist()
>  |                               local_lock_irqsave(&pagesets.lock, flags);
>  |                               [ BUG: Invalid wait context triggered ]
>
> PROVE_RAW_LOCK_NESTING is pointing out that (on RT kernels) the locking
> rules are being violated. More generally, memory is being allocated from
> a non-preemptive context (raw_spin_lock'd c-s) where it is not allowed.
>
> To properly fix this, we must prevent stackdepot from replenishing its
> "stack slab" pool if memory allocations cannot be done in the current
> context: it's a bug to use either GFP_ATOMIC nor GFP_NOWAIT in certain
> non-preemptive contexts, including raw_spin_locks (see gfp.h and
> ab00db216c9c7).
>
> The only downside is that saving a stack trace may fail if: stackdepot
> runs out of space AND the same stack trace has not been recorded before.
> I expect this to be unlikely, and a simple experiment (boot the kernel)
> didn't result in any failure to record stack trace from insert_work().
>
> The series includes a few minor fixes to stackdepot that I noticed in
> preparing the series. It then introduces __stack_depot_save(), which
> exposes the option to force stackdepot to not allocate any memory.
> Finally, KASAN is changed to use the new stackdepot interface and
> provide kasan_record_aux_stack_noalloc(), which is then used by
> workqueue code.
>
> [1] https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org
>
> v2:
> * Refer to __stack_depot_save() in comment of stack_depot_save().
>
> Marco Elver (6):
>   lib/stackdepot: include gfp.h
>   lib/stackdepot: remove unused function argument
>   lib/stackdepot: introduce __stack_depot_save()
>   kasan: common: provide can_alloc in kasan_save_stack()
>   kasan: generic: introduce kasan_record_aux_stack_noalloc()
>   workqueue, kasan: avoid alloc_pages() when recording stack
>
>  include/linux/kasan.h      |  2 ++
>  include/linux/stackdepot.h |  6 +++++
>  kernel/workqueue.c         |  2 +-
>  lib/stackdepot.c           | 52 ++++++++++++++++++++++++++++++--------
>  mm/kasan/common.c          |  6 ++---
>  mm/kasan/generic.c         | 14 ++++++++--
>  mm/kasan/kasan.h           |  2 +-
>  7 files changed, 66 insertions(+), 18 deletions(-)
>
> --
> 2.33.0.309.g3052b89438-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

for the series.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdvSmTguF_uKQTHgQK%3DQZhx7RHF-j_YaRGSPHvvqEU2cw%40mail.gmail.com.
