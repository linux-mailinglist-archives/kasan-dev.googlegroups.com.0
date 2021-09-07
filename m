Return-Path: <kasan-dev+bncBC7OBJGL2MHBB77I3WEQMGQEH4PDWRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id AF7FE402A96
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 16:17:36 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id u5-20020a63d3450000b029023a5f6e6f9bsf7083131pgi.21
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 07:17:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631024255; cv=pass;
        d=google.com; s=arc-20160816;
        b=jH3/Gyl1sB/e2Ho1Ob4sjIzSsOF68XK325gbxBl09oLtHxEiU146s97ihQrq96Gotj
         JtigFOdFfPOah1agEtSGTErsH0pUugrQqrv3EiUGw50DW01e5IV8a7yc3XBvK5dDeW/z
         VLKERIMS78RYgnE4J5TWSg5LeTewmSGpkdNwYhaxSGDStR6oUxJ4BchWjHOIJ8gIKVRm
         0jOjiMyLNkNXzTI91CDh+QqQg/chhOxlOtP5hAVF5XFZgIhkVcgPEHgdzZErbAkqwdJp
         yPTNf3GPDrNroCzuXLg75VYh7CA0Ym+EMhJY0IsdrLsyX6TR6F9ZgSLvdiFsKyu0Xy4i
         hewg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=P/BNwtzgVjTCw4Wmhk9hVc0W05jAX8R732E27O+ad9o=;
        b=rGOSEGAVAsbWPoGGKjyUwIY0P+VNcqVHOw1LJ5MybY60O+m9+GxK+y++BW2eoPQqik
         CbclZ7PxVP1xp5gPrUXhAxfMoBZ4NDhOKTarSClPO2A8dh1fpJhGBwO+0tJ1q+B7/uF2
         XEJfNk04UJhEWmR2RiNL0+FV1TpNmJ9NK4ffsYKPe4cW6fjfBexdtaSCiSJWMHFH+pbS
         tY3O25lKADg2cuCybRacxZzIUi4TnZekmm703m+BqleQNV9TbBiChskZOceVtMmZ7NUl
         J87v0Mnk8ge+lVzlIII7cDQ7u6xfqFEtVBDzJCYK0PRQGH61vcYoKZbEe0KJC3S6RwXa
         5QyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EtwIW0ig;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P/BNwtzgVjTCw4Wmhk9hVc0W05jAX8R732E27O+ad9o=;
        b=i/JRm/sYzYousz7k8HeDfwSfDIMRitURHsjlzh/uBIoyw6rYBTS/se11F8K6/vvees
         SGDosY+AYrilfrenwPcVEiFrpDh8UXtcb64FSoeSZl4siedubet9WvK74NxAqYeQNV6m
         mAmkMYG3UthGg4DXfUdRnvEPcqpBF0pZY6P9L1ZDDgvNCe43vAg8X2uk+Ar6xPqiWTKi
         dSrhZe1sMj5hJYMuaBWGfdDwlNfvtIe+FOpHEQxyz/rg17Sl6SVf93o+Tu26r0E3cZ1O
         CA/g2ClqvHySGi3UyCwzpvPyj6pDDDrwqkPgGk+hhvRfjxU1AeTb85gBi1P0RpK03A1r
         /8Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P/BNwtzgVjTCw4Wmhk9hVc0W05jAX8R732E27O+ad9o=;
        b=nX0wu2BwzyZFrcnbtb9CXOuNC0tHymuhpKqPa67RfGCdQkWm9LaA+fOw12nVNdF75g
         pz/sXWXIVLumj7o1pyLYNlJn3UEfEsnLKembQ1hItbebGGby+DSonLnvhexCBGQ4TO+E
         0nQLZS4zX9HE+YTRZ4ZrYfrclPJPxeCIx0udi3/Rs7l+sLFI05c899JnhooJRpuy9XWn
         8gAyV1PVkAScsPd6tmyKz+9zT6eScQzTJpVgHliAVMPIKdZxs0ZNXJC3tk0hu0yd/ln7
         IyFGRTP+lAmvQweFVRgpuNIUzpecHKVCkcDNvuT5K1cyW6QI+0tjoi2fzrprGkiybG+9
         mrzg==
X-Gm-Message-State: AOAM531zRZNu6zPB4zaStRbOXTkegp2N61/Yy5XHWQFMWUVJ8lZuMHKn
	fUi9Ej5/oic8yZZrjvwjfug=
X-Google-Smtp-Source: ABdhPJxEtyHqaZ6YFlA6nlp9myEy9ijVE5e9+oCe2jA6FKjPrKAJHBYqfMlYFAoezGgfBJwSRamM4g==
X-Received: by 2002:a17:90a:718c:: with SMTP id i12mr4844172pjk.182.1631024255401;
        Tue, 07 Sep 2021 07:17:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4d2:: with SMTP id 201ls4737478pge.9.gmail; Tue, 07 Sep
 2021 07:17:34 -0700 (PDT)
X-Received: by 2002:a63:aa06:: with SMTP id e6mr4347391pgf.66.1631024254797;
        Tue, 07 Sep 2021 07:17:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631024254; cv=none;
        d=google.com; s=arc-20160816;
        b=J+N6zbNZIfOlBQwJUfY8nzp5XAFgEhHKlWujq+LZa6nqS88rvRLMNymHNBgktJGQw7
         3iJYQ4Dms8lRriv7N819LAACCHAo2SAD8r60wriAUAxEJG91mpcEX0rP27G+2XxO2lZA
         Mb3yfMIa2Z/7XQZiX8ZHCN8gfGY8YAt5WRBGgqOu4+9nYgJqMqCI6eq8b/hCh73ROmPw
         Gc9Rcv8278lhimcQ6+WEQQBSZxirJm6s6mAAX6VS5VyB3OH15YI9ZejwCIZpHxAqGD6h
         UBJ14sXu+5Fn8AsivRW8y8UtLhc2ejJIM1p/b3xqrSh3FNz940bvz/c8i2pzEs4Y8W9o
         YPVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=41eOpaggA77QHE2mPAqNRgEMJRJWSV+8azyguMYtpmM=;
        b=oR27rZLilxY4A3cThftFQNFiL+/Thrp0kUzdkEmLUwcQUk51639kr/sidqGY5fPeDE
         QJsHwmR0wfu7q7pIC/7LBIVHgU3gMawFKPqTUxPCq6f2abQJQ2HJtXZF6Aa0gMSQJoRI
         XlrojC+VXaUpTK1F+PS7ZQNDYbJe2lQH7S3macLKB3P8UN3tp8nMzQG3IiCLH6bh9MKF
         9svuRa/xeQx8WxmAAXGOacIBKKUr4T4tNwoOT9HbBV+/76uAfNN8jnrq8gRCBALG6oao
         xaC/yrLsKdYx44iJ4tqkc0AK/ZVAr15roLWXlPn+45OcSY7po3lfpYGWMO29wJcMRRZn
         8iQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EtwIW0ig;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id o2si228323pjj.1.2021.09.07.07.17.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 07:17:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id p2so13000381oif.1
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 07:17:34 -0700 (PDT)
X-Received: by 2002:aca:4589:: with SMTP id s131mr3105616oia.121.1631024253637;
 Tue, 07 Sep 2021 07:17:33 -0700 (PDT)
MIME-Version: 1.0
References: <20210907141307.1437816-1-elver@google.com>
In-Reply-To: <20210907141307.1437816-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 7 Sep 2021 16:17:21 +0200
Message-ID: <CANpmjNMenewC=wBGOcRv0m=G-i4xjR+_nm2noK5QEkyG_DpnJg@mail.gmail.com>
Subject: Re: [PATCH 0/6] stackdepot, kasan, workqueue: Avoid expanding
 stackdepot slabs when holding raw_spin_lock
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vijayanand Jitta <vjitta@codeaurora.org>, Vinayak Menon <vinmenon@codeaurora.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EtwIW0ig;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

[+Cc: Thomas, Sebastian]

Sorry, forgot to Cc you... :-/

On Tue, 7 Sept 2021 at 16:14, Marco Elver <elver@google.com> wrote:
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
> [1] https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org
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
>  lib/stackdepot.c           | 51 ++++++++++++++++++++++++++++++--------
>  mm/kasan/common.c          |  6 ++---
>  mm/kasan/generic.c         | 14 +++++++++--
>  mm/kasan/kasan.h           |  2 +-
>  7 files changed, 65 insertions(+), 18 deletions(-)
>
> --
> 2.33.0.153.gba50c8fa24-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMenewC%3DwBGOcRv0m%3DG-i4xjR%2B_nm2noK5QEkyG_DpnJg%40mail.gmail.com.
