Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY7K7SEQMGQENZKKMMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B9D2408A11
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 13:26:29 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 131-20020a251489000000b0059bdeb10a84sf12525323ybu.15
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 04:26:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631532388; cv=pass;
        d=google.com; s=arc-20160816;
        b=L7vOTEfezVtL2xvNNos3oQ1IYSPWctuEtNY6Ja6+BGIQJx00GmPHOo1am0RBXJFOVP
         xJ8cTLj9o/T73PeFp4h3+UpUuUHsTMOfH3C7+/sx7xjreSNQCvh8zWJtx5FIueZMf7CH
         KNjsU7GwdhDaFAkAtbKQxMNbmD1qceFpFkeYYZi0xwe8DibgRuzFPPGQrMmFPJdbVvJA
         1sXxPUeq9buae6GrLbRoVhwk5TXWmCUS0xWKPoQgA/+zj2hF1jYSUGjs5wt+CxHLI4Fx
         vQLtievLADmN8mryr204PXvqEF2wFyj5v1khBYivLEIAPjZZUJcM2b3tRWZij71WjUqa
         JuiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=HgyEWfncRUG6ko1kr/ZR8CQJw51Tn1Ajvnn7Smgvv+A=;
        b=IjcfKV/SMNfCNW4Lcos+qKD8CwzEnzvOnASTP31hgubuaEH3ss+SbKGA4rEYLTwf+w
         SbzFbVjDAi1S+9t4vVdHNNKnxqrVyblBtl7pq8jqAfPwasLr3aUKpbVsQMl7Fg1u0mIx
         uxi54s8t9+Qd37kyX3gvD6M9VtL5FN5Vl/a4OUGmEUw8pDpI3opI3dvVgz8Ft3eNiSYu
         7nJ/5G0MqVNMLVyJXQFNisp59hJS1668Ljgw5BF0D+HLEzw3h0JEncIOPW8bGMCD6zUa
         ri+oefW2StW9tv5sfGyG/auTiHFymy+Ex8TqRSUisPOUFZqmDYipPnoRfGoqteXV5K+h
         nupg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QWAgyJAQ;
       spf=pass (google.com: domain of 3yju_yqukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3YjU_YQUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=HgyEWfncRUG6ko1kr/ZR8CQJw51Tn1Ajvnn7Smgvv+A=;
        b=L6PcBC9UDYJHo5vwa1FGT+T/EMv7Wxyd/LJFhissnEh+nSMZ9il2ZcTaI347QOzcmH
         2Nxn9zJQOQ8EWzbP9hQoEmeDt95GVtNhCWtrE8DHM5LOOuuxbQ6rKZ55lS4FhZ0h6Xw0
         7SiKn+Znr7Nc9x6euoG9oDRYgdVXXBb2GdDAzNFc261fF2v527IeygMIZyrLteVFQWVL
         a8z5egIW119x7/gTzLQDw9B0UIonSRMkHYp01oqN2fxZz68Wqgk83xgLbOrwGmjYYzY8
         WyyOpCZhXWjFeT1rzWQeqZnAPRoSD8YxDSqbQ7JYG4EBV28MHP/vGg3ucEl8fMXc+KzY
         1xow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HgyEWfncRUG6ko1kr/ZR8CQJw51Tn1Ajvnn7Smgvv+A=;
        b=moZdeJTCzYlVclUbmTwya8coiwtJZ0VThriX9VnnEhsOxLkVsCgEKWqSLP/qfsxGbO
         6XyMXeaRPfsoHWWwffyA8XDVNlzplCdjrQqm2YdSjvLnqhjeGVsRqTmkF3TOHQWq6fG4
         DsvqXCHe0xjivzzdMB15Awml3k266XdjBlwKP5GbSN39/mGI/RF45MHZ0yJhCgGFRkqz
         Md6ll95+IVRoag52doO1oAsOkWN4J4AH9Tug8zt2BuIb6LHH37+SnO+De+PzAGNQ7R0J
         RpcUyqpVTayjx8fI2BOxb4d8/o9Yxs3wgiu9IDZ7ZAk2/87IwwahG7g4FOhHCCTunPEB
         sKsQ==
X-Gm-Message-State: AOAM533K4/CSLrtkfcLs1BGbya4Y/fI8E/ANOX7IjsCYpw47VhV08TbE
	6jLDNkEYE2TVmRYwYWNt+Y8=
X-Google-Smtp-Source: ABdhPJzh+rDsqW5XwW/JaW6u29BanaI9NWKHEv+4rrEXCeswLnFkBfKe4TMeuGFNZ33p1B04ZfHBHQ==
X-Received: by 2002:a25:3109:: with SMTP id x9mr14601090ybx.184.1631532387796;
        Mon, 13 Sep 2021 04:26:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9904:: with SMTP id z4ls2959848ybn.5.gmail; Mon, 13 Sep
 2021 04:26:27 -0700 (PDT)
X-Received: by 2002:a05:6902:1148:: with SMTP id p8mr2814126ybu.513.1631532387375;
        Mon, 13 Sep 2021 04:26:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631532387; cv=none;
        d=google.com; s=arc-20160816;
        b=WEEaqvzJv1t8KYO5U4CvEHSMKvpln0hdnHxU5UGEOsQ8dIvl2CzkBLnwYyxz/y1yNO
         +KjlTkP+gOQsO0HfMG0LhxHKeEJ7ILVdZYZb5UQBQgy9lOsLYHEkV/xkV90oM9Gm/KSj
         2wpCksJDigpYABeGtUjIMisVOxJZuARb+mGbFgrzDEneGoadPka5WohPbGiybyikkl9p
         kMkw8QSZwLyM/evgPnuMumEJTi1XfNYRdRh7ZeND2Zruq6xwBWmTfxa0KIOCFj015PxM
         dgiPgP06He1YygDYRPkHTlgJ0nVmCukA63U+CAa3FJu7NgdVFQGSbMtKo/GB5O0sdsbz
         eZBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=8KTa3rnV38d0tCc/yNW+Mi1KFOkW66QAmkHuLxBgoOM=;
        b=JmatDcbPJ1pwApGjj4tOv5aGFhlApR0mK11zruEXASEMTmNJAB0qFHFb6685//nlUo
         l0/Tig7t/WqnDbma9qhX5HA18iR5uepmgqCSGSKVfVxHvpsP50nArRj9uC4zTKRuIbPP
         5ArGPiwmRdArXrNhlBou5rD22AKY6oGYYB2ysbJBEUyGptU3j7/xrhkWBbbyR8T4bEaK
         uUCwj2nTx3q4Cj1IQkxqop5ndE4SjXXvD9VyaDe90yX2qT/mDuth5fenlvitDo+vsx1n
         pnMS4wFPNrCZjn1wEDnQz5eG7Ba3xyWjQUOGVHnLLsgE2XXm/wlgq8gnkQhxcB6lxK+Y
         L8Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QWAgyJAQ;
       spf=pass (google.com: domain of 3yju_yqukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3YjU_YQUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id w6si455203ybt.0.2021.09.13.04.26.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Sep 2021 04:26:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yju_yqukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id c20-20020a05622a059400b002a0bb6f8d84so55073903qtb.15
        for <kasan-dev@googlegroups.com>; Mon, 13 Sep 2021 04:26:27 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1f19:d46:38c8:7e48])
 (user=elver job=sendgmr) by 2002:a0c:e345:: with SMTP id a5mr10045238qvm.27.1631532386935;
 Mon, 13 Sep 2021 04:26:26 -0700 (PDT)
Date: Mon, 13 Sep 2021 13:26:03 +0200
Message-Id: <20210913112609.2651084-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.309.g3052b89438-goog
Subject: [PATCH v2 0/6] stackdepot, kasan, workqueue: Avoid expanding
 stackdepot slabs when holding raw_spin_lock
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Vinayak Menon <vinmenon@codeaurora.org>, "Gustavo A. R. Silva" <gustavoars@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QWAgyJAQ;       spf=pass
 (google.com: domain of 3yju_yqukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3YjU_YQUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Shuah Khan reported [1]:

 | When CONFIG_PROVE_RAW_LOCK_NESTING=y and CONFIG_KASAN are enabled,
 | kasan_record_aux_stack() runs into "BUG: Invalid wait context" when
 | it tries to allocate memory attempting to acquire spinlock in page
 | allocation code while holding workqueue pool raw_spinlock.
 |
 | There are several instances of this problem when block layer tries
 | to __queue_work(). Call trace from one of these instances is below:
 |
 |     kblockd_mod_delayed_work_on()
 |       mod_delayed_work_on()
 |         __queue_delayed_work()
 |           __queue_work() (rcu_read_lock, raw_spin_lock pool->lock held)
 |             insert_work()
 |               kasan_record_aux_stack()
 |                 kasan_save_stack()
 |                   stack_depot_save()
 |                     alloc_pages()
 |                       __alloc_pages()
 |                         get_page_from_freelist()
 |                           rm_queue()
 |                             rm_queue_pcplist()
 |                               local_lock_irqsave(&pagesets.lock, flags);
 |                               [ BUG: Invalid wait context triggered ]

PROVE_RAW_LOCK_NESTING is pointing out that (on RT kernels) the locking
rules are being violated. More generally, memory is being allocated from
a non-preemptive context (raw_spin_lock'd c-s) where it is not allowed.

To properly fix this, we must prevent stackdepot from replenishing its
"stack slab" pool if memory allocations cannot be done in the current
context: it's a bug to use either GFP_ATOMIC nor GFP_NOWAIT in certain
non-preemptive contexts, including raw_spin_locks (see gfp.h and
ab00db216c9c7).

The only downside is that saving a stack trace may fail if: stackdepot
runs out of space AND the same stack trace has not been recorded before.
I expect this to be unlikely, and a simple experiment (boot the kernel)
didn't result in any failure to record stack trace from insert_work().

The series includes a few minor fixes to stackdepot that I noticed in
preparing the series. It then introduces __stack_depot_save(), which
exposes the option to force stackdepot to not allocate any memory.
Finally, KASAN is changed to use the new stackdepot interface and
provide kasan_record_aux_stack_noalloc(), which is then used by
workqueue code.

[1] https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org

v2:
* Refer to __stack_depot_save() in comment of stack_depot_save().

Marco Elver (6):
  lib/stackdepot: include gfp.h
  lib/stackdepot: remove unused function argument
  lib/stackdepot: introduce __stack_depot_save()
  kasan: common: provide can_alloc in kasan_save_stack()
  kasan: generic: introduce kasan_record_aux_stack_noalloc()
  workqueue, kasan: avoid alloc_pages() when recording stack

 include/linux/kasan.h      |  2 ++
 include/linux/stackdepot.h |  6 +++++
 kernel/workqueue.c         |  2 +-
 lib/stackdepot.c           | 52 ++++++++++++++++++++++++++++++--------
 mm/kasan/common.c          |  6 ++---
 mm/kasan/generic.c         | 14 ++++++++--
 mm/kasan/kasan.h           |  2 +-
 7 files changed, 66 insertions(+), 18 deletions(-)

-- 
2.33.0.309.g3052b89438-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913112609.2651084-1-elver%40google.com.
