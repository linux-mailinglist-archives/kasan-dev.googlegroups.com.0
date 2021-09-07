Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKXH3WEQMGQEHUCPERI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A4AF6402A7F
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Sep 2021 16:14:03 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id x25-20020a9d6d99000000b0051bf9bfc12fsf6293891otp.8
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Sep 2021 07:14:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631024042; cv=pass;
        d=google.com; s=arc-20160816;
        b=s0ONSCm1IpkhGz/Xfq5cXYXa4BcATS1ie8a1XXENdx4mG1Y0IXVKlTQG0AcGtUMMav
         Hunw8FZAD1cNS+nG3IXhpHKokF+fgAh34xhB0Hq8FfsGRSFefnPD8yM3VC43k4Pk2ckY
         DtCbThD+k1+/re7cDERjnze6eVEJjqZN5FLhZvZpVZ3vM8WaJ2vBCF90iUmghI5PuO4b
         Eak/CIRlsR+rzcGjQsgXuuK63MX2AM0vqDHUqTKh+z8bBnkGbOleagLncpM8T24NC5HP
         0OiwHaupaoGXNY4x1CBwj5HJUdcesaJOzv0JnRrzrVVhEFuDyikZcVqyQf3+6smVYMLL
         wBeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=UorF8NQedd0CQhG2Iyg3ZwEIObuhE3tDdvLhWiXTcbo=;
        b=mlgoDGz15u3GCYAvhqqHat9BipdFVg5LAwEM4s+3Xdd8/XZF9kWXxb4lJkYSRGetp2
         6ltruHSWR3htMOsvffIt0mOA8R//ztGhxLhJcJ7YQnajI4PhcEoRj83VRIg//jkBFemw
         ki65bEqdxtiSS1dSrTHFehr1Z7SkC5wTlfY5ecLfOeEyurkmOdQMjgMNJCqf9zMVknvf
         RQO2i4QnXxdNYk0de7tz5ScJRVrCkaegwb4FAqMxBs7YLlukHtQaT2TmdrbCEpuGX1Su
         lvPjV8ToLrQa7reKTuFWao5L0EqwZyxhZV59PC9kp18TterXu9NUtlwCPWBjd2m2vsE5
         OTeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oOD572sL;
       spf=pass (google.com: domain of 3qxm3yqukcx4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3qXM3YQUKCX4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UorF8NQedd0CQhG2Iyg3ZwEIObuhE3tDdvLhWiXTcbo=;
        b=IgzgGSRzJ5OejeGvHa8aW3kx6HtEkwUcypvA9hdzO8lhQaRSqUE46eLm0I9qNeW498
         s/N4sig8wPzwt3U1sPJkzqqeh2jG0jwWlLndgt5Cw+3gcAVg3QRud9JHQy9+M8RGt8NJ
         AjjXwAZ3OiIDthAKGCsQHI3RH9W8YlX3IpBdyVtE8HY/Lfg4SKjwWz+ZdZlH+IzJl/+o
         synwxIMx+okh8i78LYKqBkLh80MXI6Lu20sTCmBUAVgyFV4nVc+QUXP3nFCFom8by517
         9Hx9EZFYUnBjHUjFEbgy+Z342jsimpb+Ejk6/DQuGz+MgAObT2ib6XeG0FU/kAGl2Lce
         sSjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UorF8NQedd0CQhG2Iyg3ZwEIObuhE3tDdvLhWiXTcbo=;
        b=lxcVk5kx9PjQqpXAKj15X4Fcq6DppXYwChhyinHRE5cYlQe2P0VtbNv48fSgFo/xFK
         eGOCpBz5FBKXXPlJjlAnyfeiOpKAfZA62U7SDPtQNxhj8rqrXs3uc2jUeZ9kbFck4cCi
         emF3lGCFaN3NFsjwZajS+p80SoNXs0BU5yuAWJeZ0AH9EpHateLbBj27CrPYn/6ZU35a
         DE3ezro8QsY7g4O6pXYbIOhYKgEgs8I9UdrgBbFvCkyUZifSF1GAwuiBi1JoQSveZtfT
         jb4xIroQ7kYBcVsnqTfnTsVElnMyHYNQ/mwSeiamP50xUyNbMneIW+49NtRkmhwcRKrd
         pqKQ==
X-Gm-Message-State: AOAM531sLuhIk6Q7uUW7xsE3gOCkfkcQ6/3d5IRL8qWi4FRXxrLBAtCG
	S9eed24q9l9BpwobbODnoRU=
X-Google-Smtp-Source: ABdhPJxfpXmxNZpOgKXnyRAcF2gQVjqzUQa6J6CbSMGjjk3Caoj/u0HvKRYJB28Tcbk6Os/I9iEsnQ==
X-Received: by 2002:a05:6830:110a:: with SMTP id w10mr15221942otq.291.1631024042182;
        Tue, 07 Sep 2021 07:14:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3c86:: with SMTP id j128ls2110875oia.7.gmail; Tue, 07
 Sep 2021 07:14:01 -0700 (PDT)
X-Received: by 2002:aca:1802:: with SMTP id h2mr3167522oih.146.1631024041694;
        Tue, 07 Sep 2021 07:14:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631024041; cv=none;
        d=google.com; s=arc-20160816;
        b=JGH22ab3AMMruu0YQxeRYcCpFjZpLUwn5GruMoQv7MvDh7c/rKxHp02HwGHpj/lBOj
         X53BxN6eAK+JslXx6xBLCmMUiG7VctRskhSnvQaYnxa/mEZdI5N9x21NYcmN2LqdeTQq
         UWGmWyp+b4Eo56ev0lY+M/J5j7IjAEAwOESAngdAjN6LxZxBjg5iz2vkK2EDS9zAN2TM
         2TgpaZ40UJKOpzaVcVycrN8OIaTqT16yGxluvbW/8tD8vtvleBEaqemgRdvDM8ptWYn8
         v0G0eO/zAn/WHQYL57pbf+6ufnNGdj+2qQY66te8GEOFK+PGmtU0Kw6QqN+qQZEQT/QO
         OaWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=G9h0FcdPN7QTl0SnF2a3SazYP80XeLyqs+enOhlxDM0=;
        b=WIDoMNzs1se0q9CQWjzR+61mBZ0wzUrIJyinjf1+hadfFeWQ+E8dOozZ/AHNPasl0o
         RemAQAldndV1YrZ1qlqdJ7Ji54XiBrxC2qYQm781YQhE7G8isNiO6sXbVflKelhyb4H6
         pj/MHmtAMXPr387ue97bPB979vEeDqTUr7QSMbxN63oxfpFZYGNXfOAAMD7xENdyVoIo
         2fd1sWnXWAI12OZQJPjdt12t1mOsl6mTuOOxCFJbZqnqsDt7421IFlKDteBbXLTN+Rlw
         8/q0QVEYVXtHW0WovZJLRMhf+57EehiY1VdEiUdVJUUdKGe1xRojmTL6AVLOT7LI0UBj
         xm7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=oOD572sL;
       spf=pass (google.com: domain of 3qxm3yqukcx4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3qXM3YQUKCX4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id m6si710932otk.4.2021.09.07.07.14.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Sep 2021 07:14:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qxm3yqukcx4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id bp12-20020a05621407ec00b003773f981838so15105724qvb.22
        for <kasan-dev@googlegroups.com>; Tue, 07 Sep 2021 07:14:01 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6800:c1ea:4271:5898])
 (user=elver job=sendgmr) by 2002:ad4:4e86:: with SMTP id dy6mr17251813qvb.30.1631024041249;
 Tue, 07 Sep 2021 07:14:01 -0700 (PDT)
Date: Tue,  7 Sep 2021 16:13:01 +0200
Message-Id: <20210907141307.1437816-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.153.gba50c8fa24-goog
Subject: [PATCH 0/6] stackdepot, kasan, workqueue: Avoid expanding stackdepot
 slabs when holding raw_spin_lock
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Shuah Khan <skhan@linuxfoundation.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vijayanand Jitta <vjitta@codeaurora.org>, Vinayak Menon <vinmenon@codeaurora.org>, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=oOD572sL;       spf=pass
 (google.com: domain of 3qxm3yqukcx4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3qXM3YQUKCX4gnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

[1] https://lkml.kernel.org/r/20210902200134.25603-1-skhan@linuxfoundation.org

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
 lib/stackdepot.c           | 51 ++++++++++++++++++++++++++++++--------
 mm/kasan/common.c          |  6 ++---
 mm/kasan/generic.c         | 14 +++++++++--
 mm/kasan/kasan.h           |  2 +-
 7 files changed, 65 insertions(+), 18 deletions(-)

-- 
2.33.0.153.gba50c8fa24-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210907141307.1437816-1-elver%40google.com.
