Return-Path: <kasan-dev+bncBC7OBJGL2MHBB45TQ6KQMGQE7CJBFWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 87E34544A1C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:01 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id n8-20020a635908000000b00401a7b6235bsf299515pgb.5
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774260; cv=pass;
        d=google.com; s=arc-20160816;
        b=zJ7f2I0QFAryO1Fh1kOLtrSxf13jAopvB1zwuWC93fdrEmoPgR424ejx0WvH1ScjDr
         vlSm/MRp23BncKJLjvTEnAK8n5rFprBVuJ+epgilVYBwuOL5tQgr5x++bkW8v+jB4z9A
         H3QzbFwBoVQahK50kD84JdcIUOc9GYiHRRI38m1uNCJ4MA8t+G0hgc6KgLz2DCDx4MXr
         CypF5QebGyl+aow/a5NFAcN2XRxXxOrIriRIQ4dKD9/r+Pq1tHkRGqdGkAqSmPAW2ctC
         awbYEtrZVDU8o19E7EA384NmJeLEt/D4Vqg3FlYy5FSz0fQnKMoGLN7jPjjsNRC6l+On
         Mdtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=RD1XNPZOtTBy0Jcb734Gf5v1OAejKlAUb/7fav2d7cQ=;
        b=IRlcLPnWMDDh5WxQD7RY2fMlZ0ZJqjlVvXkgVVfs5lfqp3alIjWjZ5ehct4s1fRmsF
         rXQthU0UyomBYmP+yhRmGKrANw2vceLsbvC8FjSvz2VdPVTXirinAqAgXkR2TNoY5V75
         0mFveBBvqPy/nls8vdtC77vdagzthNwb1fuzPe3E8XZ7cjBSjVxgZIN9zUN5TpE0ljqw
         pL7+Phmb5pYvKAVHOUu+ya0PclI+cZGE1gs3GYhvY86MVRuDuK7Q7l9ogEwC5Rb/kPv3
         KPDPy28ycHOkc3zeBqMTMI1UGdq33KPwgC8DwjJrvB9LnDljfyB0VwzcRBcGlFX42fez
         8pxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Fy1H55Pf;
       spf=pass (google.com: domain of 38dmhygukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38dmhYgUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=RD1XNPZOtTBy0Jcb734Gf5v1OAejKlAUb/7fav2d7cQ=;
        b=aCudipj0mdAij8DXhC47/1VNYLB1ncd+7A1B3bYLrVqKyGhjse0zk3I6/nPytXIA0g
         MFzbO2vYCTr7lBrn3tTRzYi0kqqROrIY81HHxWxWVdx0mukqFQuWl7dm4ebUW4R4ivBn
         Wg0lg6CG1eIjC2zQ2b9UCA6lwPGVkBEgx2mhw3S3C2d5sZ9HwNHxDHT4JUrsfonfMiXx
         Gc/mQ6iJjBG5td3J1ACu0L1OGfgvf1FiNF2eQekW5QnyUQy4SrMh5iJZA8b4FdZslTJR
         f3VwROhVtghdJlzJoPWwjPzlVMkxNHB9Rvs+KdWnCZqar//fnVk8QjbLJPB6/uUletxP
         QYDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RD1XNPZOtTBy0Jcb734Gf5v1OAejKlAUb/7fav2d7cQ=;
        b=oXdZ3KN3HF7Rc9OaTVD2JGwEly8k9Eg+F/W3dxXO5Lb5/s/PKNNk0+KdcKupRawKXo
         D9hKGnawFgspiG2fYwZanVtSE9pitdFt7o1rD/+y58dRKdWFliV/L+wjTceD1PJ970Nb
         HiivuqG6a+pcPj2Ow7cdcKJgNsOiFyhUcZZs/5AbRkVTXNurg6uLnJo1UeQ1QVmTFPmT
         tc9b2ghrMcmkdOETK3O0kepTJu4ZFbKvIMsM6nNepagzkcJqaoOkLInvv/M64np87CpJ
         v8OGCOv3XX7YCwAlOVngnB2dtw5W1tAUDorTaiRI7F9bQyUZlDHTJEFmn2pQZZ198LE4
         eQOQ==
X-Gm-Message-State: AOAM531XfVrmT7ekxyA/OsOUBLKyPHiqmSUJtDJt4VbZ5XB17accaZdf
	ookVNF6Zu/16mBlzWAUuYDo=
X-Google-Smtp-Source: ABdhPJzS8Od9rUdYBW9Sx+dqHfSIoitbZBX5yuQsXciVM5FuQ5Z8raeNcnl4eX+iK5TTH4P/tHFTgA==
X-Received: by 2002:a63:6c44:0:b0:3fa:ec6b:33e7 with SMTP id h65-20020a636c44000000b003faec6b33e7mr33737448pgc.435.1654774259909;
        Thu, 09 Jun 2022 04:30:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f54b:b0:163:f358:d4b4 with SMTP id
 h11-20020a170902f54b00b00163f358d4b4ls13135693plf.7.gmail; Thu, 09 Jun 2022
 04:30:59 -0700 (PDT)
X-Received: by 2002:a17:903:110e:b0:167:8847:5d9d with SMTP id n14-20020a170903110e00b0016788475d9dmr17092144plh.3.1654774258356;
        Thu, 09 Jun 2022 04:30:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774258; cv=none;
        d=google.com; s=arc-20160816;
        b=ap9vQt/TjuSjrrVR0uyMkVMFNSy3oJ3uv8/3kSysgNpzpTrZ76dOXqnvYxgHQdLF+9
         uAcpT0ARbC+Qc/lBoYxW1sRGCYbX8897D5PI08Dcrx5fzKOsLgDylT2etwK/JfKl3NvP
         MGHoE9QKwP5jwgxxOWsvUyH+hrQj5IYoaQzwZ19OBKJ8c0VNb/Y0mB2DBBsYDFCZ7Dle
         fj9dUtdlf/L+zHaUNLjw5jE3/3w3mrXYJ24MQwwYXpyOyZ2MFI/FnwK/khdkqiEAbGki
         l7wEuY88F9v/sjJfJJSVn8WGaqH9Vn+9S6c1w3Y4nyyWikcdMgppCSrVeDvHZq+kvXlz
         RIag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=jgek/xbFyP6k/AwYv1XTJdXWbQnAo26L2HOt5DoBXsU=;
        b=Dm+rKKS66KzmW8PJO3lDStMdrozMb7MEyp55NAnoIZ4W5EhJ8zUWeaJp6VVGEHNRPR
         MnolmxMdUMkNOJnoYocw1gEgQ/Tj6ws64Gmh5bWn42Vt96nuzpGQAKdN4MUo+vG72oDs
         d80LiADKrhP1/aXhmArZC22Gv5k1ln4GrRKBoYMEVTHExBORkqv0vFpfvOoj3d9rB34R
         Q2pBz55xWPmpkIYX5N+qCrJZojHUyuQACB/cU0nPk32zgHo5AGG1rE8vqIpl6I9bR/2u
         or/MhSBJg2Dqdd1icy5i5KI4wo9IfLIg6vAmArrTBOGkKFpso1MYBmkiHUiMQq4hqUCh
         CA6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Fy1H55Pf;
       spf=pass (google.com: domain of 38dmhygukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38dmhYgUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id jz19-20020a17090b14d300b001df76e9c039si91164pjb.3.2022.06.09.04.30.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:30:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38dmhygukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-30cb80ee75cso199799547b3.15
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:30:58 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:a05:6902:102c:b0:663:32b8:4b24 with SMTP id
 x12-20020a056902102c00b0066332b84b24mr30477830ybt.1.1654774257606; Thu, 09
 Jun 2022 04:30:57 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:38 +0200
Message-Id: <20220609113046.780504-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 0/8] perf/hw_breakpoint: Optimize for thousands of tasks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Fy1H55Pf;       spf=pass
 (google.com: domain of 38dmhygukcugov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38dmhYgUKCUgov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

The hw_breakpoint subsystem's code has seen little change in over 10
years. In that time, systems with >100s of CPUs have become common,
along with improvements to the perf subsystem: using breakpoints on
thousands of concurrent tasks should be a supported usecase.

The breakpoint constraints accounting algorithm is the major bottleneck
in doing so:

  1. task_bp_pinned() has been O(#tasks), and called twice for each CPU.

  2. Everything is serialized on a global mutex, 'nr_bp_mutex'.

This series first optimizes task_bp_pinned() to only take O(1) on
average, and then reworks synchronization to allow concurrency when
checking and updating breakpoint constraints for tasks. Along the way,
smaller micro-optimizations and cleanups are done as they seemed obvious
when staring at the code (but likely insignificant).

The result is (on a system with 256 CPUs) that we go from:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
	 	[ ^ more aggressive benchmark parameters took too long ]
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 236.418 [sec]
 |
 |   123134.794271 usecs/op
 |  7880626.833333 usecs/op/cpu

... to -- with all optimizations:

 | $> perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.071 [sec]
 |
 |       37.134896 usecs/op
 |     2376.633333 usecs/op/cpu

On the used test system, that's an effective speedup of ~3315x per op.

Which is close to the theoretical ideal performance through
optimizations in hw_breakpoint.c -- for reference, constraints
accounting disabled:

 | perf bench -r 30 breakpoint thread -b 4 -p 64 -t 64
 | # Running 'breakpoint/thread' benchmark:
 | # Created/joined 30 threads with 4 breakpoints and 64 parallelism
 |      Total time: 0.067 [sec]
 |
 |       35.286458 usecs/op
 |     2258.333333 usecs/op/cpu

At this point, the current implementation is only ~5% slower than the
theoretical ideal. However, given constraints accounting cannot
realistically be disabled, this is likely as far as we can push it.

Marco Elver (8):
  perf/hw_breakpoint: Optimize list of per-task breakpoints
  perf/hw_breakpoint: Mark data __ro_after_init
  perf/hw_breakpoint: Optimize constant number of breakpoint slots
  perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
  perf/hw_breakpoint: Remove useless code related to flexible
    breakpoints
  perf/hw_breakpoint: Reduce contention with large number of tasks
  perf/hw_breakpoint: Optimize task_bp_pinned() if CPU-independent
  perf/hw_breakpoint: Clean up headers

 arch/sh/include/asm/hw_breakpoint.h  |   5 +-
 arch/x86/include/asm/hw_breakpoint.h |   5 +-
 include/linux/hw_breakpoint.h        |   1 -
 include/linux/perf_event.h           |   3 +-
 kernel/events/hw_breakpoint.c        | 374 +++++++++++++++++++--------
 5 files changed, 276 insertions(+), 112 deletions(-)

-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-1-elver%40google.com.
