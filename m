Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQNYUKGQMGQE6XKYXVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 088FE46613F
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Dec 2021 11:13:22 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id s12-20020a50ab0c000000b003efdf5a226fsf16893327edc.10
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 02:13:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638440001; cv=pass;
        d=google.com; s=arc-20160816;
        b=dr7jdpcpvWPo6lZgfuVqRibkoLHjOWQAadr7C5cErUaXXWsz4R5rN9FwIvThKGopl8
         WLB5tdSW6leZKs+ZcStyUxIHna4pQUUzEer8mjYiUx4rtgc4PHA9v5iczAph7+5xygLe
         PMeE61fyA95xKLXEdn59FUJiwPiX7EFe9vtBEUeh5iTC1m3O02XKkAUlCPY4UIXuEnNv
         eyK6Q79jAlgCy9Gis9rzV46q5En09/rgKPkTmYpc6vAuWsRWIPVL4Ag5XrHDj5yIabgO
         lABqkb4dS1ipD1kfJRPUnXkOq7nZ1lzZZdv4uheG8nhw+unAmO+oBhlAivkzAqc84NwG
         db+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=KiyN1WNneI01UCM+Yrm9DeJyVdbJ7jawhPs8z9lMmsE=;
        b=BDu1UEhJB/jO6JGAOuNyBnpIRYwkgl5afFseDOpLEoFnb+c9hFzeJU9AQTNDXCz57I
         68xgtpZdLu1uDYhDrLAr9x+j4ibNQDGw1aWe3ZWdlGn7Yiu2+mcMGcUQYBj3UwhkZCUN
         5iL0+9FjCQmcEUfoqBsoPYo2N9lqOJ+SKIYpjbiCKsI2078+u8egBgu5+0cVtNtLPjbK
         dZtrQ63/IxPD24noIqGZ+4eWQoyTIxAAS2BKZQaNQEr1SfsF44e5locMqWJq/0dTTmrD
         tQsnZXO9AA3Iu67UvfKQ/nrB5HthLlVVYFzQqiHvSYflRyAnor3vP6RvsfvGNqKwEGxY
         wqqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F3VmtU6A;
       spf=pass (google.com: domain of 3qjyoyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3QJyoYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KiyN1WNneI01UCM+Yrm9DeJyVdbJ7jawhPs8z9lMmsE=;
        b=YmY8ldebfAT6Vw95c5LEeSIzBWAi9rSUxYoiEabvBwRiz+LXD2Pb/fnSsClIJaemil
         W446mZvgfrdqysq68p2kcGWmH2vrH1/cGxSrSJr8A1kVXnBvlJmikmVLeCpQri5F4DK9
         AUvhXJjBdoyGYU1xV36vG/HN3RnM6hwyh/TK1WPSqu/5iKHKqppe6PLobvdMM6VCqf/T
         sKTKgkG4dSzrGF3kGJIuisKDs+etwDUU4SW8nZx+TQSha4FnS7tsVBuogvJO9TS7THot
         vScGpxDpe/T2D2wb4qp90r26QjgwhWEQPCju1RSN2JdR9RCUZzh8PzNNMW3P2VQm0j85
         tSGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KiyN1WNneI01UCM+Yrm9DeJyVdbJ7jawhPs8z9lMmsE=;
        b=P6QllWEGOhGh8riT5NadJlY1koX0YX9Fh3fglZgE9cIafRklHBg+A2WrNQVKt/JDJl
         UY+E7TSkcnhyvtim0mL3rWdWjaFWtBYdlRj7Y+uYKRyFNKrvoea1wcwabRdD8WmgT2Kj
         paV+iXCY1tYrKQUzdiZ6piQUoKSDjuJd5FOhmtigM/qhfO7mR9essJRcHHPgHcyzWAuA
         RyEC/ZOf704TbpXnS/4RUzK/hlNRdLaKCho6x+EKZtJPYYdx8aJaFE6bCEI4yRw7woPB
         b9NMga9+z4/40WTfxxaZbYMpVjkNR1lyaMXjv+Tpj7y201oKm0tfSBmK3ShbVT1N3GHd
         EmJg==
X-Gm-Message-State: AOAM531G8RftnQFUyz0jWw5aYoSkHBuWmrf9ixahRQdBwr3xKPRTS543
	LASxmCXWgdC8uA/8EUYzpt0=
X-Google-Smtp-Source: ABdhPJyB4XEtO+h8NaBttGfum/o+skk2luVGb6+Q6B6h9olSW+WmsQ4AXOrwUi+r9bue8iuTVtaFFw==
X-Received: by 2002:a05:6402:50ca:: with SMTP id h10mr16012438edb.70.1638440001797;
        Thu, 02 Dec 2021 02:13:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c517:: with SMTP id o23ls5857148edq.2.gmail; Thu, 02 Dec
 2021 02:13:20 -0800 (PST)
X-Received: by 2002:aa7:d512:: with SMTP id y18mr16970686edq.163.1638440000788;
        Thu, 02 Dec 2021 02:13:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638440000; cv=none;
        d=google.com; s=arc-20160816;
        b=CdO5R1bwfbe3L7NZerkOIW1zvvgrldfKtphZTqbxy2bg3SuVWrwssSYO4OUMi69d4N
         CeYTuGsXj4tthSiGiHZxZ9ljwrudunCf+6lEqc3kYSERlnruCrqRYQMWX+Q7RSjdlWAT
         KQR57Qq+tzPG2MYnzh4vz/UcDg1Q+phu+LQ2fk4Qff/Ip06EyeTUYgaQG/wYezWNXnXh
         g8VUhT5Y2zOOFmwUejm87iI9I7lUJj2+xXlyWF2I3kZKUUZPwq2HzhEcNe4cLPPt6Dv8
         rLkuRtFH+6khR//2Qwqb7NfsHvUHTaJt/klEnF2T4wj5qFxw8NyCkj8Wg5b0cv5EBG1K
         QUJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=8N5RdsPFCDQOOr5Z+B7VY5Dmo/Ijqkz2fn7CLWsbo/s=;
        b=bNzjj+naTKvZSYXStAaWvP5otK+ooC+aLZtcfw9EgUS6Na+BtiWdiylc9f/SfrYK4y
         PN6+mbQbrlLTxtTWn5IW0mXcs8GuGj6HgK9v+ofZRlyXMSHS5+MfAPID404sjkP5DsoD
         C8SIfWzh2f7daGIG7JsKaWPW88xv0r1w2g95tXoAzGRu8FCbuq3xZpqy9p0RAe2VwK+g
         BBhHfIiPLPp6oX1mY7YrYiWsUIxGZN5QkG5SIl48qka+HuK9SHT7WejPr8WByY3NudQP
         mvxxeMT+l8yzCRHGoCRvGnYu8i4M9n/rjQKtb4/91uzGJVO/K+p23xpETZy+vXDTvrJE
         lLEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=F3VmtU6A;
       spf=pass (google.com: domain of 3qjyoyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3QJyoYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id fl21si211722ejc.0.2021.12.02.02.13.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Dec 2021 02:13:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qjyoyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id p17-20020adff211000000b0017b902a7701so4872959wro.19
        for <kasan-dev@googlegroups.com>; Thu, 02 Dec 2021 02:13:20 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:ddd6:f3c9:b2f0:82f3])
 (user=elver job=sendgmr) by 2002:a5d:4e0b:: with SMTP id p11mr13212204wrt.88.1638440000442;
 Thu, 02 Dec 2021 02:13:20 -0800 (PST)
Date: Thu,  2 Dec 2021 11:12:38 +0100
Message-Id: <20211202101238.33546-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH] locking/mutex: Mark racy reads of owner->on_cpu
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>, 
	linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, "Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=F3VmtU6A;       spf=pass
 (google.com: domain of 3qjyoyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3QJyoYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

One of the more frequent data races reported by KCSAN is the racy read
in mutex_spin_on_owner(), which is usually reported as "race of unknown
origin" without showing the writer. This is due to the racing write
occurring in kernel/sched. Locally enabling KCSAN in kernel/sched shows:

 | write (marked) to 0xffff97f205079934 of 4 bytes by task 316 on cpu 6:
 |  finish_task                kernel/sched/core.c:4632 [inline]
 |  finish_task_switch         kernel/sched/core.c:4848
 |  context_switch             kernel/sched/core.c:4975 [inline]
 |  __schedule                 kernel/sched/core.c:6253
 |  schedule                   kernel/sched/core.c:6326
 |  schedule_preempt_disabled  kernel/sched/core.c:6385
 |  __mutex_lock_common        kernel/locking/mutex.c:680
 |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
 |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
 |  mutex_lock                 kernel/locking/mutex.c:283
 |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
 |  ...
 |
 | read to 0xffff97f205079934 of 4 bytes by task 322 on cpu 3:
 |  mutex_spin_on_owner        kernel/locking/mutex.c:370
 |  mutex_optimistic_spin      kernel/locking/mutex.c:480
 |  __mutex_lock_common        kernel/locking/mutex.c:610
 |  __mutex_lock               kernel/locking/mutex.c:740 [inline]
 |  __mutex_lock_slowpath      kernel/locking/mutex.c:1028
 |  mutex_lock                 kernel/locking/mutex.c:283
 |  tty_open_by_driver         drivers/tty/tty_io.c:2062 [inline]
 |  ...
 |
 | value changed: 0x00000001 -> 0x00000000

This race is clearly intentional, and the potential for miscompilation
is slim due to surrounding barrier() and cpu_relax(), and the value
being used as a boolean.

Nevertheless, marking this reader would more clearly denote intent and
make it obvious that concurrency is expected. Use READ_ONCE() to avoid
having to reason about compiler optimizations now and in future.

Similarly, mark the read to owner->on_cpu in mutex_can_spin_on_owner(),
which immediately precedes the loop executing mutex_spin_on_owner().

Signed-off-by: Marco Elver <elver@google.com>
---

I decided to send this out now due to the discussion at [1], because it
is one of the first things that people notice when enabling KCSAN.

[1] https://lkml.kernel.org/r/811af0bc-0c99-37f6-a39a-095418b10661@huawei.com

It had been reported before, but never with the 2nd stack trace -- so at
the very least this patch can now serve as a reference.

Thanks,
-- Marco

---
 kernel/locking/mutex.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/locking/mutex.c b/kernel/locking/mutex.c
index db1913611192..50c03a3fa61e 100644
--- a/kernel/locking/mutex.c
+++ b/kernel/locking/mutex.c
@@ -367,7 +367,7 @@ bool mutex_spin_on_owner(struct mutex *lock, struct task_struct *owner,
 		/*
 		 * Use vcpu_is_preempted to detect lock holder preemption issue.
 		 */
-		if (!owner->on_cpu || need_resched() ||
+		if (!READ_ONCE(owner->on_cpu) || need_resched() ||
 				vcpu_is_preempted(task_cpu(owner))) {
 			ret = false;
 			break;
@@ -410,7 +410,7 @@ static inline int mutex_can_spin_on_owner(struct mutex *lock)
 	 */
 
 	if (owner)
-		retval = owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
+		retval = READ_ONCE(owner->on_cpu) && !vcpu_is_preempted(task_cpu(owner));
 
 	/*
 	 * If lock->owner is not set, the mutex has been released. Return true
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211202101238.33546-1-elver%40google.com.
