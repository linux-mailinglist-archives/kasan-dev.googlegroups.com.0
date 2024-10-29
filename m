Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQF5QK4QMGQEDIZ3GUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 380BF9B4458
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 09:37:22 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-539e3cd6b66sf3077264e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 01:37:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730191041; cv=pass;
        d=google.com; s=arc-20240605;
        b=CZQ6oaPYHxZqPN+SopaAqXGtimIvlnxtqueSIQ9IB0j/Kot+Jb9YSxH7UK5a9jyC18
         z+DpqkpC2/4UJNwEZJxrEes+QmT6Ak0FoNv3ZOQvvDxKC8MEW02ojZ1l31BoNV3gEIPe
         91qQSQ9S+ER7w2eYBoUAhCsoQXLHTPbxHMjQ0MfLfrlajzcqcXK45byOZ2BTll7Q9laq
         hQvr5j2Niist2ON/4VIuB4E6974ZDlyZ5vUpLtq6cyPaHh1wshDThm5/4Mo8u6KIMOQ9
         rRfZYcn0Fshw7SidtWl9kG4RMLSlIdwwtlp/TNMHkku+covHASj/qK0QTaqxYnvqyPkL
         XyEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=v2odq5bMH+LkOM8Kd7ayr0+Cr+mcduGN4WPQ9DgBsNE=;
        fh=DU+JAH+abZyJfYlEGXl+KosUDWdUdZNz7Wrhbd8608U=;
        b=KaV5t/dffhSzOGPG30UAaKCqpp0xzZWRSlxfxwenpTivlzfsTaFaOmzP4GNCDPonTS
         DV+L9ZA3BEx2D5/27SYbB9hcu0CSzuiaLtqvema3GO65sdsHYkjt9G1X2AqqwNRPuviY
         NH1TKqz4YKDQWAcvZu9RBlaFyEvcFyRoijZoFAfNZU+nIsNWo+ox3bxNdHDW5iFzNRLk
         9ehcqE0FBGTGIwZ/z8iUtj/l4Q5587puoXtnv96lelABbUgDuUNmyduqGhJyFX6c7CSZ
         D5MculSChNeNdjal93Y1bWlSz+an/o656p0ulcOdCnxWUqo4QnlZCZBt0xVaUguId9dv
         vIXA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gaSTDFDy;
       spf=pass (google.com: domain of 3vz4gzwukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3vZ4gZwUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730191041; x=1730795841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v2odq5bMH+LkOM8Kd7ayr0+Cr+mcduGN4WPQ9DgBsNE=;
        b=ImhP+Px3czqkD+asYZ8FcMI12jE4KiL2DCUVVGqQ082KpK/NRH3SRoOM7SxyUf9obH
         daKzWzmbjJz+yOyn4mgy6atmc2wvh00/97eE5rw3Kob6Jo9V1+i93axWbNx02C4S+CPW
         o7kgOaNi8ougZOBjTXViuU9fBUVhuK3bXJ8SCaZlOj3KQjAjqzTuFgJ8hTJ2piwGeZtO
         3elD9NivBe5/POz63HdFULTwc1qUMj8Xo2I9TAr/RJr1w9bEl6BsWEjKgebEdZzeqLq9
         0mGenJYQt78MADfhYc68fo5zJlLOje2+b+gVYVzXJ4Af9Xj+2UUxsVQSg1vADXer4vJc
         YX7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730191041; x=1730795841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v2odq5bMH+LkOM8Kd7ayr0+Cr+mcduGN4WPQ9DgBsNE=;
        b=KhVTpc5sm1nZpCxUIWXQLTpsBQ+KhLCk7GnvH8JaBC2lkDgH7eWMxwwIZReWUQ7mg+
         GyZ1HlTO2Z/Idv1eZHnUw7zSKO4Vt+u4Lyhy+UgcM42dJ8uFbPWPoIP5nvDl136GEcUM
         29l/IhP+EM3MTgeofFFBqplYtYNBgK4xDVHhsYjugpZKZ6LLzFXa95kC7bGoNqZTbQ3s
         ZeGRiTc6FeRsqJCY1ywkDzm9xosNz54Yz/ofQXTI082Mcy7/728XwPQZ2px6l/uDeS2x
         06/CYi62wIgxZFdeUggxnOPCTxEXb4vLridkhgi8qFX4d3NYbuTDgMeFveJjtzHDrXnR
         4YGw==
X-Forwarded-Encrypted: i=2; AJvYcCX2Bf9XEdg2vTQAYgHseVGnOzLEnJh8Kovbqy+PPvIT3sgx8dDj0o+o0nhfD20+A+fdFJ8NeQ==@lfdr.de
X-Gm-Message-State: AOJu0YzLgglIDCtFXp8wleKb4XlDidEg9AA6QCoTc9S9cY2nFCLGsC6G
	5AtvAOZv6XE8bA0lqKTe00XqmhI6ghKSG0cUpFsJVfvglHxJGb8y
X-Google-Smtp-Source: AGHT+IGBGbNrqZ1lU8XTrGu6VdtDc2lk+aS3KCQO0BYY10lfY7nyf5Mh1SglEDaSLvu1LyDDwncBoA==
X-Received: by 2002:a05:6512:1388:b0:52f:27e:a82e with SMTP id 2adb3069b0e04-53b49461cd8mr422812e87.21.1730191040564;
        Tue, 29 Oct 2024 01:37:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1116:b0:539:e021:5378 with SMTP id
 2adb3069b0e04-53b2145776bls223431e87.1.-pod-prod-00-eu; Tue, 29 Oct 2024
 01:37:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0CFxn6+YscpmJVJrol55t2BCAXPW/MQREYXEEmz7jLMxxolPncudoBRKnSnkkXC8LfWg5MkZuXIU=@googlegroups.com
X-Received: by 2002:a05:6512:3ba6:b0:53b:1f90:5779 with SMTP id 2adb3069b0e04-53b49295bf5mr442533e87.28.1730191038138;
        Tue, 29 Oct 2024 01:37:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730191038; cv=none;
        d=google.com; s=arc-20240605;
        b=HKUAxV63zZujl6l6MxVVf2DrXXMSufWZ+u+WzT0j9Bq+GtK/uBoFKt6gtD24g/k0Hu
         141puFXetzdewUFScgp57P3bgBpWAffEe72WMoIHZtwUIHEbz80oFpEAkjWqyGn+ygnk
         d/dYjLnNupMo93MA/XIWErabzbnIrv5cQf+BHxlgVeJnbtfTZqOnIAp/UuucCgwJnpd2
         +FJ1Zm7fLbOAcUxDnrMpObzBPIk9JMoSg/U619q21mGGEK7aFGqfIzF+deirhOrfIdSP
         SNXL+gZh6Vs+cU8UZqJP+AQ9cAYfn7o/SihQL6G0zw2dcUXYDl8Z6KBVDx5L/eBwEVQ4
         JhWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=zhSkLyvcAgLlS+6T/t43F9F3pPfA6xXjKxWozXWQfL4=;
        fh=akfj7KAe1Ko72LBo2G+Kyj/E6L/86SgL+ywlT5R/J10=;
        b=MTykJkW78qaOFPaSf3pOhC/exFhTGIrOTGCSI5v2JourL4uW/tLN2tJ7wDWN0R4MD7
         72eBPLMz1fbQ1zr4Yr70FhSgJ8mQ+S69teCjvf7mQh0ODhSTV32ggQlbDb/QApTZ5KK4
         BLPvrniBKjBiBBxic/bAZ9Fn7/H3jbcY5Tszebh8zME1AA2yaResJajKpwYc56/GqYce
         LzYqhRe6BS144Qenc5Bs6u0GFFzHR/v2TmNR3tpA62Qwd/WtTQUgBVVsLvpEjusU8oui
         UH4y2w8SRAbDL/T6VLnWtgjw+q/OFM5NG8eZFSLSPQvJJXqcC2Jr2nwa2OEQloUQ7YST
         vehQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gaSTDFDy;
       spf=pass (google.com: domain of 3vz4gzwukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3vZ4gZwUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53b2e1218fdsi171950e87.4.2024.10.29.01.37.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Oct 2024 01:37:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vz4gzwukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5c935cc6a96so3472141a12.1
        for <kasan-dev@googlegroups.com>; Tue, 29 Oct 2024 01:37:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVSrE6n2muqZNtYjFYBCWfu4H3W4D8VD3ZtdFxvi9AOWwLV4o3cANDXh9rFGLphdCKTQl75LC4BRkg=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:7cc7:9e06:a6d2:add7])
 (user=elver job=sendgmr) by 2002:a05:6402:4021:b0:5cb:def2:be06 with SMTP id
 4fb4d7f45d1cf-5cbdef2c080mr1989a12.0.1730191037134; Tue, 29 Oct 2024 01:37:17
 -0700 (PDT)
Date: Tue, 29 Oct 2024 09:36:29 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.47.0.163.g1226f6d8fa-goog
Message-ID: <20241029083658.1096492-1-elver@google.com>
Subject: [PATCH] kcsan, seqlock: Support seqcount_latch_t
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gaSTDFDy;       spf=pass
 (google.com: domain of 3vz4gzwukcbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3vZ4gZwUKCbwgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

While fuzzing an arm64 kernel, Alexander Potapenko reported:

| BUG: KCSAN: data-race in ktime_get_mono_fast_ns / timekeeping_update
|
| write to 0xffffffc082e74248 of 56 bytes by interrupt on cpu 0:
|  update_fast_timekeeper kernel/time/timekeeping.c:430 [inline]
|  timekeeping_update+0x1d8/0x2d8 kernel/time/timekeeping.c:768
|  timekeeping_advance+0x9e8/0xb78 kernel/time/timekeeping.c:2344
|  update_wall_time+0x18/0x38 kernel/time/timekeeping.c:2360
|  tick_do_update_jiffies64+0x164/0x1b0 kernel/time/tick-sched.c:149
|  tick_nohz_handler+0xa4/0x2a8 kernel/time/tick-sched.c:232
|  __hrtimer_run_queues+0x198/0x33c kernel/time/hrtimer.c:1691
|  hrtimer_interrupt+0x16c/0x630 kernel/time/hrtimer.c:1817
|  timer_handler drivers/clocksource/arm_arch_timer.c:674 [inline]
|  arch_timer_handler_phys+0x60/0x74 drivers/clocksource/arm_arch_timer.c:692
|  handle_percpu_devid_irq+0xd8/0x1ec kernel/irq/chip.c:942
|  generic_handle_irq_desc include/linux/irqdesc.h:173 [inline]
|  handle_irq_desc kernel/irq/irqdesc.c:692 [inline]
|  generic_handle_domain_irq+0x5c/0x7c kernel/irq/irqdesc.c:748
|  gic_handle_irq+0x78/0x1b0 drivers/irqchip/irq-gic-v3.c:843
|  call_on_irq_stack+0x24/0x4c arch/arm64/kernel/entry.S:889
|  do_interrupt_handler+0x74/0xa8 arch/arm64/kernel/entry-common.c:310
|  __el1_irq arch/arm64/kernel/entry-common.c:536 [inline]
|  el1_interrupt+0x34/0x54 arch/arm64/kernel/entry-common.c:551
|  el1h_64_irq_handler+0x18/0x24 arch/arm64/kernel/entry-common.c:556
|  el1h_64_irq+0x64/0x68 arch/arm64/kernel/entry.S:594
|  __daif_local_irq_enable arch/arm64/include/asm/irqflags.h:26 [inline]
|  arch_local_irq_enable arch/arm64/include/asm/irqflags.h:48 [inline]
|  kvm_arch_vcpu_ioctl_run+0x8d4/0xf48 arch/arm64/kvm/arm.c:1259
|  kvm_vcpu_ioctl+0x650/0x894 virt/kvm/kvm_main.c:4487
|  __do_sys_ioctl fs/ioctl.c:51 [inline]
|  __se_sys_ioctl fs/ioctl.c:893 [inline]
|  __arm64_sys_ioctl+0xf8/0x170 fs/ioctl.c:893
|  [...]
|
| read to 0xffffffc082e74258 of 8 bytes by task 5260 on cpu 1:
|  __ktime_get_fast_ns kernel/time/timekeeping.c:372 [inline]
|  ktime_get_mono_fast_ns+0x88/0x174 kernel/time/timekeeping.c:489
|  init_srcu_struct_fields+0x40c/0x530 kernel/rcu/srcutree.c:263
|  init_srcu_struct+0x14/0x20 kernel/rcu/srcutree.c:311
|  kvm_dev_ioctl+0x304/0x908 virt/kvm/kvm_main.c:1185
|  __do_sys_ioctl fs/ioctl.c:51 [inline]
|  __se_sys_ioctl fs/ioctl.c:893 [inline]
|  __arm64_sys_ioctl+0xf8/0x170 fs/ioctl.c:893
|  [...]
|
| value changed: 0x000002f875d33266 -> 0x000002f877416866
|
| Reported by Kernel Concurrency Sanitizer on:
| CPU: 1 UID: 0 PID: 5260 Comm: syz.2.7483 Not tainted 6.12.0-rc3-dirty #78

This is a false positive data race between a seqcount latch writer and a
reader accessing stale data.

Unlike the regular seqlock interface, the seqcount_latch interface for
latch writers never has a well-defined critical section.

To support with KCSAN, optimistically declare that a fixed number of
memory accesses after raw_write_seqcount_latch() are "atomic". Latch
readers follow a similar pattern as the regular seqlock interface. This
effectively tells KCSAN that data races on accesses to seqcount_latch
protected data should be ignored.

Reviewing current raw_write_seqcount_latch() callers, the most common
patterns involve only few memory accesses, either a single plain C
assignment, or memcpy; therefore, the value of 8 memory accesses after
raw_write_seqcount_latch() is chosen to (a) avoid most false positives,
and (b) avoid excessive number of false negatives (due to inadvertently
declaring most accesses in the proximity of update_fast_timekeeper() as
"atomic").

Reported-by: Alexander Potapenko <glider@google.com>
Tested-by: Alexander Potapenko <glider@google.com>
Fixes: 88ecd153be95 ("seqlock, kcsan: Add annotations for KCSAN")
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/seqlock.h | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index fffeb754880f..e24cf144276e 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -614,6 +614,7 @@ typedef struct {
  */
 static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *s)
 {
+	kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
 	/*
 	 * Pairs with the first smp_wmb() in raw_write_seqcount_latch().
 	 * Due to the dependent load, a full smp_rmb() is not needed.
@@ -631,6 +632,7 @@ static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *
 static __always_inline int
 raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
 {
+	kcsan_atomic_next(0);
 	smp_rmb();
 	return unlikely(READ_ONCE(s->seqcount.sequence) != start);
 }
@@ -721,6 +723,13 @@ static inline void raw_write_seqcount_latch(seqcount_latch_t *s)
 	smp_wmb();	/* prior stores before incrementing "sequence" */
 	s->seqcount.sequence++;
 	smp_wmb();      /* increment "sequence" before following stores */
+
+	/*
+	 * Latch writers do not have a well-defined critical section, but to
+	 * avoid most false positives, at the cost of false negatives, assume
+	 * the next few memory accesses belong to the latch writer.
+	 */
+	kcsan_atomic_next(8);
 }
 
 #define __SEQLOCK_UNLOCKED(lockname)					\
-- 
2.47.0.163.g1226f6d8fa-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241029083658.1096492-1-elver%40google.com.
