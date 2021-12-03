Return-Path: <kasan-dev+bncBCRKFI7J2AJRBBUYU6GQMGQE44A43HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D3CC4672EA
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 08:49:27 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id v14-20020a05620a0f0e00b0043355ed67d1sf2492930qkl.7
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Dec 2021 23:49:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638517766; cv=pass;
        d=google.com; s=arc-20160816;
        b=dMzGIKZhBlxGoLRc7k1ezKUoyckxEu0D9dG7RSkVnE5iOqgzeI67kMQ4Y0fvDn3iB7
         CH/YJlxDcz8D67QxNwHl49vODnK4aJWDpTh3eizV+FBjpcQhIRwTUzBM98YTUOC1RcTx
         zstWuctl5H2B7GsunqiZizkuFPcEyMK7XRMs+zP2SoXZlTSRme1Kq541AokQX9jUK0k2
         Mh6U36CorSiQ1e75p4J0mnVkk4DXhxPbnDTsIWN9Gycc0silbmCY0ZvkTpws1V7vnFCE
         SikteEhWT8eAuSjwZc2/m2cxum8ZiDpzhc/0+qW8Fg8cmmEjbCeY56428T/WVv4x5V7e
         HjPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=f88RTHEGgA/JpmqtC0OhsQse75M57EC6HVIiTy30eQs=;
        b=fwoHvf7FQZitzYZvMYYU25CIp8t1HgQ5CjZHr5Ys3ITTeQvaBp8K03ukim95oRw4qA
         ayoNjTVe/ES/E5ooiDh6N+4B5wpcLQ9juR3eE3r5rgaVkurcg6fjbDSnjZh+KIr31WzC
         VbXeZJEsOS1Am6x3s2Vchk3w39WJ+Ebggc4f7465K+QCg//t0R2TDy0/kphglT+OCf5X
         20lihtKIq05fncI/eX0G0TLozz2RTisMp912snWaj25oMcZKWBPdylANk/DicOOu8jkh
         HHNclTrfPWFcnWG7d/E9f3XaQOKujpCtRE99kWCtSTOYil+PSv5TUXVExFZnGWQiJnUk
         ZgpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=f88RTHEGgA/JpmqtC0OhsQse75M57EC6HVIiTy30eQs=;
        b=aBFn4KNOQ3RAODjhmju0rdL+e8ohvNxDsprMb0n0n4PJy3JM3OHm64A1oqokskPzA3
         Z78jIHZQvE14+y4dvdokgxgiTroc6F3I5kjjdxlg0va6tcLTtN9E9UZvb9ro/N2xhCHd
         yz7aP7PxCRh+syVlVFB8oj/P5ic8FgEb0qHLzDEnsjY590fE45EdtjhzP1f3lkXu0cUy
         qCS+AMy6zTyGoWYMP0NMV2rsJgqMzZXlgCBZVGMa3yoY+7CPv8BqF+NjbCUuOSRfHAk1
         g3fxbGuvy1oLK8sNSuINKPWHBcRb6/hiknGUElWvQh/cIL2OoKuRPYviu1ylz6owor19
         IkxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f88RTHEGgA/JpmqtC0OhsQse75M57EC6HVIiTy30eQs=;
        b=fBfNKG/6TL8KJU74KgTuO2zTQEOqc9wUV0+SnutezW8PPY99c4puVnFR8L/84dqjWs
         7DeLauOiUzmwmxr+D2IOqzTFfaphjJxtf02es2irbkskVi5LCqmFzaPOhChVP8mAI/7m
         mTbBlyfPFWa8EJycg+tHAyQn5IWDlvf1nc68rnwXfQDHmXxa/UhsPdMuz6loRQy8jzJW
         vcDiA1l1I8FAUechBcJ+k/Df1uvASdf6cjQ8jUNs2LEhxyojVWVl41FBKjFqWoGWFQTD
         2eMRjjaO7bwrnbXkK1YcCveVzFXVi4te7ytuTZC6KvRkNtBKY8AyRL5r4si5rxNPFLFe
         815g==
X-Gm-Message-State: AOAM531JzfNtCA/GFh89vMvjW/dwee6oGL77rK3LgIQIKl5nCXuzz+xm
	hHzH4Ogt+qeluMt4yS2ZxOE=
X-Google-Smtp-Source: ABdhPJwKBEckKiJq35F+gEZc3aJrRee0Zc1RnYK3I/NmFdkJFL9+4wp3OQ+C+UxMwV/37y/RDhO35g==
X-Received: by 2002:a05:620a:2905:: with SMTP id m5mr16315178qkp.598.1638517766446;
        Thu, 02 Dec 2021 23:49:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7e88:: with SMTP id w8ls5975132qtj.3.gmail; Thu, 02 Dec
 2021 23:49:26 -0800 (PST)
X-Received: by 2002:a05:622a:346:: with SMTP id r6mr18734750qtw.78.1638517766042;
        Thu, 02 Dec 2021 23:49:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638517766; cv=none;
        d=google.com; s=arc-20160816;
        b=k2pmffaaZyJK7HCFB29EqtoJlr4ZvmB6QoYslymrVYoLRZ7U9OjwPyoYJRvCmfGngR
         HrUzF5DWGp2w5E8pESBRxjhKCOOjT2zi0L/i2vdLurY81aHpw9qy8QLTQ6fnz42gqUXp
         wCmYO5SaF+8xh3VY/sDkdlbBbg2tjhdr5zJrJytX8/yn2qqYREcL1ZnEb6rrPwLDnRli
         45eUH9Z/xNKWOKwoBB31ztgVC3/9U2hMhaG+23XouHU4+SR8Kx38aD6xeb5luX7Wq/im
         KY/NyslyLtPQuyMN7v3whAaoA2ToY3WC4tB5TSO20/Chy7SOFSqhK9Ji1oBQ4K+vZLxu
         khcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Ij7c0JXicJlvxpjl7fFS15gPUmkr3ktdr69t6ir6P3Q=;
        b=qY2gISTxHC/ItMXYpdgjrfl32HUFg516X2bdXtNNUh+bihfwhhER0R+UNZU/voLCx4
         qd9zkBYPa+h4MogaFUgTvzVOOXOYrbNjFwpp4Lv8HQCM4t4wDF0BcEX+I+7c++2DinVP
         1proFhw76nM6CBx61MbDuGWLTQix22IkK4AOxrdAn7RpNuft2//P98TmBORRp5h+dzoa
         HYSKD4B58m2axfjEEM6R75Or06yIaK/L52HbgVowxpY42t/zna2jM6haqr2Gns3Es9z1
         fhU9ez9ksdyDbShki8BtcYGqVIFDgGZGndSB+xw+z2eDae2UH5yCtU70T7Lo4N6x7qpE
         6prQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id s4si446906qtc.4.2021.12.02.23.49.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Dec 2021 23:49:26 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm500021.china.huawei.com (unknown [172.30.72.54])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4J54hD3ZPDzcbpX;
	Fri,  3 Dec 2021 15:48:44 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500021.china.huawei.com (7.185.36.109) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Fri, 3 Dec 2021 15:48:52 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Fri, 3 Dec 2021 15:48:52 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
CC: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>, Waiman Long
	<longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>, Thomas Gleixner
	<tglx@linutronix.de>, Mark Rutland <mark.rutland@arm.com>, "Paul E. McKenney"
	<paulmck@kernel.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH v2 1/2] locking: Make owner_on_cpu() into <linux/sched.h>
Date: Fri, 3 Dec 2021 15:59:34 +0800
Message-ID: <20211203075935.136808-2-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
References: <20211203075935.136808-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

Move the owner_on_cpu() from kernel/locking/rwsem.c into
include/linux/sched.h with under CONFIG_SMP, then use it
in the mutex/rwsem/rtmutex to simplify the code.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 include/linux/sched.h    |  9 +++++++++
 kernel/locking/mutex.c   | 11 ++---------
 kernel/locking/rtmutex.c |  5 ++---
 kernel/locking/rwsem.c   |  9 ---------
 4 files changed, 13 insertions(+), 21 deletions(-)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 78c351e35fec..ff609d9c2f21 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -2171,6 +2171,15 @@ extern long sched_getaffinity(pid_t pid, struct cpumask *mask);
 #endif
 
 #ifdef CONFIG_SMP
+static inline bool owner_on_cpu(struct task_struct *owner)
+{
+	/*
+	 * As lock holder preemption issue, we both skip spinning if
+	 * task is not on cpu or its cpu is preempted
+	 */
+	return owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
+}
+
 /* Returns effective CPU energy utilization, as seen by the scheduler */
 unsigned long sched_cpu_util(int cpu, unsigned long max);
 #endif /* CONFIG_SMP */
diff --git a/kernel/locking/mutex.c b/kernel/locking/mutex.c
index db1913611192..5e3585950ec8 100644
--- a/kernel/locking/mutex.c
+++ b/kernel/locking/mutex.c
@@ -367,8 +367,7 @@ bool mutex_spin_on_owner(struct mutex *lock, struct task_struct *owner,
 		/*
 		 * Use vcpu_is_preempted to detect lock holder preemption issue.
 		 */
-		if (!owner->on_cpu || need_resched() ||
-				vcpu_is_preempted(task_cpu(owner))) {
+		if (!owner_on_cpu(owner) || need_resched()) {
 			ret = false;
 			break;
 		}
@@ -403,14 +402,8 @@ static inline int mutex_can_spin_on_owner(struct mutex *lock)
 	 * structure won't go away during the spinning period.
 	 */
 	owner = __mutex_owner(lock);
-
-	/*
-	 * As lock holder preemption issue, we both skip spinning if task is not
-	 * on cpu or its cpu is preempted
-	 */
-
 	if (owner)
-		retval = owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
+		retval = owner_on_cpu(owner);
 
 	/*
 	 * If lock->owner is not set, the mutex has been released. Return true
diff --git a/kernel/locking/rtmutex.c b/kernel/locking/rtmutex.c
index 0c6a48dfcecb..41152e8e799a 100644
--- a/kernel/locking/rtmutex.c
+++ b/kernel/locking/rtmutex.c
@@ -1379,9 +1379,8 @@ static bool rtmutex_spin_on_owner(struct rt_mutex_base *lock,
 		 *    for CONFIG_PREEMPT_RCU=y)
 		 *  - the VCPU on which owner runs is preempted
 		 */
-		if (!owner->on_cpu || need_resched() ||
-		    rt_mutex_waiter_is_top_waiter(lock, waiter) ||
-		    vcpu_is_preempted(task_cpu(owner))) {
+		if (!owner_on_cpu(owner) || need_resched() ||
+		    rt_mutex_waiter_is_top_waiter(lock, waiter)) {
 			res = false;
 			break;
 		}
diff --git a/kernel/locking/rwsem.c b/kernel/locking/rwsem.c
index 04a74d040a6d..69aba4abe104 100644
--- a/kernel/locking/rwsem.c
+++ b/kernel/locking/rwsem.c
@@ -658,15 +658,6 @@ static inline bool rwsem_try_write_lock_unqueued(struct rw_semaphore *sem)
 	return false;
 }
 
-static inline bool owner_on_cpu(struct task_struct *owner)
-{
-	/*
-	 * As lock holder preemption issue, we both skip spinning if
-	 * task is not on cpu or its cpu is preempted
-	 */
-	return owner->on_cpu && !vcpu_is_preempted(task_cpu(owner));
-}
-
 static inline bool rwsem_can_spin_on_owner(struct rw_semaphore *sem)
 {
 	struct task_struct *owner;
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211203075935.136808-2-wangkefeng.wang%40huawei.com.
