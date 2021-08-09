Return-Path: <kasan-dev+bncBDKON27F3UHRBJFOY2EAMGQE6UN6BLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 235793E4E31
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 22:59:18 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id 61-20020a17090a09c3b029017897f47801sf326520pjo.8
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 13:59:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628542757; cv=pass;
        d=google.com; s=arc-20160816;
        b=ANZf7iCwkLtqu/yfNrPViUUKctrZ6sVEuIa2VaySossGVl2zCIc+tFqlN27gikI2yH
         NyxnwSLNcnrlvnTnnOMWbKK/X0YG+kxfcZnvAjn3fZesqBo6eNXK8M7+FqUyeR2fbdGR
         KYN857fUlU8AgtuKQOeW93o7dTgPPSBcCo7nuY7khqkhVWSGtE3mrQKl0cZDttq+vUP4
         0vNTYwKCnB0uuCHArx0PAsLrHNn9slUojDsYjAdVkXV5vGUyOSOxEtFw9LSYSMkd8h40
         H+mLv1RoetLHQEmS142GWdxaDcUszF/CLyQZSJ7Jg52Bdo6uU+W2lJRC9lHwMtLS9YBM
         5RWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:organization
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2qntGHxtG43IVYn2uuN2fsxCJHj5ZGVsO+k96RlAidk=;
        b=qLYGTuSnArW5OHEd4xeP8oSJqb6wctg99H0J7fHDRh0CLINVhX1S5sq5LX610hbjV7
         tupQMSfzbvZtn9TtyscbJFlQJpxJ30847RQrJDhojiYRT5/IxcZH9NOQXA4uyzB2AdXT
         cA/maTtyyDaM+IPWswyRw04zt0Ll5vP7P1/sb097tw7wwYBEFsUYFvC4fdZx7OLkfJ1A
         Yr/hov9KPsJWfp7FJSTQrw7TlvtA46uJT94/l2psP2lNHLimTq8dOyWUH9ESe5EAg7lj
         FzQNJLSY9mNt+OgiHPMi6qyzBvdu3ogNgG/lFGf4kOdScaETNhBSD31ep7V2nARbmH1H
         ghLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eNF5aDrX;
       spf=pass (google.com: domain of williams@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=williams@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:organization:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2qntGHxtG43IVYn2uuN2fsxCJHj5ZGVsO+k96RlAidk=;
        b=pgmRs937AnNDk5TIhSsT3IVAtCPaiWkFiLTGmdjNNUrz7wv4hhIIt67rHibcXJ17i1
         DSsU866TFzRhNW5c28L6CL6Ne1Cy7/LrtlOTf4sLVyBtgorJ+/FOC437F13DWxWYLA0S
         vd6MGhsclRA9wNMHewqcmLlyFgleK1YRg3QRBYN3xVT9BOGSsonNC4zlWgYY0BOlmjsh
         5mNoSy40pof6uWFOnze9RLH2VLkygkNzMSGk2+TG+U9lRquLouP5oXsd7CjLbtGQ0kCf
         1kvGtORvwaMxH/0jPMuSugleba3gfNiLh2MrTmVQeRgSOWRuLu589M41JibLDAfWo7tk
         sgvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :organization:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2qntGHxtG43IVYn2uuN2fsxCJHj5ZGVsO+k96RlAidk=;
        b=jkCV8BoSC63Mqmpaoyuiht8LQKsNETOFt3gyILcT36gdkYOvhBaZPJEKHbP50Ygymf
         UfyNOJPyNPMG8fNpS/CTShCfXd8u1VobsLYWUHraj6BVNDP8yNZ12GnIWekIq74XhiyS
         x4ar7jlvNGI3i3PcCvp9fyYJ8aID4wXzSkRJJUjO0I5jwlQuQPx9jmMY7DBDZufY+1g/
         ZOXWaghvTrF6XoN1oCVsD8zct63eTlwSBk4k9cDmMksassMDOf2yGvJTbrG40kjgbRxG
         +SpWUTVE1MN8T5YiAgm9VIBBxynHhEQGSxHDMupjwapJA3LtzGWD2h+0JHf02HlOTUZ4
         9y5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OYCgLzt6JG98oE4lWnQ0K5Tb3CIEFnDpoKiUzlYi3KU7voTmV
	FC4wnbjPYuyvSBU4OjE2bMM=
X-Google-Smtp-Source: ABdhPJwDgp9YszEcoNUref4vujcrcwi8u5mtKkh3B79D5gS2/EYJi/oe6w3TjZE9erbnsU3389fnUw==
X-Received: by 2002:a63:e23:: with SMTP id d35mr314076pgl.189.1628542756822;
        Mon, 09 Aug 2021 13:59:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:848e:: with SMTP id c14ls7984822plo.1.gmail; Mon, 09
 Aug 2021 13:59:16 -0700 (PDT)
X-Received: by 2002:a17:902:bc84:b029:12c:f9b9:db98 with SMTP id bb4-20020a170902bc84b029012cf9b9db98mr12559165plb.19.1628542756139;
        Mon, 09 Aug 2021 13:59:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628542756; cv=none;
        d=google.com; s=arc-20160816;
        b=OlQBR7dCoi0pv/1i6Fk0qHV4CEbizmtSgDQaXu47dayzVEfqJS9OogsjXe5MQB2xR5
         z5EEkjTZXl7QYtD5I/eRfvuuUYJThRbYkOtI1vG82j+0zlU4BWJpmW6xSLipk2xJBEcX
         yk5uziJGChCI9jyC0zTxtav2GNX702pNRpuKcQ5jqnB0ACrIY6h8Nt1bo3UTBCiwW2i9
         aDJP5uVcWgmZtvPEbrNR2fxWde6xRvyi8NKOs+mtmdyAoXmtMKW8Z+fm8ucYTMOLSpGI
         +wYS6lRozV5hqHujsGqoaYBP/fq8v/qHgfXEgN/K8S82k924cCk4x+6htHpv/WV3lrqV
         oxnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:organization:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=S7fF4unWqHGSW7W12PTgvCvQxdQEsv3txHXrxBi0k2k=;
        b=WCZizalX7tEFWQkiq1ol4j99E2aliO7vvMLAVa0mCIT7IH5wVCq1J0nNlOMjuVwfS9
         nxQGyGd9LWjxoobnt1PG0yQ2hzx117Qb8h0iFG7kUbKyArgsJc2uI9l0h9+aEEBuHgGE
         WOwgW4NQbglXJbHiFoEb/pwOchSHQS4nolC5CMopqe+C/igbx4uGBGw8vfjkf3yz7Fp9
         fDECUqdYQXSzTChRffQndj95bdS7iKGLlC8PydRjgrl6qu8JaEI1N5Wn0KV6e/yLtcG8
         An8X67sXmjITwXMz3TCr61EKzvf4qyrky4BsF4Ql8aP5pbN10CppKeqXORyIYOXWfqgS
         muqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eNF5aDrX;
       spf=pass (google.com: domain of williams@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=williams@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id c23si763137pls.5.2021.08.09.13.59.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Aug 2021 13:59:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of williams@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-135-3rzxQRduPMaafSiN6M_uFg-1; Mon, 09 Aug 2021 16:59:13 -0400
X-MC-Unique: 3rzxQRduPMaafSiN6M_uFg-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.phx2.redhat.com [10.5.11.11])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id DF646801AC0;
	Mon,  9 Aug 2021 20:59:11 +0000 (UTC)
Received: from theseus.lan (unknown [10.22.34.100])
	by smtp.corp.redhat.com (Postfix) with ESMTP id E2A4B604CC;
	Mon,  9 Aug 2021 20:59:10 +0000 (UTC)
Date: Mon, 9 Aug 2021 15:59:09 -0500
From: Clark Williams <williams@redhat.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Thomas Gleixner <tglx@linutronix.de>, Steven Rostedt
 <rostedt@goodmis.org>, Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Subject: [PATCH PREEMPT_RT] kcov:  fix locking splat from
 kcov_remote_start()
Message-ID: <20210809155909.333073de@theseus.lan>
Organization: Red Hat, Inc
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.11
X-Original-Sender: williams@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=eNF5aDrX;
       spf=pass (google.com: domain of williams@redhat.com designates
 216.205.24.124 as permitted sender) smtp.mailfrom=williams@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

Saw the following splat on 5.14-rc4-rt5 with:

CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_IRQ_AREA_SIZE=0x40000
CONFIG_RUNTIME_TESTING_MENU=y

kernel: ehci-pci 0000:00:1d.0: USB 2.0 started, EHCI 1.00
kernel: BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:35
kernel: in_atomic(): 0, irqs_disabled(): 1, non_block: 0, pid: 34, name: ksoftirqd/3
kernel: 4 locks held by ksoftirqd/3/34:
kernel:  #0: ffff944376d989f8 ((softirq_ctrl.lock).lock){+.+.}-{2:2}, at: __local_bh_disable_ip+0xe0/0x190
kernel:  #1: ffffffffbbfb61e0 (rcu_read_lock){....}-{1:2}, at: rt_spin_lock+0x5/0xd0
kernel:  #2: ffffffffbbfb61e0 (rcu_read_lock){....}-{1:2}, at: __local_bh_disable_ip+0xbd/0x190
kernel:  #3: ffffffffbc086518 (kcov_remote_lock){....}-{2:2}, at: kcov_remote_start+0x119/0x4a0
kernel: irq event stamp: 4653
kernel: hardirqs last  enabled at (4652): [<ffffffffbafb85ce>] _raw_spin_unlock_irqrestore+0x6e/0x80
kernel: hardirqs last disabled at (4653): [<ffffffffba2517c8>] kcov_remote_start+0x298/0x4a0
kernel: softirqs last  enabled at (4638): [<ffffffffba110a5b>] run_ksoftirqd+0x9b/0x100
kernel: softirqs last disabled at (4644): [<ffffffffba149f12>] smpboot_thread_fn+0x2b2/0x410
kernel: CPU: 3 PID: 34 Comm: ksoftirqd/3 Not tainted 5.14.0-rc4-rt5+ #3
kernel: Hardware name:  /NUC5i7RYB, BIOS RYBDWi35.86A.0359.2016.0906.1028 09/06/2016
kernel: Call Trace:
kernel:  dump_stack_lvl+0x7a/0x9b
kernel:  ___might_sleep.cold+0xf3/0x107
kernel:  rt_spin_lock+0x3a/0xd0
kernel:  ? kcov_remote_start+0x119/0x4a0
kernel:  kcov_remote_start+0x119/0x4a0
kernel:  ? led_trigger_blink_oneshot+0x83/0xa0
kernel:  __usb_hcd_giveback_urb+0x161/0x1e0
kernel:  usb_giveback_urb_bh+0xb6/0x110
kernel:  tasklet_action_common.constprop.0+0xe8/0x110
kernel:  __do_softirq+0xe2/0x525
kernel:  ? smpboot_thread_fn+0x31/0x410
kernel:  run_ksoftirqd+0x8c/0x100
kernel:  smpboot_thread_fn+0x2b2/0x410
kernel:  ? smpboot_register_percpu_thread+0x130/0x130
kernel:  kthread+0x1de/0x210
kernel:  ? set_kthread_struct+0x60/0x60
kernel:  ret_from_fork+0x22/0x30
kernel: usb usb1: New USB device found, idVendor=1d6b, idProduct=0002, bcdDevice= 5.14


Change kcov_remote_lock from regular spinlock_t to raw_spinlock_t so that
we don't get "sleeping function called from invalid context" on PREEMPT_RT kernel.

Signed-off-by: Clark Williams <williams@redhat.com>
---
 kernel/kcov.c | 28 ++++++++++++++--------------
 1 file changed, 14 insertions(+), 14 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 80bfe71bbe13..60f903f8a46c 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -82,7 +82,7 @@ struct kcov_remote {
 	struct hlist_node	hnode;
 };
 
-static DEFINE_SPINLOCK(kcov_remote_lock);
+static DEFINE_RAW_SPINLOCK(kcov_remote_lock);
 static DEFINE_HASHTABLE(kcov_remote_map, 4);
 static struct list_head kcov_remote_areas = LIST_HEAD_INIT(kcov_remote_areas);
 
@@ -375,7 +375,7 @@ static void kcov_remote_reset(struct kcov *kcov)
 	struct hlist_node *tmp;
 	unsigned long flags;
 
-	spin_lock_irqsave(&kcov_remote_lock, flags);
+	raw_spin_lock_irqsave(&kcov_remote_lock, flags);
 	hash_for_each_safe(kcov_remote_map, bkt, tmp, remote, hnode) {
 		if (remote->kcov != kcov)
 			continue;
@@ -384,7 +384,7 @@ static void kcov_remote_reset(struct kcov *kcov)
 	}
 	/* Do reset before unlock to prevent races with kcov_remote_start(). */
 	kcov_reset(kcov);
-	spin_unlock_irqrestore(&kcov_remote_lock, flags);
+	raw_spin_unlock_irqrestore(&kcov_remote_lock, flags);
 }
 
 static void kcov_disable(struct task_struct *t, struct kcov *kcov)
@@ -638,18 +638,18 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		kcov->t = t;
 		kcov->remote = true;
 		kcov->remote_size = remote_arg->area_size;
-		spin_lock_irqsave(&kcov_remote_lock, flags);
+		raw_spin_lock_irqsave(&kcov_remote_lock, flags);
 		for (i = 0; i < remote_arg->num_handles; i++) {
 			if (!kcov_check_handle(remote_arg->handles[i],
 						false, true, false)) {
-				spin_unlock_irqrestore(&kcov_remote_lock,
+				raw_spin_unlock_irqrestore(&kcov_remote_lock,
 							flags);
 				kcov_disable(t, kcov);
 				return -EINVAL;
 			}
 			remote = kcov_remote_add(kcov, remote_arg->handles[i]);
 			if (IS_ERR(remote)) {
-				spin_unlock_irqrestore(&kcov_remote_lock,
+				raw_spin_unlock_irqrestore(&kcov_remote_lock,
 							flags);
 				kcov_disable(t, kcov);
 				return PTR_ERR(remote);
@@ -658,7 +658,7 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		if (remote_arg->common_handle) {
 			if (!kcov_check_handle(remote_arg->common_handle,
 						true, false, false)) {
-				spin_unlock_irqrestore(&kcov_remote_lock,
+				raw_spin_unlock_irqrestore(&kcov_remote_lock,
 							flags);
 				kcov_disable(t, kcov);
 				return -EINVAL;
@@ -666,14 +666,14 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			remote = kcov_remote_add(kcov,
 					remote_arg->common_handle);
 			if (IS_ERR(remote)) {
-				spin_unlock_irqrestore(&kcov_remote_lock,
+				raw_spin_unlock_irqrestore(&kcov_remote_lock,
 							flags);
 				kcov_disable(t, kcov);
 				return PTR_ERR(remote);
 			}
 			t->kcov_handle = remote_arg->common_handle;
 		}
-		spin_unlock_irqrestore(&kcov_remote_lock, flags);
+		raw_spin_unlock_irqrestore(&kcov_remote_lock, flags);
 		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
 		kcov_get(kcov);
 		return 0;
@@ -845,10 +845,10 @@ void kcov_remote_start(u64 handle)
 		return;
 	}
 
-	spin_lock(&kcov_remote_lock);
+	raw_spin_lock(&kcov_remote_lock);
 	remote = kcov_remote_find(handle);
 	if (!remote) {
-		spin_unlock_irqrestore(&kcov_remote_lock, flags);
+		raw_spin_unlock_irqrestore(&kcov_remote_lock, flags);
 		return;
 	}
 	kcov_debug("handle = %llx, context: %s\n", handle,
@@ -869,7 +869,7 @@ void kcov_remote_start(u64 handle)
 		size = CONFIG_KCOV_IRQ_AREA_SIZE;
 		area = this_cpu_ptr(&kcov_percpu_data)->irq_area;
 	}
-	spin_unlock_irqrestore(&kcov_remote_lock, flags);
+	raw_spin_unlock_irqrestore(&kcov_remote_lock, flags);
 
 	/* Can only happen when in_task(). */
 	if (!area) {
@@ -1008,9 +1008,9 @@ void kcov_remote_stop(void)
 	spin_unlock(&kcov->lock);
 
 	if (in_task()) {
-		spin_lock(&kcov_remote_lock);
+		raw_spin_lock(&kcov_remote_lock);
 		kcov_remote_area_put(area, size);
-		spin_unlock(&kcov_remote_lock);
+		raw_spin_unlock(&kcov_remote_lock);
 	}
 
 	local_irq_restore(flags);
-- 
2.31.1



-- 
The United States Coast Guard
Ruining Natural Selection since 1790

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809155909.333073de%40theseus.lan.
