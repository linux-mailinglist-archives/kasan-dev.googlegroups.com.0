Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU4HQCCAMGQEJH7HZDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B0C136697B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 12:52:04 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id y10-20020a05622a004ab029019d4ad3437csf12861288qtw.12
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 03:52:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619002323; cv=pass;
        d=google.com; s=arc-20160816;
        b=lMh08vvf9/WPXNoct8iT20gwRDt/vfWS84WOgLaOG2LH5xB2MugWlSMN9UnWmAAMnr
         ZjdxZukTbEc7jOmVz2tJu2puUSgFjIKq/MMv10Glfe5UDduNfVxT5vHWBHRlqdomWDj0
         yuJKmjNqzROJ27CLEHnLxfH+1DBUHwaJKyIau+CUhMNTbxFkH+15o+g7YEsI705yYCL3
         G5dr82xaN6soGoSpMAjC9uWRD6XmwL6BOxGY+lQuscACJMa/uILNbatRHE51znVWb41U
         49C1IIb8qRH6ohU3IsYTFT/cD/WhQHB0RUOiRJmWq8adPsQejEzjwO/FdfjdidCn6Wqk
         O5VQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fOLWKqXJE6MTBxuzSQ4jxyuEgG05WKbziU7jtaJU+a4=;
        b=kEQvYw0jUZucUNgka4xFCb/JlRE5WeWbtLjGX+op7b7J9TLjdg36mtya2K5We4L+9p
         W53kVWkLyQIfl5He21wmLquN/WM7+ywYvhv60nanCmDTjWDPOpQrlWOS30Z2g9K2oPCH
         zrcqo7iUZAinpZQGsXqUXaLuT1YhQ2K8+atcp6+1IF75Iw353jjvOnhTklXapg3+Ik7Y
         RiQ65UgasE/Tvh1hfzrT294AvVC3OzfLWWkl7d4FRpjsQBiqrcjJgYheh+34EGG24o4U
         0LUmfxhemhXyHpbIwLNLeqMNdT4r6/mtf86k1kLOxh9wIwyXlzVvZujbcPW4USnm5+9c
         HHOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kZCrucRD;
       spf=pass (google.com: domain of 30goayaukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=30gOAYAUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fOLWKqXJE6MTBxuzSQ4jxyuEgG05WKbziU7jtaJU+a4=;
        b=IqE7FA/akaI7RFtYdtWfcMsRYGmtTZjpSkSpdSQEah7T89gW+HXnEs177VeHNd3DKn
         wdA2/xTwR2LafRzV9vD4ntj2GD06LRw5c2VMNcuu4oxPeZV6B2WWTV3ZDf/QR8Sy03Yr
         t6gBaAmHhMxCczHND5is4Ylluic8m3rLG2M17eJmC8CpgzzVSDBa8fsT/Dbv7Uo2n1/T
         RnJOIuYj61tsa04kXt9AclidluV3gZybBWflMgdybADX2R6c+LgpCtwWJ2JsQuS+iUVA
         IFLBnFajhz/NsqnzC4Dsc4YqLcNzEZkurZTLxSYCljwD9KG7SFh/wpC/0Q2MWcAu8v25
         BQSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fOLWKqXJE6MTBxuzSQ4jxyuEgG05WKbziU7jtaJU+a4=;
        b=tQ+ZAznTCFmjBuicUB2pU984QsqqMxMPW79pOdDB/BinRRaYLJSzjb+DWDhwaP3XIx
         4WW7ShS7SeN205tArXxW5DVjxxxwNM5alFIUSi+cADBbbStE3/9UUxZQwbFrVFtpUKGU
         HRIJiZBRJDo7tJQVyQJFFuMSjl+THFN3Q+//QhU42W7O5ub9pmAYVrWE7ElZ0kKKpgsd
         8PSFYmoQrg/BnC7TbPBIkBCF88j3TxGlUQIyluFXje9GyQ1fETPIc7K05pLl+ITORoA5
         iYLqvg91EdHk5DiEHr1lHBo3yeNl/CZ1mOOtF3fyWrpzLrQ8ok9jN/8yZO/jGvctExbT
         9/Qg==
X-Gm-Message-State: AOAM532lRXCmFfjLA/2XTNMbKszJaHo+Spn1yM/dos0ZmsO3T4VzZkrn
	//88Epz+g0JqKgq4bukJC2o=
X-Google-Smtp-Source: ABdhPJzcas+X/uPhk+oEd2fILG18o9H26caj/+zj/0nN00Cb7R5+ztrdtYAmh5Th4R7tcGLf1nedNA==
X-Received: by 2002:a05:620a:39a:: with SMTP id q26mr5690535qkm.337.1619002323281;
        Wed, 21 Apr 2021 03:52:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5810:: with SMTP id g16ls812439qtg.11.gmail; Wed, 21 Apr
 2021 03:52:02 -0700 (PDT)
X-Received: by 2002:ac8:1192:: with SMTP id d18mr20915749qtj.253.1619002322883;
        Wed, 21 Apr 2021 03:52:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619002322; cv=none;
        d=google.com; s=arc-20160816;
        b=TOvkJvv2fEtaNc4x93zlU9iTXkXwkg20jmXcOHdHdV8a0qyiX0v6o+O8DcNILf0OOg
         dYI94e4I1+1Jjb20X91hfYfDZVRqAtDzDmXzVtIrr9WXODKZy+FA+YXaSXWE6YMExjeP
         CsrLTTq+13k2v8sjl2sGif4tKFobAhL1UbiCALcviYjnEJ8vdfbYpeBaj/9uaRR71Ko7
         eK8PvoaXHXaAnqv+b+BPiA8UuY6VEwMBgzH7VLLvi+jitXevvIK5AEci4Vs1Oof0EBQX
         14Y7yUYXd/NYuA7WWKh61ackJ/1+0JFwXUxW0nHqT8rSBy/wKygiJsofTJq/JHA9wzgf
         lW2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=OxgBhA98k3tGthKxuSN/4brjg9G3Dacp3flVNK8rvYo=;
        b=GHAiSxb7FPiLUHEbm+3OC4exFp7Heo3O83VqxE1Ew30J0H/s/uIwu/g7Ar2k/JF57I
         knuh1X57rIVs3fUT57DUjVJazYWO9D81/VYQ1hFjRkR+T7X/62RaNSu1y5BECJIt5NVk
         /f21QWJfvGS4X1MBAoZTEOnIvwOxaWpxj8LcUi+xB+LATaB1gDGewlHUuJjbDTNsaf4z
         qQ9KShiojeomRqntoF9sigEb62A1t4RBZ8moZqv5Ggyg0ZlectgAUyF1cwr+J3rFguIz
         DsYKNnmMdLZITxXarJGvWybUJVqjXB9KSkRKco9o98Uk8lCeLR0Vd/FQ3dXzD9yOTSWM
         xd2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kZCrucRD;
       spf=pass (google.com: domain of 30goayaukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=30gOAYAUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id k1si196423qtg.2.2021.04.21.03.52.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 03:52:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30goayaukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id e65-20020a25e7440000b02904ecfeff1ed8so3954868ybh.19
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 03:52:02 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:c552:ee7c:6a14:80cc])
 (user=elver job=sendgmr) by 2002:a25:8b86:: with SMTP id j6mr29548944ybl.470.1619002322474;
 Wed, 21 Apr 2021 03:52:02 -0700 (PDT)
Date: Wed, 21 Apr 2021 12:51:30 +0200
In-Reply-To: <20210421105132.3965998-1-elver@google.com>
Message-Id: <20210421105132.3965998-2-elver@google.com>
Mime-Version: 1.0
References: <20210421105132.3965998-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.368.gbe11c130af-goog
Subject: [PATCH v2 1/3] kfence: await for allocation using wait_event
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kZCrucRD;       spf=pass
 (google.com: domain of 30goayaukcemjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=30gOAYAUKCeMJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

On mostly-idle systems, we have observed that toggle_allocation_gate()
is a cause of frequent wake-ups, preventing an otherwise idle CPU to go
into a lower power state.

A late change in KFENCE's development, due to a potential deadlock [1],
required changing the scheduling-friendly wait_event_timeout() and
wake_up() to an open-coded wait-loop using schedule_timeout().
[1] https://lkml.kernel.org/r/000000000000c0645805b7f982e4@google.com

To avoid unnecessary wake-ups, switch to using wait_event_timeout().

Unfortunately, we still cannot use a version with direct wake_up() in
__kfence_alloc() due to the same potential for deadlock as in [1].
Instead, add a level of indirection via an irq_work that is scheduled if
we determine that the kfence_timer requires a wake_up().

Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Replace kfence_timer_waiting with simpler waitqueue_active() check.
---
 lib/Kconfig.kfence |  1 +
 mm/kfence/core.c   | 45 +++++++++++++++++++++++++++++----------------
 2 files changed, 30 insertions(+), 16 deletions(-)

diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 78f50ccb3b45..e641add33947 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -7,6 +7,7 @@ menuconfig KFENCE
 	bool "KFENCE: low-overhead sampling-based memory safety error detector"
 	depends on HAVE_ARCH_KFENCE && (SLAB || SLUB)
 	select STACKTRACE
+	select IRQ_WORK
 	help
 	  KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
 	  access, use-after-free, and invalid-free errors. KFENCE is designed
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 768dbd58170d..235d726f88bc 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -10,6 +10,7 @@
 #include <linux/atomic.h>
 #include <linux/bug.h>
 #include <linux/debugfs.h>
+#include <linux/irq_work.h>
 #include <linux/kcsan-checks.h>
 #include <linux/kfence.h>
 #include <linux/kmemleak.h>
@@ -587,6 +588,17 @@ late_initcall(kfence_debugfs_init);
 
 /* === Allocation Gate Timer ================================================ */
 
+#ifdef CONFIG_KFENCE_STATIC_KEYS
+/* Wait queue to wake up allocation-gate timer task. */
+static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);
+
+static void wake_up_kfence_timer(struct irq_work *work)
+{
+	wake_up(&allocation_wait);
+}
+static DEFINE_IRQ_WORK(wake_up_kfence_timer_work, wake_up_kfence_timer);
+#endif
+
 /*
  * Set up delayed work, which will enable and disable the static key. We need to
  * use a work queue (rather than a simple timer), since enabling and disabling a
@@ -604,25 +616,13 @@ static void toggle_allocation_gate(struct work_struct *work)
 	if (!READ_ONCE(kfence_enabled))
 		return;
 
-	/* Enable static key, and await allocation to happen. */
 	atomic_set(&kfence_allocation_gate, 0);
 #ifdef CONFIG_KFENCE_STATIC_KEYS
+	/* Enable static key, and await allocation to happen. */
 	static_branch_enable(&kfence_allocation_key);
-	/*
-	 * Await an allocation. Timeout after 1 second, in case the kernel stops
-	 * doing allocations, to avoid stalling this worker task for too long.
-	 */
-	{
-		unsigned long end_wait = jiffies + HZ;
-
-		do {
-			set_current_state(TASK_UNINTERRUPTIBLE);
-			if (atomic_read(&kfence_allocation_gate) != 0)
-				break;
-			schedule_timeout(1);
-		} while (time_before(jiffies, end_wait));
-		__set_current_state(TASK_RUNNING);
-	}
+
+	wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
+
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
 #endif
@@ -729,6 +729,19 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	 */
 	if (atomic_read(&kfence_allocation_gate) || atomic_inc_return(&kfence_allocation_gate) > 1)
 		return NULL;
+#ifdef CONFIG_KFENCE_STATIC_KEYS
+	/*
+	 * waitqueue_active() is fully ordered after the update of
+	 * kfence_allocation_gate per atomic_inc_return().
+	 */
+	if (waitqueue_active(&allocation_wait)) {
+		/*
+		 * Calling wake_up() here may deadlock when allocations happen
+		 * from within timer code. Use an irq_work to defer it.
+		 */
+		irq_work_queue(&wake_up_kfence_timer_work);
+	}
+#endif
 
 	if (!READ_ONCE(kfence_enabled))
 		return NULL;
-- 
2.31.1.368.gbe11c130af-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210421105132.3965998-2-elver%40google.com.
