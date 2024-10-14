Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBW4WS4AMGQECBEVFCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 792F899CE63
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 16:43:20 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-43117570814sf24036955e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 07:43:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728917000; cv=pass;
        d=google.com; s=arc-20240605;
        b=NZSpH6nq06bqYKsG2TAReGN3esTrdGLsNpZtRVNTlqv3sl4IFPQonjT7OI8mW17nDr
         MAQEc+7zcITPzyCHLe0UMhcLj0AKHHgepHjXOjg21wG/8SnWsglnUUH4nnIinU2Z418g
         IWn+oy1slbWPwytI9tZgiXmu0leZgW8PIYQ9iSJDqiwq0RZPft35Bfv8BXl+xk/ayMB3
         AiaIlfo52bWnxg6rlV5cDnbmEskRevaCVZhlZbd0L3WUfKnoyfaulD6sGeOdxV+M2LK+
         phKFw4RjsXRVRrFCbU/O4cee8G491d9nI6Ia8LtYpHRrHtWkj97h2IXO6UfhcRByg7ID
         5sYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=QXMMYcHKNkkCx1isyjTzNB7/DIZnIlp+lr1MBF/Zd+E=;
        fh=FgvTCDwJwL/2c8iS+InFLKRhkwDjq1ZKN6Fh9H1JQ4Y=;
        b=epBY/sV3I1g0mjgDMOMkdHajYtrreb+gugON/+JjKo65Xf2rJ4pxKloyzhsK73ztJ9
         4EQv1Iq9ZgGT0/S9XDf86lsdwJ+3QQ8sUcq8aXR+kDo7cVeAcSNI/s5SFLe16S2WoY8T
         0jPr58Mx+1jX+hk/u8pbuRkYSHDUQSx9he4ElWHckOaGECoeri9zrUUa2vVEQGc+Xc1J
         wziwkwYeuGekwj/uo6WC271uwp04wQKw6Sw69CCijr/fkz1819bAXQwWRG3b6TvHSBF/
         etvbpMENURciHGoFqMhvAdzOqHdU2VY1/RF41GurvcbV6plnkl88zAOqXpdkPn2DYon5
         uoiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jfRkEzFS;
       spf=pass (google.com: domain of 3ay4nzwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Ay4NZwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728917000; x=1729521800; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QXMMYcHKNkkCx1isyjTzNB7/DIZnIlp+lr1MBF/Zd+E=;
        b=Hyd4sSkL3a9Y5Nc9MMl3L7rfIlLZekI3fMVLpIipaF3NTivG0jnem9Xam42y13gwyf
         w8kcCBxgNwRfa7n7i9zMH2272kBx0i8OswAtmO5T/qGTlQ0dkoxWeQQswibkFa9RDlSh
         QmeyXey0Mn+Hgn+b5zHL3bDjHvwFVlhGyW6O+2s7nP2TwR/NTp5ytyLN8Ok2IaXYILxE
         F/dDiH4ui33ILV2znZvQ3ixI0g2dRvk/8ZcR2XiqW/NjBd3XDI4sPdGCY71sNtYvpcH6
         EhIErwrJcA8BaMtFnscIrd+h95AxVO2/Amnamg6c/YCdaLy8OZ8msnpLVnpFFPr4oH5p
         D1IQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728917000; x=1729521800;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QXMMYcHKNkkCx1isyjTzNB7/DIZnIlp+lr1MBF/Zd+E=;
        b=whNRAD/lqg68h74nJrAuoj8l1kluNY60LK98eBUNb/Ma4NgL7fGbT6rHUyXps7eUtE
         bdtwlmVYLBFmJnFkC+0Ie2ZKpia3nqc6xK4FVZPJTsPFCJj5pm5Z640ILBy/fEHsHnLr
         iCYJFBLDlUaP5dGuV9hdbNqRz3N+eKouk47+DH6Omo91F9j3CBn/77olg1qk34B0dlsP
         6dA4orP/Subp0QaEoTXRLuZyvdYgkxBE788zNmEaNVAskTiB63PXBTaVoU7lzYcqqIbE
         Ix0YQrZvc95nRhpwse9+dU9bvb9ZX5kGBZY1yklx/+RNBtv1Jiw+L6K0gcFpErL09JZQ
         lrlw==
X-Forwarded-Encrypted: i=2; AJvYcCWOBEcxQhuloxws1q4LnsPdtxrMvEALmAncxraXKquEt5EnCBv5M4m3CrTmAf3qnZn6k++tdw==@lfdr.de
X-Gm-Message-State: AOJu0YxDaeTrJEkcThhOC2jkstQFoz/hJqitg1GAjIuvoQWnT77cqa0h
	4zTnCwVF/X79LPzxES4mYPf687WT+BwIjq6Bp7YFpYvTmdLOuHit
X-Google-Smtp-Source: AGHT+IFoMOb+jR67tX4cVaSWyerar/yPUkysuCxdY5Mshdx27J4NopQZoqEjB0+Lq6LTBELelvFuoQ==
X-Received: by 2002:a05:600c:c15:b0:426:5440:8541 with SMTP id 5b1f17b1804b1-43125609710mr61440005e9.27.1728916998658;
        Mon, 14 Oct 2024 07:43:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8a:b0:430:5356:aca3 with SMTP id
 5b1f17b1804b1-43115efbeafls16272445e9.0.-pod-prod-06-eu; Mon, 14 Oct 2024
 07:43:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9yM0KvJ6e1nxHltB1poCDt6F+gsnOHh0refHYUyPca8gBogz3Oxi1GnrahWFnNNUNDERSHZjFguc=@googlegroups.com
X-Received: by 2002:a05:600c:8714:b0:426:6326:4cec with SMTP id 5b1f17b1804b1-431256199cdmr73260945e9.29.1728916996294;
        Mon, 14 Oct 2024 07:43:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728916996; cv=none;
        d=google.com; s=arc-20240605;
        b=eUcgN24+U2seHGN9lRrTWlD/oc/XfQwMaqhb2dLDzUA1rFrGJ7YlmH1NLfKUOV4U3Q
         NRSPRGPP5TVf1ynZC7i1vdc7VRFvjoSjDiQgD/igNbMwmJc45ayvFf80J3u9lUc1+Jo0
         9PtR4tVQPZThqYyGzOpRMIx+gkgCrQSFmGmMK/Xvsxfzv3hITzLPLUwI/0GeWvmEvoAm
         z3/7v1K8gjXK/8hMv8i2VFUKybmp9zPrfRQsAFlOdL7A+i/D3K6eO3P7aNFNjxbLjPu6
         QG/+hq8+TOVE7acsmTOw9uhSgZ2kql3MD712HgxP6Mr9CP82g+T1gZaZ2E48tGetYOue
         fAVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=YAANA2HCjAYrDp100j/+RFsOVPjXu6D4EaWrswZHDqg=;
        fh=u3jE0edevZz9gsW6Mki2cLUwyyB0Fk+JaYiE4DztMok=;
        b=hlVmtDuKCbfeKisvT8j6YhDxUPGOnAsVKxPOB5IWsHV+nGJqqjNrqi3dUMgT150j0B
         sXNmn2dXa2ekJhZT6Nb3ZAsZmdWGjmUg3a9nkU75miJKlsckPYfWu4+at9WLTe16JOvE
         w5hZ4YG5pg9UlGTfbW/4i5UovAShgvYTWHP4EXKdUIV33ybMllQWLsrjci9AQz4pTKAh
         lu4n7yUtAgIrMEIhzMr7bBjhnJSIP7XhMZFcyVM/wINCcETaNO2M955a0T2UEgg7Ejgd
         mEswmenHfP8UDineXwGLd53X25n2NOOK5tqwFabyLu4No+a4KOYK1XPNnZEjs+0RD6pV
         f9PQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jfRkEzFS;
       spf=pass (google.com: domain of 3ay4nzwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Ay4NZwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4304ed0f679si9572295e9.1.2024.10.14.07.43.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 07:43:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ay4nzwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-5c930ca5d12so4802280a12.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 07:43:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXibx5oLax6gM2OEYk7phgEeeV8yOFmFEF0M8Qij5Vl85+yarBvbhEBa/XE0e73r+qW1wUH1w4silA=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:9a7c:c6fa:d24e:a813])
 (user=elver job=sendgmr) by 2002:a05:6402:1e96:b0:5c7:20c1:1ce with SMTP id
 4fb4d7f45d1cf-5c9475dba4cmr5899a12.2.1728916995470; Mon, 14 Oct 2024 07:43:15
 -0700 (PDT)
Date: Mon, 14 Oct 2024 16:42:52 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.47.0.rc1.288.g06298d1525-goog
Message-ID: <20241014144300.3182961-1-elver@google.com>
Subject: [PATCH 1/2] kcsan: Turn report_filterlist_lock into a raw_spinlock
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Ran Xiaokai <ran.xiaokai@zte.com.cn>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jfRkEzFS;       spf=pass
 (google.com: domain of 3ay4nzwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Ay4NZwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

Ran Xiaokai reports that with a KCSAN-enabled PREEMPT_RT kernel, we can see
splats like:

| BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
| in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 0, name: swapper/1
| preempt_count: 10002, expected: 0
| RCU nest depth: 0, expected: 0
| no locks held by swapper/1/0.
| irq event stamp: 156674
| hardirqs last  enabled at (156673): [<ffffffff81130bd9>] do_idle+0x1f9/0x240
| hardirqs last disabled at (156674): [<ffffffff82254f84>] sysvec_apic_timer_interrupt+0x14/0xc0
| softirqs last  enabled at (0): [<ffffffff81099f47>] copy_process+0xfc7/0x4b60
| softirqs last disabled at (0): [<0000000000000000>] 0x0
| Preemption disabled at:
| [<ffffffff814a3e2a>] paint_ptr+0x2a/0x90
| CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Not tainted 6.11.0+ #3
| Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.12.0-0-ga698c8995f-prebuilt.qemu.org 04/01/2014
| Call Trace:
|  <IRQ>
|  dump_stack_lvl+0x7e/0xc0
|  dump_stack+0x1d/0x30
|  __might_resched+0x1a2/0x270
|  rt_spin_lock+0x68/0x170
|  kcsan_skip_report_debugfs+0x43/0xe0
|  print_report+0xb5/0x590
|  kcsan_report_known_origin+0x1b1/0x1d0
|  kcsan_setup_watchpoint+0x348/0x650
|  __tsan_unaligned_write1+0x16d/0x1d0
|  hrtimer_interrupt+0x3d6/0x430
|  __sysvec_apic_timer_interrupt+0xe8/0x3a0
|  sysvec_apic_timer_interrupt+0x97/0xc0
|  </IRQ>

On a detected data race, KCSAN's reporting logic checks if it should
filter the report. That list is protected by the report_filterlist_lock
*non-raw* spinlock which may sleep on RT kernels.

Since KCSAN may report data races in any context, convert it to a
raw_spinlock.

This requires being careful about when to allocate memory for the filter
list itself which can be done via KCSAN's debugfs interface. Concurrent
modification of the filter list via debugfs should be rare: the chosen
strategy is to optimistically pre-allocate memory before the critical
section and discard if unused.

Link: https://lore.kernel.org/all/20240925143154.2322926-1-ranxiaokai627@163.com/
Reported-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c | 74 ++++++++++++++++++++----------------------
 1 file changed, 36 insertions(+), 38 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 53b21ae30e00..b14072071889 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -46,14 +46,8 @@ static struct {
 	int		used;		/* number of elements used */
 	bool		sorted;		/* if elements are sorted */
 	bool		whitelist;	/* if list is a blacklist or whitelist */
-} report_filterlist = {
-	.addrs		= NULL,
-	.size		= 8,		/* small initial size */
-	.used		= 0,
-	.sorted		= false,
-	.whitelist	= false,	/* default is blacklist */
-};
-static DEFINE_SPINLOCK(report_filterlist_lock);
+} report_filterlist;
+static DEFINE_RAW_SPINLOCK(report_filterlist_lock);
 
 /*
  * The microbenchmark allows benchmarking KCSAN core runtime only. To run
@@ -110,7 +104,7 @@ bool kcsan_skip_report_debugfs(unsigned long func_addr)
 		return false;
 	func_addr -= offset; /* Get function start */
 
-	spin_lock_irqsave(&report_filterlist_lock, flags);
+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
 	if (report_filterlist.used == 0)
 		goto out;
 
@@ -127,7 +121,7 @@ bool kcsan_skip_report_debugfs(unsigned long func_addr)
 		ret = !ret;
 
 out:
-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
 	return ret;
 }
 
@@ -135,9 +129,9 @@ static void set_report_filterlist_whitelist(bool whitelist)
 {
 	unsigned long flags;
 
-	spin_lock_irqsave(&report_filterlist_lock, flags);
+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
 	report_filterlist.whitelist = whitelist;
-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
 }
 
 /* Returns 0 on success, error-code otherwise. */
@@ -145,6 +139,9 @@ static ssize_t insert_report_filterlist(const char *func)
 {
 	unsigned long flags;
 	unsigned long addr = kallsyms_lookup_name(func);
+	unsigned long *delay_free = NULL;
+	unsigned long *new_addrs = NULL;
+	size_t new_size = 0;
 	ssize_t ret = 0;
 
 	if (!addr) {
@@ -152,32 +149,33 @@ static ssize_t insert_report_filterlist(const char *func)
 		return -ENOENT;
 	}
 
-	spin_lock_irqsave(&report_filterlist_lock, flags);
+retry_alloc:
+	/*
+	 * Check if we need an allocation, and re-validate under the lock. Since
+	 * the report_filterlist_lock is a raw, cannot allocate under the lock.
+	 */
+	if (data_race(report_filterlist.used == report_filterlist.size)) {
+		new_size = (report_filterlist.size ?: 4) * 2;
+		delay_free = new_addrs = kmalloc_array(new_size, sizeof(unsigned long), GFP_KERNEL);
+		if (!new_addrs)
+			return -ENOMEM;
+	}
 
-	if (report_filterlist.addrs == NULL) {
-		/* initial allocation */
-		report_filterlist.addrs =
-			kmalloc_array(report_filterlist.size,
-				      sizeof(unsigned long), GFP_ATOMIC);
-		if (report_filterlist.addrs == NULL) {
-			ret = -ENOMEM;
-			goto out;
-		}
-	} else if (report_filterlist.used == report_filterlist.size) {
-		/* resize filterlist */
-		size_t new_size = report_filterlist.size * 2;
-		unsigned long *new_addrs =
-			krealloc(report_filterlist.addrs,
-				 new_size * sizeof(unsigned long), GFP_ATOMIC);
-
-		if (new_addrs == NULL) {
-			/* leave filterlist itself untouched */
-			ret = -ENOMEM;
-			goto out;
+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
+	if (report_filterlist.used == report_filterlist.size) {
+		/* Check we pre-allocated enough, and retry if not. */
+		if (report_filterlist.used >= new_size) {
+			raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
+			kfree(new_addrs); /* kfree(NULL) is safe */
+			delay_free = new_addrs = NULL;
+			goto retry_alloc;
 		}
 
+		if (report_filterlist.used)
+			memcpy(new_addrs, report_filterlist.addrs, report_filterlist.used * sizeof(unsigned long));
+		delay_free = report_filterlist.addrs; /* free the old list */
+		report_filterlist.addrs = new_addrs;  /* switch to the new list */
 		report_filterlist.size = new_size;
-		report_filterlist.addrs = new_addrs;
 	}
 
 	/* Note: deduplicating should be done in userspace. */
@@ -185,9 +183,9 @@ static ssize_t insert_report_filterlist(const char *func)
 		kallsyms_lookup_name(func);
 	report_filterlist.sorted = false;
 
-out:
-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
 
+	kfree(delay_free);
 	return ret;
 }
 
@@ -204,13 +202,13 @@ static int show_info(struct seq_file *file, void *v)
 	}
 
 	/* show filter functions, and filter type */
-	spin_lock_irqsave(&report_filterlist_lock, flags);
+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
 	seq_printf(file, "\n%s functions: %s\n",
 		   report_filterlist.whitelist ? "whitelisted" : "blacklisted",
 		   report_filterlist.used == 0 ? "none" : "");
 	for (i = 0; i < report_filterlist.used; ++i)
 		seq_printf(file, " %ps\n", (void *)report_filterlist.addrs[i]);
-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
 
 	return 0;
 }
-- 
2.47.0.rc1.288.g06298d1525-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014144300.3182961-1-elver%40google.com.
