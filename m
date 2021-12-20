Return-Path: <kasan-dev+bncBCXKTJ63SAARBHN7QKHAMGQE6W52D7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 91BFC47AFE7
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 16:22:06 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id k25-20020a056512331900b004259a8d8090sf2796296lfe.12
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 07:22:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640013726; cv=pass;
        d=google.com; s=arc-20160816;
        b=u3/cIy74sLRhnztp6IZSbzF7Olg7jbzMtJtsOWXrcfMk71z1rwt7umvPrqAzj46vqE
         W6i/rIIXlanVlEasAYIOne61eOk2f52K69Ku8+XYvReKLpnkt4XcIcSfl8hNXg61gEHv
         A1XP+j4y0IW3SHmiJXP1QI4ChQnrDpp0L1d422ctyWttk4ax21tqJTR+Tu0XO5bTbsC5
         J+rCOQfFiBjglHNl/zNbhTkqQT27dj2to3QNo1Q9/v8SZX9S2HBgp4FMj0NT+1bBq1Y1
         xCiRPeYligpt+dth0YZtY7Uy2kVMHKa7q7QeOpDNzDZ8qQoAbAmrpumTeHRDaKRiDr5V
         5xCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=kpyKepGmSdTYEyz59OaAULL7PbRvZQ1FEg2GxdiFC6k=;
        b=beFeXg8Cx1+laK05ZNguZbZR1Fgwtc3vXBW1zbMq1iqsaUPX5VLiSlIRHlxtKrleEU
         0j7FHHU5RhqJimniTQZzjWAzAXkOgNRYgotr3iA12SkIrE0S3Gl5VuPAgHm/8yVnU/0K
         CCgLcTwncAWXaGr8y2qN1+ZGzLRlUBJyElo0LhBf4grWI5BI8ddVuEV9VpiRiFpeUIfi
         JB2Iv/2cuc2pu/nW4QoBGgKdhA5btl/zatBgr4Ce7MtPfolgow4ChTA8JlE1ep6yyQQZ
         JazZNyEg0Z+MmZcNCDhUOjuctb9WMX8QzSdHgKRkT82MsMcp5FYzwXy1vYC76xq/l/nc
         EF6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MtTxOS+N;
       spf=pass (google.com: domain of 3nj_ayqykcfeghzbdazhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nJ_AYQYKCfEghZbdaZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=kpyKepGmSdTYEyz59OaAULL7PbRvZQ1FEg2GxdiFC6k=;
        b=to4mpowwHF4eP0DqbyDp4cdM2DNfINsaFAVP7dqLye6RS8+dUd9rsO8bRsREpTJLOx
         0R2tk20zsE9/KozA7KcYfVzvQbDSRhyTnW8peF9OqSUFs1AH5sql9eVhu/PJCAO7YeYJ
         HYOYwnRvtfKcC1IXXd8BtlA0mJpaiqwMpjlJ73ZLk8ZnfXH8GX2xgxXs44Z2sAg5pgzT
         TO6vvCa4SQ4XDdIBUiB2nOBQDS8rDoZho5M4IaqZnaDFpOMhn4UN8TT2MNqEjdW6Ut/R
         l98VcJufycPtYNkkFNFqLRihT0BgCmITsI5NYcYUW87KPXPsbO9sEEqct/q52STBF9tk
         MgkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kpyKepGmSdTYEyz59OaAULL7PbRvZQ1FEg2GxdiFC6k=;
        b=14laeW6ZEUv+w/f9KqGgvQqUv6R7P1xARrTkDXhUB/Hwt8BZPOF1ZtImTSZOWvmWD1
         l2eLWM8Q7UMbx5TSxZVYyuU3Ej7v1M+Zw2z7RSwBlW6MuEklO31KSn4k8/+Y83x0pcrd
         iewrKc1BDKcWf9Fs0QoNr8bHq8oCquQ/ZfClaSQPv/z5VrZXpAyPU/ZmjHHxBATLmSCF
         E2b3qJpwQghTjTQpSlRKX4kVAdCXxKy5VfDq6n4fbhMrEiTrwhuHdj2gX29acRbVbglR
         SuZYzqS/Ciy3Jn9BpQUy2BR/Eafag141yKcVpcngIQDs8v1ppHlgjNU3UPKCvgfEZ39e
         d4Ug==
X-Gm-Message-State: AOAM530Kc8CQ92jfdvesquri/b9cDmVGF6pgrwZjc3SzUgD49i/pWzpc
	BxQx86XU9OiJtNO5W8lk6F4=
X-Google-Smtp-Source: ABdhPJz1jyA4R/+hT8AlNDujzi4p+678F7o8qT6LiBw69jKEAd3gdd6sp6C0i9drxrMHu21MfHDbFA==
X-Received: by 2002:ac2:4215:: with SMTP id y21mr16170587lfh.526.1640013725997;
        Mon, 20 Dec 2021 07:22:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls161016lfh.3.gmail; Mon, 20 Dec
 2021 07:22:05 -0800 (PST)
X-Received: by 2002:ac2:4e0d:: with SMTP id e13mr16247511lfr.388.1640013724933;
        Mon, 20 Dec 2021 07:22:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640013724; cv=none;
        d=google.com; s=arc-20160816;
        b=uLLi4ZrTqh/8H4xDviwV8jtfkZTpBeKeMUyTriejU/XQTdIpJOmY45FxwyHTbxNlAe
         loenu69N/857fBirSHPnizQCr/iiLd56hWPEQkxZx9DU4SF7aCsI1v6JAfmpXwndBrJl
         aR/3n0qoHY5fjJmGRpNbU7ylGTdSnvzg4Rt/bIuYL0BNix2KRLKxy+MjMOtOrhuh+dDI
         T0ZO1ozlWf2h8SeUilx5g8DtOYmngq3boeA0o7vCmuZMFX005xViJ21mNAUclMC1AxKP
         dtryyZ02NEOTV8o2+NJrFzAjyY1PxNevdO7QL+RguItYQG6Q68hMvGKanBSUbbAWyM46
         cOog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=DGxWEqDmq2iHcedzGdhHTPdO/cXggHy4vSm/RYyxtTI=;
        b=Ec+ttjWIn4kvQEz6gvM0cwHwX3zLqwvqPmC/hFrBxLYf0qRzqyvONv3jdXA2QVmzbF
         wXDKdGafgjc71aOhTl4wNeMaWkdDo7vD/1oEptG64tc7iH4bbR00A+TSNSA4JkJE+vc3
         x4bwyGPTuRhvblIE8KeCT9+Zr9Npp71dpX2HVInBpr6x6S4dlIOuz/5PpwsJwipUTOQ5
         mlzdopHxIO1vbk89bwpQXWKQMgMKz4yJClDo+gI7IQZtHfFAwbbUNRg6QUgJu4LiF7Ms
         bpJvtW34PL8vFOTemGrKgvpw3NqeeadYo18HWyfLaZxPyB/0HrnwaDqx8/2OMgaq7g/t
         4iDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MtTxOS+N;
       spf=pass (google.com: domain of 3nj_ayqykcfeghzbdazhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nJ_AYQYKCfEghZbdaZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id c12si830578ljf.4.2021.12.20.07.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 07:22:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nj_ayqykcfeghzbdazhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id ch27-20020a0564021bdb00b003f8389236f8so4034825edb.19
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 07:22:04 -0800 (PST)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a17:907:6e11:: with SMTP id
 sd17mr6030459ejc.143.1640013724229; Mon, 20 Dec 2021 07:22:04 -0800 (PST)
Date: Mon, 20 Dec 2021 15:21:53 +0000
Message-Id: <20211220152153.910990-1-nogikh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.1.173.g76aa8bc2d0-goog
Subject: [PATCH] kcov: properly handle subsequent mmap calls
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MtTxOS+N;       spf=pass
 (google.com: domain of 3nj_ayqykcfeghzbdazhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3nJ_AYQYKCfEghZbdaZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Subsequent mmaps of the same kcov descriptor currently do not update the
virtual memory of the task and yet return 0 (success). This is
counter-intuitive and may lead to unexpected memory access errors.

Also, this unnecessarily limits the functionality of kcov to only the
simplest usage scenarios. Kcov instances are effectively forever attached
to their first address spaces and it becomes impossible to e.g. reuse the
same kcov handle in forked child processes without mmapping the memory
first. This is exactly what we tried to do in syzkaller and
inadvertently came upon this problem.

Allocate the buffer during KCOV_MODE_INIT in order to untie mmap and
coverage collection. Modify kcov_mmap, so that it can be reliably used
any number of times once KCOV_MODE_INIT has succeeded.

Refactor ioctl processing so that a vmalloc could be executed before the
spin lock is obtained.

These changes to the user-facing interface of the tool only weaken the
preconditions, so all existing user space code should remain compatible
with the new version.

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
---
 kernel/kcov.c | 94 +++++++++++++++++++++++++++++----------------------
 1 file changed, 53 insertions(+), 41 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 36ca640c4f8e..49e1fa2b330f 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -459,37 +459,28 @@ void kcov_task_exit(struct task_struct *t)
 static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 {
 	int res = 0;
-	void *area;
 	struct kcov *kcov = vma->vm_file->private_data;
 	unsigned long size, off;
 	struct page *page;
 	unsigned long flags;
 
-	area = vmalloc_user(vma->vm_end - vma->vm_start);
-	if (!area)
-		return -ENOMEM;
-
 	spin_lock_irqsave(&kcov->lock, flags);
 	size = kcov->size * sizeof(unsigned long);
-	if (kcov->mode != KCOV_MODE_INIT || vma->vm_pgoff != 0 ||
+	if (kcov->area == NULL || vma->vm_pgoff != 0 ||
 	    vma->vm_end - vma->vm_start != size) {
 		res = -EINVAL;
 		goto exit;
 	}
-	if (!kcov->area) {
-		kcov->area = area;
-		vma->vm_flags |= VM_DONTEXPAND;
-		spin_unlock_irqrestore(&kcov->lock, flags);
-		for (off = 0; off < size; off += PAGE_SIZE) {
-			page = vmalloc_to_page(kcov->area + off);
-			if (vm_insert_page(vma, vma->vm_start + off, page))
-				WARN_ONCE(1, "vm_insert_page() failed");
-		}
-		return 0;
+	spin_unlock_irqrestore(&kcov->lock, flags);
+	vma->vm_flags |= VM_DONTEXPAND;
+	for (off = 0; off < size; off += PAGE_SIZE) {
+		page = vmalloc_to_page(kcov->area + off);
+		if (vm_insert_page(vma, vma->vm_start + off, page))
+			WARN_ONCE(1, "vm_insert_page() failed");
 	}
+	return 0;
 exit:
 	spin_unlock_irqrestore(&kcov->lock, flags);
-	vfree(area);
 	return res;
 }
 
@@ -564,31 +555,13 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			     unsigned long arg)
 {
 	struct task_struct *t;
-	unsigned long size, unused;
+	unsigned long unused;
 	int mode, i;
 	struct kcov_remote_arg *remote_arg;
 	struct kcov_remote *remote;
 	unsigned long flags;
 
 	switch (cmd) {
-	case KCOV_INIT_TRACE:
-		/*
-		 * Enable kcov in trace mode and setup buffer size.
-		 * Must happen before anything else.
-		 */
-		if (kcov->mode != KCOV_MODE_DISABLED)
-			return -EBUSY;
-		/*
-		 * Size must be at least 2 to hold current position and one PC.
-		 * Later we allocate size * sizeof(unsigned long) memory,
-		 * that must not overflow.
-		 */
-		size = arg;
-		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
-			return -EINVAL;
-		kcov->size = size;
-		kcov->mode = KCOV_MODE_INIT;
-		return 0;
 	case KCOV_ENABLE:
 		/*
 		 * Enable coverage for the current task.
@@ -685,6 +658,49 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 	}
 }
 
+static int kcov_ioctl_unlocked(struct kcov *kcov, unsigned int cmd,
+			     unsigned long arg)
+{
+	unsigned long size, flags;
+	void *area;
+	int res;
+
+	switch (cmd) {
+	case KCOV_INIT_TRACE:
+		/*
+		 * Enable kcov in trace mode and setup buffer size.
+		 * Must happen before anything else.
+		 *
+		 *
+		 * Size must be at least 2 to hold current position and one PC.
+		 */
+		size = arg;
+		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
+			return -EINVAL;
+
+		area = vmalloc_user(size * sizeof(unsigned long));
+		if (area == NULL)
+			return -ENOMEM;
+
+		spin_lock_irqsave(&kcov->lock, flags);
+		if (kcov->mode != KCOV_MODE_DISABLED) {
+			spin_unlock_irqrestore(&kcov->lock, flags);
+			vfree(area);
+			return -EBUSY;
+		}
+		kcov->area = area;
+		kcov->size = size;
+		kcov->mode = KCOV_MODE_INIT;
+		spin_unlock_irqrestore(&kcov->lock, flags);
+		return 0;
+	default:
+		spin_lock_irqsave(&kcov->lock, flags);
+		res = kcov_ioctl_locked(kcov, cmd, arg);
+		spin_unlock_irqrestore(&kcov->lock, flags);
+		return res;
+	}
+}
+
 static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 {
 	struct kcov *kcov;
@@ -692,7 +708,6 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 	struct kcov_remote_arg *remote_arg = NULL;
 	unsigned int remote_num_handles;
 	unsigned long remote_arg_size;
-	unsigned long flags;
 
 	if (cmd == KCOV_REMOTE_ENABLE) {
 		if (get_user(remote_num_handles, (unsigned __user *)(arg +
@@ -713,10 +728,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 	}
 
 	kcov = filep->private_data;
-	spin_lock_irqsave(&kcov->lock, flags);
-	res = kcov_ioctl_locked(kcov, cmd, arg);
-	spin_unlock_irqrestore(&kcov->lock, flags);
-
+	res = kcov_ioctl_unlocked(kcov, cmd, arg);
 	kfree(remote_arg);
 
 	return res;
-- 
2.34.1.173.g76aa8bc2d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211220152153.910990-1-nogikh%40google.com.
