Return-Path: <kasan-dev+bncBCXKTJ63SAARBG42S2HQMGQEBD233KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BD677490B80
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jan 2022 16:36:59 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id o3-20020a05600c4fc300b0034aee9534bdsf4556780wmq.2
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jan 2022 07:36:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1642433819; cv=pass;
        d=google.com; s=arc-20160816;
        b=qp1m/fu7kSwK6u+wLCXE4oLgpDeg0cc3c5iHw8svgIuR5tpi7/AzqZgMcaCi79UuxV
         acUptBDX2ZkCLS3XeG2LFmNOZwC0XoI0ldLtBodOkjqakQQE2B5QL3J6RIw0XUakz+N4
         hk45Btgc2+sG1jrqtZCqb0RS1Pg1MIonONNtTGRvPLBhBiAoKC+G/NaSVnJ/kVK2I75/
         Za/ZQG9RWcIWqyjFFlsJx8Dqo53taA/+6nXV+4gPNz+SnKMKkMCeVfbj4n8rEUvEeLA+
         Hw0kd3RtS1VaO03+rxp2PFe+aJW2ixbHlo3G9lTi2i2kXKZFs1H/176H0cQ0QNo1pxFm
         M8RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=HcX7f0YXl2UUvX/dpaoRXvMKBYUEaita5jc5g+Q1Szw=;
        b=HpN2EPcGUEdllGCXl4Vl+OKjD7SZU+lTeBOA3zleQYBkTs6iubyDmL0CtbyXEg742w
         d7wmSV3543BV5iqmGT74Si1DYtQuCBfSXcR3oBRTZEVkXOgF+lGemxcYYcEBe6lwCoD0
         /Nf+w/57+ZULGvdaywIljZtQGINILTyoMhQK6Ol4o7YCWD/78ivBG6zPxu7k8l7RTYuA
         cACSG7roHcW+Q7Js9NZJ5Kp9iJXhTlA4LrjkbYoWykDto6kwO23X5aQqaoPYyslJpNTN
         S/nl/nbHe00D2gIyEvsHvPE/IN680up48JbgI5nlOPyYXuNIglscFeKX2+yjpXmk/FWo
         NYZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gGqm3c74;
       spf=pass (google.com: domain of 3gy3lyqykcd4nogikhgoogle.comkasan-devgooglegroups.com@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GY3lYQYKCd4NOGIKHGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HcX7f0YXl2UUvX/dpaoRXvMKBYUEaita5jc5g+Q1Szw=;
        b=CHBKOPfRM0hZJS8mAg/g/fFvbsbbgug52NsfTq6s5zGaB3BTy3Z0fhAs33SE47qb3i
         yo13SHE4h6L8CgUFwvtmm/ZUr8mWEb9is9dPxoRuS7pCS+fha2UIYjMq9Bm3ZnB25/9V
         oyLwKNUdB+kOmhcvx3aS2XvrJ4MRK+DTij3877BeBopGsDwjFBi9HU2LUcjqtIEeJvrz
         NwIbA1+IjhpRezZk9gHCOLy7QiSct7Z4G72FvT4uApnyV5tP4anQUFqZgqidlkR/0Qtk
         9aeyRBCnR8RNHzBN3hJpL0EOahMGaz5MHnw5j3ww06WSAEDfmM1RNYErF+Tqsbyqq0UU
         Cj9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HcX7f0YXl2UUvX/dpaoRXvMKBYUEaita5jc5g+Q1Szw=;
        b=CegDVmdLhsOK0VSajuJCBjQkSKXqn+IFDhHCk+sAE61v9NOxHnpwIa3TJWBwq9Iua0
         bZAiXe2buxyYkFHSLfFzU8s7zFqZlmbbF9rIBy+4bAkC0nJqxxuOI5eBAcqsG/OxJAfT
         iJBxRGuJjNzOckiKp2WsSx0kFxebRkzoyd6NFUZJ88wjs2BRj/oLy/hh9mX5XF+rpIKJ
         wNQ5HYd7UN+75xdW7i6fmRFidNyK1qqS2yDwbu9eEY8zxOKqQpOirtdvNsyFYQ3KQtLe
         d6UaVrKzF8EkCde+/Vo0Gxz8QnZIfy/tj2AfdoH4DewWygxMjQyj7rD4TVUkLWPClViI
         VRlA==
X-Gm-Message-State: AOAM530ZjAIfZOIVAV7kQS5XobW41LCGQ57C9GWkp8xDOc0SWxqWiu1F
	hvmQbt6CTSNzpolXLaf3DQA=
X-Google-Smtp-Source: ABdhPJxN7+Ps5EXsvv4Xi35KHe3wQc2LGrnMaMzXS5f7jXivh/Af45BEfjqEZ+D8cJefAJLZt8UeIQ==
X-Received: by 2002:adf:eec9:: with SMTP id a9mr19530394wrp.178.1642433819351;
        Mon, 17 Jan 2022 07:36:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:97ca:: with SMTP id t10ls1308071wrb.2.gmail; Mon, 17 Jan
 2022 07:36:58 -0800 (PST)
X-Received: by 2002:adf:fc11:: with SMTP id i17mr20415806wrr.179.1642433818491;
        Mon, 17 Jan 2022 07:36:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1642433818; cv=none;
        d=google.com; s=arc-20160816;
        b=JsQjwkgdk9P85qensDV4XeJJqFgTnHpOd6u53uPXVDy/QiINMvFjEQlGdoJ9j+oFdm
         FOAPZQMUBKjy/GmTMGtM/a11Umr8rwiQR/J746/PYpv+R39fzjHNvvby2tbSSWyP87tO
         5K+m3z4Zkk3y8puAJyjVFvnFyOyayY4aQGeBOEqvX79+W5OcpQdkEJjnFgj0gmxANU6L
         h6y3hZIaIqXN1NueaadY84/WUI0T/Bcu0S09tBweswIb1oDnSpXH8UnDD0ixTreNXN6o
         T7jv+nECCVS4RiPoL/Q0ZI+UTxxdoAdi1NRPr17QIMeEDcC9xgpp8A5eGnAhygyP7c0I
         1JdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7DEaDOOzB1jAF1TPQvu7T4yVYcqfdELQFZk+rb6P+EE=;
        b=F+HxbCmHj0zUXma9eOVXbOZRomw4lPMlM3+B0DrT/20jpUROI3udIshn1P11B46SiG
         2K//pfIZqe7kGByZGo9T5T3DB3l3JE+P4l6Uk+D27J53ShDqjFSWPD7vsZ0KfHiFsKaf
         0QwWk4Q0MPna/vxYFg5HCG1fVHRnnw8u/BhqT0o0m71CdaHaqGKKJm77YOTGS60+IR1d
         q0xZ7pbIhJW5jj7fDu3+qAKX/uszKarS9Yj9+A7pfX0MVKMm4DKvUJeITKW2+1p5KIYU
         OzTVxeOgXJo5B7zbbQKXtNENcyRDeSY9lYRVSPSUr8eihnWHXHxwXpfFhZUQXoOKLo8R
         bb1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gGqm3c74;
       spf=pass (google.com: domain of 3gy3lyqykcd4nogikhgoogle.comkasan-devgooglegroups.com@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GY3lYQYKCd4NOGIKHGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--nogikh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v18si105585wri.1.2022.01.17.07.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Jan 2022 07:36:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gy3lyqykcd4nogikhgoogle.comkasan-devgooglegroups.com@flex--nogikh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id w5-20020a1cf605000000b0034b8cb1f55eso5190094wmc.0
        for <kasan-dev@googlegroups.com>; Mon, 17 Jan 2022 07:36:58 -0800 (PST)
X-Received: from nogikh-hp.c.googlers.com ([fda3:e722:ac3:cc00:28:9cb1:c0a8:200d])
 (user=nogikh job=sendgmr) by 2002:a05:600c:1908:: with SMTP id
 j8mr6340226wmq.155.1642433817868; Mon, 17 Jan 2022 07:36:57 -0800 (PST)
Date: Mon, 17 Jan 2022 15:36:33 +0000
In-Reply-To: <20220117153634.150357-1-nogikh@google.com>
Message-Id: <20220117153634.150357-2-nogikh@google.com>
Mime-Version: 1.0
References: <20220117153634.150357-1-nogikh@google.com>
X-Mailer: git-send-email 2.34.1.703.g22d0c6ccf7-goog
Subject: [PATCH v3 1/2] kcov: split ioctl handling into locked and unlocked parts
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	akpm@linux-foundation.org
Cc: dvyukov@google.com, andreyknvl@gmail.com, elver@google.com, 
	glider@google.com, tarasmadan@google.com, bigeasy@linutronix.de, 
	nogikh@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gGqm3c74;       spf=pass
 (google.com: domain of 3gy3lyqykcd4nogikhgoogle.comkasan-devgooglegroups.com@flex--nogikh.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GY3lYQYKCd4NOGIKHGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--nogikh.bounces.google.com;
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

Currently all ioctls are de facto processed under a spinlock in order
to serialise them. This, however, prohibits the use of vmalloc and other
memory management functions in the implementations of those ioctls,
unnecessary complicating any further changes to the code.

Let all ioctls first be processed inside the kcov_ioctl() function
which should execute the ones that are not compatible with spinlock
and then pass control to kcov_ioctl_locked() for all other ones.
KCOV_REMOTE_ENABLE is processed both in kcov_ioctl() and
kcov_ioctl_locked() as the steps are easily separable.

Although it is still compatible with a spinlock, move KCOV_INIT_TRACE
handling to kcov_ioctl(), so that the changes from the next commit are
easier to follow.

Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
---
 kernel/kcov.c | 68 ++++++++++++++++++++++++++++-----------------------
 1 file changed, 37 insertions(+), 31 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 36ca640c4f8e..e1be7301500b 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -564,31 +564,12 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			     unsigned long arg)
 {
 	struct task_struct *t;
-	unsigned long size, unused;
+	unsigned long flags, unused;
 	int mode, i;
 	struct kcov_remote_arg *remote_arg;
 	struct kcov_remote *remote;
-	unsigned long flags;
 
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
@@ -692,9 +673,32 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 	struct kcov_remote_arg *remote_arg = NULL;
 	unsigned int remote_num_handles;
 	unsigned long remote_arg_size;
-	unsigned long flags;
+	unsigned long size, flags;
 
-	if (cmd == KCOV_REMOTE_ENABLE) {
+	kcov = filep->private_data;
+	switch (cmd) {
+	case KCOV_INIT_TRACE:
+		/*
+		 * Enable kcov in trace mode and setup buffer size.
+		 * Must happen before anything else.
+		 *
+		 * First check the size argument - it must be at least 2
+		 * to hold the current position and one PC. Later we allocate
+		 * size * sizeof(unsigned long) memory, that must not overflow.
+		 */
+		size = arg;
+		if (size < 2 || size > INT_MAX / sizeof(unsigned long))
+			return -EINVAL;
+		spin_lock_irqsave(&kcov->lock, flags);
+		if (kcov->mode != KCOV_MODE_DISABLED) {
+			spin_unlock_irqrestore(&kcov->lock, flags);
+			return -EBUSY;
+		}
+		kcov->size = size;
+		kcov->mode = KCOV_MODE_INIT;
+		spin_unlock_irqrestore(&kcov->lock, flags);
+		return 0;
+	case KCOV_REMOTE_ENABLE:
 		if (get_user(remote_num_handles, (unsigned __user *)(arg +
 				offsetof(struct kcov_remote_arg, num_handles))))
 			return -EFAULT;
@@ -710,16 +714,18 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 			return -EINVAL;
 		}
 		arg = (unsigned long)remote_arg;
+		fallthrough;
+	default:
+		/*
+		 * All other commands can be normally executed under a spin lock, so we
+		 * obtain and release it here in order to simplify kcov_ioctl_locked().
+		 */
+		spin_lock_irqsave(&kcov->lock, flags);
+		res = kcov_ioctl_locked(kcov, cmd, arg);
+		spin_unlock_irqrestore(&kcov->lock, flags);
+		kfree(remote_arg);
+		return res;
 	}
-
-	kcov = filep->private_data;
-	spin_lock_irqsave(&kcov->lock, flags);
-	res = kcov_ioctl_locked(kcov, cmd, arg);
-	spin_unlock_irqrestore(&kcov->lock, flags);
-
-	kfree(remote_arg);
-
-	return res;
 }
 
 static const struct file_operations kcov_fops = {
-- 
2.34.1.703.g22d0c6ccf7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220117153634.150357-2-nogikh%40google.com.
