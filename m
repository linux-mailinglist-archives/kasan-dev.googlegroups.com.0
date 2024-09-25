Return-Path: <kasan-dev+bncBAABB7V52C3QMGQEKRGQY5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 1481D9860BF
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 16:32:32 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-45828d941f1sf119899701cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 07:32:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727274751; cv=pass;
        d=google.com; s=arc-20240605;
        b=b4AHTeSkdeayfZgpmbv6Hka2idoSjIMbZvhkGxEgcB7UN6mpg5f/Wf4DfsuaZ4WjTq
         uN2LcbsyrSORS5Xs4HQKleOq/QVEg7XapZrGGincM/rVN+MpQrgdbjQtbedOMWu8hLjy
         Va9LlOZWYTA2hCSyZ8eZ6aGVOvC/8mCngS5CsL+L0spq1QBli02y0caLyD+3Asuodkfr
         C8aRRhArKulVxO04HRprS9fDsR+SEqiXxc/axONp+F95fEGGxaSAr/YDMFmeG1aLR33N
         BPKIgZd757+OCFnjYJMiiHEyy8NZLDS8k8/1ocHfEg0ZBVLxO5ZwMKG5gY5SSNXnmfpS
         hwPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8SNi+2xBNWK+9g0Nagv/dYjsIJUpeLQtKSsEUr/uqiY=;
        fh=7e/iKFkSYfqLf60bYrQrhgMcOTImaOBZ3TI5Gyw94nw=;
        b=OBp7R38vav3B3IIBVvIVV9jVgYcrnfWJjlY2Vd/GSAEu2KoVODirgXKMrZbYpqwAL0
         71OaRIpPOBb+i5hAZtC8/WunDrAJofCKz7F4AruJgGIJHEJzwlwstYevRyGg4FJBZvyV
         G2YwIEdQzQOF7R2+Ii+6zqPChRSilgmb7gdMALrR3pQddvPrltk7fLgqE4E2PrLJiju8
         llEgvr+gaDrcNxtwkY9CsDRDsruFlxes9hrIOSd0iSPtfl+jgPe/ExMUCr8iD4COzrAe
         VGxGB3VsayjAZx5eu5oJTGwJzI4YwP7/ofVzY567e8QseHd53LqjJUhJiiTdMXTDQFHO
         BK3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=hyO85nw+;
       spf=pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.4 as permitted sender) smtp.mailfrom=ranxiaokai627@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727274751; x=1727879551; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8SNi+2xBNWK+9g0Nagv/dYjsIJUpeLQtKSsEUr/uqiY=;
        b=jWGPm5x6DFLxsPmX0r+s5d9+wUA4Xbx+pr0zkOmxLKKP6hoMqAIqEcBepntsFNU86L
         VOLmP7eN+otGR4Rou7sKPeYhWVvaUqpU1xBqSN6cDjDetTHwYL7MYy0gf1W+Hqhm/dfC
         NgnAlzJ8EBP13FVamtp1Pbl0aa8oJIvdMrGC6pJE+o4/+uWcwJfTtW0PQig6mWg3qaYA
         KJjqWos5OjuxZSLInoLfJUrlvD6rPF70a8xnQppexwspaAVvkT5zEsDbTIoPfLrYHyXZ
         NdzHrD8YfzDGKVzlaUjpUHozv4b5FutPNoslwoQQPK6FufvGrKI89ElO8+HAxDDyq05g
         8jDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727274751; x=1727879551;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8SNi+2xBNWK+9g0Nagv/dYjsIJUpeLQtKSsEUr/uqiY=;
        b=gZrXmOhGNvQ2kSxljwn2bccmIvhUrs28eHKr0VuHuxFB2ZZF3cIcVoitkHjDRKT6tU
         yYFH0yySYZ6MOLm5svDxU378NStNd//ukO63pUgkjA3t8WE1bWqKb4Um/c35/kQQQCEb
         FN8JwJiJKMSXvYGrDZYDErm6FgxGOlaHnzeAWg29XtX43ZLcGk2k29+OlyWbH2Ly4ohZ
         kKPEEHO4Y51RBzjVDhJTkp50l7Ag7UYlWxOYg8VkAu8c4WlIJlPy/QinN3z3SABUtTNX
         3vkcphlE/SKpQICtrzczeVo6IBFXnUks+05LNYd0ZpIg1awWuAOqhGXAFlAGHFDe3RL/
         SL+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXk4VOdYvL433YMASspfINsgLeR7RXZJI9SgMMnKLxmiw+OQB2y+YtRHzoRsD6uy1rh/lkoJg==@lfdr.de
X-Gm-Message-State: AOJu0YyRzpMchiwzC1E9stgd1S6C4Uw+Clkh9n7ux6m5mynrDBtJE1M2
	sVlz5Sr8ai3PbteUs6YICPP1l5fDAYcLds7Pul0R/SStPHNpcjrz
X-Google-Smtp-Source: AGHT+IHTJPAdkiOIKcz5xhoreU8Y3zi/vg90kau/tzHS5oeM95oXdA1Wf93W6Qr3PLwluG70JaLOhw==
X-Received: by 2002:a05:622a:255:b0:447:f9b2:6c48 with SMTP id d75a77b69052e-45b5e0af19emr45411311cf.53.1727274750212;
        Wed, 25 Sep 2024 07:32:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:574a:0:b0:458:2dcf:c76b with SMTP id d75a77b69052e-45b166c5e97ls5745911cf.2.-pod-prod-05-us;
 Wed, 25 Sep 2024 07:32:29 -0700 (PDT)
X-Received: by 2002:ac8:7fd4:0:b0:458:4e4c:b68f with SMTP id d75a77b69052e-45b5e096c63mr46241021cf.46.1727274748938;
        Wed, 25 Sep 2024 07:32:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727274748; cv=none;
        d=google.com; s=arc-20240605;
        b=J1huEWiuLuioDRyiFkd3Xsp9/HeV3bMmqeZY2Baan+lj951xTTP6og23lidjp/WR/X
         E4cdZ2gkvAhYLuPplo9Pq6L9kZjGqmxxAchPP9yqFnzbhavgCDuJMo9RENCRd2zZyQBC
         0/YZkP0IIo4mUiPpMr4ktd44T9IZOwQsXr4n8hQ8m4BwWStleFKPRhkhVs1JaoX9SBeA
         9/vSZWeVspcy4YP2RHHYkBiVJlfnDH8KB+TOFalgKb51kFQkELujbmN2gfenkDaEGum/
         29dOhTVMisgnJwzmVQHVlbfp6TDesNl+BEspdSRhaGlOVwIoJW80twW48KippqpvpgnH
         NtFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Q5EiuVc5mpkjolusR0Mp9uhxQxccRS+YA1w3NEqDb/o=;
        fh=soLd1rxl5Zg4+HEDKR/GyOBvVj1EgNzTFg1l3c/vbe0=;
        b=bw/cyW6fZqTA05e1NXpJWzYllDDf/g5CZB+ckGm6a1GG217pfkzBh8s0kl/DR+tdu+
         mXw3h/B2Z+2QjnQj2I9oE5WPQmFzvHVFAuLYB5s4H1mkxblHdUNWQErRZEafggjiSiz1
         Zy+IuJNcpSBmc+nSMYLdBHh7k0ftOADxxQCUqOB+CHoX+Cabp0jPRnkU8ABP32GSjZk2
         PNev+JGCHGjljOiVM6zlnrT6RiE9yrMj9tLWOqzqk6GKk8x7lESSsz6fmxRoEnztJVGj
         y1w7jMrUmyi88Ip7BWY8GStqB5VhmEhi1V0imDBBNEga0trrgKCwgppo6pS27a39HHzP
         cZZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=hyO85nw+;
       spf=pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.4 as permitted sender) smtp.mailfrom=ranxiaokai627@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m16.mail.163.com (m16.mail.163.com. [220.197.31.4])
        by gmr-mx.google.com with ESMTP id d75a77b69052e-45b5278a433si1369551cf.4.2024.09.25.07.32.27
        for <kasan-dev@googlegroups.com>;
        Wed, 25 Sep 2024 07:32:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.4 as permitted sender) client-ip=220.197.31.4;
Received: from localhost.localdomain (unknown [193.203.214.57])
	by gzga-smtp-mta-g2-2 (Coremail) with SMTP id _____wDn9EXeHvRmGMqpJA--.33673S6;
	Wed, 25 Sep 2024 22:32:08 +0800 (CST)
From: ran xiaokai <ranxiaokai627@163.com>
To: elver@google.com,
	tglx@linutronix.de,
	dvyukov@google.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Ran Xiaokai <ran.xiaokai@zte.com.cn>
Subject: [PATCH 2/4] kcsan, debugfs: refactor set_report_filterlist_whitelist() to return a value
Date: Wed, 25 Sep 2024 14:31:52 +0000
Message-Id: <20240925143154.2322926-3-ranxiaokai627@163.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240925143154.2322926-1-ranxiaokai627@163.com>
References: <20240925143154.2322926-1-ranxiaokai627@163.com>
MIME-Version: 1.0
X-CM-TRANSID: _____wDn9EXeHvRmGMqpJA--.33673S6
X-Coremail-Antispam: 1Uf129KBjvJXoW7KFy3GF13KFWUGrWDtr1UZFb_yoW8uF1fpa
	s8G3s8JryvqF1FyrW5CFW5W3yrKr95Xr12va47ur9rAF1qqr4q9a1fKF9Yv3yYgry0vr4D
	WFs0vFZ8AF4DJaUanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDUYxBIdaVFxhVjvjDU0xZFpf9x07jqeHDUUUUU=
X-Originating-IP: [193.203.214.57]
X-CM-SenderInfo: xudq5x5drntxqwsxqiywtou0bp/1tbiqRhlTGb0HXEZ0QAAsu
X-Original-Sender: ranxiaokai627@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b=hyO85nw+;       spf=pass
 (google.com: domain of ranxiaokai627@163.com designates 220.197.31.4 as
 permitted sender) smtp.mailfrom=ranxiaokai627@163.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=163.com
Content-Type: text/plain; charset="UTF-8"
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

From: Ran Xiaokai <ran.xiaokai@zte.com.cn>

This is a preparation patch, when converted to rcu lock,
set_report_filterlist_whitelist() may fail due to memory alloction,
refactor it to return a value, so the error codes can be
passed to the userspace.

Signed-off-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
---
 kernel/kcsan/debugfs.c | 18 ++++++++++--------
 1 file changed, 10 insertions(+), 8 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index ed483987869e..30547507f497 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -131,13 +131,14 @@ bool kcsan_skip_report_debugfs(unsigned long func_addr)
 	return ret;
 }
 
-static void set_report_filterlist_whitelist(bool whitelist)
+static ssize_t set_report_filterlist_whitelist(bool whitelist)
 {
 	unsigned long flags;
 
 	spin_lock_irqsave(&report_filterlist_lock, flags);
 	report_filterlist.whitelist = whitelist;
 	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	return 0;
 }
 
 /* Returns 0 on success, error-code otherwise. */
@@ -225,6 +226,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 	char kbuf[KSYM_NAME_LEN];
 	char *arg;
 	const size_t read_len = min(count, sizeof(kbuf) - 1);
+	ssize_t ret;
 
 	if (copy_from_user(kbuf, buf, read_len))
 		return -EFAULT;
@@ -242,19 +244,19 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 			return -EINVAL;
 		microbenchmark(iters);
 	} else if (!strcmp(arg, "whitelist")) {
-		set_report_filterlist_whitelist(true);
+		ret = set_report_filterlist_whitelist(true);
 	} else if (!strcmp(arg, "blacklist")) {
-		set_report_filterlist_whitelist(false);
+		ret = set_report_filterlist_whitelist(false);
 	} else if (arg[0] == '!') {
-		ssize_t ret = insert_report_filterlist(&arg[1]);
-
-		if (ret < 0)
-			return ret;
+		ret = insert_report_filterlist(&arg[1]);
 	} else {
 		return -EINVAL;
 	}
 
-	return count;
+	if (ret < 0)
+		return ret;
+	else
+		return count;
 }
 
 static const struct file_operations debugfs_ops =
-- 
2.15.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240925143154.2322926-3-ranxiaokai627%40163.com.
