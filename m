Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7NJ4SGQMGQELIIP4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F27F474D81
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:46 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id d2-20020a0565123d0200b0040370d0d2fbsf9217877lfv.23
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=BTJtrv6V+OF78qmk8qlD1yxKODgtC+6pmToH7TXGEtod01R5WG61faXLvu7XuSDWqj
         oFnBbgE6yTnnFBz+9TNPMEhrPnzf+FV3S8P5LEGB8caPdoEqzNRR3M4Yskued3iTQtbx
         wedKB5JLPCyU8GkH0s4X6ZrsMdutXOGi7Tka+bc9ckZDhbH0HQUAbzMr4WjZOdbghPrB
         jG/KpaejqIhd4wtqsj/6gtD943wxlWHktKvlcHhlmjxPArJ/ii2WxWAq8jfAqY5uzB3g
         pS1Qkw+a3O3aDyGY00ZJLF4TOWQz/AR9tNnPwWUgwoHZTy+aF/Kg0WL2z+DmMe7EU/sX
         M3lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=sIFAiPnlD6mDZ2/CTtO+YAuGA5iRcIAkhE0wqJGO2Wg=;
        b=XgSCZxY/66T7O8UTKTqwU+ZGmzi8yUiQFjCfSelhDFuc8QO2zQsbl6W2otvDvCln+3
         FJLIq7XPIT74uUCiKWIUbdoMKWmQ6KX2NanYu72hwt9w523ZLgxNDpYNuQTR610RYHUi
         dGkwRKa9s5+iN2frA+yPkl/R+KIH0gFDQ6VRtX8t6aYZBdXJPD1qbwgkiS85xDDCdnV8
         agL0Ix5c/7GoM+QZnN2e65ktl/wEDmXF9xKj85dmpoKSdQtUBTbiHbKr5zjbmZZ1gXWv
         pDsUiAeTqL1ycQpat6sZFQ0u+5YHieg5CHXZaKY9gOXliak5GdbtHe7FgwNjWSdLw//N
         YN1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JRzBhCFj;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sIFAiPnlD6mDZ2/CTtO+YAuGA5iRcIAkhE0wqJGO2Wg=;
        b=AiXuf16D20YmV19Pk4XylSpqPtahyktP3pmujLHepM8eyhScH8hVOMIBj73Wl4kt5x
         6cKNNDrSE2TqUeBA79u4/9zpurL5TXTTbWmLNb0ix30Ufagc+huF4+PqXCsJplWGsXQg
         cLVr3Ufm0MIvtw1u8fJACz+nP+Qtzu34LyV7bHZrcnC7AGcYCR3N0mJJvuSZnCDrMtvm
         ayOsNjbi0/558jzdqhiebNQfpFSTVY0v/01kZleeyrD4c8h8Oqcq0Wmm6+WMg1v6thCC
         0e/LebQi7eKaclZR8U/qs9Gdl1HnlGnFh0FOnzxqMNx4CQSDn/dKLulS5hfgzgXNM/qD
         3nkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sIFAiPnlD6mDZ2/CTtO+YAuGA5iRcIAkhE0wqJGO2Wg=;
        b=d/b09KgnhgLYNcSCRyxWYTt+LC4Iul/ofHNN9BnXeBWJAA0wAKhuPKX/vvsANyoEPX
         wkxqnHw8J2PiwkUlHtj/wEv/bGCurBxO1NzmlOMhG1XAXlBXW7nxBo5Ow4hAmhM4eDy7
         8H3Ect5l+17IO110+5etV3Mp918cNpzUD3VRUc5BIxl0OgIqFNZ8jO+1ft/HTVkAoCCf
         ZPG5uQZFTedBGYRYtrMQR0v9Cji0pYY96N1ch3+C38dDwNRMbNn0vN1ziRfRMHQDml1k
         2Xp+SLAkpJaocTsttEI/b65R4y9pUeoXRNgY7nYEfLRCvbgMNNm7gm3ySsCf5BsaL0HF
         zkTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533W1IKMSzzip/AJdk2VqK78WAhPoqQXcp8Wenz6bFezCOtiubcI
	XL+dobXwt1e1zUKXc5M8HjQ=
X-Google-Smtp-Source: ABdhPJxlYMFZZhHm2NRVrFjrGbeGJBfkq1rpfXBjoWHJ+8gUplAOPigRNBFuE2TPrNV0rT8/t5qCeg==
X-Received: by 2002:a2e:8554:: with SMTP id u20mr7594360ljj.70.1639519485876;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls98081lfv.1.gmail; Tue, 14
 Dec 2021 14:04:44 -0800 (PST)
X-Received: by 2002:a05:6512:1043:: with SMTP id c3mr6745722lfb.95.1639519484683;
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519484; cv=none;
        d=google.com; s=arc-20160816;
        b=pNU/BWhiw6uyUvEYyxGmVD53HMvs4ORp/phd3JzoH+r99FbtKXcW68MF9Z4Tn18jBO
         W9KtulErhlRNr1iWHtNEO7lO8Maw9nWVr891av0WA6E0Q10dtwXkew/8uLn3lqT+LAQT
         +MYeSvC/nOACPiJqPoMrHLtwmKCsGPBU7rCrCzRbn9gwnAUTzETHqlPkAJbK9on5BNTL
         R0yc200woM2t72OtrIZ/pPtKzIE0M4b72YRaqoGVsqa/ED52d6t80d4XsPo89FfnSAw5
         VuoutDZvce1zgyO6f3hKv/Zvf3ZtdvrlifhM9VoTN3oJWQyxlVIJghmG+3sSNcQnPCQu
         s4dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7ZzvviRE7j3QDvmTba1/qt/3kHlEodz80KBQLug+u84=;
        b=HRxh3I7PTnm2ecYNigXj2JfBUieYErOUkfQE0wnGgFZu6iXUNHtULKMgBc4UbsrCD5
         YjN1DT+WYH4gT01cZgw0gmkQeKfI5pRiFW3l3JHs837PL06F/U3IvYQce4E23BEaFT5g
         VRVRlFtcPOsSEePlG9gG6My3z0In+ONtzsGCjO7+P+0QsY0Kj1X9GdEDKidCom10Ops5
         6Ebxj4cfZj+5ImV6maymZfbuBn5cT4dXqnN5tHjDg0FaqQbej/f4+B2pvTj/cx4n32tN
         /g67G+9tMJ4TUYFgmYKeU0aFOV31mdIg+mPxSpWJNcox8ZieQpsRpmilw54Lwqs1d3Nx
         xFqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JRzBhCFj;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id y7si2350ljp.7.2021.12.14.14.04.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2F1FB6172B;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id DC3F1C34615;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6920E5C14E0; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 08/29] kcsan: Show location access was reordered to
Date: Tue, 14 Dec 2021 14:04:18 -0800
Message-Id: <20211214220439.2236564-8-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JRzBhCFj;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Also show the location the access was reordered to. An example report:

| ==================================================================
| BUG: KCSAN: data-race in test_kernel_wrong_memorder / test_kernel_wrong_memorder
|
| read-write to 0xffffffffc01e61a8 of 8 bytes by task 2311 on cpu 5:
|  test_kernel_wrong_memorder+0x57/0x90
|  access_thread+0x99/0xe0
|  kthread+0x2ba/0x2f0
|  ret_from_fork+0x22/0x30
|
| read-write (reordered) to 0xffffffffc01e61a8 of 8 bytes by task 2310 on cpu 7:
|  test_kernel_wrong_memorder+0x57/0x90
|  access_thread+0x99/0xe0
|  kthread+0x2ba/0x2f0
|  ret_from_fork+0x22/0x30
|   |
|   +-> reordered to: test_kernel_wrong_memorder+0x80/0x90
|
| Reported by Kernel Concurrency Sanitizer on:
| CPU: 7 PID: 2310 Comm: access_thread Not tainted 5.14.0-rc1+ #18
| Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
| ==================================================================

Reviewed-by: Boqun Feng <boqun.feng@gmail.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 35 +++++++++++++++++++++++------------
 1 file changed, 23 insertions(+), 12 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 1b0e050bdf6a0..67794404042a5 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -308,10 +308,12 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 
 /*
  * Skips to the first entry that matches the function of @ip, and then replaces
- * that entry with @ip, returning the entries to skip.
+ * that entry with @ip, returning the entries to skip with @replaced containing
+ * the replaced entry.
  */
 static int
-replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip)
+replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip,
+		    unsigned long *replaced)
 {
 	unsigned long symbolsize, offset;
 	unsigned long target_func;
@@ -330,6 +332,7 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
 		func -= offset;
 
 		if (func == target_func) {
+			*replaced = stack_entries[skip];
 			stack_entries[skip] = ip;
 			return skip;
 		}
@@ -342,9 +345,10 @@ replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned lon
 }
 
 static int
-sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip)
+sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip,
+		       unsigned long *replaced)
 {
-	return ip ? replace_stack_entry(stack_entries, num_entries, ip) :
+	return ip ? replace_stack_entry(stack_entries, num_entries, ip, replaced) :
 			  get_stack_skipnr(stack_entries, num_entries);
 }
 
@@ -360,6 +364,14 @@ static int sym_strcmp(void *addr1, void *addr2)
 	return strncmp(buf1, buf2, sizeof(buf1));
 }
 
+static void
+print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long reordered_to)
+{
+	stack_trace_print(stack_entries, num_entries, 0);
+	if (reordered_to)
+		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to);
+}
+
 static void print_verbose_info(struct task_struct *task)
 {
 	if (!task)
@@ -378,10 +390,12 @@ static void print_report(enum kcsan_value_change value_change,
 			 struct other_info *other_info,
 			 u64 old, u64 new, u64 mask)
 {
+	unsigned long reordered_to = 0;
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
-	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip);
+	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip, &reordered_to);
 	unsigned long this_frame = stack_entries[skipnr];
+	unsigned long other_reordered_to = 0;
 	unsigned long other_frame = 0;
 	int other_skipnr = 0; /* silence uninit warnings */
 
@@ -394,7 +408,7 @@ static void print_report(enum kcsan_value_change value_change,
 	if (other_info) {
 		other_skipnr = sanitize_stack_entries(other_info->stack_entries,
 						      other_info->num_stack_entries,
-						      other_info->ai.ip);
+						      other_info->ai.ip, &other_reordered_to);
 		other_frame = other_info->stack_entries[other_skipnr];
 
 		/* @value_change is only known for the other thread */
@@ -434,10 +448,9 @@ static void print_report(enum kcsan_value_change value_change,
 		       other_info->ai.cpu_id);
 
 		/* Print the other thread's stack trace. */
-		stack_trace_print(other_info->stack_entries + other_skipnr,
+		print_stack_trace(other_info->stack_entries + other_skipnr,
 				  other_info->num_stack_entries - other_skipnr,
-				  0);
-
+				  other_reordered_to);
 		if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
 			print_verbose_info(other_info->task);
 
@@ -451,9 +464,7 @@ static void print_report(enum kcsan_value_change value_change,
 		       get_thread_desc(ai->task_pid), ai->cpu_id);
 	}
 	/* Print stack trace of this thread. */
-	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr,
-			  0);
-
+	print_stack_trace(stack_entries + skipnr, num_stack_entries - skipnr, reordered_to);
 	if (IS_ENABLED(CONFIG_KCSAN_VERBOSE))
 		print_verbose_info(current);
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-8-paulmck%40kernel.org.
