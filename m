Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJMV3CGAMGQEAJTQJLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EA32455666
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:18 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id y9-20020aa7c249000000b003e7bf7a1579sf4561168edo.5
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223078; cv=pass;
        d=google.com; s=arc-20160816;
        b=wAhQjlb+n+cnOAZeJTPie5J0x0macMfqT14MzrTXTlXpygIIVpRPeQwA4InqOXMfZr
         oZ4MLFXIaD7gqOK5UJhV6mvK9zPDzfUHfrpKHp/UjN0L0gt1q6dzPSRv5eTMLbPFpaF4
         NEeLm6au/KufcwmpFfyQsjz3YIuwqTKs3+mAOyKEra5ayH8W7AEdDpgB0JjL+WtDMEqM
         i5VM+gWL53q3Lug0ogacYBmtaHb+jrO3F5FYtyq9+VzOaaug7Qi7IMK4cYTU98bJXod7
         v+jXAcCJ+wt4F9jpSJY8aSYsw3B/YCAV3QoviWrN7ACUD6rx2KiClrbtClSrGHNoHRg/
         dZ8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iMUgWkECTigOPgJ5pD/v7/fFzEzYA8l8grjVUbCtifw=;
        b=GEhvDYKxbUx3tckWqABHONVfnmSYWvVK6HV87YW0uMl3QjBpy2k7bg5hubxE8XFs13
         KB+UbCrdR+lWjSNXaI39JKaVLc4uIcTEsh6imP6LwTBj/nlQFyIla+hHJBlbTw93sHXL
         3LTs0TWUDDmsccNItPfvD70hcIhWT3G4iDZ2IhaO+N8bfrz3gUUWi75fG3ihAhe/mrNu
         LejdXMl2Dls5IQAi+0uQvNJ1HmU8UL/18TUaBbnzmkyfRjUj8ev52FeDpwxJxd2oWY5e
         jpnCuog+BakYD6KMRgJZIZpKHBBXrd+gUnb1EPFcQMFIGccC3SDMv5JuQYsyjCwdseVP
         kZfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DMAx5U3F;
       spf=pass (google.com: domain of 3paqwyqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3pAqWYQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iMUgWkECTigOPgJ5pD/v7/fFzEzYA8l8grjVUbCtifw=;
        b=dPPFrYinU2lpKJWmT6ZRIu47i8Wly7I0R1r3Hgv7vkF/Q2/dDURC6ht9CusOKID2OE
         fdV8ka/5wIYVztf7VEkdx3BQsWGU7PhxU50wrrNqQAGNr+QUWYR6CcTJtuZFOeRy0eTt
         UqH7G/BpLueJ/QJrjnHqnFVH+mfcswrbP4uVdKFLGOfxST2Po4+q11FHJNwTulnDs65/
         XcoNtMbucavN/4GTSuTh52yTqLqP7W3b2CxVl6OG+hJcJRfLJHxtTu3asx71TW8wis/V
         4YoIt/XptOOxF4lpwzWoF9hOu1nb2D6UonGjmnL0YBLmjoc/FQEqhPZj+WrymcBQxJUT
         y2ZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iMUgWkECTigOPgJ5pD/v7/fFzEzYA8l8grjVUbCtifw=;
        b=2GyGn2MD5cZ9KBzwCGRtuOZWCG24KPRFE+WLdz0SHoq68ZcZ1RfSE63VxZ4/d0yML4
         KJDHrvC0syOnm15FTelbCCGd1OwuCdGeI0w1r/M1kXKwdgs3kqSDNKSQ0832kUKjHF+g
         8kg7izVargTu/lcpUBhb4G/29ro6n4iI2wlJtt4wZTujqyT1DC/UU7EBYVBOyNWj1h2J
         0hTPZsSfzqQpSmyGQmfMlcVRFrnhurGJpj7cndniFhGc8Dutl6efFi4qEyDo+x/GelGu
         LlKyWWvAL8YDZdZCSdsL1WPE0pWJBnh7c6tBURXlDLmzfiTSbdzNoDv/gUhVc1pbWMjZ
         2SkA==
X-Gm-Message-State: AOAM531QejfZDRL9I6A+pGNF7cEeffyGW59Gel/q05rqX3g4ByaUyDu6
	jSxsCsg27+6tTFy30BB32pE=
X-Google-Smtp-Source: ABdhPJybk3XvewJXiddsuuwG0SIWIGonOY3BVhmGq1ZGylQ2DRa6m4+7sLapbhs8XtPrSjrymp88Ng==
X-Received: by 2002:a17:907:2da3:: with SMTP id gt35mr31028755ejc.314.1637223078142;
        Thu, 18 Nov 2021 00:11:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:8e41:: with SMTP id 1ls2431520edx.0.gmail; Thu, 18 Nov
 2021 00:11:17 -0800 (PST)
X-Received: by 2002:a05:6402:4394:: with SMTP id o20mr8459752edc.342.1637223077148;
        Thu, 18 Nov 2021 00:11:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223077; cv=none;
        d=google.com; s=arc-20160816;
        b=JuV4m5Inb8txDtTOPRZaPz/pcu7cLc/+WGeG2CeqAiUsvFCuHuzDyPSrlxJr5RQR5I
         Wg5pCeavy6lYIAPzSnOLkW+XPjxtWGyB3UtBwwKwT/WHSq+6EeYhIWIJcbyN1fm7Mg54
         hTlT9yaIE/FsEEHM/7A29GoIbtp5mtLoIhWCAso9n09aEjWvkB/dKdLTgq/Ubi7T9ViT
         76/lT4TLJqAcrhd7hGVTUhlordt6kF0WH1s78O41b2jYPiiFuYjh9asPdXDd/Q3hwrKU
         GsJol3eAwSIOdH5IxJ2+9IWSUUa9Uyc8u9gbg8xT05VsZpA80ftm/Th5qqRA+sRwbCgs
         ddCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9MKtF9b1Z9XuvDPczN5keFD3RJ+5M3WbaM5UaZup9oY=;
        b=XqEPbMHB2V4fKbhuEk/V5Q8Vmbb/BuaX9f93tmyDMX1TCDSafMYcnQlCDiD2d3iMHP
         acxcE1rKGM2tsQN5s3gpQciG1SquGuIzpBMikhwjeybKSwrMIhykUa5IDekceBvBHkj4
         rhJF5D1PQR8t0Sf8tn+Aqeagmm5aIKwRocQCjbCnlha3ARcG+Qri7O6JDirgGMcysRfP
         l09YyFM1ml42PT+KC63vkU64E2xl6rJiLiNamCt3g8zSyVxicE3aVlamMYsDFYRYn9N7
         fitKTZ1PZV6rUss6KsAkYchgIzSaThF+VMkT6pIEjMVw/IcO1p/ti3PS0vJJBWmHY5xh
         /Ttg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DMAx5U3F;
       spf=pass (google.com: domain of 3paqwyqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3pAqWYQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id w5si129838ede.3.2021.11.18.00.11.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:17 -0800 (PST)
Received-SPF: pass (google.com: domain of 3paqwyqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 69-20020a1c0148000000b0033214e5b021so2254320wmb.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:17 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:3b20:: with SMTP id
 m32mr2109456wms.0.1637223076382; Thu, 18 Nov 2021 00:11:16 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:12 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-9-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 08/23] kcsan: Show location access was reordered to
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DMAx5U3F;       spf=pass
 (google.com: domain of 3paqwyqukcsufmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3pAqWYQUKCSUFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 35 +++++++++++++++++++++++------------
 1 file changed, 23 insertions(+), 12 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 1b0e050bdf6a..67794404042a 100644
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
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-9-elver%40google.com.
