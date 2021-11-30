Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU45TCGQMGQEGECZOVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 252C04632D6
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:24 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id j25-20020a05600c1c1900b00332372c252dsf12716657wms.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272724; cv=pass;
        d=google.com; s=arc-20160816;
        b=J9xgBk2/DdABrqL9aNNDFBTNm5OIPUeeOWzRJALI0YnIY0hBl7AZrZOOOZja46Y6FA
         wJ5dHrDiNhRSbkxTbEPlcF0OlkceutiJ3ynWC1gIKz/ovFT/1xkM4C3efk1K52EFfTNy
         ew/JA0g920+tbifa4YbZLDcNK1JUeVhI+Ocqra0DjjPf8uKHSfWpwuO6ehv0f4orawGT
         um31upDmC0W7Gw2y7HWA1bLSgkm+cWyaMpCnxuI05ekIR89/bKpNNR03nD/9J3sVzuCD
         ro8Cf60X6EjPd89DIR7Pv9QvR3FKOjmHL63TeJ6/7P25pbmjETVAH9D25O/zUZJTUcWx
         Hpsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iAvlOgoI5q/ouLUysNBCt41qem+ZNtQYRpjOK9j3kYA=;
        b=sTGKL8+7HjJM0ZnOSreBbvbszs+glz8QdJPKWNo8m+M1QXJYHC1o5dhLUSy6gtpQJl
         SWfZyMRsscNNU1IgQ5mNjZqRdZO8vjBsUA0r0QIL6RlHoDhfRrbYHVjewpWreefLSP2O
         iVk18d7mrdxnnqotWkPJuRVajvG8VXZlMd8GVXGzF+s8fHFiEx8zPyo9zZ9DcvjtQgFI
         MBWTbyHznkBB2rMGhlMxnAexp+AB/7spPbwjKbEL2t++YURs88eNHi9tNhT5X0wwHbi2
         uYsxEGmOsw2uwBVMUCHD/Bz6C6eO/tTPyVvKR+PjuTt3/AWhS2M07sVOnNJMIZ3P5mmM
         rmUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Mld6ftuJ;
       spf=pass (google.com: domain of 30g6myqukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30g6mYQUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iAvlOgoI5q/ouLUysNBCt41qem+ZNtQYRpjOK9j3kYA=;
        b=FP4HDwEtnEeRmxvkpGaXLci/sC0olSuUItOpiUQMjPdYEj+luA9+hf3N3TGVpnEoWW
         aXZPRhAXWPqbnNYP5AF8UNh2FbWNHyaTI7P1bVbVJnmp3pOh5bE8hQaWH6xgs4JSmTGP
         7cfb1+LpynVBu33y4K8h5AWi8SrPLml6ub7907AfORpm2xdrihnFAigWcQDnNlK+cTZp
         +5lkA82lnNrgOHImNleR4V2Rl96e+RA5GGCuED6w5N6wEnKUDV4mEnrpMjLgVrl0MqgJ
         l4+Iork7SuVOoViQ//R//9tWiLeZCF4Qy96nWwwqewi6vkAXe0fvi+uJjI8yGhkiUj19
         +cNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iAvlOgoI5q/ouLUysNBCt41qem+ZNtQYRpjOK9j3kYA=;
        b=KPpmjEWi0DaB+odDe7DCa6wlMUNnNWckzisiEFenTJTAF64FVWPchIGuEeCHJLjUmR
         +zilhEQ8JNrvuBdjHTVwnpBqEGk28YaUJz5kdLeoT/Vu9pu0pdUpvKk+RcYrsbBfbOog
         DY0NZIEFAMh02Yepp7KhsJHPF0vnbwJBW71AxlbQLvlpLOc54iRaVotPUPfSX8iMQ7nD
         CWUZzvl0AbBVPfUKBkpfUDYDdjFyhkwiinnyMabHy6748u932+4yohY+zy7Yh3O9zX8s
         nYxIO521B/DY7RcHLcUNe69p7E3fvUVnAz5qfBD0SSgzTcSON+5JpRlP7JUs3x91NAUJ
         QOig==
X-Gm-Message-State: AOAM5304eWj0WtVekx7ix987/nXOJLieQjhelqEUh2W5I+qhWqy8ykap
	ApGkL2T6kjBFzLeo0UmQafc=
X-Google-Smtp-Source: ABdhPJwG3/Lx+vdRoVmYF7GVV7RaHjUVcSMDA8OgokwitlwunhROndVQSyBDg62fqW89TqWBerSrEg==
X-Received: by 2002:a1c:a710:: with SMTP id q16mr4422717wme.138.1638272723903;
        Tue, 30 Nov 2021 03:45:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:23c8:: with SMTP id j191ls1236741wmj.1.gmail; Tue, 30
 Nov 2021 03:45:23 -0800 (PST)
X-Received: by 2002:a7b:c8c8:: with SMTP id f8mr4382317wml.49.1638272723055;
        Tue, 30 Nov 2021 03:45:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272723; cv=none;
        d=google.com; s=arc-20160816;
        b=jS5U8q3/hxD8zg2jgOJyt4jwot1PcG78sDpjRapF+KtvjnnZFAstaJ80gVFstT9NZs
         ACT6HJJyLEgNSHUthuNWs5cxZTjXOmSO0Mv1kzgioTvxCDNH4ZGZ7IDNNe5FIgGJM8wS
         GbQCIo+uyKtQ4pgiyKH5EV1Uhu1dNbZk5aYK2ixNqlN3xE9tNcgNh8pDZFXR9NZRv6aa
         Lab2JJ4IT8u7O9PDNY6sLDGaZGgL0EVTebxlZhbHnmdYRxv1V0hdM0u2YvEpUTygGnNW
         Fh5yY0Wo6ggTwkucli3muClTic+8BZQRssBa9TmidETphQkTTnzHp+D2YqIycRPJoCnr
         ykQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9MKtF9b1Z9XuvDPczN5keFD3RJ+5M3WbaM5UaZup9oY=;
        b=giaPYKOMUtydO12PdxFK7v+8+LbyJUnZnjK0dJr01pooer8Ah2CyJ0DpBApDBIscUF
         nwJ4OPQwfXG6QnUAVEXHPxATMTGuHZXQVBAiVgLzUMEwQgy5UP8cslLAfaETpNcdQR44
         ba2iiKsJov2K2lcDrVRUjIR526oFUEbbUjMAAnZcCRjVaU6HOy7ITRCmoDlY+QdfMJSm
         Nf7iQUiSTjXEWs5b7HSqkGRVimukpbepU0MVZKDAUC0z2kDY79yw6/cST2yKs9Uo3s8a
         2P8fYALZD2N2x/2HcOYFns9/DhFKzeQ1fUfU//qyFd3MuFI63P4Jxp5ividniuWvLhnd
         nBDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Mld6ftuJ;
       spf=pass (google.com: domain of 30g6myqukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30g6mYQUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id r6si1120478wrj.2.2021.11.30.03.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 30g6myqukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g80-20020a1c2053000000b003331a764709so13624883wmg.2
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:23 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a5d:50c7:: with SMTP id f7mr38501609wrt.327.1638272722693;
 Tue, 30 Nov 2021 03:45:22 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:16 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-9-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 08/25] kcsan: Show location access was reordered to
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Mld6ftuJ;       spf=pass
 (google.com: domain of 30g6myqukczs9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=30g6mYQUKCZs9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-9-elver%40google.com.
