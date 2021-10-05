Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM7A6CFAMGQEVNVR6WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id D6CD142241E
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:03 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id v2-20020ac25582000000b003fd1c161a31sf10596974lfg.15
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431603; cv=pass;
        d=google.com; s=arc-20160816;
        b=0cVZUEG/01MhOrU2ughCa7yd0suSB1WzmfZCmU5enbe5FWP4mcADtSahfHcRtUaaz0
         842P34/47g3DEMkT1cSWkYY/R2zLpODNTOeKFDBnGjzHCcDIcAmv19CRFrXgO6l01bqQ
         UdyRp4Cz8wE1TEjqynwTDT0i8R93psZ8YHBsQ4xo9h63HlVf+6/E8TVYEUrsgiYI/YO7
         aOPSuesCZPRaLteixXKa//Db1o9T5yGFinAgA5TRr64zWYAkS4yuHWXK5V+6q14Pc90Z
         C/6W9gQTajuYSCfV3lid6LLU9ZXLlfN8xMok1LQsSb3WKV0koB+NUCRAJo0/mKjZDnzp
         lU8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5kfgRpG+ims5eV6/zCmliF4X1zMsQQW26SO2wPYVjDc=;
        b=NLCjvYDYmB6ck0w21b9LqkqCfB1SjdoO57bF7270TRjCuD8bNLMAFPtdRG0OY3BEB3
         9wzE+syLwV9C/7CVxKzRYajam349fqzDo9HaZEwvjEzSpw8crkZyVHXTz++6HB+jp48f
         ofGCU05U9oqPGlukTQkbWA0kp6Z4jbcXjnZe/ixGvtG1X/6SVvXVeTqwOr1r0y3UJp9n
         jMnjXXlm2UL+n7EVMwUFB4YI2T4i7y8fkid2CViHv5W71itkgcJ2fzpAhWd9eZ2WcdQe
         GCjqyhNFerh6CnaHfzSZxXDZyBJHsbdh+AIhQVsaFhR2IAfASNmswkyxUjfPVhmA1oSk
         Q7oA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GzYNn8Bb;
       spf=pass (google.com: domain of 3mtbcyqukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MTBcYQUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5kfgRpG+ims5eV6/zCmliF4X1zMsQQW26SO2wPYVjDc=;
        b=m2uOZbjdl2Xgp3JkTRQPHswrBixmfoaUU1cgiBW75P85W6k5+SM2ajS3XgNlN3txWx
         TbFZI3JsxE4jUNwbR9kTqGJfzZoIxdPZ+AnYRVssT3FQm2fyCsldnNqUh6AHUdsLcUn/
         vn3qoFhdZHo0OLCbiahHORoljnDqA08xW1EPLuvarxEiLSgb1CM2pX00E1JT+mgzphgE
         2lbGCFcBPDiZO0c3IzB8uAlyw6fVWG5kMnl1BWD2joGU5PvUDGPWRQn6hp/u+GUd2BzP
         nW4wfbIwiP+qPryB+LZmZOQy1hgH9yEYfHDedvfeZz8Pq5LF0xI27g/clFFL3A7Jd0Io
         MoJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5kfgRpG+ims5eV6/zCmliF4X1zMsQQW26SO2wPYVjDc=;
        b=K1r45XQzvlRXk9UslewU3BLS+1QAG+3onpEsUJyFKusKTIDrMPvTdQGKizr9A0FCAL
         6p2QGK5Iv49ltpQAzZT/8QJ3yCt5bbhkubHmCRDuprFvhJISAvjB8rE9yWtM2BxH1aUm
         rSm12GEtjLqtfFQM3vP6l17dW2K50NFI+9ASHdu+GhM7v2JoAJxIfmUw5uXIHRZZwtZI
         AbyYprsc6z5lnU5rRo1nWjjxnWYPRhCl1g3UF0WTTbgDHGHoRxGYFrS9PFMM9cnjODaE
         E/qLpkIcIoW3b39iblzLBH0ku/MOvqXT8vcBFlIVa2I4sXPHBbpFbZc+nHWyexr0GDhs
         C5zQ==
X-Gm-Message-State: AOAM530UufXzpfbDWtHYP8gp8JDYBzrLa8sNwE4JlTjOJLQTPJeEY5vE
	sHWI9iP6lKx/zYzYwHqCZ6E=
X-Google-Smtp-Source: ABdhPJyzP0+J0ccIexOO/cakEilS0FrjnxeldeknyKIQKLMjzjZMRZ3RXO4pB30Lz+oHoGK5W3th9w==
X-Received: by 2002:a05:6512:22c9:: with SMTP id g9mr2847697lfu.637.1633431603445;
        Tue, 05 Oct 2021 04:00:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls27615lfr.0.gmail; Tue, 05
 Oct 2021 04:00:02 -0700 (PDT)
X-Received: by 2002:a05:6512:33d5:: with SMTP id d21mr2789289lfg.248.1633431602350;
        Tue, 05 Oct 2021 04:00:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431602; cv=none;
        d=google.com; s=arc-20160816;
        b=PPC4GSPLQmDKKXG1sVBbVO3uodpJqqA/IUh35k0+C9OR9YTSx9Bn7bgWayPMxhFIKA
         5bitDSACgEHvjRW2FIl1jis37eHOuGTon6YK68tut4mHOPiWAgJXInjzMU6ipIopj4W6
         WR1JEmx/aGPUR164zB5R7Qo4sRgN0DINxQEF27pboL2TyECuIYY/uC+ET/dR08qaoG2c
         EnoZxA3YxEwDxF/LC2HuChc05/mATp0OdDzZbZUcdy0gRmSbMUVWMs4DipMi+DaujszW
         SF7JC3Sii0fgoGyviPASVNTNfvLjMXM3o+QDF3KbDKkK3BnksDCSh/mcs6pk3suS0TK4
         VPdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=xsbn5DHOInVTvHdCjIbH8F7lYj2M2KByY98qL4y3tHQ=;
        b=RBu1yAfEY1z0hVHRVkrYzg/RX7KO/VrRPbpzRr5O1FT31zLR32OxSlWmZJwZ0CNyIT
         blfZXIUTZSQYnIr2zsiO2usvSOX9Q5o/VHQOWelnkRua9mXlZiSYPvtpAx7BMaIkuG8J
         ibXgiTN9CbhRtg5s7N9t+XCeyeT6aBi18csrR9167tQJPvNa+mGJKR8Wo+FGiaP1SDDT
         DvE1Y7AyLheIjF16IHNjBhRi+nYoNTNXL1avap8FR1crgGeD2j/8px0rCmGjAsv90m1N
         e3kmSBadD6ARfpyVh5HWP3IbeKgqxOYoOvRh0A49iR1Yg+GyeLe678741dWqxhL1+EhH
         2+xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=GzYNn8Bb;
       spf=pass (google.com: domain of 3mtbcyqukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MTBcYQUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id z21si761574ljn.1.2021.10.05.04.00.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mtbcyqukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id x2-20020a5d54c2000000b0015dfd2b4e34so5578324wrv.6
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:02 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:adf:a35d:: with SMTP id d29mr20140800wrb.318.1633431601839;
 Tue, 05 Oct 2021 04:00:01 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:50 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-9-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 08/23] kcsan: Show location access was reordered to
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=GzYNn8Bb;       spf=pass
 (google.com: domain of 3mtbcyqukcrqy5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MTBcYQUKCRQy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-9-elver%40google.com.
