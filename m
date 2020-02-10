Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWOIQ3ZAKGQELXHID4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 0404A1582E0
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 19:43:38 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id t23sf2908313ljk.14
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Feb 2020 10:43:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581360217; cv=pass;
        d=google.com; s=arc-20160816;
        b=ukg+8B2gIK/rD7XRw3WgxY1tRcOK/iSDLspAT2iuBdHPw+KHfdqb3l1hvx94zZQ2B9
         NEpmgZt+OSmnxO2tF3k7aaiIR5L2y4HOpLw0wPBSrJUdl5VdEFo2pxAKuObDbtJJEdjE
         XFkACl+osOX+rLhHGC6magKk8cxQiwMwa0rg0ULzcAftkTnhM/L+kPfTsdrKxpaiDqL4
         71nqWMCygSFu6M1rbp43MhYOqYDKn1yZM8p/gM7pgC0UFmx+iNaGPWVosPzg8F5oKb/b
         Szc57L1e98D9KDaN/tsfWJzdWgeBWIF80j2TSA8GQUfrX0lTRJGoJIUHRTdEuWHwCKBZ
         xG8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=DLV46070pptf9WLf3Wh/gwvYvkIcTu8g84427UG8Qlo=;
        b=MHY8ycAYQMHLe4qKpZB9ajX1tq6tbjZ9/SSknaLfXyNGLi9kckzPdmT9Jy7qJPOFxT
         C+9Sj87Ize3r2+ITBpfz3ZRAVh0C7bAaU1SEHjDxn2SLXOQOAEf0aKTgc7giy6nvc6Bk
         xNSaxhWyyRaKmqJNqv8jmWunGHbkjHGO6kULbQlQsz7pWgiwBhKgY619CjSPXZxVTUEX
         dChoPtsu9dubFLyZd0iZufkVff9icW15AxMgUY2H6ADTrBjEOQAumDYv9yYoPY+bLhU6
         mW4ZAC+p5aTF12aipZXdI1AiFojyNA669ytcTak/bbbAqdzcO5GnCqbfH1PLXrfo3jlr
         27Zg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rBTG4PRG;
       spf=pass (google.com: domain of 3v6rbxgukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3V6RBXgUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DLV46070pptf9WLf3Wh/gwvYvkIcTu8g84427UG8Qlo=;
        b=QezA9JU0FO+GA5aO//g+yCwgQTSiB/OafvE/Vjmf/OcnLeRYZ3THaDwvwmLCfRJfL2
         q1HRtm1s4oQqQX7jXY29y1DEc22GIXPe4hoPsScxou0NKyQvah8pNA+SBdzzzO48+onM
         7jWMpLLK80/BIxe6R/mTHvkv1j9EDFVdwst71EUQM2ce5kzXNgL8crCuxUKyfYfHZG40
         ImB9Y60UxxQY96s9qG2WsKp9qBVnso1QWy+VptPAqS008YvK/LnIypzEPk3uoHTLD8Bj
         6S5v5K9ZtaGRoFTx/R+ymoUriYf3bu3iH6ffBE3QUkt61mjAgDgLwlv3X73EwrTRb4vx
         o4iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DLV46070pptf9WLf3Wh/gwvYvkIcTu8g84427UG8Qlo=;
        b=mTGLpREer884Wwu0RaNcv8iCoZmF5uA29wY3xkkzVmlVBIpYkAI9t8MNrGOVdP7fWw
         /aFvKmEcFnmYb8XQ1X8LYufr29CxuIW86bqpBc3cUDWiKXCpGjEG7fKjQFEf+Q+/vQ1G
         EkIfy+mHbkuoswsr3O1a0A8RuoJMEEbDQHP/lxaPa5ZRIbCjmVDvItRo3dmXZBGjrNue
         Syr31AnnjO6KCRQjYYKEsQkq2kabf7u3gF0JiwZvwiU1Yz34Lw1z/3gzKipEwAAkUa97
         +P+T9SxBzR6oygHHnPozK27sB9gOExbM0FFwqQy5JfLC40sho5CzOVSbUELMgs/SsxeJ
         9KXg==
X-Gm-Message-State: APjAAAWYKbPadCQ+F4nQe1ZorYTuvmWgI6VnLdh1VGKGBwNWh3jHcdwV
	ptFsommTazoGrccpal+vv6Y=
X-Google-Smtp-Source: APXvYqwSCYRQJgVQ5nh2XhHNGAzdLSFfBT8eS7InoqqkIQpjIp3+RNTEg7twxxxwL8ABHavP2+VEXw==
X-Received: by 2002:a2e:8490:: with SMTP id b16mr1772248ljh.282.1581360217461;
        Mon, 10 Feb 2020 10:43:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6809:: with SMTP id c9ls1624955lja.1.gmail; Mon, 10 Feb
 2020 10:43:36 -0800 (PST)
X-Received: by 2002:a2e:556:: with SMTP id 83mr1719549ljf.127.1581360216643;
        Mon, 10 Feb 2020 10:43:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581360216; cv=none;
        d=google.com; s=arc-20160816;
        b=YTAnsooy4xmQlJk34PA67pOazB6hGzLOCE14EcYTbeO3UnBIKjqYs+/oqPmTAOaXXN
         HvoStOlDouEAsKKNc0S3pzhzfezzEDzrcVViQI9B+vr8XmhQlPC11nnSrmiOm0I83dZU
         R0+n3Fw1O1w/gLJGR25EBdzs48KIPkAzCcwmNAdPkEvW3Su3/0rpsuRp+m+qgC8k2GrB
         gPpAZXeYzX8NLfhelrqH03OOdjfAvjpdnOXv92Te+QlMJLls8an7qv3cntKnL1OU8d0u
         pKxDvXITSPUnAIdlMhafqDnRh/AjoejmNFNqlqfO7+Yy9S0gm8kVITMOCI39fUquOHsS
         YI6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=fLVK9tOKi3j2sgDhQvmP7LlmkApH3ddAFsS+qtUFyqE=;
        b=n+B4Wx0TAZdnECi1w/kqAPjiq1Pekj5MYAkn0x6h7BuEDotgPTEtdHyM2ZKVR2y6A8
         n5C8XG1lU2HyJBk4UBLVpB2Ir/QuhkgvhC4EGmdYk3E9xVsWMvInHEajdAzra0OqAFqf
         YdWXb+UCeBbdLE0njxgNHDKratYuxtnlXwyMFpn5scTif3Vuwaeq2ifB4X3N7QIxEH9V
         Nrj+5N4OZZugjEAoRKQw9B7EkGX8mBXrBFSiyxjt9ODWsoH6Z3Q0yuRzvUZpayX/YCnC
         rBY+iCST7vG8J6ezbzQdXlIHwApbj5ObrgYct9+SiYu82QaFFUlVaY5ftW61WTaxPyZJ
         8TNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rBTG4PRG;
       spf=pass (google.com: domain of 3v6rbxgukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3V6RBXgUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d8si61041lji.0.2020.02.10.10.43.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Feb 2020 10:43:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3v6rbxgukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id u8so5481918wrp.10
        for <kasan-dev@googlegroups.com>; Mon, 10 Feb 2020 10:43:36 -0800 (PST)
X-Received: by 2002:a05:6000:8c:: with SMTP id m12mr3442048wrx.142.1581360215908;
 Mon, 10 Feb 2020 10:43:35 -0800 (PST)
Date: Mon, 10 Feb 2020 19:43:15 +0100
In-Reply-To: <20200210184317.233039-1-elver@google.com>
Message-Id: <20200210184317.233039-3-elver@google.com>
Mime-Version: 1.0
References: <20200210184317.233039-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 3/5] kcsan: Introduce kcsan_value_change type
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rBTG4PRG;       spf=pass
 (google.com: domain of 3v6rbxgukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3V6RBXgUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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

Introduces kcsan_value_change type, which explicitly points out if we
either observed a value-change (TRUE), or we could not observe one but
cannot rule out a value-change happened (MAYBE). The MAYBE state can
either be reported or not, depending on configuration preferences.

A follow-up patch introduces the FALSE state, which should never be
reported.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c   | 38 ++++++++++++++++++++++----------------
 kernel/kcsan/kcsan.h  | 19 ++++++++++++++++++-
 kernel/kcsan/report.c | 26 ++++++++++++++------------
 3 files changed, 54 insertions(+), 29 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 498b1eb3c1cda..3f89801161d33 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -341,7 +341,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		u32 _4;
 		u64 _8;
 	} expect_value;
-	bool value_change = false;
+	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
 	unsigned long irq_flags;
 
@@ -398,6 +398,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Read the current value, to later check and infer a race if the data
 	 * was modified via a non-instrumented access, e.g. from a device.
 	 */
+	expect_value._8 = 0;
 	switch (size) {
 	case 1:
 		expect_value._1 = READ_ONCE(*(const u8 *)ptr);
@@ -436,23 +437,36 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 */
 	switch (size) {
 	case 1:
-		value_change = expect_value._1 != READ_ONCE(*(const u8 *)ptr);
+		expect_value._1 ^= READ_ONCE(*(const u8 *)ptr);
 		break;
 	case 2:
-		value_change = expect_value._2 != READ_ONCE(*(const u16 *)ptr);
+		expect_value._2 ^= READ_ONCE(*(const u16 *)ptr);
 		break;
 	case 4:
-		value_change = expect_value._4 != READ_ONCE(*(const u32 *)ptr);
+		expect_value._4 ^= READ_ONCE(*(const u32 *)ptr);
 		break;
 	case 8:
-		value_change = expect_value._8 != READ_ONCE(*(const u64 *)ptr);
+		expect_value._8 ^= READ_ONCE(*(const u64 *)ptr);
 		break;
 	default:
 		break; /* ignore; we do not diff the values */
 	}
 
+	/* Were we able to observe a value-change? */
+	if (expect_value._8 != 0)
+		value_change = KCSAN_VALUE_CHANGE_TRUE;
+
 	/* Check if this access raced with another. */
 	if (!remove_watchpoint(watchpoint)) {
+		/*
+		 * Depending on the access type, map a value_change of MAYBE to
+		 * TRUE (require reporting).
+		 */
+		if (value_change == KCSAN_VALUE_CHANGE_MAYBE && (size > 8 || is_assert)) {
+			/* Always assume a value-change. */
+			value_change = KCSAN_VALUE_CHANGE_TRUE;
+		}
+
 		/*
 		 * No need to increment 'data_races' counter, as the racing
 		 * thread already did.
@@ -461,20 +475,12 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		 * therefore both this thread and the racing thread may
 		 * increment this counter.
 		 */
-		if (is_assert)
+		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
 			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
 
-		/*
-		 * - If we were not able to observe a value change due to size
-		 *   constraints, always assume a value change.
-		 * - If the access type is an assertion, we also always assume a
-		 *   value change to always report the race.
-		 */
-		value_change = value_change || size > 8 || is_assert;
-
 		kcsan_report(ptr, size, type, value_change, smp_processor_id(),
 			     KCSAN_REPORT_RACE_SIGNAL);
-	} else if (value_change) {
+	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
 
 		kcsan_counter_inc(KCSAN_COUNTER_RACES_UNKNOWN_ORIGIN);
@@ -482,7 +488,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 			kcsan_counter_inc(KCSAN_COUNTER_ASSERT_FAILURES);
 
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
-			kcsan_report(ptr, size, type, true,
+			kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
 				     smp_processor_id(),
 				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN);
 	}
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 50078e7d43c32..83a79b08b550e 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -88,6 +88,22 @@ extern void kcsan_counter_dec(enum kcsan_counter_id id);
  */
 extern bool kcsan_skip_report_debugfs(unsigned long func_addr);
 
+/*
+ * Value-change states.
+ */
+enum kcsan_value_change {
+	/*
+	 * Did not observe a value-change, however, it is valid to report the
+	 * race, depending on preferences.
+	 */
+	KCSAN_VALUE_CHANGE_MAYBE,
+
+	/*
+	 * The value was observed to change, and the race should be reported.
+	 */
+	KCSAN_VALUE_CHANGE_TRUE,
+};
+
 enum kcsan_report_type {
 	/*
 	 * The thread that set up the watchpoint and briefly stalled was
@@ -111,6 +127,7 @@ enum kcsan_report_type {
  * Print a race report from thread that encountered the race.
  */
 extern void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-			 bool value_change, int cpu_id, enum kcsan_report_type type);
+			 enum kcsan_value_change value_change, int cpu_id,
+			 enum kcsan_report_type type);
 
 #endif /* _KERNEL_KCSAN_KCSAN_H */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index e046dd26a2459..57805035868bc 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -130,26 +130,27 @@ static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
  * Special rules to skip reporting.
  */
 static bool
-skip_report(bool value_change, unsigned long top_frame)
+skip_report(enum kcsan_value_change value_change, unsigned long top_frame)
 {
 	/*
-	 * The first call to skip_report always has value_change==true, since we
+	 * The first call to skip_report always has value_change==TRUE, since we
 	 * cannot know the value written of an instrumented access. For the 2nd
 	 * call there are 6 cases with CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY:
 	 *
-	 * 1. read watchpoint, conflicting write (value_change==true): report;
-	 * 2. read watchpoint, conflicting write (value_change==false): skip;
-	 * 3. write watchpoint, conflicting write (value_change==true): report;
-	 * 4. write watchpoint, conflicting write (value_change==false): skip;
-	 * 5. write watchpoint, conflicting read (value_change==false): skip;
-	 * 6. write watchpoint, conflicting read (value_change==true): report;
+	 * 1. read watchpoint, conflicting write (value_change==TRUE): report;
+	 * 2. read watchpoint, conflicting write (value_change==MAYBE): skip;
+	 * 3. write watchpoint, conflicting write (value_change==TRUE): report;
+	 * 4. write watchpoint, conflicting write (value_change==MAYBE): skip;
+	 * 5. write watchpoint, conflicting read (value_change==MAYBE): skip;
+	 * 6. write watchpoint, conflicting read (value_change==TRUE): report;
 	 *
 	 * Cases 1-4 are intuitive and expected; case 5 ensures we do not report
 	 * data races where the write may have rewritten the same value; case 6
 	 * is possible either if the size is larger than what we check value
 	 * changes for or the access type is KCSAN_ACCESS_ASSERT.
 	 */
-	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) && !value_change) {
+	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) &&
+	    value_change == KCSAN_VALUE_CHANGE_MAYBE) {
 		/*
 		 * The access is a write, but the data value did not change.
 		 *
@@ -245,7 +246,7 @@ static int sym_strcmp(void *addr1, void *addr2)
  * Returns true if a report was generated, false otherwise.
  */
 static bool print_report(const volatile void *ptr, size_t size, int access_type,
-			 bool value_change, int cpu_id,
+			 enum kcsan_value_change value_change, int cpu_id,
 			 enum kcsan_report_type type)
 {
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
@@ -258,7 +259,7 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	/*
 	 * Must check report filter rules before starting to print.
 	 */
-	if (skip_report(true, stack_entries[skipnr]))
+	if (skip_report(KCSAN_VALUE_CHANGE_TRUE, stack_entries[skipnr]))
 		return false;
 
 	if (type == KCSAN_REPORT_RACE_SIGNAL) {
@@ -459,7 +460,8 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 }
 
 void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-		  bool value_change, int cpu_id, enum kcsan_report_type type)
+		  enum kcsan_value_change value_change, int cpu_id,
+		  enum kcsan_report_type type)
 {
 	unsigned long flags = 0;
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200210184317.233039-3-elver%40google.com.
