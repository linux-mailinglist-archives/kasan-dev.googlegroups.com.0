Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZNBRPZAKGQEZ376D4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6072A159451
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 17:05:57 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id s25sf1313655wmj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 08:05:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581437157; cv=pass;
        d=google.com; s=arc-20160816;
        b=WbwcOiL9YTx6SSezEx+De0Ac+ue2UkBt0w52HmzqvvL38UvoYpKsBKF/D3IQPCMASs
         VTU0TqvuVts692ibpBIRycH3nPv/97OoxMlKTF8LtUmb21WrwhK0RV4QASXbCDPWuRoV
         b1rfKyYRA/+0Ekq+XWNCOWYezbbTPwmPOK8N1Kss/PHebTMbqHLJpmrtRKgkyRy0MzMf
         rTNdjzh+yPO9aLVAghTqwSotxNsS/6qBoLvSQ7+6yyXwrWSIR9/jd9BqS/36KqMF5QKs
         K7ZMLTtnag0K81uUcSMA3+sBaN2ua7lsycf/xVzMzHniQD2eBgf7sJksCKrqDvIHqgo8
         Qy/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=YHeYaIiQ3qH9TM5ZCuLQn/PDWKdT6rQtqWU4xXJePZ0=;
        b=brigbf/jmLmLW2maqjsdLos7QLd9ZF5GrNrnclhtxUy2KZatn2XvDNQteRKUVIXFBH
         53892lAfWOEjvGZ7jsSU9I6ijmSKIBytIAzjQM3sgDpW8nX7Ir6VI3ps4aDlFjTto30e
         eePWEpWD34GlL05RPSiUQ6Hlpau4SxZlUyjyUXII/QCnxqzprkQNnuKSeWsNHkk9Jtpb
         gChHfYLpF1pGp2b/XUSPU9Q1c5ZMXIUC2Wy0mQVUUMhk9jciNcpxo21C0op0lT0fLCwE
         PtcOp6wR/mxME/dc+rWPVUKe/MTSH/i1S1Sw0bgGlLW5FX6br/14XDBiyC1nwjD/0Vav
         WoaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NSbEWpRs;
       spf=pass (google.com: domain of 349bcxgukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=349BCXgUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YHeYaIiQ3qH9TM5ZCuLQn/PDWKdT6rQtqWU4xXJePZ0=;
        b=fVbWv7vkJg0F3byc7D4rHrETwQTgNRjojg9DTDS9hC/nRLvu63WcLw/V+lRoeFNwAO
         /4ZPe3ksGAsXb+FP+tgOTs60nRAK5Xwq9vdaxgbizB5vwoBH26O3hEvu9bNb6szqYnMh
         F/2GJD1TeBz1SFUrcmDSOHMSDb7EYadCgifjFDcoHra1RRTq3lS3wI9S+PjLFuxJWKYy
         jpJlYDA1zmn7kdZ1gOuhP+8IYPnFkjSsOE3nK9yUi+IuDrcb7fHKN3qf20CwBxTAikxQ
         jkV3nb7LM85bLvhkta5seCApsT0NzX3KA4R9ntmLwTJWcok1TohiuwWsIkZg9XqEu954
         LcDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YHeYaIiQ3qH9TM5ZCuLQn/PDWKdT6rQtqWU4xXJePZ0=;
        b=WmxNT+iNLdD14q2i615E78PbS7vWZikubOArVOgP6WERjtr9e1vswWC6Zjieq7GWjQ
         qFTXfnfsrfROQ/25+hfen8dX83hY7cYF84z7l4mruXD9usTD8l5Af/8PEYb5s5ecuUQk
         sabtLc2CJD/zF1tJ7wCyF/WLf1adFqXz7KIn8IBLTzOIXfAQUy0IUGA1d52EqAT0mYsH
         iMZV9QCcn4Y1hvanBTtbRnFOrpDWHG5IPRdtBiPHj1Xxwj+ZDBosDNanu26lj4h/hXKT
         WIsgQnv7+zN32GPi92/fC2rja0gAoWX5AVdeyr7EwatR5HVIkINdOH82K/HqLf90Yjbq
         HGQQ==
X-Gm-Message-State: APjAAAXCinxygc8R5OgFQKwuMlaiq+LRVSS6J77wIZduf/yuX1zth8EL
	IzbodDTo8nAK11kqar56qng=
X-Google-Smtp-Source: APXvYqw6rxRQHB6nXwOzRq1NHN0CP9c/j/8eX5jsWkhfz6gvxrnVc65GNeEZYwvuxl5moe8Hml8wAg==
X-Received: by 2002:a5d:5752:: with SMTP id q18mr9585436wrw.277.1581437157135;
        Tue, 11 Feb 2020 08:05:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:288:: with SMTP id 8ls3687153wmk.3.gmail; Tue, 11
 Feb 2020 08:05:56 -0800 (PST)
X-Received: by 2002:a1c:6308:: with SMTP id x8mr6494932wmb.80.1581437156369;
        Tue, 11 Feb 2020 08:05:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581437156; cv=none;
        d=google.com; s=arc-20160816;
        b=b1JtucUZkieO+wSoE5CW+Fbm4B2XH0isjy7ZvciqOEENqik/ih6dffirCVuV9+WxCz
         5aUDN7TIOuWVcP0MuY7UBniiJx5ujBrbwn7rIlEwdv4y2HwbPpmNAMG8vy85PH7nEW9r
         rHs79Yx4pBd/tctNHc7qUfOI3NEx84kghVZwM7Sn27gWBGnuayICp77vFppB1O74AUw6
         PTP7dS61mig1jUSZc+M1iAy/9lMTQqqY67bhIbnNotdEaeBBfPrFlbN7ltMEJGr3YbG3
         Hft+kz7mJZztoMgCMhy0wGIGAuchxwWMe0SeXKhZc3DLO9Q47g2dxyz8o2069vHklFS4
         FuPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=IEWEaZDheAZ38OwM/O2k0lFvb0/Si6DRYRmVuatFxC8=;
        b=oTIn4tPh8JjgKhKpNDs7Mm2gwB1dy5y5/Dkd6R4c73Nu5IGKYrN7fnB2yRS5nA7YHB
         W8lO59erDVwxn+Dr7xoIwwPaxthU5yVGT3ALs0vf+lMjK3i6/pHy+oqBg1o8ylmUdPw7
         kUZ/aKBK5LeKK5uwilkTz3ZMiDxITVvDquHiUMC1DgDawSH/KRYLNzYoGCnqIgPNIBpi
         sPPT0j7aKb04Y3J5TG7Pv9T1nGIpoTJ5gFFu7PuQ0F48VzUjeJHEXAjBLtCDv4aHLViB
         rBAtfTfsxb/Gpft1ngI5ZjBGZqw6LJ6dc5YNcZ3LbWGcqQhMO79/5feujQbXpFIGSkM+
         eyuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NSbEWpRs;
       spf=pass (google.com: domain of 349bcxgukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=349BCXgUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id p23si157598wma.1.2020.02.11.08.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 08:05:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 349bcxgukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s13so7121502wrb.21
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 08:05:56 -0800 (PST)
X-Received: by 2002:a05:6000:1252:: with SMTP id j18mr9816005wrx.103.1581437155723;
 Tue, 11 Feb 2020 08:05:55 -0800 (PST)
Date: Tue, 11 Feb 2020 17:04:21 +0100
In-Reply-To: <20200211160423.138870-1-elver@google.com>
Message-Id: <20200211160423.138870-3-elver@google.com>
Mime-Version: 1.0
References: <20200211160423.138870-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.225.g125e21ebc7-goog
Subject: [PATCH v2 3/5] kcsan: Introduce kcsan_value_change type
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NSbEWpRs;       spf=pass
 (google.com: domain of 349bcxgukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=349BCXgUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
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
index abf6852dff72f..d871476dc1348 100644
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
@@ -477,7 +478,8 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 }
 
 void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-		  bool value_change, int cpu_id, enum kcsan_report_type type)
+		  enum kcsan_value_change value_change, int cpu_id,
+		  enum kcsan_report_type type)
 {
 	unsigned long flags = 0;
 
-- 
2.25.0.225.g125e21ebc7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200211160423.138870-3-elver%40google.com.
