Return-Path: <kasan-dev+bncBAABBPFGTLZQKGQE6HA3DYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 0623317E7D9
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:30 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id y17sf7367387pfp.16
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780668; cv=pass;
        d=google.com; s=arc-20160816;
        b=RlTOcLzMc1ZAxRny7BEpAeLoD/aEG+36j9ft7lAFO87HUgrhaRC/wD6MQq61A1HnrB
         aEykPduKsebptXrpANWfj/EAISb+ro2WmdjRA3OLSB5qy3aS3Wl+MZIf6Tfy0tVBKok2
         YeBeq1qIiZJNKd3YID5ZaxBfLd9V/2iD2ehYMFKbUAmKfmncnDRbYR9F/G1+E95wZT5m
         91tBPqihpHrkgM00kNwcUGXQkV49iw6YgTR2PTEsG6PNG62FGpvgH8UQhZ+DoR2h6yyd
         8GopJjhh1XEMJufKu80JjvrPzO1YhhfiymKFufPQ0Ejq22feu2egdsRI0I/XpxdK3M5z
         G3iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=AtOeyvMxjXtPHgfrF+D0HZz/i4JSXHyvEojA1cTC7Gg=;
        b=UNALnb6Gs1S2lw1VWV2eaUKi14lshwZHHv9MZqiHvWHkNMA5CTTTYmXb4TGzkwXM3N
         or6WRdGaMsKuS/Lqy1rTVuHqJ6RA8E57cmXS3Dwi91lXbQoSE7Op4emaKhSkZmm385Te
         a7G4ZRHj5coHdLYq8e5S0tdB20A39eSTyJAfomKEP3NFcjX7Cxt+iqNKtDvgoCrHmHLH
         fpGyg3CeUt7i3v0vC4hfR4gsWCVlJGp6x7gAsiS7DKI7RT+3qkyn3aaX0/jhevPlVt3J
         6gAvJv2uJXce6mvGTwhksnrUDHGFLjbEnSuqhf1GCEY3MvnoyWUdQjTUGPmP2UKTwntT
         SFmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=qeoOBVhh;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AtOeyvMxjXtPHgfrF+D0HZz/i4JSXHyvEojA1cTC7Gg=;
        b=eaHPjwYpwXDKGvmB+F/XJgTA9AdNKFW5gMwB3RRLoHOiDEv8UQ0lKfmz8tbSsOVkaB
         DNKZwh7EPvob/pWQ18I8AgcpODP1EIfy0pZqTlyq4aG8lNzdK28tqYYo10B/97tjGVND
         hxDC0DkcjIKyIxN8+JkkMmJ/dfyKPXK7kauBO5KwoZFMPIpFh75B/2s1/wJkVfWlw4B1
         v/u3kIA1raGhwYQSCiUeXBI78ezMYklaD62wQZcXuLw/Y4BxFo0havpc85/7yK8OYg71
         3O4I7TJLdNnkAGh4o+K4KL2/jOipnq/1JXdxfnpDlSjkge6N0DScb2rnkrq+U8zK/iyT
         yKiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AtOeyvMxjXtPHgfrF+D0HZz/i4JSXHyvEojA1cTC7Gg=;
        b=R416/e8QZV68sCtvL+/xEQFmxSNZN1pS/eRfxihmTN7BppxWfN7wjN52SOjpg0+lAd
         xxayFJV6a7MBPCkrCpfGE6G/KuEFJy+vHiLc+Nx/JcsDajwIlzfsy/8OTZWzXlaammGy
         syfJZ/FNA+tTdvm3heDyI46S2GVLZw/BKKnt/glWzw1Xtovx96on3r0q9Ovk4qXiV8Mv
         uDLziaSX3UVxHLkfnND0sldXzuoOVr5e8iPf9i48T8zk4YXXmeXgoLFUaL0vSb6Uoonk
         XFYMXSVFrIGa4LXed9WgZZsuGsSMAj3aP6bw5UrQcsuf8IL157qVryNdM++eoEthC7qQ
         AlyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3kjHnakW9aCi3OTKexVSVTK26W4k/yeDP7N1ykjwkD//omjBXo
	PH7UHeV6HvcQ6Z10AdVypV4=
X-Google-Smtp-Source: ADFU+vuOhqRDo/jUc7I3hBW9u1P15kmAiNlumqqFTmxR3BEgfJqUHg61PyKWDbF+ThNsaK358nu74A==
X-Received: by 2002:a17:902:694c:: with SMTP id k12mr17084697plt.329.1583780668579;
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8a89:: with SMTP id a9ls3772815pfc.10.gmail; Mon, 09 Mar
 2020 12:04:28 -0700 (PDT)
X-Received: by 2002:a62:1bd1:: with SMTP id b200mr14667234pfb.33.1583780668200;
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780668; cv=none;
        d=google.com; s=arc-20160816;
        b=jHJlhwq5OqaD3i5+2Hssm2rmtWq+s+nQ6+onTEgwv4/qzH/upriycUheY3fjOiVkSl
         MuQ9vkR/MP6wQ0suyina/SNTwsLTcgLi9bIu6XD63muyhW2e00+NSGxxwv+66/GvS17o
         un6zdruLbYaUkGjkX8b6qoshjRlhoxK9yJrxbG36e9u8CACRzGEnQGgolF90I/Cb1TAr
         xsHUffR3Y2qeNOfm20pXhjrR0IOQQQfOHikhlgfEZ4LLTXhXZa/likDtQiFNPswmfkEh
         btQhLgGY0ErylmVmfidT/83x4C8UezX+iJWIxwFy6mWv3b3O9O7C2qUVJ4VKsKJWoWOt
         +vCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=zLpFhwDFuUIyZaO4QLzZXqPxCRP8cT58H6GcnvkafTA=;
        b=0l+22r+mwGLvaXlzRkUPbJLNLWne1440gwjtgx6uTUk6oJ5QYs5+y8S+43boe1/nR8
         48XkvBBUrqFI5+2xABYMxhU1qays3p8SGDzVm8RVbL5cRqFko9nzsSKYdzVhDHkbVXXk
         SxysV5plXKcnntjxqWkdPDfOJXPA1T6HbF+Xia4O14u9qswSn0nOnC/rRz/O1SGaRTqj
         p42sVlyU+yjOV5vjPC9qMlIW3QsGO5uQYL40A8/FISmBEi0CO7F4HfkkD8lkXZn4s3Wv
         24EsTBbnbyQv945Yo8Zr/ghUASbR71ffXedn+Tr1AJCBiYxK7SNVNWN2g+3oDtDhO1xq
         4YHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=qeoOBVhh;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q19si700880pgt.0.2020.03.09.12.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CE14B2467D;
	Mon,  9 Mar 2020 19:04:27 +0000 (UTC)
From: paulmck@kernel.org
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
Subject: [PATCH kcsan 23/32] kcsan: Introduce kcsan_value_change type
Date: Mon,  9 Mar 2020 12:04:11 -0700
Message-Id: <20200309190420.6100-23-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=qeoOBVhh;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Introduces kcsan_value_change type, which explicitly points out if we
either observed a value-change (TRUE), or we could not observe one but
cannot rule out a value-change happened (MAYBE). The MAYBE state can
either be reported or not, depending on configuration preferences.

A follow-up patch introduces the FALSE state, which should never be
reported.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: John Hubbard <jhubbard@nvidia.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c   | 38 ++++++++++++++++++++++----------------
 kernel/kcsan/kcsan.h  | 19 ++++++++++++++++++-
 kernel/kcsan/report.c | 26 ++++++++++++++------------
 3 files changed, 54 insertions(+), 29 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 498b1eb..3f89801 100644
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
@@ -436,24 +437,37 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
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
 		/*
+		 * Depending on the access type, map a value_change of MAYBE to
+		 * TRUE (require reporting).
+		 */
+		if (value_change == KCSAN_VALUE_CHANGE_MAYBE && (size > 8 || is_assert)) {
+			/* Always assume a value-change. */
+			value_change = KCSAN_VALUE_CHANGE_TRUE;
+		}
+
+		/*
 		 * No need to increment 'data_races' counter, as the racing
 		 * thread already did.
 		 *
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
index 50078e7..83a79b0 100644
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
index abf6852..d871476 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-23-paulmck%40kernel.org.
