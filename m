Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP5BYSEAMGQE2R332UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C343E44C3
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:52 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id i16-20020a0568080310b029025cd3c0e2bdsf7037102oie.1
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508351; cv=pass;
        d=google.com; s=arc-20160816;
        b=oKkPBK19nspp1QgdC/EcokEggvXQaZ4Ya/7zLhtCsTQceJOkYaZIbT2BrNiIBmkyZY
         lOSRSm9/wUzE4PozaymWsTpArHGaGSvSWU+uiXJd/BcFOPdBMcYCecaoUzNPWoHkeu+M
         U3fR/5yNAQfriTm1+Koa+vjo1JI6ubESjZ0u5K57P65tsssfn4s8SGpyUDJaIAcilh7P
         izobTGY0wVC+12Tx4Pzg6N6Hv59kQ8TNrbORAd+2zDgKxLbZHP3HbKCoWVzwoaccTZuN
         T6U/HxCv2oKK4u1GTk5t25PwsZrPrFlDOcDbCTNdQxyWDdltPBVSKnQtlvv881Dar4iZ
         ISzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3wNrkrYeriRkqTMKukvll4za0ytHY268ngAL9vtDGXk=;
        b=foVq3/zKeoVhK96qZ75GXTv7naVGT5nMbdc/zDyLCMBBabjaPtR3xKRxoym861NTQ7
         eQHq63EqvhtW2cis3tvaG3IjekEq1LEtUqZaCCn9XHhp0qqBe4HY/fxGhKNzrjyuzs/h
         th7TU6xYyAz1DS3aqtajLyRVepJGyaMAqb7rUkeVMdc+n1tmnST/euQ6IgG31bswkoOO
         QlqX/VHw0HyaXbH09MG7O1WO8H7fh2gRIlAlEIAWvIkegPrUiprUBK1FY+WdYCzXeVSY
         ci0fACK4U6T/PGBoRfJm5r8H9BgMrBYJxSS5rnUKAGaORSgw4nMfVFUrssLx0zxpflnq
         Bf/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TEAy3Joe;
       spf=pass (google.com: domain of 3vharyqukctmtaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3vhARYQUKCTMTakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3wNrkrYeriRkqTMKukvll4za0ytHY268ngAL9vtDGXk=;
        b=naCGBkW2BencIXcBRyDz8dAw2RoSm2ZytCPpHKNm47Z+QhzrczvkiI1xHBEnbW5c/e
         hJ5ZOfQKhpJ/RYky2V7jbTjfepEJV6SSVXZmFtFH5nYFlZWzbj24lPIbHQm6Ohyqn0Bq
         TUJSkjIaZ1CwYHeo+U49oRxr9DZykH9KBQ5Jx0AmvgAKiSRYmdI2kgCd9HED3fNqYdgF
         A+WggAwmv0UKfdbNsHx/mkrYI8eBPZmjz7yxw6Gf6MP8iI7+Wr2uZzv5znLDGP/C9oqo
         za0W+RaTZGSqFRuDsAQ49fOqzA7DeCIFitiILYlrl2awrAUr/16C6XH1xbKGLA6Jyd/5
         TGLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3wNrkrYeriRkqTMKukvll4za0ytHY268ngAL9vtDGXk=;
        b=ZKrlyPNVDlG8l5uaaf05rh76JZHDJHLQPQMQLIACsRJumCtzycayQeyxnVt0nLxyw4
         wtCrrjHpStcOUGPxuz4RsiFbxi0Vcgez6RECAuci8Z8oAooTjLZYI02eRhVD12eVBB31
         5p41MaPrJqNxWM/07jwKx1sYA6T5P7nag7YwDjtVVOP8aqZlBaQFw8QDSSdj6je+BENB
         4WJFvlWSQHlg5Q7CyIEhAAWsAaEd0IbPAycdhe/wvk6L1oVbjnELb8dHhaSgiyl6YmPV
         92g35+IEVMstytKQzTqLBODhjLutCO8l2Ih+64QtBLNS1odkG99kjtdbnm+DwAgcy1r9
         YH2g==
X-Gm-Message-State: AOAM532mz3X1PhESyp3HmkXyemCfwn393qvFmrOGMSwXuml4PI7RgA8k
	+gtlo9dtiXOn+e0szKEAPw0=
X-Google-Smtp-Source: ABdhPJwtJyC3p+n91GnfKmRT8yolQsyjLmlYY/0R1m4sYuiE4LZKvoI//9/OPGNLp+iNXesOTLcsGQ==
X-Received: by 2002:a05:6808:114f:: with SMTP id u15mr3737852oiu.163.1628508351145;
        Mon, 09 Aug 2021 04:25:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3790:: with SMTP id r138ls113947oor.5.gmail; Mon, 09 Aug
 2021 04:25:50 -0700 (PDT)
X-Received: by 2002:a4a:1804:: with SMTP id 4mr14619621ooo.54.1628508350734;
        Mon, 09 Aug 2021 04:25:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508350; cv=none;
        d=google.com; s=arc-20160816;
        b=uRCE9yoUvOdYkCyHIvs9fW4cf0RGVUauaBiz7XVxJdfSflaz+8k8hLBF8jweBN1cSv
         jShAP9Fiyr953n47zCiZQZcCZheDya+a6rRQp/y/TMhx7JSEpclNNc0nFV+wN4M6dTLQ
         TN5Z6gm20KeQ1wGKp+rzADowNDEmuOz6RSH4mLh4KEU8dH2/rhsVu8ntfsZWJhoRRQhf
         oR2fNi+tUt9GxQVoATzODvT4HTUU0W5DNi5psGvjOk+evCms+Mvg4Mbk628uLkNH4MJs
         Xcg2QHT/yRXz6fqfKNmXfHFRkzgPDQZSHNWcyRbnIp1j6drGzMQD0swkWl4bmx9HrrA0
         ggwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=EAMypyoEmRp/mmdsUbAy/IShN4ZX4EbgjctTw6o3qXc=;
        b=EgTqDwuGEo0zzvK/00YHvkhaWgzG6EraQoeStGy2SaW3gNevnu1GiDyyN+jeLf6ifs
         n8kwq6zt8Nmq68iGEvOENyKbqsteqDg8l+ZPPtGoWIOzFyaya3D0SJ7lCVJnxQP3JSSf
         7uRRZ5iuc+jZFaeRsXc5MfvqSBQ1qrkJ2xMMuzBmEai9oIOqBiF5xjI8z3xuTipg5mke
         1boEU6SQWa7n+GTIvBYCrfxoxGxzE7xJ26YLZDFgHxn833tHi6eEjJLKXB6ZsrzSj8eW
         SDhkVlK/f0ZsJv2whFCQv3vsTs0n33eqWb/Vqdq03EU7ITMtDW3o7iHz6RnbkJDOokY3
         j4hQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TEAy3Joe;
       spf=pass (google.com: domain of 3vharyqukctmtaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3vhARYQUKCTMTakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id k2si372417oou.2.2021.08.09.04.25.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vharyqukctmtaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id q9-20020a05620a0c89b02903ba3e0f08d7so244280qki.3
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:50 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:a05:6214:d1:: with SMTP id
 f17mr12117201qvs.12.1628508350253; Mon, 09 Aug 2021 04:25:50 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:14 +0200
In-Reply-To: <20210809112516.682816-1-elver@google.com>
Message-Id: <20210809112516.682816-7-elver@google.com>
Mime-Version: 1.0
References: <20210809112516.682816-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 6/8] kcsan: Start stack trace with explicit location if provided
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TEAy3Joe;       spf=pass
 (google.com: domain of 3vharyqukctmtaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3vhARYQUKCTMTakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
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

If an explicit access address is set, as is done for scoped accesses,
always start the stack trace from that location. get_stack_skipnr() is
changed into sanitize_stack_entries(), which if given an address, scans
the stack trace for a matching function and then replaces that entry
with the explicitly provided address.

The previous reports for scoped accesses were all over the place, which
could be quite confusing. We now always point at the start of the scope.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 19 ++++++++------
 kernel/kcsan/report.c     | 55 +++++++++++++++++++++++++++++++++++----
 2 files changed, 61 insertions(+), 13 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index e282c1166373..a3b12429e1d3 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -338,7 +338,10 @@ static noinline void test_kernel_assert_bits_nochange(void)
 	ASSERT_EXCLUSIVE_BITS(test_var, ~TEST_CHANGE_BITS);
 }
 
-/* To check that scoped assertions do trigger anywhere in scope. */
+/*
+ * Scoped assertions do trigger anywhere in scope. However, the report should
+ * still only point at the start of the scope.
+ */
 static noinline void test_enter_scope(void)
 {
 	int x = 0;
@@ -845,22 +848,22 @@ static void test_assert_exclusive_writer_scoped(struct kunit *test)
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 		},
 	};
-	const struct expect_report expect_anywhere = {
+	const struct expect_report expect_inscope = {
 		.access = {
 			{ test_enter_scope, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_SCOPED },
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 		},
 	};
 	bool match_expect_start = false;
-	bool match_expect_anywhere = false;
+	bool match_expect_inscope = false;
 
 	begin_test_checks(test_kernel_assert_writer_scoped, test_kernel_write_nochange);
 	do {
 		match_expect_start |= report_matches(&expect_start);
-		match_expect_anywhere |= report_matches(&expect_anywhere);
-	} while (!end_test_checks(match_expect_start && match_expect_anywhere));
+		match_expect_inscope |= report_matches(&expect_inscope);
+	} while (!end_test_checks(match_expect_inscope));
 	KUNIT_EXPECT_TRUE(test, match_expect_start);
-	KUNIT_EXPECT_TRUE(test, match_expect_anywhere);
+	KUNIT_EXPECT_FALSE(test, match_expect_inscope);
 }
 
 __no_kcsan
@@ -889,9 +892,9 @@ static void test_assert_exclusive_access_scoped(struct kunit *test)
 	do {
 		match_expect_start |= report_matches(&expect_start1) || report_matches(&expect_start2);
 		match_expect_inscope |= report_matches(&expect_inscope);
-	} while (!end_test_checks(match_expect_start && match_expect_inscope));
+	} while (!end_test_checks(match_expect_inscope));
 	KUNIT_EXPECT_TRUE(test, match_expect_start);
-	KUNIT_EXPECT_TRUE(test, match_expect_inscope);
+	KUNIT_EXPECT_FALSE(test, match_expect_inscope);
 }
 
 /*
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 50c4119f5cc0..4849cde9db9b 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -8,6 +8,7 @@
 #include <linux/debug_locks.h>
 #include <linux/delay.h>
 #include <linux/jiffies.h>
+#include <linux/kallsyms.h>
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
 #include <linux/preempt.h>
@@ -301,6 +302,48 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 	return skip;
 }
 
+/*
+ * Skips to the first entry that matches the function of @ip, and then replaces
+ * that entry with @ip, returning the entries to skip.
+ */
+static int
+replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip)
+{
+	unsigned long symbolsize, offset;
+	unsigned long target_func;
+	int skip;
+
+	if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
+		target_func = ip - offset;
+	else
+		goto fallback;
+
+	for (skip = 0; skip < num_entries; ++skip) {
+		unsigned long func = stack_entries[skip];
+
+		if (!kallsyms_lookup_size_offset(func, &symbolsize, &offset))
+			goto fallback;
+		func -= offset;
+
+		if (func == target_func) {
+			stack_entries[skip] = ip;
+			return skip;
+		}
+	}
+
+fallback:
+	/* Should not happen; the resulting stack trace is likely misleading. */
+	WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void *)ip);
+	return get_stack_skipnr(stack_entries, num_entries);
+}
+
+static int
+sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip)
+{
+	return ip ? replace_stack_entry(stack_entries, num_entries, ip) :
+			  get_stack_skipnr(stack_entries, num_entries);
+}
+
 /* Compares symbolized strings of addr1 and addr2. */
 static int sym_strcmp(void *addr1, void *addr2)
 {
@@ -328,12 +371,12 @@ static void print_verbose_info(struct task_struct *task)
 
 static void print_report(enum kcsan_value_change value_change,
 			 const struct access_info *ai,
-			 const struct other_info *other_info,
+			 struct other_info *other_info,
 			 u64 old, u64 new, u64 mask)
 {
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
-	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries);
+	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip);
 	unsigned long this_frame = stack_entries[skipnr];
 	unsigned long other_frame = 0;
 	int other_skipnr = 0; /* silence uninit warnings */
@@ -345,8 +388,9 @@ static void print_report(enum kcsan_value_change value_change,
 		return;
 
 	if (other_info) {
-		other_skipnr = get_stack_skipnr(other_info->stack_entries,
-						other_info->num_stack_entries);
+		other_skipnr = sanitize_stack_entries(other_info->stack_entries,
+						      other_info->num_stack_entries,
+						      other_info->ai.ip);
 		other_frame = other_info->stack_entries[other_skipnr];
 
 		/* @value_change is only known for the other thread */
@@ -585,7 +629,8 @@ static struct access_info prepare_access_info(const volatile void *ptr, size_t s
 		.access_type	= access_type,
 		.task_pid	= in_task() ? task_pid_nr(current) : -1,
 		.cpu_id		= raw_smp_processor_id(),
-		.ip		= ip,
+		/* Only replace stack entry with @ip if scoped access. */
+		.ip		= (access_type & KCSAN_ACCESS_SCOPED) ? ip : 0,
 	};
 }
 
-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-7-elver%40google.com.
