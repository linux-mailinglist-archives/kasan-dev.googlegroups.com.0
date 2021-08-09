Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOVBYSEAMGQEYL5C3MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A1C23E44BF
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:47 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id h18-20020ac856920000b029025eb726dd9bsf7463787qta.8
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508346; cv=pass;
        d=google.com; s=arc-20160816;
        b=pRtrA8xlPsYAIFFSa45E0Cwjk8XzrOww1tQ+SVSlex1J4AFBBh2Zc7GDPZ7BehoOw/
         hQmuXRMYEtkStug4AZ1JZcTmsBA7VFHC50Aan4hXTBF5E5xOaGrEYZCySC1R2ix4XWiT
         DXyi9Cg2iif9Hv1eiG6Vv1T3MPugyEdiiOZYf6vG90f79/kA8Rj3J0cYkWvC+9Eq3uH1
         4vK8AHgjANq9KJmU7dsu3Exo6tMFXf4YkJJd0QQSXXYv6Fr9ogPQQ8PcAjyvOABmJKtN
         IFbyK/JmHg1kLeK/LNMWL2exGjHBT3KD6OlAWskNnvDDKjMNPC0x9gi73CYfN4suE34u
         ZqjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=V48k5XIAFJfI74dHzGQX2bU9RxeiXORIMr6m4fBlcGQ=;
        b=Uq5ZjHVvIwpHnn/cqddP8PWuKWAN0a4CNhCMRaQVKIcSte18z+7fB2KnS2DwAhAAUU
         7N/Dag2VLdPnJkMBzZH0jit3E/mlDK23JEON0WBlXuK0O3WfBBizyNOf60MUUlNZXdTJ
         X2k7Ggg4XyH41B1V1x9oPRq04+DYcKqNmMBk/qWXzOCw3Lx1rjNOcHyk7XubaQmYhuSA
         lvQ0U6gOeyoTsDTrpkfbGFWnYr4J+t64U8TmoahawSPApMpOxAkiUXd+B+HSxijtggCl
         ZNC1H72fVoNNqn5jTCWBrfM0apneDQt6iTJ0c6o/2cj5Jgw19D6o/IxZHlneRF4uSoih
         dMnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gybcbx7D;
       spf=pass (google.com: domain of 3uraryqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3uRARYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V48k5XIAFJfI74dHzGQX2bU9RxeiXORIMr6m4fBlcGQ=;
        b=nlJcUf/ApXQlYu6fHo/JfJv+suuiDBj/FyYdfHQxkssSkpqGXsi+tPPACQmW3OOfG2
         ln/pOfP05m50ltDtbASDp/K9XjxONF47UG2EWr7uCh/672/SHbqYfra912VBOxszDNwl
         0qtgLiY8D6qVB4hwKbnR4QxTdUdU/x11MZTG63JEgfggMhvQEDsMtOrXPQvGZpKDOC50
         83xCBnhSVcRzqNkSELDFgvQgb5s8JxLc5sA5yMt/5VyukCaEXbh3vOztbEU75t2IfD88
         nYG+cHNmEUBenGGwK2bgRmoZlI8JhCNGSGnbERHhGVWt/oICGf1XLonK2s6MKfMWnRbj
         /hww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V48k5XIAFJfI74dHzGQX2bU9RxeiXORIMr6m4fBlcGQ=;
        b=QV16A3HO0lfYxrvGfxeQR/oXFuXdGHnOEfnahoQL4Sgq2snQeTKiTlDFXwPlPsJuuP
         2GCmNGJKQU14GllKaJhmBzvVMPDZyPDHFcAGylxayJwZd2MyVWfDS4PCUgmk9X7UDQGQ
         2uF4Sa3GqRDNbnLvuDI3R4UE9LYvn4EJOeFG8J42s76FKzABsksEPeSX/XasO3U7FYfP
         1NERqMmMnccrtb06sa64YfrMAXHORSn1PxzhkVnFDCIvh6QEnHkhKOgVCFspvm7R7OkD
         S46B9fALg3XM2+Tbth2+ZUrhA9cdIjYRdmXKLG1QG629GaRB8PMzUWm3LzcCsoc6b/Sr
         cZ8Q==
X-Gm-Message-State: AOAM5327UmN0x0Lo3SmXCFs3X0AxEZUtAv1aBTxbBYZlduOWX36vI1Va
	Th4tpJU/PWdlHwNOtgxaphI=
X-Google-Smtp-Source: ABdhPJwX49hbaVQRDbAyXheS4mPEziWOgtr54GcZUbN0899gmMHliFrxjvvYPBCZylLsPPW2zjRczQ==
X-Received: by 2002:a37:cc1:: with SMTP id 184mr10705684qkm.323.1628508346198;
        Mon, 09 Aug 2021 04:25:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4111:: with SMTP id q17ls6250051qtl.8.gmail; Mon, 09 Aug
 2021 04:25:45 -0700 (PDT)
X-Received: by 2002:ac8:5187:: with SMTP id c7mr1499182qtn.387.1628508345715;
        Mon, 09 Aug 2021 04:25:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508345; cv=none;
        d=google.com; s=arc-20160816;
        b=kod+vj6IFbxd8I5iD5RnZOGV4cDne3gRmMYQYzdl37tH1HxuUFXrSbuBXgF+qjqYvz
         w/2uhcEVdnNAnpD9x5e+d6Bd4+qfs1h1VugF3qdmhyH6bIRmD3/f5UpVjMhqzUMTlyLm
         JuJqxpd0xFAGK3hsaO7Anvx1GrY1xiquJJFlp+fT6dXl+UqVICdeZq3p6XL8Cr+TlDd9
         YCs+KD1TuC2wk3dBG2kv1T+VUWg3NqQXOMAiU4Gymdo/ggmc/tpywxtbeQmr5ews6O+0
         4kFbnCN0W1kwCpv2PVKubHvr6RknISnFufigDhst/k5P8iMv7iDJ24NqZiwQoXjTDeqc
         LuCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=IjiThGwuRkrniINoV9rDnWwojAYXJ1ow0v64nu+9jIE=;
        b=Ijt4d7X+jqaqFsvgECMForp9oHAF+snMVEZRSK9JqZwG16ffnx8XHih/HJAmEDXWit
         2/ZmChNg8lkt2r17rCfyYYc/4uwdZx2P+QtAMgDtSLLWMEPd/yXIwpAaU4vIYTBKtgE0
         Plf9IzMZHPkX0Fj9sPqtvtUwg8RtUgAVwwyObncCwqUFwKYHAPNz9nafJZHjAoMXrc4W
         MXuMQ6CfHRqan8MYTvfqFgp9ERrY69jRW8sVcbJQ7btp+aoHcuiVHHQqfYDQAKZoByQw
         TaBWVMlv9PWqGucMVpKSFW7TWeK0s3+pK/jG3OGQKJ/ZRhIqEjyih+E8KBGyH3myS+H1
         58yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gybcbx7D;
       spf=pass (google.com: domain of 3uraryqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3uRARYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id j3si378345qko.3.2021.08.09.04.25.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uraryqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 18-20020a05620a0792b02903b8e915ccceso12287991qka.18
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:45 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:a05:6214:f2e:: with SMTP id
 iw14mr11921075qvb.36.1628508345507; Mon, 09 Aug 2021 04:25:45 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:12 +0200
In-Reply-To: <20210809112516.682816-1-elver@google.com>
Message-Id: <20210809112516.682816-5-elver@google.com>
Mime-Version: 1.0
References: <20210809112516.682816-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 4/8] kcsan: Add ability to pass instruction pointer of access
 to reporting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Gybcbx7D;       spf=pass
 (google.com: domain of 3uraryqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3uRARYQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Add the ability to pass an explicitly set instruction pointer of access
from check_access() all the way through to reporting.

In preparation of using it in reporting.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c   | 55 +++++++++++++++++++++++--------------------
 kernel/kcsan/kcsan.h  |  8 +++----
 kernel/kcsan/report.c | 20 +++++++++-------
 3 files changed, 45 insertions(+), 38 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 76e67d1e02d4..bffd1d95addb 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -350,6 +350,7 @@ void kcsan_restore_irqtrace(struct task_struct *task)
 static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 					    size_t size,
 					    int type,
+					    unsigned long ip,
 					    atomic_long_t *watchpoint,
 					    long encoded_watchpoint)
 {
@@ -396,7 +397,7 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 
 	if (consumed) {
 		kcsan_save_irqtrace(current);
-		kcsan_report_set_info(ptr, size, type, watchpoint - watchpoints);
+		kcsan_report_set_info(ptr, size, type, ip, watchpoint - watchpoints);
 		kcsan_restore_irqtrace(current);
 	} else {
 		/*
@@ -416,7 +417,7 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 }
 
 static noinline void
-kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
+kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned long ip)
 {
 	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
 	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
@@ -568,8 +569,8 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
 			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
-		kcsan_report_known_origin(ptr, size, type, value_change,
-					  watchpoint - watchpoints,
+		kcsan_report_known_origin(ptr, size, type, ip,
+					  value_change, watchpoint - watchpoints,
 					  old, new, access_mask);
 	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
@@ -578,8 +579,10 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		if (is_assert)
 			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
-		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
-			kcsan_report_unknown_origin(ptr, size, type, old, new, access_mask);
+		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert) {
+			kcsan_report_unknown_origin(ptr, size, type, ip,
+						    old, new, access_mask);
+		}
 	}
 
 	/*
@@ -596,8 +599,8 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	user_access_restore(ua_flags);
 }
 
-static __always_inline void check_access(const volatile void *ptr, size_t size,
-					 int type)
+static __always_inline void
+check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
 {
 	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
 	atomic_long_t *watchpoint;
@@ -625,13 +628,12 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 	 */
 
 	if (unlikely(watchpoint != NULL))
-		kcsan_found_watchpoint(ptr, size, type, watchpoint,
-				       encoded_watchpoint);
+		kcsan_found_watchpoint(ptr, size, type, ip, watchpoint, encoded_watchpoint);
 	else {
 		struct kcsan_ctx *ctx = get_ctx(); /* Call only once in fast-path. */
 
 		if (unlikely(should_watch(ptr, size, type, ctx)))
-			kcsan_setup_watchpoint(ptr, size, type);
+			kcsan_setup_watchpoint(ptr, size, type, ip);
 		else if (unlikely(ctx->scoped_accesses.prev))
 			kcsan_check_scoped_accesses();
 	}
@@ -757,7 +759,7 @@ kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type,
 {
 	struct kcsan_ctx *ctx = get_ctx();
 
-	__kcsan_check_access(ptr, size, type);
+	check_access(ptr, size, type, _RET_IP_);
 
 	ctx->disable_count++; /* Disable KCSAN, in case list debugging is on. */
 
@@ -802,7 +804,7 @@ EXPORT_SYMBOL(kcsan_end_scoped_access);
 
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type)
 {
-	check_access(ptr, size, type);
+	check_access(ptr, size, type, _RET_IP_);
 }
 EXPORT_SYMBOL(__kcsan_check_access);
 
@@ -823,7 +825,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	void __tsan_read##size(void *ptr);                                     \
 	void __tsan_read##size(void *ptr)                                      \
 	{                                                                      \
-		check_access(ptr, size, 0);                                    \
+		check_access(ptr, size, 0, _RET_IP_);                          \
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_read##size);                                      \
 	void __tsan_unaligned_read##size(void *ptr)                            \
@@ -832,7 +834,7 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	void __tsan_write##size(void *ptr);                                    \
 	void __tsan_write##size(void *ptr)                                     \
 	{                                                                      \
-		check_access(ptr, size, KCSAN_ACCESS_WRITE);                   \
+		check_access(ptr, size, KCSAN_ACCESS_WRITE, _RET_IP_);         \
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_write##size);                                     \
 	void __tsan_unaligned_write##size(void *ptr)                           \
@@ -842,7 +844,8 @@ EXPORT_SYMBOL(__kcsan_check_access);
 	void __tsan_read_write##size(void *ptr)                                \
 	{                                                                      \
 		check_access(ptr, size,                                        \
-			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE);      \
+			     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE,       \
+			     _RET_IP_);                                        \
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_read_write##size);                                \
 	void __tsan_unaligned_read_write##size(void *ptr)                      \
@@ -858,14 +861,14 @@ DEFINE_TSAN_READ_WRITE(16);
 void __tsan_read_range(void *ptr, size_t size);
 void __tsan_read_range(void *ptr, size_t size)
 {
-	check_access(ptr, size, 0);
+	check_access(ptr, size, 0, _RET_IP_);
 }
 EXPORT_SYMBOL(__tsan_read_range);
 
 void __tsan_write_range(void *ptr, size_t size);
 void __tsan_write_range(void *ptr, size_t size)
 {
-	check_access(ptr, size, KCSAN_ACCESS_WRITE);
+	check_access(ptr, size, KCSAN_ACCESS_WRITE, _RET_IP_);
 }
 EXPORT_SYMBOL(__tsan_write_range);
 
@@ -886,7 +889,8 @@ EXPORT_SYMBOL(__tsan_write_range);
 				       IS_ALIGNED((unsigned long)ptr, size);   \
 		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
 			return;                                                \
-		check_access(ptr, size, is_atomic ? KCSAN_ACCESS_ATOMIC : 0);  \
+		check_access(ptr, size, is_atomic ? KCSAN_ACCESS_ATOMIC : 0,   \
+			     _RET_IP_);                                        \
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
 	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
@@ -901,7 +905,8 @@ EXPORT_SYMBOL(__tsan_write_range);
 			return;                                                \
 		check_access(ptr, size,                                        \
 			     KCSAN_ACCESS_WRITE |                              \
-				     (is_atomic ? KCSAN_ACCESS_ATOMIC : 0));   \
+				     (is_atomic ? KCSAN_ACCESS_ATOMIC : 0),    \
+			     _RET_IP_);                                        \
 	}                                                                      \
 	EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
 	void __tsan_unaligned_volatile_write##size(void *ptr)                  \
@@ -955,7 +960,7 @@ EXPORT_SYMBOL(__tsan_init);
 	u##bits __tsan_atomic##bits##_load(const u##bits *ptr, int memorder)                       \
 	{                                                                                          \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
-			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC);              \
+			check_access(ptr, bits / BITS_PER_BYTE, KCSAN_ACCESS_ATOMIC, _RET_IP_);    \
 		}                                                                                  \
 		return __atomic_load_n(ptr, memorder);                                             \
 	}                                                                                          \
@@ -965,7 +970,7 @@ EXPORT_SYMBOL(__tsan_init);
 	{                                                                                          \
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
-				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC);                    \
+				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ATOMIC, _RET_IP_);          \
 		}                                                                                  \
 		__atomic_store_n(ptr, v, memorder);                                                \
 	}                                                                                          \
@@ -978,7 +983,7 @@ EXPORT_SYMBOL(__tsan_init);
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
-					     KCSAN_ACCESS_ATOMIC);                                 \
+					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
 		}                                                                                  \
 		return __atomic_##op##suffix(ptr, v, memorder);                                    \
 	}                                                                                          \
@@ -1010,7 +1015,7 @@ EXPORT_SYMBOL(__tsan_init);
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
-					     KCSAN_ACCESS_ATOMIC);                                 \
+					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
 		}                                                                                  \
 		return __atomic_compare_exchange_n(ptr, exp, val, weak, mo, fail_mo);              \
 	}                                                                                          \
@@ -1025,7 +1030,7 @@ EXPORT_SYMBOL(__tsan_init);
 		if (!IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {                                    \
 			check_access(ptr, bits / BITS_PER_BYTE,                                    \
 				     KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE |                  \
-					     KCSAN_ACCESS_ATOMIC);                                 \
+					     KCSAN_ACCESS_ATOMIC, _RET_IP_);                       \
 		}                                                                                  \
 		__atomic_compare_exchange_n(ptr, &exp, val, 0, mo, fail_mo);                       \
 		return exp;                                                                        \
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index f36e25c497ed..ae33c2a7f07e 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -121,7 +121,7 @@ enum kcsan_value_change {
  * to be consumed by the reporting thread. No report is printed yet.
  */
 void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
-			   int watchpoint_idx);
+			   unsigned long ip, int watchpoint_idx);
 
 /*
  * The calling thread observed that the watchpoint it set up was hit and
@@ -129,14 +129,14 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
  * thread.
  */
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
-			       enum kcsan_value_change value_change, int watchpoint_idx,
-			       u64 old, u64 new, u64 mask);
+			       unsigned long ip, enum kcsan_value_change value_change,
+			       int watchpoint_idx, u64 old, u64 new, u64 mask);
 
 /*
  * No other thread was observed to race with the access, but the data value
  * before and after the stall differs. Reports a race of "unknown origin".
  */
 void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type,
-				 u64 old, u64 new, u64 mask);
+				 unsigned long ip, u64 old, u64 new, u64 mask);
 
 #endif /* _KERNEL_KCSAN_KCSAN_H */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 21137929d428..50c4119f5cc0 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -31,6 +31,7 @@ struct access_info {
 	int			access_type;
 	int			task_pid;
 	int			cpu_id;
+	unsigned long		ip;
 };
 
 /*
@@ -576,21 +577,22 @@ static bool prepare_report_consumer(unsigned long *flags,
 }
 
 static struct access_info prepare_access_info(const volatile void *ptr, size_t size,
-					      int access_type)
+					      int access_type, unsigned long ip)
 {
 	return (struct access_info) {
 		.ptr		= ptr,
 		.size		= size,
 		.access_type	= access_type,
 		.task_pid	= in_task() ? task_pid_nr(current) : -1,
-		.cpu_id		= raw_smp_processor_id()
+		.cpu_id		= raw_smp_processor_id(),
+		.ip		= ip,
 	};
 }
 
 void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
-			   int watchpoint_idx)
+			   unsigned long ip, int watchpoint_idx)
 {
-	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type, ip);
 	unsigned long flags;
 
 	kcsan_disable_current();
@@ -603,10 +605,10 @@ void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_typ
 }
 
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
-			       enum kcsan_value_change value_change, int watchpoint_idx,
-			       u64 old, u64 new, u64 mask)
+			       unsigned long ip, enum kcsan_value_change value_change,
+			       int watchpoint_idx, u64 old, u64 new, u64 mask)
 {
-	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type, ip);
 	struct other_info *other_info = &other_infos[watchpoint_idx];
 	unsigned long flags = 0;
 
@@ -637,9 +639,9 @@ void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access
 }
 
 void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type,
-				 u64 old, u64 new, u64 mask)
+				 unsigned long ip, u64 old, u64 new, u64 mask)
 {
-	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type, ip);
 	unsigned long flags;
 
 	kcsan_disable_current();
-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-5-elver%40google.com.
