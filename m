Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK5OZCTAMGQEYVD3FDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id EF109773997
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 12:21:32 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-686e7b27f55sf4021210b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 03:21:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691490091; cv=pass;
        d=google.com; s=arc-20160816;
        b=zJNSQJT1aSalU92+PiqDOOujlrIpRxiga/PxxP1aNPcs9/VoBjMSDNNZtFkirFsl6Q
         0Z0MEnDLJbYMHNVD1Z5F2yvPToZbacaH0DLidZCDBnoKMM6+jmw5f4VUhDA8n+WPjO2o
         b/MwpmgpG7nLuTv/YlwX5VAuXtFcVEkxCgKTvwoQIvq+s9FWRIbL6TjJq8Ri3IwY/DE8
         QS2mL3hXAsYznfz7O2+Gy2KHkIAVn+Ozj9bm1nr/9C9IPJ6akEFP6PqSKdQ9LBWjho2p
         XctgWijhVQ2iMh3G/Z2Uxc7bx+WYgx0xg/QOlBS12ZrDEo1e+KRrGPcTuqPsEvUhxjW5
         wAbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Njx33BUJBEs8T59S+VHNH6sAN8z8IdIzpQPa7/8qw+4=;
        fh=0+1A2GTyPkIZP1JqAjZ2aq5svYM3vBrC3jkZRiGb8LI=;
        b=l8AWXPWI3kxDgX5nuzLzKMMhRLnq4k3lqTNdncZdqjyUgyCRDD4CkxLAERDB838Ogs
         PG1KTEZsxFI9zQ0qvz+Z0eNSRN12M2RPjlwuUIYDInZetO9HAfODH2tr2ML/WWvf8Ny/
         whZbc0K4Rb5fuyTozfX9WiHQZgGJWpq2fkYjJI49iGlxgUAs25ySO6okENhvgpYZmjRP
         NovBK/ShPyr64YLdI4JxS/cnbpyof2mROfpP3T4Y+tnyMsT7SKgCDwzVRa5nel9qVEFs
         urePogyyjQc5arDTn0B0c6pvtRfbC9nTm0NStxC5dxHBvmmirpySddYBqGbvCk8lQ71w
         5llw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=eGKzGkRm;
       spf=pass (google.com: domain of 3krfszaukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KRfSZAUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691490091; x=1692094891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Njx33BUJBEs8T59S+VHNH6sAN8z8IdIzpQPa7/8qw+4=;
        b=bqar+6zXi7LWW/0JY1RjGa4ESQevd+Z7jt/KH5w5cbFpbqosecdEt3FfQP0FyNMYnC
         ZDVvSt41CxIt9yghJqQJmrSk217UekND6bN2yZKt0tqGtbFJLC6XjIteoQqJ1JtAiwPy
         NK66Z2jWj2AXOG/qVxg+Nsx6v76zIYSma18KfYdHGgE+VTCSy868LM43dRNssFq+dWD0
         4qytHjgidbmJNSe3m2RP5vr+/CMPf8hJhEqSkz0+ADDbTDWEQGSQu6xZyInvMDQt9eyF
         1WCmi/uT+MNO3C3ycXt1ZDWXGtghV18t3Zb7hF6n1VQog47VuGVopzn6YF21SDPdxaBi
         uuwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691490091; x=1692094891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Njx33BUJBEs8T59S+VHNH6sAN8z8IdIzpQPa7/8qw+4=;
        b=k+NiQuaCilhKmcY8H3V1dRqoy4eTiSNm30q/K49XUW2YN8RI2KLuCWB2xkofOSSVsh
         OYC5XTZExT942an1s2ngBZkBBwkzjD2ziTe/jr30F5PbI/wqZgh4moCBISCnWYSiIb7O
         BjlWuio5Sx8P6T3r/IFumm+/BmKIs75G/K3hDRXA6CvAHRsq+m9XP+dTOZzE1c3S57rV
         5quGjaZRrqAIRNo7FUHshJd/2kJrfeXo+1ZGBCly447Vywa49pLlyxHLxKY4+IHnokWw
         UASpDFEnCrZQN9wTw6CwfugMMvP/Fy+RJNxDI49uhJ9oq3RZbe/VkDIC6QtEMJUjKvHw
         KAVg==
X-Gm-Message-State: AOJu0Yzus2Sd1mZoO7/mrNnG6f32wdi1Gg9gXPzBLw0t+/i/HpLIe9jB
	V3Piq+ntNXUmAPc5UcO0pP96Yg==
X-Google-Smtp-Source: AGHT+IFhAZWzVv1P+2TztL/6FVOsZZ579uTxpOwdc45GWgeSn8kWnj4ddaw0bBcV0gvmC6GJjmrqsw==
X-Received: by 2002:a05:6a00:c84:b0:686:bc23:e20a with SMTP id a4-20020a056a000c8400b00686bc23e20amr13160729pfv.21.1691490091167;
        Tue, 08 Aug 2023 03:21:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7907:0:b0:687:b288:7b7e with SMTP id u7-20020a627907000000b00687b2887b7els1802513pfc.2.-pod-prod-05-us;
 Tue, 08 Aug 2023 03:21:30 -0700 (PDT)
X-Received: by 2002:a05:6a00:2289:b0:66a:2771:6c4d with SMTP id f9-20020a056a00228900b0066a27716c4dmr11781599pfe.4.1691490090112;
        Tue, 08 Aug 2023 03:21:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691490090; cv=none;
        d=google.com; s=arc-20160816;
        b=tdlRj8Hga8jq+NG/4IRj599Jk8iehBe1JO+qnCIZ6mQelV4bbEfJaXZcl1CPAk4zsp
         J2UIoLmg4X2290zwo6ZjGev1HMN7Ffd+eTggHf5NBmHNBKj2kuUi5MLewyxsiOUreurB
         Pv7T2rc3KOfWFmI2pRIy7NVTsLJM+/2BSMTowdCOSLsk7dWeWl8I4NBU+4DmTFfKjhBb
         82pPJQeCFG6/tcXMWBAXWiUO7k8YN/eHh8CEFDtwHTIZLDEuLuWAfAozHZH6NK/NXCXM
         Gx+hIsEp8th0oMkYli+3oj1d3kjKR8w1VPw3GS6fKwdCnKFuTuw69Ut3T6vYhZHwzOrb
         uHyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=LIkYxQB49dC0FQNHu2erIkpIfETNvfhvCz995ch8SuY=;
        fh=21lXPMSK2yK/sEXDyQrJ/fRnyJ9/L86+gRgt0otc1Cc=;
        b=Lbk/90oCh7RLl2axDyYFJg3vsTG9OmM+CtS11jAsjwzo8tnVVsTlhRrOnn8H2ek4qB
         dLuNlHePEw5RmwdbRavRE789vbI/O5N2ZvYapTxnwEZCtMcaj2XZPNnOhq4Qe6oqf96q
         PUwdFFGx/68ahqXXzeZI96uiAiczcPNrmq5tTg3EviiX7UN2peF1aJaDrrYuUdi0W4j7
         oEc4Xa5xvXYqfFrShblEjZH2JAEps9KdLKR8ZVk1u1eDQSxoh4OxJKrTAejvWwS20a2b
         QX9W2qIbZdf2lngFQn/c84npC3PxZu5nX+XYsgSyftGrlir6ZXEfB46Dl2Pooi/bfWUr
         9S7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=eGKzGkRm;
       spf=pass (google.com: domain of 3krfszaukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KRfSZAUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id dw20-20020a056a00369400b006866e984764si553289pfb.6.2023.08.08.03.21.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Aug 2023 03:21:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3krfszaukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-585f254c41aso64714717b3.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Aug 2023 03:21:30 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:39c0:833d:c267:7f64])
 (user=elver job=sendgmr) by 2002:a81:451f:0:b0:577:617b:f881 with SMTP id
 s31-20020a81451f000000b00577617bf881mr88047ywa.8.1691490089320; Tue, 08 Aug
 2023 03:21:29 -0700 (PDT)
Date: Tue,  8 Aug 2023 12:17:26 +0200
In-Reply-To: <20230808102049.465864-1-elver@google.com>
Mime-Version: 1.0
References: <20230808102049.465864-1-elver@google.com>
X-Mailer: git-send-email 2.41.0.640.ga95def55d0-goog
Message-ID: <20230808102049.465864-2-elver@google.com>
Subject: [PATCH v3 2/3] list_debug: Introduce inline wrappers for debug checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>, 
	Kees Cook <keescook@chromium.org>
Cc: Guenter Roeck <linux@roeck-us.net>, Peter Zijlstra <peterz@infradead.org>, 
	Mark Rutland <mark.rutland@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Marc Zyngier <maz@kernel.org>, Oliver Upton <oliver.upton@linux.dev>, 
	James Morse <james.morse@arm.com>, Suzuki K Poulose <suzuki.poulose@arm.com>, 
	Zenghui Yu <yuzenghui@huawei.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Sami Tolvanen <samitolvanen@google.com>, 
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=eGKzGkRm;       spf=pass
 (google.com: domain of 3krfszaukccww3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3KRfSZAUKCcww3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

Turn the list debug checking functions __list_*_valid() into inline
functions that wrap the out-of-line functions. Care is taken to ensure
the inline wrappers are always inlined, so that additional compiler
instrumentation (such as sanitizers) does not result in redundant
outlining.

This change is preparation for performing checks in the inline wrappers.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Rename ___list_*_valid() to __list_*_valid_or_report().
* Some documentation.
---
 arch/arm64/kvm/hyp/nvhe/list_debug.c |  6 ++---
 include/linux/list.h                 | 37 +++++++++++++++++++++++++---
 lib/list_debug.c                     | 11 ++++-----
 3 files changed, 41 insertions(+), 13 deletions(-)

diff --git a/arch/arm64/kvm/hyp/nvhe/list_debug.c b/arch/arm64/kvm/hyp/nvhe/list_debug.c
index d68abd7ea124..16266a939a4c 100644
--- a/arch/arm64/kvm/hyp/nvhe/list_debug.c
+++ b/arch/arm64/kvm/hyp/nvhe/list_debug.c
@@ -26,8 +26,8 @@ static inline __must_check bool nvhe_check_data_corruption(bool v)
 
 /* The predicates checked here are taken from lib/list_debug.c. */
 
-bool __list_add_valid(struct list_head *new, struct list_head *prev,
-		      struct list_head *next)
+bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
+				struct list_head *next)
 {
 	if (NVHE_CHECK_DATA_CORRUPTION(next->prev != prev) ||
 	    NVHE_CHECK_DATA_CORRUPTION(prev->next != next) ||
@@ -37,7 +37,7 @@ bool __list_add_valid(struct list_head *new, struct list_head *prev,
 	return true;
 }
 
-bool __list_del_entry_valid(struct list_head *entry)
+bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
 
diff --git a/include/linux/list.h b/include/linux/list.h
index f10344dbad4d..130c6a1bb45c 100644
--- a/include/linux/list.h
+++ b/include/linux/list.h
@@ -39,10 +39,39 @@ static inline void INIT_LIST_HEAD(struct list_head *list)
 }
 
 #ifdef CONFIG_DEBUG_LIST
-extern bool __list_add_valid(struct list_head *new,
-			      struct list_head *prev,
-			      struct list_head *next);
-extern bool __list_del_entry_valid(struct list_head *entry);
+/*
+ * Performs the full set of list corruption checks before __list_add().
+ * On list corruption reports a warning, and returns false.
+ */
+extern bool __list_add_valid_or_report(struct list_head *new,
+				       struct list_head *prev,
+				       struct list_head *next);
+
+/*
+ * Performs list corruption checks before __list_add(). Returns false if a
+ * corruption is detected, true otherwise.
+ */
+static __always_inline bool __list_add_valid(struct list_head *new,
+					     struct list_head *prev,
+					     struct list_head *next)
+{
+	return __list_add_valid_or_report(new, prev, next);
+}
+
+/*
+ * Performs the full set of list corruption checks before __list_del_entry().
+ * On list corruption reports a warning, and returns false.
+ */
+extern bool __list_del_entry_valid_or_report(struct list_head *entry);
+
+/*
+ * Performs list corruption checks before __list_del_entry(). Returns false if a
+ * corruption is detected, true otherwise.
+ */
+static __always_inline bool __list_del_entry_valid(struct list_head *entry)
+{
+	return __list_del_entry_valid_or_report(entry);
+}
 #else
 static inline bool __list_add_valid(struct list_head *new,
 				struct list_head *prev,
diff --git a/lib/list_debug.c b/lib/list_debug.c
index d98d43f80958..2def33b1491f 100644
--- a/lib/list_debug.c
+++ b/lib/list_debug.c
@@ -17,8 +17,8 @@
  * attempt).
  */
 
-bool __list_add_valid(struct list_head *new, struct list_head *prev,
-		      struct list_head *next)
+bool __list_add_valid_or_report(struct list_head *new, struct list_head *prev,
+				struct list_head *next)
 {
 	if (CHECK_DATA_CORRUPTION(prev == NULL,
 			"list_add corruption. prev is NULL.\n") ||
@@ -37,9 +37,9 @@ bool __list_add_valid(struct list_head *new, struct list_head *prev,
 
 	return true;
 }
-EXPORT_SYMBOL(__list_add_valid);
+EXPORT_SYMBOL(__list_add_valid_or_report);
 
-bool __list_del_entry_valid(struct list_head *entry)
+bool __list_del_entry_valid_or_report(struct list_head *entry)
 {
 	struct list_head *prev, *next;
 
@@ -65,6 +65,5 @@ bool __list_del_entry_valid(struct list_head *entry)
 		return false;
 
 	return true;
-
 }
-EXPORT_SYMBOL(__list_del_entry_valid);
+EXPORT_SYMBOL(__list_del_entry_valid_or_report);
-- 
2.41.0.640.ga95def55d0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230808102049.465864-2-elver%40google.com.
