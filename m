Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4FD3OBQMGQE6EXBBSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6931935F26A
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:28:50 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id v5sf623737pgj.7
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:28:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399729; cv=pass;
        d=google.com; s=arc-20160816;
        b=VBrDdR6lAaIADHZrQjS1CWWmZWHlx40lbG/F1tGnOU8o5ULt/IECLl+u6I+QYqLxn6
         9Sdsa6xKIPwjsBlr+gb2rvQgkaisNdYJKkQBOQyTCB+DGkBB6jXI4Ms7xzWhgB0eJ8Gv
         pTRtciwIlsUb0gdJcWLu4+j1rt5MGISJkBofaTtVO8I2CiylDa55GcuSO4ES3H3BA+DT
         SmyxMEQq4gJIOiPmbHJySiX0m2ELXY+9coZHtbWooZhAMP0fI8hvzA5YJ3rug2+F5ZI+
         PSxfhtfGxD2DX1Q6gGgzdUXheMFqzh58wrIZL3iJOgbBSUIdyrPSOK5qswGr1v84aU2W
         tJWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Q+1v0oFxAHlp2NMBaVWapLkBgKlJZAEEkSQ32fFywDs=;
        b=zqLcTfBumCdX24RFa3JgDFgXlyq3aQnzKZteSSS68WfPn6yv3nbmiU5uycybwp4FMK
         YBe1h0GAXkz0ercGuC2ttED4V+Gvow49Nrgtr+tE4OztxQe7PhFyO+aLmTgS/WiWRkqb
         D+bwQ71USMrE0Hs9b4/0fVbDcm4CFZImhsqNUtawR/RlERLhmBC48BP4nLA0Ok9EDL5K
         nYR1H2Vdu/JSaC3W/c5wLGMFuqOtK2HdsDGHkQv7n7hyDrRei1Dw2ytP/f/4CcNqdSHB
         v4huld4BO/gqFDZaYXVsv+pHDBp73UpucLYC81lNNs6lzBUbrceIbZ4laAduxul2XZl4
         U3jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZaPyMeCk;
       spf=pass (google.com: domain of 379f2yaukcxgahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=379F2YAUKCXgahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+1v0oFxAHlp2NMBaVWapLkBgKlJZAEEkSQ32fFywDs=;
        b=fxSdJMOTGJSaVu1F8eZLx2FAxzLIMVw/W+M0V7ZfTLZDbNM3DPQxm2wR+A/bJqnId6
         u1ZB42HDQmZ0ffkz9feTHocd3hQN5AC5/fLxBGYU/XNamo/DCxzj2k5hUlZBnXO5zOmZ
         RGKRxjuhLSs4TbDQO6GIqZnW8edVopgrJVtUzJug38Gv9qFs4Wlq+hFDG01v71w7H/UO
         1gTJ4smxRh9Cna+xX7vk0InyylNKaMnnfrM7/HMjwp97IpjNbnjaZJdO46+V2Mn5fWLG
         SI9dMNfzQfZQ6kg7PgPXOXwxOn6tzLyf83nNgXXq/1Jspt3Thmf2dysWrlxHT5zGyGMJ
         QIwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+1v0oFxAHlp2NMBaVWapLkBgKlJZAEEkSQ32fFywDs=;
        b=tEIqtpHMgjDG7Jybxw0RrZWwtQv2602DzegjfMerFP67+HrgxrMRfAvW/n8x/jBpkZ
         InfvKNUw9lCuRa9e0vqKim5NA7t9xx+ILQuy88wUVQjD2hfzQX1SzKmtJl1HW63tAaMc
         YQDAGXcPRqfOH/eRFPZlDuDjw7KeJS7irBGTn+8v9lS1uIP3dweVZ59/AJ6VQGgxRQJG
         JU7tMFxYzOAv9fZn2hV7mzYRVStbfA/u84YbgQTO8m03b/qgCtqr7Trguj+Mrxir1ZF2
         oRMXtpOm/U74gmqsxeQ1wQDQ42WYHgKKO2ql7eFVywN+oFAOTh3fGDXWSBWzITLg7dZA
         lmkA==
X-Gm-Message-State: AOAM530smQAEbZFXx3/tEcB8Kh0CXoJRhnI6zqDWJFACrXubjqPr6auF
	sKMgUgpF1fgOs8dfTg+WQNw=
X-Google-Smtp-Source: ABdhPJyNCXjrBlsobrdnHoitY4uJrOW0ujpC3pyc8gntMXjW2c40uvRNnHkVMyP6XDLvDRD0GTiyRg==
X-Received: by 2002:a17:902:760b:b029:e9:8bda:ae44 with SMTP id k11-20020a170902760bb02900e98bdaae44mr33382235pll.26.1618399729083;
        Wed, 14 Apr 2021 04:28:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bc47:: with SMTP id t7ls1102564plz.3.gmail; Wed, 14
 Apr 2021 04:28:48 -0700 (PDT)
X-Received: by 2002:a17:90a:5b0b:: with SMTP id o11mr3050377pji.150.1618399728544;
        Wed, 14 Apr 2021 04:28:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399728; cv=none;
        d=google.com; s=arc-20160816;
        b=ABHEnRuclqMnxBUwqL5p5mxtWqCw54pzGJmEiSf75tNf9Cnk8BKJ099fSgoJLlV02B
         81l0X2++Ge57PpCmZsLupvDrxKadRUyOdzAIwgXJbvwtwjjNWs/QJLBdyEe2A0uUXTTQ
         DN+pu7r59ptmLrT5vWRluox/sK/pWxO9l1cQahRApDaLc1X4WEZGCTBAuPcXbT/aOqVX
         3pXCTrAwzEc+S2XOFfTWlwW6eEtntLUkvOVuS+d/GrFVYf4il7l5Wjd7rTzM6tI5DDNz
         uEkz1wgnZKbMH51MlcoTmc3b0kRhSMjuIm22AYWV8My40KVTmNKyNJat/BnaJSyR5yNP
         GzQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mMtpkoi7Dg1KI2BVOCvCvQkqmnY+V0ww8kwlTHqSHyQ=;
        b=lCwqIpSRh6cKePZIYAFXq4344OWAluP2I82iicrQkwndoHtG/C730E1p3EE3DjuLWS
         7sMh4bVCr+b2AJ4Ao04zj1o+y8+0Tuhl1KdUmXC1YOA9wm1NrbfWTD78rbGr2nUXkRu4
         i6ltomrpT1NotjO9/OGMDqJnd2+5igFkAh9K+yfFo6sAXzfuB8U1+soeoX81E7cSGfjR
         vSw5ZLbRkYxQdtTWVetubuShs2g6i3v9CwGfdTe0pmoT0uJRfxbpLHtGjgxzj53l8OG9
         i08e/hT8IFXTnzkGFS+13HO5cQKfhxUB63GNDRgiJpAOetKNC6ubwyOOWt+ppap183SE
         37CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZaPyMeCk;
       spf=pass (google.com: domain of 379f2yaukcxgahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=379F2YAUKCXgahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id v22si355600pjn.0.2021.04.14.04.28.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:28:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 379f2yaukcxgahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id g9so810632qvz.20
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:28:48 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a05:6214:248f:: with SMTP id
 gi15mr37426775qvb.40.1618399727735; Wed, 14 Apr 2021 04:28:47 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:18 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-3-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 2/9] kcsan: Distinguish kcsan_report() calls
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZaPyMeCk;       spf=pass
 (google.com: domain of 379f2yaukcxgahranckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=379F2YAUKCXgahranckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--elver.bounces.google.com;
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

From: Mark Rutland <mark.rutland@arm.com>

Currently kcsan_report() is used to handle three distinct cases:

* The caller hit a watchpoint when attempting an access. Some
  information regarding the caller and access are recorded, but no
  output is produced.

* A caller which previously setup a watchpoint detected that the
  watchpoint has been hit, and possibly detected a change to the
  location in memory being watched. This may result in output reporting
  the interaction between this caller and the caller which hit the
  watchpoint.

* A caller detected a change to a modification to a memory location
  which wasn't detected by a watchpoint, for which there is no
  information on the other thread. This may result in output reporting
  the unexpected change.

... depending on the specific case the caller has distinct pieces of
information available, but the prototype of kcsan_report() has to handle
all three cases. This means that in some cases we pass redundant
information, and in others we don't pass all the information we could
pass. This also means that the report code has to demux these three
cases.

So that we can pass some additional information while also simplifying
the callers and report code, add separate kcsan_report_*() functions for
the distinct cases, updating callers accordingly. As the watchpoint_idx
is unused in the case of kcsan_report_unknown_origin(), this passes a
dummy value into kcsan_report(). Subsequent patches will refactor the
report code to avoid this.

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
[ elver@google.com: try to make kcsan_report_*() names more descriptive ]
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c   | 12 ++++--------
 kernel/kcsan/kcsan.h  | 10 ++++++----
 kernel/kcsan/report.c | 26 +++++++++++++++++++++++---
 3 files changed, 33 insertions(+), 15 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index d360183002d6..6fe1513e1e6a 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -380,9 +380,7 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 
 	if (consumed) {
 		kcsan_save_irqtrace(current);
-		kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_MAYBE,
-			     KCSAN_REPORT_CONSUMED_WATCHPOINT,
-			     watchpoint - watchpoints);
+		kcsan_report_set_info(ptr, size, type, watchpoint - watchpoints);
 		kcsan_restore_irqtrace(current);
 	} else {
 		/*
@@ -558,8 +556,8 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		if (is_assert && value_change == KCSAN_VALUE_CHANGE_TRUE)
 			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
-		kcsan_report(ptr, size, type, value_change, KCSAN_REPORT_RACE_SIGNAL,
-			     watchpoint - watchpoints);
+		kcsan_report_known_origin(ptr, size, type, value_change,
+					  watchpoint - watchpoints);
 	} else if (value_change == KCSAN_VALUE_CHANGE_TRUE) {
 		/* Inferring a race, since the value should not have changed. */
 
@@ -568,9 +566,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 			atomic_long_inc(&kcsan_counters[KCSAN_COUNTER_ASSERT_FAILURES]);
 
 		if (IS_ENABLED(CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN) || is_assert)
-			kcsan_report(ptr, size, type, KCSAN_VALUE_CHANGE_TRUE,
-				     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN,
-				     watchpoint - watchpoints);
+			kcsan_report_unknown_origin(ptr, size, type);
 	}
 
 	/*
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 9881099d4179..2ee43fd5d6a4 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -136,10 +136,12 @@ enum kcsan_report_type {
 };
 
 /*
- * Print a race report from thread that encountered the race.
+ * Notify the report code that a race occurred.
  */
-extern void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-			 enum kcsan_value_change value_change,
-			 enum kcsan_report_type type, int watchpoint_idx);
+void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
+			   int watchpoint_idx);
+void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
+			       enum kcsan_value_change value_change, int watchpoint_idx);
+void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type);
 
 #endif /* _KERNEL_KCSAN_KCSAN_H */
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 13dce3c664d6..5232bf218ea7 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -598,9 +598,9 @@ static noinline bool prepare_report(unsigned long *flags,
 	}
 }
 
-void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-		  enum kcsan_value_change value_change,
-		  enum kcsan_report_type type, int watchpoint_idx)
+static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
+			 enum kcsan_value_change value_change,
+			 enum kcsan_report_type type, int watchpoint_idx)
 {
 	unsigned long flags = 0;
 	const struct access_info ai = {
@@ -645,3 +645,23 @@ void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 out:
 	kcsan_enable_current();
 }
+
+void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
+			   int watchpoint_idx)
+{
+	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_MAYBE,
+		     KCSAN_REPORT_CONSUMED_WATCHPOINT, watchpoint_idx);
+}
+
+void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
+			       enum kcsan_value_change value_change, int watchpoint_idx)
+{
+	kcsan_report(ptr, size, access_type, value_change,
+		     KCSAN_REPORT_RACE_SIGNAL, watchpoint_idx);
+}
+
+void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type)
+{
+	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_TRUE,
+		     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, 0);
+}
-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-3-elver%40google.com.
