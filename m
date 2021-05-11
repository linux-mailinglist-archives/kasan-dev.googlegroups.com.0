Return-Path: <kasan-dev+bncBCJZRXGY5YJBBGFE5SCAMGQE3XAFTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id C45AE37B27A
	for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 01:24:09 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id q79-20020a4a33520000b02901faafd3c603sf10023136ooq.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 May 2021 16:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620775448; cv=pass;
        d=google.com; s=arc-20160816;
        b=GBgBfE9tqUs43Pll509yzcUJ1ZuMFZ8IJaWlMwhM/cQa5hZucXd3aNx6bHQXqbtaSW
         H/G3zqf959rfB0XMlRSiFaTjJIxWzC9JLsHL8aYCeIzS0doJ2T1thz/YMuUD0U2VAdxI
         8lioKhL1ZN7janVrZFPQN/+5DWEnXqVsbC6E72hDqYoP/kiakXgnESbz5vZKBYawpYKB
         +npv2Tmam4tbl2WaK6z75bSpm3dtC7btb9ErIJ+KMDFyuqd0qqt+z0Ccn11EaKHl4S8g
         VJ15RJ/i2J7dMmjtrOdP/jRGo1SBdnB1yC1feOXMU0e3YVvbtcLQa43GA4WY8u2B3HmQ
         PQTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QVExkqiBiIS2JoyZs2VpdkZMRHiBMGXr2KXUiDpsgpc=;
        b=P+/r5eNT5quDvBkJ4JLJ1jkH3eYil68FuPP9Ms1we0n8dei8jJJJ339lBrppEp3ESr
         2djNN9uf3trp3Fv046iXsV748W1ZYjNi7JryWctkSmTDTMxnvl888shjUew1p4r69ptc
         jtAUNFQzs8JgnpUVHqokb0WkabEBFqXB4w4KAq49StWbr1gPE7jZI6vyI0lupEmmDOXr
         dcesbhBK69Uh9va5OxJZOoHUUA6NjGyOgi341aOW8OM18+S1JYBMmTqau/5qqBhOZw8v
         SaKvYea1iuigUj9ysbxFVmzN2k4218yuFfPgsYngB/xTeAX84CG2jky4Lj77ZRHs+5N1
         zwWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OdlhUWP0;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QVExkqiBiIS2JoyZs2VpdkZMRHiBMGXr2KXUiDpsgpc=;
        b=ZerGLZWZ6pJ9upHU5CbtHLHhXnJlq/pChv1TXhHKMXltfI1z2OVKqztwBBFoUPzy3y
         PPiwsA8KV8i/mYD42N5GtJa1uj0y0Dfy4BZZg766OcwkKvT0dW7/guNCuXYjqq2e5qtw
         M0Oj3d3wUt5EBvbUPYIuhZjIEyYLKabaLeG3utqxtbzNkepAO1ShL1YmQbBGoGEHlV/A
         xkLauY+lnuefDzpxx4U8jxdOPe57G8IFIkKYLSZiewspEO1F1ePZoWqTLssyJ7m9iXVF
         4HkugX2j9nMcALJ7v4FI6ckt8BEk+i3rIGFNVMlWQGWGMvBV1/V9LEXxy6I2NYXFAbYw
         akrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QVExkqiBiIS2JoyZs2VpdkZMRHiBMGXr2KXUiDpsgpc=;
        b=YfCTmxABdGRJ8OmD6bayV8l4uqd6LqGsIlxwuNlKLaFlW32SzgZSc99cp0GXYNcxm2
         i/S5HosqTBMD0hy5/gmmwmdV2c/a0eFCKzzqEBYXx+E9Kj3Xyg7XlEldbpU3xOd4UhBf
         8lbJXtWV8ZeI80rBRFX3sJfWTIKmRmry1rA9qKQQ6l+91laaMIyVjqIA3P+VvPvICmJ7
         3HuteOMPS4R+u9p8BGHcwDKY0MLYv1VR2R1CS/Iw8K7IYGbmwquYasvPe7zYaHL7AlHk
         QkGJ/mtb7LVkOk+LU+MUlBkdWX/HiqzB0b1/iYuF+6MznRawE4ajUbyo29vb6Hqn831M
         BLtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531JHMKjGQh1E1HQ67rPUVkiuUwOV8YUrGhg/KljxMIJIDWFzm4I
	QXCt7ykw9Rxm63TXZ+hznpk=
X-Google-Smtp-Source: ABdhPJwgojKdi3zJpVwFECUtQHo17jGhS8Z0zjjYnvvAAeAsO5DiwuRBFKkurocfMEPlvisd4A2K4A==
X-Received: by 2002:a05:6830:1184:: with SMTP id u4mr1737541otq.324.1620775448532;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9732:: with SMTP id u47ls27452ooi.5.gmail; Tue, 11 May
 2021 16:24:08 -0700 (PDT)
X-Received: by 2002:a4a:b915:: with SMTP id x21mr25423642ooo.16.1620775448210;
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620775448; cv=none;
        d=google.com; s=arc-20160816;
        b=CGQ43cl5IiNUSP7nDMe/i1baiNYJ7dfBki8H5fR8dL5yX0w3aCW4uHVdoAm6f2mmZ7
         WzfAQUkQc2zN7yKIYCMk0UdYhcBPYnu7XzMlpHukBSf2/2ldr0NPDikj0XJRJq8PJ6oj
         OJWshqXWxo0cpKD9Ilz9lMEg5jIfN6FhqJnsgIe7MGgToSZidEi8eUM/CtaCPMMYm3nd
         R9owQ9DFxQG8Knqg5MS+Wz1KuztDmddqDm7BMvVxKUtZkkxQc1K3Tou8YVyQwYKfoyrF
         MfXf+biOd27+rGikuwojl7wN4frI8Ljesk6rzApf1ees5dia9v5DIiFuW2g5WJmKePEn
         9neg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4yAEUL5OXEmi9YtKoUPypGh5ip4iIlTMBDv3BpLpqiE=;
        b=Dnqj1Sr1s33ytcNXwvS/e9cURK5usDvoD4xhG/kEOW8+DqWYKJIKmyfvNLQB3WzmmS
         1sIHati4wL8RN+UCiY6+iGJEwP1c/e3GTHK7YdiTR71C4f2o0QrXSPoAcL4LYg7xdYu+
         3600R56wT05wbckNW4hMiU/jteMhyGpxLa/2s+2ys8ZC+OyZ60UFsXLswyt0f759+4Ux
         NulCzsnZX9C2I4x3eveQ+Fm0hv1TexgnePv12u0BLoNc5b+J/3uxTqn9ZgFNA7OLwvB9
         dZOK5Jvo2smRO7bdkT8PL+UAJBP+yG+5pG+EMaYmZoSwQ4K7vzGJp9nB5BLVMFpHLETK
         yDTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OdlhUWP0;
       spf=pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n10si1225246oib.3.2021.05.11.16.24.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 May 2021 16:24:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id F2B296191D;
	Tue, 11 May 2021 23:24:06 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9E3575C09EF; Tue, 11 May 2021 16:24:06 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 03/10] kcsan: Distinguish kcsan_report() calls
Date: Tue, 11 May 2021 16:23:54 -0700
Message-Id: <20210511232401.2896217-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OdlhUWP0;       spf=pass
 (google.com: domain of srs0=6jxx=kg=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6JXx=KG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210511232401.2896217-3-paulmck%40kernel.org.
