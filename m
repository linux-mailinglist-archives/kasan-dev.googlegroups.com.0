Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5NARKFAMGQEK4LQ5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 94D5A40D0E1
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:50 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id e3-20020a056102034300b002d3180128efsf2108642vsa.11
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752309; cv=pass;
        d=google.com; s=arc-20160816;
        b=pzYVVnlKAqsk542XhLyYh14S/atKF2sKl6qZ6JL/fkYU/X2WtUWL4J4uU57lphgxus
         QF3tKbVzy+9Ks54cv5HKMzgtIuF+hD6DPmTsFeDRJnSKTDGKONBXmg1myuMJezHp3MZB
         OCGSGpZsmi0k47kjdPRx0mqtsBmgEkQd3u1VdEPtL+VfwUAso8UoA498SP3h0ZTMku1q
         G763bvTI7++iz44Yt/0f9DiUM+TkG0PJ+WoDZjU1ZcL48hMMSIwJ1669CqqN8RPO5mUE
         ZSy/hNwEGrdKeKQzW8BnvaT2sOguJUVIMSu1jZ1zG2csEQQkA7tTk2JNmn2n9ro9w/lt
         MOMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9IruJm0ulzi6LGqs7EEs7yWRXFbHsibnvpZKpH1VZL8=;
        b=ncx2ccQdSWBrgqD/J+RykjQwaxIkUn8rcrp/6XwucSmCoVtgRQDxr7/cxbAYEU8VrC
         ezuxDFhFISIk+ARD7l5G/53cWB/g4cH07U//aRYRmV/4BvrWF+YPwy7docAqKnDIOnM1
         KtGqWWicE61tLUR86Zku6vUVQix9LNXzCA186F8h4SejBDZdjd/AFuUnMU7YQUqrcLZv
         cYmzPEMQ/8Ea30iL76IflsYfWu/0wTXJlzu/Bz467hdKGcHfXqnBEyhZM76PZ3lI1/Sr
         uHE54XGdPSETs1FHsw3+nFLvqmn+MtCpdlZmfna1n465HPUiTc6XLORnv3PBTdVp7sCT
         FrKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QDIv7AuL;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9IruJm0ulzi6LGqs7EEs7yWRXFbHsibnvpZKpH1VZL8=;
        b=ttA6VaKrPFab0kz73gFZ3KjMlO4lbKTvcTqWc38LV7amTvBAdBmpwtbhWjIM0FPAPV
         0qviGODiZosx/TAmB+8a4g2kk6wttXlhP+V7UUSmyU70z88lDDKvSB4VciQlaEQlSOwI
         LOepMxTNvhvpZs713kF9ZlYRUjaNKBXxawLKCXeNRxguASVv4JrB3/9zHpvJRqmWG1sb
         Y54P7L63OvACSrbTzJzHQQDj31QxedatrdV9ugcOU//ZcIEw2wCEpiLoojtw66jWOfID
         iL/To127xZWIlI4qRgw9EyflN9oBPvXZG5XQnjbrKdP+mdTXXxGP3WAVcM2OcPpsJYxN
         bkyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9IruJm0ulzi6LGqs7EEs7yWRXFbHsibnvpZKpH1VZL8=;
        b=PWMyHQ1PKqG/DwNb+oAr+56IuUOvvyyd0Khm+G6dNxtE7czxtM1QiladmvNBnMy2Im
         D5Tv4OvZKMwK9EzpHCMG2Pa9//VlRiJEVu9XKA38yjWeV2oRKRccO2bGX87Zlsm5cOie
         oywZ42aVPLGLgiwx7U6U0sA5fllBkHbZD4+LdMGKFACW68pymLG5xCtVHeMOSbqzd4xV
         JKBSQTCOVjHp1IM9ZmRpCc+CgKhxNHJb/UmdAAwtyIUhArUO5KkzV2M5FJSKi3hShsKd
         AgtBwi1GklJl8EC1UnDKtEnYcStxoPU7bnB6GvUerhHut76jKY8hl7f3abher1WcWwsj
         y32g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5331YJo1dij06FSBIOe7myu2Nu65u6NZMexW44b/k7xqHOyLMAzL
	BLYZLg7x+q52ZeX9WApnzXo=
X-Google-Smtp-Source: ABdhPJzSKwlapTapjvAUi9OmNdI7+rDMlYbSee/bkHBNFwXMnxS/46O7J3nbFHMuFIlqktIdz6LVNw==
X-Received: by 2002:a05:6122:d8c:: with SMTP id bc12mr2570018vkb.2.1631752309579;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:48a6:: with SMTP id x35ls359792uac.2.gmail; Wed, 15 Sep
 2021 17:31:49 -0700 (PDT)
X-Received: by 2002:ab0:6357:: with SMTP id f23mr2578674uap.104.1631752309117;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752309; cv=none;
        d=google.com; s=arc-20160816;
        b=k20kgBgWAmYP67U74ZPbJ+VFZy4I3a6FrIghiEsflf/zJY54DkEenVX70lQ6LWSvmQ
         RsMWMluj2r2aAOY4kWfomT4xRMD8MhEDXEtCAPaeFFoQ4X/fzuiwk0HtW2EqPzAHI5zD
         IbOaJOGjNwpcKcPa3xLUTBB2eTQmJvgMOPkgocr8Wm7iQm66vu00HTqBmk2o/TCMolln
         xXbdo0QYT1RLDVsO+QF6q9zXHrrPU06paKulkJbHdGa659Saev13gipNqgbK87E2tfQm
         PMR5EQR4RufTgVMEougBAgazYtlAeRwb40avy0dxgctWNKhPA7atGQE7BfO/vVTFKjLh
         z1gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PyRjF+cJvvduLdC4GL2nIPiBDZ9QREDGD0YWODYWekM=;
        b=Qdhwh/HY7a5lY1UEIvTqGVioukK/7zGKH9qErU4snYgU34scm4C5SPfOgsv3GJMRlE
         X9ihS6DD7UvTDugkcwCpwZixc4DGimSbT/SMAq39N52CchcsXie+hW5gZaIC5TZyia9w
         d9oltCLurTjUfY8x4BgEIs2BgXxTXDe9/1jyj2QxMOENvqKdZ37pH2dkJ7Tfjro1oPjQ
         eJ+tYc5JTfKStYqDpVPBIT7lHlhJJ/JJYWWNvBwzL/7zVif4nJzYD1G8u5iWlWNDxWSW
         e68778IvpGmxOaw5vgC4smJqPXTZolKO4+lCUsvLF6S7gYlLjJrBk3Q6ao36Vob/oigw
         UxAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QDIv7AuL;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u23si330315vsn.2.2021.09.15.17.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D780C6108F;
	Thu, 16 Sep 2021 00:31:47 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B258D5C08E8; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 4/9] kcsan: Add ability to pass instruction pointer of access to reporting
Date: Wed, 15 Sep 2021 17:31:41 -0700
Message-Id: <20210916003146.3910358-4-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QDIv7AuL;       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

From: Marco Elver <elver@google.com>

Add the ability to pass an explicitly set instruction pointer of access
from check_access() all the way through to reporting.

In preparation of using it in reporting.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-4-paulmck%40kernel.org.
