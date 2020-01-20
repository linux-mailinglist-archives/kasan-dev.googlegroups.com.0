Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7XNS3YQKGQEIESYWSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 69F5E142D07
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:19:42 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id v5sf22019811edq.8
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:19:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579529982; cv=pass;
        d=google.com; s=arc-20160816;
        b=NWnJqJioxCO7lowR+NQX4pnDba3ockw73XQI7raEfuMP+Ehmv0a4xvYmbsIHSJAauU
         /v8dHz2Ei7ab886RN80nYDmpbQq1R2hTt7KYWWXR87sAHAQrpyvP7OaKx2V4twj5gMAd
         nOENCyUEyrkw0FnASUQp1xdD2aoe8fNymqTqCwn3Tpjfrg2jh+6+grmzYsxKcwBcc/3A
         vkTzk2cEvaXhVlAVSoRSECG+RAJEaP1xqzu8qspGEinYLfHSPyTGzL5tycqdUkblP5Bk
         l8MzXAPkAmHI6OQwjy7wNLPzIF0Sf4xmjODho94eKqIJ9erkcfAUOGWuZsbEUTL0lNUg
         4kPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ZE8pZYdX/b930GW0WLPSycHgESU+pbli6WxpY9pvxos=;
        b=w0ksw9RCTB7DVrMT1402/feKbZWjhHGIu7U2wcdZuIiA5jOpAWtunbyDZSomANyk71
         bJJPj5lAa/NFte6aBM4PwI3WE1u+IU1ZBEjIE0nsWk1XcxBNJHHrBIv15pzg8ScIHVsX
         JW08cxRwN3jAaKDbxt6Z5po+0Hu5eWAas86s2hb1MaqvqWdeoIuLBRwE5saNsBLe8acx
         kN9hxZwlQy3JpWRVIHlTCMcjEpJIlhbVdTTosBp+mEOL2OVtjWf61oIHfvbKvI0dnl4m
         Sb3YLBHjgUIG22hfaJZ6y3AzXPlGbwzF4kcnUktvPvCW2erjXbXO96EN1xYPgIh29TbK
         /B2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UhbxWX6A;
       spf=pass (google.com: domain of 3_lylxgukcfcdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3_LYlXgUKCfcdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZE8pZYdX/b930GW0WLPSycHgESU+pbli6WxpY9pvxos=;
        b=NGHTj0jSBqGr3YAMUhP4wLUJ5hSXj3dJLqT5wH/cl9lRLJk5aa5lTp8h+36JPMZgoT
         OsoGpNhbCrNy2hxQN68Kn8a4zPqid3QzvRfQS4iP6FPmrvFBwKCnQwh2I4WKsgQY2SiK
         RwLD4nRt+bVZ5gztBya2TCgvQmUr0b5wsLA+jNqitQzYPRxQB68dYagzxkYzYrvRTEkx
         JSf7KXJUOaGFJJk7UpLXhTlefNal/1VgSKFtJlQhCCiKSk9goTkKI6p9YLliYT3h/xJ/
         xHJWNomocifaGaVoG35q99OZFVzE7vnm53ZzXbUPLMNvGneXEtTMsiMMhuoZtU38r5N8
         Lzpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZE8pZYdX/b930GW0WLPSycHgESU+pbli6WxpY9pvxos=;
        b=GbZ+1dJ6z+Y0AXXMElCh/8aKgXkdqm7ZJ1yOwGg9Lr+CCbuaO72r1SFiMyvqaTJMnD
         v6pRcyFGICy5Pb3bileAKGzt2zY96Q1Tspv3tEJmQXfNN/Giknf/DMND9R2s9Zq7o6IG
         jfbNgD3mXlQvl0wSDi/CPUz6INbSqclZ0OwKwjwthUsFqP+9nqLf/VieLGsd+i6McQQT
         We9lqG+zEbZBtcIMTMy44xxviVdfcPfm3Or7bwDuQB2mFDWKCJ7SBlLP5DpL2QFwuuSO
         nedUTdm3oyZ+hvoiI6qgyImO8Mx3/VAdzeAndguca3JTFu9DQ6SIesFcGsyI6aqrHdCw
         khwQ==
X-Gm-Message-State: APjAAAXJoaCyGKKqOKd8LHsUY2fw0FQF6legnAdfQ/2+4PmPvDj+xc8Y
	Om5H4lEKUe/M9Q5BDPL+QBg=
X-Google-Smtp-Source: APXvYqxHpzBfpxhOrbKyOU7qjSOuWykMq0iekb1CeVGEjOKLdB9FbD3Jk9B3XtykDFPTUrjnHOy7rw==
X-Received: by 2002:a17:906:f241:: with SMTP id gy1mr20902089ejb.345.1579529982120;
        Mon, 20 Jan 2020 06:19:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1248:: with SMTP id l8ls8110949edw.16.gmail; Mon,
 20 Jan 2020 06:19:41 -0800 (PST)
X-Received: by 2002:a50:8a93:: with SMTP id j19mr17882197edj.90.1579529981469;
        Mon, 20 Jan 2020 06:19:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579529981; cv=none;
        d=google.com; s=arc-20160816;
        b=jlhvh+wlNE9/9ftnBNC/27x5myV/nmkPUQk+jABK4eFoKlP+T44cLoOysTPs8dSn+c
         KmMtSLNkqv/JNdlNbYkWiTm1AHRLmuXS76Q9OjnUIt19vFFLXpFIoe9w5ktZR2K2b7g8
         1BKjW+zXwsoNc6S932v6+Mhacosn1q7HPUVbxwBQK2B0lYmeEQUNIS10lpIGKz8oIqBc
         ghlERNSYJLwxswX0wo7z2nTvZgq+3OFR4Hm4gwxBffH26jxRuM2433UKcdmFypE0vI7A
         Zwx45aheIdk7ZXGaq69a5sRMEUJZdvEkNt385pdkUxqkzKbEk5/8hIuhzOStTgEyWcXi
         mF/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Nfa3SPvPtmfv9OXDVBjRxJwd9iLaWZX/BpfniwtezQo=;
        b=ZW1dQyD7WSkn97G+6kl49ZNk2R5KR/eDqttJKE3bLzJZnS4iKl4vCVASNgjj7oGxA/
         eANHfErhSv2C6HysIRMVPem1uz82J0BWpzC2LQP0ypgAA0x8h/ibS4/l0xKySMSyu0ia
         JKT8CLpqFkHL+cqh3VvZqmgrjbFpPnbKN+w2Z5oMt24RGMzHXhRuFuESeUd1P7b19QZx
         WrTWdQuDyP1Zm5tQ2s7xu++pSSWH7GleXTo+r1EhUnK5TUIgsx5AFWl//wmS/xE3ZMJ/
         4o43PLsz61Ju/AkvCqVSU6H/vkHZFUad8Z4aYvjG56De/ILLv2EbrPcDM4ZXL26YMc7C
         BqPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UhbxWX6A;
       spf=pass (google.com: domain of 3_lylxgukcfcdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3_LYlXgUKCfcdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id cc24si1567116edb.5.2020.01.20.06.19.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:19:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_lylxgukcfcdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id t4so3749896wmf.2
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:19:41 -0800 (PST)
X-Received: by 2002:a5d:45c4:: with SMTP id b4mr18022313wrs.303.1579529980939;
 Mon, 20 Jan 2020 06:19:40 -0800 (PST)
Date: Mon, 20 Jan 2020 15:19:23 +0100
Message-Id: <20200120141927.114373-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, 
	christophe.leroy@c-s.fr, dja@axtens.net, mpe@ellerman.id.au, 
	rostedt@goodmis.org, mhiramat@kernel.org, mingo@kernel.org, 
	christian.brauner@ubuntu.com, daniel@iogearbox.net, cyphar@cyphar.com, 
	keescook@chromium.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UhbxWX6A;       spf=pass
 (google.com: domain of 3_lylxgukcfcdkudqfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3_LYlXgUKCfcdkudqfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com;
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

This adds instrumented.h, which provides generic wrappers for memory
access instrumentation that the compiler cannot emit for various
sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
future this will also include KMSAN instrumentation.

Note that, copy_{to,from}_user require special instrumentation,
providing hooks before and after the access, since we may need to know
the actual bytes accessed (currently this is relevant for KCSAN, and is
also relevant in future for KMSAN).

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
 1 file changed, 153 insertions(+)
 create mode 100644 include/linux/instrumented.h

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
new file mode 100644
index 000000000000..9f83c8520223
--- /dev/null
+++ b/include/linux/instrumented.h
@@ -0,0 +1,153 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+
+/*
+ * This header provides generic wrappers for memory access instrumentation that
+ * the compiler cannot emit for: KASAN, KCSAN.
+ */
+#ifndef _LINUX_INSTRUMENTED_H
+#define _LINUX_INSTRUMENTED_H
+
+#include <linux/compiler.h>
+#include <linux/kasan-checks.h>
+#include <linux/kcsan-checks.h>
+#include <linux/types.h>
+
+/**
+ * instrument_read - instrument regular read access
+ *
+ * Instrument a regular read access. The instrumentation should be inserted
+ * before the actual read happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_read(const volatile void *v, size_t size)
+{
+	kasan_check_read(v, size);
+	kcsan_check_read(v, size);
+}
+
+/**
+ * instrument_write - instrument regular write access
+ *
+ * Instrument a regular write access. The instrumentation should be inserted
+ * before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_write(v, size);
+}
+
+/**
+ * instrument_atomic_read - instrument atomic read access
+ *
+ * Instrument an atomic read access. The instrumentation should be inserted
+ * before the actual read happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_atomic_read(const volatile void *v, size_t size)
+{
+	kasan_check_read(v, size);
+	kcsan_check_atomic_read(v, size);
+}
+
+/**
+ * instrument_atomic_write - instrument atomic write access
+ *
+ * Instrument an atomic write access. The instrumentation should be inserted
+ * before the actual write happens.
+ *
+ * @ptr address of access
+ * @size size of access
+ */
+static __always_inline void instrument_atomic_write(const volatile void *v, size_t size)
+{
+	kasan_check_write(v, size);
+	kcsan_check_atomic_write(v, size);
+}
+
+/**
+ * instrument_copy_to_user_pre - instrument reads of copy_to_user
+ *
+ * Instrument reads from kernel memory, that are due to copy_to_user (and
+ * variants).
+ *
+ * The instrumentation must be inserted before the accesses. At this point the
+ * actual number of bytes accessed is not yet known.
+ *
+ * @dst destination address
+ * @size maximum access size
+ */
+static __always_inline void
+instrument_copy_to_user_pre(const volatile void *src, size_t size)
+{
+	/* Check before, to warn before potential memory corruption. */
+	kasan_check_read(src, size);
+}
+
+/**
+ * instrument_copy_to_user_post - instrument reads of copy_to_user
+ *
+ * Instrument reads from kernel memory, that are due to copy_to_user (and
+ * variants).
+ *
+ * The instrumentation must be inserted after the accesses. At this point the
+ * actual number of bytes accessed should be known.
+ *
+ * @dst destination address
+ * @size maximum access size
+ * @left number of bytes left that were not copied
+ */
+static __always_inline void
+instrument_copy_to_user_post(const volatile void *src, size_t size, size_t left)
+{
+	/* Check after, to avoid false positive if memory was not accessed. */
+	kcsan_check_read(src, size - left);
+}
+
+/**
+ * instrument_copy_from_user_pre - instrument writes of copy_from_user
+ *
+ * Instrument writes to kernel memory, that are due to copy_from_user (and
+ * variants).
+ *
+ * The instrumentation must be inserted before the accesses. At this point the
+ * actual number of bytes accessed is not yet known.
+ *
+ * @dst destination address
+ * @size maximum access size
+ */
+static __always_inline void
+instrument_copy_from_user_pre(const volatile void *dst, size_t size)
+{
+	/* Check before, to warn before potential memory corruption. */
+	kasan_check_write(dst, size);
+}
+
+/**
+ * instrument_copy_from_user_post - instrument writes of copy_from_user
+ *
+ * Instrument writes to kernel memory, that are due to copy_from_user (and
+ * variants).
+ *
+ * The instrumentation must be inserted after the accesses. At this point the
+ * actual number of bytes accessed should be known.
+ *
+ * @dst destination address
+ * @size maximum access size
+ * @left number of bytes left that were not copied
+ */
+static __always_inline void
+instrument_copy_from_user_post(const volatile void *dst, size_t size, size_t left)
+{
+	/* Check after, to avoid false positive if memory was not accessed. */
+	kcsan_check_write(dst, size - left);
+}
+
+#endif /* _LINUX_INSTRUMENTED_H */
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200120141927.114373-1-elver%40google.com.
