Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWPT4XYQKGQEF45THZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 142AD151BCB
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 15:04:10 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id z11sf2998900ljm.15
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 06:04:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580825049; cv=pass;
        d=google.com; s=arc-20160816;
        b=MbFFkL0bDoT0K/sVoE0/Ag0QCoSi1XJzrwQVe3UA1s4W731ug88EDCM6ShRKpaV3MR
         qo8AbkkXEO46Kiidpe0MEjGsGyz5OEt7jZd3a4uE44Eq0wa9SIjc3KeKItU9RTnHZ7AH
         vPQw6/lzVofGn0r5Ve1z2TrHHlUTcVaX8rK0PCE82BTkqTKEZhNWdTH+BzL5cWyenBgV
         iCgOOeTo9Khb8An4ES3dxOWNxBmkz2mPj7qvlR+CbObXGDJOlCZQvyfI38L404HhabmY
         28SEVDrSTWGAECJaWB4uWGqdNuZ0EgxY6byzyXJ4xjN6wUaNuLfUthf7/ncVioTQbJrv
         gXpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=vprTChvYmxtkJmO05rLeiaQzS/tYrUZnN4zaqBKOMlY=;
        b=nRM4tsLWM7ufm6EMMgzRwpkjv6B7iIdly+ULLV1SAcwGyKxsMDZSQNzPwOTYAnerCa
         EfEb1PB53i+Ly3ikgXz11fsz0wNt5giQdATNjkH5Wrq1BZllkUQFVlxeTfx35VMZvA4A
         aPeudMApGqEQmRUoc6ERsouCV1NVPIT1stWUfkFGe+cx2HQE6XZJlRdV6a732TFaMIKt
         7rSPNkWRCzkOvH4mmqKlEoDHbGqTMZyF4z8SYutj54/rc8UwtM3eYMInupBAa8/t1mmm
         r3WXjwGHvTvW60LwpVzd4tC275OcxYQr0lYva6TGMLIifvv76nMH1NrfvcR+icUEfF1X
         FBgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lGIAixLV;
       spf=pass (google.com: domain of 313k5xgukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=313k5XgUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=vprTChvYmxtkJmO05rLeiaQzS/tYrUZnN4zaqBKOMlY=;
        b=NA1ZimEa5LeiN8QAbSEJcZGMwHvPD4rWR6iej9Aad+UfCqmUsTEWBAU1uyYJ66s/5E
         IshVAkrRczEgbjchASaJho9MQ4Jg9ZJe6NIGXUIMO4Iq0DNRJqD9oyZvikqAde0cUEJi
         PwBkpvoLObDcAkNY6b++bEWZ3bolZkKWUqMZ0X5lPyf/SRNBQVTDWpm0IGL9STAFG4yb
         +NvOw4Tawm/J7wfg6C6b9nSe9hPpPrW2dDNBxQdNDgQP88agycPT572Jiyao5dvo9RDq
         13b5ubxbh9p3uNpxSCxjD2dS54gBoxwO2Wqnro1r0YvYcN8nhpgEobcGfsj+Yxwj81aH
         BbOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vprTChvYmxtkJmO05rLeiaQzS/tYrUZnN4zaqBKOMlY=;
        b=YmOSKOz98e4KrzQYis4u9HMmnZrrA93ytRJUIyeNZCv3FKnysOLB4qvUtRGMXOK7f6
         5ScEv+zFo7EqiykSyGmFeLnN+idAqEqMNOXSE4/bvPYuPP3MOiu92P5BbpgkmeLww0OX
         ls1ZrtigO8K7CLC5YdeVMDWuH6SutmH5UAwbh9vErsHFkznhwQqMUR1uaATxPQ6NOvE2
         SRgg+Zt1rjpaCl9jNffFkb4IIWWqQ+wDlN2uDc/y3VQ/HQh6t+PezsYPGMGMerl5K4DQ
         SEkIITmJTMTNaw+zwmV5sZXseltxZwEbcM5HUG7uVgaQ8QfY8OWGK6oB30eoz/wR3srU
         AqsA==
X-Gm-Message-State: APjAAAWx7bkW3D7TSmBNtBbg76+PnGQ/5ygBwHDV2C0PvUpTYmDQwjoS
	FVsyv7TQO1vy7L/+oWV1FxQ=
X-Google-Smtp-Source: APXvYqwwQyK0y7laCMeB1+eZv7aXxhvnq66EIT0w58uPF/Ze7ugikcHlM4qGpw2Q7YqBeiW0SAVjIg==
X-Received: by 2002:a19:6449:: with SMTP id b9mr15056181lfj.5.1580825049486;
        Tue, 04 Feb 2020 06:04:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c397:: with SMTP id t145ls1593092lff.10.gmail; Tue, 04
 Feb 2020 06:04:08 -0800 (PST)
X-Received: by 2002:ac2:5f74:: with SMTP id c20mr15193169lfc.15.1580825048673;
        Tue, 04 Feb 2020 06:04:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580825048; cv=none;
        d=google.com; s=arc-20160816;
        b=YX0JqPTM0gpphNzEiBLWj9Kph+nNymEIAtY/lJuEaqAqTAcQYStul+Nn3+PV3JH56B
         1qo1a1SRX53XHf5ON2J1qe9+N1x/oUFP+S8x4wFWan8DVbhDA9y1xty+vZ60+IaI0lW8
         obSImtM4zmLmJhiTNBangU55PzwGJ8vscRRxtGe3+b+hfYDP0njMgWYXek8N9Um78UhE
         wc4Z3zbEF6oSOceDvP+oHt/NgbBll77VOyf6dv/bfym3UAMDXlL5fD2RXmk4JblG7XB9
         98tQM+fW+nxU+6IAxXP7mFb6iYikjXBoLXjLaVZ8bRWIwWHR1UmC86aM3+62uNwa9LJn
         tXTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=6E0waZpVztRIyJBw+i4kvl8HN7efuLnbdgojMgz5Rmw=;
        b=O9OSlf/W71I3TLtnxycRtpR9+Omy68ThC+CXC078hM1ODMX30dKz9GydCSAhRAl6Y9
         3avCAsiIByoyjRJhkuqKBceRVXgU4eKFoIK5wLo89Y6B3D4cazK7Z9r79Nv5jGVFXNHh
         mYuyLtEZkB0DvPHk2k2GLQu1PdkLPeEpOZpw3u797nUENpdNygKs4Co8/c6ozE3EfWRi
         hXzMvkYPFDiAkprwE3nJGc34P3/InHQvwbj7fi1/IoUGODpblMeIzR3yPl+xStrKtkvh
         POglsFQjQprugbwuN2Jl04RHu4/HToKer5kutZSH/PBcw3Pzv6qWsTPwEJmeDnf3gZ19
         6gPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lGIAixLV;
       spf=pass (google.com: domain of 313k5xgukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=313k5XgUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id e3si1045154ljg.2.2020.02.04.06.04.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2020 06:04:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 313k5xgukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y24so1206312wmj.8
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2020 06:04:08 -0800 (PST)
X-Received: by 2002:a5d:6411:: with SMTP id z17mr23816462wru.57.1580825047557;
 Tue, 04 Feb 2020 06:04:07 -0800 (PST)
Date: Tue,  4 Feb 2020 15:03:51 +0100
Message-Id: <20200204140353.177797-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 1/3] kcsan: Add option to assume plain writes up to word size
 are atomic
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lGIAixLV;       spf=pass
 (google.com: domain of 313k5xgukcagmtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=313k5XgUKCagMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

This adds option KCSAN_ASSUME_PLAIN_WRITES_ATOMIC. If enabled, plain
writes up to word size are also assumed to be atomic, and also not
subject to other unsafe compiler optimizations resulting in data races.

This option has been enabled by default to reflect current kernel-wide
preferences.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 20 +++++++++++++++-----
 lib/Kconfig.kcsan   | 26 +++++++++++++++++++-------
 2 files changed, 34 insertions(+), 12 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 64b30f7716a12..3bd1bf8d6bfeb 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -169,10 +169,19 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
-static __always_inline bool is_atomic(const volatile void *ptr)
+static __always_inline bool
+is_atomic(const volatile void *ptr, size_t size, int type)
 {
-	struct kcsan_ctx *ctx = get_ctx();
+	struct kcsan_ctx *ctx;
+
+	if ((type & KCSAN_ACCESS_ATOMIC) != 0)
+		return true;
 
+	if (IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) &&
+	    (type & KCSAN_ACCESS_WRITE) != 0 && size <= sizeof(long))
+		return true; /* Assume all writes up to word size are atomic. */
+
+	ctx = get_ctx();
 	if (unlikely(ctx->atomic_next > 0)) {
 		/*
 		 * Because we do not have separate contexts for nested
@@ -193,7 +202,8 @@ static __always_inline bool is_atomic(const volatile void *ptr)
 	return kcsan_is_atomic(ptr);
 }
 
-static __always_inline bool should_watch(const volatile void *ptr, int type)
+static __always_inline bool
+should_watch(const volatile void *ptr, size_t size, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -202,7 +212,7 @@ static __always_inline bool should_watch(const volatile void *ptr, int type)
 	 * should not count towards skipped instructions, and (2) to actually
 	 * decrement kcsan_atomic_next for consecutive instruction stream.
 	 */
-	if ((type & KCSAN_ACCESS_ATOMIC) != 0 || is_atomic(ptr))
+	if (is_atomic(ptr, size, type))
 		return false;
 
 	if (this_cpu_dec_return(kcsan_skip) >= 0)
@@ -460,7 +470,7 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 	if (unlikely(watchpoint != NULL))
 		kcsan_found_watchpoint(ptr, size, type, watchpoint,
 				       encoded_watchpoint);
-	else if (unlikely(should_watch(ptr, type)))
+	else if (unlikely(should_watch(ptr, size, type)))
 		kcsan_setup_watchpoint(ptr, size, type);
 }
 
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 3552990abcfe5..08972376f0454 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -91,13 +91,13 @@ config KCSAN_REPORT_ONCE_IN_MS
 	  limiting reporting to avoid flooding the console with reports.
 	  Setting this to 0 disables rate limiting.
 
-# Note that, while some of the below options could be turned into boot
-# parameters, to optimize for the common use-case, we avoid this because: (a)
-# it would impact performance (and we want to avoid static branch for all
-# {READ,WRITE}_ONCE, atomic_*, bitops, etc.), and (b) complicate the design
-# without real benefit. The main purpose of the below options is for use in
-# fuzzer configs to control reported data races, and they are not expected
-# to be switched frequently by a user.
+# The main purpose of the below options is to control reported data races (e.g.
+# in fuzzer configs), and are not expected to be switched frequently by other
+# users. We could turn some of them into boot parameters, but given they should
+# not be switched normally, let's keep them here to simplify configuration.
+#
+# The defaults below are chosen to be very conservative, and may miss certain
+# bugs.
 
 config KCSAN_REPORT_RACE_UNKNOWN_ORIGIN
 	bool "Report races of unknown origin"
@@ -116,6 +116,18 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
 	  the data value of the memory location was observed to remain
 	  unchanged, do not report the data race.
 
+config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
+	bool "Assume that plain writes up to word size are atomic"
+	default y
+	help
+	  Assume that plain writes up to word size are atomic by default, and
+	  also not subject to other unsafe compiler optimizations resulting in
+	  data races. This will cause KCSAN to not report data races due to
+	  conflicts where the only plain accesses are writes up to word size:
+	  conflicts between marked reads and plain writes up to word size will
+	  not be reported as data races; notice that data races between two
+	  conflicting plain writes will also not be reported.
+
 config KCSAN_IGNORE_ATOMICS
 	bool "Do not instrument marked atomic accesses"
 	help
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200204140353.177797-1-elver%40google.com.
