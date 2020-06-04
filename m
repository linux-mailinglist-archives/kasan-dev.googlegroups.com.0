Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQUI4P3AKGQEWXBJTIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6316E1EE1D3
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 11:52:03 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e5sf3310046ill.10
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 02:52:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591264322; cv=pass;
        d=google.com; s=arc-20160816;
        b=s1b7ZttdMximP0DYG/1/s9yHccIPI04FFzoVOT4zfgbzmKzqYTq3C/dqkx76HOGijs
         RKxxp0CTOhAaWO0OBe258fxRNpqGw/0pHp+q9/mx8NUg+BT9UpZH3/U3jCh+d48FW20x
         EdT2kBoxR5xQmPydirieYjZDqfPbbl3BB6U77XEY1FUcS6DF0LjRsOuCZzQlke6v6Mgk
         nzn421bMAotTC/LViW2NHYhYQejDi2+aOq24ehzDLRRXq6QPQ3LJ8SLT0wD2JLa1agB4
         2djXAtAep6UzeLHkkt90oAOqhR1vIAmfFRLXv+QQzCrt0NdoqGkv5wDO/rgXuYGTc3sC
         UbLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=UlysNNSmKa+wAIb3CbSD71nO8SoKq8ZeipWjhcaKplQ=;
        b=yaP0oCxknugjiWT9xPUsHmJ5EHDs7712xRNIfhe3/wSqC+RaUoXz5AmkqahkXvi6nF
         raC5p2xyqscYw9XPAisB9V72fPU97ApXSuasLGPp1dTE6/L/G9nI2t5PAz152DPUotAT
         3AYry5CXk1MNINrTKEg1tucUCneQRiFUASVBFyaFgTT9/GN5HLwoLxL2eAOk77Vp8PQE
         YuJzOLUhr1aCSvk/qWznQuikAd6Gb1McTli63LnKFZ2iQDrV3gSr8G7FV6afyhmXeaKE
         hezk6BG/wv14v8ecnN4ZF7CVSKS+PgD4lhuCQEMA7uX+Ovh7/F9Ie4ZGjtrwYOkiTYt6
         7dBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SeNAh2Su;
       spf=pass (google.com: domain of 3qmtyxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QMTYXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UlysNNSmKa+wAIb3CbSD71nO8SoKq8ZeipWjhcaKplQ=;
        b=mesT2frmUfxTVUF+c0yYSrSKIhaA84Or+tjX+pvs/a2mTH1hZlZXrp4+QzWm+RDoZA
         nQtWkK3ZQNZjdFpaM9KGOrkCkaKMzVESx6v3B6aaYOufqVSe7iNmtbpPvxAA4wwGWlI5
         UElnouCYxuU6rC4P0YopfwizT11zWexRgUvNue/qrlTIfRt8tG8V/W227bT5mwz9ozYs
         GcO7MIZBvkKIG7AbEiI3UnrRftUAo4Mx0vosNsGIptFu3TLbHUTGgtTbf1aOnXGCA+fS
         H1CsmUGGEuxSo2JVwXEhAsHgyYS1ffSqCq1h/kyH6Hk69qNevg8l1qCAalKRUy75hir4
         rteA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UlysNNSmKa+wAIb3CbSD71nO8SoKq8ZeipWjhcaKplQ=;
        b=YVgRDXO0zTylFibkWQETIqy7AbVhoJ4CGzEiLqGB4hMS+tARDoIjZ3z6QVmO+8ReEw
         e2fOM4vn/2ramLPT4zwLHHH2U9CheJuZ5xPFPwNoPXet1M2er7k+BLMZUsvSwjWKZ81f
         /AwGEecm8R34ojWlglPoKi9qeI8STkqO9wUUSEn+sldHIQBzOTAs3YRfMRUEv7xNbMfZ
         aJUvqQu+nxWFboKaJzk9YFGQOkyIfpFdVkbQh/XwTZN9mjoDl4lNftkURUD60aP6Xo1Y
         i2LSi3G8rjNJvLiXL7ci4dkuCZM+zsSMPVU+CBdr4yoLatN9rMEFsGzq3DnU7puaHVjM
         akgA==
X-Gm-Message-State: AOAM531T01Y/mFPc08LvQu4WdF3XujqXzMPTpe8ZTbveQdM+vT7bc8Iv
	buXcwK9mEttucDm+8p7eHG4=
X-Google-Smtp-Source: ABdhPJyZ3oPTnGatkBquAyQy1vU2nxM1fXLNvm4v2PPHpWHbojmp9Ekaza/PiJ4fWKf371cXeoJBBw==
X-Received: by 2002:a92:4948:: with SMTP id w69mr3014725ila.15.1591264322350;
        Thu, 04 Jun 2020 02:52:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b9d6:: with SMTP id j205ls844602iof.6.gmail; Thu, 04 Jun
 2020 02:52:01 -0700 (PDT)
X-Received: by 2002:a5d:8cc1:: with SMTP id k1mr3417871iot.123.1591264321244;
        Thu, 04 Jun 2020 02:52:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591264321; cv=none;
        d=google.com; s=arc-20160816;
        b=ZLwWffolU7qam4FzqdeDRKWJyFyNm1OaMcmmDN2Ts6fXhx++ndWMCcCPGWVbO0Agp2
         9pa+D9BkUsmA8oOPHXhTuXRqNoCcB96aBEFdUglDVXMLVdHfMOG52hzBhkPYjUk4Rho8
         vQHRnKfjZMSTtYtnON1NQgT0b+s48eH8r5A90P1PpOyc+L8W3KuU1YAXoXvmAI4FKZ9U
         hPKvChaWLA/xUL8o9jic/bitooB6rlTE824AwVsX+kTLSh4/KEdefvXgtPuA4Kj351/i
         08J/ZK0bOxCPrhqeZ/eIOq4jH6vlq3RKNuRYIkX7qnEAHH9KCi/Nm5Uc2dBgdC2CtG8c
         kJlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=r692uYxf+UU+Krdksb9nzub5hLmbN/XbgAudqBHpBo4=;
        b=F/kIta/RLXmR736/HtDFL0x5Gb3iy/aT5B9OF2lfY4oRgerybdY0eK0CT0E/iqDsVw
         W0MvIzB2jalGBg87miF0OqPpWVPghf1BIwxuf9dPfg8tL1aUFIEEUnufzTAwP9FZ5bBq
         Za0ysTi7f8qn+XJOv/6PTbwhKCbIdT3NokOeItV1Sv1iVFL26qEHw23EQ+UcMWLLxZEo
         OYa6TGweTU+/nNHqCBvF2OrsruXSd5Oxa+Gonxxl5K92VY9EEah05YM/vVXnMv8J0AdN
         P5+DmLofif2fjaY+zM/4TlBx7TUsFWLdyriDAtETDNaEz4veaCFDAo8yDpypiwV1579t
         mcGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SeNAh2Su;
       spf=pass (google.com: domain of 3qmtyxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QMTYXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id x10si44172ila.3.2020.06.04.02.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 02:52:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qmtyxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id u186so7353202ybf.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 02:52:01 -0700 (PDT)
X-Received: by 2002:a25:2f4f:: with SMTP id v76mr6129459ybv.7.1591264320706;
 Thu, 04 Jun 2020 02:52:00 -0700 (PDT)
Date: Thu,  4 Jun 2020 11:50:57 +0200
Message-Id: <20200604095057.259452-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc2.251.g90737beb825-goog
Subject: [PATCH -tip] kcov: Make runtime functions noinstr-compatible
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, mingo@kernel.org, 
	clang-built-linux@googlegroups.com, paulmck@kernel.org, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SeNAh2Su;       spf=pass
 (google.com: domain of 3qmtyxgukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3QMTYXgUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
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

The KCOV runtime is very minimal, only updating a field in 'current',
and none of __sanitizer_cov-functions generates reports nor calls any
other external functions.

Therefore we can make the KCOV runtime noinstr-compatible by:

  1. always-inlining internal functions and marking
     __sanitizer_cov-functions noinstr. The function write_comp_data() is
     now guaranteed to be inlined into __sanitize_cov_trace_*cmp()
     functions, which saves a call in the fast-path and reduces stack
     pressure due to the first argument being a constant.

  2. For Clang, correctly pass -fno-stack-protector via a separate
     cc-option, as -fno-conserve-stack does not exist on Clang.

The major benefit compared to adding another attribute to 'noinstr' to
not collect coverage information, is that we retain coverage visibility
in noinstr functions. We also currently lack such an attribute in both
GCC and Clang.

Signed-off-by: Marco Elver <elver@google.com>
---
Note: There are a set of KCOV patches from Andrey in -next:
https://lkml.kernel.org/r/cover.1585233617.git.andreyknvl@google.com --
Git cleanly merges this patch with those patches, and no merge conflict
is expected.
---
 kernel/Makefile |  2 +-
 kernel/kcov.c   | 26 +++++++++++++-------------
 2 files changed, 14 insertions(+), 14 deletions(-)

diff --git a/kernel/Makefile b/kernel/Makefile
index 5d935b63f812..8e282c611a72 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -35,7 +35,7 @@ KCOV_INSTRUMENT_stacktrace.o := n
 KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
-CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
+CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) $(call cc-option, -fno-stack-protector)
 
 # cond_syscall is currently not LTO compatible
 CFLAGS_sys_ni.o = $(DISABLE_LTO)
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 8accc9722a81..d6e3be2d0570 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -142,7 +142,7 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
 	list_add(&area->list, &kcov_remote_areas);
 }
 
-static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
+static __always_inline bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
 {
 	unsigned int mode;
 
@@ -164,7 +164,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	return mode == needed_mode;
 }
 
-static notrace unsigned long canonicalize_ip(unsigned long ip)
+static __always_inline unsigned long canonicalize_ip(unsigned long ip)
 {
 #ifdef CONFIG_RANDOMIZE_BASE
 	ip -= kaslr_offset();
@@ -176,7 +176,7 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
  * Entry point from instrumented code.
  * This is called once per basic-block/edge.
  */
-void notrace __sanitizer_cov_trace_pc(void)
+void noinstr __sanitizer_cov_trace_pc(void)
 {
 	struct task_struct *t;
 	unsigned long *area;
@@ -198,7 +198,7 @@ void notrace __sanitizer_cov_trace_pc(void)
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
 
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
-static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
+static __always_inline void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 {
 	struct task_struct *t;
 	u64 *area;
@@ -231,59 +231,59 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	}
 }
 
-void notrace __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
+void noinstr __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(0), arg1, arg2, _RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp1);
 
-void notrace __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2)
+void noinstr __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(1), arg1, arg2, _RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp2);
 
-void notrace __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2)
+void noinstr __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(2), arg1, arg2, _RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp4);
 
-void notrace __sanitizer_cov_trace_cmp8(u64 arg1, u64 arg2)
+void noinstr __sanitizer_cov_trace_cmp8(u64 arg1, u64 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(3), arg1, arg2, _RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp8);
 
-void notrace __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2)
+void noinstr __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(0) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp1);
 
-void notrace __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2)
+void noinstr __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(1) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp2);
 
-void notrace __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2)
+void noinstr __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(2) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp4);
 
-void notrace __sanitizer_cov_trace_const_cmp8(u64 arg1, u64 arg2)
+void noinstr __sanitizer_cov_trace_const_cmp8(u64 arg1, u64 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(3) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp8);
 
-void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
+void noinstr __sanitizer_cov_trace_switch(u64 val, u64 *cases)
 {
 	u64 i;
 	u64 count = cases[0];
-- 
2.27.0.rc2.251.g90737beb825-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604095057.259452-1-elver%40google.com.
