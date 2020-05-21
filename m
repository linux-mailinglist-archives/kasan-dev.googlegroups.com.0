Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNU5TL3AKGQEGINLMCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C99151DCF8B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:47 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id b22sf4125510pfi.23
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070966; cv=pass;
        d=google.com; s=arc-20160816;
        b=Juw3Xnvt1l/7L64fr4ta2oh8N0OIm4lw/So39MBR/Ufj8UhiVGTor/h121xFBPO34G
         jxE2v+3qPMT28tFnDqvcWQt5bzS6a9eWpHs6/bDxyRInxdK/lZ5GkTYzz5mniwksquW8
         ZKIQ5fW0E0uaDwkZbwxQoniVMYHTBQasWYVAo9mXt+VOZV+ulj9hJ5vzPCuCjqsaQXR4
         /1K9vJyg3ayb0L7miPf6HiCl6N4t+fYEQ45pN9PzbLt3op/A+awwUW4TKg/iigvjzQ9P
         gt4T8tGozOsi8zREkkTvFEJdz8BUx6luDTjG2BJ5fctAk49c35sGCkEDwPBxg2ADWp9/
         cYtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=hSjJPG6gmZQ9i70Ou+bi0slGshjtkiFQJGhrizR2Ax4=;
        b=HBVC+oq7Tuse4sWq6LL/PLPX+IVuTFsgaGtACO+eITktCJaVNP6S24yRAxaDIy7cWT
         Fe0HhtljyNqtGJ+6FWd0y9wchH2RXXVPVVmkfrfcYixalVkPgOr2ew22JKLKVZFAePY2
         JiM+C17uPA7lUiz+HCz8mHGLFsImpsTCvIUY8ZrHxhbx2+/17rzRrcGx8d99SuNhvpZh
         v57TjuVTNh954cwiDNANPLy449/v93J2hzZgJ6lUtduno+8agSjN4+cFtS8WAqutcpcx
         9wUtMdSV0joUlMbqCYDtt7Civ8z3VU00QHNK4IjSMh4950EuwucX99DqfSVse1e1xWjd
         cbrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b48sod3H;
       spf=pass (google.com: domain of 3ty7gxgukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3tY7GXgUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hSjJPG6gmZQ9i70Ou+bi0slGshjtkiFQJGhrizR2Ax4=;
        b=KhOAMGuq22g2myGQfRxSxunHOUFCsmS7gI6m31wgIG8KfsFUo1HLC0bo1HEDiqoGjs
         WKHr526AoTS2+HpvyIToQ65krGNywBwenVcsk+OvdAfiU68WG+DA9WslwCbdPokM1I1F
         MeHsWH9hNaLPey9mw1HNYU49A2Yn5rbMhvktoB3mQ3eCRMOsEd7Z7iZN3ShvXAyilh1+
         JA6mC3IuPfTZRBZPM61cEnjWo1hUIZTux6wMUHOAQ74xIzrg+8EEQ7yxFa/jbfWL9X1V
         0Igh+ArpmhH3xNT8cAe2GciJ4pVH3x1MLtVvsavOvWvNb3daT8hXDya/puJIhOG0kclb
         KI5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hSjJPG6gmZQ9i70Ou+bi0slGshjtkiFQJGhrizR2Ax4=;
        b=i22zavO18pr6ct4jakmPUUYSkxB0jVhASHgTSNVUzq+nR08mdhUy2G26V544n/j1ZH
         xdvtpTzxl2gw1IpjE58eTMFFOxEeAGImd3QhEDlrxANy+jGaXiYXlnFCWvi4SgsZjDCo
         0JMfIcJ1VUxPcHP5IWw5lT5g97WslAzD8HALJxfkW1evbgcHqTsPtqN3bIwSnH8ywQFB
         /kMOjRHnqyDiJt9dKKgBmNQ2GvDNBiOHrDVf14SgQYoAKzh0AHd5HlpCZAMTGzUUl98m
         9vAB+VM7c22l65yBd0MCAvrtffynGOl/DBjvNluDL/4HkB5MJYIoljz/XG1vQxijP8WS
         Zf+g==
X-Gm-Message-State: AOAM533eEOXDGkWe1XA27YYmAuoM/9cUUHJ6g3Pm5A8oXBXHidvCF9tp
	bvupa+iIPIbdboQF/YkqkLI=
X-Google-Smtp-Source: ABdhPJyX/ycv57Rkmafd6bUxUqWtWGthy2AI5OOiU0qBkWyq+c4IBZRnWM3rs+mA4bksxIuk9PdOBA==
X-Received: by 2002:a17:90b:3c7:: with SMTP id go7mr12169027pjb.67.1590070966465;
        Thu, 21 May 2020 07:22:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c02:: with SMTP id na2ls1240254pjb.0.gmail; Thu, 21
 May 2020 07:22:46 -0700 (PDT)
X-Received: by 2002:a17:90a:3ad1:: with SMTP id b75mr11958680pjc.216.1590070966051;
        Thu, 21 May 2020 07:22:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070966; cv=none;
        d=google.com; s=arc-20160816;
        b=od2mmKaEci5SZ+e7gc4A76vmGK/u6UcmXOTe7oV3kZRqAOn7rFT+GSAd5lXh9B+H1Y
         Wdaezl2KYj/ZQXktn7RzTQRz57cU73acXinqK9rS7IB00nkHXD/QmMskuUBL31DQkjSL
         0y+dJRXgSOVqBX/ZnoQAgA/a4H9du7lVSTweNuAO34XushsZHm8oazKXQvWsxXSkeUPd
         2sZFSLAxZdMl4UC2SeLUnCB6rM2qn5IsBweZ36qI9c1xUu6fznx/9a10CzeQ2d8VZ7v/
         Sf75OCASXu0Vjie0JRn53ADrWxX0dQTk2DE64drz5obbZyhkGo1xzp1/IRoiP6r8iq6r
         uWlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LdWtxw6Vf28rU4H8/TQCyMB4NDqGcmdRqUmsRUyh1H4=;
        b=fG0KFQwYOk2VUEx8RTaojNc9V7eSb7L4wA9DMX6KDn0LxtZ1P9DjOuciaDLJibkcwW
         0/wqIh88cNOlpviAyScCRXsXN0gdCYo//RjjJzI05DyiaJ79K84fGTJ69gigRJrBHSvP
         cYjD/eQOhfknawVbEbsGOeCUeeM1oyjHshpjRTFEWTIzJAeKJY581MZcSfJSO9OW2lKU
         bteLrumEnXKNOacLVpJ+/1NxDGpMlVnIDeH4CKiYq6VutE1vKFBkRHSuKBpcxzhM5Suj
         CotgswWsrwvFmfgWIZo+QJmb4uxeN5nHZYqcLuu6Y32tjJFf8nWZZKWYYcoWrxkKDGOE
         qYeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b48sod3H;
       spf=pass (google.com: domain of 3ty7gxgukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3tY7GXgUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id g11si369984pgj.2.2020.05.21.07.22.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ty7gxgukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id v6so7593821qkh.7
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:46 -0700 (PDT)
X-Received: by 2002:ad4:4a8b:: with SMTP id h11mr10542388qvx.232.1590070965164;
 Thu, 21 May 2020 07:22:45 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:47 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-12-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 11/11] compiler_types.h, kasan: Use
 __SANITIZE_ADDRESS__ instead of CONFIG_KASAN to decide inlining
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b48sod3H;       spf=pass
 (google.com: domain of 3ty7gxgukcegovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3tY7GXgUKCegOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Like is done for KCSAN, for KASAN we should also use __always_inline in
compilation units that have instrumentation disabled
(KASAN_SANITIZE_foo.o := n). Adds common documentation for KASAN and
KCSAN explaining the attribute.

Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler_types.h | 13 ++++++++-----
 1 file changed, 8 insertions(+), 5 deletions(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index b190a12e7089..5faf68eae204 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -167,7 +167,14 @@ struct ftrace_likely_data {
  */
 #define noinline_for_stack noinline
 
-#ifdef CONFIG_KASAN
+/*
+ * Sanitizer helper attributes: Because using __always_inline and
+ * __no_sanitize_* conflict, provide helper attributes that will either expand
+ * to __no_sanitize_* in compilation units where instrumentation is enabled
+ * (__SANITIZE_*__), or __always_inline in compilation units without
+ * instrumentation (__SANITIZE_*__ undefined).
+ */
+#ifdef __SANITIZE_ADDRESS__
 /*
  * We can't declare function 'inline' because __no_sanitize_address conflicts
  * with inlining. Attempt to inline it may cause a build failure.
@@ -182,10 +189,6 @@ struct ftrace_likely_data {
 
 #define __no_kcsan __no_sanitize_thread
 #ifdef __SANITIZE_THREAD__
-/*
- * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
- * compilation units where instrumentation is disabled.
- */
 # define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
 # define __no_sanitize_or_inline __no_kcsan_or_inline
 #else
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-12-elver%40google.com.
