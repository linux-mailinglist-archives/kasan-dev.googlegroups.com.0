Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS6CTTYQKGQEJMTHM7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DAF2144187
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 17:05:33 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id i196sf1960488pfe.6
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jan 2020 08:05:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579622731; cv=pass;
        d=google.com; s=arc-20160816;
        b=rRpsRzqMSTghHAt/ktoX7tY+dXoTkW8jP2p1vp/xF0ws/qc5EFCA+EBnap6+0Nw9PH
         Iu0HpF4zq8Q3PnWZudD51kN6ruOrBc1owFkiyLhnoTZ0agauWBzCpGeE34n5azefOKc0
         9kCZeAy5xvVM7Yzh8J63Sy8rv7ssY76Z0vK8JZDhjjW+/KESjoxHtV0XPF0mSkZhymiZ
         VvClp+s9miLlwxXFaQKHOwCrjLbMdHfB5Ua6C/eRkm15R5Al+uR4+8g87Y/9OxG4clp+
         KvbSIRVJzlDLMsiLo+irPtzHtT5Ed1+rp5Jf7UiQSpOoe4lgpUSvj1ItaD43mF6vwNal
         3dQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=SEbz4z69fLaZuECba+V7FAhkj6GzlPn5YUdVGpLbNS4=;
        b=xesE9N5tGc6k6sRdlS12Qf3N138c8tM3lgy9Nyii0oqipKaXMCKb0JU8wEmkx+tW5N
         7bPafRMxDWo/9pISUatcfVdPfdXZbBezV4zl7xC9spPy9I3SB7eNXCl/mFi2l67pYQ/y
         9Ztu6l1+oQYiYtrR3ae+IS59Dc5IPofCInIa9nllbM/4UnBhJ6OYxXNtrAb0f8pYrSPR
         QuAt+0ydz0yOpYvsUZ7NKV8QRKDhZqCzuDZw1ucvvjbKoZVjs0UMgHuQkzl2gzU4zfZ1
         /+mWXg4ON/ProAS9jGhBxdnj7TdU6uPjTHeBcuZybhZVrdsRC5VIqRU21ZZvFCKyVcSF
         I4kw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v2F3CTwZ;
       spf=pass (google.com: domain of 3ssenxgukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3SSEnXgUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SEbz4z69fLaZuECba+V7FAhkj6GzlPn5YUdVGpLbNS4=;
        b=n9yLOOFWy9gabd0Fr6Rt2ZUmOzAUQ8IdDUGLa7gs1HrUzrjJ8JY3xWnIDBLQAcuWnu
         kKR5Q1AB21ituYYhJQnA5iLRWsfldhf7jkcs7ZKhhscXwhOTDvxqcnU+7EGBDfL/sqym
         A/Q5rZL3CE5vUTRt5urQYQoBOdERCk2n2DfVT0xyjQle2oVXSLad2kzRary9XnUupJe7
         L7h14hr9uXy4QbauCnExnp7DMbBE7QLbRXwbfPdsBgm6XxIYv551JtEyTmozPNZAlcQ8
         YTSfLK3n7XMzbzJqCOYLKdpAvK/LELN/5zIuIfT577HKU7V4z+PyRmfgzjjKcA9Bn6fT
         +e7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SEbz4z69fLaZuECba+V7FAhkj6GzlPn5YUdVGpLbNS4=;
        b=dEMqJ9ZHTnfQzAxcjK3AQ6Uj9PLkq+4SZLgFUHtvQDQnXYVpf19qBrZZ3uIYId18Nr
         UFmrA2K0gInZH5Nd9P/9c4xwyiyUeAS3HyUajLMjSYiSks+WBYQABFFQrSPRFyrhO8Lh
         nEomBu2niCz0Wh4oSwcB4LuS0bnJNAAnjI4R4Gqt95sqftPIggQ+HEQRCBsp74bdlrNG
         K+theGixXr0iIQTbGaFNDktdK/+TPOkVWmNkvlmWdWF/AIHeSXtNxg1dq5zDjjN73HHF
         AlIA7ve/rhM5LSYOkIP+eLYwoPo7IW8CxSSE2EMlP4bdN7XODMhg6HEVsv13+I04pX3i
         Y5Jw==
X-Gm-Message-State: APjAAAWXLzQqudCER4QEwvPwr1m5evG+0m5H8uqSx4KgaPZvn+8aZtuM
	4CV+1iYI4+4TuNIsHusDI5Q=
X-Google-Smtp-Source: APXvYqzpE0OvmUhM7EBvOzKPDprVswQxwKejUZ53WR/L3ku2Dhy4vLzCDCFEZCaXvD3+TiP/WPihfQ==
X-Received: by 2002:a63:181a:: with SMTP id y26mr6367852pgl.423.1579622731354;
        Tue, 21 Jan 2020 08:05:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:fe5:: with SMTP id 92ls1377203pjz.5.canary-gmail;
 Tue, 21 Jan 2020 08:05:30 -0800 (PST)
X-Received: by 2002:a17:90a:3243:: with SMTP id k61mr6323072pjb.46.1579622730806;
        Tue, 21 Jan 2020 08:05:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579622730; cv=none;
        d=google.com; s=arc-20160816;
        b=jgbd8YKyFKfPfK4DXu2J+wtohrP65iTdRhoaspb27+CKzo6xf9YU6LfAdIsCPDAtpm
         x1f633Y1+RiT/ezdnXmzMiwW435/ZMa6aTaaid7BLzqY7rPcVkFoQzQhZTfyNpumZnjP
         8odLOFSskPa78p8xfb9mbJVXW8LAJbKAhPjvsPOeQ/T8l4b31p5T/fpqvnxcpvU/wdia
         kmSNVJQ449t88dgr7aM25VD/ifcBb9trvqvOeb2U+s7SzcMvLWBBEG3sWcdYSCUimjYg
         fenA3d7qBAGzBAe+kjgZkYD0rip9dDye8yQiCoOGcdTq5ctj3zDAvX6wvAIPPXGuwk+l
         qCMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=gOTObLS6sIUumSLv4AZxxemI8TrkhdrsbCPGC0X3Xl8=;
        b=rm+RtCHXp+q/Lg0Db9lfyA0O7/unS9EjLawXvIzcAhKPg4pfQYEo7YQ9F01HcvWmeF
         n4S95L1zrpxb2EmLixRVRUR8dsuScPJqtQUUP7h11fZKdje2aa76qT6ad0lLtQNr9P1k
         cWH/6m2tAhFlcuuFLCkMLhwfKb/A6bemt2OCtWy4BzjUsmuc7lR80fWMSORKlehvILBW
         hAii5QhDuk5nCXeyf6nz2UXr9UhkS9WzaLxw9Ju4naBsV1ShQiFgI+SMOMSZHV7u22r5
         E4xXysdcsom7tDjuobE2T1/0kHpfsW339596vik+AzWMUQIFoFHDTvTfgKHdLu4K0i1Y
         6Ghg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=v2F3CTwZ;
       spf=pass (google.com: domain of 3ssenxgukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3SSEnXgUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x94a.google.com (mail-ua1-x94a.google.com. [2607:f8b0:4864:20::94a])
        by gmr-mx.google.com with ESMTPS id f31si64029pje.2.2020.01.21.08.05.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jan 2020 08:05:30 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ssenxgukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) client-ip=2607:f8b0:4864:20::94a;
Received: by mail-ua1-x94a.google.com with SMTP id f15so650728uap.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Jan 2020 08:05:30 -0800 (PST)
X-Received: by 2002:ab0:770b:: with SMTP id z11mr3566817uaq.127.1579622729505;
 Tue, 21 Jan 2020 08:05:29 -0800 (PST)
Date: Tue, 21 Jan 2020 17:05:09 +0100
In-Reply-To: <20200121160512.70887-1-elver@google.com>
Message-Id: <20200121160512.70887-2-elver@google.com>
Mime-Version: 1.0
References: <20200121160512.70887-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 2/5] asm-generic, atomic-instrumented: Use generic instrumented.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	mark.rutland@arm.com, will@kernel.org, peterz@infradead.org, 
	boqun.feng@gmail.com, arnd@arndb.de, viro@zeniv.linux.org.uk, dja@axtens.net, 
	christophe.leroy@c-s.fr, mpe@ellerman.id.au, mhiramat@kernel.org, 
	rostedt@goodmis.org, mingo@kernel.org, christian.brauner@ubuntu.com, 
	daniel@iogearbox.net, keescook@chromium.org, cyphar@cyphar.com, 
	linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=v2F3CTwZ;       spf=pass
 (google.com: domain of 3ssenxgukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3SSEnXgUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

This switches atomic-instrumented.h to use the generic instrumentation
wrappers provided by instrumented.h.

No functional change intended.

Suggested-by: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Arnd Bergmann <arnd@arndb.de>
---
 include/asm-generic/atomic-instrumented.h | 395 +++++++++++-----------
 scripts/atomic/gen-atomic-instrumented.sh |  19 +-
 2 files changed, 194 insertions(+), 220 deletions(-)

diff --git a/include/asm-generic/atomic-instrumented.h b/include/asm-generic/atomic-instrumented.h
index 63869ded73ac..379986e40159 100644
--- a/include/asm-generic/atomic-instrumented.h
+++ b/include/asm-generic/atomic-instrumented.h
@@ -19,25 +19,12 @@
 
 #include <linux/build_bug.h>
 #include <linux/compiler.h>
-#include <linux/kasan-checks.h>
-#include <linux/kcsan-checks.h>
-
-static __always_inline void __atomic_check_read(const volatile void *v, size_t size)
-{
-	kasan_check_read(v, size);
-	kcsan_check_atomic_read(v, size);
-}
-
-static __always_inline void __atomic_check_write(const volatile void *v, size_t size)
-{
-	kasan_check_write(v, size);
-	kcsan_check_atomic_write(v, size);
-}
+#include <linux/instrumented.h>
 
 static __always_inline int
 atomic_read(const atomic_t *v)
 {
-	__atomic_check_read(v, sizeof(*v));
+	instrument_atomic_read(v, sizeof(*v));
 	return arch_atomic_read(v);
 }
 #define atomic_read atomic_read
@@ -46,7 +33,7 @@ atomic_read(const atomic_t *v)
 static __always_inline int
 atomic_read_acquire(const atomic_t *v)
 {
-	__atomic_check_read(v, sizeof(*v));
+	instrument_atomic_read(v, sizeof(*v));
 	return arch_atomic_read_acquire(v);
 }
 #define atomic_read_acquire atomic_read_acquire
@@ -55,7 +42,7 @@ atomic_read_acquire(const atomic_t *v)
 static __always_inline void
 atomic_set(atomic_t *v, int i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_set(v, i);
 }
 #define atomic_set atomic_set
@@ -64,7 +51,7 @@ atomic_set(atomic_t *v, int i)
 static __always_inline void
 atomic_set_release(atomic_t *v, int i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_set_release(v, i);
 }
 #define atomic_set_release atomic_set_release
@@ -73,7 +60,7 @@ atomic_set_release(atomic_t *v, int i)
 static __always_inline void
 atomic_add(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_add(i, v);
 }
 #define atomic_add atomic_add
@@ -82,7 +69,7 @@ atomic_add(int i, atomic_t *v)
 static __always_inline int
 atomic_add_return(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_add_return(i, v);
 }
 #define atomic_add_return atomic_add_return
@@ -92,7 +79,7 @@ atomic_add_return(int i, atomic_t *v)
 static __always_inline int
 atomic_add_return_acquire(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_add_return_acquire(i, v);
 }
 #define atomic_add_return_acquire atomic_add_return_acquire
@@ -102,7 +89,7 @@ atomic_add_return_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_add_return_release(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_add_return_release(i, v);
 }
 #define atomic_add_return_release atomic_add_return_release
@@ -112,7 +99,7 @@ atomic_add_return_release(int i, atomic_t *v)
 static __always_inline int
 atomic_add_return_relaxed(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_add_return_relaxed(i, v);
 }
 #define atomic_add_return_relaxed atomic_add_return_relaxed
@@ -122,7 +109,7 @@ atomic_add_return_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_add(i, v);
 }
 #define atomic_fetch_add atomic_fetch_add
@@ -132,7 +119,7 @@ atomic_fetch_add(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add_acquire(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_add_acquire(i, v);
 }
 #define atomic_fetch_add_acquire atomic_fetch_add_acquire
@@ -142,7 +129,7 @@ atomic_fetch_add_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add_release(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_add_release(i, v);
 }
 #define atomic_fetch_add_release atomic_fetch_add_release
@@ -152,7 +139,7 @@ atomic_fetch_add_release(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add_relaxed(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_add_relaxed(i, v);
 }
 #define atomic_fetch_add_relaxed atomic_fetch_add_relaxed
@@ -161,7 +148,7 @@ atomic_fetch_add_relaxed(int i, atomic_t *v)
 static __always_inline void
 atomic_sub(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_sub(i, v);
 }
 #define atomic_sub atomic_sub
@@ -170,7 +157,7 @@ atomic_sub(int i, atomic_t *v)
 static __always_inline int
 atomic_sub_return(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_sub_return(i, v);
 }
 #define atomic_sub_return atomic_sub_return
@@ -180,7 +167,7 @@ atomic_sub_return(int i, atomic_t *v)
 static __always_inline int
 atomic_sub_return_acquire(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_sub_return_acquire(i, v);
 }
 #define atomic_sub_return_acquire atomic_sub_return_acquire
@@ -190,7 +177,7 @@ atomic_sub_return_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_sub_return_release(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_sub_return_release(i, v);
 }
 #define atomic_sub_return_release atomic_sub_return_release
@@ -200,7 +187,7 @@ atomic_sub_return_release(int i, atomic_t *v)
 static __always_inline int
 atomic_sub_return_relaxed(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_sub_return_relaxed(i, v);
 }
 #define atomic_sub_return_relaxed atomic_sub_return_relaxed
@@ -210,7 +197,7 @@ atomic_sub_return_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_sub(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_sub(i, v);
 }
 #define atomic_fetch_sub atomic_fetch_sub
@@ -220,7 +207,7 @@ atomic_fetch_sub(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_sub_acquire(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_sub_acquire(i, v);
 }
 #define atomic_fetch_sub_acquire atomic_fetch_sub_acquire
@@ -230,7 +217,7 @@ atomic_fetch_sub_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_sub_release(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_sub_release(i, v);
 }
 #define atomic_fetch_sub_release atomic_fetch_sub_release
@@ -240,7 +227,7 @@ atomic_fetch_sub_release(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_sub_relaxed(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_sub_relaxed(i, v);
 }
 #define atomic_fetch_sub_relaxed atomic_fetch_sub_relaxed
@@ -250,7 +237,7 @@ atomic_fetch_sub_relaxed(int i, atomic_t *v)
 static __always_inline void
 atomic_inc(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_inc(v);
 }
 #define atomic_inc atomic_inc
@@ -260,7 +247,7 @@ atomic_inc(atomic_t *v)
 static __always_inline int
 atomic_inc_return(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_inc_return(v);
 }
 #define atomic_inc_return atomic_inc_return
@@ -270,7 +257,7 @@ atomic_inc_return(atomic_t *v)
 static __always_inline int
 atomic_inc_return_acquire(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_inc_return_acquire(v);
 }
 #define atomic_inc_return_acquire atomic_inc_return_acquire
@@ -280,7 +267,7 @@ atomic_inc_return_acquire(atomic_t *v)
 static __always_inline int
 atomic_inc_return_release(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_inc_return_release(v);
 }
 #define atomic_inc_return_release atomic_inc_return_release
@@ -290,7 +277,7 @@ atomic_inc_return_release(atomic_t *v)
 static __always_inline int
 atomic_inc_return_relaxed(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_inc_return_relaxed(v);
 }
 #define atomic_inc_return_relaxed atomic_inc_return_relaxed
@@ -300,7 +287,7 @@ atomic_inc_return_relaxed(atomic_t *v)
 static __always_inline int
 atomic_fetch_inc(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_inc(v);
 }
 #define atomic_fetch_inc atomic_fetch_inc
@@ -310,7 +297,7 @@ atomic_fetch_inc(atomic_t *v)
 static __always_inline int
 atomic_fetch_inc_acquire(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_inc_acquire(v);
 }
 #define atomic_fetch_inc_acquire atomic_fetch_inc_acquire
@@ -320,7 +307,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
 static __always_inline int
 atomic_fetch_inc_release(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_inc_release(v);
 }
 #define atomic_fetch_inc_release atomic_fetch_inc_release
@@ -330,7 +317,7 @@ atomic_fetch_inc_release(atomic_t *v)
 static __always_inline int
 atomic_fetch_inc_relaxed(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_inc_relaxed(v);
 }
 #define atomic_fetch_inc_relaxed atomic_fetch_inc_relaxed
@@ -340,7 +327,7 @@ atomic_fetch_inc_relaxed(atomic_t *v)
 static __always_inline void
 atomic_dec(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_dec(v);
 }
 #define atomic_dec atomic_dec
@@ -350,7 +337,7 @@ atomic_dec(atomic_t *v)
 static __always_inline int
 atomic_dec_return(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_dec_return(v);
 }
 #define atomic_dec_return atomic_dec_return
@@ -360,7 +347,7 @@ atomic_dec_return(atomic_t *v)
 static __always_inline int
 atomic_dec_return_acquire(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_dec_return_acquire(v);
 }
 #define atomic_dec_return_acquire atomic_dec_return_acquire
@@ -370,7 +357,7 @@ atomic_dec_return_acquire(atomic_t *v)
 static __always_inline int
 atomic_dec_return_release(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_dec_return_release(v);
 }
 #define atomic_dec_return_release atomic_dec_return_release
@@ -380,7 +367,7 @@ atomic_dec_return_release(atomic_t *v)
 static __always_inline int
 atomic_dec_return_relaxed(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_dec_return_relaxed(v);
 }
 #define atomic_dec_return_relaxed atomic_dec_return_relaxed
@@ -390,7 +377,7 @@ atomic_dec_return_relaxed(atomic_t *v)
 static __always_inline int
 atomic_fetch_dec(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_dec(v);
 }
 #define atomic_fetch_dec atomic_fetch_dec
@@ -400,7 +387,7 @@ atomic_fetch_dec(atomic_t *v)
 static __always_inline int
 atomic_fetch_dec_acquire(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_dec_acquire(v);
 }
 #define atomic_fetch_dec_acquire atomic_fetch_dec_acquire
@@ -410,7 +397,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
 static __always_inline int
 atomic_fetch_dec_release(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_dec_release(v);
 }
 #define atomic_fetch_dec_release atomic_fetch_dec_release
@@ -420,7 +407,7 @@ atomic_fetch_dec_release(atomic_t *v)
 static __always_inline int
 atomic_fetch_dec_relaxed(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_dec_relaxed(v);
 }
 #define atomic_fetch_dec_relaxed atomic_fetch_dec_relaxed
@@ -429,7 +416,7 @@ atomic_fetch_dec_relaxed(atomic_t *v)
 static __always_inline void
 atomic_and(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_and(i, v);
 }
 #define atomic_and atomic_and
@@ -438,7 +425,7 @@ atomic_and(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_and(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_and(i, v);
 }
 #define atomic_fetch_and atomic_fetch_and
@@ -448,7 +435,7 @@ atomic_fetch_and(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_and_acquire(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_and_acquire(i, v);
 }
 #define atomic_fetch_and_acquire atomic_fetch_and_acquire
@@ -458,7 +445,7 @@ atomic_fetch_and_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_and_release(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_and_release(i, v);
 }
 #define atomic_fetch_and_release atomic_fetch_and_release
@@ -468,7 +455,7 @@ atomic_fetch_and_release(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_and_relaxed(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_and_relaxed(i, v);
 }
 #define atomic_fetch_and_relaxed atomic_fetch_and_relaxed
@@ -478,7 +465,7 @@ atomic_fetch_and_relaxed(int i, atomic_t *v)
 static __always_inline void
 atomic_andnot(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_andnot(i, v);
 }
 #define atomic_andnot atomic_andnot
@@ -488,7 +475,7 @@ atomic_andnot(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_andnot(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_andnot(i, v);
 }
 #define atomic_fetch_andnot atomic_fetch_andnot
@@ -498,7 +485,7 @@ atomic_fetch_andnot(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_andnot_acquire(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_andnot_acquire(i, v);
 }
 #define atomic_fetch_andnot_acquire atomic_fetch_andnot_acquire
@@ -508,7 +495,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_andnot_release(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_andnot_release(i, v);
 }
 #define atomic_fetch_andnot_release atomic_fetch_andnot_release
@@ -518,7 +505,7 @@ atomic_fetch_andnot_release(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_andnot_relaxed(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_andnot_relaxed(i, v);
 }
 #define atomic_fetch_andnot_relaxed atomic_fetch_andnot_relaxed
@@ -527,7 +514,7 @@ atomic_fetch_andnot_relaxed(int i, atomic_t *v)
 static __always_inline void
 atomic_or(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_or(i, v);
 }
 #define atomic_or atomic_or
@@ -536,7 +523,7 @@ atomic_or(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_or(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_or(i, v);
 }
 #define atomic_fetch_or atomic_fetch_or
@@ -546,7 +533,7 @@ atomic_fetch_or(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_or_acquire(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_or_acquire(i, v);
 }
 #define atomic_fetch_or_acquire atomic_fetch_or_acquire
@@ -556,7 +543,7 @@ atomic_fetch_or_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_or_release(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_or_release(i, v);
 }
 #define atomic_fetch_or_release atomic_fetch_or_release
@@ -566,7 +553,7 @@ atomic_fetch_or_release(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_or_relaxed(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_or_relaxed(i, v);
 }
 #define atomic_fetch_or_relaxed atomic_fetch_or_relaxed
@@ -575,7 +562,7 @@ atomic_fetch_or_relaxed(int i, atomic_t *v)
 static __always_inline void
 atomic_xor(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic_xor(i, v);
 }
 #define atomic_xor atomic_xor
@@ -584,7 +571,7 @@ atomic_xor(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_xor(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_xor(i, v);
 }
 #define atomic_fetch_xor atomic_fetch_xor
@@ -594,7 +581,7 @@ atomic_fetch_xor(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_xor_acquire(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_xor_acquire(i, v);
 }
 #define atomic_fetch_xor_acquire atomic_fetch_xor_acquire
@@ -604,7 +591,7 @@ atomic_fetch_xor_acquire(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_xor_release(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_xor_release(i, v);
 }
 #define atomic_fetch_xor_release atomic_fetch_xor_release
@@ -614,7 +601,7 @@ atomic_fetch_xor_release(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_xor_relaxed(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_xor_relaxed(i, v);
 }
 #define atomic_fetch_xor_relaxed atomic_fetch_xor_relaxed
@@ -624,7 +611,7 @@ atomic_fetch_xor_relaxed(int i, atomic_t *v)
 static __always_inline int
 atomic_xchg(atomic_t *v, int i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_xchg(v, i);
 }
 #define atomic_xchg atomic_xchg
@@ -634,7 +621,7 @@ atomic_xchg(atomic_t *v, int i)
 static __always_inline int
 atomic_xchg_acquire(atomic_t *v, int i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_xchg_acquire(v, i);
 }
 #define atomic_xchg_acquire atomic_xchg_acquire
@@ -644,7 +631,7 @@ atomic_xchg_acquire(atomic_t *v, int i)
 static __always_inline int
 atomic_xchg_release(atomic_t *v, int i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_xchg_release(v, i);
 }
 #define atomic_xchg_release atomic_xchg_release
@@ -654,7 +641,7 @@ atomic_xchg_release(atomic_t *v, int i)
 static __always_inline int
 atomic_xchg_relaxed(atomic_t *v, int i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_xchg_relaxed(v, i);
 }
 #define atomic_xchg_relaxed atomic_xchg_relaxed
@@ -664,7 +651,7 @@ atomic_xchg_relaxed(atomic_t *v, int i)
 static __always_inline int
 atomic_cmpxchg(atomic_t *v, int old, int new)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_cmpxchg(v, old, new);
 }
 #define atomic_cmpxchg atomic_cmpxchg
@@ -674,7 +661,7 @@ atomic_cmpxchg(atomic_t *v, int old, int new)
 static __always_inline int
 atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_cmpxchg_acquire(v, old, new);
 }
 #define atomic_cmpxchg_acquire atomic_cmpxchg_acquire
@@ -684,7 +671,7 @@ atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 static __always_inline int
 atomic_cmpxchg_release(atomic_t *v, int old, int new)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_cmpxchg_release(v, old, new);
 }
 #define atomic_cmpxchg_release atomic_cmpxchg_release
@@ -694,7 +681,7 @@ atomic_cmpxchg_release(atomic_t *v, int old, int new)
 static __always_inline int
 atomic_cmpxchg_relaxed(atomic_t *v, int old, int new)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_cmpxchg_relaxed(v, old, new);
 }
 #define atomic_cmpxchg_relaxed atomic_cmpxchg_relaxed
@@ -704,8 +691,8 @@ atomic_cmpxchg_relaxed(atomic_t *v, int old, int new)
 static __always_inline bool
 atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 {
-	__atomic_check_write(v, sizeof(*v));
-	__atomic_check_write(old, sizeof(*old));
+	instrument_atomic_write(v, sizeof(*v));
+	instrument_atomic_write(old, sizeof(*old));
 	return arch_atomic_try_cmpxchg(v, old, new);
 }
 #define atomic_try_cmpxchg atomic_try_cmpxchg
@@ -715,8 +702,8 @@ atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 static __always_inline bool
 atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 {
-	__atomic_check_write(v, sizeof(*v));
-	__atomic_check_write(old, sizeof(*old));
+	instrument_atomic_write(v, sizeof(*v));
+	instrument_atomic_write(old, sizeof(*old));
 	return arch_atomic_try_cmpxchg_acquire(v, old, new);
 }
 #define atomic_try_cmpxchg_acquire atomic_try_cmpxchg_acquire
@@ -726,8 +713,8 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 static __always_inline bool
 atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 {
-	__atomic_check_write(v, sizeof(*v));
-	__atomic_check_write(old, sizeof(*old));
+	instrument_atomic_write(v, sizeof(*v));
+	instrument_atomic_write(old, sizeof(*old));
 	return arch_atomic_try_cmpxchg_release(v, old, new);
 }
 #define atomic_try_cmpxchg_release atomic_try_cmpxchg_release
@@ -737,8 +724,8 @@ atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 static __always_inline bool
 atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 {
-	__atomic_check_write(v, sizeof(*v));
-	__atomic_check_write(old, sizeof(*old));
+	instrument_atomic_write(v, sizeof(*v));
+	instrument_atomic_write(old, sizeof(*old));
 	return arch_atomic_try_cmpxchg_relaxed(v, old, new);
 }
 #define atomic_try_cmpxchg_relaxed atomic_try_cmpxchg_relaxed
@@ -748,7 +735,7 @@ atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 static __always_inline bool
 atomic_sub_and_test(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_sub_and_test(i, v);
 }
 #define atomic_sub_and_test atomic_sub_and_test
@@ -758,7 +745,7 @@ atomic_sub_and_test(int i, atomic_t *v)
 static __always_inline bool
 atomic_dec_and_test(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_dec_and_test(v);
 }
 #define atomic_dec_and_test atomic_dec_and_test
@@ -768,7 +755,7 @@ atomic_dec_and_test(atomic_t *v)
 static __always_inline bool
 atomic_inc_and_test(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_inc_and_test(v);
 }
 #define atomic_inc_and_test atomic_inc_and_test
@@ -778,7 +765,7 @@ atomic_inc_and_test(atomic_t *v)
 static __always_inline bool
 atomic_add_negative(int i, atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_add_negative(i, v);
 }
 #define atomic_add_negative atomic_add_negative
@@ -788,7 +775,7 @@ atomic_add_negative(int i, atomic_t *v)
 static __always_inline int
 atomic_fetch_add_unless(atomic_t *v, int a, int u)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_fetch_add_unless(v, a, u);
 }
 #define atomic_fetch_add_unless atomic_fetch_add_unless
@@ -798,7 +785,7 @@ atomic_fetch_add_unless(atomic_t *v, int a, int u)
 static __always_inline bool
 atomic_add_unless(atomic_t *v, int a, int u)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_add_unless(v, a, u);
 }
 #define atomic_add_unless atomic_add_unless
@@ -808,7 +795,7 @@ atomic_add_unless(atomic_t *v, int a, int u)
 static __always_inline bool
 atomic_inc_not_zero(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_inc_not_zero(v);
 }
 #define atomic_inc_not_zero atomic_inc_not_zero
@@ -818,7 +805,7 @@ atomic_inc_not_zero(atomic_t *v)
 static __always_inline bool
 atomic_inc_unless_negative(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_inc_unless_negative(v);
 }
 #define atomic_inc_unless_negative atomic_inc_unless_negative
@@ -828,7 +815,7 @@ atomic_inc_unless_negative(atomic_t *v)
 static __always_inline bool
 atomic_dec_unless_positive(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_dec_unless_positive(v);
 }
 #define atomic_dec_unless_positive atomic_dec_unless_positive
@@ -838,7 +825,7 @@ atomic_dec_unless_positive(atomic_t *v)
 static __always_inline int
 atomic_dec_if_positive(atomic_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic_dec_if_positive(v);
 }
 #define atomic_dec_if_positive atomic_dec_if_positive
@@ -847,7 +834,7 @@ atomic_dec_if_positive(atomic_t *v)
 static __always_inline s64
 atomic64_read(const atomic64_t *v)
 {
-	__atomic_check_read(v, sizeof(*v));
+	instrument_atomic_read(v, sizeof(*v));
 	return arch_atomic64_read(v);
 }
 #define atomic64_read atomic64_read
@@ -856,7 +843,7 @@ atomic64_read(const atomic64_t *v)
 static __always_inline s64
 atomic64_read_acquire(const atomic64_t *v)
 {
-	__atomic_check_read(v, sizeof(*v));
+	instrument_atomic_read(v, sizeof(*v));
 	return arch_atomic64_read_acquire(v);
 }
 #define atomic64_read_acquire atomic64_read_acquire
@@ -865,7 +852,7 @@ atomic64_read_acquire(const atomic64_t *v)
 static __always_inline void
 atomic64_set(atomic64_t *v, s64 i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_set(v, i);
 }
 #define atomic64_set atomic64_set
@@ -874,7 +861,7 @@ atomic64_set(atomic64_t *v, s64 i)
 static __always_inline void
 atomic64_set_release(atomic64_t *v, s64 i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_set_release(v, i);
 }
 #define atomic64_set_release atomic64_set_release
@@ -883,7 +870,7 @@ atomic64_set_release(atomic64_t *v, s64 i)
 static __always_inline void
 atomic64_add(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_add(i, v);
 }
 #define atomic64_add atomic64_add
@@ -892,7 +879,7 @@ atomic64_add(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_add_return(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_add_return(i, v);
 }
 #define atomic64_add_return atomic64_add_return
@@ -902,7 +889,7 @@ atomic64_add_return(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_add_return_acquire(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_add_return_acquire(i, v);
 }
 #define atomic64_add_return_acquire atomic64_add_return_acquire
@@ -912,7 +899,7 @@ atomic64_add_return_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_add_return_release(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_add_return_release(i, v);
 }
 #define atomic64_add_return_release atomic64_add_return_release
@@ -922,7 +909,7 @@ atomic64_add_return_release(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_add_return_relaxed(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_add_return_relaxed(i, v);
 }
 #define atomic64_add_return_relaxed atomic64_add_return_relaxed
@@ -932,7 +919,7 @@ atomic64_add_return_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add(i, v);
 }
 #define atomic64_fetch_add atomic64_fetch_add
@@ -942,7 +929,7 @@ atomic64_fetch_add(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add_acquire(i, v);
 }
 #define atomic64_fetch_add_acquire atomic64_fetch_add_acquire
@@ -952,7 +939,7 @@ atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add_release(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add_release(i, v);
 }
 #define atomic64_fetch_add_release atomic64_fetch_add_release
@@ -962,7 +949,7 @@ atomic64_fetch_add_release(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add_relaxed(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add_relaxed(i, v);
 }
 #define atomic64_fetch_add_relaxed atomic64_fetch_add_relaxed
@@ -971,7 +958,7 @@ atomic64_fetch_add_relaxed(s64 i, atomic64_t *v)
 static __always_inline void
 atomic64_sub(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_sub(i, v);
 }
 #define atomic64_sub atomic64_sub
@@ -980,7 +967,7 @@ atomic64_sub(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_sub_return(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_sub_return(i, v);
 }
 #define atomic64_sub_return atomic64_sub_return
@@ -990,7 +977,7 @@ atomic64_sub_return(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_sub_return_acquire(i, v);
 }
 #define atomic64_sub_return_acquire atomic64_sub_return_acquire
@@ -1000,7 +987,7 @@ atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_sub_return_release(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_sub_return_release(i, v);
 }
 #define atomic64_sub_return_release atomic64_sub_return_release
@@ -1010,7 +997,7 @@ atomic64_sub_return_release(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_sub_return_relaxed(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_sub_return_relaxed(i, v);
 }
 #define atomic64_sub_return_relaxed atomic64_sub_return_relaxed
@@ -1020,7 +1007,7 @@ atomic64_sub_return_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_sub(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_sub(i, v);
 }
 #define atomic64_fetch_sub atomic64_fetch_sub
@@ -1030,7 +1017,7 @@ atomic64_fetch_sub(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_sub_acquire(i, v);
 }
 #define atomic64_fetch_sub_acquire atomic64_fetch_sub_acquire
@@ -1040,7 +1027,7 @@ atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_sub_release(i, v);
 }
 #define atomic64_fetch_sub_release atomic64_fetch_sub_release
@@ -1050,7 +1037,7 @@ atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_sub_relaxed(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_sub_relaxed(i, v);
 }
 #define atomic64_fetch_sub_relaxed atomic64_fetch_sub_relaxed
@@ -1060,7 +1047,7 @@ atomic64_fetch_sub_relaxed(s64 i, atomic64_t *v)
 static __always_inline void
 atomic64_inc(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_inc(v);
 }
 #define atomic64_inc atomic64_inc
@@ -1070,7 +1057,7 @@ atomic64_inc(atomic64_t *v)
 static __always_inline s64
 atomic64_inc_return(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_inc_return(v);
 }
 #define atomic64_inc_return atomic64_inc_return
@@ -1080,7 +1067,7 @@ atomic64_inc_return(atomic64_t *v)
 static __always_inline s64
 atomic64_inc_return_acquire(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_inc_return_acquire(v);
 }
 #define atomic64_inc_return_acquire atomic64_inc_return_acquire
@@ -1090,7 +1077,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_inc_return_release(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_inc_return_release(v);
 }
 #define atomic64_inc_return_release atomic64_inc_return_release
@@ -1100,7 +1087,7 @@ atomic64_inc_return_release(atomic64_t *v)
 static __always_inline s64
 atomic64_inc_return_relaxed(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_inc_return_relaxed(v);
 }
 #define atomic64_inc_return_relaxed atomic64_inc_return_relaxed
@@ -1110,7 +1097,7 @@ atomic64_inc_return_relaxed(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_inc(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_inc(v);
 }
 #define atomic64_fetch_inc atomic64_fetch_inc
@@ -1120,7 +1107,7 @@ atomic64_fetch_inc(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_inc_acquire(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_inc_acquire(v);
 }
 #define atomic64_fetch_inc_acquire atomic64_fetch_inc_acquire
@@ -1130,7 +1117,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_inc_release(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_inc_release(v);
 }
 #define atomic64_fetch_inc_release atomic64_fetch_inc_release
@@ -1140,7 +1127,7 @@ atomic64_fetch_inc_release(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_inc_relaxed(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_inc_relaxed(v);
 }
 #define atomic64_fetch_inc_relaxed atomic64_fetch_inc_relaxed
@@ -1150,7 +1137,7 @@ atomic64_fetch_inc_relaxed(atomic64_t *v)
 static __always_inline void
 atomic64_dec(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_dec(v);
 }
 #define atomic64_dec atomic64_dec
@@ -1160,7 +1147,7 @@ atomic64_dec(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_return(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_dec_return(v);
 }
 #define atomic64_dec_return atomic64_dec_return
@@ -1170,7 +1157,7 @@ atomic64_dec_return(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_return_acquire(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_dec_return_acquire(v);
 }
 #define atomic64_dec_return_acquire atomic64_dec_return_acquire
@@ -1180,7 +1167,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_return_release(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_dec_return_release(v);
 }
 #define atomic64_dec_return_release atomic64_dec_return_release
@@ -1190,7 +1177,7 @@ atomic64_dec_return_release(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_return_relaxed(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_dec_return_relaxed(v);
 }
 #define atomic64_dec_return_relaxed atomic64_dec_return_relaxed
@@ -1200,7 +1187,7 @@ atomic64_dec_return_relaxed(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_dec(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_dec(v);
 }
 #define atomic64_fetch_dec atomic64_fetch_dec
@@ -1210,7 +1197,7 @@ atomic64_fetch_dec(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_dec_acquire(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_dec_acquire(v);
 }
 #define atomic64_fetch_dec_acquire atomic64_fetch_dec_acquire
@@ -1220,7 +1207,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_dec_release(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_dec_release(v);
 }
 #define atomic64_fetch_dec_release atomic64_fetch_dec_release
@@ -1230,7 +1217,7 @@ atomic64_fetch_dec_release(atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_dec_relaxed(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_dec_relaxed(v);
 }
 #define atomic64_fetch_dec_relaxed atomic64_fetch_dec_relaxed
@@ -1239,7 +1226,7 @@ atomic64_fetch_dec_relaxed(atomic64_t *v)
 static __always_inline void
 atomic64_and(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_and(i, v);
 }
 #define atomic64_and atomic64_and
@@ -1248,7 +1235,7 @@ atomic64_and(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_and(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_and(i, v);
 }
 #define atomic64_fetch_and atomic64_fetch_and
@@ -1258,7 +1245,7 @@ atomic64_fetch_and(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_and_acquire(i, v);
 }
 #define atomic64_fetch_and_acquire atomic64_fetch_and_acquire
@@ -1268,7 +1255,7 @@ atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_and_release(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_and_release(i, v);
 }
 #define atomic64_fetch_and_release atomic64_fetch_and_release
@@ -1278,7 +1265,7 @@ atomic64_fetch_and_release(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_and_relaxed(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_and_relaxed(i, v);
 }
 #define atomic64_fetch_and_relaxed atomic64_fetch_and_relaxed
@@ -1288,7 +1275,7 @@ atomic64_fetch_and_relaxed(s64 i, atomic64_t *v)
 static __always_inline void
 atomic64_andnot(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_andnot(i, v);
 }
 #define atomic64_andnot atomic64_andnot
@@ -1298,7 +1285,7 @@ atomic64_andnot(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_andnot(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_andnot(i, v);
 }
 #define atomic64_fetch_andnot atomic64_fetch_andnot
@@ -1308,7 +1295,7 @@ atomic64_fetch_andnot(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_andnot_acquire(i, v);
 }
 #define atomic64_fetch_andnot_acquire atomic64_fetch_andnot_acquire
@@ -1318,7 +1305,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_andnot_release(i, v);
 }
 #define atomic64_fetch_andnot_release atomic64_fetch_andnot_release
@@ -1328,7 +1315,7 @@ atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_andnot_relaxed(i, v);
 }
 #define atomic64_fetch_andnot_relaxed atomic64_fetch_andnot_relaxed
@@ -1337,7 +1324,7 @@ atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
 static __always_inline void
 atomic64_or(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_or(i, v);
 }
 #define atomic64_or atomic64_or
@@ -1346,7 +1333,7 @@ atomic64_or(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_or(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_or(i, v);
 }
 #define atomic64_fetch_or atomic64_fetch_or
@@ -1356,7 +1343,7 @@ atomic64_fetch_or(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_or_acquire(i, v);
 }
 #define atomic64_fetch_or_acquire atomic64_fetch_or_acquire
@@ -1366,7 +1353,7 @@ atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_or_release(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_or_release(i, v);
 }
 #define atomic64_fetch_or_release atomic64_fetch_or_release
@@ -1376,7 +1363,7 @@ atomic64_fetch_or_release(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_or_relaxed(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_or_relaxed(i, v);
 }
 #define atomic64_fetch_or_relaxed atomic64_fetch_or_relaxed
@@ -1385,7 +1372,7 @@ atomic64_fetch_or_relaxed(s64 i, atomic64_t *v)
 static __always_inline void
 atomic64_xor(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	arch_atomic64_xor(i, v);
 }
 #define atomic64_xor atomic64_xor
@@ -1394,7 +1381,7 @@ atomic64_xor(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_xor(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_xor(i, v);
 }
 #define atomic64_fetch_xor atomic64_fetch_xor
@@ -1404,7 +1391,7 @@ atomic64_fetch_xor(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_xor_acquire(i, v);
 }
 #define atomic64_fetch_xor_acquire atomic64_fetch_xor_acquire
@@ -1414,7 +1401,7 @@ atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_xor_release(i, v);
 }
 #define atomic64_fetch_xor_release atomic64_fetch_xor_release
@@ -1424,7 +1411,7 @@ atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_xor_relaxed(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_xor_relaxed(i, v);
 }
 #define atomic64_fetch_xor_relaxed atomic64_fetch_xor_relaxed
@@ -1434,7 +1421,7 @@ atomic64_fetch_xor_relaxed(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_xchg(atomic64_t *v, s64 i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_xchg(v, i);
 }
 #define atomic64_xchg atomic64_xchg
@@ -1444,7 +1431,7 @@ atomic64_xchg(atomic64_t *v, s64 i)
 static __always_inline s64
 atomic64_xchg_acquire(atomic64_t *v, s64 i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_xchg_acquire(v, i);
 }
 #define atomic64_xchg_acquire atomic64_xchg_acquire
@@ -1454,7 +1441,7 @@ atomic64_xchg_acquire(atomic64_t *v, s64 i)
 static __always_inline s64
 atomic64_xchg_release(atomic64_t *v, s64 i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_xchg_release(v, i);
 }
 #define atomic64_xchg_release atomic64_xchg_release
@@ -1464,7 +1451,7 @@ atomic64_xchg_release(atomic64_t *v, s64 i)
 static __always_inline s64
 atomic64_xchg_relaxed(atomic64_t *v, s64 i)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_xchg_relaxed(v, i);
 }
 #define atomic64_xchg_relaxed atomic64_xchg_relaxed
@@ -1474,7 +1461,7 @@ atomic64_xchg_relaxed(atomic64_t *v, s64 i)
 static __always_inline s64
 atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_cmpxchg(v, old, new);
 }
 #define atomic64_cmpxchg atomic64_cmpxchg
@@ -1484,7 +1471,7 @@ atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 static __always_inline s64
 atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_cmpxchg_acquire(v, old, new);
 }
 #define atomic64_cmpxchg_acquire atomic64_cmpxchg_acquire
@@ -1494,7 +1481,7 @@ atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 static __always_inline s64
 atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_cmpxchg_release(v, old, new);
 }
 #define atomic64_cmpxchg_release atomic64_cmpxchg_release
@@ -1504,7 +1491,7 @@ atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 static __always_inline s64
 atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_cmpxchg_relaxed(v, old, new);
 }
 #define atomic64_cmpxchg_relaxed atomic64_cmpxchg_relaxed
@@ -1514,8 +1501,8 @@ atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new)
 static __always_inline bool
 atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 {
-	__atomic_check_write(v, sizeof(*v));
-	__atomic_check_write(old, sizeof(*old));
+	instrument_atomic_write(v, sizeof(*v));
+	instrument_atomic_write(old, sizeof(*old));
 	return arch_atomic64_try_cmpxchg(v, old, new);
 }
 #define atomic64_try_cmpxchg atomic64_try_cmpxchg
@@ -1525,8 +1512,8 @@ atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 static __always_inline bool
 atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 {
-	__atomic_check_write(v, sizeof(*v));
-	__atomic_check_write(old, sizeof(*old));
+	instrument_atomic_write(v, sizeof(*v));
+	instrument_atomic_write(old, sizeof(*old));
 	return arch_atomic64_try_cmpxchg_acquire(v, old, new);
 }
 #define atomic64_try_cmpxchg_acquire atomic64_try_cmpxchg_acquire
@@ -1536,8 +1523,8 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 static __always_inline bool
 atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 {
-	__atomic_check_write(v, sizeof(*v));
-	__atomic_check_write(old, sizeof(*old));
+	instrument_atomic_write(v, sizeof(*v));
+	instrument_atomic_write(old, sizeof(*old));
 	return arch_atomic64_try_cmpxchg_release(v, old, new);
 }
 #define atomic64_try_cmpxchg_release atomic64_try_cmpxchg_release
@@ -1547,8 +1534,8 @@ atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 static __always_inline bool
 atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 {
-	__atomic_check_write(v, sizeof(*v));
-	__atomic_check_write(old, sizeof(*old));
+	instrument_atomic_write(v, sizeof(*v));
+	instrument_atomic_write(old, sizeof(*old));
 	return arch_atomic64_try_cmpxchg_relaxed(v, old, new);
 }
 #define atomic64_try_cmpxchg_relaxed atomic64_try_cmpxchg_relaxed
@@ -1558,7 +1545,7 @@ atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 static __always_inline bool
 atomic64_sub_and_test(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_sub_and_test(i, v);
 }
 #define atomic64_sub_and_test atomic64_sub_and_test
@@ -1568,7 +1555,7 @@ atomic64_sub_and_test(s64 i, atomic64_t *v)
 static __always_inline bool
 atomic64_dec_and_test(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_dec_and_test(v);
 }
 #define atomic64_dec_and_test atomic64_dec_and_test
@@ -1578,7 +1565,7 @@ atomic64_dec_and_test(atomic64_t *v)
 static __always_inline bool
 atomic64_inc_and_test(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_inc_and_test(v);
 }
 #define atomic64_inc_and_test atomic64_inc_and_test
@@ -1588,7 +1575,7 @@ atomic64_inc_and_test(atomic64_t *v)
 static __always_inline bool
 atomic64_add_negative(s64 i, atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_add_negative(i, v);
 }
 #define atomic64_add_negative atomic64_add_negative
@@ -1598,7 +1585,7 @@ atomic64_add_negative(s64 i, atomic64_t *v)
 static __always_inline s64
 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_fetch_add_unless(v, a, u);
 }
 #define atomic64_fetch_add_unless atomic64_fetch_add_unless
@@ -1608,7 +1595,7 @@ atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 static __always_inline bool
 atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_add_unless(v, a, u);
 }
 #define atomic64_add_unless atomic64_add_unless
@@ -1618,7 +1605,7 @@ atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 static __always_inline bool
 atomic64_inc_not_zero(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_inc_not_zero(v);
 }
 #define atomic64_inc_not_zero atomic64_inc_not_zero
@@ -1628,7 +1615,7 @@ atomic64_inc_not_zero(atomic64_t *v)
 static __always_inline bool
 atomic64_inc_unless_negative(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_inc_unless_negative(v);
 }
 #define atomic64_inc_unless_negative atomic64_inc_unless_negative
@@ -1638,7 +1625,7 @@ atomic64_inc_unless_negative(atomic64_t *v)
 static __always_inline bool
 atomic64_dec_unless_positive(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_dec_unless_positive(v);
 }
 #define atomic64_dec_unless_positive atomic64_dec_unless_positive
@@ -1648,7 +1635,7 @@ atomic64_dec_unless_positive(atomic64_t *v)
 static __always_inline s64
 atomic64_dec_if_positive(atomic64_t *v)
 {
-	__atomic_check_write(v, sizeof(*v));
+	instrument_atomic_write(v, sizeof(*v));
 	return arch_atomic64_dec_if_positive(v);
 }
 #define atomic64_dec_if_positive atomic64_dec_if_positive
@@ -1658,7 +1645,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define xchg(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_xchg(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1667,7 +1654,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define xchg_acquire(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_xchg_acquire(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1676,7 +1663,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define xchg_release(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_xchg_release(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1685,7 +1672,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define xchg_relaxed(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_xchg_relaxed(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1694,7 +1681,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1703,7 +1690,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg_acquire(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg_acquire(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1712,7 +1699,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg_release(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg_release(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1721,7 +1708,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg_relaxed(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg_relaxed(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1730,7 +1717,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg64(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg64(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1739,7 +1726,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg64_acquire(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg64_acquire(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1748,7 +1735,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg64_release(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg64_release(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1757,7 +1744,7 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg64_relaxed(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg64_relaxed(__ai_ptr, __VA_ARGS__);				\
 })
 #endif
@@ -1765,28 +1752,28 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg_local(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg_local(__ai_ptr, __VA_ARGS__);				\
 })
 
 #define cmpxchg64_local(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_cmpxchg64_local(__ai_ptr, __VA_ARGS__);				\
 })
 
 #define sync_cmpxchg(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, sizeof(*__ai_ptr));		\
 	arch_sync_cmpxchg(__ai_ptr, __VA_ARGS__);				\
 })
 
 #define cmpxchg_double(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, 2 * sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr));		\
 	arch_cmpxchg_double(__ai_ptr, __VA_ARGS__);				\
 })
 
@@ -1794,9 +1781,9 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define cmpxchg_double_local(ptr, ...)						\
 ({									\
 	typeof(ptr) __ai_ptr = (ptr);					\
-	__atomic_check_write(__ai_ptr, 2 * sizeof(*__ai_ptr));		\
+	instrument_atomic_write(__ai_ptr, 2 * sizeof(*__ai_ptr));		\
 	arch_cmpxchg_double_local(__ai_ptr, __VA_ARGS__);				\
 })
 
 #endif /* _ASM_GENERIC_ATOMIC_INSTRUMENTED_H */
-// 7b7e2af0e75c8ecb6f02298a7075f503f30d244c
+// 89bf97f3a7509b740845e51ddf31055b48a81f40
diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
index fb4222548b22..6afadf73da17 100755
--- a/scripts/atomic/gen-atomic-instrumented.sh
+++ b/scripts/atomic/gen-atomic-instrumented.sh
@@ -20,7 +20,7 @@ gen_param_check()
 	# We don't write to constant parameters
 	[ ${type#c} != ${type} ] && rw="read"
 
-	printf "\t__atomic_check_${rw}(${name}, sizeof(*${name}));\n"
+	printf "\tinstrument_atomic_${rw}(${name}, sizeof(*${name}));\n"
 }
 
 #gen_param_check(arg...)
@@ -107,7 +107,7 @@ cat <<EOF
 #define ${xchg}(ptr, ...)						\\
 ({									\\
 	typeof(ptr) __ai_ptr = (ptr);					\\
-	__atomic_check_write(__ai_ptr, ${mult}sizeof(*__ai_ptr));		\\
+	instrument_atomic_write(__ai_ptr, ${mult}sizeof(*__ai_ptr));		\\
 	arch_${xchg}(__ai_ptr, __VA_ARGS__);				\\
 })
 EOF
@@ -148,20 +148,7 @@ cat << EOF
 
 #include <linux/build_bug.h>
 #include <linux/compiler.h>
-#include <linux/kasan-checks.h>
-#include <linux/kcsan-checks.h>
-
-static __always_inline void __atomic_check_read(const volatile void *v, size_t size)
-{
-	kasan_check_read(v, size);
-	kcsan_check_atomic_read(v, size);
-}
-
-static __always_inline void __atomic_check_write(const volatile void *v, size_t size)
-{
-	kasan_check_write(v, size);
-	kcsan_check_atomic_write(v, size);
-}
+#include <linux/instrumented.h>
 
 EOF
 
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200121160512.70887-2-elver%40google.com.
