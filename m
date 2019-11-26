Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBXC6TXAKGQEXLJSCFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A6AB1109FD2
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 15:04:55 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id n125sf12802983ywb.6
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 06:04:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574777094; cv=pass;
        d=google.com; s=arc-20160816;
        b=LnG/h02x7C4WoALatPMYNt7v6k4ruRHpcHvV/Hfx8M0QWkdOuf00Mco4YN4uXH6k6j
         8u179ZicHPIgPqR/7iyb8yi2nmysG2ON2OpccNOT7tJuvN6FWOvQePbfhMuBBCGL1/wX
         My7wazDeT8+1IGbTnT3sB1RBFuVm5PcJx4FsMqipr6RLQU+GAokdxbrS7RNEiE/AMj+7
         2unA2HV96PVchRYgWcVMJONLWx7G/1e06dsurI5Vaq4nRn5fynTjAw5XgsQi5Kcmv0/a
         YrWVDvlZEggz/t2gxE7tW6FH8vBqVJXSTV2T2tFQg1P5nec7vrStS4gmY81nlVZgulG7
         Bong==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=ZJB1CI9MCbBwzqBcLNxKj6d7Wd/Ha+0qw0EqvN08wQE=;
        b=Cm61za8Nd54Ka27u5UAFmEk2H7yeVH4gpG2wvFj3gPSZr05dnYW7O+uSPxHffaaXxp
         uqSBTZmy2a6QHjgy+9CE9xA1AOQFWIx5cB7XDJyUjouxTCxaTx36WIG+0pZG6vWdX+Yb
         WPQOH33pc/WztuXkTFZaeUpFaysVQpum5wsZBYVRNdm3IXGOGBk1E3ROxSUCH/C2jC/a
         d4VHWEwUpvoatx+GAz61vZOZk+AyWytDlafttxyWDC3zwkkatZDKAsrcGLtxWGvfqUam
         OztXS+MzHB2D/FAX4RFS/Ce7JPj01ocPH2oWwRKJIMNoc/r4O96ByBYfDy8bMM6jZGPg
         Mm2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tAJANXeQ;
       spf=pass (google.com: domain of 3bdhdxqukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3BDHdXQUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZJB1CI9MCbBwzqBcLNxKj6d7Wd/Ha+0qw0EqvN08wQE=;
        b=pVhJKc2//fJI5EOdYzTl+DKFjAMmF9B92pOIbCexTj6bSKiBdY+1bm8xInbC0B4a9n
         44ssqg6lHrPio1egfmK7bjQ/0N9xILSpyqMP/XC6HEbcFrjoUyd8C1UACbAsY/tAPTL/
         CllZr6OypZTWO9P668e+SIgMaRJfOh+8wtuPSgq8CdYTFf+c9/Bh1rL/w6El4Z0AsrqM
         4oiFZ4OhAE9MjokX+x+/E8tQ/fmNJztbI2wfehELoesa4vYF2PrmdtIivDOuSkoB3mIU
         BEIOactnwdzfTYBiGaQuKMW3fMI5kbPfkkjrsT/PNL0eRMdbgklSyLovjPLCX13OP70v
         zBPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZJB1CI9MCbBwzqBcLNxKj6d7Wd/Ha+0qw0EqvN08wQE=;
        b=Eg1egURFJP6qWk+oFn7wbanFU+6jfeVDJBGmRxLvtnWtAuSqjkJuk/1pzmHsF1PzpA
         o+CSTVlFkG3k7aHeBTHQvw3nWKwqC/fJvb8UYVDTeRjiHxpX5pX0XEl3ZBNG6aFG/D6e
         IR8RxUKvr+6LC3JUK7ckT/bqCjZZmW4HldsuPhZbHehMigbih+O8Al9UM40zAPRFGH8g
         PAKvf/29UXOPqMYoHmzhz0FY2BduON8jk+LKpT5rBaYmJIvh7LE9jO7moPIj/KvQnLpo
         n7bkA7nqms/pU6quBQD0YxEr+5IUWtukUueACvfYEDNYJCZdRwP9UkHPMcDAiJ5FjDAp
         yQlA==
X-Gm-Message-State: APjAAAXux02Sqvr/5+ufQCWNI2SkQjjiB58meFWpCvH3VAUeDJOK4dLz
	dkGwZ/6MDzJklCTLNeqL1+E=
X-Google-Smtp-Source: APXvYqxcNwkTu9hx5zV7Xbxrb1H/k1D0vBD9vYCCKsSJL/Yu6tPzDCuq9vdosNBWAklCEDq5aSilzQ==
X-Received: by 2002:a81:9bcf:: with SMTP id s198mr23804126ywg.450.1574777094188;
        Tue, 26 Nov 2019 06:04:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:adcd:: with SMTP id d13ls3489429ybe.10.gmail; Tue, 26
 Nov 2019 06:04:53 -0800 (PST)
X-Received: by 2002:a25:b219:: with SMTP id i25mr28262264ybj.195.1574777093359;
        Tue, 26 Nov 2019 06:04:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574777093; cv=none;
        d=google.com; s=arc-20160816;
        b=FREQP9f7quNv4S6TgodmjTvAOJhU2DBBqWD54jIm7fTMJ/28ZSP18RkbrHTEH5ye4+
         qhwBqx6Z6Het0ZsTRm042L42yvTENw6hyx+CNEkLWvpCav1YWBw2S54CzJ3X80rM4Uvm
         VJqn1XMQHcs+ScQ7VDdzDo92YKIxwSidB6Fh/08AkE+OdpTTbtEnOnY3pGCoZzO14vY8
         wWftPSQtQvgQq+h4B8VdgLUTWPZlj7VjJ3UwxBvaJ3oz1oFUcQra1VD50AFYvamb64e4
         zNv982K/a405GJz0uny1iDXcL4wDT2IgEQx3GPOaju8/3K2PNkFeimDdQDWbNOe/yRBU
         iEHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=9Xj5ljSjEIuudCq1lWAA39r3gUkzeQ7YBXohA4L7aNQ=;
        b=Qv97N04vvObNw1V0kb/aYuLyuwC6ItdOncub2rs0YC+wbfevrmu7S0/D3KAoYrS8av
         azkbl09+nyBY35FDRQ/GUfPVIvyxkcILSUtr18vMdVaI0cWXEQaFgYxx/sToOzQJ5GeS
         4uF7lTwDEZgWkQMGwhTU/uK6CJEDBRhq7yKnuz36xnmD4tDrNRy7myI/AK5obbGVwVrQ
         /HYd1IAyr7xf49gApm/0PFwCu5nArOoR0fdoiBv6L+hquG7lmc21oZNJtFikLwHYLN+h
         +5xOLkBNlL4wfU3aOiMAKdmERCWEQJuoYAbf9VXbivCP1aFDZ0yTLsju4BlDn/Ojji4v
         pWGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tAJANXeQ;
       spf=pass (google.com: domain of 3bdhdxqukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3BDHdXQUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id 5si435574ybl.1.2019.11.26.06.04.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Nov 2019 06:04:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bdhdxqukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id o144so8994833vko.13
        for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2019 06:04:53 -0800 (PST)
X-Received: by 2002:a67:de96:: with SMTP id r22mr22403139vsk.24.1574777092570;
 Tue, 26 Nov 2019 06:04:52 -0800 (PST)
Date: Tue, 26 Nov 2019 15:04:04 +0100
Message-Id: <20191126140406.164870-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v3 1/3] asm-generic/atomic: Use __always_inline for pure wrappers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: mark.rutland@arm.com, paulmck@kernel.org, linux-kernel@vger.kernel.org, 
	will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com, arnd@arndb.de, 
	dvyukov@google.com, linux-arch@vger.kernel.org, kasan-dev@googlegroups.com, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tAJANXeQ;       spf=pass
 (google.com: domain of 3bdhdxqukcc8z6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3BDHdXQUKCc8z6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

Prefer __always_inline for atomic wrappers. When building for size
(CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
inline even relatively small static inline functions that are assumed to
be inlinable such as atomic ops. This can cause problems, for example in
UACCESS regions.

By using __always_inline, we let the real implementation and not the
wrapper determine the final inlining preference.

For x86 tinyconfig we observe:
- vmlinux baseline: 1316204
- vmlinux with patch: 1315988 (-216 bytes)

This came up when addressing UACCESS warnings with CC_OPTIMIZE_FOR_SIZE
in the KCSAN runtime:
http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org

Reported-by: Randy Dunlap <rdunlap@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
---
v3:
* Reorder includes alphabetically (except <asm/..>).

v2: http://lkml.kernel.org/r/20191126114121.85552-1-elver@google.com
* Add missing '#include <linux/compiler.h>'
* Add size diff to commit message.

v1: http://lkml.kernel.org/r/20191122154221.247680-1-elver@google.com
---
 include/asm-generic/atomic-instrumented.h | 335 +++++++++++-----------
 include/asm-generic/atomic-long.h         | 331 ++++++++++-----------
 scripts/atomic/gen-atomic-instrumented.sh |   7 +-
 scripts/atomic/gen-atomic-long.sh         |   3 +-
 4 files changed, 340 insertions(+), 336 deletions(-)

diff --git a/include/asm-generic/atomic-instrumented.h b/include/asm-generic/atomic-instrumented.h
index 3dc0f38544f6..63869ded73ac 100644
--- a/include/asm-generic/atomic-instrumented.h
+++ b/include/asm-generic/atomic-instrumented.h
@@ -18,22 +18,23 @@
 #define _ASM_GENERIC_ATOMIC_INSTRUMENTED_H
 
 #include <linux/build_bug.h>
+#include <linux/compiler.h>
 #include <linux/kasan-checks.h>
 #include <linux/kcsan-checks.h>
 
-static inline void __atomic_check_read(const volatile void *v, size_t size)
+static __always_inline void __atomic_check_read(const volatile void *v, size_t size)
 {
 	kasan_check_read(v, size);
 	kcsan_check_atomic_read(v, size);
 }
 
-static inline void __atomic_check_write(const volatile void *v, size_t size)
+static __always_inline void __atomic_check_write(const volatile void *v, size_t size)
 {
 	kasan_check_write(v, size);
 	kcsan_check_atomic_write(v, size);
 }
 
-static inline int
+static __always_inline int
 atomic_read(const atomic_t *v)
 {
 	__atomic_check_read(v, sizeof(*v));
@@ -42,7 +43,7 @@ atomic_read(const atomic_t *v)
 #define atomic_read atomic_read
 
 #if defined(arch_atomic_read_acquire)
-static inline int
+static __always_inline int
 atomic_read_acquire(const atomic_t *v)
 {
 	__atomic_check_read(v, sizeof(*v));
@@ -51,7 +52,7 @@ atomic_read_acquire(const atomic_t *v)
 #define atomic_read_acquire atomic_read_acquire
 #endif
 
-static inline void
+static __always_inline void
 atomic_set(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -60,7 +61,7 @@ atomic_set(atomic_t *v, int i)
 #define atomic_set atomic_set
 
 #if defined(arch_atomic_set_release)
-static inline void
+static __always_inline void
 atomic_set_release(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -69,7 +70,7 @@ atomic_set_release(atomic_t *v, int i)
 #define atomic_set_release atomic_set_release
 #endif
 
-static inline void
+static __always_inline void
 atomic_add(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -78,7 +79,7 @@ atomic_add(int i, atomic_t *v)
 #define atomic_add atomic_add
 
 #if !defined(arch_atomic_add_return_relaxed) || defined(arch_atomic_add_return)
-static inline int
+static __always_inline int
 atomic_add_return(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -88,7 +89,7 @@ atomic_add_return(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_add_return_acquire)
-static inline int
+static __always_inline int
 atomic_add_return_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -98,7 +99,7 @@ atomic_add_return_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_add_return_release)
-static inline int
+static __always_inline int
 atomic_add_return_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -108,7 +109,7 @@ atomic_add_return_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_add_return_relaxed)
-static inline int
+static __always_inline int
 atomic_add_return_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -118,7 +119,7 @@ atomic_add_return_relaxed(int i, atomic_t *v)
 #endif
 
 #if !defined(arch_atomic_fetch_add_relaxed) || defined(arch_atomic_fetch_add)
-static inline int
+static __always_inline int
 atomic_fetch_add(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -128,7 +129,7 @@ atomic_fetch_add(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_add_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_add_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -138,7 +139,7 @@ atomic_fetch_add_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_add_release)
-static inline int
+static __always_inline int
 atomic_fetch_add_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -148,7 +149,7 @@ atomic_fetch_add_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_add_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_add_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -157,7 +158,7 @@ atomic_fetch_add_relaxed(int i, atomic_t *v)
 #define atomic_fetch_add_relaxed atomic_fetch_add_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic_sub(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -166,7 +167,7 @@ atomic_sub(int i, atomic_t *v)
 #define atomic_sub atomic_sub
 
 #if !defined(arch_atomic_sub_return_relaxed) || defined(arch_atomic_sub_return)
-static inline int
+static __always_inline int
 atomic_sub_return(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -176,7 +177,7 @@ atomic_sub_return(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_sub_return_acquire)
-static inline int
+static __always_inline int
 atomic_sub_return_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -186,7 +187,7 @@ atomic_sub_return_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_sub_return_release)
-static inline int
+static __always_inline int
 atomic_sub_return_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -196,7 +197,7 @@ atomic_sub_return_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_sub_return_relaxed)
-static inline int
+static __always_inline int
 atomic_sub_return_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -206,7 +207,7 @@ atomic_sub_return_relaxed(int i, atomic_t *v)
 #endif
 
 #if !defined(arch_atomic_fetch_sub_relaxed) || defined(arch_atomic_fetch_sub)
-static inline int
+static __always_inline int
 atomic_fetch_sub(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -216,7 +217,7 @@ atomic_fetch_sub(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_sub_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_sub_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -226,7 +227,7 @@ atomic_fetch_sub_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_sub_release)
-static inline int
+static __always_inline int
 atomic_fetch_sub_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -236,7 +237,7 @@ atomic_fetch_sub_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_sub_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_sub_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -246,7 +247,7 @@ atomic_fetch_sub_relaxed(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc)
-static inline void
+static __always_inline void
 atomic_inc(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -256,7 +257,7 @@ atomic_inc(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_return)
-static inline int
+static __always_inline int
 atomic_inc_return(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -266,7 +267,7 @@ atomic_inc_return(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_return_acquire)
-static inline int
+static __always_inline int
 atomic_inc_return_acquire(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -276,7 +277,7 @@ atomic_inc_return_acquire(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_return_release)
-static inline int
+static __always_inline int
 atomic_inc_return_release(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -286,7 +287,7 @@ atomic_inc_return_release(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_return_relaxed)
-static inline int
+static __always_inline int
 atomic_inc_return_relaxed(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -296,7 +297,7 @@ atomic_inc_return_relaxed(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_inc)
-static inline int
+static __always_inline int
 atomic_fetch_inc(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -306,7 +307,7 @@ atomic_fetch_inc(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_inc_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_inc_acquire(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -316,7 +317,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_inc_release)
-static inline int
+static __always_inline int
 atomic_fetch_inc_release(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -326,7 +327,7 @@ atomic_fetch_inc_release(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_inc_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_inc_relaxed(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -336,7 +337,7 @@ atomic_fetch_inc_relaxed(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec)
-static inline void
+static __always_inline void
 atomic_dec(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -346,7 +347,7 @@ atomic_dec(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_return)
-static inline int
+static __always_inline int
 atomic_dec_return(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -356,7 +357,7 @@ atomic_dec_return(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_return_acquire)
-static inline int
+static __always_inline int
 atomic_dec_return_acquire(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -366,7 +367,7 @@ atomic_dec_return_acquire(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_return_release)
-static inline int
+static __always_inline int
 atomic_dec_return_release(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -376,7 +377,7 @@ atomic_dec_return_release(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_return_relaxed)
-static inline int
+static __always_inline int
 atomic_dec_return_relaxed(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -386,7 +387,7 @@ atomic_dec_return_relaxed(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_dec)
-static inline int
+static __always_inline int
 atomic_fetch_dec(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -396,7 +397,7 @@ atomic_fetch_dec(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_dec_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_dec_acquire(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -406,7 +407,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_dec_release)
-static inline int
+static __always_inline int
 atomic_fetch_dec_release(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -416,7 +417,7 @@ atomic_fetch_dec_release(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_dec_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_dec_relaxed(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -425,7 +426,7 @@ atomic_fetch_dec_relaxed(atomic_t *v)
 #define atomic_fetch_dec_relaxed atomic_fetch_dec_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic_and(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -434,7 +435,7 @@ atomic_and(int i, atomic_t *v)
 #define atomic_and atomic_and
 
 #if !defined(arch_atomic_fetch_and_relaxed) || defined(arch_atomic_fetch_and)
-static inline int
+static __always_inline int
 atomic_fetch_and(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -444,7 +445,7 @@ atomic_fetch_and(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_and_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_and_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -454,7 +455,7 @@ atomic_fetch_and_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_and_release)
-static inline int
+static __always_inline int
 atomic_fetch_and_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -464,7 +465,7 @@ atomic_fetch_and_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_and_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_and_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -474,7 +475,7 @@ atomic_fetch_and_relaxed(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_andnot)
-static inline void
+static __always_inline void
 atomic_andnot(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -484,7 +485,7 @@ atomic_andnot(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_andnot)
-static inline int
+static __always_inline int
 atomic_fetch_andnot(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -494,7 +495,7 @@ atomic_fetch_andnot(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_andnot_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_andnot_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -504,7 +505,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_andnot_release)
-static inline int
+static __always_inline int
 atomic_fetch_andnot_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -514,7 +515,7 @@ atomic_fetch_andnot_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_andnot_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_andnot_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -523,7 +524,7 @@ atomic_fetch_andnot_relaxed(int i, atomic_t *v)
 #define atomic_fetch_andnot_relaxed atomic_fetch_andnot_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic_or(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -532,7 +533,7 @@ atomic_or(int i, atomic_t *v)
 #define atomic_or atomic_or
 
 #if !defined(arch_atomic_fetch_or_relaxed) || defined(arch_atomic_fetch_or)
-static inline int
+static __always_inline int
 atomic_fetch_or(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -542,7 +543,7 @@ atomic_fetch_or(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_or_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_or_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -552,7 +553,7 @@ atomic_fetch_or_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_or_release)
-static inline int
+static __always_inline int
 atomic_fetch_or_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -562,7 +563,7 @@ atomic_fetch_or_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_or_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_or_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -571,7 +572,7 @@ atomic_fetch_or_relaxed(int i, atomic_t *v)
 #define atomic_fetch_or_relaxed atomic_fetch_or_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic_xor(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -580,7 +581,7 @@ atomic_xor(int i, atomic_t *v)
 #define atomic_xor atomic_xor
 
 #if !defined(arch_atomic_fetch_xor_relaxed) || defined(arch_atomic_fetch_xor)
-static inline int
+static __always_inline int
 atomic_fetch_xor(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -590,7 +591,7 @@ atomic_fetch_xor(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_xor_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_xor_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -600,7 +601,7 @@ atomic_fetch_xor_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_xor_release)
-static inline int
+static __always_inline int
 atomic_fetch_xor_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -610,7 +611,7 @@ atomic_fetch_xor_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_xor_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_xor_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -620,7 +621,7 @@ atomic_fetch_xor_relaxed(int i, atomic_t *v)
 #endif
 
 #if !defined(arch_atomic_xchg_relaxed) || defined(arch_atomic_xchg)
-static inline int
+static __always_inline int
 atomic_xchg(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -630,7 +631,7 @@ atomic_xchg(atomic_t *v, int i)
 #endif
 
 #if defined(arch_atomic_xchg_acquire)
-static inline int
+static __always_inline int
 atomic_xchg_acquire(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -640,7 +641,7 @@ atomic_xchg_acquire(atomic_t *v, int i)
 #endif
 
 #if defined(arch_atomic_xchg_release)
-static inline int
+static __always_inline int
 atomic_xchg_release(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -650,7 +651,7 @@ atomic_xchg_release(atomic_t *v, int i)
 #endif
 
 #if defined(arch_atomic_xchg_relaxed)
-static inline int
+static __always_inline int
 atomic_xchg_relaxed(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -660,7 +661,7 @@ atomic_xchg_relaxed(atomic_t *v, int i)
 #endif
 
 #if !defined(arch_atomic_cmpxchg_relaxed) || defined(arch_atomic_cmpxchg)
-static inline int
+static __always_inline int
 atomic_cmpxchg(atomic_t *v, int old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -670,7 +671,7 @@ atomic_cmpxchg(atomic_t *v, int old, int new)
 #endif
 
 #if defined(arch_atomic_cmpxchg_acquire)
-static inline int
+static __always_inline int
 atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -680,7 +681,7 @@ atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 #endif
 
 #if defined(arch_atomic_cmpxchg_release)
-static inline int
+static __always_inline int
 atomic_cmpxchg_release(atomic_t *v, int old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -690,7 +691,7 @@ atomic_cmpxchg_release(atomic_t *v, int old, int new)
 #endif
 
 #if defined(arch_atomic_cmpxchg_relaxed)
-static inline int
+static __always_inline int
 atomic_cmpxchg_relaxed(atomic_t *v, int old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -700,7 +701,7 @@ atomic_cmpxchg_relaxed(atomic_t *v, int old, int new)
 #endif
 
 #if defined(arch_atomic_try_cmpxchg)
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -711,7 +712,7 @@ atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 #endif
 
 #if defined(arch_atomic_try_cmpxchg_acquire)
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -722,7 +723,7 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 #endif
 
 #if defined(arch_atomic_try_cmpxchg_release)
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -733,7 +734,7 @@ atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 #endif
 
 #if defined(arch_atomic_try_cmpxchg_relaxed)
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -744,7 +745,7 @@ atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 #endif
 
 #if defined(arch_atomic_sub_and_test)
-static inline bool
+static __always_inline bool
 atomic_sub_and_test(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -754,7 +755,7 @@ atomic_sub_and_test(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_and_test)
-static inline bool
+static __always_inline bool
 atomic_dec_and_test(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -764,7 +765,7 @@ atomic_dec_and_test(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_and_test)
-static inline bool
+static __always_inline bool
 atomic_inc_and_test(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -774,7 +775,7 @@ atomic_inc_and_test(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_add_negative)
-static inline bool
+static __always_inline bool
 atomic_add_negative(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -784,7 +785,7 @@ atomic_add_negative(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_add_unless)
-static inline int
+static __always_inline int
 atomic_fetch_add_unless(atomic_t *v, int a, int u)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -794,7 +795,7 @@ atomic_fetch_add_unless(atomic_t *v, int a, int u)
 #endif
 
 #if defined(arch_atomic_add_unless)
-static inline bool
+static __always_inline bool
 atomic_add_unless(atomic_t *v, int a, int u)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -804,7 +805,7 @@ atomic_add_unless(atomic_t *v, int a, int u)
 #endif
 
 #if defined(arch_atomic_inc_not_zero)
-static inline bool
+static __always_inline bool
 atomic_inc_not_zero(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -814,7 +815,7 @@ atomic_inc_not_zero(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_unless_negative)
-static inline bool
+static __always_inline bool
 atomic_inc_unless_negative(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -824,7 +825,7 @@ atomic_inc_unless_negative(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_unless_positive)
-static inline bool
+static __always_inline bool
 atomic_dec_unless_positive(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -834,7 +835,7 @@ atomic_dec_unless_positive(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_if_positive)
-static inline int
+static __always_inline int
 atomic_dec_if_positive(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -843,7 +844,7 @@ atomic_dec_if_positive(atomic_t *v)
 #define atomic_dec_if_positive atomic_dec_if_positive
 #endif
 
-static inline s64
+static __always_inline s64
 atomic64_read(const atomic64_t *v)
 {
 	__atomic_check_read(v, sizeof(*v));
@@ -852,7 +853,7 @@ atomic64_read(const atomic64_t *v)
 #define atomic64_read atomic64_read
 
 #if defined(arch_atomic64_read_acquire)
-static inline s64
+static __always_inline s64
 atomic64_read_acquire(const atomic64_t *v)
 {
 	__atomic_check_read(v, sizeof(*v));
@@ -861,7 +862,7 @@ atomic64_read_acquire(const atomic64_t *v)
 #define atomic64_read_acquire atomic64_read_acquire
 #endif
 
-static inline void
+static __always_inline void
 atomic64_set(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -870,7 +871,7 @@ atomic64_set(atomic64_t *v, s64 i)
 #define atomic64_set atomic64_set
 
 #if defined(arch_atomic64_set_release)
-static inline void
+static __always_inline void
 atomic64_set_release(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -879,7 +880,7 @@ atomic64_set_release(atomic64_t *v, s64 i)
 #define atomic64_set_release atomic64_set_release
 #endif
 
-static inline void
+static __always_inline void
 atomic64_add(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -888,7 +889,7 @@ atomic64_add(s64 i, atomic64_t *v)
 #define atomic64_add atomic64_add
 
 #if !defined(arch_atomic64_add_return_relaxed) || defined(arch_atomic64_add_return)
-static inline s64
+static __always_inline s64
 atomic64_add_return(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -898,7 +899,7 @@ atomic64_add_return(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_add_return_acquire)
-static inline s64
+static __always_inline s64
 atomic64_add_return_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -908,7 +909,7 @@ atomic64_add_return_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_add_return_release)
-static inline s64
+static __always_inline s64
 atomic64_add_return_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -918,7 +919,7 @@ atomic64_add_return_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_add_return_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_add_return_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -928,7 +929,7 @@ atomic64_add_return_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if !defined(arch_atomic64_fetch_add_relaxed) || defined(arch_atomic64_fetch_add)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -938,7 +939,7 @@ atomic64_fetch_add(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_add_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -948,7 +949,7 @@ atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_add_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -958,7 +959,7 @@ atomic64_fetch_add_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_add_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -967,7 +968,7 @@ atomic64_fetch_add_relaxed(s64 i, atomic64_t *v)
 #define atomic64_fetch_add_relaxed atomic64_fetch_add_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic64_sub(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -976,7 +977,7 @@ atomic64_sub(s64 i, atomic64_t *v)
 #define atomic64_sub atomic64_sub
 
 #if !defined(arch_atomic64_sub_return_relaxed) || defined(arch_atomic64_sub_return)
-static inline s64
+static __always_inline s64
 atomic64_sub_return(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -986,7 +987,7 @@ atomic64_sub_return(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_sub_return_acquire)
-static inline s64
+static __always_inline s64
 atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -996,7 +997,7 @@ atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_sub_return_release)
-static inline s64
+static __always_inline s64
 atomic64_sub_return_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1006,7 +1007,7 @@ atomic64_sub_return_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_sub_return_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_sub_return_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1016,7 +1017,7 @@ atomic64_sub_return_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if !defined(arch_atomic64_fetch_sub_relaxed) || defined(arch_atomic64_fetch_sub)
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1026,7 +1027,7 @@ atomic64_fetch_sub(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_sub_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1036,7 +1037,7 @@ atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_sub_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1046,7 +1047,7 @@ atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_sub_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1056,7 +1057,7 @@ atomic64_fetch_sub_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc)
-static inline void
+static __always_inline void
 atomic64_inc(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1066,7 +1067,7 @@ atomic64_inc(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_return)
-static inline s64
+static __always_inline s64
 atomic64_inc_return(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1076,7 +1077,7 @@ atomic64_inc_return(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_return_acquire)
-static inline s64
+static __always_inline s64
 atomic64_inc_return_acquire(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1086,7 +1087,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_return_release)
-static inline s64
+static __always_inline s64
 atomic64_inc_return_release(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1096,7 +1097,7 @@ atomic64_inc_return_release(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_return_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_inc_return_relaxed(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1106,7 +1107,7 @@ atomic64_inc_return_relaxed(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_inc)
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1116,7 +1117,7 @@ atomic64_fetch_inc(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_inc_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_acquire(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1126,7 +1127,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_inc_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_release(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1136,7 +1137,7 @@ atomic64_fetch_inc_release(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_inc_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_relaxed(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1146,7 +1147,7 @@ atomic64_fetch_inc_relaxed(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec)
-static inline void
+static __always_inline void
 atomic64_dec(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1156,7 +1157,7 @@ atomic64_dec(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_return)
-static inline s64
+static __always_inline s64
 atomic64_dec_return(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1166,7 +1167,7 @@ atomic64_dec_return(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_return_acquire)
-static inline s64
+static __always_inline s64
 atomic64_dec_return_acquire(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1176,7 +1177,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_return_release)
-static inline s64
+static __always_inline s64
 atomic64_dec_return_release(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1186,7 +1187,7 @@ atomic64_dec_return_release(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_return_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_dec_return_relaxed(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1196,7 +1197,7 @@ atomic64_dec_return_relaxed(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_dec)
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1206,7 +1207,7 @@ atomic64_fetch_dec(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_dec_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_acquire(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1216,7 +1217,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_dec_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_release(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1226,7 +1227,7 @@ atomic64_fetch_dec_release(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_dec_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_relaxed(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1235,7 +1236,7 @@ atomic64_fetch_dec_relaxed(atomic64_t *v)
 #define atomic64_fetch_dec_relaxed atomic64_fetch_dec_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic64_and(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1244,7 +1245,7 @@ atomic64_and(s64 i, atomic64_t *v)
 #define atomic64_and atomic64_and
 
 #if !defined(arch_atomic64_fetch_and_relaxed) || defined(arch_atomic64_fetch_and)
-static inline s64
+static __always_inline s64
 atomic64_fetch_and(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1254,7 +1255,7 @@ atomic64_fetch_and(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_and_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1264,7 +1265,7 @@ atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_and_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_and_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1274,7 +1275,7 @@ atomic64_fetch_and_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_and_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_and_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1284,7 +1285,7 @@ atomic64_fetch_and_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_andnot)
-static inline void
+static __always_inline void
 atomic64_andnot(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1294,7 +1295,7 @@ atomic64_andnot(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_andnot)
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1304,7 +1305,7 @@ atomic64_fetch_andnot(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_andnot_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1314,7 +1315,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_andnot_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1324,7 +1325,7 @@ atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_andnot_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1333,7 +1334,7 @@ atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
 #define atomic64_fetch_andnot_relaxed atomic64_fetch_andnot_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic64_or(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1342,7 +1343,7 @@ atomic64_or(s64 i, atomic64_t *v)
 #define atomic64_or atomic64_or
 
 #if !defined(arch_atomic64_fetch_or_relaxed) || defined(arch_atomic64_fetch_or)
-static inline s64
+static __always_inline s64
 atomic64_fetch_or(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1352,7 +1353,7 @@ atomic64_fetch_or(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_or_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1362,7 +1363,7 @@ atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_or_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_or_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1372,7 +1373,7 @@ atomic64_fetch_or_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_or_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_or_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1381,7 +1382,7 @@ atomic64_fetch_or_relaxed(s64 i, atomic64_t *v)
 #define atomic64_fetch_or_relaxed atomic64_fetch_or_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic64_xor(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1390,7 +1391,7 @@ atomic64_xor(s64 i, atomic64_t *v)
 #define atomic64_xor atomic64_xor
 
 #if !defined(arch_atomic64_fetch_xor_relaxed) || defined(arch_atomic64_fetch_xor)
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1400,7 +1401,7 @@ atomic64_fetch_xor(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_xor_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1410,7 +1411,7 @@ atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_xor_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1420,7 +1421,7 @@ atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_xor_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1430,7 +1431,7 @@ atomic64_fetch_xor_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if !defined(arch_atomic64_xchg_relaxed) || defined(arch_atomic64_xchg)
-static inline s64
+static __always_inline s64
 atomic64_xchg(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1440,7 +1441,7 @@ atomic64_xchg(atomic64_t *v, s64 i)
 #endif
 
 #if defined(arch_atomic64_xchg_acquire)
-static inline s64
+static __always_inline s64
 atomic64_xchg_acquire(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1450,7 +1451,7 @@ atomic64_xchg_acquire(atomic64_t *v, s64 i)
 #endif
 
 #if defined(arch_atomic64_xchg_release)
-static inline s64
+static __always_inline s64
 atomic64_xchg_release(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1460,7 +1461,7 @@ atomic64_xchg_release(atomic64_t *v, s64 i)
 #endif
 
 #if defined(arch_atomic64_xchg_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_xchg_relaxed(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1470,7 +1471,7 @@ atomic64_xchg_relaxed(atomic64_t *v, s64 i)
 #endif
 
 #if !defined(arch_atomic64_cmpxchg_relaxed) || defined(arch_atomic64_cmpxchg)
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1480,7 +1481,7 @@ atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #if defined(arch_atomic64_cmpxchg_acquire)
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1490,7 +1491,7 @@ atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #if defined(arch_atomic64_cmpxchg_release)
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1500,7 +1501,7 @@ atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #if defined(arch_atomic64_cmpxchg_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1510,7 +1511,7 @@ atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #if defined(arch_atomic64_try_cmpxchg)
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1521,7 +1522,7 @@ atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #if defined(arch_atomic64_try_cmpxchg_acquire)
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1532,7 +1533,7 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #if defined(arch_atomic64_try_cmpxchg_release)
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1543,7 +1544,7 @@ atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #if defined(arch_atomic64_try_cmpxchg_relaxed)
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1554,7 +1555,7 @@ atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #if defined(arch_atomic64_sub_and_test)
-static inline bool
+static __always_inline bool
 atomic64_sub_and_test(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1564,7 +1565,7 @@ atomic64_sub_and_test(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_and_test)
-static inline bool
+static __always_inline bool
 atomic64_dec_and_test(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1574,7 +1575,7 @@ atomic64_dec_and_test(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_and_test)
-static inline bool
+static __always_inline bool
 atomic64_inc_and_test(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1584,7 +1585,7 @@ atomic64_inc_and_test(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_add_negative)
-static inline bool
+static __always_inline bool
 atomic64_add_negative(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1594,7 +1595,7 @@ atomic64_add_negative(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_add_unless)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1604,7 +1605,7 @@ atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 #endif
 
 #if defined(arch_atomic64_add_unless)
-static inline bool
+static __always_inline bool
 atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1614,7 +1615,7 @@ atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 #endif
 
 #if defined(arch_atomic64_inc_not_zero)
-static inline bool
+static __always_inline bool
 atomic64_inc_not_zero(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1624,7 +1625,7 @@ atomic64_inc_not_zero(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_unless_negative)
-static inline bool
+static __always_inline bool
 atomic64_inc_unless_negative(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1634,7 +1635,7 @@ atomic64_inc_unless_negative(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_unless_positive)
-static inline bool
+static __always_inline bool
 atomic64_dec_unless_positive(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1644,7 +1645,7 @@ atomic64_dec_unless_positive(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_if_positive)
-static inline s64
+static __always_inline s64
 atomic64_dec_if_positive(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1798,4 +1799,4 @@ atomic64_dec_if_positive(atomic64_t *v)
 })
 
 #endif /* _ASM_GENERIC_ATOMIC_INSTRUMENTED_H */
-// beea41c2a0f2c69e4958ed71bf26f59740fa4b12
+// 7b7e2af0e75c8ecb6f02298a7075f503f30d244c
diff --git a/include/asm-generic/atomic-long.h b/include/asm-generic/atomic-long.h
index 881c7e27af28..073cf40f431b 100644
--- a/include/asm-generic/atomic-long.h
+++ b/include/asm-generic/atomic-long.h
@@ -6,6 +6,7 @@
 #ifndef _ASM_GENERIC_ATOMIC_LONG_H
 #define _ASM_GENERIC_ATOMIC_LONG_H
 
+#include <linux/compiler.h>
 #include <asm/types.h>
 
 #ifdef CONFIG_64BIT
@@ -22,493 +23,493 @@ typedef atomic_t atomic_long_t;
 
 #ifdef CONFIG_64BIT
 
-static inline long
+static __always_inline long
 atomic_long_read(const atomic_long_t *v)
 {
 	return atomic64_read(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_read_acquire(const atomic_long_t *v)
 {
 	return atomic64_read_acquire(v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_set(atomic_long_t *v, long i)
 {
 	atomic64_set(v, i);
 }
 
-static inline void
+static __always_inline void
 atomic_long_set_release(atomic_long_t *v, long i)
 {
 	atomic64_set_release(v, i);
 }
 
-static inline void
+static __always_inline void
 atomic_long_add(long i, atomic_long_t *v)
 {
 	atomic64_add(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_add_return(long i, atomic_long_t *v)
 {
 	return atomic64_add_return(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_add_return_acquire(long i, atomic_long_t *v)
 {
 	return atomic64_add_return_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_add_return_release(long i, atomic_long_t *v)
 {
 	return atomic64_add_return_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_add_return_relaxed(long i, atomic_long_t *v)
 {
 	return atomic64_add_return_relaxed(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_add(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add_acquire(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_add_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add_release(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_add_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add_relaxed(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_add_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_sub(long i, atomic_long_t *v)
 {
 	atomic64_sub(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_sub_return(long i, atomic_long_t *v)
 {
 	return atomic64_sub_return(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_sub_return_acquire(long i, atomic_long_t *v)
 {
 	return atomic64_sub_return_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_sub_return_release(long i, atomic_long_t *v)
 {
 	return atomic64_sub_return_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_sub_return_relaxed(long i, atomic_long_t *v)
 {
 	return atomic64_sub_return_relaxed(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_sub(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_sub(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_sub_acquire(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_sub_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_sub_release(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_sub_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_sub_relaxed(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_sub_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_inc(atomic_long_t *v)
 {
 	atomic64_inc(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_inc_return(atomic_long_t *v)
 {
 	return atomic64_inc_return(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_inc_return_acquire(atomic_long_t *v)
 {
 	return atomic64_inc_return_acquire(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_inc_return_release(atomic_long_t *v)
 {
 	return atomic64_inc_return_release(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_inc_return_relaxed(atomic_long_t *v)
 {
 	return atomic64_inc_return_relaxed(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_inc(atomic_long_t *v)
 {
 	return atomic64_fetch_inc(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_inc_acquire(atomic_long_t *v)
 {
 	return atomic64_fetch_inc_acquire(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_inc_release(atomic_long_t *v)
 {
 	return atomic64_fetch_inc_release(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_inc_relaxed(atomic_long_t *v)
 {
 	return atomic64_fetch_inc_relaxed(v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_dec(atomic_long_t *v)
 {
 	atomic64_dec(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_return(atomic_long_t *v)
 {
 	return atomic64_dec_return(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_return_acquire(atomic_long_t *v)
 {
 	return atomic64_dec_return_acquire(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_return_release(atomic_long_t *v)
 {
 	return atomic64_dec_return_release(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_return_relaxed(atomic_long_t *v)
 {
 	return atomic64_dec_return_relaxed(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_dec(atomic_long_t *v)
 {
 	return atomic64_fetch_dec(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_dec_acquire(atomic_long_t *v)
 {
 	return atomic64_fetch_dec_acquire(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_dec_release(atomic_long_t *v)
 {
 	return atomic64_fetch_dec_release(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_dec_relaxed(atomic_long_t *v)
 {
 	return atomic64_fetch_dec_relaxed(v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_and(long i, atomic_long_t *v)
 {
 	atomic64_and(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_and(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_and(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_and_acquire(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_and_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_and_release(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_and_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_and_relaxed(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_and_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_andnot(long i, atomic_long_t *v)
 {
 	atomic64_andnot(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_andnot(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_andnot(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_andnot_acquire(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_andnot_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_andnot_release(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_andnot_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_andnot_relaxed(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_andnot_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_or(long i, atomic_long_t *v)
 {
 	atomic64_or(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_or(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_or(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_or_acquire(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_or_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_or_release(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_or_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_or_relaxed(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_or_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_xor(long i, atomic_long_t *v)
 {
 	atomic64_xor(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_xor(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_xor(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_xor_acquire(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_xor_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_xor_release(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_xor_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_xor_relaxed(long i, atomic_long_t *v)
 {
 	return atomic64_fetch_xor_relaxed(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_xchg(atomic_long_t *v, long i)
 {
 	return atomic64_xchg(v, i);
 }
 
-static inline long
+static __always_inline long
 atomic_long_xchg_acquire(atomic_long_t *v, long i)
 {
 	return atomic64_xchg_acquire(v, i);
 }
 
-static inline long
+static __always_inline long
 atomic_long_xchg_release(atomic_long_t *v, long i)
 {
 	return atomic64_xchg_release(v, i);
 }
 
-static inline long
+static __always_inline long
 atomic_long_xchg_relaxed(atomic_long_t *v, long i)
 {
 	return atomic64_xchg_relaxed(v, i);
 }
 
-static inline long
+static __always_inline long
 atomic_long_cmpxchg(atomic_long_t *v, long old, long new)
 {
 	return atomic64_cmpxchg(v, old, new);
 }
 
-static inline long
+static __always_inline long
 atomic_long_cmpxchg_acquire(atomic_long_t *v, long old, long new)
 {
 	return atomic64_cmpxchg_acquire(v, old, new);
 }
 
-static inline long
+static __always_inline long
 atomic_long_cmpxchg_release(atomic_long_t *v, long old, long new)
 {
 	return atomic64_cmpxchg_release(v, old, new);
 }
 
-static inline long
+static __always_inline long
 atomic_long_cmpxchg_relaxed(atomic_long_t *v, long old, long new)
 {
 	return atomic64_cmpxchg_relaxed(v, old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_try_cmpxchg(atomic_long_t *v, long *old, long new)
 {
 	return atomic64_try_cmpxchg(v, (s64 *)old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_try_cmpxchg_acquire(atomic_long_t *v, long *old, long new)
 {
 	return atomic64_try_cmpxchg_acquire(v, (s64 *)old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_try_cmpxchg_release(atomic_long_t *v, long *old, long new)
 {
 	return atomic64_try_cmpxchg_release(v, (s64 *)old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_try_cmpxchg_relaxed(atomic_long_t *v, long *old, long new)
 {
 	return atomic64_try_cmpxchg_relaxed(v, (s64 *)old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_sub_and_test(long i, atomic_long_t *v)
 {
 	return atomic64_sub_and_test(i, v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_dec_and_test(atomic_long_t *v)
 {
 	return atomic64_dec_and_test(v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_inc_and_test(atomic_long_t *v)
 {
 	return atomic64_inc_and_test(v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_add_negative(long i, atomic_long_t *v)
 {
 	return atomic64_add_negative(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add_unless(atomic_long_t *v, long a, long u)
 {
 	return atomic64_fetch_add_unless(v, a, u);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_add_unless(atomic_long_t *v, long a, long u)
 {
 	return atomic64_add_unless(v, a, u);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_inc_not_zero(atomic_long_t *v)
 {
 	return atomic64_inc_not_zero(v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_inc_unless_negative(atomic_long_t *v)
 {
 	return atomic64_inc_unless_negative(v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_dec_unless_positive(atomic_long_t *v)
 {
 	return atomic64_dec_unless_positive(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_if_positive(atomic_long_t *v)
 {
 	return atomic64_dec_if_positive(v);
@@ -516,493 +517,493 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 
 #else /* CONFIG_64BIT */
 
-static inline long
+static __always_inline long
 atomic_long_read(const atomic_long_t *v)
 {
 	return atomic_read(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_read_acquire(const atomic_long_t *v)
 {
 	return atomic_read_acquire(v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_set(atomic_long_t *v, long i)
 {
 	atomic_set(v, i);
 }
 
-static inline void
+static __always_inline void
 atomic_long_set_release(atomic_long_t *v, long i)
 {
 	atomic_set_release(v, i);
 }
 
-static inline void
+static __always_inline void
 atomic_long_add(long i, atomic_long_t *v)
 {
 	atomic_add(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_add_return(long i, atomic_long_t *v)
 {
 	return atomic_add_return(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_add_return_acquire(long i, atomic_long_t *v)
 {
 	return atomic_add_return_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_add_return_release(long i, atomic_long_t *v)
 {
 	return atomic_add_return_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_add_return_relaxed(long i, atomic_long_t *v)
 {
 	return atomic_add_return_relaxed(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add(long i, atomic_long_t *v)
 {
 	return atomic_fetch_add(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add_acquire(long i, atomic_long_t *v)
 {
 	return atomic_fetch_add_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add_release(long i, atomic_long_t *v)
 {
 	return atomic_fetch_add_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add_relaxed(long i, atomic_long_t *v)
 {
 	return atomic_fetch_add_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_sub(long i, atomic_long_t *v)
 {
 	atomic_sub(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_sub_return(long i, atomic_long_t *v)
 {
 	return atomic_sub_return(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_sub_return_acquire(long i, atomic_long_t *v)
 {
 	return atomic_sub_return_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_sub_return_release(long i, atomic_long_t *v)
 {
 	return atomic_sub_return_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_sub_return_relaxed(long i, atomic_long_t *v)
 {
 	return atomic_sub_return_relaxed(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_sub(long i, atomic_long_t *v)
 {
 	return atomic_fetch_sub(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_sub_acquire(long i, atomic_long_t *v)
 {
 	return atomic_fetch_sub_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_sub_release(long i, atomic_long_t *v)
 {
 	return atomic_fetch_sub_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_sub_relaxed(long i, atomic_long_t *v)
 {
 	return atomic_fetch_sub_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_inc(atomic_long_t *v)
 {
 	atomic_inc(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_inc_return(atomic_long_t *v)
 {
 	return atomic_inc_return(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_inc_return_acquire(atomic_long_t *v)
 {
 	return atomic_inc_return_acquire(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_inc_return_release(atomic_long_t *v)
 {
 	return atomic_inc_return_release(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_inc_return_relaxed(atomic_long_t *v)
 {
 	return atomic_inc_return_relaxed(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_inc(atomic_long_t *v)
 {
 	return atomic_fetch_inc(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_inc_acquire(atomic_long_t *v)
 {
 	return atomic_fetch_inc_acquire(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_inc_release(atomic_long_t *v)
 {
 	return atomic_fetch_inc_release(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_inc_relaxed(atomic_long_t *v)
 {
 	return atomic_fetch_inc_relaxed(v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_dec(atomic_long_t *v)
 {
 	atomic_dec(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_return(atomic_long_t *v)
 {
 	return atomic_dec_return(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_return_acquire(atomic_long_t *v)
 {
 	return atomic_dec_return_acquire(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_return_release(atomic_long_t *v)
 {
 	return atomic_dec_return_release(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_return_relaxed(atomic_long_t *v)
 {
 	return atomic_dec_return_relaxed(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_dec(atomic_long_t *v)
 {
 	return atomic_fetch_dec(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_dec_acquire(atomic_long_t *v)
 {
 	return atomic_fetch_dec_acquire(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_dec_release(atomic_long_t *v)
 {
 	return atomic_fetch_dec_release(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_dec_relaxed(atomic_long_t *v)
 {
 	return atomic_fetch_dec_relaxed(v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_and(long i, atomic_long_t *v)
 {
 	atomic_and(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_and(long i, atomic_long_t *v)
 {
 	return atomic_fetch_and(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_and_acquire(long i, atomic_long_t *v)
 {
 	return atomic_fetch_and_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_and_release(long i, atomic_long_t *v)
 {
 	return atomic_fetch_and_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_and_relaxed(long i, atomic_long_t *v)
 {
 	return atomic_fetch_and_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_andnot(long i, atomic_long_t *v)
 {
 	atomic_andnot(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_andnot(long i, atomic_long_t *v)
 {
 	return atomic_fetch_andnot(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_andnot_acquire(long i, atomic_long_t *v)
 {
 	return atomic_fetch_andnot_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_andnot_release(long i, atomic_long_t *v)
 {
 	return atomic_fetch_andnot_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_andnot_relaxed(long i, atomic_long_t *v)
 {
 	return atomic_fetch_andnot_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_or(long i, atomic_long_t *v)
 {
 	atomic_or(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_or(long i, atomic_long_t *v)
 {
 	return atomic_fetch_or(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_or_acquire(long i, atomic_long_t *v)
 {
 	return atomic_fetch_or_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_or_release(long i, atomic_long_t *v)
 {
 	return atomic_fetch_or_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_or_relaxed(long i, atomic_long_t *v)
 {
 	return atomic_fetch_or_relaxed(i, v);
 }
 
-static inline void
+static __always_inline void
 atomic_long_xor(long i, atomic_long_t *v)
 {
 	atomic_xor(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_xor(long i, atomic_long_t *v)
 {
 	return atomic_fetch_xor(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_xor_acquire(long i, atomic_long_t *v)
 {
 	return atomic_fetch_xor_acquire(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_xor_release(long i, atomic_long_t *v)
 {
 	return atomic_fetch_xor_release(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_xor_relaxed(long i, atomic_long_t *v)
 {
 	return atomic_fetch_xor_relaxed(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_xchg(atomic_long_t *v, long i)
 {
 	return atomic_xchg(v, i);
 }
 
-static inline long
+static __always_inline long
 atomic_long_xchg_acquire(atomic_long_t *v, long i)
 {
 	return atomic_xchg_acquire(v, i);
 }
 
-static inline long
+static __always_inline long
 atomic_long_xchg_release(atomic_long_t *v, long i)
 {
 	return atomic_xchg_release(v, i);
 }
 
-static inline long
+static __always_inline long
 atomic_long_xchg_relaxed(atomic_long_t *v, long i)
 {
 	return atomic_xchg_relaxed(v, i);
 }
 
-static inline long
+static __always_inline long
 atomic_long_cmpxchg(atomic_long_t *v, long old, long new)
 {
 	return atomic_cmpxchg(v, old, new);
 }
 
-static inline long
+static __always_inline long
 atomic_long_cmpxchg_acquire(atomic_long_t *v, long old, long new)
 {
 	return atomic_cmpxchg_acquire(v, old, new);
 }
 
-static inline long
+static __always_inline long
 atomic_long_cmpxchg_release(atomic_long_t *v, long old, long new)
 {
 	return atomic_cmpxchg_release(v, old, new);
 }
 
-static inline long
+static __always_inline long
 atomic_long_cmpxchg_relaxed(atomic_long_t *v, long old, long new)
 {
 	return atomic_cmpxchg_relaxed(v, old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_try_cmpxchg(atomic_long_t *v, long *old, long new)
 {
 	return atomic_try_cmpxchg(v, (int *)old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_try_cmpxchg_acquire(atomic_long_t *v, long *old, long new)
 {
 	return atomic_try_cmpxchg_acquire(v, (int *)old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_try_cmpxchg_release(atomic_long_t *v, long *old, long new)
 {
 	return atomic_try_cmpxchg_release(v, (int *)old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_try_cmpxchg_relaxed(atomic_long_t *v, long *old, long new)
 {
 	return atomic_try_cmpxchg_relaxed(v, (int *)old, new);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_sub_and_test(long i, atomic_long_t *v)
 {
 	return atomic_sub_and_test(i, v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_dec_and_test(atomic_long_t *v)
 {
 	return atomic_dec_and_test(v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_inc_and_test(atomic_long_t *v)
 {
 	return atomic_inc_and_test(v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_add_negative(long i, atomic_long_t *v)
 {
 	return atomic_add_negative(i, v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_fetch_add_unless(atomic_long_t *v, long a, long u)
 {
 	return atomic_fetch_add_unless(v, a, u);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_add_unless(atomic_long_t *v, long a, long u)
 {
 	return atomic_add_unless(v, a, u);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_inc_not_zero(atomic_long_t *v)
 {
 	return atomic_inc_not_zero(v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_inc_unless_negative(atomic_long_t *v)
 {
 	return atomic_inc_unless_negative(v);
 }
 
-static inline bool
+static __always_inline bool
 atomic_long_dec_unless_positive(atomic_long_t *v)
 {
 	return atomic_dec_unless_positive(v);
 }
 
-static inline long
+static __always_inline long
 atomic_long_dec_if_positive(atomic_long_t *v)
 {
 	return atomic_dec_if_positive(v);
@@ -1010,4 +1011,4 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 
 #endif /* CONFIG_64BIT */
 #endif /* _ASM_GENERIC_ATOMIC_LONG_H */
-// 77558968132ce4f911ad53f6f52ce423006f6268
+// a624200981f552b2c6be4f32fe44da8289f30d87
diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
index 8b8b2a6f8d68..fb4222548b22 100755
--- a/scripts/atomic/gen-atomic-instrumented.sh
+++ b/scripts/atomic/gen-atomic-instrumented.sh
@@ -84,7 +84,7 @@ gen_proto_order_variant()
 	[ ! -z "${guard}" ] && printf "#if ${guard}\n"
 
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomicname}(${params})
 {
 ${checks}
@@ -147,16 +147,17 @@ cat << EOF
 #define _ASM_GENERIC_ATOMIC_INSTRUMENTED_H
 
 #include <linux/build_bug.h>
+#include <linux/compiler.h>
 #include <linux/kasan-checks.h>
 #include <linux/kcsan-checks.h>
 
-static inline void __atomic_check_read(const volatile void *v, size_t size)
+static __always_inline void __atomic_check_read(const volatile void *v, size_t size)
 {
 	kasan_check_read(v, size);
 	kcsan_check_atomic_read(v, size);
 }
 
-static inline void __atomic_check_write(const volatile void *v, size_t size)
+static __always_inline void __atomic_check_write(const volatile void *v, size_t size)
 {
 	kasan_check_write(v, size);
 	kcsan_check_atomic_write(v, size);
diff --git a/scripts/atomic/gen-atomic-long.sh b/scripts/atomic/gen-atomic-long.sh
index c240a7231b2e..e318d3f92e53 100755
--- a/scripts/atomic/gen-atomic-long.sh
+++ b/scripts/atomic/gen-atomic-long.sh
@@ -46,7 +46,7 @@ gen_proto_order_variant()
 	local retstmt="$(gen_ret_stmt "${meta}")"
 
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 atomic_long_${name}(${params})
 {
 	${retstmt}${atomic}_${name}(${argscast});
@@ -64,6 +64,7 @@ cat << EOF
 #ifndef _ASM_GENERIC_ATOMIC_LONG_H
 #define _ASM_GENERIC_ATOMIC_LONG_H
 
+#include <linux/compiler.h>
 #include <asm/types.h>
 
 #ifdef CONFIG_64BIT
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191126140406.164870-1-elver%40google.com.
