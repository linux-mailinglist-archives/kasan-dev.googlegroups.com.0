Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIME4DXAKGQEV2QEQRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 38225107519
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 16:43:30 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id y14sf3201525wmj.9
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 07:43:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574437410; cv=pass;
        d=google.com; s=arc-20160816;
        b=yruNzhZ9IfnIzW5jkcfqRtHhE9gDdp5PkfX3pyMBwZ8Akd6s+WPdw9junw2qqJHbYP
         qxCJmdmdLKUE+7lSdiSHCM4sVEV597hN/AiKai6wr12zZbFq478dWCo6gCU+dCPvIZrX
         FWBWxNkB1wR4+bxjCuJ6ouH6708re6fWVr8auHZx1gqztR4q33txwPWIigfHt/EgWC8H
         2znjcKpniHfASobE6qTq321QvhN/u8T8DDix5AHjWz29uzZr/VYccYfJ6f6GExGXEPiM
         QBygSMEAyNa0fY/MXPTzoDuuhRhnhzivxtPOcXPjS5cq1LUy6NclMLmkntENeszQSThH
         6fNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=auNp/NX8bJQ6Yd4Dy2DAw1lUw+rk0yV+4/gwfbaaXt8=;
        b=r/3HdM2toPrhuuPgzm9oAAUNkec/ZmqigIOybyVq7/c74lA6YKWtZz90PJQcXpD6w0
         E5fgSZ7niHSF0yHiF2YiBFIG/0vVH6Y25gOM8W4lcPix2ecrhdXbT84/z7crah4ZWnAO
         MTBVtS3cJFOfcnreWybs1OLuky4dTHgIusanW6kYp8aWnN+X3J6UcriBL6rKYscaDxRW
         HMeD5sD12H2j+CVA0vYFlD3QcybNtm+XygA1aiVcLMG3jg2x/+TzzmYVs+JLLVZ3TIxX
         ug9Onnbqin7rgKfTCbI0s9kKxnRmbGvUUJoHA0kqpJzx8eUhMCmnCbPdAq6WBMDag0E3
         s1eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UY0XB28i;
       spf=pass (google.com: domain of 3ialyxqukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3IALYXQUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=auNp/NX8bJQ6Yd4Dy2DAw1lUw+rk0yV+4/gwfbaaXt8=;
        b=WC9WC2wBHzMwMekG/dblOzRIrHd4pr1O6bcocjwaGRF7c30E21ZmcOPGM+eij9iY1/
         HDYJBr5h1er5cFys6CXh7zwS8xuMnPaJPx5DQCgXLEeKIc6mQ9v+mq5cqUOZGGzARdqd
         XP2ZtFwHM9WPTOh0ijJomJ0VqgYkV8uTgrAkuNVzBYzkChuqARB2/liz3p7firrlah9q
         6c6zGwXl57TVCHRXx3YiWMYBZEmpry14IqxKCCcCarTYKCnmchu3qo4hgiZKyw9fLblu
         O2O84S6MyPkN5Luo4lVwq6Zvg3qJsfe6/QG5cN1deQ+ssJYNHKnlhX/V534cDOMyQgKI
         ceNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=auNp/NX8bJQ6Yd4Dy2DAw1lUw+rk0yV+4/gwfbaaXt8=;
        b=SGe12/uhBJFBSFsoHr3emg6d4JLy/C/BFbMPABoJMNas58YECuIjoziQhg6GmoBDuq
         d0kbx/9ZDic5bTqMW/KkECdu2ESsdVGoh4ZXt1+fCx6uvCzMxl5cvynV/04dGfnGCcOM
         qnmfZYQhgmoUFTa0BRghlq3F0Y1nh+VyGPvrIXWcT9hXRp7jrJhxW+U2KjDkcnYaZryd
         vwLBc2+/QMzBBfuTfNkT54+g0dmo4M4cyJbJyXDNE0e7ZQvPUDRj4ff2ZkAdARyyOUpa
         fEI+nTB9aAHT3O5d9hrCT8WUFpGVxP0eIIZo3eZ6y4qR5FXmaJLDJy7iMQn0z3daJMRx
         YEOA==
X-Gm-Message-State: APjAAAWMPMY7gU6dl/ieWxQvYpqw1D/piQ58ys4R+dFEmXnwtVeZ6xsh
	IPZy4cOtQsyhRpDb/R+zdq0=
X-Google-Smtp-Source: APXvYqwPum6l1n8jsK52p3uMyhzcSYO5LolqDqHSjH1zxiRg+94ETOF4zfy5/eQi/Vltcx5I9D1KdA==
X-Received: by 2002:adf:df0e:: with SMTP id y14mr16826618wrl.377.1574437409713;
        Fri, 22 Nov 2019 07:43:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4050:: with SMTP id w16ls4806330wrp.13.gmail; Fri, 22
 Nov 2019 07:43:28 -0800 (PST)
X-Received: by 2002:a5d:6548:: with SMTP id z8mr19517703wrv.273.1574437408864;
        Fri, 22 Nov 2019 07:43:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574437408; cv=none;
        d=google.com; s=arc-20160816;
        b=MfJVcZ0ylIbqqbK2MstYWa8jgQpfLgqpDhN1G/PV7dWZ6gydOQLUKm5XOmrN8ai6DC
         LW+/lEYrVTqB4fDFPhuQNctWi7fuD/IkKite8MpQ7nfAsE4dqvPE4FkkVx5BCAUqMEwr
         unutPjK3ddwG3Lw+5Ws+GM1q8OOHpiX/NFng47PzPhcwA+JOkMT7dAPC1MivwUWELZvV
         t8dLSeTEdMoOVV23sch9s2nyMsjCQYYSTPrX81PM2s5RwWswGmIummIZCPI7uaHjO/bJ
         q/MAQWlcavB0vvR3ku51ikXNeHKRIJvMyRqpOb5tDkAuw/MBdyjTcRXHJhPQIyzerC07
         73UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=1Uc/+wpPV5jYcQNJmzkAKgFrIOqIAGABs+n6v5EVGQI=;
        b=wzRNpturtglBtCHa0h7vtOJNcmyhaDTNbwPY1hhCvTxmZTwbbdltcb53mqim0nyk0B
         9EoxXfDbEJobom9pnzNxC4X9n2qsEW3hCyUdLXGfgT/o+BNeLa86fdWznqTVimojvJ0X
         1dCDRdDB0l75Ut5YcucnuYduoj72LtsfOpWd8oX8afjhbm4jyOfy/2tVMkDDASNQPEO8
         6evajLN5EqGoIiDnL0kPSFp8iXXDzgnueURHhR2ZGETdONUaqbC+kHJilm4MpnhLthi0
         mMUVeZ+zuqKfK68qiX/65Q2kdufTiKdVYoiNbW3MQl7dkJ+bijMyn2opxVwPhMuLthU6
         pnew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UY0XB28i;
       spf=pass (google.com: domain of 3ialyxqukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3IALYXQUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id d3si166973wmb.0.2019.11.22.07.43.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Nov 2019 07:43:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ialyxqukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id y14so3201499wmj.9
        for <kasan-dev@googlegroups.com>; Fri, 22 Nov 2019 07:43:28 -0800 (PST)
X-Received: by 2002:a5d:62d0:: with SMTP id o16mr1732296wrv.197.1574437408076;
 Fri, 22 Nov 2019 07:43:28 -0800 (PST)
Date: Fri, 22 Nov 2019 16:42:20 +0100
Message-Id: <20191122154221.247680-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH 1/2] asm-generic/atomic: Prefer __always_inline for wrappers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com, arnd@arndb.de, 
	dvyukov@google.com, linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, paulmck@kernel.org, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UY0XB28i;       spf=pass
 (google.com: domain of 3ialyxqukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3IALYXQUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
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

This came up when addressing UACCESS warnings with CC_OPTIMIZE_FOR_SIZE
in the KCSAN runtime:
http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org

Reported-by: Randy Dunlap <rdunlap@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/atomic-instrumented.h | 334 +++++++++++-----------
 include/asm-generic/atomic-long.h         | 330 ++++++++++-----------
 scripts/atomic/gen-atomic-instrumented.sh |   6 +-
 scripts/atomic/gen-atomic-long.sh         |   2 +-
 4 files changed, 336 insertions(+), 336 deletions(-)

diff --git a/include/asm-generic/atomic-instrumented.h b/include/asm-generic/atomic-instrumented.h
index 3dc0f38544f6..d25734ee1ce5 100644
--- a/include/asm-generic/atomic-instrumented.h
+++ b/include/asm-generic/atomic-instrumented.h
@@ -21,19 +21,19 @@
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
@@ -42,7 +42,7 @@ atomic_read(const atomic_t *v)
 #define atomic_read atomic_read
 
 #if defined(arch_atomic_read_acquire)
-static inline int
+static __always_inline int
 atomic_read_acquire(const atomic_t *v)
 {
 	__atomic_check_read(v, sizeof(*v));
@@ -51,7 +51,7 @@ atomic_read_acquire(const atomic_t *v)
 #define atomic_read_acquire atomic_read_acquire
 #endif
 
-static inline void
+static __always_inline void
 atomic_set(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -60,7 +60,7 @@ atomic_set(atomic_t *v, int i)
 #define atomic_set atomic_set
 
 #if defined(arch_atomic_set_release)
-static inline void
+static __always_inline void
 atomic_set_release(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -69,7 +69,7 @@ atomic_set_release(atomic_t *v, int i)
 #define atomic_set_release atomic_set_release
 #endif
 
-static inline void
+static __always_inline void
 atomic_add(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -78,7 +78,7 @@ atomic_add(int i, atomic_t *v)
 #define atomic_add atomic_add
 
 #if !defined(arch_atomic_add_return_relaxed) || defined(arch_atomic_add_return)
-static inline int
+static __always_inline int
 atomic_add_return(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -88,7 +88,7 @@ atomic_add_return(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_add_return_acquire)
-static inline int
+static __always_inline int
 atomic_add_return_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -98,7 +98,7 @@ atomic_add_return_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_add_return_release)
-static inline int
+static __always_inline int
 atomic_add_return_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -108,7 +108,7 @@ atomic_add_return_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_add_return_relaxed)
-static inline int
+static __always_inline int
 atomic_add_return_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -118,7 +118,7 @@ atomic_add_return_relaxed(int i, atomic_t *v)
 #endif
 
 #if !defined(arch_atomic_fetch_add_relaxed) || defined(arch_atomic_fetch_add)
-static inline int
+static __always_inline int
 atomic_fetch_add(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -128,7 +128,7 @@ atomic_fetch_add(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_add_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_add_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -138,7 +138,7 @@ atomic_fetch_add_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_add_release)
-static inline int
+static __always_inline int
 atomic_fetch_add_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -148,7 +148,7 @@ atomic_fetch_add_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_add_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_add_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -157,7 +157,7 @@ atomic_fetch_add_relaxed(int i, atomic_t *v)
 #define atomic_fetch_add_relaxed atomic_fetch_add_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic_sub(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -166,7 +166,7 @@ atomic_sub(int i, atomic_t *v)
 #define atomic_sub atomic_sub
 
 #if !defined(arch_atomic_sub_return_relaxed) || defined(arch_atomic_sub_return)
-static inline int
+static __always_inline int
 atomic_sub_return(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -176,7 +176,7 @@ atomic_sub_return(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_sub_return_acquire)
-static inline int
+static __always_inline int
 atomic_sub_return_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -186,7 +186,7 @@ atomic_sub_return_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_sub_return_release)
-static inline int
+static __always_inline int
 atomic_sub_return_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -196,7 +196,7 @@ atomic_sub_return_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_sub_return_relaxed)
-static inline int
+static __always_inline int
 atomic_sub_return_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -206,7 +206,7 @@ atomic_sub_return_relaxed(int i, atomic_t *v)
 #endif
 
 #if !defined(arch_atomic_fetch_sub_relaxed) || defined(arch_atomic_fetch_sub)
-static inline int
+static __always_inline int
 atomic_fetch_sub(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -216,7 +216,7 @@ atomic_fetch_sub(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_sub_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_sub_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -226,7 +226,7 @@ atomic_fetch_sub_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_sub_release)
-static inline int
+static __always_inline int
 atomic_fetch_sub_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -236,7 +236,7 @@ atomic_fetch_sub_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_sub_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_sub_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -246,7 +246,7 @@ atomic_fetch_sub_relaxed(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc)
-static inline void
+static __always_inline void
 atomic_inc(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -256,7 +256,7 @@ atomic_inc(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_return)
-static inline int
+static __always_inline int
 atomic_inc_return(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -266,7 +266,7 @@ atomic_inc_return(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_return_acquire)
-static inline int
+static __always_inline int
 atomic_inc_return_acquire(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -276,7 +276,7 @@ atomic_inc_return_acquire(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_return_release)
-static inline int
+static __always_inline int
 atomic_inc_return_release(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -286,7 +286,7 @@ atomic_inc_return_release(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_return_relaxed)
-static inline int
+static __always_inline int
 atomic_inc_return_relaxed(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -296,7 +296,7 @@ atomic_inc_return_relaxed(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_inc)
-static inline int
+static __always_inline int
 atomic_fetch_inc(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -306,7 +306,7 @@ atomic_fetch_inc(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_inc_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_inc_acquire(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -316,7 +316,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_inc_release)
-static inline int
+static __always_inline int
 atomic_fetch_inc_release(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -326,7 +326,7 @@ atomic_fetch_inc_release(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_inc_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_inc_relaxed(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -336,7 +336,7 @@ atomic_fetch_inc_relaxed(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec)
-static inline void
+static __always_inline void
 atomic_dec(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -346,7 +346,7 @@ atomic_dec(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_return)
-static inline int
+static __always_inline int
 atomic_dec_return(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -356,7 +356,7 @@ atomic_dec_return(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_return_acquire)
-static inline int
+static __always_inline int
 atomic_dec_return_acquire(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -366,7 +366,7 @@ atomic_dec_return_acquire(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_return_release)
-static inline int
+static __always_inline int
 atomic_dec_return_release(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -376,7 +376,7 @@ atomic_dec_return_release(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_return_relaxed)
-static inline int
+static __always_inline int
 atomic_dec_return_relaxed(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -386,7 +386,7 @@ atomic_dec_return_relaxed(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_dec)
-static inline int
+static __always_inline int
 atomic_fetch_dec(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -396,7 +396,7 @@ atomic_fetch_dec(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_dec_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_dec_acquire(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -406,7 +406,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_dec_release)
-static inline int
+static __always_inline int
 atomic_fetch_dec_release(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -416,7 +416,7 @@ atomic_fetch_dec_release(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_dec_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_dec_relaxed(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -425,7 +425,7 @@ atomic_fetch_dec_relaxed(atomic_t *v)
 #define atomic_fetch_dec_relaxed atomic_fetch_dec_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic_and(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -434,7 +434,7 @@ atomic_and(int i, atomic_t *v)
 #define atomic_and atomic_and
 
 #if !defined(arch_atomic_fetch_and_relaxed) || defined(arch_atomic_fetch_and)
-static inline int
+static __always_inline int
 atomic_fetch_and(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -444,7 +444,7 @@ atomic_fetch_and(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_and_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_and_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -454,7 +454,7 @@ atomic_fetch_and_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_and_release)
-static inline int
+static __always_inline int
 atomic_fetch_and_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -464,7 +464,7 @@ atomic_fetch_and_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_and_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_and_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -474,7 +474,7 @@ atomic_fetch_and_relaxed(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_andnot)
-static inline void
+static __always_inline void
 atomic_andnot(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -484,7 +484,7 @@ atomic_andnot(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_andnot)
-static inline int
+static __always_inline int
 atomic_fetch_andnot(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -494,7 +494,7 @@ atomic_fetch_andnot(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_andnot_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_andnot_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -504,7 +504,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_andnot_release)
-static inline int
+static __always_inline int
 atomic_fetch_andnot_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -514,7 +514,7 @@ atomic_fetch_andnot_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_andnot_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_andnot_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -523,7 +523,7 @@ atomic_fetch_andnot_relaxed(int i, atomic_t *v)
 #define atomic_fetch_andnot_relaxed atomic_fetch_andnot_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic_or(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -532,7 +532,7 @@ atomic_or(int i, atomic_t *v)
 #define atomic_or atomic_or
 
 #if !defined(arch_atomic_fetch_or_relaxed) || defined(arch_atomic_fetch_or)
-static inline int
+static __always_inline int
 atomic_fetch_or(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -542,7 +542,7 @@ atomic_fetch_or(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_or_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_or_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -552,7 +552,7 @@ atomic_fetch_or_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_or_release)
-static inline int
+static __always_inline int
 atomic_fetch_or_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -562,7 +562,7 @@ atomic_fetch_or_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_or_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_or_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -571,7 +571,7 @@ atomic_fetch_or_relaxed(int i, atomic_t *v)
 #define atomic_fetch_or_relaxed atomic_fetch_or_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic_xor(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -580,7 +580,7 @@ atomic_xor(int i, atomic_t *v)
 #define atomic_xor atomic_xor
 
 #if !defined(arch_atomic_fetch_xor_relaxed) || defined(arch_atomic_fetch_xor)
-static inline int
+static __always_inline int
 atomic_fetch_xor(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -590,7 +590,7 @@ atomic_fetch_xor(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_xor_acquire)
-static inline int
+static __always_inline int
 atomic_fetch_xor_acquire(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -600,7 +600,7 @@ atomic_fetch_xor_acquire(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_xor_release)
-static inline int
+static __always_inline int
 atomic_fetch_xor_release(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -610,7 +610,7 @@ atomic_fetch_xor_release(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_xor_relaxed)
-static inline int
+static __always_inline int
 atomic_fetch_xor_relaxed(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -620,7 +620,7 @@ atomic_fetch_xor_relaxed(int i, atomic_t *v)
 #endif
 
 #if !defined(arch_atomic_xchg_relaxed) || defined(arch_atomic_xchg)
-static inline int
+static __always_inline int
 atomic_xchg(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -630,7 +630,7 @@ atomic_xchg(atomic_t *v, int i)
 #endif
 
 #if defined(arch_atomic_xchg_acquire)
-static inline int
+static __always_inline int
 atomic_xchg_acquire(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -640,7 +640,7 @@ atomic_xchg_acquire(atomic_t *v, int i)
 #endif
 
 #if defined(arch_atomic_xchg_release)
-static inline int
+static __always_inline int
 atomic_xchg_release(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -650,7 +650,7 @@ atomic_xchg_release(atomic_t *v, int i)
 #endif
 
 #if defined(arch_atomic_xchg_relaxed)
-static inline int
+static __always_inline int
 atomic_xchg_relaxed(atomic_t *v, int i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -660,7 +660,7 @@ atomic_xchg_relaxed(atomic_t *v, int i)
 #endif
 
 #if !defined(arch_atomic_cmpxchg_relaxed) || defined(arch_atomic_cmpxchg)
-static inline int
+static __always_inline int
 atomic_cmpxchg(atomic_t *v, int old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -670,7 +670,7 @@ atomic_cmpxchg(atomic_t *v, int old, int new)
 #endif
 
 #if defined(arch_atomic_cmpxchg_acquire)
-static inline int
+static __always_inline int
 atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -680,7 +680,7 @@ atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 #endif
 
 #if defined(arch_atomic_cmpxchg_release)
-static inline int
+static __always_inline int
 atomic_cmpxchg_release(atomic_t *v, int old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -690,7 +690,7 @@ atomic_cmpxchg_release(atomic_t *v, int old, int new)
 #endif
 
 #if defined(arch_atomic_cmpxchg_relaxed)
-static inline int
+static __always_inline int
 atomic_cmpxchg_relaxed(atomic_t *v, int old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -700,7 +700,7 @@ atomic_cmpxchg_relaxed(atomic_t *v, int old, int new)
 #endif
 
 #if defined(arch_atomic_try_cmpxchg)
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -711,7 +711,7 @@ atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 #endif
 
 #if defined(arch_atomic_try_cmpxchg_acquire)
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -722,7 +722,7 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 #endif
 
 #if defined(arch_atomic_try_cmpxchg_release)
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -733,7 +733,7 @@ atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 #endif
 
 #if defined(arch_atomic_try_cmpxchg_relaxed)
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -744,7 +744,7 @@ atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 #endif
 
 #if defined(arch_atomic_sub_and_test)
-static inline bool
+static __always_inline bool
 atomic_sub_and_test(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -754,7 +754,7 @@ atomic_sub_and_test(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_and_test)
-static inline bool
+static __always_inline bool
 atomic_dec_and_test(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -764,7 +764,7 @@ atomic_dec_and_test(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_and_test)
-static inline bool
+static __always_inline bool
 atomic_inc_and_test(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -774,7 +774,7 @@ atomic_inc_and_test(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_add_negative)
-static inline bool
+static __always_inline bool
 atomic_add_negative(int i, atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -784,7 +784,7 @@ atomic_add_negative(int i, atomic_t *v)
 #endif
 
 #if defined(arch_atomic_fetch_add_unless)
-static inline int
+static __always_inline int
 atomic_fetch_add_unless(atomic_t *v, int a, int u)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -794,7 +794,7 @@ atomic_fetch_add_unless(atomic_t *v, int a, int u)
 #endif
 
 #if defined(arch_atomic_add_unless)
-static inline bool
+static __always_inline bool
 atomic_add_unless(atomic_t *v, int a, int u)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -804,7 +804,7 @@ atomic_add_unless(atomic_t *v, int a, int u)
 #endif
 
 #if defined(arch_atomic_inc_not_zero)
-static inline bool
+static __always_inline bool
 atomic_inc_not_zero(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -814,7 +814,7 @@ atomic_inc_not_zero(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_inc_unless_negative)
-static inline bool
+static __always_inline bool
 atomic_inc_unless_negative(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -824,7 +824,7 @@ atomic_inc_unless_negative(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_unless_positive)
-static inline bool
+static __always_inline bool
 atomic_dec_unless_positive(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -834,7 +834,7 @@ atomic_dec_unless_positive(atomic_t *v)
 #endif
 
 #if defined(arch_atomic_dec_if_positive)
-static inline int
+static __always_inline int
 atomic_dec_if_positive(atomic_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -843,7 +843,7 @@ atomic_dec_if_positive(atomic_t *v)
 #define atomic_dec_if_positive atomic_dec_if_positive
 #endif
 
-static inline s64
+static __always_inline s64
 atomic64_read(const atomic64_t *v)
 {
 	__atomic_check_read(v, sizeof(*v));
@@ -852,7 +852,7 @@ atomic64_read(const atomic64_t *v)
 #define atomic64_read atomic64_read
 
 #if defined(arch_atomic64_read_acquire)
-static inline s64
+static __always_inline s64
 atomic64_read_acquire(const atomic64_t *v)
 {
 	__atomic_check_read(v, sizeof(*v));
@@ -861,7 +861,7 @@ atomic64_read_acquire(const atomic64_t *v)
 #define atomic64_read_acquire atomic64_read_acquire
 #endif
 
-static inline void
+static __always_inline void
 atomic64_set(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -870,7 +870,7 @@ atomic64_set(atomic64_t *v, s64 i)
 #define atomic64_set atomic64_set
 
 #if defined(arch_atomic64_set_release)
-static inline void
+static __always_inline void
 atomic64_set_release(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -879,7 +879,7 @@ atomic64_set_release(atomic64_t *v, s64 i)
 #define atomic64_set_release atomic64_set_release
 #endif
 
-static inline void
+static __always_inline void
 atomic64_add(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -888,7 +888,7 @@ atomic64_add(s64 i, atomic64_t *v)
 #define atomic64_add atomic64_add
 
 #if !defined(arch_atomic64_add_return_relaxed) || defined(arch_atomic64_add_return)
-static inline s64
+static __always_inline s64
 atomic64_add_return(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -898,7 +898,7 @@ atomic64_add_return(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_add_return_acquire)
-static inline s64
+static __always_inline s64
 atomic64_add_return_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -908,7 +908,7 @@ atomic64_add_return_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_add_return_release)
-static inline s64
+static __always_inline s64
 atomic64_add_return_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -918,7 +918,7 @@ atomic64_add_return_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_add_return_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_add_return_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -928,7 +928,7 @@ atomic64_add_return_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if !defined(arch_atomic64_fetch_add_relaxed) || defined(arch_atomic64_fetch_add)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -938,7 +938,7 @@ atomic64_fetch_add(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_add_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -948,7 +948,7 @@ atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_add_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -958,7 +958,7 @@ atomic64_fetch_add_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_add_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -967,7 +967,7 @@ atomic64_fetch_add_relaxed(s64 i, atomic64_t *v)
 #define atomic64_fetch_add_relaxed atomic64_fetch_add_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic64_sub(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -976,7 +976,7 @@ atomic64_sub(s64 i, atomic64_t *v)
 #define atomic64_sub atomic64_sub
 
 #if !defined(arch_atomic64_sub_return_relaxed) || defined(arch_atomic64_sub_return)
-static inline s64
+static __always_inline s64
 atomic64_sub_return(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -986,7 +986,7 @@ atomic64_sub_return(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_sub_return_acquire)
-static inline s64
+static __always_inline s64
 atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -996,7 +996,7 @@ atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_sub_return_release)
-static inline s64
+static __always_inline s64
 atomic64_sub_return_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1006,7 +1006,7 @@ atomic64_sub_return_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_sub_return_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_sub_return_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1016,7 +1016,7 @@ atomic64_sub_return_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if !defined(arch_atomic64_fetch_sub_relaxed) || defined(arch_atomic64_fetch_sub)
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1026,7 +1026,7 @@ atomic64_fetch_sub(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_sub_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1036,7 +1036,7 @@ atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_sub_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1046,7 +1046,7 @@ atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_sub_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1056,7 +1056,7 @@ atomic64_fetch_sub_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc)
-static inline void
+static __always_inline void
 atomic64_inc(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1066,7 +1066,7 @@ atomic64_inc(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_return)
-static inline s64
+static __always_inline s64
 atomic64_inc_return(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1076,7 +1076,7 @@ atomic64_inc_return(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_return_acquire)
-static inline s64
+static __always_inline s64
 atomic64_inc_return_acquire(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1086,7 +1086,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_return_release)
-static inline s64
+static __always_inline s64
 atomic64_inc_return_release(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1096,7 +1096,7 @@ atomic64_inc_return_release(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_return_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_inc_return_relaxed(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1106,7 +1106,7 @@ atomic64_inc_return_relaxed(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_inc)
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1116,7 +1116,7 @@ atomic64_fetch_inc(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_inc_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_acquire(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1126,7 +1126,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_inc_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_release(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1136,7 +1136,7 @@ atomic64_fetch_inc_release(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_inc_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_relaxed(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1146,7 +1146,7 @@ atomic64_fetch_inc_relaxed(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec)
-static inline void
+static __always_inline void
 atomic64_dec(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1156,7 +1156,7 @@ atomic64_dec(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_return)
-static inline s64
+static __always_inline s64
 atomic64_dec_return(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1166,7 +1166,7 @@ atomic64_dec_return(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_return_acquire)
-static inline s64
+static __always_inline s64
 atomic64_dec_return_acquire(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1176,7 +1176,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_return_release)
-static inline s64
+static __always_inline s64
 atomic64_dec_return_release(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1186,7 +1186,7 @@ atomic64_dec_return_release(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_return_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_dec_return_relaxed(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1196,7 +1196,7 @@ atomic64_dec_return_relaxed(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_dec)
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1206,7 +1206,7 @@ atomic64_fetch_dec(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_dec_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_acquire(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1216,7 +1216,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_dec_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_release(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1226,7 +1226,7 @@ atomic64_fetch_dec_release(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_dec_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_relaxed(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1235,7 +1235,7 @@ atomic64_fetch_dec_relaxed(atomic64_t *v)
 #define atomic64_fetch_dec_relaxed atomic64_fetch_dec_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic64_and(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1244,7 +1244,7 @@ atomic64_and(s64 i, atomic64_t *v)
 #define atomic64_and atomic64_and
 
 #if !defined(arch_atomic64_fetch_and_relaxed) || defined(arch_atomic64_fetch_and)
-static inline s64
+static __always_inline s64
 atomic64_fetch_and(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1254,7 +1254,7 @@ atomic64_fetch_and(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_and_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1264,7 +1264,7 @@ atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_and_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_and_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1274,7 +1274,7 @@ atomic64_fetch_and_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_and_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_and_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1284,7 +1284,7 @@ atomic64_fetch_and_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_andnot)
-static inline void
+static __always_inline void
 atomic64_andnot(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1294,7 +1294,7 @@ atomic64_andnot(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_andnot)
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1304,7 +1304,7 @@ atomic64_fetch_andnot(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_andnot_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1314,7 +1314,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_andnot_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1324,7 +1324,7 @@ atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_andnot_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1333,7 +1333,7 @@ atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
 #define atomic64_fetch_andnot_relaxed atomic64_fetch_andnot_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic64_or(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1342,7 +1342,7 @@ atomic64_or(s64 i, atomic64_t *v)
 #define atomic64_or atomic64_or
 
 #if !defined(arch_atomic64_fetch_or_relaxed) || defined(arch_atomic64_fetch_or)
-static inline s64
+static __always_inline s64
 atomic64_fetch_or(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1352,7 +1352,7 @@ atomic64_fetch_or(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_or_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1362,7 +1362,7 @@ atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_or_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_or_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1372,7 +1372,7 @@ atomic64_fetch_or_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_or_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_or_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1381,7 +1381,7 @@ atomic64_fetch_or_relaxed(s64 i, atomic64_t *v)
 #define atomic64_fetch_or_relaxed atomic64_fetch_or_relaxed
 #endif
 
-static inline void
+static __always_inline void
 atomic64_xor(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1390,7 +1390,7 @@ atomic64_xor(s64 i, atomic64_t *v)
 #define atomic64_xor atomic64_xor
 
 #if !defined(arch_atomic64_fetch_xor_relaxed) || defined(arch_atomic64_fetch_xor)
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1400,7 +1400,7 @@ atomic64_fetch_xor(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_xor_acquire)
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1410,7 +1410,7 @@ atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_xor_release)
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1420,7 +1420,7 @@ atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_xor_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor_relaxed(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1430,7 +1430,7 @@ atomic64_fetch_xor_relaxed(s64 i, atomic64_t *v)
 #endif
 
 #if !defined(arch_atomic64_xchg_relaxed) || defined(arch_atomic64_xchg)
-static inline s64
+static __always_inline s64
 atomic64_xchg(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1440,7 +1440,7 @@ atomic64_xchg(atomic64_t *v, s64 i)
 #endif
 
 #if defined(arch_atomic64_xchg_acquire)
-static inline s64
+static __always_inline s64
 atomic64_xchg_acquire(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1450,7 +1450,7 @@ atomic64_xchg_acquire(atomic64_t *v, s64 i)
 #endif
 
 #if defined(arch_atomic64_xchg_release)
-static inline s64
+static __always_inline s64
 atomic64_xchg_release(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1460,7 +1460,7 @@ atomic64_xchg_release(atomic64_t *v, s64 i)
 #endif
 
 #if defined(arch_atomic64_xchg_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_xchg_relaxed(atomic64_t *v, s64 i)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1470,7 +1470,7 @@ atomic64_xchg_relaxed(atomic64_t *v, s64 i)
 #endif
 
 #if !defined(arch_atomic64_cmpxchg_relaxed) || defined(arch_atomic64_cmpxchg)
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1480,7 +1480,7 @@ atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #if defined(arch_atomic64_cmpxchg_acquire)
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1490,7 +1490,7 @@ atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #if defined(arch_atomic64_cmpxchg_release)
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1500,7 +1500,7 @@ atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #if defined(arch_atomic64_cmpxchg_relaxed)
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1510,7 +1510,7 @@ atomic64_cmpxchg_relaxed(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #if defined(arch_atomic64_try_cmpxchg)
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1521,7 +1521,7 @@ atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #if defined(arch_atomic64_try_cmpxchg_acquire)
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1532,7 +1532,7 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #if defined(arch_atomic64_try_cmpxchg_release)
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1543,7 +1543,7 @@ atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #if defined(arch_atomic64_try_cmpxchg_relaxed)
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1554,7 +1554,7 @@ atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #if defined(arch_atomic64_sub_and_test)
-static inline bool
+static __always_inline bool
 atomic64_sub_and_test(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1564,7 +1564,7 @@ atomic64_sub_and_test(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_and_test)
-static inline bool
+static __always_inline bool
 atomic64_dec_and_test(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1574,7 +1574,7 @@ atomic64_dec_and_test(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_and_test)
-static inline bool
+static __always_inline bool
 atomic64_inc_and_test(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1584,7 +1584,7 @@ atomic64_inc_and_test(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_add_negative)
-static inline bool
+static __always_inline bool
 atomic64_add_negative(s64 i, atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1594,7 +1594,7 @@ atomic64_add_negative(s64 i, atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_fetch_add_unless)
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1604,7 +1604,7 @@ atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 #endif
 
 #if defined(arch_atomic64_add_unless)
-static inline bool
+static __always_inline bool
 atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1614,7 +1614,7 @@ atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 #endif
 
 #if defined(arch_atomic64_inc_not_zero)
-static inline bool
+static __always_inline bool
 atomic64_inc_not_zero(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1624,7 +1624,7 @@ atomic64_inc_not_zero(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_inc_unless_negative)
-static inline bool
+static __always_inline bool
 atomic64_inc_unless_negative(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1634,7 +1634,7 @@ atomic64_inc_unless_negative(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_unless_positive)
-static inline bool
+static __always_inline bool
 atomic64_dec_unless_positive(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1644,7 +1644,7 @@ atomic64_dec_unless_positive(atomic64_t *v)
 #endif
 
 #if defined(arch_atomic64_dec_if_positive)
-static inline s64
+static __always_inline s64
 atomic64_dec_if_positive(atomic64_t *v)
 {
 	__atomic_check_write(v, sizeof(*v));
@@ -1798,4 +1798,4 @@ atomic64_dec_if_positive(atomic64_t *v)
 })
 
 #endif /* _ASM_GENERIC_ATOMIC_INSTRUMENTED_H */
-// beea41c2a0f2c69e4958ed71bf26f59740fa4b12
+// 2b3a93e48048270083bbc1e192474b8dba566781
diff --git a/include/asm-generic/atomic-long.h b/include/asm-generic/atomic-long.h
index 881c7e27af28..ff1ac91f6365 100644
--- a/include/asm-generic/atomic-long.h
+++ b/include/asm-generic/atomic-long.h
@@ -22,493 +22,493 @@ typedef atomic_t atomic_long_t;
 
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
@@ -516,493 +516,493 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 
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
@@ -1010,4 +1010,4 @@ atomic_long_dec_if_positive(atomic_long_t *v)
 
 #endif /* CONFIG_64BIT */
 #endif /* _ASM_GENERIC_ATOMIC_LONG_H */
-// 77558968132ce4f911ad53f6f52ce423006f6268
+// da08a357061b164141a6f9bf38a2aa949421919c
diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
index 8b8b2a6f8d68..68532d4f36ca 100755
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
@@ -150,13 +150,13 @@ cat << EOF
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
index c240a7231b2e..4036d2dd22e9 100755
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
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191122154221.247680-1-elver%40google.com.
