Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCPC6TXAKGQEQPBDQ3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B6AD8109FD5
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 15:04:58 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id p2sf13445956iof.4
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 06:04:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574777097; cv=pass;
        d=google.com; s=arc-20160816;
        b=Py9CtlsfwbwK/XccmUWcjrwTeTc27b1lltPYALyYGKI1FsYeiUrqY+uzinFah31w2v
         orKRP0MAVPLKoxdi969IQiB24C2+u2JVyuMLzS/bebvqLQHC8I6spB4ZAGYl0zH+hy+g
         RBIkU2aEeFaEZJxM9J3UA+aoLu2abMxkVoAq6Le2IObioeDRL3Zr+7Vxwj19GAIpTN0L
         GJYJ6iQKmT4nRL0QbuMQeg9W0U9XC8OruSMGgBTplsnlJ6ucRsu4OpijyzTXzHSLJ4lL
         NWeq46u6dnMZcWsitLNI0sH0H50khRXTSbbvqBYu/y48amGyfKctohFTY+JmtD2rIlpA
         qYvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Rw5Ue20sdXIX+sgHUhm/M9Gn858h80C7OYQoXslps4w=;
        b=TBU6ema/sa6tGGnln8Fhukv9aEUdfB8Jaah44caGsLCoea2AhyOFvXyePwnrCx9ID5
         9jn+ixl/EbYRQ6kQ9GaTAmFvFWIgZpo4B4pbKzEs7Qb2/ZNIt4jno2ffkgctVQY7wEds
         SMXtQxPfyI11LDOiaGNaELT6/nvGDj3iPpbc8vqWdnZ/cjR4RbM7/M9j5kXaVTI8xEiS
         MtVSMckS7zdZTKR/qEmiCmd3KM1vo8wAmabH0I+FStK/fgf9XHkOq9S/nSoGXS/wILiO
         N1iGD7BoJ5gmI8td0ekkqWGyyZr7bxzGdaLE8rlQm/5Qzh6BAUUvDjIvRgJR+iLoGiRZ
         M38Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lZeOwJz8;
       spf=pass (google.com: domain of 3bzhdxqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3BzHdXQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rw5Ue20sdXIX+sgHUhm/M9Gn858h80C7OYQoXslps4w=;
        b=LezXUo1/4li1E/MBWYQxGbrQEh4OIj1Qzr0MDUbK7NIkfRRua2EkQuKPEvY+j9bvbL
         MvPnfwNjHqMSMBnhuSumsOIHcUMk28+ut3jP7TJvIIuJbIvMd+I0C+onu8Hds18EDRFQ
         08LBttGRPGOA2ma40CrH8D8242yL/mVWeWbrAyI322bwSeHBbVmpfQ72bsomdEafWdqn
         vgo6gn36ZlFM0EBKTnWfXKHXbZAObsYQMy54W12o2gnBWpT9dilrIXt5nsFj6+ng8XPP
         u4muPgJms05D5Y9z1I+6nnB5YNkzYw9ocYAHoA0A3v0B+caZSFZaMKj2jMwe68uyxmzU
         0w+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rw5Ue20sdXIX+sgHUhm/M9Gn858h80C7OYQoXslps4w=;
        b=DBPr7QMPcpjgLGrU3X1o2n+i/Hly1nJ1sTrpa49C7XFqYehoMfiv9Rahs6+rc1MyHa
         Ji6DClC4XDgHkTREmoZyGO2fhaeDL3XEqp7WcYY3QnPtOYcuyZh+fBkNuSpW6twKCSTk
         7RHzfGpM+TqRX/mzHTrnnRCoyMmNODhMXH5Gu/kAnK3iL6Okrh1IgZi+TJCAxCjjTqoP
         qsKwZLW/PGqE70RmMQUfiJV19shsRE3mEW9S1Qa4JppeBEVUf5b7Sd8fgdXAP+NXJQSL
         g7q365DfwDony551YkJsekecrMu1pMKNx8zQUeZUQkHLDVP7mjhEhDME93j3DMo1Hpq4
         pbZw==
X-Gm-Message-State: APjAAAUjLRfPf/BEfIS9E1vhSsQq6BXCf+jk1qduknKWbeEHP0aa9b8k
	CL1yVm+j/E5Ai6bsDcJy85I=
X-Google-Smtp-Source: APXvYqxCr0oX+6RphysUzLL+oc+/HOzdFjk0G1B+Tb3epKi/Xmz6jTF5hyZg48A5Z4x6wSvVHiborw==
X-Received: by 2002:a5d:924f:: with SMTP id e15mr22870871iol.212.1574777097372;
        Tue, 26 Nov 2019 06:04:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9e18:: with SMTP id h24ls257580ioh.3.gmail; Tue, 26 Nov
 2019 06:04:56 -0800 (PST)
X-Received: by 2002:a6b:ba04:: with SMTP id k4mr32978286iof.131.1574777096821;
        Tue, 26 Nov 2019 06:04:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574777096; cv=none;
        d=google.com; s=arc-20160816;
        b=j20vQkWTrFh0jVhVCjFdWYxxVkLj4ui8zpQX7lo0RxX0ColBfkywuYbNviKGJZ2T5X
         JRvNIrmnroUBPjjitL3Hq2BsRnXA7QBSInubtFpEJk6FpgrqcKLEMMmYQDA5DOxEIbKu
         s3YcuPFAv/QQFxo9vils8HhYIFgHSIV6l49oJr7lscqnHdIFHbdadOL2DDU16W0Ba9uI
         kW4DH0JtMC7r/p09qtINQzy5KBuASd7cdSIKo1VZaBjfhdIFunUkbezM3ZvAqF0RwiAh
         4RvWGSvxBB+UL+zztofkpD2eXR65KkmH+8EOTbBIY5B9XBldjqu0rcYSZDQ9w4MJ6a56
         wYTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=C/YkA1U25Xyo3YzA8brWdqkEROmkrjPvIePbzCyR5/0=;
        b=I/HZIkDbBHQWwppu5HmmSAiyHlSRtEFDJc2ZcFf3DhHIiFjJtwOSVnbaVX1xM6O25x
         3loqAw1vSdXVFDHjBpcHNSmCM6Z0YOAF1gyzj34ncnP4vauRz1GB7r957/IV1VB0XtKL
         7jHOfQB9HXjn0emruNS4qtlxvXyBg6HsEOaDxZu25n4k99l7ZCqgFehAvaT2LQ6VTmeU
         lFsOGN9/5hXP2gSw82gA2TTpF6HA0flqR4DsRQHu7VWySUW9+HxgnYL/C/M0p7z1Fr73
         qUaI3v8wADuXGWpyS0Z4/ZBWK7f2U43nyioUK7kV5ycEdVqOaCjI2mnyFO0kn5pRiEvA
         zzUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lZeOwJz8;
       spf=pass (google.com: domain of 3bzhdxqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3BzHdXQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id v3si214964ilq.0.2019.11.26.06.04.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Nov 2019 06:04:56 -0800 (PST)
Received-SPF: pass (google.com: domain of 3bzhdxqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id t20so366856qtr.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2019 06:04:56 -0800 (PST)
X-Received: by 2002:a05:6214:6e3:: with SMTP id bk3mr18763882qvb.20.1574777095934;
 Tue, 26 Nov 2019 06:04:55 -0800 (PST)
Date: Tue, 26 Nov 2019 15:04:05 +0100
In-Reply-To: <20191126140406.164870-1-elver@google.com>
Message-Id: <20191126140406.164870-2-elver@google.com>
Mime-Version: 1.0
References: <20191126140406.164870-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v3 2/3] asm-generic/atomic: Use __always_inline for fallback wrappers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: mark.rutland@arm.com, paulmck@kernel.org, linux-kernel@vger.kernel.org, 
	will@kernel.org, peterz@infradead.org, boqun.feng@gmail.com, arnd@arndb.de, 
	dvyukov@google.com, linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lZeOwJz8;       spf=pass
 (google.com: domain of 3bzhdxqukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3BzHdXQUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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

Use __always_inline for atomic fallback wrappers. When building for size
(CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
inline even relatively small static inline functions that are assumed to
be inlinable such as atomic ops. This can cause problems, for example in
UACCESS regions.

While the fallback wrappers aren't pure wrappers, they are trivial
nonetheless, and the function they wrap should determine the final
inlining policy.

For x86 tinyconfig we observe:
- vmlinux baseline: 1315988
- vmlinux with patch: 1315928 (-60 bytes)

Suggested-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
---
v2:
* Add patch to series.
---
 include/linux/atomic-fallback.h              | 340 ++++++++++---------
 scripts/atomic/fallbacks/acquire             |   2 +-
 scripts/atomic/fallbacks/add_negative        |   2 +-
 scripts/atomic/fallbacks/add_unless          |   2 +-
 scripts/atomic/fallbacks/andnot              |   2 +-
 scripts/atomic/fallbacks/dec                 |   2 +-
 scripts/atomic/fallbacks/dec_and_test        |   2 +-
 scripts/atomic/fallbacks/dec_if_positive     |   2 +-
 scripts/atomic/fallbacks/dec_unless_positive |   2 +-
 scripts/atomic/fallbacks/fence               |   2 +-
 scripts/atomic/fallbacks/fetch_add_unless    |   2 +-
 scripts/atomic/fallbacks/inc                 |   2 +-
 scripts/atomic/fallbacks/inc_and_test        |   2 +-
 scripts/atomic/fallbacks/inc_not_zero        |   2 +-
 scripts/atomic/fallbacks/inc_unless_negative |   2 +-
 scripts/atomic/fallbacks/read_acquire        |   2 +-
 scripts/atomic/fallbacks/release             |   2 +-
 scripts/atomic/fallbacks/set_release         |   2 +-
 scripts/atomic/fallbacks/sub_and_test        |   2 +-
 scripts/atomic/fallbacks/try_cmpxchg         |   2 +-
 scripts/atomic/gen-atomic-fallback.sh        |   2 +
 21 files changed, 192 insertions(+), 188 deletions(-)

diff --git a/include/linux/atomic-fallback.h b/include/linux/atomic-fallback.h
index a7d240e465c0..656b5489b673 100644
--- a/include/linux/atomic-fallback.h
+++ b/include/linux/atomic-fallback.h
@@ -6,6 +6,8 @@
 #ifndef _LINUX_ATOMIC_FALLBACK_H
 #define _LINUX_ATOMIC_FALLBACK_H
 
+#include <linux/compiler.h>
+
 #ifndef xchg_relaxed
 #define xchg_relaxed		xchg
 #define xchg_acquire		xchg
@@ -76,7 +78,7 @@
 #endif /* cmpxchg64_relaxed */
 
 #ifndef atomic_read_acquire
-static inline int
+static __always_inline int
 atomic_read_acquire(const atomic_t *v)
 {
 	return smp_load_acquire(&(v)->counter);
@@ -85,7 +87,7 @@ atomic_read_acquire(const atomic_t *v)
 #endif
 
 #ifndef atomic_set_release
-static inline void
+static __always_inline void
 atomic_set_release(atomic_t *v, int i)
 {
 	smp_store_release(&(v)->counter, i);
@@ -100,7 +102,7 @@ atomic_set_release(atomic_t *v, int i)
 #else /* atomic_add_return_relaxed */
 
 #ifndef atomic_add_return_acquire
-static inline int
+static __always_inline int
 atomic_add_return_acquire(int i, atomic_t *v)
 {
 	int ret = atomic_add_return_relaxed(i, v);
@@ -111,7 +113,7 @@ atomic_add_return_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_add_return_release
-static inline int
+static __always_inline int
 atomic_add_return_release(int i, atomic_t *v)
 {
 	__atomic_release_fence();
@@ -121,7 +123,7 @@ atomic_add_return_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_add_return
-static inline int
+static __always_inline int
 atomic_add_return(int i, atomic_t *v)
 {
 	int ret;
@@ -142,7 +144,7 @@ atomic_add_return(int i, atomic_t *v)
 #else /* atomic_fetch_add_relaxed */
 
 #ifndef atomic_fetch_add_acquire
-static inline int
+static __always_inline int
 atomic_fetch_add_acquire(int i, atomic_t *v)
 {
 	int ret = atomic_fetch_add_relaxed(i, v);
@@ -153,7 +155,7 @@ atomic_fetch_add_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_add_release
-static inline int
+static __always_inline int
 atomic_fetch_add_release(int i, atomic_t *v)
 {
 	__atomic_release_fence();
@@ -163,7 +165,7 @@ atomic_fetch_add_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_add
-static inline int
+static __always_inline int
 atomic_fetch_add(int i, atomic_t *v)
 {
 	int ret;
@@ -184,7 +186,7 @@ atomic_fetch_add(int i, atomic_t *v)
 #else /* atomic_sub_return_relaxed */
 
 #ifndef atomic_sub_return_acquire
-static inline int
+static __always_inline int
 atomic_sub_return_acquire(int i, atomic_t *v)
 {
 	int ret = atomic_sub_return_relaxed(i, v);
@@ -195,7 +197,7 @@ atomic_sub_return_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_sub_return_release
-static inline int
+static __always_inline int
 atomic_sub_return_release(int i, atomic_t *v)
 {
 	__atomic_release_fence();
@@ -205,7 +207,7 @@ atomic_sub_return_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_sub_return
-static inline int
+static __always_inline int
 atomic_sub_return(int i, atomic_t *v)
 {
 	int ret;
@@ -226,7 +228,7 @@ atomic_sub_return(int i, atomic_t *v)
 #else /* atomic_fetch_sub_relaxed */
 
 #ifndef atomic_fetch_sub_acquire
-static inline int
+static __always_inline int
 atomic_fetch_sub_acquire(int i, atomic_t *v)
 {
 	int ret = atomic_fetch_sub_relaxed(i, v);
@@ -237,7 +239,7 @@ atomic_fetch_sub_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_sub_release
-static inline int
+static __always_inline int
 atomic_fetch_sub_release(int i, atomic_t *v)
 {
 	__atomic_release_fence();
@@ -247,7 +249,7 @@ atomic_fetch_sub_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_sub
-static inline int
+static __always_inline int
 atomic_fetch_sub(int i, atomic_t *v)
 {
 	int ret;
@@ -262,7 +264,7 @@ atomic_fetch_sub(int i, atomic_t *v)
 #endif /* atomic_fetch_sub_relaxed */
 
 #ifndef atomic_inc
-static inline void
+static __always_inline void
 atomic_inc(atomic_t *v)
 {
 	atomic_add(1, v);
@@ -278,7 +280,7 @@ atomic_inc(atomic_t *v)
 #endif /* atomic_inc_return */
 
 #ifndef atomic_inc_return
-static inline int
+static __always_inline int
 atomic_inc_return(atomic_t *v)
 {
 	return atomic_add_return(1, v);
@@ -287,7 +289,7 @@ atomic_inc_return(atomic_t *v)
 #endif
 
 #ifndef atomic_inc_return_acquire
-static inline int
+static __always_inline int
 atomic_inc_return_acquire(atomic_t *v)
 {
 	return atomic_add_return_acquire(1, v);
@@ -296,7 +298,7 @@ atomic_inc_return_acquire(atomic_t *v)
 #endif
 
 #ifndef atomic_inc_return_release
-static inline int
+static __always_inline int
 atomic_inc_return_release(atomic_t *v)
 {
 	return atomic_add_return_release(1, v);
@@ -305,7 +307,7 @@ atomic_inc_return_release(atomic_t *v)
 #endif
 
 #ifndef atomic_inc_return_relaxed
-static inline int
+static __always_inline int
 atomic_inc_return_relaxed(atomic_t *v)
 {
 	return atomic_add_return_relaxed(1, v);
@@ -316,7 +318,7 @@ atomic_inc_return_relaxed(atomic_t *v)
 #else /* atomic_inc_return_relaxed */
 
 #ifndef atomic_inc_return_acquire
-static inline int
+static __always_inline int
 atomic_inc_return_acquire(atomic_t *v)
 {
 	int ret = atomic_inc_return_relaxed(v);
@@ -327,7 +329,7 @@ atomic_inc_return_acquire(atomic_t *v)
 #endif
 
 #ifndef atomic_inc_return_release
-static inline int
+static __always_inline int
 atomic_inc_return_release(atomic_t *v)
 {
 	__atomic_release_fence();
@@ -337,7 +339,7 @@ atomic_inc_return_release(atomic_t *v)
 #endif
 
 #ifndef atomic_inc_return
-static inline int
+static __always_inline int
 atomic_inc_return(atomic_t *v)
 {
 	int ret;
@@ -359,7 +361,7 @@ atomic_inc_return(atomic_t *v)
 #endif /* atomic_fetch_inc */
 
 #ifndef atomic_fetch_inc
-static inline int
+static __always_inline int
 atomic_fetch_inc(atomic_t *v)
 {
 	return atomic_fetch_add(1, v);
@@ -368,7 +370,7 @@ atomic_fetch_inc(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_inc_acquire
-static inline int
+static __always_inline int
 atomic_fetch_inc_acquire(atomic_t *v)
 {
 	return atomic_fetch_add_acquire(1, v);
@@ -377,7 +379,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_inc_release
-static inline int
+static __always_inline int
 atomic_fetch_inc_release(atomic_t *v)
 {
 	return atomic_fetch_add_release(1, v);
@@ -386,7 +388,7 @@ atomic_fetch_inc_release(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_inc_relaxed
-static inline int
+static __always_inline int
 atomic_fetch_inc_relaxed(atomic_t *v)
 {
 	return atomic_fetch_add_relaxed(1, v);
@@ -397,7 +399,7 @@ atomic_fetch_inc_relaxed(atomic_t *v)
 #else /* atomic_fetch_inc_relaxed */
 
 #ifndef atomic_fetch_inc_acquire
-static inline int
+static __always_inline int
 atomic_fetch_inc_acquire(atomic_t *v)
 {
 	int ret = atomic_fetch_inc_relaxed(v);
@@ -408,7 +410,7 @@ atomic_fetch_inc_acquire(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_inc_release
-static inline int
+static __always_inline int
 atomic_fetch_inc_release(atomic_t *v)
 {
 	__atomic_release_fence();
@@ -418,7 +420,7 @@ atomic_fetch_inc_release(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_inc
-static inline int
+static __always_inline int
 atomic_fetch_inc(atomic_t *v)
 {
 	int ret;
@@ -433,7 +435,7 @@ atomic_fetch_inc(atomic_t *v)
 #endif /* atomic_fetch_inc_relaxed */
 
 #ifndef atomic_dec
-static inline void
+static __always_inline void
 atomic_dec(atomic_t *v)
 {
 	atomic_sub(1, v);
@@ -449,7 +451,7 @@ atomic_dec(atomic_t *v)
 #endif /* atomic_dec_return */
 
 #ifndef atomic_dec_return
-static inline int
+static __always_inline int
 atomic_dec_return(atomic_t *v)
 {
 	return atomic_sub_return(1, v);
@@ -458,7 +460,7 @@ atomic_dec_return(atomic_t *v)
 #endif
 
 #ifndef atomic_dec_return_acquire
-static inline int
+static __always_inline int
 atomic_dec_return_acquire(atomic_t *v)
 {
 	return atomic_sub_return_acquire(1, v);
@@ -467,7 +469,7 @@ atomic_dec_return_acquire(atomic_t *v)
 #endif
 
 #ifndef atomic_dec_return_release
-static inline int
+static __always_inline int
 atomic_dec_return_release(atomic_t *v)
 {
 	return atomic_sub_return_release(1, v);
@@ -476,7 +478,7 @@ atomic_dec_return_release(atomic_t *v)
 #endif
 
 #ifndef atomic_dec_return_relaxed
-static inline int
+static __always_inline int
 atomic_dec_return_relaxed(atomic_t *v)
 {
 	return atomic_sub_return_relaxed(1, v);
@@ -487,7 +489,7 @@ atomic_dec_return_relaxed(atomic_t *v)
 #else /* atomic_dec_return_relaxed */
 
 #ifndef atomic_dec_return_acquire
-static inline int
+static __always_inline int
 atomic_dec_return_acquire(atomic_t *v)
 {
 	int ret = atomic_dec_return_relaxed(v);
@@ -498,7 +500,7 @@ atomic_dec_return_acquire(atomic_t *v)
 #endif
 
 #ifndef atomic_dec_return_release
-static inline int
+static __always_inline int
 atomic_dec_return_release(atomic_t *v)
 {
 	__atomic_release_fence();
@@ -508,7 +510,7 @@ atomic_dec_return_release(atomic_t *v)
 #endif
 
 #ifndef atomic_dec_return
-static inline int
+static __always_inline int
 atomic_dec_return(atomic_t *v)
 {
 	int ret;
@@ -530,7 +532,7 @@ atomic_dec_return(atomic_t *v)
 #endif /* atomic_fetch_dec */
 
 #ifndef atomic_fetch_dec
-static inline int
+static __always_inline int
 atomic_fetch_dec(atomic_t *v)
 {
 	return atomic_fetch_sub(1, v);
@@ -539,7 +541,7 @@ atomic_fetch_dec(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_dec_acquire
-static inline int
+static __always_inline int
 atomic_fetch_dec_acquire(atomic_t *v)
 {
 	return atomic_fetch_sub_acquire(1, v);
@@ -548,7 +550,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_dec_release
-static inline int
+static __always_inline int
 atomic_fetch_dec_release(atomic_t *v)
 {
 	return atomic_fetch_sub_release(1, v);
@@ -557,7 +559,7 @@ atomic_fetch_dec_release(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_dec_relaxed
-static inline int
+static __always_inline int
 atomic_fetch_dec_relaxed(atomic_t *v)
 {
 	return atomic_fetch_sub_relaxed(1, v);
@@ -568,7 +570,7 @@ atomic_fetch_dec_relaxed(atomic_t *v)
 #else /* atomic_fetch_dec_relaxed */
 
 #ifndef atomic_fetch_dec_acquire
-static inline int
+static __always_inline int
 atomic_fetch_dec_acquire(atomic_t *v)
 {
 	int ret = atomic_fetch_dec_relaxed(v);
@@ -579,7 +581,7 @@ atomic_fetch_dec_acquire(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_dec_release
-static inline int
+static __always_inline int
 atomic_fetch_dec_release(atomic_t *v)
 {
 	__atomic_release_fence();
@@ -589,7 +591,7 @@ atomic_fetch_dec_release(atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_dec
-static inline int
+static __always_inline int
 atomic_fetch_dec(atomic_t *v)
 {
 	int ret;
@@ -610,7 +612,7 @@ atomic_fetch_dec(atomic_t *v)
 #else /* atomic_fetch_and_relaxed */
 
 #ifndef atomic_fetch_and_acquire
-static inline int
+static __always_inline int
 atomic_fetch_and_acquire(int i, atomic_t *v)
 {
 	int ret = atomic_fetch_and_relaxed(i, v);
@@ -621,7 +623,7 @@ atomic_fetch_and_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_and_release
-static inline int
+static __always_inline int
 atomic_fetch_and_release(int i, atomic_t *v)
 {
 	__atomic_release_fence();
@@ -631,7 +633,7 @@ atomic_fetch_and_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_and
-static inline int
+static __always_inline int
 atomic_fetch_and(int i, atomic_t *v)
 {
 	int ret;
@@ -646,7 +648,7 @@ atomic_fetch_and(int i, atomic_t *v)
 #endif /* atomic_fetch_and_relaxed */
 
 #ifndef atomic_andnot
-static inline void
+static __always_inline void
 atomic_andnot(int i, atomic_t *v)
 {
 	atomic_and(~i, v);
@@ -662,7 +664,7 @@ atomic_andnot(int i, atomic_t *v)
 #endif /* atomic_fetch_andnot */
 
 #ifndef atomic_fetch_andnot
-static inline int
+static __always_inline int
 atomic_fetch_andnot(int i, atomic_t *v)
 {
 	return atomic_fetch_and(~i, v);
@@ -671,7 +673,7 @@ atomic_fetch_andnot(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_andnot_acquire
-static inline int
+static __always_inline int
 atomic_fetch_andnot_acquire(int i, atomic_t *v)
 {
 	return atomic_fetch_and_acquire(~i, v);
@@ -680,7 +682,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_andnot_release
-static inline int
+static __always_inline int
 atomic_fetch_andnot_release(int i, atomic_t *v)
 {
 	return atomic_fetch_and_release(~i, v);
@@ -689,7 +691,7 @@ atomic_fetch_andnot_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_andnot_relaxed
-static inline int
+static __always_inline int
 atomic_fetch_andnot_relaxed(int i, atomic_t *v)
 {
 	return atomic_fetch_and_relaxed(~i, v);
@@ -700,7 +702,7 @@ atomic_fetch_andnot_relaxed(int i, atomic_t *v)
 #else /* atomic_fetch_andnot_relaxed */
 
 #ifndef atomic_fetch_andnot_acquire
-static inline int
+static __always_inline int
 atomic_fetch_andnot_acquire(int i, atomic_t *v)
 {
 	int ret = atomic_fetch_andnot_relaxed(i, v);
@@ -711,7 +713,7 @@ atomic_fetch_andnot_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_andnot_release
-static inline int
+static __always_inline int
 atomic_fetch_andnot_release(int i, atomic_t *v)
 {
 	__atomic_release_fence();
@@ -721,7 +723,7 @@ atomic_fetch_andnot_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_andnot
-static inline int
+static __always_inline int
 atomic_fetch_andnot(int i, atomic_t *v)
 {
 	int ret;
@@ -742,7 +744,7 @@ atomic_fetch_andnot(int i, atomic_t *v)
 #else /* atomic_fetch_or_relaxed */
 
 #ifndef atomic_fetch_or_acquire
-static inline int
+static __always_inline int
 atomic_fetch_or_acquire(int i, atomic_t *v)
 {
 	int ret = atomic_fetch_or_relaxed(i, v);
@@ -753,7 +755,7 @@ atomic_fetch_or_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_or_release
-static inline int
+static __always_inline int
 atomic_fetch_or_release(int i, atomic_t *v)
 {
 	__atomic_release_fence();
@@ -763,7 +765,7 @@ atomic_fetch_or_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_or
-static inline int
+static __always_inline int
 atomic_fetch_or(int i, atomic_t *v)
 {
 	int ret;
@@ -784,7 +786,7 @@ atomic_fetch_or(int i, atomic_t *v)
 #else /* atomic_fetch_xor_relaxed */
 
 #ifndef atomic_fetch_xor_acquire
-static inline int
+static __always_inline int
 atomic_fetch_xor_acquire(int i, atomic_t *v)
 {
 	int ret = atomic_fetch_xor_relaxed(i, v);
@@ -795,7 +797,7 @@ atomic_fetch_xor_acquire(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_xor_release
-static inline int
+static __always_inline int
 atomic_fetch_xor_release(int i, atomic_t *v)
 {
 	__atomic_release_fence();
@@ -805,7 +807,7 @@ atomic_fetch_xor_release(int i, atomic_t *v)
 #endif
 
 #ifndef atomic_fetch_xor
-static inline int
+static __always_inline int
 atomic_fetch_xor(int i, atomic_t *v)
 {
 	int ret;
@@ -826,7 +828,7 @@ atomic_fetch_xor(int i, atomic_t *v)
 #else /* atomic_xchg_relaxed */
 
 #ifndef atomic_xchg_acquire
-static inline int
+static __always_inline int
 atomic_xchg_acquire(atomic_t *v, int i)
 {
 	int ret = atomic_xchg_relaxed(v, i);
@@ -837,7 +839,7 @@ atomic_xchg_acquire(atomic_t *v, int i)
 #endif
 
 #ifndef atomic_xchg_release
-static inline int
+static __always_inline int
 atomic_xchg_release(atomic_t *v, int i)
 {
 	__atomic_release_fence();
@@ -847,7 +849,7 @@ atomic_xchg_release(atomic_t *v, int i)
 #endif
 
 #ifndef atomic_xchg
-static inline int
+static __always_inline int
 atomic_xchg(atomic_t *v, int i)
 {
 	int ret;
@@ -868,7 +870,7 @@ atomic_xchg(atomic_t *v, int i)
 #else /* atomic_cmpxchg_relaxed */
 
 #ifndef atomic_cmpxchg_acquire
-static inline int
+static __always_inline int
 atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 {
 	int ret = atomic_cmpxchg_relaxed(v, old, new);
@@ -879,7 +881,7 @@ atomic_cmpxchg_acquire(atomic_t *v, int old, int new)
 #endif
 
 #ifndef atomic_cmpxchg_release
-static inline int
+static __always_inline int
 atomic_cmpxchg_release(atomic_t *v, int old, int new)
 {
 	__atomic_release_fence();
@@ -889,7 +891,7 @@ atomic_cmpxchg_release(atomic_t *v, int old, int new)
 #endif
 
 #ifndef atomic_cmpxchg
-static inline int
+static __always_inline int
 atomic_cmpxchg(atomic_t *v, int old, int new)
 {
 	int ret;
@@ -911,7 +913,7 @@ atomic_cmpxchg(atomic_t *v, int old, int new)
 #endif /* atomic_try_cmpxchg */
 
 #ifndef atomic_try_cmpxchg
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 {
 	int r, o = *old;
@@ -924,7 +926,7 @@ atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 #endif
 
 #ifndef atomic_try_cmpxchg_acquire
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 {
 	int r, o = *old;
@@ -937,7 +939,7 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 #endif
 
 #ifndef atomic_try_cmpxchg_release
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 {
 	int r, o = *old;
@@ -950,7 +952,7 @@ atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 #endif
 
 #ifndef atomic_try_cmpxchg_relaxed
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 {
 	int r, o = *old;
@@ -965,7 +967,7 @@ atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
 #else /* atomic_try_cmpxchg_relaxed */
 
 #ifndef atomic_try_cmpxchg_acquire
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 {
 	bool ret = atomic_try_cmpxchg_relaxed(v, old, new);
@@ -976,7 +978,7 @@ atomic_try_cmpxchg_acquire(atomic_t *v, int *old, int new)
 #endif
 
 #ifndef atomic_try_cmpxchg_release
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 {
 	__atomic_release_fence();
@@ -986,7 +988,7 @@ atomic_try_cmpxchg_release(atomic_t *v, int *old, int new)
 #endif
 
 #ifndef atomic_try_cmpxchg
-static inline bool
+static __always_inline bool
 atomic_try_cmpxchg(atomic_t *v, int *old, int new)
 {
 	bool ret;
@@ -1010,7 +1012,7 @@ atomic_try_cmpxchg(atomic_t *v, int *old, int new)
  * true if the result is zero, or false for all
  * other cases.
  */
-static inline bool
+static __always_inline bool
 atomic_sub_and_test(int i, atomic_t *v)
 {
 	return atomic_sub_return(i, v) == 0;
@@ -1027,7 +1029,7 @@ atomic_sub_and_test(int i, atomic_t *v)
  * returns true if the result is 0, or false for all other
  * cases.
  */
-static inline bool
+static __always_inline bool
 atomic_dec_and_test(atomic_t *v)
 {
 	return atomic_dec_return(v) == 0;
@@ -1044,7 +1046,7 @@ atomic_dec_and_test(atomic_t *v)
  * and returns true if the result is zero, or false for all
  * other cases.
  */
-static inline bool
+static __always_inline bool
 atomic_inc_and_test(atomic_t *v)
 {
 	return atomic_inc_return(v) == 0;
@@ -1062,7 +1064,7 @@ atomic_inc_and_test(atomic_t *v)
  * if the result is negative, or false when
  * result is greater than or equal to zero.
  */
-static inline bool
+static __always_inline bool
 atomic_add_negative(int i, atomic_t *v)
 {
 	return atomic_add_return(i, v) < 0;
@@ -1080,7 +1082,7 @@ atomic_add_negative(int i, atomic_t *v)
  * Atomically adds @a to @v, so long as @v was not already @u.
  * Returns original value of @v
  */
-static inline int
+static __always_inline int
 atomic_fetch_add_unless(atomic_t *v, int a, int u)
 {
 	int c = atomic_read(v);
@@ -1105,7 +1107,7 @@ atomic_fetch_add_unless(atomic_t *v, int a, int u)
  * Atomically adds @a to @v, if @v was not already @u.
  * Returns true if the addition was done.
  */
-static inline bool
+static __always_inline bool
 atomic_add_unless(atomic_t *v, int a, int u)
 {
 	return atomic_fetch_add_unless(v, a, u) != u;
@@ -1121,7 +1123,7 @@ atomic_add_unless(atomic_t *v, int a, int u)
  * Atomically increments @v by 1, if @v is non-zero.
  * Returns true if the increment was done.
  */
-static inline bool
+static __always_inline bool
 atomic_inc_not_zero(atomic_t *v)
 {
 	return atomic_add_unless(v, 1, 0);
@@ -1130,7 +1132,7 @@ atomic_inc_not_zero(atomic_t *v)
 #endif
 
 #ifndef atomic_inc_unless_negative
-static inline bool
+static __always_inline bool
 atomic_inc_unless_negative(atomic_t *v)
 {
 	int c = atomic_read(v);
@@ -1146,7 +1148,7 @@ atomic_inc_unless_negative(atomic_t *v)
 #endif
 
 #ifndef atomic_dec_unless_positive
-static inline bool
+static __always_inline bool
 atomic_dec_unless_positive(atomic_t *v)
 {
 	int c = atomic_read(v);
@@ -1162,7 +1164,7 @@ atomic_dec_unless_positive(atomic_t *v)
 #endif
 
 #ifndef atomic_dec_if_positive
-static inline int
+static __always_inline int
 atomic_dec_if_positive(atomic_t *v)
 {
 	int dec, c = atomic_read(v);
@@ -1186,7 +1188,7 @@ atomic_dec_if_positive(atomic_t *v)
 #endif
 
 #ifndef atomic64_read_acquire
-static inline s64
+static __always_inline s64
 atomic64_read_acquire(const atomic64_t *v)
 {
 	return smp_load_acquire(&(v)->counter);
@@ -1195,7 +1197,7 @@ atomic64_read_acquire(const atomic64_t *v)
 #endif
 
 #ifndef atomic64_set_release
-static inline void
+static __always_inline void
 atomic64_set_release(atomic64_t *v, s64 i)
 {
 	smp_store_release(&(v)->counter, i);
@@ -1210,7 +1212,7 @@ atomic64_set_release(atomic64_t *v, s64 i)
 #else /* atomic64_add_return_relaxed */
 
 #ifndef atomic64_add_return_acquire
-static inline s64
+static __always_inline s64
 atomic64_add_return_acquire(s64 i, atomic64_t *v)
 {
 	s64 ret = atomic64_add_return_relaxed(i, v);
@@ -1221,7 +1223,7 @@ atomic64_add_return_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_add_return_release
-static inline s64
+static __always_inline s64
 atomic64_add_return_release(s64 i, atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1231,7 +1233,7 @@ atomic64_add_return_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_add_return
-static inline s64
+static __always_inline s64
 atomic64_add_return(s64 i, atomic64_t *v)
 {
 	s64 ret;
@@ -1252,7 +1254,7 @@ atomic64_add_return(s64 i, atomic64_t *v)
 #else /* atomic64_fetch_add_relaxed */
 
 #ifndef atomic64_fetch_add_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 {
 	s64 ret = atomic64_fetch_add_relaxed(i, v);
@@ -1263,7 +1265,7 @@ atomic64_fetch_add_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_add_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_release(s64 i, atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1273,7 +1275,7 @@ atomic64_fetch_add_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_add
-static inline s64
+static __always_inline s64
 atomic64_fetch_add(s64 i, atomic64_t *v)
 {
 	s64 ret;
@@ -1294,7 +1296,7 @@ atomic64_fetch_add(s64 i, atomic64_t *v)
 #else /* atomic64_sub_return_relaxed */
 
 #ifndef atomic64_sub_return_acquire
-static inline s64
+static __always_inline s64
 atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 {
 	s64 ret = atomic64_sub_return_relaxed(i, v);
@@ -1305,7 +1307,7 @@ atomic64_sub_return_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_sub_return_release
-static inline s64
+static __always_inline s64
 atomic64_sub_return_release(s64 i, atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1315,7 +1317,7 @@ atomic64_sub_return_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_sub_return
-static inline s64
+static __always_inline s64
 atomic64_sub_return(s64 i, atomic64_t *v)
 {
 	s64 ret;
@@ -1336,7 +1338,7 @@ atomic64_sub_return(s64 i, atomic64_t *v)
 #else /* atomic64_fetch_sub_relaxed */
 
 #ifndef atomic64_fetch_sub_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 {
 	s64 ret = atomic64_fetch_sub_relaxed(i, v);
@@ -1347,7 +1349,7 @@ atomic64_fetch_sub_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_sub_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1357,7 +1359,7 @@ atomic64_fetch_sub_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_sub
-static inline s64
+static __always_inline s64
 atomic64_fetch_sub(s64 i, atomic64_t *v)
 {
 	s64 ret;
@@ -1372,7 +1374,7 @@ atomic64_fetch_sub(s64 i, atomic64_t *v)
 #endif /* atomic64_fetch_sub_relaxed */
 
 #ifndef atomic64_inc
-static inline void
+static __always_inline void
 atomic64_inc(atomic64_t *v)
 {
 	atomic64_add(1, v);
@@ -1388,7 +1390,7 @@ atomic64_inc(atomic64_t *v)
 #endif /* atomic64_inc_return */
 
 #ifndef atomic64_inc_return
-static inline s64
+static __always_inline s64
 atomic64_inc_return(atomic64_t *v)
 {
 	return atomic64_add_return(1, v);
@@ -1397,7 +1399,7 @@ atomic64_inc_return(atomic64_t *v)
 #endif
 
 #ifndef atomic64_inc_return_acquire
-static inline s64
+static __always_inline s64
 atomic64_inc_return_acquire(atomic64_t *v)
 {
 	return atomic64_add_return_acquire(1, v);
@@ -1406,7 +1408,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
 #endif
 
 #ifndef atomic64_inc_return_release
-static inline s64
+static __always_inline s64
 atomic64_inc_return_release(atomic64_t *v)
 {
 	return atomic64_add_return_release(1, v);
@@ -1415,7 +1417,7 @@ atomic64_inc_return_release(atomic64_t *v)
 #endif
 
 #ifndef atomic64_inc_return_relaxed
-static inline s64
+static __always_inline s64
 atomic64_inc_return_relaxed(atomic64_t *v)
 {
 	return atomic64_add_return_relaxed(1, v);
@@ -1426,7 +1428,7 @@ atomic64_inc_return_relaxed(atomic64_t *v)
 #else /* atomic64_inc_return_relaxed */
 
 #ifndef atomic64_inc_return_acquire
-static inline s64
+static __always_inline s64
 atomic64_inc_return_acquire(atomic64_t *v)
 {
 	s64 ret = atomic64_inc_return_relaxed(v);
@@ -1437,7 +1439,7 @@ atomic64_inc_return_acquire(atomic64_t *v)
 #endif
 
 #ifndef atomic64_inc_return_release
-static inline s64
+static __always_inline s64
 atomic64_inc_return_release(atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1447,7 +1449,7 @@ atomic64_inc_return_release(atomic64_t *v)
 #endif
 
 #ifndef atomic64_inc_return
-static inline s64
+static __always_inline s64
 atomic64_inc_return(atomic64_t *v)
 {
 	s64 ret;
@@ -1469,7 +1471,7 @@ atomic64_inc_return(atomic64_t *v)
 #endif /* atomic64_fetch_inc */
 
 #ifndef atomic64_fetch_inc
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc(atomic64_t *v)
 {
 	return atomic64_fetch_add(1, v);
@@ -1478,7 +1480,7 @@ atomic64_fetch_inc(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_inc_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_acquire(atomic64_t *v)
 {
 	return atomic64_fetch_add_acquire(1, v);
@@ -1487,7 +1489,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_inc_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_release(atomic64_t *v)
 {
 	return atomic64_fetch_add_release(1, v);
@@ -1496,7 +1498,7 @@ atomic64_fetch_inc_release(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_inc_relaxed
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_relaxed(atomic64_t *v)
 {
 	return atomic64_fetch_add_relaxed(1, v);
@@ -1507,7 +1509,7 @@ atomic64_fetch_inc_relaxed(atomic64_t *v)
 #else /* atomic64_fetch_inc_relaxed */
 
 #ifndef atomic64_fetch_inc_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_acquire(atomic64_t *v)
 {
 	s64 ret = atomic64_fetch_inc_relaxed(v);
@@ -1518,7 +1520,7 @@ atomic64_fetch_inc_acquire(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_inc_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc_release(atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1528,7 +1530,7 @@ atomic64_fetch_inc_release(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_inc
-static inline s64
+static __always_inline s64
 atomic64_fetch_inc(atomic64_t *v)
 {
 	s64 ret;
@@ -1543,7 +1545,7 @@ atomic64_fetch_inc(atomic64_t *v)
 #endif /* atomic64_fetch_inc_relaxed */
 
 #ifndef atomic64_dec
-static inline void
+static __always_inline void
 atomic64_dec(atomic64_t *v)
 {
 	atomic64_sub(1, v);
@@ -1559,7 +1561,7 @@ atomic64_dec(atomic64_t *v)
 #endif /* atomic64_dec_return */
 
 #ifndef atomic64_dec_return
-static inline s64
+static __always_inline s64
 atomic64_dec_return(atomic64_t *v)
 {
 	return atomic64_sub_return(1, v);
@@ -1568,7 +1570,7 @@ atomic64_dec_return(atomic64_t *v)
 #endif
 
 #ifndef atomic64_dec_return_acquire
-static inline s64
+static __always_inline s64
 atomic64_dec_return_acquire(atomic64_t *v)
 {
 	return atomic64_sub_return_acquire(1, v);
@@ -1577,7 +1579,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
 #endif
 
 #ifndef atomic64_dec_return_release
-static inline s64
+static __always_inline s64
 atomic64_dec_return_release(atomic64_t *v)
 {
 	return atomic64_sub_return_release(1, v);
@@ -1586,7 +1588,7 @@ atomic64_dec_return_release(atomic64_t *v)
 #endif
 
 #ifndef atomic64_dec_return_relaxed
-static inline s64
+static __always_inline s64
 atomic64_dec_return_relaxed(atomic64_t *v)
 {
 	return atomic64_sub_return_relaxed(1, v);
@@ -1597,7 +1599,7 @@ atomic64_dec_return_relaxed(atomic64_t *v)
 #else /* atomic64_dec_return_relaxed */
 
 #ifndef atomic64_dec_return_acquire
-static inline s64
+static __always_inline s64
 atomic64_dec_return_acquire(atomic64_t *v)
 {
 	s64 ret = atomic64_dec_return_relaxed(v);
@@ -1608,7 +1610,7 @@ atomic64_dec_return_acquire(atomic64_t *v)
 #endif
 
 #ifndef atomic64_dec_return_release
-static inline s64
+static __always_inline s64
 atomic64_dec_return_release(atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1618,7 +1620,7 @@ atomic64_dec_return_release(atomic64_t *v)
 #endif
 
 #ifndef atomic64_dec_return
-static inline s64
+static __always_inline s64
 atomic64_dec_return(atomic64_t *v)
 {
 	s64 ret;
@@ -1640,7 +1642,7 @@ atomic64_dec_return(atomic64_t *v)
 #endif /* atomic64_fetch_dec */
 
 #ifndef atomic64_fetch_dec
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec(atomic64_t *v)
 {
 	return atomic64_fetch_sub(1, v);
@@ -1649,7 +1651,7 @@ atomic64_fetch_dec(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_dec_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_acquire(atomic64_t *v)
 {
 	return atomic64_fetch_sub_acquire(1, v);
@@ -1658,7 +1660,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_dec_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_release(atomic64_t *v)
 {
 	return atomic64_fetch_sub_release(1, v);
@@ -1667,7 +1669,7 @@ atomic64_fetch_dec_release(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_dec_relaxed
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_relaxed(atomic64_t *v)
 {
 	return atomic64_fetch_sub_relaxed(1, v);
@@ -1678,7 +1680,7 @@ atomic64_fetch_dec_relaxed(atomic64_t *v)
 #else /* atomic64_fetch_dec_relaxed */
 
 #ifndef atomic64_fetch_dec_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_acquire(atomic64_t *v)
 {
 	s64 ret = atomic64_fetch_dec_relaxed(v);
@@ -1689,7 +1691,7 @@ atomic64_fetch_dec_acquire(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_dec_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec_release(atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1699,7 +1701,7 @@ atomic64_fetch_dec_release(atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_dec
-static inline s64
+static __always_inline s64
 atomic64_fetch_dec(atomic64_t *v)
 {
 	s64 ret;
@@ -1720,7 +1722,7 @@ atomic64_fetch_dec(atomic64_t *v)
 #else /* atomic64_fetch_and_relaxed */
 
 #ifndef atomic64_fetch_and_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 {
 	s64 ret = atomic64_fetch_and_relaxed(i, v);
@@ -1731,7 +1733,7 @@ atomic64_fetch_and_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_and_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_and_release(s64 i, atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1741,7 +1743,7 @@ atomic64_fetch_and_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_and
-static inline s64
+static __always_inline s64
 atomic64_fetch_and(s64 i, atomic64_t *v)
 {
 	s64 ret;
@@ -1756,7 +1758,7 @@ atomic64_fetch_and(s64 i, atomic64_t *v)
 #endif /* atomic64_fetch_and_relaxed */
 
 #ifndef atomic64_andnot
-static inline void
+static __always_inline void
 atomic64_andnot(s64 i, atomic64_t *v)
 {
 	atomic64_and(~i, v);
@@ -1772,7 +1774,7 @@ atomic64_andnot(s64 i, atomic64_t *v)
 #endif /* atomic64_fetch_andnot */
 
 #ifndef atomic64_fetch_andnot
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot(s64 i, atomic64_t *v)
 {
 	return atomic64_fetch_and(~i, v);
@@ -1781,7 +1783,7 @@ atomic64_fetch_andnot(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_andnot_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 {
 	return atomic64_fetch_and_acquire(~i, v);
@@ -1790,7 +1792,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_andnot_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 {
 	return atomic64_fetch_and_release(~i, v);
@@ -1799,7 +1801,7 @@ atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_andnot_relaxed
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
 {
 	return atomic64_fetch_and_relaxed(~i, v);
@@ -1810,7 +1812,7 @@ atomic64_fetch_andnot_relaxed(s64 i, atomic64_t *v)
 #else /* atomic64_fetch_andnot_relaxed */
 
 #ifndef atomic64_fetch_andnot_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 {
 	s64 ret = atomic64_fetch_andnot_relaxed(i, v);
@@ -1821,7 +1823,7 @@ atomic64_fetch_andnot_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_andnot_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1831,7 +1833,7 @@ atomic64_fetch_andnot_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_andnot
-static inline s64
+static __always_inline s64
 atomic64_fetch_andnot(s64 i, atomic64_t *v)
 {
 	s64 ret;
@@ -1852,7 +1854,7 @@ atomic64_fetch_andnot(s64 i, atomic64_t *v)
 #else /* atomic64_fetch_or_relaxed */
 
 #ifndef atomic64_fetch_or_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 {
 	s64 ret = atomic64_fetch_or_relaxed(i, v);
@@ -1863,7 +1865,7 @@ atomic64_fetch_or_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_or_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_or_release(s64 i, atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1873,7 +1875,7 @@ atomic64_fetch_or_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_or
-static inline s64
+static __always_inline s64
 atomic64_fetch_or(s64 i, atomic64_t *v)
 {
 	s64 ret;
@@ -1894,7 +1896,7 @@ atomic64_fetch_or(s64 i, atomic64_t *v)
 #else /* atomic64_fetch_xor_relaxed */
 
 #ifndef atomic64_fetch_xor_acquire
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 {
 	s64 ret = atomic64_fetch_xor_relaxed(i, v);
@@ -1905,7 +1907,7 @@ atomic64_fetch_xor_acquire(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_xor_release
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 {
 	__atomic_release_fence();
@@ -1915,7 +1917,7 @@ atomic64_fetch_xor_release(s64 i, atomic64_t *v)
 #endif
 
 #ifndef atomic64_fetch_xor
-static inline s64
+static __always_inline s64
 atomic64_fetch_xor(s64 i, atomic64_t *v)
 {
 	s64 ret;
@@ -1936,7 +1938,7 @@ atomic64_fetch_xor(s64 i, atomic64_t *v)
 #else /* atomic64_xchg_relaxed */
 
 #ifndef atomic64_xchg_acquire
-static inline s64
+static __always_inline s64
 atomic64_xchg_acquire(atomic64_t *v, s64 i)
 {
 	s64 ret = atomic64_xchg_relaxed(v, i);
@@ -1947,7 +1949,7 @@ atomic64_xchg_acquire(atomic64_t *v, s64 i)
 #endif
 
 #ifndef atomic64_xchg_release
-static inline s64
+static __always_inline s64
 atomic64_xchg_release(atomic64_t *v, s64 i)
 {
 	__atomic_release_fence();
@@ -1957,7 +1959,7 @@ atomic64_xchg_release(atomic64_t *v, s64 i)
 #endif
 
 #ifndef atomic64_xchg
-static inline s64
+static __always_inline s64
 atomic64_xchg(atomic64_t *v, s64 i)
 {
 	s64 ret;
@@ -1978,7 +1980,7 @@ atomic64_xchg(atomic64_t *v, s64 i)
 #else /* atomic64_cmpxchg_relaxed */
 
 #ifndef atomic64_cmpxchg_acquire
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 {
 	s64 ret = atomic64_cmpxchg_relaxed(v, old, new);
@@ -1989,7 +1991,7 @@ atomic64_cmpxchg_acquire(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #ifndef atomic64_cmpxchg_release
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 {
 	__atomic_release_fence();
@@ -1999,7 +2001,7 @@ atomic64_cmpxchg_release(atomic64_t *v, s64 old, s64 new)
 #endif
 
 #ifndef atomic64_cmpxchg
-static inline s64
+static __always_inline s64
 atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 {
 	s64 ret;
@@ -2021,7 +2023,7 @@ atomic64_cmpxchg(atomic64_t *v, s64 old, s64 new)
 #endif /* atomic64_try_cmpxchg */
 
 #ifndef atomic64_try_cmpxchg
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 {
 	s64 r, o = *old;
@@ -2034,7 +2036,7 @@ atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #ifndef atomic64_try_cmpxchg_acquire
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 {
 	s64 r, o = *old;
@@ -2047,7 +2049,7 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #ifndef atomic64_try_cmpxchg_release
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 {
 	s64 r, o = *old;
@@ -2060,7 +2062,7 @@ atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #ifndef atomic64_try_cmpxchg_relaxed
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 {
 	s64 r, o = *old;
@@ -2075,7 +2077,7 @@ atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
 #else /* atomic64_try_cmpxchg_relaxed */
 
 #ifndef atomic64_try_cmpxchg_acquire
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 {
 	bool ret = atomic64_try_cmpxchg_relaxed(v, old, new);
@@ -2086,7 +2088,7 @@ atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #ifndef atomic64_try_cmpxchg_release
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 {
 	__atomic_release_fence();
@@ -2096,7 +2098,7 @@ atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
 #endif
 
 #ifndef atomic64_try_cmpxchg
-static inline bool
+static __always_inline bool
 atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
 {
 	bool ret;
@@ -2120,7 +2122,7 @@ atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
  * true if the result is zero, or false for all
  * other cases.
  */
-static inline bool
+static __always_inline bool
 atomic64_sub_and_test(s64 i, atomic64_t *v)
 {
 	return atomic64_sub_return(i, v) == 0;
@@ -2137,7 +2139,7 @@ atomic64_sub_and_test(s64 i, atomic64_t *v)
  * returns true if the result is 0, or false for all other
  * cases.
  */
-static inline bool
+static __always_inline bool
 atomic64_dec_and_test(atomic64_t *v)
 {
 	return atomic64_dec_return(v) == 0;
@@ -2154,7 +2156,7 @@ atomic64_dec_and_test(atomic64_t *v)
  * and returns true if the result is zero, or false for all
  * other cases.
  */
-static inline bool
+static __always_inline bool
 atomic64_inc_and_test(atomic64_t *v)
 {
 	return atomic64_inc_return(v) == 0;
@@ -2172,7 +2174,7 @@ atomic64_inc_and_test(atomic64_t *v)
  * if the result is negative, or false when
  * result is greater than or equal to zero.
  */
-static inline bool
+static __always_inline bool
 atomic64_add_negative(s64 i, atomic64_t *v)
 {
 	return atomic64_add_return(i, v) < 0;
@@ -2190,7 +2192,7 @@ atomic64_add_negative(s64 i, atomic64_t *v)
  * Atomically adds @a to @v, so long as @v was not already @u.
  * Returns original value of @v
  */
-static inline s64
+static __always_inline s64
 atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
 {
 	s64 c = atomic64_read(v);
@@ -2215,7 +2217,7 @@ atomic64_fetch_add_unless(atomic64_t *v, s64 a, s64 u)
  * Atomically adds @a to @v, if @v was not already @u.
  * Returns true if the addition was done.
  */
-static inline bool
+static __always_inline bool
 atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
 {
 	return atomic64_fetch_add_unless(v, a, u) != u;
@@ -2231,7 +2233,7 @@ atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
  * Atomically increments @v by 1, if @v is non-zero.
  * Returns true if the increment was done.
  */
-static inline bool
+static __always_inline bool
 atomic64_inc_not_zero(atomic64_t *v)
 {
 	return atomic64_add_unless(v, 1, 0);
@@ -2240,7 +2242,7 @@ atomic64_inc_not_zero(atomic64_t *v)
 #endif
 
 #ifndef atomic64_inc_unless_negative
-static inline bool
+static __always_inline bool
 atomic64_inc_unless_negative(atomic64_t *v)
 {
 	s64 c = atomic64_read(v);
@@ -2256,7 +2258,7 @@ atomic64_inc_unless_negative(atomic64_t *v)
 #endif
 
 #ifndef atomic64_dec_unless_positive
-static inline bool
+static __always_inline bool
 atomic64_dec_unless_positive(atomic64_t *v)
 {
 	s64 c = atomic64_read(v);
@@ -2272,7 +2274,7 @@ atomic64_dec_unless_positive(atomic64_t *v)
 #endif
 
 #ifndef atomic64_dec_if_positive
-static inline s64
+static __always_inline s64
 atomic64_dec_if_positive(atomic64_t *v)
 {
 	s64 dec, c = atomic64_read(v);
@@ -2292,4 +2294,4 @@ atomic64_dec_if_positive(atomic64_t *v)
 #define atomic64_cond_read_relaxed(v, c) smp_cond_load_relaxed(&(v)->counter, (c))
 
 #endif /* _LINUX_ATOMIC_FALLBACK_H */
-// 25de4a2804d70f57e994fe3b419148658bb5378a
+// baaf45f4c24ed88ceae58baca39d7fd80bb8101b
diff --git a/scripts/atomic/fallbacks/acquire b/scripts/atomic/fallbacks/acquire
index e38871e64db6..ea489acc285e 100755
--- a/scripts/atomic/fallbacks/acquire
+++ b/scripts/atomic/fallbacks/acquire
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomic}_${pfx}${name}${sfx}_acquire(${params})
 {
 	${ret} ret = ${atomic}_${pfx}${name}${sfx}_relaxed(${args});
diff --git a/scripts/atomic/fallbacks/add_negative b/scripts/atomic/fallbacks/add_negative
index e6f4815637de..03cc2e07fac5 100755
--- a/scripts/atomic/fallbacks/add_negative
+++ b/scripts/atomic/fallbacks/add_negative
@@ -8,7 +8,7 @@ cat <<EOF
  * if the result is negative, or false when
  * result is greater than or equal to zero.
  */
-static inline bool
+static __always_inline bool
 ${atomic}_add_negative(${int} i, ${atomic}_t *v)
 {
 	return ${atomic}_add_return(i, v) < 0;
diff --git a/scripts/atomic/fallbacks/add_unless b/scripts/atomic/fallbacks/add_unless
index 792533885fbf..daf87a04c850 100755
--- a/scripts/atomic/fallbacks/add_unless
+++ b/scripts/atomic/fallbacks/add_unless
@@ -8,7 +8,7 @@ cat << EOF
  * Atomically adds @a to @v, if @v was not already @u.
  * Returns true if the addition was done.
  */
-static inline bool
+static __always_inline bool
 ${atomic}_add_unless(${atomic}_t *v, ${int} a, ${int} u)
 {
 	return ${atomic}_fetch_add_unless(v, a, u) != u;
diff --git a/scripts/atomic/fallbacks/andnot b/scripts/atomic/fallbacks/andnot
index 9f3a3216b5e3..14efce01225a 100755
--- a/scripts/atomic/fallbacks/andnot
+++ b/scripts/atomic/fallbacks/andnot
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomic}_${pfx}andnot${sfx}${order}(${int} i, ${atomic}_t *v)
 {
 	${retstmt}${atomic}_${pfx}and${sfx}${order}(~i, v);
diff --git a/scripts/atomic/fallbacks/dec b/scripts/atomic/fallbacks/dec
index 10bbc82be31d..118282f3a5a3 100755
--- a/scripts/atomic/fallbacks/dec
+++ b/scripts/atomic/fallbacks/dec
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomic}_${pfx}dec${sfx}${order}(${atomic}_t *v)
 {
 	${retstmt}${atomic}_${pfx}sub${sfx}${order}(1, v);
diff --git a/scripts/atomic/fallbacks/dec_and_test b/scripts/atomic/fallbacks/dec_and_test
index 0ce7103b3df2..f8967a891117 100755
--- a/scripts/atomic/fallbacks/dec_and_test
+++ b/scripts/atomic/fallbacks/dec_and_test
@@ -7,7 +7,7 @@ cat <<EOF
  * returns true if the result is 0, or false for all other
  * cases.
  */
-static inline bool
+static __always_inline bool
 ${atomic}_dec_and_test(${atomic}_t *v)
 {
 	return ${atomic}_dec_return(v) == 0;
diff --git a/scripts/atomic/fallbacks/dec_if_positive b/scripts/atomic/fallbacks/dec_if_positive
index c52eacec43c8..cfb380bd2da6 100755
--- a/scripts/atomic/fallbacks/dec_if_positive
+++ b/scripts/atomic/fallbacks/dec_if_positive
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomic}_dec_if_positive(${atomic}_t *v)
 {
 	${int} dec, c = ${atomic}_read(v);
diff --git a/scripts/atomic/fallbacks/dec_unless_positive b/scripts/atomic/fallbacks/dec_unless_positive
index 8a2578f14268..69cb7aa01f9c 100755
--- a/scripts/atomic/fallbacks/dec_unless_positive
+++ b/scripts/atomic/fallbacks/dec_unless_positive
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline bool
+static __always_inline bool
 ${atomic}_dec_unless_positive(${atomic}_t *v)
 {
 	${int} c = ${atomic}_read(v);
diff --git a/scripts/atomic/fallbacks/fence b/scripts/atomic/fallbacks/fence
index 82f68fa6931a..92a3a4691bab 100755
--- a/scripts/atomic/fallbacks/fence
+++ b/scripts/atomic/fallbacks/fence
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomic}_${pfx}${name}${sfx}(${params})
 {
 	${ret} ret;
diff --git a/scripts/atomic/fallbacks/fetch_add_unless b/scripts/atomic/fallbacks/fetch_add_unless
index d2c091db7eae..fffbc0d16fdf 100755
--- a/scripts/atomic/fallbacks/fetch_add_unless
+++ b/scripts/atomic/fallbacks/fetch_add_unless
@@ -8,7 +8,7 @@ cat << EOF
  * Atomically adds @a to @v, so long as @v was not already @u.
  * Returns original value of @v
  */
-static inline ${int}
+static __always_inline ${int}
 ${atomic}_fetch_add_unless(${atomic}_t *v, ${int} a, ${int} u)
 {
 	${int} c = ${atomic}_read(v);
diff --git a/scripts/atomic/fallbacks/inc b/scripts/atomic/fallbacks/inc
index f866b3ad2353..10751cd62829 100755
--- a/scripts/atomic/fallbacks/inc
+++ b/scripts/atomic/fallbacks/inc
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomic}_${pfx}inc${sfx}${order}(${atomic}_t *v)
 {
 	${retstmt}${atomic}_${pfx}add${sfx}${order}(1, v);
diff --git a/scripts/atomic/fallbacks/inc_and_test b/scripts/atomic/fallbacks/inc_and_test
index 4e2068869f7e..4acea9c93604 100755
--- a/scripts/atomic/fallbacks/inc_and_test
+++ b/scripts/atomic/fallbacks/inc_and_test
@@ -7,7 +7,7 @@ cat <<EOF
  * and returns true if the result is zero, or false for all
  * other cases.
  */
-static inline bool
+static __always_inline bool
 ${atomic}_inc_and_test(${atomic}_t *v)
 {
 	return ${atomic}_inc_return(v) == 0;
diff --git a/scripts/atomic/fallbacks/inc_not_zero b/scripts/atomic/fallbacks/inc_not_zero
index a7c45c8d107c..d9f7b97aab42 100755
--- a/scripts/atomic/fallbacks/inc_not_zero
+++ b/scripts/atomic/fallbacks/inc_not_zero
@@ -6,7 +6,7 @@ cat <<EOF
  * Atomically increments @v by 1, if @v is non-zero.
  * Returns true if the increment was done.
  */
-static inline bool
+static __always_inline bool
 ${atomic}_inc_not_zero(${atomic}_t *v)
 {
 	return ${atomic}_add_unless(v, 1, 0);
diff --git a/scripts/atomic/fallbacks/inc_unless_negative b/scripts/atomic/fallbacks/inc_unless_negative
index 0c266e71dbd4..177a7cb51eda 100755
--- a/scripts/atomic/fallbacks/inc_unless_negative
+++ b/scripts/atomic/fallbacks/inc_unless_negative
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline bool
+static __always_inline bool
 ${atomic}_inc_unless_negative(${atomic}_t *v)
 {
 	${int} c = ${atomic}_read(v);
diff --git a/scripts/atomic/fallbacks/read_acquire b/scripts/atomic/fallbacks/read_acquire
index 75863b5203f7..12fa83cb3a6d 100755
--- a/scripts/atomic/fallbacks/read_acquire
+++ b/scripts/atomic/fallbacks/read_acquire
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomic}_read_acquire(const ${atomic}_t *v)
 {
 	return smp_load_acquire(&(v)->counter);
diff --git a/scripts/atomic/fallbacks/release b/scripts/atomic/fallbacks/release
index 3f628a3802d9..730d2a6d3e07 100755
--- a/scripts/atomic/fallbacks/release
+++ b/scripts/atomic/fallbacks/release
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline ${ret}
+static __always_inline ${ret}
 ${atomic}_${pfx}${name}${sfx}_release(${params})
 {
 	__atomic_release_fence();
diff --git a/scripts/atomic/fallbacks/set_release b/scripts/atomic/fallbacks/set_release
index 45bb5e0cfc08..e5d72c717434 100755
--- a/scripts/atomic/fallbacks/set_release
+++ b/scripts/atomic/fallbacks/set_release
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline void
+static __always_inline void
 ${atomic}_set_release(${atomic}_t *v, ${int} i)
 {
 	smp_store_release(&(v)->counter, i);
diff --git a/scripts/atomic/fallbacks/sub_and_test b/scripts/atomic/fallbacks/sub_and_test
index 289ef17a2d7a..6cfe4ed49746 100755
--- a/scripts/atomic/fallbacks/sub_and_test
+++ b/scripts/atomic/fallbacks/sub_and_test
@@ -8,7 +8,7 @@ cat <<EOF
  * true if the result is zero, or false for all
  * other cases.
  */
-static inline bool
+static __always_inline bool
 ${atomic}_sub_and_test(${int} i, ${atomic}_t *v)
 {
 	return ${atomic}_sub_return(i, v) == 0;
diff --git a/scripts/atomic/fallbacks/try_cmpxchg b/scripts/atomic/fallbacks/try_cmpxchg
index 4ed85e2f5378..c7a26213b978 100755
--- a/scripts/atomic/fallbacks/try_cmpxchg
+++ b/scripts/atomic/fallbacks/try_cmpxchg
@@ -1,5 +1,5 @@
 cat <<EOF
-static inline bool
+static __always_inline bool
 ${atomic}_try_cmpxchg${order}(${atomic}_t *v, ${int} *old, ${int} new)
 {
 	${int} r, o = *old;
diff --git a/scripts/atomic/gen-atomic-fallback.sh b/scripts/atomic/gen-atomic-fallback.sh
index 1bd7c1707633..b6c6f5d306a7 100755
--- a/scripts/atomic/gen-atomic-fallback.sh
+++ b/scripts/atomic/gen-atomic-fallback.sh
@@ -149,6 +149,8 @@ cat << EOF
 #ifndef _LINUX_ATOMIC_FALLBACK_H
 #define _LINUX_ATOMIC_FALLBACK_H
 
+#include <linux/compiler.h>
+
 EOF
 
 for xchg in "xchg" "cmpxchg" "cmpxchg64"; do
-- 
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191126140406.164870-2-elver%40google.com.
