Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYU5TCGQMGQEEIOEIXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id A46C24632EA
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:38 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id c1-20020aa7c741000000b003e7bf1da4bcsf16610806eds.21
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272738; cv=pass;
        d=google.com; s=arc-20160816;
        b=qFiTcs+XLyJf7prwUnrsBAGBep6XzIrplhGVJ5YstENoqWL82cHG3NNSNeh11T4n64
         Y3ts1CLpb7ITQMY4qU/ClprkTnenPt7vIVmDcQH4cYzq6Vy004Vby5e9rKTBpe2f8w/j
         wJ9ZCoRoKWBtPjgFTpPQE/cPUyW3Q3XbxuM0zVtkhgOhgr2pAhe3bcsh/04Zz1EV+3pz
         OAY7hJD1I4ZJWwi9uzGd6spqBa7hu7i4ioyK6T2ij+nWrB1+VWDtuL5xEoaaJQEy8blJ
         /CHwp2K737XmuSnKyloFjPlbGlJ3QE6FjrmelHvRY2EDc4Fz1K69d0uscJ8F1/yY6W6D
         bR7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=7gw1TRL9b9MPvZ8mahCKpgbsF55bto8frPWQ6GlI0hQ=;
        b=Tellz/9c0vdY92PRQbflCbzSvvoKH9gsJmBNYui7OqwLq5xgEDm8wHib2aWppKgn9Y
         vvXIMjQwLvb0IATGeWPryNOF7s7JablzaMeYihXxsQfUtM3wvilu+u948vabnFmYZq0k
         tZTViyepNZrLPCzOsE5cOFonSkB8qcfwBNFsboB0ijbH0neoFrBKD1i1lBkUBt7/0efg
         fR7kFiIPmoaB8lRDQZvMSf6pfC3uYJaCG02KBdSY4+cDo2ouoxye1iibRbANRm/8f60v
         SO1UvIp19k9rMOz7RxRP+12HPzbVRnUJB0/TScSqp/3+vnNV2ZmrK5D39aGDzwil0w/7
         +rxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sAns+f6z;
       spf=pass (google.com: domain of 34q6myqukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Q6mYQUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7gw1TRL9b9MPvZ8mahCKpgbsF55bto8frPWQ6GlI0hQ=;
        b=XPfS/AQAWgqphyPQwOIYpEKhuXtmx97GbprQBiRLRcdm7Bpvko5dZO3Wb2xiNW1uah
         tcsWXA2XYCQaMyqm4boPlqKavzPE21cUmcyyQuncKkmEjWB0EIA2lspFfy0LNyh3qd5R
         DSvOswmwoq3p6yf3xGiZiczj7Tx2n5Z7XC1PT+Tmt8YcPpQXZ2udtfEhAh+JBZhWnuK3
         ArQxYZlhprk6xYdNoZZBDKGgKbbPVZkT4xmO2Q/Ccy4l6iXqytsR3liTyLyjcR7K6jgu
         NC2VtboQjA90stdlBPKr9ofT8X28Dl2Y4oxInCwd4aTj1Li2975+QfjIMrdGiv8yKm4r
         YLbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7gw1TRL9b9MPvZ8mahCKpgbsF55bto8frPWQ6GlI0hQ=;
        b=qwSzXh6eB3aY42UXTsvNRH6SJG3FKUk8fySnf0u+S50GiQDS6CaZPRwjf7ZeGQycQ2
         HSVbYGbpdBjuxElWRIiPSkFfeVbtolWD066F1qD+i3gdL51UU7xuzHteRkyUTh8Cmm8b
         87rBJ0le9mfVAjtM0ap97KCBT24chsn7YelWtKJL4/4W9h3bRJniBr7P/fX7Ks8nkW8y
         YD2f800oXZHPNKoMWrBgNw3PXmgXS5iuXKwLr1l2YVOtuxPV0z9MTmJ2ZEaVmdQtutcH
         cuHVYOc9l5evYxPQUAVoqRU38/Tsoxq+/ePyzRg+dSSpK8WJtUghEmjzFV40/KOIei/C
         yDcQ==
X-Gm-Message-State: AOAM533wmUL8FUtMQuA3Bf5wWyxNbYlQDLLPbFmfEgvMh2rdl/FHCDgH
	z8RIsGJ+iSURzY+7+YIj8Ko=
X-Google-Smtp-Source: ABdhPJwxhhmTzC3EAoDileRHJ4PN/4/OEADPTMfZUfQdxSu0wx4XFWh5IgpSLu8D4KIa/8xPMzGJJA==
X-Received: by 2002:a05:6402:84b:: with SMTP id b11mr81817675edz.69.1638272738453;
        Tue, 30 Nov 2021 03:45:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6da0:: with SMTP id sb32ls2926668ejc.8.gmail; Tue,
 30 Nov 2021 03:45:37 -0800 (PST)
X-Received: by 2002:a17:907:9487:: with SMTP id dm7mr69602123ejc.95.1638272737485;
        Tue, 30 Nov 2021 03:45:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272737; cv=none;
        d=google.com; s=arc-20160816;
        b=z2dERHqYO8EJyhrL3mge8qChtkX2NUTtY+5RoK/jX5Ku9x4CjxONWaEbPGkZjCd725
         vb2ORUk+DmDoY8gfzkG/HNJvJvlMVjsRhkWRShw5oH4F7tKTHTyxGTkZnUFA9s54Z2oj
         CSxqDlabQD2Sodloa/3O4teWqSeVoKO8JVkdKjOTlHJ/+H95jlVB07Z91ox5lDOUoSTc
         Aa85Uu5Z8G5i4rn1tmTQnPsAQJJPiBq8uE7Vz3TyMKkeSu1EjoCnfyQDoco80C+eGU8Z
         fFba0lymctE9s2eGEsVrGkzrWyuV0X9Ol1t0RGDCT9+Jmz8G8O1KQkxJWvtXubxoVepJ
         05Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=HO2j8fDcTjG33FWF1g1vyRfUzwW+oeuePm13p24Xfnw=;
        b=JTI5VvDX6L+emm+VzUylo/VJ1gVTv9jvJ9hTxHjfX1dHaNlQ9NSEG3hQ7Mr/5uYyp8
         a1W+Oc5VQx70r7mGV3JvK9uVLMUq/ViMdybsj/nAKErYem67SbKBGL7XR03H+vI1jn59
         MeNW1cbAcolpO1BRjMPVQvPLqfxiTvO8hP2rNN7MDH187QcioBi8oy7zODYrjNJRO2pV
         spPnRbSO/FApYq+F+GPg8Pom10qetomwm7TCd5wLausAGzP90JJIzkD8W8SBlwWrAGW5
         bogxU0JEJGgvQ3MYKiHCGJq4xT2PyQ3I97b6ERogiFLHC7BrtGRR6e3pJniAkn7e2sHC
         AZhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sAns+f6z;
       spf=pass (google.com: domain of 34q6myqukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Q6mYQUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id e10si1441095edz.5.2021.11.30.03.45.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 34q6myqukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id p12-20020a05600c1d8c00b0033a22e48203so12698951wms.6
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:37 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:4308:: with SMTP id
 p8mr4243163wme.132.1638272737238; Tue, 30 Nov 2021 03:45:37 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:22 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-15-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 14/25] locking/barriers, kcsan: Add instrumentation for barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sAns+f6z;       spf=pass
 (google.com: domain of 34q6myqukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=34Q6mYQUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Adds the required KCSAN instrumentation for barriers if CONFIG_SMP.
KCSAN supports modeling the effects of:

	smp_mb()
	smp_rmb()
	smp_wmb()
	smp_store_release()

Signed-off-by: Marco Elver <elver@google.com>
---
 include/asm-generic/barrier.h | 29 +++++++++++++++--------------
 include/linux/spinlock.h      |  2 +-
 2 files changed, 16 insertions(+), 15 deletions(-)

diff --git a/include/asm-generic/barrier.h b/include/asm-generic/barrier.h
index 640f09479bdf..27a9c9edfef6 100644
--- a/include/asm-generic/barrier.h
+++ b/include/asm-generic/barrier.h
@@ -14,6 +14,7 @@
 #ifndef __ASSEMBLY__
 
 #include <linux/compiler.h>
+#include <linux/kcsan-checks.h>
 #include <asm/rwonce.h>
 
 #ifndef nop
@@ -62,15 +63,15 @@
 #ifdef CONFIG_SMP
 
 #ifndef smp_mb
-#define smp_mb()	__smp_mb()
+#define smp_mb()	do { kcsan_mb(); __smp_mb(); } while (0)
 #endif
 
 #ifndef smp_rmb
-#define smp_rmb()	__smp_rmb()
+#define smp_rmb()	do { kcsan_rmb(); __smp_rmb(); } while (0)
 #endif
 
 #ifndef smp_wmb
-#define smp_wmb()	__smp_wmb()
+#define smp_wmb()	do { kcsan_wmb(); __smp_wmb(); } while (0)
 #endif
 
 #else	/* !CONFIG_SMP */
@@ -123,19 +124,19 @@ do {									\
 #ifdef CONFIG_SMP
 
 #ifndef smp_store_mb
-#define smp_store_mb(var, value)  __smp_store_mb(var, value)
+#define smp_store_mb(var, value)  do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
 #endif
 
 #ifndef smp_mb__before_atomic
-#define smp_mb__before_atomic()	__smp_mb__before_atomic()
+#define smp_mb__before_atomic()	do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
 #endif
 
 #ifndef smp_mb__after_atomic
-#define smp_mb__after_atomic()	__smp_mb__after_atomic()
+#define smp_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
 #endif
 
 #ifndef smp_store_release
-#define smp_store_release(p, v) __smp_store_release(p, v)
+#define smp_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
 #endif
 
 #ifndef smp_load_acquire
@@ -178,13 +179,13 @@ do {									\
 #endif	/* CONFIG_SMP */
 
 /* Barriers for virtual machine guests when talking to an SMP host */
-#define virt_mb() __smp_mb()
-#define virt_rmb() __smp_rmb()
-#define virt_wmb() __smp_wmb()
-#define virt_store_mb(var, value) __smp_store_mb(var, value)
-#define virt_mb__before_atomic() __smp_mb__before_atomic()
-#define virt_mb__after_atomic()	__smp_mb__after_atomic()
-#define virt_store_release(p, v) __smp_store_release(p, v)
+#define virt_mb() do { kcsan_mb(); __smp_mb(); } while (0)
+#define virt_rmb() do { kcsan_rmb(); __smp_rmb(); } while (0)
+#define virt_wmb() do { kcsan_wmb(); __smp_wmb(); } while (0)
+#define virt_store_mb(var, value) do { kcsan_mb(); __smp_store_mb(var, value); } while (0)
+#define virt_mb__before_atomic() do { kcsan_mb(); __smp_mb__before_atomic(); } while (0)
+#define virt_mb__after_atomic()	do { kcsan_mb(); __smp_mb__after_atomic(); } while (0)
+#define virt_store_release(p, v) do { kcsan_release(); __smp_store_release(p, v); } while (0)
 #define virt_load_acquire(p) __smp_load_acquire(p)
 
 /**
diff --git a/include/linux/spinlock.h b/include/linux/spinlock.h
index b4e5ca23f840..5c0c5174155d 100644
--- a/include/linux/spinlock.h
+++ b/include/linux/spinlock.h
@@ -171,7 +171,7 @@ do {									\
  * Architectures that can implement ACQUIRE better need to take care.
  */
 #ifndef smp_mb__after_spinlock
-#define smp_mb__after_spinlock()	do { } while (0)
+#define smp_mb__after_spinlock()	kcsan_mb()
 #endif
 
 #ifdef CONFIG_DEBUG_SPINLOCK
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-15-elver%40google.com.
