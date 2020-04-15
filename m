Return-Path: <kasan-dev+bncBAABBKNH3X2AKGQE5OU4ZVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 067B91AB0D2
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:19 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id e8sf361147vsp.16
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975658; cv=pass;
        d=google.com; s=arc-20160816;
        b=WRjvDX7ZeG1w9KA5N8aTUr1d8FxKjbVc2dhZqs+9kjNwupFpjETtn9gFHefZy2oikY
         NJu4w3ePN4TJ8Px0B+IuoRMZy7VX4Lka8j/YhVKg6hJ78V97jLu+HU/CJQMGwRWB6C2H
         L9nTghMQm0DS6gRKE34mH3An0T0/49ICEydS4eghOoxK8o9LVIu8okNzssy5voQikqXn
         Q0Q89vtOB3LMb0oI8wvJpLPMacHtEKJw9ePq8HquJWY1m/OE6gJPKTBbJliE+KyHaVNB
         cV5udv/dxq5/RWty+8wgznaWennuuWpDE6rP5fgHXghm7btQOCYQ7XXLIiX8oRiiUVXK
         0N6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=QAhdC6Rx57C1O6Ugz0jFkvg9H8x+XkIQw8XEDLp6DXI=;
        b=HsvWXMXIq9d+N/4yTqS/N0C5dD9KmN/YcWbWJsNv6GmicFX/3R1zi6LxZzR83a+CTg
         93fX3uw12h+LjDFfLsSNFPV7FZBVI4tcN/YQUvHn8l0EQ5ZBZbQIw/fvXliCKsopTrJm
         N/jfSmEcRVKVQpBJOiztfDoTpUj5tyjzTnT/Ow4ZKrh6TTxb9rJ/t1EuRT5+NiKE0ROE
         c9aB99REL2HMzj3r7qE45W/NeSTQDPfQgzW44lIVCzjrZ5rH+AC81Xl5PncgVeUudqmb
         xWrdjQtROqcVaQymEwh2KY2vdUFFBuP+Wn/3AjGC0jnAbzJUYmZ7R6wQYVKh9g06yfbK
         aiKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=K5vsb4pq;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QAhdC6Rx57C1O6Ugz0jFkvg9H8x+XkIQw8XEDLp6DXI=;
        b=Yd3+x5sMFeitpbIaDFd5Ra6ivshjTLF3XQAohMSPLGq76UdomcaNiMh3sNm4va14lh
         F1UtooWekdcRnOiQrmonKdw87idIoTsd1vmA+AMtT4DiNVIx6TwkFSG0391paqpwwL4S
         6osrt9kZb6MxRzhGXiM5ThqLmf1SWnSiv7HgRT86rMDZVam3j9fnNyOIO2SgL+S1utXc
         +dgJ2tJRwqBmMCCWtu1KHV3NXkKkuFMFnIfNi7i/IeUwfaX8YxjhbIb4ITQLIIYFMIVe
         5m6ud1oTlPUEod0qwCGFIMr0q8Cmf861opegUffS1ra6H73sHdGt7KHPBLEu9+oDZ5Ly
         jNlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QAhdC6Rx57C1O6Ugz0jFkvg9H8x+XkIQw8XEDLp6DXI=;
        b=DfnMos+kvgaiT7qpEOhBXxYYz78NYLPK4AcBcvEEUpzhsJOOdfJ8ch5lNKqbG1hUze
         5raegVBUcmuB7Pl1XiVM80QM4NZl0tTgHtGsrOPn6l+BzARoZJJZFU9y+R8RTPnwahP0
         iwaXMjkFzb47ebisvCXC8t/BBMxISw9RThR5lxEtMp/XvlhArYeXwBvW/cZgvuAkW3np
         5tccXIkbiLCBZHhpYkBCq6jJxicVoNs9wtehkAIpUOs4co160TBxpskbJ9IA94D/Z2zQ
         KUqXRlUu1TkiMRLKa9MPrzM7mlmiur4jLKh0huelOr6ur6dtgcltAcqGISgR8CuMjQwf
         yRHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubwvJd0qFNcpZFsSoT2s76fR1DsX33lz/WDznx9XeUdveHPHfL2
	/70o32GInRpQT2ZvDvy515Y=
X-Google-Smtp-Source: APiQypJd8aahZAQZ6RGn4hRQ10vSclTZSL4TuQRDHWqVKxPz6aedl77uOGXHopF6Xm6mP/4vEGIrtg==
X-Received: by 2002:ab0:30e:: with SMTP id 14mr2591008uat.1.1586975657707;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2844:: with SMTP id o65ls566345vso.8.gmail; Wed, 15 Apr
 2020 11:34:17 -0700 (PDT)
X-Received: by 2002:a67:fd69:: with SMTP id h9mr2723779vsa.129.1586975657199;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975657; cv=none;
        d=google.com; s=arc-20160816;
        b=wka4i+C+HQtUCIHtdYf0Ogq8y0BS3NGmx1mJPDK1fr/wkOEJH2pdW66A6WRU7Nik5C
         CtKHeD9D0Y7bjmhqJB+mcwmTTlAzRavDcdsobPrV/TYmjvwtNkPV31FAXN1VyI/x9G/X
         KcQqJ2B3WAQRiSKnzZywBqoPSPKYCklWQvryk5amqZ7joI4DVA2lQIIBvwRlYKBwJRif
         8rPOknWc+eYwxdKH2vAn7FlGnzN6RPSef6PeQVo0n2A965nTadAoe7+ldhC1+NO/QQGe
         odZkO4ATOdir8ik7FfK0LKNxRH2AES4CeQ/U+kSBlbTo5b7auqjlR3TNPHa4RPcoN9fs
         6Pyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=E72fHdzs1tLy0jSCQfLpx7OiaTGak04q7a0wiGrsF+g=;
        b=rarN9MGbuJSmej8RgaEfAEz14XVsjM3m10+3cz9mtvyzL0VLwYznhOQw6vIJtDMD75
         M1l1BN/W4/ZIf9xpLM+3nopZ2rFYvdoCKTUSF3YJ3b8f+qHiwqr0kpjqrTasPjYyt6vk
         Kg+i00kI+0aDsz59uLn1Ebtvt5IPaYF3B8fo4XYh7PXxnGgmPXVu/NU377WTY7maqOX4
         twk9L26GWmSXO+Uit/9ea9DvcztZIwolEmgCL6Hr8LGaOlgbPoY+4uQCrBRVmHm4wmNq
         Sp823o0f66a/Nk9mprfWwnEoFtrqabMSxZgukHQgWPUUMJ/5YGbhG+oeO4lW9g0pfESw
         ztUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=K5vsb4pq;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s64si174526vkg.1.2020.04.15.11.34.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 17DB92173E;
	Wed, 15 Apr 2020 18:34:16 +0000 (UTC)
From: paulmck@kernel.org
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
Subject: [PATCH v4 tip/core/rcu 12/15] kcsan: Move kcsan_{disable,enable}_current() to kcsan-checks.h
Date: Wed, 15 Apr 2020 11:34:08 -0700
Message-Id: <20200415183411.12368-12-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=K5vsb4pq;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Both affect access checks, and should therefore be in kcsan-checks.h.
This is in preparation to use these in compiler.h.

Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 16 ++++++++++++++++
 include/linux/kcsan.h        | 16 ----------------
 2 files changed, 16 insertions(+), 16 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 101df7f..ef95ddc 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -37,6 +37,20 @@
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type);
 
 /**
+ * kcsan_disable_current - disable KCSAN for the current context
+ *
+ * Supports nesting.
+ */
+void kcsan_disable_current(void);
+
+/**
+ * kcsan_enable_current - re-enable KCSAN for the current context
+ *
+ * Supports nesting.
+ */
+void kcsan_enable_current(void);
+
+/**
  * kcsan_nestable_atomic_begin - begin nestable atomic region
  *
  * Accesses within the atomic region may appear to race with other accesses but
@@ -133,6 +147,8 @@ void kcsan_end_scoped_access(struct kcsan_scoped_access *sa);
 static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
 					int type) { }
 
+static inline void kcsan_disable_current(void)		{ }
+static inline void kcsan_enable_current(void)		{ }
 static inline void kcsan_nestable_atomic_begin(void)	{ }
 static inline void kcsan_nestable_atomic_end(void)	{ }
 static inline void kcsan_flat_atomic_begin(void)	{ }
diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index 17ae59e..53340d8 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -50,25 +50,9 @@ struct kcsan_ctx {
  */
 void kcsan_init(void);
 
-/**
- * kcsan_disable_current - disable KCSAN for the current context
- *
- * Supports nesting.
- */
-void kcsan_disable_current(void);
-
-/**
- * kcsan_enable_current - re-enable KCSAN for the current context
- *
- * Supports nesting.
- */
-void kcsan_enable_current(void);
-
 #else /* CONFIG_KCSAN */
 
 static inline void kcsan_init(void)			{ }
-static inline void kcsan_disable_current(void)		{ }
-static inline void kcsan_enable_current(void)		{ }
 
 #endif /* CONFIG_KCSAN */
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-12-paulmck%40kernel.org.
