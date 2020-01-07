Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJXF2LYAKGQEPLFMTLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id DFE05132B22
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Jan 2020 17:32:38 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id f10sf160559wro.14
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Jan 2020 08:32:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578414758; cv=pass;
        d=google.com; s=arc-20160816;
        b=BgmT1iz1MWkZSOA9U3kSSihPteyUsWNiOSMocRmdSZZf770FdhBgQNI5JkHRaaZpmC
         EQejv5ZfB2nU5PzKRgGxkmA+MXUabwvf3kg3z7LiRs0k35i1dMmjl5lYyF68kdnCYFqq
         iuAGOsrz3Lk9dsr5+77bb5ovpd/viBgDyiz6dn5fGtyTAf9tqJMvYkIAlxYRS0ODzcSx
         TaagkwuVHWhknQ8fAnFpxEq+eFdMswsvppuOP3uTVc/08m14xZcbCjRVfsoT18/FsAEo
         C7Flr/sOR5+37y29Ok4wPZvgWRB/awcxs2r6hO6MIa8E/PFSAHzG+rAn2VCjCig/an1e
         nGJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=blBlFvlTDZmyqilxm2fbAU68Bk9E9KMpZdbKqgmP1Hc=;
        b=jCGvPg3YEZJT5XgyxpFsKVDLwP+wVPbKmV1HPF6wRAWb02MsUfcQjQBiOOaY89TtcE
         RDy4yIcgG/zxcumeKY2hOXB5ZAW1Q3c0Y4r71AkOWFfQo3AkhGNKZ1LhjyO0LgaRJDG/
         ZDwS/D5NUd+2cFLLqDx3d3UFHFHtajfB2LUuL6bVaYShaKg7f7xF3Fl2WkdDoqWnipgT
         Fpt9e8BGLwG2x0NjmGPTnOZ3fmeKg7BAqyumt+mWcACTnJAKnolXWW00CbIsWn4ohhF7
         YxH6baRBf1/kNWr65w8xOaCoj76cUJxrmiwf9aQIfnpTyafoFw8G4tLhTm3zuwCj3uIU
         4ywQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hkbMLZEK;
       spf=pass (google.com: domain of 3pbiuxgukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3pbIUXgUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=blBlFvlTDZmyqilxm2fbAU68Bk9E9KMpZdbKqgmP1Hc=;
        b=tT4g+MBjaaQfOzhiNVzdSM6KwZ7UMh6pVbPTz5Oa8g6AV8rAmOBJGaEnKtt4vsBMRP
         FTFyqOw9rQh1F4fhLn+w3Hl9bE6Nw4SlnDQbciE6pqmKfmJe3tmsZCqaZticZFIK4DMU
         63pOs40xXpO4Y16ywrmlCKQX54WpG1nEJioQp86mLqNPIx3lCcnPI5RaUQTOZ4Meg8H6
         HPsCjbH5piDYUXVdFDih7LsG6if/TiyyjLSL+j04ejSpWHxj5WDDHejA32SDvspoWf9b
         RXDQTWt7aau5ET8Irr6hYp9548VOAeYbNFclyLhbUqxf+ydYd7wBzAxaHGUvHlHV2ghg
         6D4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=blBlFvlTDZmyqilxm2fbAU68Bk9E9KMpZdbKqgmP1Hc=;
        b=QcMSxgFt7GWQLhfc6U+QDN6nV3yp2vEutGoFbGKz7XaJvoPzD2dQResMrDNp6MWEF/
         sHfnv5+KBoE0AgVmnzaVxk+SfRQ4Qqb9qEQ0FagmCaTCXLwUY1uiPWpStanSiZl1SbT9
         iw6rWChaWjqApxFmoSqdHYK3Zc+LUCKslcUofym6saE13Gp10Bj9dmjjNQLpMJhChmtF
         yiIJr7NwAwtEmSpRQjcV9xLIZxTDNiJXH8WgH2XssWgsqg6XGNne3zxvQnmvPcWN8E0W
         TbOBLUEl3s3TGn2SnezPFYGg/gHVRPmWANoyzrHFdoCnDX8UOU89cP5NEjxJGdQJcaLO
         cvUw==
X-Gm-Message-State: APjAAAU4mW8NGjEAruVNErFSTQNHEYuX6lrx/9G/PlOENxrjre/li9KS
	E8RvwOv21AMep86Lf76Y+ak=
X-Google-Smtp-Source: APXvYqyf8MX+tUb9p6oFmMHdqywUY337LemifEVRVYsglRCacci8kBy5NpLj/tn57a40/3tL3k4tkA==
X-Received: by 2002:a5d:4b88:: with SMTP id b8mr62384276wrt.343.1578414758578;
        Tue, 07 Jan 2020 08:32:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c3d8:: with SMTP id t24ls2157wmj.5.canary-gmail; Tue, 07
 Jan 2020 08:32:37 -0800 (PST)
X-Received: by 2002:a7b:c4cc:: with SMTP id g12mr42208308wmk.68.1578414757917;
        Tue, 07 Jan 2020 08:32:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578414757; cv=none;
        d=google.com; s=arc-20160816;
        b=DBiuX10Hi0BrhEaiK6uTQyG7VKzIowgMl1UKFO0eRyLpraQ9ZXBnzqg1CCBdAO8sIR
         ZaJVV2fkmClT3nwGY/nvrDi8/8d99dvhJ+LZtjW+1r8V5e1sPFZFCZgiW6VDvrCYVbmy
         t65MrgROpT33osDtriQMofpkBYwlaZoCWOgULhyw+VDnxOLicJ/ANLizaqmlpw7NREDL
         N52pVaRGfGp59SKoX5mPtOVUj5/IxtSvFCNFMsabqR9xplKfF5T51611iYGqlxOfhYjp
         W8JaFqfi+4S/YlLbU/u16VlQmRFJJQqUQznpjdMDyGpaRa1Fv93uGAdzXkbtquJOAA02
         Xnog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=fb41PwBszVzphy7ivShzNkn2ANS2zPkBPktoauw+T4w=;
        b=ZZKN1G60fmIoa2l7AhIRivZmAlf6oc/8lDXgR43Ujizkfx+lQ6/USjE9j1nJg94sIT
         PE6alFsE58P0p6uwpZ/oWo3fCQJloLHxOEKO268rePe886SkgqO2JEfp1swTxu2WcyrV
         fWOczQIzR9Ol0P7R/2El2eK9tnYom8H0LKawWNWMVqmfxlRA+X0q/C0YfPZ7dwxg9Pk2
         fS8cQonlJzG92wRq0oq+m/5dMqKx/pkovDsivUc1nKQVYmtius5g1J1R1HmEwQCn08If
         KvIjAZOsvQymCp5g6cFmiOg7yREvd5aF871L0Ucw2LC0KQVqZdoHrgCW12ITAntoW7ZX
         YWhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hkbMLZEK;
       spf=pass (google.com: domain of 3pbiuxgukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3pbIUXgUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id u9si7167wri.3.2020.01.07.08.32.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 07 Jan 2020 08:32:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pbiuxgukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id j13so152456wrr.20
        for <kasan-dev@googlegroups.com>; Tue, 07 Jan 2020 08:32:37 -0800 (PST)
X-Received: by 2002:a05:6000:1288:: with SMTP id f8mr109864131wrx.66.1578414757306;
 Tue, 07 Jan 2020 08:32:37 -0800 (PST)
Date: Tue,  7 Jan 2020 17:31:04 +0100
Message-Id: <20200107163104.143542-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.1.735.g03f4e72817-goog
Subject: [PATCH RESEND -rcu] kcsan: Prefer __always_inline for fast-path
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, dvyukov@google.com, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hkbMLZEK;       spf=pass
 (google.com: domain of 3pbiuxgukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3pbIUXgUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

Prefer __always_inline for fast-path functions that are called outside
of user_access_save, to avoid generating UACCESS warnings when
optimizing for size (CC_OPTIMIZE_FOR_SIZE). It will also avoid future
surprises with compiler versions that change the inlining heuristic even
when optimizing for performance.

Report: http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
Reported-by: Randy Dunlap <rdunlap@infradead.org>
Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested
Signed-off-by: Marco Elver <elver@google.com>
---
Rebased against -rcu/dev branch.

---
 kernel/kcsan/atomic.h   |  2 +-
 kernel/kcsan/core.c     | 18 +++++++++---------
 kernel/kcsan/encoding.h | 14 +++++++-------
 3 files changed, 17 insertions(+), 17 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index 576e03ddd6a3..a9c193053491 100644
--- a/kernel/kcsan/atomic.h
+++ b/kernel/kcsan/atomic.h
@@ -18,7 +18,7 @@
  * than cast to volatile. Eventually, we hope to be able to remove this
  * function.
  */
-static inline bool kcsan_is_atomic(const volatile void *ptr)
+static __always_inline bool kcsan_is_atomic(const volatile void *ptr)
 {
 	/* only jiffies for now */
 	return ptr == &jiffies;
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3314fc29e236..4d4ab5c5dc53 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -78,10 +78,10 @@ static atomic_long_t watchpoints[CONFIG_KCSAN_NUM_WATCHPOINTS + NUM_SLOTS-1];
  */
 static DEFINE_PER_CPU(long, kcsan_skip);
 
-static inline atomic_long_t *find_watchpoint(unsigned long addr,
-					     size_t size,
-					     bool expect_write,
-					     long *encoded_watchpoint)
+static __always_inline atomic_long_t *find_watchpoint(unsigned long addr,
+						      size_t size,
+						      bool expect_write,
+						      long *encoded_watchpoint)
 {
 	const int slot = watchpoint_slot(addr);
 	const unsigned long addr_masked = addr & WATCHPOINT_ADDR_MASK;
@@ -146,7 +146,7 @@ insert_watchpoint(unsigned long addr, size_t size, bool is_write)
  *	2. the thread that set up the watchpoint already removed it;
  *	3. the watchpoint was removed and then re-used.
  */
-static inline bool
+static __always_inline bool
 try_consume_watchpoint(atomic_long_t *watchpoint, long encoded_watchpoint)
 {
 	return atomic_long_try_cmpxchg_relaxed(watchpoint, &encoded_watchpoint, CONSUMED_WATCHPOINT);
@@ -160,7 +160,7 @@ static inline bool remove_watchpoint(atomic_long_t *watchpoint)
 	return atomic_long_xchg_relaxed(watchpoint, INVALID_WATCHPOINT) != CONSUMED_WATCHPOINT;
 }
 
-static inline struct kcsan_ctx *get_ctx(void)
+static __always_inline struct kcsan_ctx *get_ctx(void)
 {
 	/*
 	 * In interrupts, use raw_cpu_ptr to avoid unnecessary checks, that would
@@ -169,7 +169,7 @@ static inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
-static inline bool is_atomic(const volatile void *ptr)
+static __always_inline bool is_atomic(const volatile void *ptr)
 {
 	struct kcsan_ctx *ctx = get_ctx();
 
@@ -193,7 +193,7 @@ static inline bool is_atomic(const volatile void *ptr)
 	return kcsan_is_atomic(ptr);
 }
 
-static inline bool should_watch(const volatile void *ptr, int type)
+static __always_inline bool should_watch(const volatile void *ptr, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -226,7 +226,7 @@ static inline void reset_kcsan_skip(void)
 	this_cpu_write(kcsan_skip, skip_count);
 }
 
-static inline bool kcsan_is_enabled(void)
+static __always_inline bool kcsan_is_enabled(void)
 {
 	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
 }
diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index b63890e86449..f03562aaf2eb 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -59,10 +59,10 @@ encode_watchpoint(unsigned long addr, size_t size, bool is_write)
 		      (addr & WATCHPOINT_ADDR_MASK));
 }
 
-static inline bool decode_watchpoint(long watchpoint,
-				     unsigned long *addr_masked,
-				     size_t *size,
-				     bool *is_write)
+static __always_inline bool decode_watchpoint(long watchpoint,
+					      unsigned long *addr_masked,
+					      size_t *size,
+					      bool *is_write)
 {
 	if (watchpoint == INVALID_WATCHPOINT ||
 	    watchpoint == CONSUMED_WATCHPOINT)
@@ -78,13 +78,13 @@ static inline bool decode_watchpoint(long watchpoint,
 /*
  * Return watchpoint slot for an address.
  */
-static inline int watchpoint_slot(unsigned long addr)
+static __always_inline int watchpoint_slot(unsigned long addr)
 {
 	return (addr / PAGE_SIZE) % CONFIG_KCSAN_NUM_WATCHPOINTS;
 }
 
-static inline bool matching_access(unsigned long addr1, size_t size1,
-				   unsigned long addr2, size_t size2)
+static __always_inline bool matching_access(unsigned long addr1, size_t size1,
+					    unsigned long addr2, size_t size2)
 {
 	unsigned long end_range1 = addr1 + size1 - 1;
 	unsigned long end_range2 = addr2 + size2 - 1;
-- 
2.24.1.735.g03f4e72817-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200107163104.143542-1-elver%40google.com.
