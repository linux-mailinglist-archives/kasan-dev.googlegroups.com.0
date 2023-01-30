Return-Path: <kasan-dev+bncBAABB3O24CPAMGQEG6P6OYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A2D0681BBE
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:49:50 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id y2-20020adfee02000000b002bfb44f286dsf2204952wrn.11
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:49:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111790; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICraGBIdEe1KGhPtnRbkLJuKKL1aCCUB0yyrgkOdu6RaNZDr/Pi7lc/m/ZcNaEeffg
         tx53TZbphmZjv0/5SZ1DIngO7ff/HSo7koZEqgKjE2ki6SEkrwefBdT/DJLzWbtRHRvA
         5chObo9ca8SpZI7KDlm6I1tgY+/uv6lkraf93gtx54RCcyspRffqLPsrYeqHlZX1DwCx
         b7kW+tgl6PhYUgFAstumh3rjGwQ4leIMsyip4cHn8zrs7JBUpsFuqqgpUPebFiUqVV37
         1vrfFUYkEVCTs/fzn8gE5MsZzLjJpn4iKLlUOdyNFazwFyD+alYm2LZANOJitNjVvaBN
         KVEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ugA40xOqjO3KaAQ7wm+ZhxGzdwFEgK5rSUi5juywMOI=;
        b=jvFPeZiheN9TH0FzLMGh92s5Exambw0GPHDJMZUoDoyhokbXY0pkTXlUvypf55Hfcd
         Ar6t08wCS9Wk/i7J/7Rpm3t3/Jg3744WwyaWoCILLsP+ZNjXn8hamugfl1KgcLzTgeQb
         l0G2ZYV6rd8dCHCdYT1dvcMGh8d/0wCiL6D2/nLEg5iRUKhiMKCnqyn8qylJJGnA5Arf
         FcL+HO71uIM44ShQM7rYD08QAre9nA71FwnXq0jfmrW3+BzA25UtW6DJJwvUn+PvE3Md
         dfu0cgVPoGoOsZU8+a/P3hjep6mum2/r29oTJgNuT3TVMySXmI2p1BnfImeKlHtJEQ8e
         oCaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="cW/knli1";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.149 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ugA40xOqjO3KaAQ7wm+ZhxGzdwFEgK5rSUi5juywMOI=;
        b=KY9l9zci9+TxA2RVgUzIH0tzukyG0eBFeqKZa0oGzeJePHRmczNk+KAo+81VsP7OZQ
         mQuKLuvkBwybmPq7gnAbrXguUJXdRz0jma+yWIqMhrRKdvqD7c5rB1axS+tLNvZsSQvQ
         WM5EqIm8KhiOhm7m+rRPGz2CePA/ScxQ8YZTMUtSjiH0uaFV0Eh3oEp9BSDK62o7JpzA
         BuibljyIgaYBAUVtMWeG4+kWyK/qnIEzxJvTPg2h6z/Wg/tKVqSrILtYPuiZDX+I75Mf
         oKwIiLIYV9pMNjbTrL2TDLvRsrw837lPSCwrV2yLxjkFxE/rDeVkU+aKmoT6Q5oSxSu1
         T35A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ugA40xOqjO3KaAQ7wm+ZhxGzdwFEgK5rSUi5juywMOI=;
        b=Hq2jwBVIKDelHx5gGgx+IfPNV3wjUTGz3zDRqqjpLiOAHYvzmUlLVMEC+CScX+vnRO
         6j4AEULcRjQ2H1XpNvKSPqJJZCpjOlDtBWYZxWouShqWDPedV0V4z0q33KLEtYPNysHv
         BkvRFASNtuY1UsmoDL5+anufyCOnejO+cd1sSScykmpXaYhZkxUlqk+VpyW2GaLQ8gAc
         P0PaCBJfL9IEusof5wLcUturgoDx20crozU3awUyAFq6FkjRi5UizYa85Y8IcC70tZnK
         tcPYm490WMFthnqBkMdEkQIDVQ5ULwLPkjmH3PjIu8L0HToUPKiGvqu6M2A68qg7vjhM
         Dq1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko9SJUt41AfTAhXDtH7wPKrARYbdULlrG1zqIXHrgI9mreHrjbI
	OLFrK95kznyxfG33TtfDGcc=
X-Google-Smtp-Source: AMrXdXsuatMX6CmHpLkx631pnlqRygQ17uGl4hQ/iostRQNcFOhutpW6Jymm9C5C4kXD/HSKY9DYCQ==
X-Received: by 2002:a05:600c:180a:b0:3d0:a089:4d6b with SMTP id n10-20020a05600c180a00b003d0a0894d6bmr2843474wmp.78.1675111789961;
        Mon, 30 Jan 2023 12:49:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ce90:0:b0:2bf:ae0c:669b with SMTP id r16-20020adfce90000000b002bfae0c669bls3446493wrn.2.-pod-prod-gmail;
 Mon, 30 Jan 2023 12:49:49 -0800 (PST)
X-Received: by 2002:adf:f10a:0:b0:2bf:b503:4e5a with SMTP id r10-20020adff10a000000b002bfb5034e5amr20027069wro.49.1675111789034;
        Mon, 30 Jan 2023 12:49:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111789; cv=none;
        d=google.com; s=arc-20160816;
        b=bNf/kdJmWchL/RMHSGchXUJl/8Vs7aIrb8KiK9N3Q3g4YzV21/4HAlnrm+FjjFYeOC
         G3BTtalGOeD+O1dsxn+1gjBHyRYbT+fT/3uoRtfAjlwYMcOAKeRZBRLWqpV/eyoz70K+
         8sEH/dA5CDRygy9m7uhuToLnus5/jWvHmEq0k9lo2kAt4d51PG0IEqCsHzVRewIZwOz8
         P3IXaIUhz8XTaerjsU+UAWO8f8ZFW3g5iBj+wN9XsSzV8OY4ULkjWifiR1ebUQH74nTU
         GcfBulw/Lj08TmFseTuuqcGAlvrceIZ5Kh/O8dHUFWXimNucZsxundH1i2XzJDBaHXN5
         R1Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ePKn7wp1b3FbqZznSS/x2B/da1B4by5dKxtQzEtZAxA=;
        b=T6GefKLaUSq9Vl86KmlUxjLmQ7lztckutv29CAfNk3yfCMzL9+Is5EKX5IKPAl8ZMx
         LQR8LB5Hto1XEMF9H42OINo+gCNBu93nF6bEStdCtsj4R5mVB+KIpx1/zJnhZ8DJz0zN
         WiK4KDjhlfyhRVUMXhG0w9d02osY+jFz/V9K6pWmrM8h33bcxJNJptRv8sZFefFHCynV
         3PgYSmoqVFCe+lCrpPkp/B1sopqZM7nXE5CgTI45H9r0fOiTj5v0Y7OUZzguzpYx3EDc
         hdaKap8huzzIchBUQh5a6OhGhmgjclX4GajFjLt/ydOlYsMKDkjuJPYsA00aot4LUU5d
         HEYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="cW/knli1";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.149 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-149.mta1.migadu.com (out-149.mta1.migadu.com. [95.215.58.149])
        by gmr-mx.google.com with ESMTPS id az20-20020adfe194000000b002bf9650b759si665990wrb.2.2023.01.30.12.49.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:49:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.149 as permitted sender) client-ip=95.215.58.149;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 04/18] lib/stackdepot, mm: rename stack_depot_want_early_init
Date: Mon, 30 Jan 2023 21:49:28 +0100
Message-Id: <cb34925852c81be2ec6aac75766292e4e590523e.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="cW/knli1";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.149 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Rename stack_depot_want_early_init to stack_depot_request_early_init.

The old name is confusing, as it hints at returning some kind of intention
of stack depot. The new name reflects that this function requests an action
from stack depot instead.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/stackdepot.h | 14 +++++++-------
 lib/stackdepot.c           | 10 +++++-----
 mm/page_owner.c            |  2 +-
 mm/slub.c                  |  4 ++--
 4 files changed, 15 insertions(+), 15 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 1296a6eeaec0..c4e3abc16b16 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -31,26 +31,26 @@ typedef u32 depot_stack_handle_t;
  * enabled as part of mm_init(), for subsystems where it's known at compile time
  * that stack depot will be used.
  *
- * Another alternative is to call stack_depot_want_early_init(), when the
+ * Another alternative is to call stack_depot_request_early_init(), when the
  * decision to use stack depot is taken e.g. when evaluating kernel boot
  * parameters, which precedes the enablement point in mm_init().
  *
- * stack_depot_init() and stack_depot_want_early_init() can be called regardless
- * of CONFIG_STACKDEPOT and are no-op when disabled. The actual save/fetch/print
- * functions should only be called from code that makes sure CONFIG_STACKDEPOT
- * is enabled.
+ * stack_depot_init() and stack_depot_request_early_init() can be called
+ * regardless of CONFIG_STACKDEPOT and are no-op when disabled. The actual
+ * save/fetch/print functions should only be called from code that makes sure
+ * CONFIG_STACKDEPOT is enabled.
  */
 #ifdef CONFIG_STACKDEPOT
 int stack_depot_init(void);
 
-void __init stack_depot_want_early_init(void);
+void __init stack_depot_request_early_init(void);
 
 /* This is supposed to be called only from mm_init() */
 int __init stack_depot_early_init(void);
 #else
 static inline int stack_depot_init(void) { return 0; }
 
-static inline void stack_depot_want_early_init(void) { }
+static inline void stack_depot_request_early_init(void) { }
 
 static inline int stack_depot_early_init(void)	{ return 0; }
 #endif
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 90c4dd48d75e..8743fad1485f 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -71,7 +71,7 @@ struct stack_record {
 	unsigned long entries[];	/* Variable-sized array of entries. */
 };
 
-static bool __stack_depot_want_early_init __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
+static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
 
 static void *stack_slabs[STACK_ALLOC_MAX_SLABS];
@@ -107,12 +107,12 @@ static int __init is_stack_depot_disabled(char *str)
 }
 early_param("stack_depot_disable", is_stack_depot_disabled);
 
-void __init stack_depot_want_early_init(void)
+void __init stack_depot_request_early_init(void)
 {
-	/* Too late to request early init now */
+	/* Too late to request early init now. */
 	WARN_ON(__stack_depot_early_init_passed);
 
-	__stack_depot_want_early_init = true;
+	__stack_depot_early_init_requested = true;
 }
 
 int __init stack_depot_early_init(void)
@@ -128,7 +128,7 @@ int __init stack_depot_early_init(void)
 	if (kasan_enabled() && !stack_hash_order)
 		stack_hash_order = STACK_HASH_ORDER_MAX;
 
-	if (!__stack_depot_want_early_init || stack_depot_disable)
+	if (!__stack_depot_early_init_requested || stack_depot_disable)
 		return 0;
 
 	if (stack_hash_order)
diff --git a/mm/page_owner.c b/mm/page_owner.c
index 2d27f532df4c..90a4a087e6c7 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -48,7 +48,7 @@ static int __init early_page_owner_param(char *buf)
 	int ret = kstrtobool(buf, &page_owner_enabled);
 
 	if (page_owner_enabled)
-		stack_depot_want_early_init();
+		stack_depot_request_early_init();
 
 	return ret;
 }
diff --git a/mm/slub.c b/mm/slub.c
index 13459c69095a..f2c6c356bc36 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1592,7 +1592,7 @@ static int __init setup_slub_debug(char *str)
 		} else {
 			slab_list_specified = true;
 			if (flags & SLAB_STORE_USER)
-				stack_depot_want_early_init();
+				stack_depot_request_early_init();
 		}
 	}
 
@@ -1611,7 +1611,7 @@ static int __init setup_slub_debug(char *str)
 out:
 	slub_debug = global_flags;
 	if (slub_debug & SLAB_STORE_USER)
-		stack_depot_want_early_init();
+		stack_depot_request_early_init();
 	if (slub_debug != 0 || slub_debug_string)
 		static_branch_enable(&slub_debug_enabled);
 	else
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cb34925852c81be2ec6aac75766292e4e590523e.1675111415.git.andreyknvl%40google.com.
