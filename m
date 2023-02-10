Return-Path: <kasan-dev+bncBAABBHHITKPQMGQEPRFEWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 44EBB692901
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:16:13 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id n14-20020a5d598e000000b002c3f0a93825sf1601514wri.15
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:16:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063773; cv=pass;
        d=google.com; s=arc-20160816;
        b=xSCFOAvCzWznBIXkyHoOpe7bNP9HYi0Arh9h3yCsDGNJkcLwxq/0ntzf8LfP/V8EfV
         89evPlUeg0bCHR1sYvDLY9Ps9TEuudG0NR/vM1vxShp0HdXhtspzFBaGLlTOaJ4UI797
         /QEqBMv5Ct++JnZUuMNKngrHYvor99DJagFr3n3oJaOFXwWmHbn/BxBGwRgQ9nRSeXhA
         vtk6OG6pNWCmHKySirFfQ80poni6+ypEvRmYX/dXRQAMXHCjap1FpjgyckHrJS9vicTX
         u7+pipighU/BuE6hfNQMHZuHbyW7glMBcwoqc8cwWAp5A9FXfj9roJTmd3rlZPAqZLTW
         cqNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7Bezs+XXsJX4PmxOpOBnljws2hQtwc2r/U1IbuAbQf0=;
        b=jhs0OpoeRmL06fgRiKAZ8+VFE76qwO4eQ2TQ99aKVZzbxTIvfGW6uWlsVVoA5o3hxm
         oyDoBKSrwvCjktJWRQnNzW28Yuli3fvJoBC5Y67JWiS5DXcKcXK1zJ4AXDZSCVjalIUW
         nD8Up2wgxMlchfeprK8fPJtCI9HwOUaxVBZtBe6QegHLVO9G5DC6zTRZX42wF2ELAArB
         whgG7SgYx0R1ZGuYZULiWtYNFNrlkfumgYF4RLDTArvtLzfL5474GmUjqVAaCpX5NfBl
         KfDv0GmQOyvdjSwRQujg7e9eG71H+1PLYc6sDMX1NcdSu2cCcM85CpDCmuu1piEBFac6
         fZVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dh6wp1Eq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.100 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Bezs+XXsJX4PmxOpOBnljws2hQtwc2r/U1IbuAbQf0=;
        b=FCQSWkt7P2A+2GLKGH4MaHjf8bYFzaiA/q06I4xECHEobVjLgvXJXEA93dRQA4tffk
         sxOtnwqm2CbeUaqpgu/QL64dkJIPy9miJRBEk0T79egR7sUfFCq10/iP0VEF/amKZzMG
         d+GQZlaytykCpDZM2Bx93T6LMrDGp8IYOPVvs8M2ayNixeEMu8qCN2vk6lm5h9y+gLyf
         C59K7givYF06hscZZ5yVJ3D086mUaypI3Q8QT+rmLBw5HgEpD4UOn2uOPQGsWO8RDw7S
         kFjU3cgs/QekyOVzbVuhnj8Kz+5geMnNuAC/kwuXHPsDchng2ZowCrBLwPhxCGl34vtn
         8aXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Bezs+XXsJX4PmxOpOBnljws2hQtwc2r/U1IbuAbQf0=;
        b=EcuLb96ZrG2oWNYuezewFCxo5Yfd4FKxX1kXeWOyVDmPJWf2QBMOh5pydd99EjKlpx
         xRJwvti1YmqFbSHS/Ze7x/BgwRtTF23I86kus32jXxXQ1FodxVu98ikc/+12Ig+dy1h3
         pfi6v38YhclY13AhtiTcg53PDEfVIpl4pC/HUIK4lxbcoC0gjjc6PbrIieEKbjS4bn7m
         6PO2evsuZfUQ7thUGtj++G89WR2v/TS/QM3+8gYdaKFcmG+2EpG+zAYQHIhAkkoESjGI
         I+qU9kzJyDOWNnYvMc8Sjmf6AdfBzAAVy4jY6nJ15gqzara65SgpOrJQQ/yNk7la1kf8
         WIvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKX+43mKbmHK2etU4ALZO9VMiTTXfH4iuxC90GqBeIwa5NL15VN0
	Flcoi+IBI9//Rq/CHq1dCWY=
X-Google-Smtp-Source: AK7set91D2IKsuPn8UHcjVpHGHYh1nFh5sfbvqudHSBFVvih9YqiuTCijjuH6q5TnM5K7blxjGkanw==
X-Received: by 2002:adf:efca:0:b0:2bf:b6a2:a053 with SMTP id i10-20020adfefca000000b002bfb6a2a053mr757625wrp.287.1676063772632;
        Fri, 10 Feb 2023 13:16:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ea50:0:b0:298:bd4a:4dd9 with SMTP id j16-20020adfea50000000b00298bd4a4dd9ls2229291wrn.1.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:16:11 -0800 (PST)
X-Received: by 2002:a05:6000:118c:b0:2bf:bd43:aacc with SMTP id g12-20020a056000118c00b002bfbd43aaccmr13673387wrx.55.1676063771705;
        Fri, 10 Feb 2023 13:16:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063771; cv=none;
        d=google.com; s=arc-20160816;
        b=DNvaM4lRmi68q823w7+Son32F8WEQEfzoLi9e99+ANNKrogKD7ARKUdEQRY1FoP9iq
         P4cebGAWMy0selsgOfqKDa9cpNFF053dRS/vueoZydFCjKEvXlIaHaoXykOo3thrInyn
         aNdV+oBW7jVvs9BDmcSWm5Cnr+ztbdxNCLaQMIZGjzAQMURL2MXaSl+sBzT49hKg4Tt8
         QOnf3TPA/uGrPZc3qKiboe9J3WAoeNpmdclpz4xD/Ym4N2iBo096P8ivD4ADd2MwrSYL
         Lh/atC4qKYEmL3zOB8SPF7xcKQOBZ+7l8YUBqf/qoejdmtfqySM1Q651KJC84gPj5oIB
         h8xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TynB0J5qbcRBuS5BSP3vU74TPjYQ5881BbX5zggeusA=;
        b=LxUWvwKCk1nORoFdBqWJkGeOu2JoL7/26x4QEjEt5OE64T2j1h9C5L7pPaY1WN9wDG
         ZfzeA+szpMdIDotWiC4XtrFaT/b0NuqFYEV9vO5vFydRTvv1SDEzp5w3mdZg/h/5yQkN
         6TyqUDJLXIISDhMkWpbVex3t/yu2AfNZTbmZJsUVyAEjEgI/EkxjAZsph1Qj4JoEE9dn
         oZP1Aqgc/rTQf26AXPxk1ymk19I02rQbyzzjU1x4aFkhUBtR5VzArPmD7YTHzv/61+5E
         T+06WKT0Lssnap1ic2mrLCJaIbRNRCM6MgVQwXf8jw5MOKU6l4tNlyaXiEsD+ymvtIFB
         WLcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=dh6wp1Eq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.100 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-100.mta0.migadu.com (out-100.mta0.migadu.com. [91.218.175.100])
        by gmr-mx.google.com with ESMTPS id 1-20020a056000156100b002c54cdd5f0bsi57605wrz.4.2023.02.10.13.16.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:16:11 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.100 as permitted sender) client-ip=91.218.175.100;
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
Subject: [PATCH v2 03/18] lib/stackdepot, mm: rename stack_depot_want_early_init
Date: Fri, 10 Feb 2023 22:15:51 +0100
Message-Id: <359f31bf67429a06e630b4395816a967214ef753.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=dh6wp1Eq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.100
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Reviewed-by: Alexander Potapenko <glider@google.com>
Acked-by: Vlastimil Babka <vbabka@suse.cz>
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
index 83787e46a3ab..136706efe339 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/359f31bf67429a06e630b4395816a967214ef753.1676063693.git.andreyknvl%40google.com.
