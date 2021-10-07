Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBU4J7OFAMGQEOZ3R4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D79E942508F
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 11:58:43 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id bi16-20020a0565120e9000b003fd56ef5a94sf3050940lfb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 02:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633600723; cv=pass;
        d=google.com; s=arc-20160816;
        b=OhERHI43x+LlxEdaFAFLb5Xn2PdjqE15Zft/tmZ1qN8P3KPsohv4fU5gBH73jZYTQn
         v+IPIaWPB6La6+3QtBuFBaCX8Pxs62WhVEjRmJYFyx4glFPX6uGExzUukHnh8X4QcF2l
         JbBu0cI6uRGjZFXJv63Ehff/WIpOXhwbI2JI4Ol3caxfBfcEc27/i8g0zdwCVBsKTatN
         wDACoRSRtAWwqK5BUmQc0MzPejGDgAjEBr+McpsryjIsXS2/w+6AncXelieHxG47BMpQ
         ud/0e8BMqIKstXRikrrLcKHh9a/PvqOXNYJHlGMaM6ncaIfAU6A/P8hRTbtUckpR/bfB
         wi1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=GFn6UGSsAz9XorjxwcTRj+R1l1ryDupGbCTAj4Ohy3A=;
        b=WTp/AyzEcc3I0tHZsPEmAg+OzgPgVpmi+HqBadiwByyebz6V2g9ZnkjF1B+IL0Ycvi
         Vrg2rAqhikp9GSrOzGA8UL5dLAkNX5BWXxSm+5e0NO0cjcKtmA37SW+YN3XUrgXUtQKk
         zwxYhkAOguaOO1s6/cCMxAsvfYpMvONEbXQ8VFasnrg2Bt2GnOT8DrlwMw5/48L2CBM9
         r7MZgz6zfFk/QkaH2yjCao8wGyXfWYaY520dvGUKrQXz+h/cwo3Q6A6srBnTRkc7l9jw
         UhJiD5QcO0m/d/b2Flb++8yZijZAwc78n7pAUgL/+z+gFGK3ZSuxoGY1yCK42FYfxvMB
         KzFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1CFhFZQT;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GFn6UGSsAz9XorjxwcTRj+R1l1ryDupGbCTAj4Ohy3A=;
        b=kTSavWc+RSUHvUuGVeeutAGoSmPLegwlMf4RJy9Q6yd0zwzhA6Yl3G4jZEKHzfAPLI
         WyBxU0o48C4MaP3Guc1xMsfL993EaZuAyX/GE5w0N3CA4GQC2CN9nZNC4MU7Qi35ooKJ
         tC8+s9/kVWAd1WGCNCTvjRxK6zquI9R2dlXRK15jtRCXyIco3UVK/eOEDCK+aBCgszVc
         nCfyGsRK0xRUi1gSDO3V9/mBkZugHmyua5xQMkJYdo8psEcyQcl9n1IfYLwLRrzwAyPF
         yr5S8qvz+ivApKTmosI6icoJZRxZN0DL5L5jHgctfcVUH6+CmFB6GYQpxhzhHaBYdIR/
         BcUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GFn6UGSsAz9XorjxwcTRj+R1l1ryDupGbCTAj4Ohy3A=;
        b=x/BbMKTPHNAFd+AaMjaM96gDOx0v1/tqVJ2ft4NWACxvefbqOFOJvmcQkANeVeNbd/
         LdwxSjtTle0qqcAEVDEt53EkQyoLKsYRc4diBIp2qa1P5BnYFcmrrlDiT32GOCLOnAcA
         ZMGU68iOtR8imNz8RaJi5u77hlH+I5wzwZPaeYFQDQJhspR1P/CXz/fzAcrIe/RoWfJQ
         6Y6r9n6ZAVXhXkYVbiTckV79uB6ALBo0mevv0z9HJo5e+DeCUkybFKGE09meT+ES2QC1
         uzHW5UCSyLM18hb6e+AB1HAWgk1humbftd+NUVJ//YpSb0C/z3JTOEi7QlrKTbqPId0O
         yVpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/GeBfntLPGaAUhhHhcWwqfKpU4hmOz7lMTr3b+ZWROdXy8NDD
	eTjcx5H+wgxABKJAg2/e82Q=
X-Google-Smtp-Source: ABdhPJzGVTvjU5Z3KLALmmY+wCsl/Oz3RCxsBNPF8uSwuxmeS0ZROspN2UdgRK1ohvjFequnTp1IlQ==
X-Received: by 2002:a05:6512:c22:: with SMTP id z34mr3285175lfu.664.1633600723428;
        Thu, 07 Oct 2021 02:58:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3994:: with SMTP id j20ls497010lfu.3.gmail; Thu, 07
 Oct 2021 02:58:42 -0700 (PDT)
X-Received: by 2002:a05:6512:3bc:: with SMTP id v28mr3383828lfp.604.1633600722258;
        Thu, 07 Oct 2021 02:58:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633600722; cv=none;
        d=google.com; s=arc-20160816;
        b=dw3JeBGoi/NKdrJruIv0vn0KVvIDZAQBY0mYGDbohed8kwlMIMOv9JKvvx4+86b9T/
         i8bAmwwg1EVkN6gCbO8HyqZ3csGbhUYvTHIgaMqL32KqqUZFHd6+8gtbPwXaZ6ttRWrW
         xXD7Z7hiUKe5o04ZCV7eX3k5ty+SeWGF4fibjletEUAT/j/CAffM6r7uDHEkkWxmnVtA
         KfTsSSl9dD18kX9BRoapEelGF48hf80Ba0zME7q9pYGBCQG2AMX/YfOV3Hp1HomSkGFN
         m9C2f1yrxilFZki3GGhoeF5i5gMjSrpAXHefjQcYmF0obqiT36ANXVsAB7XbZiLn0elS
         vO0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-signature;
        bh=tE+KpJkG32exYjSKNVJFpDoJhh1mV3sWGv1DIr8+vbw=;
        b=k3johlht67GFBxvWrvzvECkIdOvUdzkffjrQRrde+genCNN8VJ++Gh7QgbuYD87uEv
         Vv4vIOB47P3aFUNMAK5eaAujcCR78YG3u3gaitRyIMF69f7KEXN1GlbCbdnusCoc3sP6
         CtlvuWf4IUoyTxQ/At+naNnQn86TQa7Sp8exuI7D4N2P5FxeODWZdiujDK/CtQyJV2fZ
         9EsOZXkUdyrzo5YQA3FyOWInvMSraeFjS/mmJSHJWPTkuTxXIzjp2voSqS8l174jtOpz
         GSEGfQMEABtBl/I7mDpxIdFTlDVuXWZItUtIiUNu8yVKwqPNtjqFMlOYvPIAOFyBJ7bu
         WIWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1CFhFZQT;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id u24si156636lfr.10.2021.10.07.02.58.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Oct 2021 02:58:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8C94A2258F;
	Thu,  7 Oct 2021 09:58:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4540913B68;
	Thu,  7 Oct 2021 09:58:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id XuI1ENHEXmFWQwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 07 Oct 2021 09:58:41 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	David Airlie <airlied@linux.ie>,
	Daniel Vetter <daniel@ffwll.ch>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Oliver Glitta <glittao@gmail.com>,
	Imran Khan <imran.f.khan@oracle.com>
Subject: [PATCH] lib/stackdepot: allow optional init and stack_table allocation by kvmalloc()
Date: Thu,  7 Oct 2021 11:58:15 +0200
Message-Id: <20211007095815.3563-1-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.0
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=9728; h=from:subject; bh=cmFU9IIwiMam4qL9IpFsBX7s20Xoak4Vs4wOahaA+jg=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhXsSo8XQVjAIb+/CD2HTqNplWygw85zfk9+3D7FyA J5fJh+qJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYV7EqAAKCRDgIcpz8YmpEH+VB/ 9TUOnhw2poTAWn2t9D0vPkiEb9K2llRcbSi60L1GSS9VQztsRj0DpBBKJ7lLw3pMPyVEz/+TrJ3W+M iyFJ/1Uq06LY4UcwrGt+RDjgDQmRHQy7a7Neq7tctQQQ1Ar+q8MlWLoyNinz2YJKRfIdZRGq23Ypw5 /wFS1FOpLR3wnDr24rYRJPCrLa/i32fzB+ZfZSQd6JgYVMUSaXy+ye+cbLA+ptwz+QTygQFbKR/Kgl kQON0ZLgkBqapAeisWJ/RoXGJLtC3TNeyTDJmdjRCyYV9Za9AlxVO9j5ebOJFZI/91WeSWJkBIELBT SvTqiVCXL2x00tvF0XbO29TTkHJjTY
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=1CFhFZQT;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Currently, enabling CONFIG_STACKDEPOT means its stack_table will be allocated
from memblock, even if stack depot ends up not actually used. The default size
of stack_table is 4MB on 32-bit, 8MB on 64-bit.

This is fine for use-cases such as KASAN which is also a config option and
has overhead on its own. But it's an issue for functionality that has to be
actually enabled on boot (page_owner) or depends on hardware (GPU drivers)
and thus the memory might be wasted. This was raised as an issue when trying
to add stackdepot support for SLUB's debug object tracking functionality. It's
common to build kernels with CONFIG_SLUB_DEBUG and enable slub_debug on boot
only when needed, or create specific kmem caches with debugging for testing
purposes.

It would thus be more efficient if stackdepot's table was allocated only when
actually going to be used. This patch thus makes the allocation (and whole
stack_depot_init() call) optional:

- Add a CONFIG_STACKDEPOT_ALWAYS_INIT flag to keep using the current
  well-defined point of allocation as part of mem_init(). Make CONFIG_KASAN
  select this flag.
- Other users have to call stack_depot_init() as part of their own init when
  it's determined that stack depot will actually be used. This may depend on
  both config and runtime conditions. Convert current users which are
  page_owner and several in the DRM subsystem. Same will be done for SLUB
  later.
- Because the init might now be called after the boot-time memblock allocation
  has given all memory to the buddy allocator, change stack_depot_init() to
  allocate stack_table with kvmalloc() when memblock is no longer available.
  Also handle allocation failure by disabling stackdepot (could have
  theoretically happened even with memblock allocation previously), and don't
  unnecessarily align the memblock allocation to its own size anymore.

[1] https://lore.kernel.org/all/CAMuHMdW=eoVzM1Re5FVoEN87nKfiLmM2+Ah7eNu2KXEhCvbZyA@mail.gmail.com/

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
Cc: Marco Elver <elver@google.com>
Cc: Vijayanand Jitta <vjitta@codeaurora.org>
Cc: Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
Cc: Maxime Ripard <mripard@kernel.org>
Cc: Thomas Zimmermann <tzimmermann@suse.de>
Cc: David Airlie <airlied@linux.ie>
Cc: Daniel Vetter <daniel@ffwll.ch>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Oliver Glitta <glittao@gmail.com>
Cc: Imran Khan <imran.f.khan@oracle.com>
---
Hi, I'd appreciate review of the DRM parts - namely that I've got correctly
that stack_depot_init() is called from the proper init functions and iff
stack_depot_save() is going to be used later. Thanks!

 drivers/gpu/drm/drm_dp_mst_topology.c   |  1 +
 drivers/gpu/drm/drm_mm.c                |  4 ++++
 drivers/gpu/drm/i915/intel_runtime_pm.c |  3 +++
 include/linux/stackdepot.h              | 19 ++++++++-------
 init/main.c                             |  3 ++-
 lib/Kconfig                             |  3 +++
 lib/Kconfig.kasan                       |  1 +
 lib/stackdepot.c                        | 32 +++++++++++++++++++++----
 mm/page_owner.c                         |  2 ++
 9 files changed, 53 insertions(+), 15 deletions(-)

diff --git a/drivers/gpu/drm/drm_dp_mst_topology.c b/drivers/gpu/drm/drm_dp_mst_topology.c
index 2d1adab9e360..bbe972d59dae 100644
--- a/drivers/gpu/drm/drm_dp_mst_topology.c
+++ b/drivers/gpu/drm/drm_dp_mst_topology.c
@@ -5490,6 +5490,7 @@ int drm_dp_mst_topology_mgr_init(struct drm_dp_mst_topology_mgr *mgr,
 	mutex_init(&mgr->probe_lock);
 #if IS_ENABLED(CONFIG_DRM_DEBUG_DP_MST_TOPOLOGY_REFS)
 	mutex_init(&mgr->topology_ref_history_lock);
+	stack_depot_init();
 #endif
 	INIT_LIST_HEAD(&mgr->tx_msg_downq);
 	INIT_LIST_HEAD(&mgr->destroy_port_list);
diff --git a/drivers/gpu/drm/drm_mm.c b/drivers/gpu/drm/drm_mm.c
index 7d1c578388d3..8257f9d4f619 100644
--- a/drivers/gpu/drm/drm_mm.c
+++ b/drivers/gpu/drm/drm_mm.c
@@ -980,6 +980,10 @@ void drm_mm_init(struct drm_mm *mm, u64 start, u64 size)
 	add_hole(&mm->head_node);
 
 	mm->scan_active = 0;
+
+#ifdef CONFIG_DRM_DEBUG_MM
+	stack_depot_init();
+#endif
 }
 EXPORT_SYMBOL(drm_mm_init);
 
diff --git a/drivers/gpu/drm/i915/intel_runtime_pm.c b/drivers/gpu/drm/i915/intel_runtime_pm.c
index 0d85f3c5c526..806c32ab410b 100644
--- a/drivers/gpu/drm/i915/intel_runtime_pm.c
+++ b/drivers/gpu/drm/i915/intel_runtime_pm.c
@@ -68,6 +68,9 @@ static noinline depot_stack_handle_t __save_depot_stack(void)
 static void init_intel_runtime_pm_wakeref(struct intel_runtime_pm *rpm)
 {
 	spin_lock_init(&rpm->debug.lock);
+
+	if (rpm->available)
+		stack_depot_init();
 }
 
 static noinline depot_stack_handle_t
diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index c34b55a6e554..60ba99a43745 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -15,6 +15,16 @@
 
 typedef u32 depot_stack_handle_t;
 
+/*
+ * Every user of stack depot has to call this during its own init when it's
+ * decided that it will be calling stack_depot_save() later.
+ *
+ * The alternative is to select STACKDEPOT_ALWAYS_INIT to have stack depot
+ * enabled as part of mm_init(), for subsystems where it's known at compile time
+ * that stack depot will be used.
+ */
+int stack_depot_init(void);
+
 depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 					unsigned int nr_entries,
 					gfp_t gfp_flags, bool can_alloc);
@@ -30,13 +40,4 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
 
 void stack_depot_print(depot_stack_handle_t stack);
 
-#ifdef CONFIG_STACKDEPOT
-int stack_depot_init(void);
-#else
-static inline int stack_depot_init(void)
-{
-	return 0;
-}
-#endif	/* CONFIG_STACKDEPOT */
-
 #endif
diff --git a/init/main.c b/init/main.c
index ee4d3e1b3eb9..b6a5833d98f5 100644
--- a/init/main.c
+++ b/init/main.c
@@ -844,7 +844,8 @@ static void __init mm_init(void)
 	init_mem_debugging_and_hardening();
 	kfence_alloc_pool();
 	report_meminit();
-	stack_depot_init();
+	if (IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT))
+		stack_depot_init();
 	mem_init();
 	mem_init_print_info();
 	/* page_owner must be initialized after buddy is ready */
diff --git a/lib/Kconfig b/lib/Kconfig
index 5e7165e6a346..df6bcf0a4cc3 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -671,6 +671,9 @@ config STACKDEPOT
 	bool
 	select STACKTRACE
 
+config STACKDEPOT_ALWAYS_INIT
+	bool
+
 config STACK_HASH_ORDER
 	int "stack depot hash size (12 => 4KB, 20 => 1024KB)"
 	range 12 20
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cdc842d090db..695deb603c66 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -39,6 +39,7 @@ menuconfig KASAN
 		   HAVE_ARCH_KASAN_HW_TAGS
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
 	select STACKDEPOT
+	select STACKDEPOT_ALWAYS_INIT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index b437ae79aca1..a4f449ccd0dc 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -23,6 +23,7 @@
 #include <linux/jhash.h>
 #include <linux/kernel.h>
 #include <linux/mm.h>
+#include <linux/mutex.h>
 #include <linux/percpu.h>
 #include <linux/printk.h>
 #include <linux/slab.h>
@@ -145,6 +146,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 #define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
 #define STACK_HASH_SEED 0x9747b28c
 
+DEFINE_MUTEX(stack_depot_init_mutex);
 static bool stack_depot_disable;
 static struct stack_record **stack_table;
 
@@ -161,18 +163,38 @@ static int __init is_stack_depot_disabled(char *str)
 }
 early_param("stack_depot_disable", is_stack_depot_disabled);
 
-int __init stack_depot_init(void)
+/*
+ * __ref because of memblock_alloc(), which will not be actually called after
+ * the __init code is gone
+ */
+__ref int stack_depot_init(void)
 {
-	if (!stack_depot_disable) {
+	mutex_lock(&stack_depot_init_mutex);
+	if (!stack_depot_disable && stack_table == NULL) {
 		size_t size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
 		int i;
 
-		stack_table = memblock_alloc(size, size);
-		for (i = 0; i < STACK_HASH_SIZE;  i++)
-			stack_table[i] = NULL;
+		if (slab_is_available()) {
+			pr_info("Stack Depot allocating hash table with kvmalloc\n");
+			stack_table = kvmalloc(size, GFP_KERNEL);
+		} else {
+			pr_info("Stack Depot allocating hash table with memblock_alloc\n");
+			stack_table = memblock_alloc(size, SMP_CACHE_BYTES);
+		}
+		if (stack_table) {
+			for (i = 0; i < STACK_HASH_SIZE;  i++)
+				stack_table[i] = NULL;
+		} else {
+			pr_err("Stack Depot failed hash table allocationg, disabling\n");
+			stack_depot_disable = true;
+			mutex_unlock(&stack_depot_init_mutex);
+			return -ENOMEM;
+		}
 	}
+	mutex_unlock(&stack_depot_init_mutex);
 	return 0;
 }
+EXPORT_SYMBOL_GPL(stack_depot_init);
 
 /* Calculate hash for a stack */
 static inline u32 hash_stack(unsigned long *entries, unsigned int size)
diff --git a/mm/page_owner.c b/mm/page_owner.c
index a83f546c06b5..a48607b51a97 100644
--- a/mm/page_owner.c
+++ b/mm/page_owner.c
@@ -80,6 +80,8 @@ static void init_page_owner(void)
 	if (!page_owner_enabled)
 		return;
 
+	stack_depot_init();
+
 	register_dummy_stack();
 	register_failure_stack();
 	register_early_stack();
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211007095815.3563-1-vbabka%40suse.cz.
