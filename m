Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBBEWTKFQMGQE7EVEQEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0481342B91C
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 09:30:13 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id u17-20020a05651206d100b003fd714d9a38sf1312669lff.8
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 00:30:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634110212; cv=pass;
        d=google.com; s=arc-20160816;
        b=X+YaUfB9Jwnk4HaSii7llz3vFMhX3sOvjeMMkKM9H3FroS51X2G6OVWNaSUxoGeBNE
         URgH+DQostu2PzbjAZwuGqkZgZojDQjP63C6mSgW7VKrhpR6V8APY1fYAi/ruVF8QhjK
         wBj/sGbJwcYl1P9T4QXvy9KZ75dg/Key6wqL9olQaVLInK5iyZPkRZMR5763TusfywOz
         4a24wLaw88UMrtKjzfQ76xgpyu07YATuV089LGY0Sto7nuwskhv7U7txNQCVoncLL5hz
         B5qlxxyKXSGMehcosGkRNyjmRqSxebJUhiPUojRn1LyM80jtM3QV23+J5rsYiMO/AJ3e
         5V8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4SsGPyfmk4kid4AxrgQ20bGmYVIEHWMWZPy+Pg3i1B4=;
        b=yh5Zr12ytjQuMTmU7Bm0poSir8coRiy7dMa8PeLAHHOW8h4AiJDVqRspxn0EfFulfk
         MXCaD6avVCw3+8k5kwl1RpdkwH/obF9PXmB5zq2X2km5oiRkXPHJk9aoYZS+nIRYcYQ4
         JKGZ44RFgblwhzqVIuEngSAyIY+xlSl8twMfI7WZJcVVdgZJnl6ct7vD+M3epgF029QB
         oDeSIfPmpRMkMbyi++hfTK+kLNaTS5rjEC/GLq75S57DqtTuwcqH7hiltDoGOHLOi9Ze
         eNmHW/9IsChF0pGmvckPTaTjaynskh6/rtdBrndLfYTyFOk3jD8Vl0f8ozv1U5BKIOww
         9jZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uITKLYCJ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4SsGPyfmk4kid4AxrgQ20bGmYVIEHWMWZPy+Pg3i1B4=;
        b=biU/OGjd3A2mlBvnT/cZlqYIrn8zLMm5HSNFVU9kQgUB3+8BYEOkONC0MKs2hxL3Nv
         U2v9PxZipET9kmWUF1WlUoI7vxKiuo5Ffbs/GbQFaLFsGDL/ZptRsUONWiSBYe180i4N
         o6Qja1IilCCIj8oSQ6pwddvhZp54vIRo0/swKExrW6CV9XaRq0pB+QoysUVRQqET7iB+
         4dPpfq7ZBHQQkIR3lzx44fu37mj21aYFP/fvI05z+92cu+RIlZrqPBTFcKwOipE8eItm
         9g1DAjVzL2ANrryQPaT0mlnvVLFehivtVds0zHHgQy4swvrLA3pmxkQuuifNYwmCwj+C
         LtPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4SsGPyfmk4kid4AxrgQ20bGmYVIEHWMWZPy+Pg3i1B4=;
        b=1TpiihRZQRtZGHLwPr3w2rrNQsXR/A81gu5ybbABW1fJ4+xy7cN2k6LXQiLWo/1Agm
         unaNBAbjfVvKp4rGhj4EfWDzbL/osajwyx/qVgbDiF0nYK79FRFhekYAdKL7lfNCYEYU
         g1Dh1BIvFL9wHlqYftQkAmG0zy1ohzup/wqtwW/PONy1DZYY9YxGet+r3Tk5KznqD1LD
         ElGauBuH79puUtTtvQ768i2R8I2LcSsF6ei5A5MP0OkNsjAfUwP6ta2fgS+6tenT3xSV
         7YrDL2XSwkRwqq2MBGG/wYqaN9tkZ2FvC3m+peT1sL8CiZRkxQcUUqkOm13K+7X3KvUv
         aP/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313hxx9vl0nurojPeMRH2z/kNiw+58/vSclYz/8wtnpj8E9Bl1E
	rX1D6Grbwfm7/aIEyJ6dQl0=
X-Google-Smtp-Source: ABdhPJziE0Sj9fJLMqSBZsocJkiKqR0lh3X64GaNGszDOcOAbZloS/lq/f/WXQHgeKVx//9arYv9oA==
X-Received: by 2002:a19:dc59:: with SMTP id f25mr40663854lfj.414.1634110212508;
        Wed, 13 Oct 2021 00:30:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:982:: with SMTP id b2ls227406ljq.7.gmail; Wed, 13
 Oct 2021 00:30:11 -0700 (PDT)
X-Received: by 2002:a05:651c:1549:: with SMTP id y9mr35306291ljp.105.1634110211293;
        Wed, 13 Oct 2021 00:30:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634110211; cv=none;
        d=google.com; s=arc-20160816;
        b=0o0qFvkdlQKLnbhET9REsB9SSmeSPVNC7OOQTtIWbe5s9eDHBYqrKw/mfLioQZOICN
         Dmq6fJTaLPhrR+lPY31XbfQnxzV1oRDEr61HkXY1+8JvBEzUHKOpUuz7vN+tGAt29bZ4
         KM+tAXXtN+Hy3sGBp4z654YC3jaLIdxg0AStNSRQSh+O7Ma/0MNuntf+mQHbWTgcJUIP
         BLs/2ZICXY7sjzPrjQ+vIc590hP+6BLIM1mnK6Njnv12tDd8Xt/tfPf5hMjZgsach3ce
         Le2BNauwoxeG5vHsTwAj+DFTB5MEHz9tVGU5NnkBdP5l9DKzpTK6cAE50bAiFeFDWIGR
         AnHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=vRq42N1XLsyLwSLUiEBzWgw9ErM7r3K5wCbitSDHSyo=;
        b=f+0S1Sepk3IC6juhd0mCL8B7lHYaapYBLuO5S7bBr0pqx0x0atU3aywfUQ55s8GUT0
         IoPwR1SQAF1iLezB22rwSZIH7oyOZGCeZ1OoG1EyfCx1hY0TD+xXsihIaAMkHgz0bRY2
         T5JWhWk70KNnImaj9KEEPEndALCwG/33eshqeKl2xRWA5H2BMZQVGehp4LileGacBfT1
         Edm45l1X05Yw+A1Yj9mySEhCUQ91Y/t8RAYZDSNMRNdDaCVY6CGce9s2wDdnrtGiZTnv
         VvozkD5+QFr2hflY6YAx7EK30u3PgoGWnbug91e6myjRU2W91B1pUzGUSMU7I/3/ql2P
         eAMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=uITKLYCJ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id t20si704727lfg.12.2021.10.13.00.30.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Oct 2021 00:30:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 823121FF8D;
	Wed, 13 Oct 2021 07:30:10 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3B53F13CBE;
	Wed, 13 Oct 2021 07:30:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id o9nIDQKLZmEjdQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 13 Oct 2021 07:30:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	Vlastimil Babka <vbabka@suse.cz>,
	Dmitry Vyukov <dvyukov@google.com>,
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
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Oliver Glitta <glittao@gmail.com>,
	Imran Khan <imran.f.khan@oracle.com>
Subject: [PATCH v3] lib/stackdepot: allow optional init and stack_table allocation by kvmalloc()
Date: Wed, 13 Oct 2021 09:30:05 +0200
Message-Id: <20211013073005.11351-1-vbabka@suse.cz>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20211012090621.1357-1-vbabka@suse.cz>
References: <20211012090621.1357-1-vbabka@suse.cz>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=9908; h=from:subject; bh=qKzKhI1AHwrSrbWvBiUMgXVjAfkBM20Gt+RN+iz94ug=; b=owEBbQGS/pANAwAIAeAhynPxiakQAcsmYgBhZoroX1oZ3COYXA1v5xFy/NEofHOjrYXATAI9XEsE ivh3F/WJATMEAAEIAB0WIQSNS5MBqTXjGL5IXszgIcpz8YmpEAUCYWaK6AAKCRDgIcpz8YmpEJkuB/ 9KmtN5+EN4UjZv6tC5JHtuFlHLHtEvMlkdwvWywlhDC5BS/Or4lo/jwhGdNMWOwfhnBH49WvvmMzH/ jk0Q2WYFgNyuaKA9qvUjOrCh+DfViHv80nF0A1gg+By/bXouEGZ7PbnZsQZMj0zKSdllS/wF/kf+mO j/KB+Jb6V4WXCmZefZsJoX45s9rS5ghpucsMwODS9xjYPIW+MDpF0RWy5fiPCoo7fy142xzxbmoDIw uKxHcFdNuhDlvgq7xmDn9cQDnGA2A6Z5ZkVSPV7xZlKdaVB53vfAZQtbQcW2Lm+OlLPFdu6E1OBXfW ID4CN2f5u8b5cP80r8K/cI2Y3wnd90
X-Developer-Key: i=vbabka@suse.cz; a=openpgp; fpr=A940D434992C2E8E99103D50224FA7E7CC82A664
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=uITKLYCJ;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
and thus the memory might be wasted. This was raised as an issue [1] when
attempting to add stackdepot support for SLUB's debug object tracking
functionality. It's common to build kernels with CONFIG_SLUB_DEBUG and enable
slub_debug on boot only when needed, or create only specific kmem caches with
debugging for testing purposes.

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
Acked-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com> # stackdepot
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
Changes in v3:
- stack_depot_init_mutex made static and moved inside stack_depot_init()
  Reported-by: kernel test robot <lkp@intel.com>
- use !stack_table condition instead of stack_table == NULL
  reported by checkpatch on freedesktop.org patchwork
 drivers/gpu/drm/drm_dp_mst_topology.c   |  1 +
 drivers/gpu/drm/drm_mm.c                |  4 +++
 drivers/gpu/drm/i915/intel_runtime_pm.c |  3 +++
 include/linux/stackdepot.h              | 25 ++++++++++++-------
 init/main.c                             |  2 +-
 lib/Kconfig                             |  4 +++
 lib/Kconfig.kasan                       |  2 +-
 lib/stackdepot.c                        | 33 +++++++++++++++++++++----
 mm/page_owner.c                         |  2 ++
 9 files changed, 60 insertions(+), 16 deletions(-)

diff --git a/drivers/gpu/drm/drm_dp_mst_topology.c b/drivers/gpu/drm/drm_dp_mst_topology.c
index 86d13d6bc463..b0ebdc843a00 100644
--- a/drivers/gpu/drm/drm_dp_mst_topology.c
+++ b/drivers/gpu/drm/drm_dp_mst_topology.c
@@ -5493,6 +5493,7 @@ int drm_dp_mst_topology_mgr_init(struct drm_dp_mst_topology_mgr *mgr,
 	mutex_init(&mgr->probe_lock);
 #if IS_ENABLED(CONFIG_DRM_DEBUG_DP_MST_TOPOLOGY_REFS)
 	mutex_init(&mgr->topology_ref_history_lock);
+	stack_depot_init();
 #endif
 	INIT_LIST_HEAD(&mgr->tx_msg_downq);
 	INIT_LIST_HEAD(&mgr->destroy_port_list);
diff --git a/drivers/gpu/drm/drm_mm.c b/drivers/gpu/drm/drm_mm.c
index 93d48a6f04ab..5916228ea0c9 100644
--- a/drivers/gpu/drm/drm_mm.c
+++ b/drivers/gpu/drm/drm_mm.c
@@ -983,6 +983,10 @@ void drm_mm_init(struct drm_mm *mm, u64 start, u64 size)
 	add_hole(&mm->head_node);
 
 	mm->scan_active = 0;
+
+#ifdef CONFIG_DRM_DEBUG_MM
+	stack_depot_init();
+#endif
 }
 EXPORT_SYMBOL(drm_mm_init);
 
diff --git a/drivers/gpu/drm/i915/intel_runtime_pm.c b/drivers/gpu/drm/i915/intel_runtime_pm.c
index eaf7688f517d..d083506986e1 100644
--- a/drivers/gpu/drm/i915/intel_runtime_pm.c
+++ b/drivers/gpu/drm/i915/intel_runtime_pm.c
@@ -78,6 +78,9 @@ static void __print_depot_stack(depot_stack_handle_t stack,
 static void init_intel_runtime_pm_wakeref(struct intel_runtime_pm *rpm)
 {
 	spin_lock_init(&rpm->debug.lock);
+
+	if (rpm->available)
+		stack_depot_init();
 }
 
 static noinline depot_stack_handle_t
diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 6bb4bc1a5f54..40fc5e92194f 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -13,6 +13,22 @@
 
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
+#ifdef CONFIG_STACKDEPOT_ALWAYS_INIT
+static inline int stack_depot_early_init(void)	{ return stack_depot_init(); }
+#else
+static inline int stack_depot_early_init(void)	{ return 0; }
+#endif
+
 depot_stack_handle_t stack_depot_save(unsigned long *entries,
 				      unsigned int nr_entries, gfp_t gfp_flags);
 
@@ -21,13 +37,4 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 
 unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries);
 
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
index 81a79a77db46..ca2765c8e45c 100644
--- a/init/main.c
+++ b/init/main.c
@@ -842,7 +842,7 @@ static void __init mm_init(void)
 	init_mem_debugging_and_hardening();
 	kfence_alloc_pool();
 	report_meminit();
-	stack_depot_init();
+	stack_depot_early_init();
 	mem_init();
 	mem_init_print_info();
 	/* page_owner must be initialized after buddy is ready */
diff --git a/lib/Kconfig b/lib/Kconfig
index 5e7165e6a346..9d0569084152 100644
--- a/lib/Kconfig
+++ b/lib/Kconfig
@@ -671,6 +671,10 @@ config STACKDEPOT
 	bool
 	select STACKTRACE
 
+config STACKDEPOT_ALWAYS_INIT
+	bool
+	select STACKDEPOT
+
 config STACK_HASH_ORDER
 	int "stack depot hash size (12 => 4KB, 20 => 1024KB)"
 	range 12 20
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index cdc842d090db..879757b6dd14 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -38,7 +38,7 @@ menuconfig KASAN
 		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
 		   HAVE_ARCH_KASAN_HW_TAGS
 	depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
-	select STACKDEPOT
+	select STACKDEPOT_ALWAYS_INIT
 	help
 	  Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
 	  designed to find out-of-bounds accesses and use-after-free bugs.
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0a2e417f83cb..049d7d025d78 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -24,6 +24,7 @@
 #include <linux/jhash.h>
 #include <linux/kernel.h>
 #include <linux/mm.h>
+#include <linux/mutex.h>
 #include <linux/percpu.h>
 #include <linux/printk.h>
 #include <linux/slab.h>
@@ -162,18 +163,40 @@ static int __init is_stack_depot_disabled(char *str)
 }
 early_param("stack_depot_disable", is_stack_depot_disabled);
 
-int __init stack_depot_init(void)
+/*
+ * __ref because of memblock_alloc(), which will not be actually called after
+ * the __init code is gone, because at that point slab_is_available() is true
+ */
+__ref int stack_depot_init(void)
 {
-	if (!stack_depot_disable) {
+	static DEFINE_MUTEX(stack_depot_init_mutex);
+
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
index 62402d22539b..16a0ef903384 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211013073005.11351-1-vbabka%40suse.cz.
