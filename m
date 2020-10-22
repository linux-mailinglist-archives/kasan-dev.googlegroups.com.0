Return-Path: <kasan-dev+bncBDX4HWEMTEBRB54NY36AKGQEV4RAY6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CE6B295FB4
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:52 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id k14sf621183wrd.6
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372792; cv=pass;
        d=google.com; s=arc-20160816;
        b=sO8zXXlljQTjaA/kMcHBfeSONHKsmC/wWArl2HkLC/HgzMKroM4IAh4l3QBf3aASPO
         tLHwuS/fxBCjXZ/6eBC/6z+YPT3mw2umQ6FulGho50PSWEvx6tZUlpbyNSaurHQnoRDd
         PeHYDLqxzcaId5WO0sukuaJ/fcMIWwnpEPYDX3Z4NkJ6+pMo45N8fYjdisNBP4acQ3OT
         DsufCDRlEKBDzGtO9eI74MjNDprjeLaReT7aXg2JsK19s7fxt4G264LVUx5KPdBMqIkT
         pC+2YJlnSQcMgpoLF6FPqRiU9XVsJ4r3aYyk8hCFfZWfVJv08yk/o3KMiPHCloIFoeDT
         BAQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=wneF8Zac/VEmt1y3HJNPxSRJCggmzZWxVeX4CBkbpzA=;
        b=FROABthXBx4pR8xtTBlfaa342o5MRKGvwes4hRm1gv43uIy3ypL9wy7sFQyv9fjMQ6
         Y+MxdPLgYUMOVNZuQCVuK73/zLy6POzINTWDL+Adio4iIOMHfsg+DIBTQkpbC8sUNnNd
         N9ky8YcFHdFG7bn2fw4m08Dhkub9u967kMvWwnLsoQiAcsK9ut8XtQ8N8DNYJpp1fwic
         ouiBRKf8gkxyhv5iHe+3WLBeCWG49SENFpclrnfe85CLKzoM1z+gRBrfp8NkMxQdsgw7
         FL8K8HnxpcBiXqbKX8Mb9GldbVOa3IsjACC0Udpd6L4sDMRi1ElFTmJnsOOTuX0Wd8sc
         vtfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g6JwnRNL;
       spf=pass (google.com: domain of 39oarxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=39oaRXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wneF8Zac/VEmt1y3HJNPxSRJCggmzZWxVeX4CBkbpzA=;
        b=mP4MsSWTO7OKGh4LTy78gx/cLpzQF4Xt4YfpE96hsjRSbBmrlGJYjXUyAB/hMyqcn+
         D5BPn845mewXCSDQitlyze/Y7ZtcQNHvoxy8Jx2q+shyAoU0yFMPIjquRaEQk1fYYX6a
         Aqk5kpxOkGyK1PXfZ5zPFpsfEr1B0pyfbVpAVGeFWSez6xEWa+MfX3oXfk2Qk+zTi8wA
         AbHR2eYz5No2wPaMJm6L3KtDwfZwppnAYisVMxIngus8mAAN4LYxKA9Q9UDR6aIjzCIP
         R8qfNuKnMs6HENUT+NFa8sbpZK7TlSzcF3vJ4AKXEsKTs0ylrftmy5FqxrX6OwWU+SNe
         Mg1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wneF8Zac/VEmt1y3HJNPxSRJCggmzZWxVeX4CBkbpzA=;
        b=bRY8qcWiqpCJ7wk6/bXcBnv7wJeLhrt+OOLeLKuwMmaA6BlRkQ20OoNafKT8jLXhbC
         XFSCQnnHuKBbvwhI6816bKEqLwBnm6IEyU1cPdrF0sNqgl5kggmzuDC5x1Sjik4SUOSn
         A6UMrobX8+xMtP5riqTX6fS9z3KQME+MPVRgdz02UazOpsu5GxN1f/vxCw+SKhl48H3/
         ykUu94v66h1sV4bgHejLI/g9a+1XzdQt2qKFOJKnm4UTmTEiFVBMIxaFLv95ik/PWchK
         rAgwWBzOTquok7r4uQJ0ldafVEjnHjcZf6S1kbzpMAsiSrF8bwmmmZYPwDrmiirjRSqN
         A0uA==
X-Gm-Message-State: AOAM53000C8PRlcTWof0cAmNLfR2C7O0DJIlrjImEU2pX663YkyyoJAY
	Lk/RVw9slxZFDm+UwY+mvAQ=
X-Google-Smtp-Source: ABdhPJwI6bUj7boe0LXanZ9QBzwgysedVAOopJ7RxTpw59huGTfnQKNu6PsBoZZOi5GMA7hE8kztCw==
X-Received: by 2002:a5d:46c1:: with SMTP id g1mr2811305wrs.101.1603372791985;
        Thu, 22 Oct 2020 06:19:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a544:: with SMTP id j4ls2406790wrb.3.gmail; Thu, 22 Oct
 2020 06:19:51 -0700 (PDT)
X-Received: by 2002:adf:cd82:: with SMTP id q2mr2900571wrj.118.1603372791157;
        Thu, 22 Oct 2020 06:19:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372791; cv=none;
        d=google.com; s=arc-20160816;
        b=PmEHkpqFDA0SR4M5Ejr6oP7n66POiSA5Ixuy/PggqEpErabNuOCUgAwZWEQ8W5vCLG
         RcetswC/COiokrjWj8zno3BgFRwpSAgp8UYF+T9CmRCk/24ITJ8W+j8Ju2jA1XjShkOe
         zaTf4PU4EluLF5vfSuIvD70bDEbn3JBWY06hRCmU2sgEM/Zq6BGeuplZEjnpmCcIMsM5
         g5zTUYXpYNMCCZkoCs7sdMHdUVJVMo2fahcg9tWPA5SP50gxZlAXxJGy9BOmH8ZWWRzD
         OVzaPRfirHHOBdzO8nP5F4t+IeK3jzVyEpvhM2IQevkRPdBGWFeUqmL1Kz5uVIjLGs6g
         Vkzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ZDpLws4WWjszeBZt7nTlIzp0p338D/8ILsPCgH/ymC0=;
        b=kSQPNpwruHKNP86hnwk3a08flPrd3pck11SnhYZ+yjz2SLId6bLm6ggF15rHPvlZQw
         w37XpCU9xQBbJ7kOqutCN0yKfS3MuksKr5C/DA5bS/dhhsJeanf/bEuFGr0LRN53kDRl
         PKAzkQHZUcCrMSa7tCphoQbNRjlXOCCYxUhmOsqJLWj1zMGY2JRh+QfQvrvJ4d27sJnm
         hoBonKjKCZBEnwi55Ou6quWuJsltIm9qdIHdHctKqqHBYmhJnjr8XavcMP8dTVBAoniX
         19oTu4oro93RQsbtd3t2Hf6/NaljoU47uzbs0B7Z78W8ndRarYEHj1wov9GsdLDllJjc
         2d/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g6JwnRNL;
       spf=pass (google.com: domain of 39oarxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=39oaRXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id j5si55336wro.2.2020.10.22.06.19.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39oarxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 28so665514edv.9
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:51 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a50:fb06:: with SMTP id
 d6mr2197662edq.312.1603372790776; Thu, 22 Oct 2020 06:19:50 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:03 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <a3cd7d83cc1f9ca06ef6d8c84e70f122212bf8ef.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 11/21] kasan: inline kasan_poison_memory and check_invalid_free
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g6JwnRNL;       spf=pass
 (google.com: domain of 39oarxwokcu0p2s6tdz2a0v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=39oaRXwoKCU0p2s6tDz2A0v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Using kasan_poison_memory() or check_invalid_free() currently results in
function calls. Move their definitions to mm/kasan/kasan.h and turn them
into static inline functions for hardware tag-based mode to avoid uneeded
function calls.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia9d8191024a12d1374675b3d27197f10193f50bb
---
 mm/kasan/hw_tags.c | 15 ---------------
 mm/kasan/kasan.h   | 28 ++++++++++++++++++++++++----
 2 files changed, 24 insertions(+), 19 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 4c24bfcfeff9..f03161f3da19 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -24,27 +24,12 @@ void __init kasan_init_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void kasan_poison_memory(const void *address, size_t size, u8 value)
-{
-	set_mem_tag_range(reset_tag(address),
-			  round_up(size, KASAN_GRANULE_SIZE), value);
-}
-
 void kasan_unpoison_memory(const void *address, size_t size)
 {
 	set_mem_tag_range(reset_tag(address),
 			  round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
-bool check_invalid_free(void *addr)
-{
-	u8 ptr_tag = get_tag(addr);
-	u8 mem_tag = get_mem_tag(addr);
-
-	return (mem_tag == KASAN_TAG_INVALID) ||
-		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
-}
-
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 94ba15c2f860..8d84ae6f58f1 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,8 +153,6 @@ struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 						const void *object);
 
-void kasan_poison_memory(const void *address, size_t size, u8 value);
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
@@ -194,8 +192,6 @@ void print_tags(u8 addr_tag, const void *addr);
 static inline void print_tags(u8 addr_tag, const void *addr) { }
 #endif
 
-bool check_invalid_free(void *addr);
-
 void *find_first_bad_addr(void *addr, size_t size);
 const char *get_bug_type(struct kasan_access_info *info);
 void metadata_fetch_row(char *buffer, void *row);
@@ -276,6 +272,30 @@ static inline u8 random_tag(void)
 }
 #endif
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+static inline void kasan_poison_memory(const void *address, size_t size, u8 value)
+{
+	set_mem_tag_range(reset_tag(address),
+			  round_up(size, KASAN_GRANULE_SIZE), value);
+}
+
+static inline bool check_invalid_free(void *addr)
+{
+	u8 ptr_tag = get_tag(addr);
+	u8 mem_tag = get_mem_tag(addr);
+
+	return (mem_tag == KASAN_TAG_INVALID) ||
+		(ptr_tag != KASAN_TAG_KERNEL && ptr_tag != mem_tag);
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
+void kasan_poison_memory(const void *address, size_t size, u8 value);
+bool check_invalid_free(void *addr);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 /*
  * Exported functions for interfaces called from assembly or from generated
  * code. Declarations here to avoid warning about missing declarations.
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3cd7d83cc1f9ca06ef6d8c84e70f122212bf8ef.1603372719.git.andreyknvl%40google.com.
