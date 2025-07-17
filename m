Return-Path: <kasan-dev+bncBDAOJ6534YNBBBUR4TBQMGQEB245YGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id CCCFAB08F4A
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:28:23 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-456013b59c1sf5887265e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:28:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762503; cv=pass;
        d=google.com; s=arc-20240605;
        b=RJ93HsLs2vZbEOQ25Sdhd7W56VVzXRVelgz/lqEP1inWi+QTKmCAEd2vpXomtBKICe
         axiwGhaAWP+lxEgHdDOKwSJ/D4MVLnR437cgvdgBAH7EQ/dXp7bYCcSFxwE8BXth9dsI
         nVOzFcsI0JJPEgB6jeIGBBAXDq9eJtwxQb74IvM8Top2SurSz7AzJ/K12BXF7XXlqT7H
         qpOzenzRoyzcXsoqA7Ho+ZMzK6/4+4SsIx8OdroDNTb8E1D52JIagrs5wvo8mwm9iQqJ
         s+fmwX15ZHl2HM7Y2Bvp8sbePAiZNdlxZRcSd+2ZutUf3e3R34WHbh7Y3Je1kzvghBDU
         +hLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=epQhGA/wPk3hHs8WRsyTQKarqm9raq0L0zJPL/j9YA4=;
        fh=0HGm+NNi5lsqmEux7CNXWoIyfyxhcArDylRf6v/LHII=;
        b=DAYDjjSw0cBsIPtN7Xo3/qQoWQ/M7X+CN05fhN1CKdbk/uhprsNxsPrRxrQbIjoGL9
         lvYP4PQYWi/JVvUfbNjd0RFGSB15MiP92l25AnVYySkkvEHch+D5Z9fHyK9hQ96r6SVn
         7h2/9VkpY5CzbMbwNGCme6krOnLhoHexY2hHRsiutcULTFH3ygOO5Lctu/gwDz8vr1t+
         QTBb86ywRKXDhQxhYbxkbCGpDlxdMTR0i1BNXbqr/ti4nmEH/+8ROnlW59UeYA9MzulD
         GqwrvVV3f6xLVl6ePTzoNNRUXuDHNIc/PNlMFiHZr6bHOCCU/qUZnBQH5SiyASQ+p3hE
         q4dg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CYrWlQde;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762503; x=1753367303; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=epQhGA/wPk3hHs8WRsyTQKarqm9raq0L0zJPL/j9YA4=;
        b=brkaAYMI2E9eAU9C3mHUFC/tSg5jZsLS65NXuXAz1pYol0XSs+/q4KMgxixjnbFbqG
         qN072FVXK2RZz/jknf7k9edVifZkzjscbZ2UUC5QxZKiy2MYj3Tx0k7A5cHwZYBM5wyW
         2IAlV96GNsBxdHl8FhWFpoa3uygEq/mZZ07afyOcYBSe4b2GEk4ztIVTYiQbO9vDACc8
         WhDy4OMLCmZ599zqF4oa2IiT+MfWnHPjfnxugdkiNiRKFuF6/yHS7sC8yLOxXQ+QXdw4
         ueYotTc+2tVwjSqC1ORp2woHsTpLnHuaM5gZUnDDo5p2bHFRaezb3m2UdKReTVtKrXd7
         F40Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762503; x=1753367303; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=epQhGA/wPk3hHs8WRsyTQKarqm9raq0L0zJPL/j9YA4=;
        b=kZTo0CN6eF4oI4InOfslQTfV0PY+HShPioun+l92coZjn1LfFx5Hd5JViRCYK97jqe
         Zf4KZFCgXpnj2f5dK8LUlf0ObDNXgwVoUmEW4TAzB+fXg1PzpT1Nj8xgjniFk8t1shhE
         y/wr+QSrlX0BQNGSR8QvPSoAXnkfuf814PjJfmsvfddeSSnxyA3ye98tLmCdwi/IZcUp
         cJmylemNWxxGGvxgbSoLDDcPOPntLR0oUTs5arEDJIZKwmVYWzgs/YUyRCknBzm+XarQ
         t1waxJ8YY+QocNPpx5wUk7P00vneecKVIVrCwpybDJTFFNbbfUMgRATc7kfMnjF5rq5P
         FiWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762503; x=1753367303;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=epQhGA/wPk3hHs8WRsyTQKarqm9raq0L0zJPL/j9YA4=;
        b=jigfIB22Q+QaFVlT6C2ZElShYNLeOpngq/C7p/bDejEwG0b+qfDhNeEhuUEBJiHmSB
         ywppFUvlOz4S8XgaFNYp7ue5qPOQYeCT29Mmgx3f31rY6lxrLJS2DBsb+t1kQNjSs6Fy
         w7o022Gf+6CcGOGVjRAc9rvLD7elCrPFSVBjw063xpToq1UDpnK4IpOPUJ0fO/J83o8U
         ckj/yZWZdGy9Dji7D05C/4UhsKtACYXvhajWxumQVs46XugfSLK2SADqgqjvz9D1E8tm
         O+VLRgVJTseYQSXvjwQq3+rbn2D0OiJJODXs5Y0JvoQjCxSO6+2eQ0H/fcMNmlUIXH35
         xcsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUUGYdInCWEwTdbHW53fIQss+AdWPFf9RZDu/4mdrxOH7MQUgnglkQ6bzQsFKixdaH1SXB8ug==@lfdr.de
X-Gm-Message-State: AOJu0YxWlyHkKUFeJdufbQ41IPNHaTNeQ5tNrh5bqxf+ErmsIKwaSNhV
	NE40O9G3EAEH/iePrI+TgRIuV3ycvA7LCi/dcLzB7a7OU+ditHZETBcS
X-Google-Smtp-Source: AGHT+IG8nSryPBwGiVO+XBBf3QNY7eBX2PuYHG/rvub1UDEx7NXKlzQWyJjLnMnaQVZ3kvUI/Wn1BA==
X-Received: by 2002:a05:600c:a010:b0:453:6ca:16b1 with SMTP id 5b1f17b1804b1-45633d37a00mr32437965e9.26.1752762503114;
        Thu, 17 Jul 2025 07:28:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdavsw12J772VvAPA3aofa/6fAfr2EKdCGrqD3Ke69izQ==
Received: by 2002:a05:600c:4e4a:b0:456:136f:d41f with SMTP id
 5b1f17b1804b1-45637a13d6els3442975e9.1.-pod-prod-07-eu; Thu, 17 Jul 2025
 07:28:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXa2yYiFdwv9f8bYZY4QU3HB7k8/+N4cvMitAKpNuxV+X+zH5gvUEJ2Chw2P970xGoXggASEVKbvNA=@googlegroups.com
X-Received: by 2002:a05:600c:4709:b0:456:f1e:205c with SMTP id 5b1f17b1804b1-4562e32e598mr64696185e9.4.1752762500409;
        Thu, 17 Jul 2025 07:28:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762500; cv=none;
        d=google.com; s=arc-20240605;
        b=lWcNxrMOFQ8w7+qBt6D2qljvC57Or0jYoOv5VFLgVPS845ZxFdeXL6XtKi1d7qMkfx
         Ps3DMpdJ3bgxnr5IOUQg5uRY5XpL1Z7qWCqbyT9kjqQlRkBA7lf9ZKFUgnjLU5XxAuyv
         4CefHcJiUiFkUwWDGA6yXaCiXZXd0MwxwFVE7qnYOXMJYOTLcg2T7PUsbNWK2tmLZLUl
         DbVmhefX/usMAQMYUF2VFWXuF7pyqd0tHexZ1sXvXBnc+4McJ2eUX5hgyZfpL2Sgz/62
         6zjRyk/3AovI3nkhf7j3OrKKMv6vVAKjsgOQ2dfau0NgNtdWOYEr1a0t4jY9CwpHtHD8
         gS8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=f7ZdWtvjGwx1QVMejTFRuKlxOMwOJa4SlH8rLzpLr/Q=;
        fh=bUmiiAR7tJpmAksVH4P2Vcl1vYU3piIRqXeMfjkEctk=;
        b=ejAE6t0syiIK+K/moVkgCXTBgww2zbmSxiH7jyDA3TuAMZEoRB4Jx8z5I3oFBP2836
         iQ330RHYMtyaf6Cr7X+tFYtKUGeW5X20hIv7YZ0oYmO45wxi3ugW7dHifX7MtpwnpgbM
         Qd6b5wDWM2Z0UMlERGZPcoXUJ/FRaxDPCKoLrsRLGll1JU8BGwfR4yij+Myq+MtSjYRi
         HKjqnTGOrK3Mb4VqEoE9jFQVsMX7iRZWoHd3KyFdWAW3b/uIO6BwnILoeOfTiNp/+Wdq
         VczKySw/a3q+id/TmmuifFrbTquwbFt2QidR2AHSX5SrtBT4OVt6RVZuK0g4WUGCf2JC
         SwGw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CYrWlQde;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45626c7b1dbsi2115585e9.0.2025.07.17.07.28.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:28:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id 2adb3069b0e04-55a2604ebc1so1000776e87.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:28:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUDFJV2mw/xJ+wl3WalGgEPCoeZLSGl62cJ5EB9yhwjbOytDUXSFsUfiAWTJ3evLjOxQIZ3ugkFOqs=@googlegroups.com
X-Gm-Gg: ASbGnctLb4gYBdfHc427MLQ1dw3ptN1YJRetxxbKpeyi6LnNi8+Zr9azjsCKRkGBmSg
	k7AvJ6l5rkPnpEoKZGlOVBoCE2W8OO5bDnxw9/GrDTK8m4OuPKjiZKVPToyBLMMpc9ki8pSlKUH
	q2pWXwFBk18edmuYAv0H243Wv4YfWs3my3pCjtxPs7LHMhzHs4mb8Jz3pTv/G/WKDj3GlJOteE9
	FnTAQZlT4MCXgj0f2JGVub2I2FxNpB3mNQ3s4cfbagj0fePOjE9/rY3+Zj5bwXvLhr4Nym8+XPC
	iCNiomEReTtXHsJsCWXIVBdegETjHVJg2Omm1pqMwTCQtCRJa14A3t5iv/MkfW0G7JXGSy4mlns
	jkgNF+IS9ExadwCnm5y3IBK924K+SkK3VKhy726lOLEEK9WbeEP4A4mMOMdRsVLPEjD5y
X-Received: by 2002:a05:6512:2345:b0:558:f7fc:87c4 with SMTP id 2adb3069b0e04-55a23f7fc98mr2461079e87.32.1752762499563;
        Thu, 17 Jul 2025 07:28:19 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.28.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:28:18 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 12/12] kasan: add shadow checks to wrappers and rename kasan_arch_is_ready
Date: Thu, 17 Jul 2025 19:27:32 +0500
Message-Id: <20250717142732.292822-13-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CYrWlQde;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This patch completes:
1. Adding kasan_shadow_initialized() checks to existing wrapper functions
2. Replacing kasan_arch_is_ready() calls with kasan_shadow_initialized()
3. Creating wrapper functions for internal functions that need shadow
   readiness checks
4. Removing the kasan_arch_is_ready() fallback definition

The two-level approach is now fully implemented:
- kasan_enabled() - controls whether KASAN is enabled at all.
  (compile-time for most archs)
- kasan_shadow_initialized() - tracks shadow memory initialization
  (static key for ARCH_DEFER_KASAN archs, compile-time for others)

This provides complete elimination of kasan_arch_is_ready() calls from
KASAN implementation while moving all shadow readiness logic to
wrapper functions.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v3:
- Addresses Andrey's feedback to move shadow checks to wrappers
- Rename kasan_arch_is_ready with kasan_shadow_initialized
- Added kasan_shadow_initialized() checks to all necessary wrapper functions
- Eliminated all remaining kasan_arch_is_ready() usage per reviewer guidance
---
 include/linux/kasan.h | 36 +++++++++++++++++++++++++++---------
 mm/kasan/common.c     |  9 +++------
 mm/kasan/generic.c    | 12 +++---------
 mm/kasan/kasan.h      | 36 ++++++++++++++++++++++++++----------
 mm/kasan/shadow.c     | 32 +++++++-------------------------
 5 files changed, 66 insertions(+), 59 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 51a8293d1af..292bd741d8d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -194,7 +194,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *s, void *object,
 static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
 						void *object)
 {
-	if (kasan_enabled())
+	if (kasan_enabled() && kasan_shadow_initialized())
 		return __kasan_slab_pre_free(s, object, _RET_IP_);
 	return false;
 }
@@ -229,7 +229,7 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s,
 						void *object, bool init,
 						bool still_accessible)
 {
-	if (kasan_enabled())
+	if (kasan_enabled() && kasan_shadow_initialized())
 		return __kasan_slab_free(s, object, init, still_accessible);
 	return false;
 }
@@ -237,7 +237,7 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s,
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static __always_inline void kasan_kfree_large(void *ptr)
 {
-	if (kasan_enabled())
+	if (kasan_enabled() && kasan_shadow_initialized())
 		__kasan_kfree_large(ptr, _RET_IP_);
 }
 
@@ -302,7 +302,7 @@ bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
 static __always_inline bool kasan_mempool_poison_pages(struct page *page,
 						       unsigned int order)
 {
-	if (kasan_enabled())
+	if (kasan_enabled() && kasan_shadow_initialized())
 		return __kasan_mempool_poison_pages(page, order, _RET_IP_);
 	return true;
 }
@@ -356,7 +356,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
  */
 static __always_inline bool kasan_mempool_poison_object(void *ptr)
 {
-	if (kasan_enabled())
+	if (kasan_enabled() && kasan_shadow_initialized())
 		return __kasan_mempool_poison_object(ptr, _RET_IP_);
 	return true;
 }
@@ -568,11 +568,29 @@ static inline void kasan_init_hw_tags(void) { }
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
-int kasan_populate_vmalloc(unsigned long addr, unsigned long size);
-void kasan_release_vmalloc(unsigned long start, unsigned long end,
+
+int __kasan_populate_vmalloc(unsigned long addr, unsigned long size);
+static inline int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
+{
+	if (!kasan_shadow_initialized())
+		return 0;
+	return __kasan_populate_vmalloc(addr, size);
+}
+
+void __kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end,
 			   unsigned long flags);
+static inline void kasan_release_vmalloc(unsigned long start,
+			   unsigned long end,
+			   unsigned long free_region_start,
+			   unsigned long free_region_end,
+			   unsigned long flags)
+{
+	if (kasan_shadow_initialized())
+		__kasan_release_vmalloc(start, end, free_region_start,
+			   free_region_end, flags);
+}
 
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
@@ -598,7 +616,7 @@ static __always_inline void *kasan_unpoison_vmalloc(const void *start,
 						unsigned long size,
 						kasan_vmalloc_flags_t flags)
 {
-	if (kasan_enabled())
+	if (kasan_enabled() && kasan_shadow_initialized())
 		return __kasan_unpoison_vmalloc(start, size, flags);
 	return (void *)start;
 }
@@ -607,7 +625,7 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size);
 static __always_inline void kasan_poison_vmalloc(const void *start,
 						 unsigned long size)
 {
-	if (kasan_enabled())
+	if (kasan_enabled() && kasan_shadow_initialized())
 		__kasan_poison_vmalloc(start, size);
 }
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index c3a6446404d..b561734767d 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -259,7 +259,7 @@ static inline void poison_slab_object(struct kmem_cache *cache, void *object,
 bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 				unsigned long ip)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (is_kfence_address(object))
 		return false;
 	return check_slab_allocation(cache, object, ip);
 }
@@ -267,7 +267,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
 bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 		       bool still_accessible)
 {
-	if (!kasan_arch_is_ready() || is_kfence_address(object))
+	if (is_kfence_address(object))
 		return false;
 
 	poison_slab_object(cache, object, init, still_accessible);
@@ -291,9 +291,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
 
 static inline bool check_page_allocation(void *ptr, unsigned long ip)
 {
-	if (!kasan_arch_is_ready())
-		return false;
-
 	if (ptr != page_address(virt_to_head_page(ptr))) {
 		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
 		return true;
@@ -520,7 +517,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 		return true;
 	}
 
-	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
+	if (is_kfence_address(ptr))
 		return true;
 
 	slab = folio_slab(folio);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 03b6d322ff6..1d20b925b9d 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -176,7 +176,7 @@ static __always_inline bool check_region_inline(const void *addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
-	if (!kasan_arch_is_ready())
+	if (!kasan_shadow_initialized())
 		return true;
 
 	if (unlikely(size == 0))
@@ -200,13 +200,10 @@ bool kasan_check_range(const void *addr, size_t size, bool write,
 	return check_region_inline(addr, size, write, ret_ip);
 }
 
-bool kasan_byte_accessible(const void *addr)
+bool __kasan_byte_accessible(const void *addr)
 {
 	s8 shadow_byte;
 
-	if (!kasan_arch_is_ready())
-		return true;
-
 	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
 
 	return shadow_byte >= 0 && shadow_byte < KASAN_GRANULE_SIZE;
@@ -506,9 +503,6 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
 
 static void release_free_meta(const void *object, struct kasan_free_meta *meta)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	/* Check if free meta is valid. */
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREE_META)
 		return;
@@ -573,7 +567,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 	kasan_save_track(&alloc_meta->alloc_track, flags);
 }
 
-void kasan_save_free_info(struct kmem_cache *cache, void *object)
+void __kasan_save_free_info(struct kmem_cache *cache, void *object)
 {
 	struct kasan_free_meta *free_meta;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e6..67a0a1095d2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -398,7 +398,13 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, depot_flags_t depot_flags);
 void kasan_set_track(struct kasan_track *track, depot_stack_handle_t stack);
 void kasan_save_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
-void kasan_save_free_info(struct kmem_cache *cache, void *object);
+
+void __kasan_save_free_info(struct kmem_cache *cache, void *object);
+static inline void kasan_save_free_info(struct kmem_cache *cache, void *object)
+{
+	if (kasan_enabled() && kasan_shadow_initialized())
+		__kasan_save_free_info(cache, object);
+}
 
 #ifdef CONFIG_KASAN_GENERIC
 bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
@@ -499,6 +505,7 @@ static inline bool kasan_byte_accessible(const void *addr)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
+void __kasan_poison(const void *addr, size_t size, u8 value, bool init);
 /**
  * kasan_poison - mark the memory range as inaccessible
  * @addr: range start address, must be aligned to KASAN_GRANULE_SIZE
@@ -506,7 +513,11 @@ static inline bool kasan_byte_accessible(const void *addr)
  * @value: value that's written to metadata for the range
  * @init: whether to initialize the memory range (only for hardware tag-based)
  */
-void kasan_poison(const void *addr, size_t size, u8 value, bool init);
+static inline void kasan_poison(const void *addr, size_t size, u8 value, bool init)
+{
+	if (kasan_shadow_initialized())
+		__kasan_poison(addr, size, value, init);
+}
 
 /**
  * kasan_unpoison - mark the memory range as accessible
@@ -521,12 +532,19 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init);
  */
 void kasan_unpoison(const void *addr, size_t size, bool init);
 
-bool kasan_byte_accessible(const void *addr);
+bool __kasan_byte_accessible(const void *addr);
+static inline bool kasan_byte_accessible(const void *addr)
+{
+	if (!kasan_shadow_initialized())
+		return true;
+	return __kasan_byte_accessible(addr);
+}
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #ifdef CONFIG_KASAN_GENERIC
 
+void __kasan_poison_last_granule(const void *address, size_t size);
 /**
  * kasan_poison_last_granule - mark the last granule of the memory range as
  * inaccessible
@@ -536,7 +554,11 @@ bool kasan_byte_accessible(const void *addr);
  * This function is only available for the generic mode, as it's the only mode
  * that has partially poisoned memory granules.
  */
-void kasan_poison_last_granule(const void *address, size_t size);
+static inline void kasan_poison_last_granule(const void *address, size_t size)
+{
+	if (kasan_shadow_initialized())
+		__kasan_poison_last_granule(address, size);
+}
 
 #else /* CONFIG_KASAN_GENERIC */
 
@@ -544,12 +566,6 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifndef kasan_arch_is_ready
-static inline bool kasan_arch_is_ready(void)	{ return true; }
-#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
-#error kasan_arch_is_ready only works in KASAN generic outline mode!
-#endif
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_kunit_test_suite_start(void);
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d2c70cd2afb..90c508cad63 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -121,13 +121,10 @@ void *__hwasan_memcpy(void *dest, const void *src, ssize_t len) __alias(__asan_m
 EXPORT_SYMBOL(__hwasan_memcpy);
 #endif
 
-void kasan_poison(const void *addr, size_t size, u8 value, bool init)
+void __kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
 	void *shadow_start, *shadow_end;
 
-	if (!kasan_arch_is_ready())
-		return;
-
 	/*
 	 * Perform shadow offset calculation based on untagged address, as
 	 * some of the callers (e.g. kasan_poison_new_object) pass tagged
@@ -145,14 +142,11 @@ void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
-EXPORT_SYMBOL_GPL(kasan_poison);
+EXPORT_SYMBOL_GPL(__kasan_poison);
 
 #ifdef CONFIG_KASAN_GENERIC
-void kasan_poison_last_granule(const void *addr, size_t size)
+void __kasan_poison_last_granule(const void *addr, size_t size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (size & KASAN_GRANULE_MASK) {
 		u8 *shadow = (u8 *)kasan_mem_to_shadow(addr + size);
 		*shadow = size & KASAN_GRANULE_MASK;
@@ -353,7 +347,7 @@ static int ___alloc_pages_bulk(struct page **pages, int nr_pages)
 	return 0;
 }
 
-static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
+static int __kasan_populate_vmalloc_do(unsigned long start, unsigned long end)
 {
 	unsigned long nr_pages, nr_total = PFN_UP(end - start);
 	struct vmalloc_populate_data data;
@@ -385,14 +379,11 @@ static int __kasan_populate_vmalloc(unsigned long start, unsigned long end)
 	return ret;
 }
 
-int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
+int __kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 {
 	unsigned long shadow_start, shadow_end;
 	int ret;
 
-	if (!kasan_arch_is_ready())
-		return 0;
-
 	if (!is_vmalloc_or_module_addr((void *)addr))
 		return 0;
 
@@ -414,7 +405,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
 	shadow_start = PAGE_ALIGN_DOWN(shadow_start);
 	shadow_end = PAGE_ALIGN(shadow_end);
 
-	ret = __kasan_populate_vmalloc(shadow_start, shadow_end);
+	ret = __kasan_populate_vmalloc_do(shadow_start, shadow_end);
 	if (ret)
 		return ret;
 
@@ -551,7 +542,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
  * pages entirely covered by the free region, we will not run in to any
  * trouble - any simultaneous allocations will be for disjoint regions.
  */
-void kasan_release_vmalloc(unsigned long start, unsigned long end,
+void __kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end,
 			   unsigned long flags)
@@ -560,9 +551,6 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	unsigned long region_start, region_end;
 	unsigned long size;
 
-	if (!kasan_arch_is_ready())
-		return;
-
 	region_start = ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
 	region_end = ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
 
@@ -611,9 +599,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored.
 	 */
 
-	if (!kasan_arch_is_ready())
-		return (void *)start;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
@@ -636,9 +621,6 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
  */
 void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
-	if (!kasan_arch_is_ready())
-		return;
-
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-13-snovitoll%40gmail.com.
