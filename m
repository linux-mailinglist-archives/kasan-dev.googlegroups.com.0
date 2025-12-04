Return-Path: <kasan-dev+bncBAABBQ5UY7EQMGQEMK3HSGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD43CA509B
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 20:00:23 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-29809acd049sf30382645ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 11:00:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764874822; cv=pass;
        d=google.com; s=arc-20240605;
        b=k3QxfvaXPfLpVeFGu8Hv27HZVCQ+cNTmqH1s/tJUWchRnUX1YUdzIhz27RKelDh+uM
         HZb446kf4zV/DWKFfbTrVFXcVP/52jjeN/V6A9/1zEwgUNPbvB0J0rPNK0TKEE4vgjez
         l+3W6w7w1Os1hmLcpqB5Dc8JCzwswQnzOopQfoqyUsWR1quFiSLzBaJRHATujJp3Te09
         f42J2MLN78wZGw1Rl9rYuZ5zqIcoJOZ/UGms1Vo8ViONANCNf2ENwseTF3IegMR53e14
         lkcopxkDg0zCjncyYk0BKu4abFdMBDYIiUUlseXTHdABJWRQs2TEoiVkB+lN9cz147nN
         93sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=dc+K/0BnkwzyRFtJrhHCBCHfHCsAjteyQg1fzlCoybw=;
        fh=nFAfg5qcnU8U/VHv1wrJ0JNbH69HJ/m5mZK6IFSY2zs=;
        b=RAZbXbEAY3pAP14YSl2xOpN9D5sEAP351vEwbbcGROkT7FLbj/b+pqf8umtI/QZIUd
         hekjYIa0AAXZB+Nl1yPUqGGCO3Wy2OKfQlCYlhrzNXJ9fcCMA3ABdsmik+tkyeEatB+N
         ze0NgnuKwv+Urvf1ezi6icUdxVAm0+HRbYxTfF/9iwcAl551DLI2LONuLBJnhIiLbKvp
         DF+o++nEBO71mfRb9WuFFSKCmVze9VPDLwBNDb8dMPsE1rVz+lji0e0+DtB+5UpiO474
         ai3v5DatR6pqihD+oLFvmdGYjjVh5FIgjLO5yvnZQFX4kW5tznF8z9SvWslenXEcfzPA
         CwyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=MGFUiyyI;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764874822; x=1765479622; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=dc+K/0BnkwzyRFtJrhHCBCHfHCsAjteyQg1fzlCoybw=;
        b=dBmsUUgfo6KhkidIRZnjUiwgJgmSco/2zkiZ+8r3UDN7YSpNWViQpxqytWdjMlWvw0
         koaA8Ludtzp9bi1Vkk8gbUfJC3JJ1TCkYSSECL2rbCz56KcjG/sdApOV4vpLmt216GeU
         0AKaUk5d50YreuB2eV+2J7Z1DA8f1dALZr6oiaUbfGbvo10bg4+KrN5X4qrizZ9E+uiF
         ZPu53tSvgfH7wQ9Y1gaFAwb8ZaNMN4xxfibSMMymYQT5c0/kv7V+SU3ozfMqMPYErAFu
         f6FHb44j7znORa0kVZ/80fGsN9Zo1b1hq0RDT0aShghZj6CRYI8PAAtTWOm39h19jVr7
         jGeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764874822; x=1765479622;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dc+K/0BnkwzyRFtJrhHCBCHfHCsAjteyQg1fzlCoybw=;
        b=Evuuk58YnqeGaEqEXRgnQkgICTsTk1HS4l94D4B43OZbcQTVA1iI+F3Nit20Tgalvg
         qxa6WcgcX1cJ8iGZCHs+Y3jAueFXC2v6NUO+r7jB4/0UQdqqTwt+WEKvZ6oeqMDFqONC
         Z9fTjbOpOlsMeBCMyZu2j3rZSIzflL0GIyVXB6iqegmCEuA79z9rGJ9+HNOwWUSsL66Y
         ++Vu7K/gIf20Gileodx2uYxASKI8QK9Nh88kLZJV6mR9KwFu3WU0dwOWJ3BiZJfy7zVi
         DjLLshPxSdRf5kwUA6+9UV4CvnF1sej4ZiJQPrx+VUX80pf6NK1iFqrihAyJZji6Y6yN
         t4jg==
X-Forwarded-Encrypted: i=2; AJvYcCWc6Yv6Rs8UJzjHWMCWjpT0tg4wdXLY/Lsb5sCliupDlrbcZsLWgZ4ndE740XK8RTwBymeriw==@lfdr.de
X-Gm-Message-State: AOJu0Yzws4rv1jam0PB+gXRm39FKr1H5wOngLJj2wtCdCC2t+PvOxKDo
	oWCCfuy+g6jEXrg0uu+L+JFmagid5xwKj9OdW/KDSiFPblKdS+JwWXbR
X-Google-Smtp-Source: AGHT+IFWiErCgxNMp1wdrxX561UhD33Vp/QHHO+5f/zZ+iPxGbo+O1NDdA1ANEql3UD7Pm8zT5AWTw==
X-Received: by 2002:a17:902:c94b:b0:294:def6:5961 with SMTP id d9443c01a7336-29d683af981mr85334795ad.45.1764874820061;
        Thu, 04 Dec 2025 11:00:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y8QWWXv0nf8aUqqf9ELhOS73wOyeughwn6POM5tESssA=="
Received: by 2002:a17:902:e944:b0:295:3ea0:cf8b with SMTP id
 d9443c01a7336-29dac820e4bls15902145ad.1.-pod-prod-02-us; Thu, 04 Dec 2025
 11:00:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX8vNjuwbNWdIOk2RjJLYhocRsbsBxSd4Q3RYKLLYUwaX58T1NqYw6IRRbMpW5mR+AQ4n7coQTU5n0=@googlegroups.com
X-Received: by 2002:a17:903:8c3:b0:295:6a9:cb62 with SMTP id d9443c01a7336-29d6839269fmr92157145ad.35.1764874818164;
        Thu, 04 Dec 2025 11:00:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764874818; cv=none;
        d=google.com; s=arc-20240605;
        b=GG882G7AWNZ5VybZkKpOHF1GmLtWxUGfBxOHU3Z/SkXnC2JISc5sRhpRY2+R8iUXrf
         wmiiOHqqq6PBPPI7S9WnHeYG+MOe6SJuOnhui0zrQMacJYz58tM2wXFmlbxROHQBRU4W
         lnyedBG9gfN+nsrMoqxavLg64shb+p2o72GjUUqVIN4Iv/49a8uhQTvU3b6Qs8pXqfoK
         IbYRQIdpFJlqyztIlbKFTebp93LApXI2t4GrC+8AwbbmXhgfohvpsNxh12zvwqSQ/RGv
         xXd6vN41K4Bteq4Uc9EX9wYOmT/AeOqc1g7z8s3jvAWSSWwTf8rB12fK54wYrH2LWtj4
         4CIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=OkoBRhgSwjuQLuLgL6yseexB7KxkTDwJEiXAnUMLOgo=;
        fh=3lmbJFsKFqn3G1mMRJGp1wiZI/iYXmMF53JZkSuq2Ek=;
        b=fSbL9vRPeuW5167iFRfOdJlC1DfjNVBnzt1RAkg1GqjWi3ALUGs8x4Hl7Wfw6TpdRp
         PGTmuSraGnOcdEkG5imCYwIORNDqe6tlpW8LE1o+wJfiKE1mAsKyeDp1P3OMaC7Au6Pu
         VOlPeW0ETreY8nMJ6AuNDFUYSAmqxjGeau2eYPrhIbVSmJ653WNg2ViuitxgroiTOui3
         un2sU1Sg28K8evGpFx6dZaaKFGPYHy9lj1HCP8o0nKVBTz9NQxG3FPmbecJyU7Q0Ww/D
         0Qg3MKyQ+F31sgBHxaWV6G3TWfp7BVxxIwx/FUEMOKRFmOebnJfDzHM4Qg6dSKcRddeN
         jnDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=MGFUiyyI;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244122.protonmail.ch (mail-244122.protonmail.ch. [109.224.244.122])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29dae54743dsi930065ad.2.2025.12.04.11.00.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 11:00:18 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as permitted sender) client-ip=109.224.244.122;
Date: Thu, 04 Dec 2025 19:00:11 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, jiayuan.chen@linux.dev, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: [PATCH v3 3/3] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <873821114a9f722ffb5d6702b94782e902883fdf.1764874575.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1764874575.git.m.wieczorretman@pm.me>
References: <cover.1764874575.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 68527f4c7d069f0e80ad4d48c006acca2241fe68
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=MGFUiyyI;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.122 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

A KASAN tag mismatch, possibly causing a kernel panic, can be observed
on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
It was reported on arm64 and reproduced on x86. It can be explained in
the following points:

	1. There can be more than one virtual memory chunk.
	2. Chunk's base address has a tag.
	3. The base address points at the first chunk and thus inherits
	   the tag of the first chunk.
	4. The subsequent chunks will be accessed with the tag from the
	   first chunk.
	5. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Use the new vmalloc flag that disables random tag assignment in
__kasan_unpoison_vmalloc() - pass the same random tag to all the
vm_structs by tagging the pointers before they go inside
__kasan_unpoison_vmalloc(). Assigning a common tag resolves the pcpu
chunk address mismatch.

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: <stable@vger.kernel.org> # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Redo the patch by using a flag instead of a new argument in
  __kasan_unpoison_vmalloc() (Andrey Konovalov)

Changelog v2:
- Revise the whole patch to match the fixed refactorization from the
  first patch.

Changelog v1:
- Rewrite the patch message to point at the user impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

 mm/kasan/common.c | 23 ++++++++++++++++++++---
 1 file changed, 20 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1ed6289d471a..496bb2c56911 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -591,11 +591,28 @@ void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
 	unsigned long size;
 	void *addr;
 	int area;
+	u8 tag;
+
+	/*
+	 * If KASAN_VMALLOC_KEEP_TAG was set at this point, all vms[] pointers
+	 * would be unpoisoned with the KASAN_TAG_KERNEL which would disable
+	 * KASAN checks down the line.
+	 */
+	if (flags & KASAN_VMALLOC_KEEP_TAG) {
+		pr_warn("KASAN_VMALLOC_KEEP_TAG flag shouldn't be already set!\n");
+		return;
+	}
+
+	size = vms[0]->size;
+	addr = vms[0]->addr;
+	vms[0]->addr = __kasan_unpoison_vmalloc(addr, size, flags);
+	tag = get_tag(vms[0]->addr);
 
-	for (area = 0 ; area < nr_vms ; area++) {
+	for (area = 1 ; area < nr_vms ; area++) {
 		size = vms[area]->size;
-		addr = vms[area]->addr;
-		vms[area]->addr = __kasan_unpoison_vmalloc(addr, size, flags);
+		addr = set_tag(vms[area]->addr, tag);
+		vms[area]->addr =
+			__kasan_unpoison_vmalloc(addr, size, flags | KASAN_VMALLOC_KEEP_TAG);
 	}
 }
 #endif
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/873821114a9f722ffb5d6702b94782e902883fdf.1764874575.git.m.wieczorretman%40pm.me.
