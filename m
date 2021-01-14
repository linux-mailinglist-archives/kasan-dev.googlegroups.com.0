Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZF2QKAAMGQEQDFQW6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 587D72F6B24
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:37:09 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id b1sf2745011vkl.3
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:37:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653028; cv=pass;
        d=google.com; s=arc-20160816;
        b=VtGzs+MPVBlbF85foQh0NfhRYn5FpuYy+glmHKPLRgKJMMh+qnc2oQiBDGLy7ChZLN
         aOvTjEREgjslBVjxM1RdoOQwdlhoia05dW3lhAEvUu6/OG5RtPV44hDaZL2ySUE+Ds+e
         brRzUtMNQNSj32fQMm2130/ZHpSRfi65Q1IofCkDH1Ec4NW1AMoAQwViRDjQ6fnCpLoA
         DjRAlV1lKqFKav+vRdL2gshFoLD10BxCqSkVJqorwzbXcGjCdYBrTfiUZxp3dytFkMCm
         eBX4GtFSmwxXSKhP79qld4Wfo7x6QLg/P0AJ4ctIbFuLqtReMnBV4lEbN5wLoAxpdsyc
         tStw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=yKeCeln/xcqa5yL78wU3/Sp2VG37TPvEJXwCFSNzX0o=;
        b=p+JlfQ0Sm4WmmF3m7mqzcb3ytPDw1M+xOZW1J3Ggem9fOXsOCiE5klzflsQkZmKsTt
         WghHODF1GKLAU3TtqaWhcr6KLYYWj7m39fKW7Vk5keOTrggrppK2EGqoq9q0LdVjKbSP
         UjGFYcwbwp585NxfDC+iVifvTRvZYPvvlo06jYBIWfrHwTzn/wXysAQ25AunSccCp8DV
         RIGxqhdojVD5D1VXXVGCeGgmJdHoJ3T2wmC0Mq9OKcr3mVrmy9aED8KBxKgY5pI3lAa1
         9rAgiXBS2+G7xU1kwkrE/wkmAiPoLl0/YbgxcXk8JxbZoA/eX8CqJzKZVh6grJoFjC7U
         AhnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l3zgn02f;
       spf=pass (google.com: domain of 3yp0ayaokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Yp0AYAoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yKeCeln/xcqa5yL78wU3/Sp2VG37TPvEJXwCFSNzX0o=;
        b=jcf82kTYMYajpR8UVWowCtJDGSgzOcrQBszVxKXt1UFryg8HlvfyHto57zOpwtdZCp
         KguMPPpIfsfHLwegoJ+ErDMqe31SVZQfUim0yCfGDFvI4VOFQDH6ZmMOHt9OnNfXQHN7
         jjpD14o7/WN70wZkn1/3RzxgC/wC5GsiV7uW6v6Z0zZQv0tMe1Qpk+lMzPf6nDbwu0Iy
         tUOyie5ViTICtldlcNiwTUR0mV7mCVgX5PK5l+h980yKiBNbFww8P3f8xkrZg48b4uSe
         s8pyiv5FujKVj6ry7uZLendQy3wUgcGghyT0dIkAV7l44qKB+94FlUolS/0JxzM42lk6
         zPIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yKeCeln/xcqa5yL78wU3/Sp2VG37TPvEJXwCFSNzX0o=;
        b=ohAuA+6T0/sLGNL3DXpuAVzRHhkYLBYF/MCG4h3VQDC9Jjis/yjKJRaXTGFSvj498k
         7sOyTEA4my5MjIg93R4KBGqiszDP45bU8KUSJ6lJ287xY9s+U8Wix1wVPsMlnBJVUF/g
         aMcYJsrTb6NinvUJbBmUO66x15tOF1M2+R7C+CEcnIuw6WDPQC4arGXLa8ON8FA5ycfh
         F8sWa4b98E/y2GnzeAzAPjoKN23EZGme24Ce5rXVkJkHf3aCX+TjCna/g6/nviLVRDlb
         ILCgItngd7ID7UwVwFLr8E7flULidO/+vAeZ4k4CChsAxC1BgcgQ/4A44ajjxzW57CzB
         BPRg==
X-Gm-Message-State: AOAM531EttxRs6jVEVLK9QHFLImrXk4ikSdE1XweOnbbjwgZRWdHWWfK
	1pv5xdZeo/TFT1I/IOHHOmA=
X-Google-Smtp-Source: ABdhPJzyTH8zwPDGlLfkpmYwakiJJx356Q+ewBtdTBtHljWP+od3btdqLGJkBJbnISCL2ce3GIBkvA==
X-Received: by 2002:a1f:28c7:: with SMTP id o190mr8034373vko.1.1610653028343;
        Thu, 14 Jan 2021 11:37:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6c44:: with SMTP id q4ls492435uas.7.gmail; Thu, 14 Jan
 2021 11:37:07 -0800 (PST)
X-Received: by 2002:ab0:242:: with SMTP id 60mr7247148uas.134.1610653027409;
        Thu, 14 Jan 2021 11:37:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653027; cv=none;
        d=google.com; s=arc-20160816;
        b=ushSWQsG5V485mAZInJ94NwogeJ2Dt4qnVc9p7TOJGfTQhKic5zL+dGxiaTwJCfbVP
         iCGMkQd0G98swOSrf9hyEALkCFn6qg7ri00wNeJe4RHzFD1zxSc316R2cztQTl50NoII
         jtiK0yL9kGhtoHF2gjUPKbooyuDzL3786mZ4/uVd9TVOwac/WbvaRr/s8ancEekZoXYO
         rtU9ZZJ7XQhi1GnYcuV/mWhfxKWl9MyXCBaqPqAu7cBAkmvh8vRoiVecI1FhgrnQPicG
         GrsqwpmzHE4mVSNW3locRBGG+D3ilUqLStKOrn7itTvrxtsfdWKm5/xkd6S/x8Q8rC7r
         EJ7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=mpVlk1+Mq66Mf4g3XdhCLFVXRKuPdNXXWU/IOGoVVBY=;
        b=YSddxdxuCIEyQsRU75RGZhSRGAhkrO9g9hplcFZK/RdU86Ou1Ev69k4zs2/zFce1gU
         fTKpai4xFYJ5mlMYgBZhInwVYmn9rROFW0NzyTZpXoQh00fLGqlwQssSZAryzQZOX9x1
         cK10odP6aT4h66JDAy4vVebQkis9lpViG6zW6Exs5Y/zvljozxxKimAN9X/jOztn+mVE
         V1o2gxysnDcj9MbpdzrndBecdWcxE6hhmMRHinE8PJgH/OIIceVnRtMpkNItQRQykxgz
         yv/xJZtcEY9ZdQXKbUY6dBkZTd8gRsMYdTLv3Vv6+b4dDyQUQAGhUZjqgwN/+b7UvWYx
         5uDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l3zgn02f;
       spf=pass (google.com: domain of 3yp0ayaokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Yp0AYAoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id q22si366599vsn.2.2021.01.14.11.37.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:37:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yp0ayaokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id p21so5665483qke.6
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:37:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:b2f:: with SMTP id
 w15mr8831064qvj.8.1610653026992; Thu, 14 Jan 2021 11:37:06 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:30 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <b75320408b90f18e369a464c446b6969c2afb06c.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 14/15] kasan: add a test for kmem_cache_alloc/free_bulk
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=l3zgn02f;       spf=pass
 (google.com: domain of 3yp0ayaokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3Yp0AYAoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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

Add a test for kmem_cache_alloc/free_bulk to make sure there are no
false-positives when these functions are used.

Link: https://linux-review.googlesource.com/id/I2a8bf797aecf81baeac61380c567308f319e263d
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 38 +++++++++++++++++++++++++++++++++-----
 1 file changed, 33 insertions(+), 5 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ab22a653762e..a96376aa7293 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -479,10 +479,11 @@ static void kmem_cache_oob(struct kunit *test)
 {
 	char *p;
 	size_t size = 200;
-	struct kmem_cache *cache = kmem_cache_create("test_cache",
-						size, 0,
-						0, NULL);
+	struct kmem_cache *cache;
+
+	cache = kmem_cache_create("test_cache",	size, 0, 0, NULL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
 	p = kmem_cache_alloc(cache, GFP_KERNEL);
 	if (!p) {
 		kunit_err(test, "Allocation failed: %s\n", __func__);
@@ -491,11 +492,12 @@ static void kmem_cache_oob(struct kunit *test)
 	}
 
 	KUNIT_EXPECT_KASAN_FAIL(test, *p = p[size + OOB_TAG_OFF]);
+
 	kmem_cache_free(cache, p);
 	kmem_cache_destroy(cache);
 }
 
-static void memcg_accounted_kmem_cache(struct kunit *test)
+static void kmem_cache_accounted(struct kunit *test)
 {
 	int i;
 	char *p;
@@ -522,6 +524,31 @@ static void memcg_accounted_kmem_cache(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void kmem_cache_bulk(struct kunit *test)
+{
+	struct kmem_cache *cache;
+	size_t size = 200;
+	char *p[10];
+	bool ret;
+	int i;
+
+	cache = kmem_cache_create("test_cache",	size, 0, 0, NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	ret = kmem_cache_alloc_bulk(cache, GFP_KERNEL, ARRAY_SIZE(p), (void **)&p);
+	if (!ret) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		kmem_cache_destroy(cache);
+		return;
+	}
+
+	for (i = 0; i < ARRAY_SIZE(p); i++)
+		p[i][0] = p[i][size - 1] = 42;
+
+	kmem_cache_free_bulk(cache, ARRAY_SIZE(p), (void **)&p);
+	kmem_cache_destroy(cache);
+}
+
 static char global_array[10];
 
 static void kasan_global_oob(struct kunit *test)
@@ -961,7 +988,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kfree_via_page),
 	KUNIT_CASE(kfree_via_phys),
 	KUNIT_CASE(kmem_cache_oob),
-	KUNIT_CASE(memcg_accounted_kmem_cache),
+	KUNIT_CASE(kmem_cache_accounted),
+	KUNIT_CASE(kmem_cache_bulk),
 	KUNIT_CASE(kasan_global_oob),
 	KUNIT_CASE(kasan_stack_oob),
 	KUNIT_CASE(kasan_alloca_oob_left),
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b75320408b90f18e369a464c446b6969c2afb06c.1610652890.git.andreyknvl%40google.com.
