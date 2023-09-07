Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2EV46TQMGQEDRQ2WCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6212279728F
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Sep 2023 15:06:50 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2bcb47970eesf10842851fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Sep 2023 06:06:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694092009; cv=pass;
        d=google.com; s=arc-20160816;
        b=C0R0rg8MWrUYrXqanDgKIbKdX3nM6oJVbkalHe4VY8kcDsmhCcNVLoF0605asqfEOO
         nuU3b9JlAV/uGYfyZvlnZ8A3T24n1QUW9lZZ5PyZBlVDcNSBN04vBq4G4IGycUW3zNVu
         7Mc7ekx95EsAQqF0qS62lRDe7SKx2Q4I7fuNNd1kUvVpmcQ1/2tQvnXBzY29ObSwgBEP
         vAQ/NjZB1V9waXwWvJcb4/ab++hExbh73pmwhDxN27DemJ77qzabC7lqJ4qk2mpIV6bZ
         WUDzebQSyUUIDJUScXvAsSDr+OEP0MnmzTfJsvNNgjZNimUmUtRLXxi3Y/rByXapkaAo
         FwQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=h5Dr7sRK5+EIel0uLYGIZw6rBqZOSbt6qDBMnh47xrs=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=NWtZHjIMAUGfFjczpMvQZoIB3CvaFg1sh7eueZ/OgetyTmp4YrA1nPcbumnyrMs3aM
         qKR1NjwQpHjJ3rjC5AJ8GgDMo7XohFCMzB7HzT8yMR3I7/tDxyEViq/6tZt5/l7F9z/C
         ETrtlgWRpNI+OjuJxV7vh8Bij9ha41QcTeJ04/yCQtFLLnR10p6UQeotnabAolpLXdyx
         bFVuqKLzGw4wI2tn4hVoszlzsng1u++a5ur8kXMVCJmk3voiHcxDHdOuFDLXDs8G6GcE
         gqlj6ojAqaSL7pFqwrA8zGzOM9Rb1cewhvtDkY4W9HNDH+HnXLr03Q9vFvZ+tIrDLPJL
         ZTJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1LqUCt5D;
       spf=pass (google.com: domain of 35sr5zaykcze163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35sr5ZAYKCZE163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694092009; x=1694696809; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h5Dr7sRK5+EIel0uLYGIZw6rBqZOSbt6qDBMnh47xrs=;
        b=QaKVCUgkQmDfqNXtdSeQQNUHAjJcx6MTwmsy7UwenKcLSXH3eGbWegyN6op8imVWR8
         sbTAo+4fYjyeosz5C8QG56h7KCP2L77BsLP1ZuyO+aFoV1kBI6Mws7GRE4sl/n49R4Ah
         ZM5eKxd6UkIkG2d9SIV7SBdmSpJ50fcoB91SiyWjNSR0efMmOPH5Oh2hOWroJKqNpWUz
         oHNlZ6bEmwMALIGuToudXovbPU5qY9L2aWhaazSbQZGA2GHYApApz2EVu92mATqm03TM
         hvqpv5//oU7DZcRitU+YSVzQ7pQ85udrpWLoH5OXDILj6nznZzuSaFsuv4g34PJnesPm
         iLLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1694092009; x=1694696809;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=h5Dr7sRK5+EIel0uLYGIZw6rBqZOSbt6qDBMnh47xrs=;
        b=jFRleMbOjZH7PbbkAVrowlapmrmW4mmgp8GvARjSxGYv1KlP+sozTTNUqpC0ZyIrLD
         +ZNJyAMT9652+8jNP6ShosOa5qDVAhwM39nijBWKJpBi4uX+apQ/g2kMcYYJXwtUVqrD
         MY2z5u8DujetKhrO3ExFdJpXLz9dU85oLy0YPSsop95pNShhaynkg7TCN78XpbDW4Brt
         t0xrOjq/vew/VlA88Uf8SMlCMZuUe/IIzJYcUCV75s3CpDPJazVPx2jC2gh+/ViK9Q20
         C4azfIF9qtSA33CBoOeR2xhe2CNr4vl1n/TN1aTd1mKB0ZO0ZxSB+St+SA0wCCs3IOcy
         itDg==
X-Gm-Message-State: AOJu0Yw36v6JUbwOOGhn//r7CeRAGM538AuHt4T0TUoGE0NX16aHTyJo
	Og3mU3uzj0iqnlPxlU1ea3U=
X-Google-Smtp-Source: AGHT+IGFOybbHMluR4uz7NN2GUlzUI/ZtVp+XBx+XmDVT5f6fzc/ghRPweHljwGuWNVXh8ks3HrBzw==
X-Received: by 2002:a05:651c:232:b0:2b8:39e4:2e2c with SMTP id z18-20020a05651c023200b002b839e42e2cmr4892744ljn.1.1694092009097;
        Thu, 07 Sep 2023 06:06:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f02:0:b0:2be:574a:3b04 with SMTP id f2-20020a2e1f02000000b002be574a3b04ls344818ljf.0.-pod-prod-08-eu;
 Thu, 07 Sep 2023 06:06:47 -0700 (PDT)
X-Received: by 2002:a05:6512:304d:b0:4fb:741f:75bf with SMTP id b13-20020a056512304d00b004fb741f75bfmr6183766lfb.16.1694092007281;
        Thu, 07 Sep 2023 06:06:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694092007; cv=none;
        d=google.com; s=arc-20160816;
        b=BuGs1KL2LHP0rgi7cGtP8G5N5DGo8f8yg8TjzsSpaosdYEZhRNuDDaG+dxwijEH0uO
         HynVcLHUmWdsl+66fLRvX+niC89GxA9b9VzErQD4Rc47AT7FvoCvG/MjEIegLuqFKONc
         saQQj/cq8OVPAwID1OFaKWY2bxT0mGCvduCelFtP3QA3CqgbskqnOmJbbryZtGqKlnmO
         5toV0B8DtPh+5fNpNCfxYFKKjgWv0LNguEZYbmUl2VfGy0ChYEiJhCSjAKDEz5Z6i435
         viuMd9B4yNYloVSaibdaOHOHt4DoQ7darIkvjYl+Aqkd4ijn8ufd+QyiwqlwC7ZGxGUv
         XYAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=pguS5nzVV0mhBjB/CrXM2tdNaYwlS7Rq+h24iaGnEBI=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=KyRbsVuNHOctXcbSRArLQlSMEmlr3Wvl3ckNjYzAlzFhDB6k3vrbrrrFcFOFQG/o/u
         eoOdMdT3/+IqpD754+eO+zRpjHyVuCALrv7fgf0TNrVtanH/k5NGpoNrya/JwXwpJkb+
         2kqQ56S6nE1lHjwh4ni2DJeDoQRMr7yCMVjYLLQg6dkAFKK9MpPPar0HhqbZ5obT7d9W
         MKEmVv+xOYvI8m/dt5i9pQVdW4oGp5hU8FWYQVn23kO0ttwFIzh22tsG9JQ1GFxqQ7Ow
         0rRemRrr3qcng3ODrV78YMLB3hPS/mzAJr6UKoIApaIXN/j3I6aE+/l20G5b3mJWE4Kw
         loOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1LqUCt5D;
       spf=pass (google.com: domain of 35sr5zaykcze163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35sr5ZAYKCZE163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id u1-20020a05651220c100b004ffa23b6e2asi1078744lfr.5.2023.09.07.06.06.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Sep 2023 06:06:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35sr5zaykcze163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-3feeb420c8aso6476545e9.2
        for <kasan-dev@googlegroups.com>; Thu, 07 Sep 2023 06:06:47 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:33dd:e36e:b6dc:1a69])
 (user=glider job=sendgmr) by 2002:a05:600c:2d84:b0:402:eacb:a797 with SMTP id
 i4-20020a05600c2d8400b00402eacba797mr47988wmg.4.1694092006816; Thu, 07 Sep
 2023 06:06:46 -0700 (PDT)
Date: Thu,  7 Sep 2023 15:06:41 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.42.0.283.g2d96d420d3-goog
Message-ID: <20230907130642.245222-1-glider@google.com>
Subject: [PATCH 1/2] kmsan: simplify kmsan_internal_memmove_metadata()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, dvyukov@google.com, elver@google.com, 
	akpm@linux-foundation.org, linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=1LqUCt5D;       spf=pass
 (google.com: domain of 35sr5zaykcze163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=35sr5ZAYKCZE163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

kmsan_internal_memmove_metadata() is the function that implements
copying metadata every time memcpy()/memmove() is called.
Because shadow memory stores 1 byte per each byte of kernel memory,
copying the shadow is trivial and can be done by a single memmove()
call.
Origins, on the other hand, are stored as 4-byte values corresponding
to every aligned 4 bytes of kernel memory. Therefore, if either the
source or the destination of kmsan_internal_memmove_metadata() is
unaligned, the number of origin slots corresponding to the source or
destination may differ:

  1) memcpy(0xffff888080a00000, 0xffff888080900000, 4)
     copies 1 origin slot into 1 origin slot:

     src (0xffff888080900000): xxxx
     src origins:              o111
     dst (0xffff888080a00000): xxxx
     dst origins:              o111

  2) memcpy(0xffff888080a00001, 0xffff888080900000, 4)
     copies 1 origin slot into 2 origin slots:

     src (0xffff888080900000): xxxx
     src origins:              o111
     dst (0xffff888080a00000): .xxx x...
     dst origins:              o111 o111

  3) memcpy(0xffff888080a00000, 0xffff888080900001, 4)
     copies 2 origin slots into 1 origin slot:

     src (0xffff888080900000): .xxx x...
     src origins:              o111 o222
     dst (0xffff888080a00000): xxxx
     dst origins:              o111
                           (or o222)

Previously, kmsan_internal_memmove_metadata() tried to solve this
problem by copying min(src_slots, dst_slots) as is and cloning the
missing slot on one of the ends, if needed.
This was error-prone even in the simple cases where 4 bytes were copied,
and did not account for situations where the total number of nonzero
origin slots could have increased by more than one after copying:

  memcpy(0xffff888080a00000, 0xffff888080900002, 8)

  src (0xffff888080900002): ..xx .... xx..
  src origins:              o111 0000 o222
  dst (0xffff888080a00000): xx.. ..xx
                            o111 0000
                        (or 0000 o222)

The new implementation simply copies the shadow byte by byte, and
updates the corresponding origin slot, if the shadow byte is nonzero.
This approach can handle complex cases with mixed initialized and
uninitialized bytes. Similarly to KMSAN inline instrumentation, latter
writes to bytes sharing the same origin slots take precedence.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/core.c | 127 ++++++++++++------------------------------------
 1 file changed, 31 insertions(+), 96 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 3adb4c1d3b193..c19f47af04241 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -83,131 +83,66 @@ depot_stack_handle_t kmsan_save_stack_with_flags(gfp_t flags,
 /* Copy the metadata following the memmove() behavior. */
 void kmsan_internal_memmove_metadata(void *dst, void *src, size_t n)
 {
+	depot_stack_handle_t prev_old_origin = 0, prev_new_origin = 0;
+	int i, iter, step, src_off, dst_off, oiter_src, oiter_dst;
 	depot_stack_handle_t old_origin = 0, new_origin = 0;
-	int src_slots, dst_slots, i, iter, step, skip_bits;
 	depot_stack_handle_t *origin_src, *origin_dst;
-	void *shadow_src, *shadow_dst;
-	u32 *align_shadow_src, shadow;
+	u8 *shadow_src, *shadow_dst;
+	u32 *align_shadow_dst;
 	bool backwards;
 
 	shadow_dst = kmsan_get_metadata(dst, KMSAN_META_SHADOW);
 	if (!shadow_dst)
 		return;
 	KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(dst, n));
+	align_shadow_dst =
+		(u32 *)ALIGN_DOWN((u64)shadow_dst, KMSAN_ORIGIN_SIZE);
 
 	shadow_src = kmsan_get_metadata(src, KMSAN_META_SHADOW);
 	if (!shadow_src) {
-		/*
-		 * @src is untracked: zero out destination shadow, ignore the
-		 * origins, we're done.
-		 */
-		__memset(shadow_dst, 0, n);
+		/* @src is untracked: mark @dst as initialized. */
+		kmsan_internal_unpoison_memory(dst, n, /*checked*/ false);
 		return;
 	}
 	KMSAN_WARN_ON(!kmsan_metadata_is_contiguous(src, n));
 
-	__memmove(shadow_dst, shadow_src, n);
-
 	origin_dst = kmsan_get_metadata(dst, KMSAN_META_ORIGIN);
 	origin_src = kmsan_get_metadata(src, KMSAN_META_ORIGIN);
 	KMSAN_WARN_ON(!origin_dst || !origin_src);
-	src_slots = (ALIGN((u64)src + n, KMSAN_ORIGIN_SIZE) -
-		     ALIGN_DOWN((u64)src, KMSAN_ORIGIN_SIZE)) /
-		    KMSAN_ORIGIN_SIZE;
-	dst_slots = (ALIGN((u64)dst + n, KMSAN_ORIGIN_SIZE) -
-		     ALIGN_DOWN((u64)dst, KMSAN_ORIGIN_SIZE)) /
-		    KMSAN_ORIGIN_SIZE;
-	KMSAN_WARN_ON((src_slots < 1) || (dst_slots < 1));
-	KMSAN_WARN_ON((src_slots - dst_slots > 1) ||
-		      (dst_slots - src_slots < -1));
 
 	backwards = dst > src;
-	i = backwards ? min(src_slots, dst_slots) - 1 : 0;
-	iter = backwards ? -1 : 1;
-
-	align_shadow_src =
-		(u32 *)ALIGN_DOWN((u64)shadow_src, KMSAN_ORIGIN_SIZE);
-	for (step = 0; step < min(src_slots, dst_slots); step++, i += iter) {
-		KMSAN_WARN_ON(i < 0);
-		shadow = align_shadow_src[i];
-		if (i == 0) {
-			/*
-			 * If @src isn't aligned on KMSAN_ORIGIN_SIZE, don't
-			 * look at the first @src % KMSAN_ORIGIN_SIZE bytes
-			 * of the first shadow slot.
-			 */
-			skip_bits = ((u64)src % KMSAN_ORIGIN_SIZE) * 8;
-			shadow = (shadow >> skip_bits) << skip_bits;
+	step = backwards ? -1 : 1;
+	iter = backwards ? n - 1 : 0;
+	src_off = (u64)src % KMSAN_ORIGIN_SIZE;
+	dst_off = (u64)dst % KMSAN_ORIGIN_SIZE;
+
+	/* Copy shadow bytes one by one, updating the origins if necessary. */
+	for (i = 0; i < n; i++, iter += step) {
+		oiter_src = (iter + src_off) / KMSAN_ORIGIN_SIZE;
+		oiter_dst = (iter + dst_off) / KMSAN_ORIGIN_SIZE;
+		if (!shadow_src[iter]) {
+			shadow_dst[iter] = 0;
+			if (!align_shadow_dst[oiter_dst])
+				origin_dst[oiter_dst] = 0;
+			continue;
 		}
-		if (i == src_slots - 1) {
-			/*
-			 * If @src + n isn't aligned on
-			 * KMSAN_ORIGIN_SIZE, don't look at the last
-			 * (@src + n) % KMSAN_ORIGIN_SIZE bytes of the
-			 * last shadow slot.
-			 */
-			skip_bits = (((u64)src + n) % KMSAN_ORIGIN_SIZE) * 8;
-			shadow = (shadow << skip_bits) >> skip_bits;
-		}
-		/*
-		 * Overwrite the origin only if the corresponding
-		 * shadow is nonempty.
-		 */
-		if (origin_src[i] && (origin_src[i] != old_origin) && shadow) {
-			old_origin = origin_src[i];
-			new_origin = kmsan_internal_chain_origin(old_origin);
+		shadow_dst[iter] = shadow_src[iter];
+		old_origin = origin_src[oiter_src];
+		if (old_origin == prev_old_origin)
+			new_origin = prev_new_origin;
+		else {
 			/*
 			 * kmsan_internal_chain_origin() may return
 			 * NULL, but we don't want to lose the previous
 			 * origin value.
 			 */
+			new_origin = kmsan_internal_chain_origin(old_origin);
 			if (!new_origin)
 				new_origin = old_origin;
 		}
-		if (shadow)
-			origin_dst[i] = new_origin;
-		else
-			origin_dst[i] = 0;
-	}
-	/*
-	 * If dst_slots is greater than src_slots (i.e.
-	 * dst_slots == src_slots + 1), there is an extra origin slot at the
-	 * beginning or end of the destination buffer, for which we take the
-	 * origin from the previous slot.
-	 * This is only done if the part of the source shadow corresponding to
-	 * slot is non-zero.
-	 *
-	 * E.g. if we copy 8 aligned bytes that are marked as uninitialized
-	 * and have origins o111 and o222, to an unaligned buffer with offset 1,
-	 * these two origins are copied to three origin slots, so one of then
-	 * needs to be duplicated, depending on the copy direction (@backwards)
-	 *
-	 *   src shadow: |uuuu|uuuu|....|
-	 *   src origin: |o111|o222|....|
-	 *
-	 * backwards = 0:
-	 *   dst shadow: |.uuu|uuuu|u...|
-	 *   dst origin: |....|o111|o222| - fill the empty slot with o111
-	 * backwards = 1:
-	 *   dst shadow: |.uuu|uuuu|u...|
-	 *   dst origin: |o111|o222|....| - fill the empty slot with o222
-	 */
-	if (src_slots < dst_slots) {
-		if (backwards) {
-			shadow = align_shadow_src[src_slots - 1];
-			skip_bits = (((u64)dst + n) % KMSAN_ORIGIN_SIZE) * 8;
-			shadow = (shadow << skip_bits) >> skip_bits;
-			if (shadow)
-				/* src_slots > 0, therefore dst_slots is at least 2 */
-				origin_dst[dst_slots - 1] =
-					origin_dst[dst_slots - 2];
-		} else {
-			shadow = align_shadow_src[0];
-			skip_bits = ((u64)dst % KMSAN_ORIGIN_SIZE) * 8;
-			shadow = (shadow >> skip_bits) << skip_bits;
-			if (shadow)
-				origin_dst[0] = origin_dst[1];
-		}
+		origin_dst[oiter_dst] = new_origin;
+		prev_new_origin = new_origin;
+		prev_old_origin = old_origin;
 	}
 }
 
-- 
2.42.0.283.g2d96d420d3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230907130642.245222-1-glider%40google.com.
