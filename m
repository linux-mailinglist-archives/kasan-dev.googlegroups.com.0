Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSOV7STQMGQE7ENMK2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3010D79A92E
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 16:57:15 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1bf681d3d04sf60988895ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 07:57:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694444233; cv=pass;
        d=google.com; s=arc-20160816;
        b=USCXErpJTJ+c7Cm6y5OUdq5nwA4/fS09sbflXgApNPnar2TrG7uSZx1Pn3C8PmL+4N
         HzbAfYqXtNC1yLlT8j/JazKh6UTenVYoknlvMfZNSfGE4T93QvHXoGz0t4IzJD4Dx+KH
         I4kNyWTlCDrIVtcTN4rKPBSDUkVwex82xVcMy6Bi6n5EBMtTgcXLJgkGK0ec0qRFwSl/
         160t1PTlNFvphHKMvGyChoonKTZSzf/NeVq95o6HRNnZxcAouyrUvgDzzA1YrWn9TMLS
         dFCFQRVE3SPhNHHhjDzb/PZQMgudMvbjGY3dGO2mCgaohyubfRakANgPfTyJIkwCe8K1
         KAMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=gfoEN7uAdAMeujHXQAxEY43BdYz7iENLnhD8qFCcGCs=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=rqPvpKA/pF0ZcaIH9RQkFTVSmWLafBWnhv1/j+4Tp+msrrgOs4y0/9mVmOVJKYH0i1
         UjlVYgNd4G4VXRjFf8Zb7INfCl+iblHL7f4VWDrN6I32o5n3HKAYlaHEt00pn7O0Z3D3
         X8SMIz3hW8XvFqNT6+wO4+Sti1VpH+6G8nFnXOx88hAWO5Xk2Get5BCh0PE+PPs9dips
         wmNxq/bxMlYl9vLcyevrBYaOYXWMR07NSoGFWwz1JHxXwRkvzpziVIO9BhTZ89+K3Lp3
         sSgxRykRWmqmo3wz9+xJBC1JBOj7brwEBvCqDOx9MgFCP/9NpfTBBtRqrA9LxsCMjm4l
         /0/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=RM5+wTG1;
       spf=pass (google.com: domain of 3xyr_zaykcugqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3xyr_ZAYKCUgqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694444233; x=1695049033; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gfoEN7uAdAMeujHXQAxEY43BdYz7iENLnhD8qFCcGCs=;
        b=lb2Z5AGuGuXZyPFAQMdOCpXhVUR+Q66tF2P26FLP2kwEEsQUduJW7uQLcH1aUCB+gt
         Z2XRTRuSOPEV1KQzLHbJ1RisH6Mj6IaW9XGJrO96Bpv/eso901XYlUdH89iwk1bbn3EN
         sC7kdixNNcRJiRTHNDKMiPfUmVahbnbNTRWnTuyWrcUySC0Yy0EpqQezk5PJ51dRil24
         oPjcxyl4PTTiaMrimidfWNVrwOAzVAEI2JCRLZCj74FufJgiA4htsciQxZ6/JC00xypf
         hH297rVwkWgvsf7P/LeHNsjRntH9JaSaaJGA/x1Kv/aqBjddBAUAIzyVptTmnRFAVo0d
         RIGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694444233; x=1695049033;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gfoEN7uAdAMeujHXQAxEY43BdYz7iENLnhD8qFCcGCs=;
        b=mvLPg5OEFF0sxVVJ9xgAfP3YrKeFXodDYsIOOwH8s05+NPr9ksMyUAb1RF+vWtolGe
         Mo7C5OwIKvPvRj0uXSGY6nkJUMkbimF2PT/8U5laq0J3TgGEcGIkw4msHRzgccn4amCD
         ilq2RO3OjI7DH1H0w00NX28kd1u39aegLMGPOTllLjPNYSP0TSb5qCtp2H5NK6y3qM/1
         fAYU9ZgR+ji5zGTfC9LRwfupFjC2G4c3vAEsc/qeCHe9dwKXJUzKWnBmYLtYr5FmqyNx
         8nCIfJwTjhtzQDEbG04OEAD0ZFTiNct6+DXMrZ6iE2oL/rFdZgO/2WUz9AYUznN9+7Ot
         uWdw==
X-Gm-Message-State: AOJu0YwUO3mx8a/KfHjrzKj1mhMe6JHSp0mhLZhoahQEhSQbnpQEkbns
	mPmlniAdUJ3QhIrKrTzl8mw=
X-Google-Smtp-Source: AGHT+IFI9i208E3fHAnMAAe0qpsCoFHxqEEXdXFtD/HuAY4w8TGRnymndcmwEOEQolZ62lpxrxQ8PQ==
X-Received: by 2002:a17:902:9892:b0:1bb:d7d4:e0d with SMTP id s18-20020a170902989200b001bbd7d40e0dmr6863685plp.64.1694444233538;
        Mon, 11 Sep 2023 07:57:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a3cf:b0:1bd:c972:493a with SMTP id
 q15-20020a170902a3cf00b001bdc972493als347526plb.2.-pod-prod-01-us; Mon, 11
 Sep 2023 07:57:12 -0700 (PDT)
X-Received: by 2002:a17:903:495:b0:1bc:5924:2da2 with SMTP id jj21-20020a170903049500b001bc59242da2mr7435417plb.56.1694444232437;
        Mon, 11 Sep 2023 07:57:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694444232; cv=none;
        d=google.com; s=arc-20160816;
        b=US6sGjnGLoPrxIlGfZJfItDIlJrh9rNTpumLxCm2c4zZ+PhgdMIRG7VugTz2F82uUm
         OU2wtRZ2u6mjBYbc4Qk1dFENY3wKOqUKCYTec7o49dT/70PJG6TK+qp34gpC8uWs0m15
         ItfPlYZdlh3cgz9slUuvPLsOUDP2ex3yy6IvF/tb9MwResNj8X4Y+aE3LhZClt+8j/ma
         Ah5uQp4rOQ+puLXEIjhqsFv72H9DEF55S/I2TpbEcyAOEkbH9eF6Rju4mdYtmEukLRrV
         ByQvYoPP841FeRJ/+bew16egm6R0FpzG5vb4OT5Hzd9uJTPt4AEkxzhC/u/HNjNcW87a
         EqKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=6iMPMRaHZZkPt2h2lba04yggcsYBY9dzA07C/TArg4s=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=c4jeHZEjcSc1daIUWR3RQz+yAH0qTbBO0sj5cxwnjbfGOZxaqXrp6w8rVrcVvOv4Kx
         snunYLpAVEwvSyDcZsmkgZK/Sfs7J6dowuDMYFT+vQzcNaeUD+vgPgJHkTgTd4AMfNqA
         RfSgMD7I6v3bZd/6E6y7enwHNpc7g0jQxGtU7uY/8m5FJSI6cjQM62X3o34CF66oS26d
         SA3OkIVbDgZBRb0gMUuWSuXIy7iJcO4iXrRjbSVHR0VIkWvIAOAYPxBLxWD+1rH5UPeY
         MEiQir/g4o7CKS4nW4+uQe/r0MlZ1FzOGswiMOA0gbdtZzmhF9Xy9o/ebqAAU/Dau+Fy
         lf+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=RM5+wTG1;
       spf=pass (google.com: domain of 3xyr_zaykcugqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3xyr_ZAYKCUgqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id kp16-20020a170903281000b001b8ae571794si784324plb.3.2023.09.11.07.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 07:57:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xyr_zaykcugqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-597f461adc5so49344087b3.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 07:57:12 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:62e7:6658:cb4:b858])
 (user=glider job=sendgmr) by 2002:a81:b706:0:b0:58c:74ec:339b with SMTP id
 v6-20020a81b706000000b0058c74ec339bmr231210ywh.1.1694444231601; Mon, 11 Sep
 2023 07:57:11 -0700 (PDT)
Date: Mon, 11 Sep 2023 16:56:59 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.42.0.283.g2d96d420d3-goog
Message-ID: <20230911145702.2663753-1-glider@google.com>
Subject: [PATCH v2 1/4] kmsan: simplify kmsan_internal_memmove_metadata()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, dvyukov@google.com, elver@google.com, 
	akpm@linux-foundation.org, linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=RM5+wTG1;       spf=pass
 (google.com: domain of 3xyr_zaykcugqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3xyr_ZAYKCUgqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
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
Fixes: f80be4571b19 ("kmsan: add KMSAN runtime core")
Acked-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230911145702.2663753-1-glider%40google.com.
