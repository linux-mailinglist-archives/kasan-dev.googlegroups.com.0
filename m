Return-Path: <kasan-dev+bncBAABBKXKRLFAMGQESZABMSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 5618ECC7F72
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 14:50:35 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4779da35d27sf54150845e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 05:50:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765979435; cv=pass;
        d=google.com; s=arc-20240605;
        b=OfOpPBs9OeFTO1IaIrO/bzTiC3WfWdtRq585aGEr0IdT8JmsFhA4SbXFlebdfVM/1p
         QCeiuQaVJsbGaf8iIT80PpnAqfLLw1/zV7qNEBLHs/hofL9P5WLOvHqg5zRh/pgbG/Th
         33P7OVlT8uDlOCXQDdSK1T8VP8JEKBiSXDlV6u/EfbrTVcXXqEmKRX8tisYPwc28BNDa
         H3/08lSgwj2vb9VtQxmi+0Dzot7ZyFd4HGQ7VCXSU7PZX3Bh4giRMKnfIgrPLh+XIJaw
         pkTVI3RmPttzt+Jr1/yx92ZroIEyXQoR5QvLS3pJ/Uz2TlPH2oxRtcWHwYO7w4NwVKr+
         eQ6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=O9SOhtr6/HznA+2YTUaNxEmSSvOy9skrpCJjbyLRKB4=;
        fh=n65wlaNyIVyidfsl4EC3+Bd0QVgi7D3nOybB4xbLLf4=;
        b=awBWetAtd046CfSSwX4KVtrxRyMDVnMesKpLRzj3M2DdbzQgVHzBcWLjDB+6fe83vg
         2j1QNmAA+mKp9uttuF55JlCLos6z7cEQIsLl0g9pGP/VqNxMytbsXiTHG5Qx9mfPxlxt
         cXVlOfXfyf4OQonxtTilAN32AgqvkUGBU7ESL4F/R3+yAXA9yYTLDDsiteRP52AQ0Ytg
         x16UY668kxtLzUM3uYOALmZr/KZKwDtMh23P6mIe358ZgREMiWuKaYZEEFCxMq6BDI88
         jnCFgyErDTSOKVCwBQ6foGMyE91MkpYSUwKfPZy9YX+LSvp9HkNu+0wwZRifYsai0khZ
         XfjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=p9cmJ2rv;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765979435; x=1766584235; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=O9SOhtr6/HznA+2YTUaNxEmSSvOy9skrpCJjbyLRKB4=;
        b=r/unPLnUWNv7kTA/m1rzLpRcwWef7NYdaaQtUaX+liwHLznFY9KeChcxR1f6HQBFP0
         TNxwgLpzoT64fq2WPaJSl61DxHqiiGSeXaIdOfU7eYSTiJbhWPVTemYIQKZUdUiQ8rZs
         h1cLcl18OyAsBfIpi2XJP40nFrZRP7pO1+E8LURTNIpgMFD03vzNKdfwfjapwUE1OObn
         G8aefil5hzE4Bbm4okxpNmKp/yC9wm137nD5d6qY6AIfFadTvINYzWxDv1QM3hasje7y
         EJzq2Mr/palVSi+9KTmB/Vr467DZKvjBpS/oJ8im3u6iPc5QLr9p/aBY8dKa+zDhq6WE
         WTJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765979435; x=1766584235;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=O9SOhtr6/HznA+2YTUaNxEmSSvOy9skrpCJjbyLRKB4=;
        b=Fdz+XiZXQspxK3xtyPsjWohuOR/0cZmj3UpWZiqD0Sr8rnxPJd3NXQF1uQpyuX5eqA
         HMCpnXh3/hjUBHAc09S9kDHgT8RCr5TBw/jgEw0+IcZmsZAH/JD73XW2v6hL/Ux1qytY
         2941aX0Ic0qVAQO1foG2DukGWahdCmhByQhMBOwb0T/IcEUCGh7Ler0dhVzLdVRMXUoA
         KHXQtAn2nz7PYfbbw7gzAairgnOMXKVHz+2ZEAVBfosMCmDZ1Nx4CasYqQywEFxr1EKl
         50esogmFEREFivwdSn6bJlXQwTTrGDyQJa7Vzncv7ciMYQS2/Kd6Lpp76zw8Q6SwJ9ee
         JOLg==
X-Forwarded-Encrypted: i=2; AJvYcCXw7JnGkFuI+weCMpGBcAXNULU1KvJPFyx20atEIzMQQgBnLl8YOp6MyR5Z7YkSJZf1PaggiQ==@lfdr.de
X-Gm-Message-State: AOJu0YxcirGkjypxKBzH4TPftkE8tKEpava+E3qnH7IK7GvuFIhmKeXg
	zFIx0ArAD1FcG/M+/Ro2eDDs6EEWjP9v2MXJKgnmXfXA4M0bMlAfc89H
X-Google-Smtp-Source: AGHT+IEYWfYsshVjvyzh/h5DkTQkSanuBtSj4+L9rffEEC8H7xfsRyG4J+HBUQIe5NtOyLttJFS3vw==
X-Received: by 2002:a05:600c:468c:b0:477:7f4a:44b0 with SMTP id 5b1f17b1804b1-47a8f9142bcmr199381385e9.33.1765979434600;
        Wed, 17 Dec 2025 05:50:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZvz7ETQQidBHzXmTx3MDvAABSVB7AMlZwoUApVsraQ2A=="
Received: by 2002:a05:600c:4ec6:b0:477:980b:baeb with SMTP id
 5b1f17b1804b1-47a8ec67936ls34884315e9.2.-pod-prod-09-eu; Wed, 17 Dec 2025
 05:50:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWdqXN7cyAsvk8W2r3RPmwLEjgspCK7gfWiuIs4pqDHQ+IthdMX6dkeknWe7A0QvhR7tB0j5y2EJcE=@googlegroups.com
X-Received: by 2002:a05:600c:83c6:b0:47b:da85:b9ea with SMTP id 5b1f17b1804b1-47bda85bc4bmr53534115e9.18.1765979432487;
        Wed, 17 Dec 2025 05:50:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765979432; cv=none;
        d=google.com; s=arc-20240605;
        b=eVoHx0DNjCUQ/cnCTQYJPZhDiVPvhtZWt6Aph7QDERrkVhl51tODRl3dXyYP0ZGpcb
         HteXeIoJd29SEHu0tIApTon77P4mbtU3IngyAyY/k0u8mMPsZF2ifDGsDjKKAXxK0p+L
         S7otqusRIvgKUP4ruyS8+AYgI6y9+ZXHuHo/bwo38xajtzEzc9IYDMHNxR335wAj7Doh
         B87MY1GxbYnZ05vwDjZkyMLyztR8wawj4elzXdT5bFYH1t4vmI74mCE6JnO96U31t/YZ
         xmWzgpcJWiU7KbE8NoGkiD97SNTAD1uAyRev6MRLsveg3Aa3BQ2d5kvC0fsvlaXGVkQo
         N79A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=geckSBD2rjVv/S+5QzW1VD5eMz8cQME5gCZakvPeAEo=;
        fh=miFYoH8n2z3v8l6ulMW7IhUIKmRq1l/xU3InOrmRgYg=;
        b=Lq4TOwCtmcBXVd/vFC30iNj76HLALZqPI9whj+fSAi78xdAWIDRnP+WvhGmfblQ5cr
         U0WAvwGfFZRIBn+pzhyELTiJsqSxsYkCN23DXwPmKrfcTRRuwr3BViTfZqTu7cRJY58C
         ILGL2NqQ2d72PyLryD2nBm1qSsgE6zZ1rU+UTRkhqP1UccMl6kmPD/6RfPTSGv6WPny/
         9yStARxlpNM5qUt9XGA5RbSCgeIhGJekOQ1v45rc4lIiQkAa/uTMaIlL+Kk4cXwnA+XX
         p7oAlqqaFJripvp0r9m/2WXQ0gzdcCxXg9iCD9JAj4KsLQswvLW22nvRwzqVCT+qF3+2
         APuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=p9cmJ2rv;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106118.protonmail.ch (mail-106118.protonmail.ch. [79.135.106.118])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4310ada7bd7si48711f8f.1.2025.12.17.05.50.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 05:50:32 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as permitted sender) client-ip=79.135.106.118;
Date: Wed, 17 Dec 2025 13:50:26 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: [PATCH v5 3/3] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <a2a1889754be3d97b8919cb2d3d099d12461f814.1765978969.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765978969.git.m.wieczorretman@pm.me>
References: <cover.1765978969.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: d75a71bd0b83a1602390f2bf46fa186102550207
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=p9cmJ2rv;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.118 as
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
Cc: stable@vger.kernel.org # 6.1+
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add WARN_ON_ONCE() if the new flag is already set in the helper.
  (Andrey)
- Remove pr_warn() since the comment should be enough. (Andrey)

Changelog v3:
- Redo the patch by using a flag instead of a new argument in
  __kasan_unpoison_vmalloc() (Andrey Konovalov)

Changelog v2:
- Revise the whole patch to match the fixed refactorization from the
  first patch.

Changelog v1:
- Rewrite the patch message to point at the user impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

 mm/kasan/common.c | 21 ++++++++++++++++++---
 1 file changed, 18 insertions(+), 3 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b2b40c59ce18..ed489a14dddf 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -584,11 +584,26 @@ void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
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
+	if (WARN_ON_ONCE(flags & KASAN_VMALLOC_KEEP_TAG))
+		return;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a2a1889754be3d97b8919cb2d3d099d12461f814.1765978969.git.m.wieczorretman%40pm.me.
