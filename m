Return-Path: <kasan-dev+bncBAABB4PGZPEQMGQEZUWMZJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6542DCA80D4
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 16:00:07 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-7b8b79cbd76sf1799571b3a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 07:00:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764946802; cv=pass;
        d=google.com; s=arc-20240605;
        b=RUdtgz+eUkTlZpZHoh2JT92ica1ps7EAdLGbHA8KQjfC9ORQ4NGsT0T2sZIKIBmaYw
         xOenrK6MR/76a26+GcWVOmdqBPMZLfbBXRGJjbGa48fRdp9FKlr+RdC4zuXao5mCSx/j
         EAN/1f/Dwh9YnfGVAxir7kNBB1ljsHm4as3DwmrMZpXSACDazGs2I6A3pwE870NovnlA
         /vfZumzYgO9CX0EIfBRdGvkSxPGirvx+1iyFy4Kagddqhoak0f6ZVYp7M0VD+AOAYUfM
         7YdmGHzQSkC+FmTQwd8ITDM8/B5v2hEelcCrhh0xENoSz7Hz9Nt62zl4J7udDJqbActF
         7Udw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=7Y5gILRd3r9p/IRh4YndoA1hRnCuxnslr7V75FDb/EY=;
        fh=G28BYP6cZQdHBDi5BnY4djATPGW3g3zUJ4oqUppZrXc=;
        b=OLe8P6jScW0MBei3vVDLQ28GXQzaS7lLSOC3Q9bhOB09gq57UgOyDRzf0hYNYUGVFw
         Y38PEcv9D0TXPSvuxtBQjkQFUrUUKUl0g2kPGYHL9SNRuaNEpIg9SGbn3ZkRwsdTVjDu
         WnXlBBdVJQ2bkBkpu6stxk2dm8qqXc+BJ0kFfHayivTrQh+YI8c2kZIXDEyS2JPR6v90
         ci0UTCjqAhXXccJaNtrHNzSKfgGwK+kl4oWoGw6BJxBnjqCcnZ3/CGHhrv8F/B5jUzXa
         hqwBgBHzHq0RzD4G0f8gy/y/87uiMWZFtJfdTbg5PoXUGQexw6R3R1WISvHh4cDUKefH
         Qnag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=N+3AZIRl;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764946802; x=1765551602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=7Y5gILRd3r9p/IRh4YndoA1hRnCuxnslr7V75FDb/EY=;
        b=Uxg3L/bnRg+cF/OaHTO1Izpi7Gj5UOxuaEJLifioBO6dga1yw3n+g0ntV/aVtJdTsw
         oVElQSb7n9IC1V8l5DtibuWyz1gJaYOMUFqSEa88dDHVMHxwSx6+iwOMmHQbRQShQ8Eo
         c9wSgoaobxIF8vDZ3OAAnnQJn6AjYrTf//j9AvRyNU5oFXBSS0Yi+6x0Prxi5txzPdUk
         WmLajQnil7cW8X93nWYlK6gKuVEPC8bjvxrn7R1QE9w7Kl5M0klNlxmaepeLm5IbWl4v
         a5yjVaE56AfWwzoj+yMZOdyqRPsZLbArhPbqvMGhNx1DUO+qVu94Uva8N6l6KfgiqvqO
         VryQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764946802; x=1765551602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7Y5gILRd3r9p/IRh4YndoA1hRnCuxnslr7V75FDb/EY=;
        b=VmQSlkf8D9bHMFbn+3+U2BGiHFz2sardbr0pJGmAyBDt3EaOGiuypr5hqUXocISRha
         cAei0ZUXC50UGfmhsuwNxNxwhr7SY62SJMwIpCVqakiIOCpIJdJRGMoGS97vGdrnXoRM
         vHuIfEAYt0G7b6ebNPLfBYeYfwRnWY4evnixqIaOBCwAgAc+UpecCwqp7cjhku+7XmOG
         SR6bf44pLZgIxA1COSVZr5nFMtKC1yx63VUVdrN3RnoDaJ1Qw2K10GRZqiPBsbXr3xSq
         pek8buMdRRoXaXWyumifw+dG8QS9bbvptUWfHmmYW3xZQVghjQHqjT6fXP0vHr5NpUVN
         jbWA==
X-Forwarded-Encrypted: i=2; AJvYcCVPcS9xB/Aosz8atIj9jPpQRMqTBHpaB560fRQhgMFkixxwpVkXZTl/Uzi4mzWQKhLTeR4LMA==@lfdr.de
X-Gm-Message-State: AOJu0Yxanln3JEsOQ6LkA2b9H26K26GEBO48NZTD0uhYRgL3u3OEFU80
	7TyosMlwPoFTfZ/clXSlH8A6jzZKKnC6fQAdN6PwkS/I1fqPrFd+zLRR
X-Google-Smtp-Source: AGHT+IEFXPURVWe5K0n00ExyX6mVK4Z60FTzB70XIYrDv1tV99xWUE6E6RtyH8wy6+b8TAJHucqBfg==
X-Received: by 2002:a05:6a00:2d90:b0:7e8:3fcb:bc3c with SMTP id d2e1a72fcca58-7e847d541f5mr308839b3a.17.1764946802025;
        Fri, 05 Dec 2025 07:00:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZjZsVNDVp5CdZB6rvCucyElpEaoc4jkLyotQK80Wa8mA=="
Received: by 2002:a05:6a00:1a91:b0:7c2:b10c:566b with SMTP id
 d2e1a72fcca58-7e26a123844ls1286805b3a.1.-pod-prod-00-us; Fri, 05 Dec 2025
 07:00:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVu2KwqiE8jP3epoLwhfktX3IDqA1MQo4qtqexLOb0KxIRYdCReHkAteri7BZRmC/ITxhXbAFOFv3M=@googlegroups.com
X-Received: by 2002:a05:6a00:2d89:b0:7ab:242b:95c6 with SMTP id d2e1a72fcca58-7e2033a87a8mr8642197b3a.6.1764946800337;
        Fri, 05 Dec 2025 07:00:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764946800; cv=none;
        d=google.com; s=arc-20240605;
        b=i7VKBqzxB4QtjQGrCLLzk3+6OqUdYu5UHQRs8rKhWH+NHOwtohjLvok8HVxbOimgVi
         EpcLdzU3GYOqb8N3B3MO/5ENWxqYiXL/HKZNf/IOVJto7RckMwMr7ziOx/+Swem5vN9Q
         8poPGKuOWv89eELAeLr1RBRVq8Zgp4oTqQuEJ7LhNM3o2hMDi9RccpoRE6Bxzt01bflE
         4u1JAWiJBbEWhPZh+zGzI+2Zj3XCNGU3le1PMjBEAhurBMP/OR1RUMuA/IhUVuoELJcq
         2fepiHI+lHn9xBYaY82uZOw8GhlZhxknYZu0GSSmx/XgXcbTaUWsDaMPeC0m66Xe+KZ4
         jWpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=L0KdqaoEvJRt9/c4L5Rt4JS2SHbqfjLO2UUM/bE4AmE=;
        fh=5kxAAPzAGl++gPn/32fHh6v+pow+ts81MXbkvG/Dll8=;
        b=MasvZ8DITKMYqwOOnadIbb9mF8/WoTWsR/TckRAjd2+sEG7vyLXfv/vIdYEPjC6C7C
         gt43KHwHEGlOeSqP7OFZvJQj42AJOLzI5wZXNPC8N/X7fdNOc2eozZUP7+bPAJ4+CSVm
         jdZWsUAdjOa++tVStlDmnbKcgzcufopdvQ9ro3wUPdJ/9qZUPb6PMYNcHPQXpmKHXIpr
         Hb94Mf4zyUZn5lrbxsQfgIjL8p6NaFO9CleMg8+Zj1/KgulSgpfsVjfYPc3z3skif2ih
         I0dbscIbjQRbducrdgpUj4e2SNU/F9uUoXVYbGyj1jP3lMvfHMkoXJ//G7MDawwCktlB
         n3tw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=N+3AZIRl;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7e2e48d3aa5si191245b3a.1.2025.12.05.07.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Dec 2025 07:00:00 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Fri, 05 Dec 2025 14:59:26 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: jiayuan.chen@linux.dev, m.wieczorretman@pm.me, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: [PATCH v4 3/3] kasan: Unpoison vms[area] addresses with a common tag
Message-ID: <919897daaaa3c982a27762a2ee038769ad033991.1764945396.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1764945396.git.m.wieczorretman@pm.me>
References: <cover.1764945396.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 1f0ff2af25c0def600917e4f386d03b302b45161
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=N+3AZIRl;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as
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
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
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
index 1ed6289d471a..589be3d86735 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -591,11 +591,26 @@ void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/919897daaaa3c982a27762a2ee038769ad033991.1764945396.git.m.wieczorretman%40pm.me.
