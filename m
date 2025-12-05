Return-Path: <kasan-dev+bncBAABBY7GZPEQMGQE2DKOOEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb139.google.com (mail-yx1-xb139.google.com [IPv6:2607:f8b0:4864:20::b139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F034CA80D0
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 15:59:49 +0100 (CET)
Received: by mail-yx1-xb139.google.com with SMTP id 956f58d0204a3-64442f985a4sf1686688d50.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 06:59:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764946788; cv=pass;
        d=google.com; s=arc-20240605;
        b=XCDiwfRnzQML/b5d7tVxJbDivC615cRztbY8PGDMhvOdHykDXD36ds8YeIbED/+NE/
         U2jQEn3gP1x2nSSrxLA+2jYnv2quXjIyutvcykL3n3a8yp6xY95SrsxkxtLFxY9Dy/N+
         /D+TTuNR9/NeK6/aCiq3Frwg5QWqsZ6sv5KEWpA4PKLkvcqICRWMnYP8C5iV5psxerSC
         GgMCp8ZTDW6TlaVnxwdCV5jiM+SDh5TB5DVePJDlbXXrw5pPEGRUKWj2UJr+4aFyAQyQ
         zv0Yej6sEjnoQRKUnkF6hmp4FBM2GKSjyPzJ+wHvcbHka34/zUFRlMX8/R567ejzOHg/
         w/hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=C+Md14exAPdHZXUdJk0uxhaiu8sicSnF57085QIu45Q=;
        fh=1KOUHKIEAIkDGzQbmIc8t9S5b6Wh+/lmEsxFmPGU75Y=;
        b=QbxRvSFhMenquoPFuSUyoKzO2pIXIeey2wJUaDQZYP1Z/z7iWX+8a0qXMROJE4Evko
         ZFp3toI5pDDIgA7JdyZiN2ezB6yUbjSN7Ny3XvVaWJNN+0kMs9Y+SIZKFzbk37B0jEuF
         GM8P3kN11eTZXyU/2ey0kHHHtLin3hClqY0ybWeq+QNXeBCdczCUQEIv6jcpdADZDlTL
         apTICLFiVEzbJzZ576anemxt+GLhmgiQhafR+umsP+tEYE0N+10Z81607TpJDFQOrVcM
         Cw1adJYezmdeIgK1e4VHaQ7/kCVwFbn0lBA60tZYzMAXd+uOky1j58fc31AodcTddGqE
         F9XA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=NvvwT+Xl;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764946788; x=1765551588; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=C+Md14exAPdHZXUdJk0uxhaiu8sicSnF57085QIu45Q=;
        b=ImThHlgYjb0yWsRsNarsnQ/plkLeI/oY24dQWopoHOLXAUdNmYAAn++pY8CKcnb2NS
         LK+zMQH4acgaIiH9A5+qzs2BFaQHMxEiJnLbbdJVCZS5Kgh3h5imfz7hnv6REXnjDj3a
         Fzm1WIbiYa0G6DpHUPRxBLnKB01oFqrCIIsRWs2QhjpNSvyx8CS5ZoKcbmK7nHGSgAw0
         azbBS5TSOI2LLpWaiEgOUT4XL9K/jGmViQgnWyE3/bshr977YAoMGaa75ujhKj+ad0DW
         YC+KEyH1vZ2opPLTWsmD1akB0rDs8zN2Lm+UKSWC10cAxaKl2mzicD4KX78Nml50dOOk
         zGRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764946788; x=1765551588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=C+Md14exAPdHZXUdJk0uxhaiu8sicSnF57085QIu45Q=;
        b=Kg4ULBKo60jqNvZhYvy8oE/MVO9a2jAUqGJkK9S1ZjtexVsV2Sio3qYZkxWNW0qqUk
         udu/CGwogCOeH88nBOoW6QMO9ZgsvaAMBlvx3QYMt1wf0kxCU32TDN/p2LfrtiWT9ZC/
         ClUqC9RMPqqGKCELw3p7PYUr3cJkPS0WW0vKma36ndVkok08SVzkRn+AnCN2CTTdSMJe
         ieOMur3uNavnPY9b25PLmJtfOVzZl1piuQQzaiu0H46TEdZXAwYkmmiW9RieRax5DV37
         cKrBBONLazU6bRVBalASjbnPKCAOd6eX38hLflgUeQJicV+f4mje4GK4oRs+dERynlUR
         j/6Q==
X-Forwarded-Encrypted: i=2; AJvYcCXinztVaFVvX6GzO+GzNt+lLusKFDk+Gyguo9Mtjqa0Ich3Mlw2IODTT45Lg/ssWF6NbobavQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx2Q6nwSfCul8v51a/SHQwf0w7mFVm7fXLgbq222c/cMPf099QQ
	QoWRJx2LuAUYk5Ut70gfniOk+gkBwlwbWPPsE1OT010rIQIxvhW089S9
X-Google-Smtp-Source: AGHT+IGTEdZnFc0HOj6qjZ2iomYhC4RfaGJldgq1I9e//q2jkY1CZ+REo3kVedhF5JC786sdJeSqVQ==
X-Received: by 2002:a05:690e:169c:b0:644:41e5:dea1 with SMTP id 956f58d0204a3-64441e5e1a7mr4157195d50.4.1764946787742;
        Fri, 05 Dec 2025 06:59:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYtvLghDX4qIFaGTiN1zlY3V3dPmBVQ/BNwfOoinUvsyg=="
Received: by 2002:a53:c04c:0:10b0:63f:abbe:3977 with SMTP id
 956f58d0204a3-6443e7e23d2ls1186767d50.0.-pod-prod-05-us; Fri, 05 Dec 2025
 06:59:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWNEk1RvcPQYhPqpv98Gd65JkTWHhh6HicFJ7cJrNFsR9g2dYTP34NWMOwtvBHj0r3hYr1uUp6a2gw=@googlegroups.com
X-Received: by 2002:a05:690e:1187:b0:635:4ecd:5fcc with SMTP id 956f58d0204a3-64437040448mr7059546d50.41.1764946786986;
        Fri, 05 Dec 2025 06:59:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764946786; cv=none;
        d=google.com; s=arc-20240605;
        b=SqaInVyP28pxiEbUWaH+sgK8aT/vfekqw27Ae73cyJwamNpYoUriS1hS4MtTsMh43t
         8IJUXAd41D22ioerq5T2I/pO/9DGJ2c7RbILCTopzOdoxTYxdE73j3YcAT47n5dvIFm8
         EnNFKDQdNqBSz0FgBvY4loLvXxuJUQyliwu2PBk0skRFzW8DERfptrYZdKaaZ3Y1eSVN
         0xjVDKNnbdpAeDU0rP9do7wZED0u/QYzGa0pTTTM56sr+J6swtLUOxS6nET3RYuRkg2i
         fYyd5NFsiBZ3lsHeI6/yrh6PtwTdoPiWI8lK/gU6jAJt+nbDxo8UMOV0YDMSSUGSP8R1
         Z2iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=/FxBYSqiLvEPPLBRet/OeAbti72yHyHumcmcCrArpUM=;
        fh=ZzqSw+9e8FBR28VpZstXpCgJ15RDO6aPXYmj5QS5U9M=;
        b=Mh9AElAsDFhXfbeWxlKpS596gbdBLR5h0gmkoD1m4pl1YtjCsQ/bdDS60urmCAKIKd
         G7y/k9H/Tre/1deXxQ568jNnypMiZO/xSh5aUsjvwmdTIOPcIuYFikPLtNtkGaZ7hKRm
         UDkVtaVOODLXWBxRLwaz7RZ8jwf//5xLcY9ea+9EfP2rNNUKwzb+ZbdXG8sD2zHpGJY3
         O7NJNuAcnzuFJvL5KaeO+iAGvo2ygkqDF5yDlgYP+TBVkRY+M/dQb0XYorxpkMw7x5dh
         hyLALN6EhOq/tH7auTrLowJqWmZVHqMW0y63xH9FMkN0gWEGd213roXpwqgc0+kGt6gI
         mo+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=NvvwT+Xl;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244116.protonmail.ch (mail-244116.protonmail.ch. [109.224.244.116])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6443f580eaasi144146d50.6.2025.12.05.06.59.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Dec 2025 06:59:46 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as permitted sender) client-ip=109.224.244.116;
Date: Fri, 05 Dec 2025 14:59:05 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Kees Cook <kees@kernel.org>, Danilo Krummrich <dakr@kernel.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: jiayuan.chen@linux.dev, m.wieczorretman@pm.me, stable@vger.kernel.org, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v4 1/3] mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN
Message-ID: <247fd641cbf4a8e6c8135051772867f6bd2610ad.1764945396.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1764945396.git.m.wieczorretman@pm.me>
References: <cover.1764945396.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: d2dc6589d37d0aba1e593ab762db40d7e36c2a38
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=NvvwT+Xl;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.116 as
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

From: Jiayuan Chen <jiayuan.chen@linux.dev>

Syzkaller reported a memory out-of-bounds bug [1]. This patch fixes two
issues:

1. In vrealloc the KASAN_VMALLOC_VM_ALLOC flag is missing when
   unpoisoning the extended region. This flag is required to correctly
   associate the allocation with KASAN's vmalloc tracking.

   Note: In contrast, vzalloc (via __vmalloc_node_range_noprof) explicitly
   sets KASAN_VMALLOC_VM_ALLOC and calls kasan_unpoison_vmalloc() with it.
   vrealloc must behave consistently =E2=80=94 especially when reusing exis=
ting
   vmalloc regions =E2=80=94 to ensure KASAN can track allocations correctl=
y.

2. When vrealloc reuses an existing vmalloc region (without allocating
   new pages) KASAN generates a new tag, which breaks tag-based memory
   access tracking.

Introduce KASAN_VMALLOC_KEEP_TAG, a new KASAN flag that allows reusing
the tag already attached to the pointer, ensuring consistent tag
behavior during reallocation.

Pass KASAN_VMALLOC_KEEP_TAG and KASAN_VMALLOC_VM_ALLOC to the
kasan_unpoison_vmalloc inside vrealloc_node_align_noprof().

[1]: https://syzkaller.appspot.com/bug?extid=3D997752115a851cb0cf36

Fixes: a0309faf1cb0 ("mm: vmalloc: support more granular vrealloc() sizing"=
)
Cc: <stable@vger.kernel.org>
Reported-by: syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/68e243a2.050a0220.1696c6.007d.GAE@googl=
e.com/T/
Signed-off-by: Jiayuan Chen <jiayuan.chen@linux.dev>
Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 include/linux/kasan.h | 1 +
 mm/kasan/hw_tags.c    | 2 +-
 mm/kasan/shadow.c     | 4 +++-
 mm/vmalloc.c          | 4 +++-
 4 files changed, 8 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d12e1a5f5a9a..6d7972bb390c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -28,6 +28,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 #define KASAN_VMALLOC_INIT		((__force kasan_vmalloc_flags_t)0x01u)
 #define KASAN_VMALLOC_VM_ALLOC		((__force kasan_vmalloc_flags_t)0x02u)
 #define KASAN_VMALLOC_PROT_NORMAL	((__force kasan_vmalloc_flags_t)0x04u)
+#define KASAN_VMALLOC_KEEP_TAG		((__force kasan_vmalloc_flags_t)0x08u)
=20
 #define KASAN_VMALLOC_PAGE_RANGE 0x1 /* Apply exsiting page range */
 #define KASAN_VMALLOC_TLB_FLUSH  0x2 /* TLB flush */
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 1c373cc4b3fa..cbef5e450954 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -361,7 +361,7 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
 		return (void *)start;
 	}
=20
-	tag =3D kasan_random_tag();
+	tag =3D (flags & KASAN_VMALLOC_KEEP_TAG) ? get_tag(start) : kasan_random_=
tag();
 	start =3D set_tag(start, tag);
=20
 	/* Unpoison and initialize memory up to size. */
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 5d2a876035d6..5e47ae7fdd59 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -648,7 +648,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
ned long size,
 	    !(flags & KASAN_VMALLOC_PROT_NORMAL))
 		return (void *)start;
=20
-	start =3D set_tag(start, kasan_random_tag());
+	if (unlikely(!(flags & KASAN_VMALLOC_KEEP_TAG)))
+		start =3D set_tag(start, kasan_random_tag());
+
 	kasan_unpoison(start, size, false);
 	return (void *)start;
 }
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 798b2ed21e46..22a73a087135 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4176,7 +4176,9 @@ void *vrealloc_node_align_noprof(const void *p, size_=
t size, unsigned long align
 	 */
 	if (size <=3D alloced_size) {
 		kasan_unpoison_vmalloc(p + old_size, size - old_size,
-				       KASAN_VMALLOC_PROT_NORMAL);
+				       KASAN_VMALLOC_PROT_NORMAL |
+				       KASAN_VMALLOC_VM_ALLOC |
+				       KASAN_VMALLOC_KEEP_TAG);
 		/*
 		 * No need to zero memory here, as unused memory will have
 		 * already been zeroed at initial allocation time or during
--=20
2.52.0


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
47fd641cbf4a8e6c8135051772867f6bd2610ad.1764945396.git.m.wieczorretman%40pm=
.me.
