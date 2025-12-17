Return-Path: <kasan-dev+bncBAABBFPKRLFAMGQEJKVMR6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 71B66CC7F66
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 14:50:15 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-5944d65a8f5sf3651847e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 05:50:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765979414; cv=pass;
        d=google.com; s=arc-20240605;
        b=f7x6nRaz8eY8ofvt8FYhEcOErmSw5v+DkkwlcoqkQbFjgOtCQGpJyBsC5C2CJm2GE+
         e4MZpWP0xUbOXR/UUlYzceRU6VThvm2qczui8vMQeRmguK48yKtKwkoEIEQKr7iLW/P5
         78SSvYCm8rnSwhiPBr5V9K0qPEnM+LgAcY9iPXn8yEDWFuidSvkKjZpX6tXlHGCFfwzb
         quWFbxajp3wAsPU1JFu/Acg+BdiVXERSHZuy/WN66wsfSFVwxs4XraOUYDZj0rTOqheg
         c2Ft/ZcklgmIjRcxSTpC01wbIFCHzJEhwKm+9B4JY/6C8Qo0MIINl7DP3F/Cb05t5Ywd
         9Tlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=K9GRDi9vktxKYTn6Zg93bbO6BLceybX2FbROgxXjEso=;
        fh=jJnwB+zDC9dt+AmnCmuph1Akfq7c13PgjEFg8H2lE6U=;
        b=bvdvy1G1u9M4q1MSgTSblKHZw5GuWsixkplW5BZ/AWuUBP7zsdJn4gftIZIc7t2yTC
         72H1jN79ZZEJbl1TkQbg/Xa2hsziHGHCAusfgccUd999W/gGonb/1FoFQHZ6WW+tva+j
         4hg2KiS7N+9m6dIiKgFSQMEkQY7CdVCHirdGSPMoB/5Jpo/H8rkFTzVi1Mhp55LQ3jhk
         JFPOVNRxVtBXyQhGAo1PIKilkqzkhcRzSlRLDk0zCGFCntFnCa+bKk0zN79KWbR3Rrrg
         eDfx1pwPICMEkPtge1rJS1c73bUJ1A+yLYCBsQhIgy60w1B5q3yCPNV4tJwpPwDQWSkt
         H1Lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=O35IO7JW;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765979414; x=1766584214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=K9GRDi9vktxKYTn6Zg93bbO6BLceybX2FbROgxXjEso=;
        b=lmE7ZTScjo2Xr3zVYfEWvG+XKCOcip2Di+jMuXd7S4bipcM1AG+NloXuyYXUvrKBO7
         pfSVrsEF5/0ks4TBX3DWRL6ltkqHKbxcfbeiwPU8V5sW1HScO3ls+rWY6hJ3+5THevjK
         rXozRQcrL8dn1uVsvsqjJsGMxOU3mnIDNgE5d+Aa63HcLcWfC+Gyt8zoBRUiWelMih6x
         cqRxiBGeZKTJuXTcaFiwUErHzvlgM3GI+PER9WmtNnTTdjB00ti9TCzj5DZHFTbSqztW
         cj6kkENNU1H32eP7ueKmDqsDXXK86d06x7xdEgn6tS1g8rK7CfEIcHKahg51ym5NFt9R
         tHlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765979414; x=1766584214;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=K9GRDi9vktxKYTn6Zg93bbO6BLceybX2FbROgxXjEso=;
        b=CrXNAUk5Q8+wjI2QtClsyIGtnsSXhgmjjVHgAsQ1eeJQ0CWxLwQkCUXiX758RMQWh9
         Zh2xHGPdzI2kZA7kxG/h5QHs6XWSkuahbxNKYyqsncJnT+by3hi7x9Ic/KmQkvFLKdCd
         VD03ycpy1uiiWZrrwV+7zVWnQDdMQMEfPjeB/eXBlesaJwCGoA3ayFykDfcE3KpcAy1a
         rq9pn4yD3jXXlAFc1YsuA6XTHraEXeEtU6XhsnlfjQaCxvKWxpziF0btwCP9oPqoXOVS
         6zSRKt6nX8ZCbN5bjQQdBCBQ4pZpgx2MmgBAerT2B3SKZ6Pr2P2RiW7CUifNE/RxgSv5
         pnzQ==
X-Forwarded-Encrypted: i=2; AJvYcCUklsly0TyRQVxmrlSZjImBnSyYrR5TRtPf9O+P9qLBuSn+dReNYMmGyIudN2yAiKYsVFx64A==@lfdr.de
X-Gm-Message-State: AOJu0Yx0Zq9jUgtJ1VDifUhdZAOjrT7FQ1tYbu7+tyQtFVfYlHjJYSvK
	0439XGYnv4FSiRCc31rT0dAeHGxTehspEteErvBV0f5b0BooeN2OmO6i
X-Google-Smtp-Source: AGHT+IG0ZgXDzp1lqoP+D9clj9IYQ7MDev0ZqqT82qDLiG+PizYDUkB9DhbtJ4IBsxOIC75NOAv3DQ==
X-Received: by 2002:a05:6512:2351:b0:594:347e:e679 with SMTP id 2adb3069b0e04-598faa904d8mr6112434e87.43.1765979413998;
        Wed, 17 Dec 2025 05:50:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYyOHxQWWC2rmYYl9N4bm/hQO2PSfJEbqYm/0rc3UziQw=="
Received: by 2002:a05:6512:2211:b0:598:f96e:8c4d with SMTP id
 2adb3069b0e04-598fa390e50ls1874129e87.0.-pod-prod-09-eu; Wed, 17 Dec 2025
 05:50:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXWkRYdukZUcxDy9jj7uBWiNyu09SrZQ+oxHKQ6r36wShV8K6rnumhMqooXJSKH2pjv6es5bVHUN3U=@googlegroups.com
X-Received: by 2002:a05:6512:3da3:b0:594:2dbb:723a with SMTP id 2adb3069b0e04-598faa886f3mr6616065e87.39.1765979411748;
        Wed, 17 Dec 2025 05:50:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765979411; cv=none;
        d=google.com; s=arc-20240605;
        b=eCGRi9jLMDv538HrDK64W7jVAkoFUpwwEAhdHexYbQXsN8jm1OkcpOGU7jNrmX8YPw
         vfYei1H1Tm1/f1vD7sbhJCEb0OBKFXvac3z3OZqFH/+ItETq514OVxnxVbWlXwTn05jp
         8Yxvsi0PJj4urgeTgrMOXTtmeZkwl7f6DYGf1G9UQbPxrZbRrzp4z9F2oPxiotq2wuym
         +X0LUXjjB9IThiWjNJlyagirvZeZH9e+f73QcNcyDJ11T+Y4Co9HYChTjmos9aCaPWeK
         S2380gjtUPh7xKb1cET25k5aKDtyPZ1EAwWtdYWoe6fVPMMjsL3JoPME4E74NAjQNXuE
         KeTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=srKF/LsI6PPbEJ2JymYTvJSPX0AgbkVbHs9iEZzuI9A=;
        fh=8LqMIleaaS0kmaLaQ/rJucBBPvaN0H02cSW3W0icSd4=;
        b=FjISePcoeU1oFtinxjazULbiqUrsC1IBRooE9s2gvae1IaBLRGJ3Fh7JrGCYhEbJGB
         lPQNfTqkmzHTh1dpcS1QS8L7R2/HXni9mvF2YwPz/qpckkaYGqFmtcsTsXZSxqCoZvas
         5THejrtdMBMUGNR+Mcf0gyWJFrv3o/FNogsz/2xgn0N9gQq22/fhpm5/nBXjWMpZpRcY
         biGId7Ajs72Sl0XPLRgah4ioUObndR0RnI7q38fo4nwdv053GqHmoE6nkEOtSmkKDTzi
         ocVbd1OLR9FoIbo/4sILubj1r1s7Ygxf4/Z0ecJ83mSWbabrlQ3LUZnYRwREzl/v47bQ
         kbaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=O35IO7JW;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10630.protonmail.ch (mail-10630.protonmail.ch. [79.135.106.30])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5990da3f107si123234e87.3.2025.12.17.05.50.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 05:50:11 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) client-ip=79.135.106.30;
Date: Wed, 17 Dec 2025 13:50:05 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Kees Cook <kees@kernel.org>, Danilo Krummrich <dakr@kernel.org>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, stable@vger.kernel.org, syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, Jiayuan Chen <jiayuan.chen@linux.dev>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v5 1/3] mm/kasan: Fix incorrect unpoisoning in vrealloc for KASAN
Message-ID: <3f851f7704ab8468530f384b901b22cdef94aa43.1765978969.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765978969.git.m.wieczorretman@pm.me>
References: <cover.1765978969.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 0bc86e18ec967a34de1512b770ea99c717647150
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=O35IO7JW;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as
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
index f335c1d7b61d..df3d8567dde9 100644
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
index 29a751a8a08d..32fbdf759ea2 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -631,7 +631,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsig=
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
index ecbac900c35f..94c0a9262a46 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4331,7 +4331,9 @@ void *vrealloc_node_align_noprof(const void *p, size_=
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
f851f7704ab8468530f384b901b22cdef94aa43.1765978969.git.m.wieczorretman%40pm=
.me.
