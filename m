Return-Path: <kasan-dev+bncBAABBFO6STFQMGQEGMDDULA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id A2787D1459A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:27:51 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-38323e5932esf13982251fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 09:27:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768238871; cv=pass;
        d=google.com; s=arc-20240605;
        b=JqONt4Rs3PObHnDl+t5JJ1zilqVRA4GJs9z6qgf91nnfRYY4nHVLe/WIAFrstb4R0a
         FR2B9SO4F6M2Ey2f4bm4j/P0q/Eynhq69kZYlsNIKeAHc+0yTvtH56xkT2YR1jWhN84B
         upqZCXHAAHopxb6jAqG38WdgIoYItFwKNHycEjKnGkKHzrTNQuEbuWVQ6z0c/m14LxNv
         4L194S930ZG9Oy7Cb1Pjjr2cuZpxEtdM1qQii0OtFFuJoqwUBRkyzlxHwWZ/gEtK0xon
         7QXKMGB4valvUd9IabMJyv95Lm4Hwhaimt2Od1gai2dxcBeOeRNzEi6zsNA7QmVTXpO/
         PFpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=smuoDEOysP++vdlnuI72dHGpPiDP8LLap/SynDX3su4=;
        fh=0rzeFSnBob3fP4dYYdoYDw4P4VPz5xC/OhTbmJlQUCY=;
        b=OBCEgKSmzUCHqkE0UolEUos18s0kZKt2MPOSsB+4yA01muXij4lDFYOOAeajw/llwK
         H+IHH9G/gv5pnv5/q1FvVH4XflKBpkYj5g9Cs5RvMwkUg6InlAAQ1S8Ca7yii8ZtHZlf
         uulVCXP8Xa/48naLUWrKoc6g/shLHaf2hAsVR2K4z/D5SiwxMMgUFaEkolzQ7lGZGqax
         pfW449imcDX9gkjC4WTg+vbKWU4hlE/WbDgvGq2eQm+6ZRJXlpg8bstL+otd3eo52fkA
         JCiKexVwG7bnN1cV7cqrf+EzYb1Vq1KmaYmmQQMvF9rsOu2o20pIkae6xDAohXsAC7T+
         59/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=E0ml2UWO;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768238871; x=1768843671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=smuoDEOysP++vdlnuI72dHGpPiDP8LLap/SynDX3su4=;
        b=Q1psgTaeRe5UKgcc4YsAsCq0CxCwX42xDXfKttd2UB0wVRI1BZDv0JfBKZzM4rfQQY
         Nho17jq7Smc8YKx/xbQ9qaNK6JSVIBPuyh/qbWXEc+H3l6x0Z7Kh37p3grfjEsNpLefE
         ObvBN2ZfNjse5zb6KQCyk3LWn5ub7J6znNnFEE+e0kxRUTX6Q4TBHMXKZQYfxNrzsuuN
         B8BDzurSf33f/ewHS0ANfzNJgj30kM1mnvnPXaUXGTqBGxJvJrdUfYu3w4Y8OK7Sif+G
         cGSCFWadZVjvqhH0YExKI1Ov2D46ipqc8FZMUH0l4VhYwaWmo+mNUfBlM8NfiZ+oLroX
         PrDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768238871; x=1768843671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=smuoDEOysP++vdlnuI72dHGpPiDP8LLap/SynDX3su4=;
        b=cLgyOz4qAUXhkiINyu/a9ZeOaS2sBIKqFxj0QQMkFEf9ot3D3WiwUkveQZn7oud1vg
         8hiBoWnnm9Z6C//O/AmOmFG/irSZt3QGH8s1VK8hp3slNKR56rPVQiZChbBVlyUGqxfH
         j6DiOM7v5TYV4siYhI+IR4K4FVUF8XOwWN4r+Aq0PaTMCxpew2Lxbnlw6VKVRdCExWUb
         9GMXGhWASKMOUFe17CY2ux11K8JO54vRfwBKYUg0Z2OFr5uDt4KKlCLOB/L2ueTcVxE/
         sRnBwDTVNGmVQqAYkMRdwaWaq8gUpt/IxmxJZi4iqxm1YgHSVfo4Kugnjs3jkn4lImid
         0HDw==
X-Forwarded-Encrypted: i=2; AJvYcCWXBfBz6XB59rKgppED0e/ySQve+1nc14ThrXslpR+kAAAMC1lL1I0Fwg/LVwT4a0QoEw3Uiw==@lfdr.de
X-Gm-Message-State: AOJu0Yw4jHbKvsi7sZwBFzXD7oRUQ4JvDfaKjl9tsnz1L6bg6KAOcOvF
	aQaEr3/Or0/0uJi0z6MiENtgBBd6tf7I10s44kcBsc0V+f8ZXKhyFZ69
X-Google-Smtp-Source: AGHT+IHki2o+OSdjibHLGnQPE8krUIBvN703igi6yxt/WZKc1R4a9Vr4HbyYLIvZ8OkRZ4bsYKt85g==
X-Received: by 2002:a2e:bc1c:0:b0:383:1c5f:84c7 with SMTP id 38308e7fff4ca-3831c5f85c9mr32798001fa.12.1768238870442;
        Mon, 12 Jan 2026 09:27:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GXYRLDgRxn0Sm+Bi0c0/A7WyMUweaOcO8pb3TcJX4TIA=="
Received: by 2002:a05:651c:1116:20b0:383:1460:e8 with SMTP id
 38308e7fff4ca-38314600337ls4309841fa.2.-pod-prod-01-eu; Mon, 12 Jan 2026
 09:27:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU+OHX3daR3e+rXYfWIcDoPLwr9PcfoMSqX6Ty1egM+R5lG6Uyw/3JW5Y0fSbY5X9KrfVDJWQxUY0M=@googlegroups.com
X-Received: by 2002:a05:651c:503:b0:383:210a:7b3a with SMTP id 38308e7fff4ca-383210a8011mr29436991fa.17.1768238868321;
        Mon, 12 Jan 2026 09:27:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768238868; cv=none;
        d=google.com; s=arc-20240605;
        b=dTNDgyM/S7XIhup/UNq9JG5UYw2w3EwXQLjcJA8LYZU5A/Jxl0JmZWChadNtOKgR6F
         Z+RjPDP3gpNi0UE+sThgnR/ycxDVQ1ui7XJXc2UvgCGChbShMEm3hrZ6ebs80pFpbWtV
         1YDQo53a5rXY8Kc0c5d7Bx0Rtdr58Sij7351bikTiEiEQP9BIQLLP5mfpuYx0OyeGXMn
         a6PP3J7xO85dnwRTFRYd8D18kGi17aveV13WxFl1EgSxvcFs0Y5QtSLi1YqswPXu3H4t
         ebARxyM/GunIa/Zy0B6VrJ6u35KBFjTtHYTsP8+fispCeEDfae1JIxi/0OfM2Fwyq4VD
         D7EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=yESMxyUg3nEjWhMgjSTmmglxLz0NhSPoNJMpCNZiqMs=;
        fh=cJXmhCP8DC+WrXzvw1naa+LNCCILCB3dr6HhvGsMiuM=;
        b=NgHI3AY9KMXgQnagpQf9r4VimRV5FvGGxgtam8REO1j2J1EWyORM7x2AadKV0nwmLf
         wBiCfJPqF3CvxYtwK/EfaQjQMyLI3O0H0l4SSAQHV8gDuAluuQan1acR4XhgDuZDLGGr
         LYggBl4Z/kllPYYiqer9x3bWv1iWJJlWiy/+e4l94kRLRWsp3GBl0AkcRY1N1quNRmIC
         50hyB3CDj+NgDjU0BnApcoLeVzQnwyASFtWDH/z1OES1kzNd3aW0O3m3R+VsGrtNZsJ1
         tiL6rCQhMWe6iwf+TI/8Bmy/N5bJYser1I9qpJYaDgae6rwZXgbB236aQgHCKopQ04XH
         TRXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=E0ml2UWO;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106121.protonmail.ch (mail-106121.protonmail.ch. [79.135.106.121])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382ecb22dfbsi2962741fa.3.2026.01.12.09.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 09:27:48 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as permitted sender) client-ip=79.135.106.121;
Date: Mon, 12 Jan 2026 17:27:43 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Axel Rasmussen <axelrasmussen@google.com>, Yuanchu Xie <yuanchu@google.com>, Wei Xu <weixugc@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v8 04/14] x86/kasan: Add arch specific kasan functions
Message-ID: <785eb728e2cc897e05ee709d42214172be481ab9.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 10432f028dc5aec035899d14c4ef5f6e6dbe8005
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=E0ml2UWO;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.121 as
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

KASAN's software tag-based mode needs multiple macros/functions to
handle tag and pointer interactions - to set, retrieve and reset tags
from the top bits of a pointer.

Mimic functions currently used by arm64 but change the tag's position to
bits [60:57] in the pointer.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v7:
- Add KASAN_TAG_BYTE_MASK to avoid circular includes and avoid removing
  KASAN_TAG_MASK from mmzone.h.
- Remove Andrey's Acked-by tag.

Changelog v6:
- Remove empty line after ifdef CONFIG_KASAN_SW_TAGS
- Add ifdef 64 bit to avoid problems in vdso32.
- Add Andrey's Acked-by tag.

Changelog v4:
- Rewrite __tag_set() without pointless casts and make it more readable.

Changelog v3:
- Reorder functions so that __tag_*() etc are above the
  arch_kasan_*() ones.
- Remove CONFIG_KASAN condition from __tag_set()

 arch/x86/include/asm/kasan.h | 42 ++++++++++++++++++++++++++++++++++--
 include/linux/kasan-tags.h   |  2 ++
 include/linux/mmzone.h       |  2 +-
 3 files changed, 43 insertions(+), 3 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index d7e33c7f096b..eab12527ed7f 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -3,6 +3,8 @@
 #define _ASM_X86_KASAN_H
 
 #include <linux/const.h>
+#include <linux/kasan-tags.h>
+#include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #define KASAN_SHADOW_SCALE_SHIFT 3
 
@@ -24,8 +26,43 @@
 						  KASAN_SHADOW_SCALE_SHIFT)))
 
 #ifndef __ASSEMBLER__
+#include <linux/bitops.h>
+#include <linux/bitfield.h>
+#include <linux/bits.h>
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
+#define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
+#define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
+#else
+#define __tag_shifted(tag)		0UL
+#define __tag_reset(addr)		(addr)
+#define __tag_get(addr)			0
+#endif /* CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_64BIT
+static inline void *__tag_set(const void *__addr, u8 tag)
+{
+	u64 addr = (u64)__addr;
+
+	addr &= ~__tag_shifted(KASAN_TAG_BYTE_MASK);
+	addr |= __tag_shifted(tag & KASAN_TAG_BYTE_MASK);
+
+	return (void *)addr;
+}
+#else
+static inline void *__tag_set(void *__addr, u8 tag)
+{
+	return __addr;
+}
+#endif
+
+#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
+#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
+#define arch_kasan_get_tag(addr)	__tag_get(addr)
 
 #ifdef CONFIG_KASAN
+
 void __init kasan_early_init(void);
 void __init kasan_init(void);
 void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid);
@@ -34,8 +71,9 @@ static inline void kasan_early_init(void) { }
 static inline void kasan_init(void) { }
 static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size,
 						   int nid) { }
-#endif
 
-#endif
+#endif /* CONFIG_KASAN */
+
+#endif /* __ASSEMBLER__ */
 
 #endif
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index ad5c11950233..e4f26bec3673 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -10,6 +10,8 @@
 #define KASAN_TAG_WIDTH		0
 #endif
 
+#define KASAN_TAG_BYTE_MASK	((1UL << KASAN_TAG_WIDTH) - 1)
+
 #ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #endif
diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index 75ef7c9f9307..3839052121d4 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -1177,7 +1177,7 @@ static inline bool zone_is_empty(const struct zone *zone)
 #define NODES_MASK		((1UL << NODES_WIDTH) - 1)
 #define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
 #define LAST_CPUPID_MASK	((1UL << LAST_CPUPID_SHIFT) - 1)
-#define KASAN_TAG_MASK		((1UL << KASAN_TAG_WIDTH) - 1)
+#define KASAN_TAG_MASK		KASAN_TAG_BYTE_MASK
 #define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)
 
 static inline enum zone_type memdesc_zonenum(memdesc_flags_t flags)
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/785eb728e2cc897e05ee709d42214172be481ab9.1768233085.git.m.wieczorretman%40pm.me.
