Return-Path: <kasan-dev+bncBAABBYOLRHEAMGQEIFCTOVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B840CC1CE6F
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:07:15 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-431db4650b7sf3255765ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:07:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764834; cv=pass;
        d=google.com; s=arc-20240605;
        b=YHYnx5VQSG/VJFdv6OKJw2T+qIEhGZCJewAkyeXlaNhaNaIkVMjYKcsX3RQ/BbVT8f
         Ixnvr5SRFF8W51gRhWop7HDRjgqjvPN/S061AKQ5AYTmlQmxCS8Pl1+kmL6LcaQiL6j1
         WbOkLPqJMEkXcvEa1mB+6SocexUrkZlo1y+3nDCAqh0YkBSQmS+BSSrFqTQV2kPkhACj
         XrAzEP4bqGLNTNtxlAOYGz6vRro5GM9X2XqK6Ne3xYiiS4Z414pBwI6Nlk//+liR33wH
         6Prn8o/Kbh+U1u3pHlTN1otXjZ0W7qyT3EDXVPloBNLe2I/MK8XqSQob086LPHApPHVj
         cfpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=SBFAroReMOqfDB8sHzqKa5VutVSjuCtBj1hxK3XTu6M=;
        fh=7+N1RYQTuacQmyQNGbmqbgQpi+Rp4DqV33nsulJalOo=;
        b=DG5Jy5S521sfOQcs6b5/GaCRpdzHlCK/V+Lx/nVBp+01MM8AaCphhvTvHEOLiBqGby
         3x/pons9rSfvAW/WKTSSqNh7ua0nqENBKdt3t3MRXt2/+Wnm9hJPD74mego521TN5rh6
         JnXrrxngphmxy+l7VG0zt7pB0PSei1HAWaAOFk87Rzl3tcuj5gCzWY96oOBhBjB/D6Y8
         svQHRqQhACu9TyPeQuZ7kd8OgEFkVuskqTXPb5vIJ+bv0aGdCuI6Bgz5WQuH8a8aQZMK
         IlyG7zqiunwwewQSzZ+Si1cyPEjuQiNRU5tZiv5qzb+clt3FL+ESp4UJW2ebiqhDtDfi
         g0UQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=OLK+mYTZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764834; x=1762369634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=SBFAroReMOqfDB8sHzqKa5VutVSjuCtBj1hxK3XTu6M=;
        b=jhyO6djmUT5MhORBUuAG/TXMGWQXl4DXCLqMhYLF4d4oa7tXqm1zPDnO0o+NIJpsws
         ikMPSiGhya6JvQUyG6nO0Z+M649zr1f/Faf72Q8DP7t5C8lNRvaAYXLcuMwGw1QPFvFP
         jnejXT51mQfU8mZc+8qDryvXkPqJ+HyTaOodQ403Hg23S7+32QVyuyXjj0ljd9oLTSBM
         qDVXPjoaEQ8UPxgAnZkCJjQu+DaAwwKZeZQVwDjdQ6CE9qyIDFm36mg1kDTUN20zkoJp
         5SiW4DMOW660tfY6csnVEqxDM2NNBp/B2z/jUEmmqDQB1Td0gnX2Y7CK0eYavk0kJw+3
         o6DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764834; x=1762369634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SBFAroReMOqfDB8sHzqKa5VutVSjuCtBj1hxK3XTu6M=;
        b=kugANVITW9L97cwtbcYRXEgXBTE9dojzEvCOYnkYPxRN8mYHWsRnr011Z1vUAWkgnk
         /aLoacn3jA6pvfcmWovyG576P0t7UXuJ3Uu33cjDmM4SKzIJ8D2ESpc72c47q0lVsbHv
         8fMdeVUOGzvQkYWUdutbXeL0DukXmaKBkb6mQs7sW+c92OM0eiKo054Rz8Aiz6SaMmBv
         WyRMOPOjTAvE5DUNKDqncPd5bm+2HZ2vOnimYRkU8XO51NHKZEh5s2LHJsqQo2uds+PI
         5uI1BQEhTlCGP1IcH4VnEwbrJEHZkM7HTObRiLs52tMEysBGC941h1tG03bBrNaMKYK9
         21uQ==
X-Forwarded-Encrypted: i=2; AJvYcCX9JqmTZdPZzIlGjNLZ4Bl68NetqUhR1dfPMNM8y8O5qyC2r99GNt8C+D9W9ovyRPUAGM76lA==@lfdr.de
X-Gm-Message-State: AOJu0Yw9Gu8l2qTDUxe7XZNJu4wTz77yRVHnmXVKSYSB9blAnyeQqC0L
	EhATm7lSdcMLiX1/Qf0Knvb/bbRcRJxdTgu/kaKcPq4+cGnpYir4rwhn
X-Google-Smtp-Source: AGHT+IHb2zxlPU2B2PvIzjTa7piwK1gn4OsOebyb/ZQPHJ4QbjgSI/Pr8E6oTDJgOGo5TujuVC+K7Q==
X-Received: by 2002:a05:6e02:12e5:b0:42f:9353:c7bc with SMTP id e9e14a558f8ab-433014e2039mr7109355ab.6.1761764833863;
        Wed, 29 Oct 2025 12:07:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+akGk4J0YjVWmXyw82H4TLLO6dNxCA/OgxmZr0WvPVo1g=="
Received: by 2002:a05:6e02:1888:b0:430:b4de:58b4 with SMTP id
 e9e14a558f8ab-433019521c8ls698675ab.2.-pod-prod-07-us; Wed, 29 Oct 2025
 12:07:12 -0700 (PDT)
X-Received: by 2002:a05:6e02:19ca:b0:430:b4ca:2696 with SMTP id e9e14a558f8ab-433013ee053mr9950755ab.0.1761764832669;
        Wed, 29 Oct 2025 12:07:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764832; cv=none;
        d=google.com; s=arc-20240605;
        b=WNLrM0SUUuh2o9vxZRxlVcn9xr9RqMcVKExx5zMDLPC5PWlSJMJSw+2+z49CY8yWmM
         iA4FLwCcgjmC7UJUv48I8+nnRYLD5EWz7iOrRmfnjwCmFtKFdFhhCiNhlCHpfBvwjdu1
         uP05LScv7NRVraF532yUPOqO8hJ9Q2KVVUnQCBJwR2qtcYd+0/yK2ZwCQ8BjWIqeizVy
         HxquX6IgOFNtSlPLOewOC7sbmFvP5LHTFTyM4I5g/kIBO7ZhuGfeqxL4RT7wvG3WP5+8
         E3kDfs2YtxIZ0Whsq5CdRjXCPNh5T6skO25T5Fhh5rHFRwlNIiUo8eCdeWKNfeCXGMg+
         hPPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=V+GI3JCHWjOQcFbXmMHTXI5iGSfAXcKKoBJ+NaZcg5c=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=l1CzyprA9y111VxhiIECnD6h+uJSD3M60zTtTW+9IIkbQq2hXE7NDds5+c8JS5L/Oz
         1UPXhPqSuH1+UieHYPbjeTNU31ii6uL9mOO3wN1Cy+6mpuoc87QdF7kpwQCL6eZDRTOp
         keeZ03k+Jee8vNieata+psXJyXUDmUPp1hN93LJvzBHoua/ceVpLq41Q3fkjA0DJpGyv
         +9XOmMbirG8M9vUb2Ix4XdeOutsGu58r2YsX0qkyVBnecSYB/xHAkP/8R0uR8VQfgjg1
         CscCxefnJUI+wuhLm0S7JObXEjHp/bYz1r4zG6IziA8uN+LlzXa9OWFe72fQbpzz/o2z
         gd9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=OLK+mYTZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24416.protonmail.ch (mail-24416.protonmail.ch. [109.224.244.16])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-431f7eb007asi8513775ab.2.2025.10.29.12.07.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:07:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.16 as permitted sender) client-ip=109.224.244.16;
Date: Wed, 29 Oct 2025 19:07:05 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 06/18] x86/kasan: Add arch specific kasan functions
Message-ID: <5be986faa12ed1176889c3ba25852c42674305f4.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 78312123e49b3e9b61a0495ac0e750673eadf38b
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=OLK+mYTZ;       spf=pass
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

KASAN's software tag-based mode needs multiple macros/functions to
handle tag and pointer interactions - to set, retrieve and reset tags
from the top bits of a pointer.

Mimic functions currently used by arm64 but change the tag's position to
bits [60:57] in the pointer.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
---
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
 1 file changed, 40 insertions(+), 2 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index d7e33c7f096b..396071832d02 100644
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
+	addr &= ~__tag_shifted(KASAN_TAG_MASK);
+	addr |= __tag_shifted(tag);
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
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5be986faa12ed1176889c3ba25852c42674305f4.1761763681.git.m.wieczorretman%40pm.me.
