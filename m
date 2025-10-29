Return-Path: <kasan-dev+bncBAABBA6MRHEAMGQE3LGLQFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E556CC1CE81
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:07:52 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-471168953bdsf1784445e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:07:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764869; cv=pass;
        d=google.com; s=arc-20240605;
        b=X98eW8BP17pEfz7dX0LBHTF2Aaz9D3aluvmNHOOv3bZVbWGF/rzDyUHW2v2kw4uOHu
         5+C9NdTZLAERM8IrZ2uFInV8p+F/vRBVtQZHjMeaPnesbNGlfm2f7Y6R4GzePybz65cf
         zWa4wMWnx7j0HvUlv0pJH3Syd9+ths7E7tqkjFLNXeOQ2NE9vKgFa3JTDuOCd/QyOZgJ
         3pKh9gN8wNKmcbjEEq79K4LDS7yDOu3D3hpEJQvWZd/Y/oAu1WWaJbeu/qs1nsSOgsCY
         auVtQ88AyMat3Mq9Hg2x6OBrNRHfBxRb27oBjUrUqRjQpO0MRXrPO5NT86Z8ak2SSVkd
         QXww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=kHIOXTVtAa2yDN5hq3l6lz3avOXxZQmAguljUzt3jZ4=;
        fh=fV2RyH50BIE8DlctAZSx6ZZollCVgbkG6UxIFG3kWPk=;
        b=BuROp7t6F1+6vZ+AtGC8LBw9sR1dDbP7SfhSQypTMWxc8bidw8XsKDKqtZX2IqG+Vu
         3R0b4ssYTNviGjvGCXefFhfizJVHX42HoedxAx/oXOR2rMvaGYUNff7jUiCW5Xbxjyr6
         B7uxbd2Jyf30sAoBEDTpMIPRZ2TBDFZTwxSObQPz/gyBZkzEgtIghtVXEoMweHgraQ/W
         ypBhNjJvp4ik+xpcBie/8vMZOFk7LMDA+pg6fXf+8Qqyu9P+MlFCXjJ2d8Ih4f7UmjLO
         leviuyYHb3v8zrHTNvW9vQQQrOx2K5PRprWEAss/eWzr3tYJi/rir91KWxnwhESjNq7I
         cQHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=oLFtUaeP;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764869; x=1762369669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=kHIOXTVtAa2yDN5hq3l6lz3avOXxZQmAguljUzt3jZ4=;
        b=EbODFCIELRmH8okwS0flHHaFWCJLvI77i8f5xXBs5s+QI+AT20bPy+1MJyMUdSWoSo
         uPy26YrKL03LOWae+XagL0yed4tx3kw9pZuXNAR9yxKepACVFyzDxL/laqzQ/156aYBB
         zk2OfutznjyRQVJmIGTLcAXiKvAgm3bG5V9KHybPkJg7iLiw0/VjxzKvXOn9YCftNYOl
         WTtOZGHBACJwFOHs9FaL3ubRz4FBm444IsomL1cz4EQbqPKolmEXQ7kz/nKtH6n3h/qm
         BdTyYlCoyDgoc2ue/BV1axTkhgane/E7Fu47X0ehcKB6lvStucFzGJ+MPkqC9TUGwWZ9
         2sdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764869; x=1762369669;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kHIOXTVtAa2yDN5hq3l6lz3avOXxZQmAguljUzt3jZ4=;
        b=jUbzs3tsHJxfHbmR9T90lnfjZbU3UrTYeRo7FlYUoz9qO6K6RM0Y6gjJkINnYukvfi
         Y4S1d0VbJTt+9NDgwZbHvRRRswiw8RgWfVHAYFnUa6zBvqDSiXX7nDySVFUrLHy0cmsL
         3T0UQA0l6vpJfWe4I9duilpDZ1wjfDTu/16UNyj9+7QpeI+z6UO4IeovWjfh2yw2okT9
         kaqczJBWw0A+hoNdvCIewgs4PF2enwO1PoKi4zmHAeV3ILT/atH5G/ZYHAm2TGyOYA3G
         F8vtUnjDv7Tv/lRI7sA6XOwM/PHmjKdFv3S5k0+aSFZkDXOaM1fV1z1oINhas/FsQAZm
         FoOw==
X-Forwarded-Encrypted: i=2; AJvYcCW2zAzFujU57DXJoKwv6qhsLZ0cbr42wTqiBFOSy1toLQJGJzDlp6k+Wo2rRjIsYdlBCq5EzA==@lfdr.de
X-Gm-Message-State: AOJu0YxJNf3Yx/63aAL7l7ds+mMEKTKhofwRhIrNW9ks39Ixy2ztFxNn
	lvTCZOzKWkf7dWvonpHyvv+vzTDwYXoZ5cfe4cxOIjjMp3O6TqlglNoJ
X-Google-Smtp-Source: AGHT+IGIh42pJ8SPDSNc3fWZF2kCYZAYFQnQbXr75uPjupvsLeJGzsRTxs1UbfKpjuSG8YE8vFuDEA==
X-Received: by 2002:a05:600d:435a:b0:475:d278:1ab8 with SMTP id 5b1f17b1804b1-477262226d8mr4547765e9.2.1761764868640;
        Wed, 29 Oct 2025 12:07:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YKQvWwHzLkHY5gNuzzvennMz9EtOfqOW/fw6fvq6iE8w=="
Received: by 2002:a05:600c:5805:b0:477:2205:db97 with SMTP id
 5b1f17b1804b1-4772205df6cls2202525e9.0.-pod-prod-00-eu-canary; Wed, 29 Oct
 2025 12:07:46 -0700 (PDT)
X-Received: by 2002:a05:600c:a407:b0:477:14ba:28da with SMTP id 5b1f17b1804b1-47726239940mr7431125e9.5.1761764865850;
        Wed, 29 Oct 2025 12:07:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764865; cv=none;
        d=google.com; s=arc-20240605;
        b=VXWIXZTMuLctoRNfuLAGEprvxjpnpj9UHrD0SoR9it/o2UCmvLUi1qZRntraR6rNXY
         Rfryx7fT2TLLrF4n+lCUGbbJ+OIbD+d3QuOtqkxB4rbvZm+hNWSbqzz17z5dyeQRqhEZ
         Cdi+7NJshnvV9WVWECsc4I6jUjoB/GWIrqMmwTPK7GjBXxXMoJWBybtX/UxECTV5EQYl
         JAGtnDxM3hlV9qr0tDYX59Kt3WP7t7sm2jHHcv9zPljOYyjXP01j5uK3hnGUnwBwxIrH
         /aBnYlfU5etvKWjdUOdqwOTvieqyFh9mu5Om9Q3xo3vbLnwyr4liCioTqk75A0Oe95Wk
         4rRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=sFQWpkAgZ4WYl8uNu/8Fmdid7sZ+Bxs6DzYolFKr5rI=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=ex/eg7iPxEiBbQehlN1Xq4ZpuFZW0uSD5mtPSM743gLa+VK+SpSvlN+PqpHfd1rzZQ
         tq74+EgmsHfzeWxNYr6gXD7kVrwGuCPBVLKtl6b/mZNjwdpcfWpbYTPbh1aS7S9z0zD2
         sRb0+kH7OCczt5ba6sy6xtvCNFJyHy0OSzc/huug863oGGpcssrkVXCMurg9elJPl6uC
         bjNcRYJ7bINdEcPndluVAqY3T0Mn+EpBut0ec3ZIq0LFpa0CH/kmXWfFDtvMqftG9EgG
         nffCyTm2lYPV/e4V3qX67ndur1m0Pim8jiNntTjFMT4L0ZuXFFHD2ulIxepgyqEfZ4lC
         Vqdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=oLFtUaeP;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42995ffd3desi281336f8f.7.2025.10.29.12.07.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:07:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Wed, 29 Oct 2025 19:07:34 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 08/18] x86/mm: Reset tag for virtual to physical address conversions
Message-ID: <d030a07c956c1e7cbf8cd44d6b42120baaa41723.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: c34c086f0ceececd458efcce81b943565370c09a
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=oLFtUaeP;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as
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

Any place where pointer arithmetic is used to convert a virtual address
into a physical one can raise errors if the virtual address is tagged.

Reset the pointer's tag by sign extending the tag bits in macros that do
pointer arithmetic in address conversions. There will be no change in
compiled code with KASAN disabled since the compiler will optimize the
__tag_reset() out.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v5:
- Move __tag_reset() calls into __phys_addr_nodebug() and
  __virt_addr_valid() instead of calling it on the arguments of higher
  level functions.

Changelog v4:
- Simplify page_to_virt() by removing pointless casts.
- Remove change in __is_canonical_address() because it's taken care of
  in a later patch due to a LAM compatible definition of canonical.

 arch/x86/include/asm/page.h    | 8 ++++++++
 arch/x86/include/asm/page_64.h | 1 +
 arch/x86/mm/physaddr.c         | 2 ++
 3 files changed, 11 insertions(+)

diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
index 9265f2fca99a..bcf5cad3da36 100644
--- a/arch/x86/include/asm/page.h
+++ b/arch/x86/include/asm/page.h
@@ -7,6 +7,7 @@
 #ifdef __KERNEL__
 
 #include <asm/page_types.h>
+#include <asm/kasan.h>
 
 #ifdef CONFIG_X86_64
 #include <asm/page_64.h>
@@ -65,6 +66,13 @@ static inline void copy_user_page(void *to, void *from, unsigned long vaddr,
  * virt_to_page(kaddr) returns a valid pointer if and only if
  * virt_addr_valid(kaddr) returns true.
  */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define page_to_virt(x) ({							\
+	void *__addr = __va(page_to_pfn((struct page *)x) << PAGE_SHIFT);	\
+	__tag_set(__addr, page_kasan_tag(x));					\
+})
+#endif
 #define virt_to_page(kaddr)	pfn_to_page(__pa(kaddr) >> PAGE_SHIFT)
 extern bool __virt_addr_valid(unsigned long kaddr);
 #define virt_addr_valid(kaddr)	__virt_addr_valid((unsigned long) (kaddr))
diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
index 015d23f3e01f..b18fef43dd34 100644
--- a/arch/x86/include/asm/page_64.h
+++ b/arch/x86/include/asm/page_64.h
@@ -21,6 +21,7 @@ extern unsigned long direct_map_physmem_end;
 
 static __always_inline unsigned long __phys_addr_nodebug(unsigned long x)
 {
+	x = __tag_reset(x);
 	unsigned long y = x - __START_KERNEL_map;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
diff --git a/arch/x86/mm/physaddr.c b/arch/x86/mm/physaddr.c
index fc3f3d3e2ef2..d6aa3589c798 100644
--- a/arch/x86/mm/physaddr.c
+++ b/arch/x86/mm/physaddr.c
@@ -14,6 +14,7 @@
 #ifdef CONFIG_DEBUG_VIRTUAL
 unsigned long __phys_addr(unsigned long x)
 {
+	x = __tag_reset(x);
 	unsigned long y = x - __START_KERNEL_map;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
@@ -46,6 +47,7 @@ EXPORT_SYMBOL(__phys_addr_symbol);
 
 bool __virt_addr_valid(unsigned long x)
 {
+	x = __tag_reset(x);
 	unsigned long y = x - __START_KERNEL_map;
 
 	/* use the carry flag to determine if x was < __START_KERNEL_map */
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d030a07c956c1e7cbf8cd44d6b42120baaa41723.1761763681.git.m.wieczorretman%40pm.me.
