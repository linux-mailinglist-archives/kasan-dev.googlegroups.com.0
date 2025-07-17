Return-Path: <kasan-dev+bncBDCPL7WX3MKBBYUM43BQMGQEXPFHJBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CECAB0973E
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3e29380e516sf16381055ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794723; cv=pass;
        d=google.com; s=arc-20240605;
        b=kzskrRD3lMiBj8l1KAeSWvaGfmW6qPYam6h+uv8eZPpYGcKc18RiIFNo4q2ElM5lEz
         sYtymd33DF6SDL2JQQrzyJEBV6u9Dew9ud9g+al8UpJyDDGZ9+lMQaNH3X8yLSxBRRYW
         cjrZ8xzk0miEZ/6BAyVFpFPu/Hh6Jxu2xc8l/ET8FH33jLHKw02uEF+mJLPlLVHmqqU1
         g3FAMVAFMg1Vr/BESLnJhSDIDDo9/EJ94kpN8FEgsPe9o8EYUSC2rANAax09D72ICirb
         cJw/Phf8ZZoGO/oAIgxscdbL4RX81IseWBh/K+Kyg1yDyUIc6wu2IAz7OdocjflOQ/0D
         QA+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DrLYrcSBbkU37Zzjl57PHSM/iA1Nsw9M1kXOP9fTY8o=;
        fh=T4xrCzLFilM+hYWronkuuKpMovQOKtz1KJaOaAsi8OU=;
        b=QTAUoWtK5McdSbq9UOZIlrc0FGZgyscWYSp4tqpuMeY7s67ayWHTElKGb7/Cuf5HUU
         NuWgpOV8dxeWnCUAdpbWcqhuZIOnOknUxuLC8pq0sC8hiMmpf2sJpdKL/SjiQ6WzIpjU
         VmUxgr6wRELEHkQ/SDEsLrsBwAdjgxi72yn8dXEVnZNsChYIkibiGiOcBPjc8JXQU4IN
         4EA1+u9FPUlpsRi5j2es34Y/3fBKJkmBY4JFvjNCYnC/gZxeeoPNQqwUjqEjtQK69rvt
         FKtrm2nA5Vz7tQNelO3To+BxjivLOk7mAhnqKx1LzdZilNKCstjMI3zE52RYMvcSykYl
         Ghfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ncp2Paoy;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794723; x=1753399523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DrLYrcSBbkU37Zzjl57PHSM/iA1Nsw9M1kXOP9fTY8o=;
        b=P2fGu7a0Q2G/8Et6lZ8jvGUk9WHUc9G1O6KAnRHjsuOo+chb0wGCbVEzGLHCwsbuHS
         UZcTOJ24ZWlOWJWaHWu3jupwLsAEJybDUWPNRXBqYrCv49Yx5fog0NeUeN5rW8AqydRv
         AgX3SXWQDW5TqYiPwdDwE5T6Q6Nr1lxm/Bf6A3TCebQ9Jjvi+2LFW4UrwwvroZ2X+bMF
         Gp5cizRmSmRtVNLeoyVcfjcLkSxss3VoMGp5y2fpXC3x7oq6vMUi32us+CRS2IvC3xpk
         2X5Ka60OUEjQhFly6F5A2P7MQ/XUX+q1SJcjbOL0ZGv6DD2k0CyQGgAnwivAvf5WvFnF
         fNrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794723; x=1753399523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DrLYrcSBbkU37Zzjl57PHSM/iA1Nsw9M1kXOP9fTY8o=;
        b=tkXbENFRsh21fkILylvifhcwoP7NjfxWpIb1dy5ELB3RIgtxor2Q47jGtZdq36QVSU
         f00RTAJjyVtxY0ict/vsmTmZU5Lva91ULscGIEBCB5Decaosu6+kxDKFt4uBBP4yP1ub
         MID4y5KJ7n2cyUMBfIhogDcx8V/l0Dn9qHtKK+W+tE8W7uVzpTLNr4R10sJJbIZP8OfU
         ywEUWo6bhDpLY/uZobEjO5zEnyyCI70GF2H8dbiRROSOecaSqYyW9tdAMrZ6ZiE5MN2N
         2jjatbkLiRwAdyL4NyxvkN/OsxYVsoqGuktmYhttsdNRv+qTBeGu2HPqrVIbW5cty6K7
         Wd6w==
X-Forwarded-Encrypted: i=2; AJvYcCV8nlElXq70NqzaNrt5CE9dB3x3Zm8ijrIIitt6RWTkoHJz1Q0a0Cu5baADKFJvJ+18wmyUSA==@lfdr.de
X-Gm-Message-State: AOJu0YxYEOwxc0cpZmGDz6PEfnK9qTSDZhxkbNP8H+C7mnR2xKsnUWoV
	ARpC9lqYRnU6JgqoilRgViNmyl7bIpfrvNnW4nyWbinuJsRVjuO21EcA
X-Google-Smtp-Source: AGHT+IEh0TY10mQ/YON017pZ7mmuNNd/wtUzEacU1By4QzOwHKvi/fWUO1dksWw2OHlLcl8ak2U0Dg==
X-Received: by 2002:a05:6e02:180f:b0:3e2:8770:8f78 with SMTP id e9e14a558f8ab-3e28770a04amr85287855ab.22.1752794722725;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcgTh4hGXk5yAKU18jWWkdlMgsGneblHPbBNEmgbcD0tw==
Received: by 2002:a05:6e02:4614:b0:3e0:5846:49 with SMTP id
 e9e14a558f8ab-3e28ae19effls12366195ab.1.-pod-prod-01-us; Thu, 17 Jul 2025
 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFaPSLGYwEewfc2BiWBO4073O8oCHZz5fWNvoRX76YDBSONoq8D7utxCwU5c/eYY1+21q2pzM1nuI=@googlegroups.com
X-Received: by 2002:a05:6e02:350b:b0:3dd:f743:d182 with SMTP id e9e14a558f8ab-3e2822fce43mr103261425ab.5.1752794721930;
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794721; cv=none;
        d=google.com; s=arc-20240605;
        b=A7idLqMzvT9tMay9g2Sxm1HtL2g6vVxKtDIWXM+LMXWbbhBCVyBRzPqD59c6TmtUMU
         koOSXoVsmKqkc9UAkgrsrrl+OvlJSjZd/1uJdN1HMp9pt7jA1Ws0FEWVYaHYHlLhUpbf
         l2cJ7AFTeU+ej/ZdZSJjOSA2MVR1Ka6h/y3xzu4Q4ZQBsONBYltHXYsU2Zt1T2/zo/uh
         GhUBpOsnhrnnkYL/Kbzu86PaIGXPJcq7lYGyWqKCozWs0yxnWOK7qoJJFDl42gX+5Ue+
         IUKeQBlwfBlVomDYzADDdmpf2n78qX0qbJNpVLSImlR72z1UmJPIA70IDacILYGjVigx
         kbGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Io0O9ivrDSI7ib4HbNGMnvrCvRBFdYG2jjlaeqr/xtQ=;
        fh=V4HowUP2NC5NbNu5MBuG0tqRpGlVpCML0hPcIjOcdAY=;
        b=UlpABJPF8S22ktcrCpSgLIKBYNvhPX9epKupLqu2IFa1MLYJWAnOrMCARe5oyXB/sv
         XCCjNo0D0JXtJ6m6uyQOKSo224il3px5FazYuK7lUBDaT31Gt6Btzhfi8SUA3LbsbdEi
         yAOb2YcWNodqaNvVZAarq//V+VQm6MoqWEOb0KpCLPmGtZj9OEjw1NbEh3GOk7tNWNlg
         no0S0UmngzUPG14bNId8ZJ2d1dI0oC+uRWBIz+3utKjvzsPuBkeBKr3lcAgTmo113/mM
         17k61VsJXAKszHdYvHVQVeNtm7+totaquPL91OyPdw5v6jc9+EEZgnpT/M3HzxtdFUEz
         60MA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ncp2Paoy;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5084c91b927si8004173.7.2025.07.17.16.25.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 534EF5C6CCA;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 91A59C4AF53;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>,
	kernel test robot <lkp@intel.com>,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 08/13] powerpc/mm/book3s64: Move kfence and debug_pagealloc related calls to __init section
Date: Thu, 17 Jul 2025 16:25:13 -0700
Message-Id: <20250717232519.2984886-8-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3037; i=kees@kernel.org; h=from:subject; bh=CG642rxsBTdbPAtwaZfuIeBH3/DpJlnhh8PcAMrPPa0=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbTEqNd9vzJzycNaO4gcXLpt8qbN9PS/KjKft9UGzD eY5vwSjO0pZGMS4GGTFFFmC7NzjXDzetoe7z1WEmcPKBDKEgYtTACZSI8jI8GVbRcbCExcPa6wy fDZNO+lvONfEslf91zgk5+/tDwzasp+RYXdX0OYrJ9+2fley5O3+YLKGlStl6nnrVzK5ghu5VvP GMQEA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ncp2Paoy;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
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

From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>

Move a few kfence and debug_pagealloc related functions in hash_utils.c
and radix_pgtable.c to __init sections since these are only invoked once
by an __init function during system initialization.

i.e.
- hash_debug_pagealloc_alloc_slots()
- hash_kfence_alloc_pool()
- hash_kfence_map_pool()
  The above 3 functions only gets called by __init htab_initialize().

- alloc_kfence_pool()
- map_kfence_pool()
  The above 2 functions only gets called by __init radix_init_pgtable()

This should also help fix warning msgs like:

>> WARNING: modpost: vmlinux: section mismatch in reference:
hash_debug_pagealloc_alloc_slots+0xb0 (section: .text) ->
memblock_alloc_try_nid (section: .init.text)

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202504190552.mnFGs5sj-lkp@intel.com/
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
Signed-off-by: Kees Cook <kees@kernel.org>
---
 arch/powerpc/mm/book3s64/hash_utils.c    | 6 +++---
 arch/powerpc/mm/book3s64/radix_pgtable.c | 4 ++--
 2 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 5158aefe4873..4693c464fc5a 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -343,7 +343,7 @@ static inline bool hash_supports_debug_pagealloc(void)
 static u8 *linear_map_hash_slots;
 static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
-static void hash_debug_pagealloc_alloc_slots(void)
+static __init void hash_debug_pagealloc_alloc_slots(void)
 {
 	if (!hash_supports_debug_pagealloc())
 		return;
@@ -409,7 +409,7 @@ static DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
 
 static phys_addr_t kfence_pool;
 
-static inline void hash_kfence_alloc_pool(void)
+static __init void hash_kfence_alloc_pool(void)
 {
 	if (!kfence_early_init_enabled())
 		goto err;
@@ -445,7 +445,7 @@ static inline void hash_kfence_alloc_pool(void)
 	disable_kfence();
 }
 
-static inline void hash_kfence_map_pool(void)
+static __init void hash_kfence_map_pool(void)
 {
 	unsigned long kfence_pool_start, kfence_pool_end;
 	unsigned long prot = pgprot_val(PAGE_KERNEL);
diff --git a/arch/powerpc/mm/book3s64/radix_pgtable.c b/arch/powerpc/mm/book3s64/radix_pgtable.c
index 9f908b1a52db..be523e5fe9c5 100644
--- a/arch/powerpc/mm/book3s64/radix_pgtable.c
+++ b/arch/powerpc/mm/book3s64/radix_pgtable.c
@@ -363,7 +363,7 @@ static int __meminit create_physical_mapping(unsigned long start,
 }
 
 #ifdef CONFIG_KFENCE
-static inline phys_addr_t alloc_kfence_pool(void)
+static __init phys_addr_t alloc_kfence_pool(void)
 {
 	phys_addr_t kfence_pool;
 
@@ -393,7 +393,7 @@ static inline phys_addr_t alloc_kfence_pool(void)
 	return 0;
 }
 
-static inline void map_kfence_pool(phys_addr_t kfence_pool)
+static __init void map_kfence_pool(phys_addr_t kfence_pool)
 {
 	if (!kfence_pool)
 		return;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-8-kees%40kernel.org.
