Return-Path: <kasan-dev+bncBAABBPHIRHEAMGQEIAT4W7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id AAC63C1D246
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:08:30 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-592f857601esf173745e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:08:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768510; cv=pass;
        d=google.com; s=arc-20240605;
        b=jyrjPCD7UkrWlfN5bf1iOtEl6z8NLoNGwHDGu+dikbMc+tLJPcpBrioDj480ZcWYa9
         VzaMrFCQ4/Y26lrF7CSFILdBaJ5plPEYpGfThYhVt1BjmmdXouaqGz8v7wY/+ahjQEd4
         LEmVHBxGySYN+otLcmZZ7KT1ZDg+6b3spifwlfixlUlkcAsLV4VgJboT+Kg+hEGLTpRz
         HnpPPe4I6OHZV1F9Zz1dirzpWp+kOaQSacVJ3vw/tNMr9lGbQxFZXu8HVJKis5gVvGmP
         SrWsi65rt4f0YjLM8quRe3iv/SzHULtdmQKrrIjRpdS31ABUdywlWf19rWPb6YjXkOQZ
         UlrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=yCzzQYHU3hUtIFIYsK6ZMg+g3Of5p+LP9rowKuhqpXk=;
        fh=OhTEQM87/Lou04UB48NP/AJl+IpDH8vMAK0fL0AJBkw=;
        b=euE4Nr5DwStvtq39RdwxM/FkkNaHc2eIu0DeSPdLnFsTyC8gzDjjgYFzzit/kfiA8i
         qgHxO1AcDKr2c+EFBs1Wdpj/vYYpMeXdCYVK1g6gHlGMSB9P8UrXPtfFKDWUMg9AWFDy
         LqIyrum6aFwFwXCQuYejDNxlQxjN0ggSbDfafeZWBbtQ4WydQc/fa5yi1SjbCMBgegc+
         57s36+dy6JB35YQv9zm6dEKBxwdur/tVRzSRk00pE4ubpbNgxG5BMGBhYNikepw5ntLz
         i6HtbEbfBB3nHFwjiY9OcAqyTPuJlztgfeZDZ356SjsV9AYJdYnFQZKJK2EWI0DCoZU/
         kgNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=f1ahGvJ8;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768510; x=1762373310; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=yCzzQYHU3hUtIFIYsK6ZMg+g3Of5p+LP9rowKuhqpXk=;
        b=UNuBxDpJ4ue4dgEy2NsvvVCutawzvZZICJFO2j0VpEPoA6yseGLRDYYkL34SXYltsE
         7PRxPhTdgadRh71s5dmw6vnoWLgbFQk7Dt+fOcuiI0Se+/lutKgxdgQ9p+lcMQuz94Lq
         aXgrWBOQ+EmT6oIHJjY1ppt+QXkCNph7JGpUoJxmiHaQNX/U2vo+uWUHYobC8moyIG1P
         ydijPe8Zkk0hw3ouUOE9WRUK1xz0GCj14G01rxlQNvcPjLKwPZis/C3LFOg0lVK+2d9T
         HENoY++GIt5iWsIgq0g4IJyPiz9YP/rpRuYqjxhSt6eURa9Gri06cFx8GEpsgj5RpmAt
         ut7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768510; x=1762373310;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yCzzQYHU3hUtIFIYsK6ZMg+g3Of5p+LP9rowKuhqpXk=;
        b=JJGup/OlVI7WwnDld7X+aP7zwmd5QwG+F8F0Gc+eu+dcMkzVE1tIfQpE4iQtasl3Y0
         mVsE+fXShKv87zqdkYwwdPY9b0PGzCZig7W3t80DNENbK5bsxBNyTLGHLpELeAqbi+NH
         ErgKbo+mFY7PxQsUa5S0DFEgZpqHa8SfXOG47Tgi2CbRDUHnmOVyWpZh4mm1aonVkNAF
         mAlGh+gPaz6Kc/aGlmX8b3bmyeLHs0Y5e11cd+HCB5VkDZ6C1gIwFTw8mOrp9XGLsvpY
         vLWDkj7M4nwot90XOZLiooQEOl7G8Aa65YQALYMS97bjav1CfWc4LgAezhBMSmvd2UNb
         wHZw==
X-Forwarded-Encrypted: i=2; AJvYcCUplzrf99lAQ9qttGiBvtCWTLYlZt0UBQJNKjOgKRG5qoDhmR6EDWUOl2wHz2hUrwMMbOMUfw==@lfdr.de
X-Gm-Message-State: AOJu0Yya3GD/k5OuSzbWhBelWiMdyx6nObxf0bewlgNO1S784pXIfD++
	S4PUWR2n0CkvYYwb1FTdBlxo+1JHKk5bBSSHZPi/NLap7jpMGVbzyuUA
X-Google-Smtp-Source: AGHT+IG5JVvf9SVITLbt70QXFeNRl1SE6ON2QN7+zN7LNrBrRLnoKElLsn9DFAuyUFnZ1CCiduorHg==
X-Received: by 2002:a05:6512:3da8:b0:55f:6f5b:8e65 with SMTP id 2adb3069b0e04-594128cbbbdmr1304079e87.30.1761768509619;
        Wed, 29 Oct 2025 13:08:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bdl/RHjNgXyM5a2nm1VV/xqJYLaZPm2ogJ7rsUN3vuyA=="
Received: by 2002:a05:6512:3c91:b0:590:6c0f:4e4c with SMTP id
 2adb3069b0e04-5941763473fls48046e87.1.-pod-prod-02-eu; Wed, 29 Oct 2025
 13:08:27 -0700 (PDT)
X-Received: by 2002:a2e:a54c:0:b0:355:e2d9:9c8c with SMTP id 38308e7fff4ca-37a023f8e30mr13575041fa.28.1761768507119;
        Wed, 29 Oct 2025 13:08:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768507; cv=none;
        d=google.com; s=arc-20240605;
        b=Tz6hibm1Cs0RsNRuUKRJfZZXFIOCjbxmC7FjggZi9xG1dNDdCyMx4H0ECMo8vDFBkP
         iiqPj/ugQl+CVkVy0p+EomIC6E2cupEej+Fw6vjQeZPWirYmse5QDFpe1qalLOG3a4VY
         yg5LHm+EvoiW+rlzVc5v5NbpQbvrzLmNI0fXjdayuoL1ZAcLYcPygs65MBQUZfIl4pvq
         wpFqODUAOeaZjDLcJ4kg7MOhmwx3coAbAF3mQa4z5Clqi++dcDTQuGh/xwBdynXCgSKJ
         h1eWMDU7DiinJ4UfUCtVcG1Sxtl/7jR1OQdGwwhMbqmGCJqBkwfkI3yFHa6MSXmp1/XK
         Cjog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=Ye8tYnzEiAyAJOizOqIrcZYSk2K1DbVUwkfvl955amo=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=Hgc6wd6/zEYIuID9ZcylPI5UQ+YbrBBZkPMsM9NPB6SC54wnbRyd8JFK9m/wfJib2V
         3oGC5MOLhwb+Wc+lZQW9yiLjI1skV9RTDeiU2ZkcdB+SPnIDmly7lINfIahVBYRbCfRL
         1/bet7ADEU4cNlgAx9ItWrGHStTDLHSYT+y67jJY/F0oz5lufvzwSwF75bh4GNQTPMFp
         N2mUb7qQa9HpFgA7/V4p+yNMp1UAt+3k/Oi3RHKCPlDu2Rd32hUEBlYLYZQ09d5hKOZV
         8XtVqZpEz72lhes3tzdiXtJK8WnGeBRzFN6RwA/92EJlNRglJrelFgm2YIxKWdJUmZqy
         cc6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=f1ahGvJ8;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378eef3be91si2187011fa.6.2025.10.29.13.08.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:08:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Wed, 29 Oct 2025 20:08:18 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 12/18] x86/mm: LAM compatible non-canonical definition
Message-ID: <56d9203b1fcb6281b0d29b44bc181530e5c72327.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 015c7fdaea374a790951b755b565538ef4bdd04b
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=f1ahGvJ8;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
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

For an address to be canonical it has to have its top bits equal to each
other. The number of bits depends on the paging level and whether
they're supposed to be ones or zeroes depends on whether the address
points to kernel or user space.

With Linear Address Masking (LAM) enabled, the definition of linear
address canonicality is modified. Not all of the previously required
bits need to be equal, only the first and last from the previously equal
bitmask. So for example a 5-level paging kernel address needs to have
bits [63] and [56] set.

Change the canonical checking function to use bit masks instead of bit
shifts.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v6:
- Use bitmasks to check both kernel and userspace addresses (Dave Hansen
  and Samuel Holland).

Changelog v4:
- Add patch to the series.

 arch/x86/include/asm/page.h | 25 ++++++++++++++++++++++++-
 1 file changed, 24 insertions(+), 1 deletion(-)

diff --git a/arch/x86/include/asm/page.h b/arch/x86/include/asm/page.h
index bcf5cad3da36..df2c93b90a6b 100644
--- a/arch/x86/include/asm/page.h
+++ b/arch/x86/include/asm/page.h
@@ -82,14 +82,37 @@ static __always_inline void *pfn_to_kaddr(unsigned long pfn)
 	return __va(pfn << PAGE_SHIFT);
 }
 
+/*
+ * CONFIG_KASAN_SW_TAGS requires LAM which changes the canonicality checks.
+ */
+#ifdef CONFIG_KASAN_SW_TAGS
+static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
+{
+	return (vaddr | BIT_ULL(63) | BIT_ULL(vaddr_bits - 1));
+}
+#else
 static __always_inline u64 __canonical_address(u64 vaddr, u8 vaddr_bits)
 {
 	return ((s64)vaddr << (64 - vaddr_bits)) >> (64 - vaddr_bits);
 }
+#endif
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define CANONICAL_MASK(vaddr_bits) (BIT_ULL(63) | BIT_ULL(vaddr_bits - 1))
+#else
+#define CANONICAL_MASK(vaddr_bits) GENMASK_ULL(63, vaddr_bits)
+#endif
 
 static __always_inline u64 __is_canonical_address(u64 vaddr, u8 vaddr_bits)
 {
-	return __canonical_address(vaddr, vaddr_bits) == vaddr;
+	unsigned long cmask = CANONICAL_MASK(vaddr_bits);
+
+	/*
+	 * Kernel canonical address & cmask will evaluate to cmask while
+	 * userspace canonical address & cmask will evaluate to zero.
+	 */
+	u64 result = (vaddr & cmask) == cmask || !(vaddr & cmask);
+	return result;
 }
 
 #endif	/* __ASSEMBLER__ */
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/56d9203b1fcb6281b0d29b44bc181530e5c72327.1761763681.git.m.wieczorretman%40pm.me.
