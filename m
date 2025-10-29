Return-Path: <kasan-dev+bncBAABBVXIRHEAMGQESYESCXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BC5E0C1D258
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:08:55 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-78e5b6f1296sf7213956d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:08:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768534; cv=pass;
        d=google.com; s=arc-20240605;
        b=P1BiiGpNIBbjYUhynVoMnx4LUzMg/blfN5TaYXNpCb2xOUyg+Zm93qbB5nguzClmb+
         8JOSGGBTscksHMPneAQRJfpZjWW9z8oisUre/CDf3TXueydd3QrL1ZmDp+Qn7FH1ykXy
         v3vqwoyv9a+cdjTlZTe0rxJ4/mmNMLLt33prt0rEbr+0c7DG2c6PIa7GtuYDS7GYvW6z
         o29qgSHjkC6Ru7w+Qv9bMyw9MBCae+Q2o93KSjcAHEkRDy3AFQkiK05H0JFhJzwCdTPE
         hdRIgSSvz5WAsJpYuEWlyurd7P0eOkQ67gE3lG6uoQLjXPWywAD1BxkyBFCK6eMCtWNp
         3k4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=t/dVikdu4Qtt7SJ4nJJQVugasbxoZco6tWTXPQmkqWw=;
        fh=6UnIzaZ5bsMIwwd4qwpK3pAUy3R/NVnq6XgpkoEopWk=;
        b=X7PCtQdd+fHW07Wxnhi4JabBA0oEhEHo4l50L6hkmYrykmHiDGhR5XMjY7UQLsU3y/
         fJyxw0jopiJfClvhg34/Wa1GSA7HKfAf8F/QxKQeCMd5uSD8e7rMV3gUOT9oM52S4inf
         F+ef1wOdNWlk1YI99uLhp/uV0jaC49JKMqJOfAoNUdp6I2PfN/AKcSx18UWMUZf1TP/c
         H6utLDrD+PYXnIdu3Olx5o2pQB0Xkq6kihMbDgvkkPUlcb4RobSqjopajX/BFvQlk4OH
         hHa8rNwyBE6mYOU8rEByd6dKKX8NDl/NfnTRUVhEkDEhwypAuxQm2StgmBzSVxkgy300
         m6zA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=f2ixPvRO;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768534; x=1762373334; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=t/dVikdu4Qtt7SJ4nJJQVugasbxoZco6tWTXPQmkqWw=;
        b=HoX2vYqyF8BUw9Ofcrnf+JnMTc0onknSGzFhQ1GFkSFhKQGI5BMz+i1oSzUQ38lErU
         AhFFodq863mNEU79hV6TPzKVlxznwNVAxhDqKKVN0vYoST0Lf8Zx32AOlW8IvMzacn+w
         SW03yf3qq3gkU6GC9cZEK4LZhSGLlA6ogPJYOKHsriYozg/jUvXxzBzx8vs4EUXqeBiI
         f3eaqGv588HDhHXz5j0lDVQ2Wo0osb/rOXFw5cy8AQRXSnz7wqsrWzEOv7OLDVZ8ZAF9
         fGKXGSzC3yP+x1Xy8GhW4h0nIJLikIMUR4gMXSK5MgRFAvMUPbLrMFYfVpybZy3jRr0F
         YeHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768534; x=1762373334;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t/dVikdu4Qtt7SJ4nJJQVugasbxoZco6tWTXPQmkqWw=;
        b=nlXKGbujmTqazF78LJzfOpyeDDp8aX6pe9n2s9HprZBnCRl3h+2PrOQ3rSbuQ8nq39
         6l866J4cYKjg+lNMRvZXVvD8ifza+8tN1MdsjfgxRJ6A9WWyjyVtEJnI7d/RgHeYFZbt
         5uwHA6/4Iq/2JkCPjagOiwLIqwpxeyhuru0j2a2XDL0cboFKXm3wW6M31JK0MV/7rIm0
         Q3vHXJeaPFkBCXHMPDDo6H5uowqHIYGPpqJtfGs95BwmdUnN1DAlYKwJkqUCMvd5QcQR
         8vh8z/EhU5ErbD4OFijpJ68Z6SSUm0FNJLfXoomTOEiXU7/MRYFoQ4z3hUqmyxhZiOFx
         49yw==
X-Forwarded-Encrypted: i=2; AJvYcCVOzPXPm7lAD1DnSJvsECQhGmEkbe/JmiN+Y7NPFdyg7wA9s81CnH5eYjtobs23W02LTyC1Iw==@lfdr.de
X-Gm-Message-State: AOJu0YywW4inZVaFKwobjYQdAeiwJIjwyaSXjInkp1dhTHsOsK/N282k
	wuqE973Y+BlEFDd2P76537+R0Ag/0ZjpMs/lCMBQtufCzLlp0PkGhmnK
X-Google-Smtp-Source: AGHT+IE3+KbE9QEbjVg6d88Yf1LmyL1KCV8skLbgDBiyLM7gy4Ta7tUyHjbq8WFyI1ApUMVTpgB0QA==
X-Received: by 2002:a05:6214:c6c:b0:87c:176d:b464 with SMTP id 6a1803df08f44-88009ad53famr54611176d6.8.1761768534457;
        Wed, 29 Oct 2025 13:08:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YhcljOypvxg51cFDQXrF4VoWaQcULrbp9Oo5gpmbptaQ=="
Received: by 2002:a05:6214:4892:b0:70d:9fb7:7561 with SMTP id
 6a1803df08f44-8801b53f42fls4369676d6.2.-pod-prod-05-us; Wed, 29 Oct 2025
 13:08:53 -0700 (PDT)
X-Received: by 2002:a05:6123:2eb:b0:558:251:f0e8 with SMTP id 71dfb90a1353d-5581423c68cmr1470163e0c.11.1761768533773;
        Wed, 29 Oct 2025 13:08:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768533; cv=none;
        d=google.com; s=arc-20240605;
        b=ju2iKtdopDS9q1VaDXLteWLoTBmdf2xzbuS3YAUaiFxPsMcWSlRWHu8hSG9T1VC1Nr
         vqUz+phMs5bIIuUAUTmgWUloTyxPYcReYogcfFgLMzP2bYKe2G90RBZNUN2YouHbplV2
         6lGU3f0SFpHdvQHDA24knuC9rGj+TD7LRscpVLytH45E0dAb/c9HwLPbf5liRcMKMO4V
         ixpWcSVtfLqIkLIbgz5dIq/RzFWfmJKgH2y0hYlV1Gifgo1Xeryugrx2+6EX0HM/r946
         5m9Sky7nnT7e7mnCfwA+7nnnunLpE0UhUGOAknRQ/cl9GoU/OPJl1bV8IUHm5CwPwUED
         Du4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=+vFEd2i7cGwKfB76083zqMnaJRzsau0IVtzvsF2hHkA=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=Xu2r/iwqc7wA/tvGU3cu45to7rfPXuuTh32AvPd5Bqxn3Ws2VwevUU+4g3D0li54GW
         HR/FHFWoJ03hpAe9gsD3ppmyGqEannGBjuqfvmpCrCLW9GsDZJ1ZVcJ69jU0oa3ZOSiW
         tj9ihpzJMaGDU+kQgYXNBsQ1vSOkE0R9qTz6hqaUJo1royYe2APxYiuN2wy7GB8lblTF
         Vdlz7jnt3XCrYOeb42UTaIdzAgBtMA93gT6yY0F94IJAJs5W4wJ/FcQoc7JJFx+lh7yw
         EPZxdxcjWJhxNe03Mva3APQvDdgYklPk0bu77DRSeWXwKpoL1lGQtkvlhQ2cBsp/pTk5
         6vCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=f2ixPvRO;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24417.protonmail.ch (mail-24417.protonmail.ch. [109.224.244.17])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-557deb4d8b4si767525e0c.0.2025.10.29.13.08.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:08:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) client-ip=109.224.244.17;
Date: Wed, 29 Oct 2025 20:08:43 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 13/18] x86/mm: LAM initialization
Message-ID: <96559d5a8e897f97879259bad3117db617e21377.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 0e1842514ef97eaa33355f60d534577848d5c6b8
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=f2ixPvRO;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as
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

To make use of KASAN's tag based mode on x86, Linear Address Masking
(LAM) needs to be enabled. To do that the 28th bit in CR4 has to be set.

Set the bit in early memory initialization.

When launching secondary CPUs the LAM bit gets lost. To avoid this add
it in a mask in head_64.S. The bitmask permits some bits of CR4 to pass
from the primary CPU to the secondary CPUs without being cleared.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v6:
- boot_cpu_has() -> cpu_feature_enabled()

 arch/x86/kernel/head_64.S | 3 +++
 arch/x86/mm/init.c        | 3 +++
 2 files changed, 6 insertions(+)

diff --git a/arch/x86/kernel/head_64.S b/arch/x86/kernel/head_64.S
index 21816b48537c..c5a0bfbe280d 100644
--- a/arch/x86/kernel/head_64.S
+++ b/arch/x86/kernel/head_64.S
@@ -209,6 +209,9 @@ SYM_INNER_LABEL(common_startup_64, SYM_L_LOCAL)
 	 *  there will be no global TLB entries after the execution."
 	 */
 	movl	$(X86_CR4_PAE | X86_CR4_LA57), %edx
+#ifdef CONFIG_ADDRESS_MASKING
+	orl	$X86_CR4_LAM_SUP, %edx
+#endif
 #ifdef CONFIG_X86_MCE
 	/*
 	 * Preserve CR4.MCE if the kernel will enable #MC support.
diff --git a/arch/x86/mm/init.c b/arch/x86/mm/init.c
index 8bf6ad4b9400..a8442b255481 100644
--- a/arch/x86/mm/init.c
+++ b/arch/x86/mm/init.c
@@ -764,6 +764,9 @@ void __init init_mem_mapping(void)
 	probe_page_size_mask();
 	setup_pcid();
 
+	if (cpu_feature_enabled(X86_FEATURE_LAM) && IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+		cr4_set_bits_and_update_boot(X86_CR4_LAM_SUP);
+
 #ifdef CONFIG_X86_64
 	end = max_pfn << PAGE_SHIFT;
 #else
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/96559d5a8e897f97879259bad3117db617e21377.1761763681.git.m.wieczorretman%40pm.me.
