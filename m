Return-Path: <kasan-dev+bncBDLKPY4HVQKBBIPAQOBAMGQE6FKD2NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D22A32D55A
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 15:35:14 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id g6sf9946285lfu.13
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 06:35:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614868513; cv=pass;
        d=google.com; s=arc-20160816;
        b=xCnlumRlAfgQ5lj/E7mmeTkd83j0Y+R4i5cuobobavpBa2UaRJogeBl8vvL5U6l3ZH
         v5SEKJ0L4Ffrh9BySFhlYP9sX4bq7jzk0Uivep7m58g7npdxM+TQ7ovNCxO15hFNT7dt
         rLnpPPrmONO8HwlV1Zv5/bXPf+2wcbj56CmOkDL6l/+p6ai7LddWyVmmBh/+ggn5nlv4
         1KukigWvx0AKdlMErJUzJFWrXPhaWdsjoE8XjYimkQJQAk+j0fI8r0oBO2Ev8JWicppt
         NeoU0NJ8D0VWrMptARf/KmrgtEeF4slp1+dOZ4qikj0ss1Y2TqXPLY0H22ba1DHqoRqu
         I9Tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:references
         :in-reply-to:message-id:mime-version:sender:dkim-signature;
        bh=TWSyEGt0s0cKNB/GKn7IVQzTnjkjifBeVdHqyG4wjg4=;
        b=sYa9g+cY/7ceDyw6KobB1JDO7MosN4omHO35iRIyziHsVQNAau8cIecba7eYnTFDhu
         c6QhEVHX+6ugvEKLkelngCqKGS7izFs2AQFgWin/lSFU9TcPGXsQ07WAqfSxXLGDk/HG
         +hA8Ya0lRIeN6Zlxj8TjfZho8tumZT3z1EXiutz23A70LopDwQHdymoIPOjMwDB6ZF7L
         +6lv+d0eZqEcReZxo03sWbBZfOnCmEN/wtmKPCJUwM3poxA0a3YjrAFVZ1u3gWxGoliF
         yiGtOah2OfZctuquZNy0Rzu8N5LE/FgItofWxAqxOVeYvihYIeT1/ThLshsG1ec5ssao
         1AUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:in-reply-to:references:from:subject
         :to:cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TWSyEGt0s0cKNB/GKn7IVQzTnjkjifBeVdHqyG4wjg4=;
        b=GlavuPXVQJib4hqzX7n5MVDNGBsd0wlmcIcnU1ihhBCAoJH8I9WcxVIvC4yITYz/np
         OWMlIq8eg2XTxLGxC6MZLnLuLlz6hN7BjOCDzSYxzcA2tRamiK4zqhFV3W1UwXXg/8fm
         Bmn10nQDwdAj4zGlN7gt6ZkzQBHt9/Bq82O7EPRTJexU1Tq7w/d/JiEoL+Ul9yRPDe8+
         aFXctoQ1MT6gPXpmVZ7uoC6408+Gn1QDvkZ69OmssYNpM1r7WYkoB+aXcP/q7V2lyFmH
         JNyzFAlEonPbYiHEL8srEjXT3NwYvthQ6A2VkxeG6wWDSBv0uL2TJz/yYrFehpYHRzX6
         w3Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:in-reply-to
         :references:from:subject:to:cc:date:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TWSyEGt0s0cKNB/GKn7IVQzTnjkjifBeVdHqyG4wjg4=;
        b=a82eu3Wf2N2kJ7edjBs2ZmYSqfMYhNOGSxKjFd+EYZNIDoKxRQjSMSHvD3/3EFv35R
         5kh8tXXk2kx5iuBYfnpxXrC2zOoaRjXyQ4Vvn4genI7ApsnljRYty42FWSi6AZNb+3VC
         k6eO4kB+sWF0mjMhGzJdFxUWqS4x7t5WBwa33EKlru4BxP2r3cxUxkUT25Dj5fTHCuaq
         cDCSWuIaJftBJNvdtfa8Nfo3M4IsNliJwHpshdiWmaXQBCa3Sd2Nw6MIZibt4/whQzSr
         kwr1N5lY/aIM7y7wCA3MJ9oEvwUmFSXp2XRAPVRkw41wwg8C5ILQPpReHdPQqVZk9PGm
         Efyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HEpUXjHnDxgaMwgAQjEoE8fHe6RwxtI1+baKIKVBeA/gUTY/0
	B6XyXwQBeseeLWiYhSjvk88=
X-Google-Smtp-Source: ABdhPJxHK6cYlqTlsvgEQY2CP8KaD3AAgacmqOF9P2DPBQhNgPs0OW1kEKd3LhOABYyw1wXizqRkSg==
X-Received: by 2002:a19:b81:: with SMTP id 123mr2405541lfl.553.1614868513757;
        Thu, 04 Mar 2021 06:35:13 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:e86:: with SMTP id 128ls1112850lfo.0.gmail; Thu, 04 Mar
 2021 06:35:12 -0800 (PST)
X-Received: by 2002:a05:6512:39c3:: with SMTP id k3mr2402701lfu.501.1614868512725;
        Thu, 04 Mar 2021 06:35:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614868512; cv=none;
        d=google.com; s=arc-20160816;
        b=lojrCdu6Uishj3i5zeDrjmlA3bdtDgjVUIhS31lLygjjgiGJtO9hQkWG8xQasXX5gU
         ohNE5KBEl8cjJkra/5UvtYRazRhSTJ6gxJa0TL8DyxEr6QUZxgW4nek5yrY0MgPRcyGr
         wIe+5BFiCBwZrRTUGpi5PIvG03exGP1+5ETGlZUfO38pRzLPLy6UNAwBkB+L7OPadfQV
         qnHyauTQ2mdyIhTg8KDqulxes8pAhy3WOJGj7pBItnScmypHputm5xdpkT176MFx7XJA
         iupGY0EbIv4gRNvm5NGeZYbhGbfapsMN4GIIlnZY8Rox7rd36igdMIGGihUnmxCI77LC
         5YZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:references:in-reply-to:message-id;
        bh=zbdqzi/Z7mnQG9J+xJMlXYZC647GQJr7IhM8mhpRnME=;
        b=vFj0zZGq9PU0rKLql1cECD1hrKV+7SJhn+/i9SValg3b9eGcf52wXunOHRo9x/rhuf
         8IjSNkeOwg8BnajASAWUjfFGCWRw+PwEz0IvSGJ6+iDpDYSXKuqSCMDmKH2jXsvS+qkF
         l+GoFmeTZIP5tb8VF6EjcVVBNYMj0hRAoyRYcOcmtrn44UXAmeZmV9yh3P37X+dCjghh
         eeAq14X9sZstDWX+cUtmz+j55K8DAs/23ewXSCTVP2wr31uqxyP2sEZ9hwEJ46VIruiU
         kLo+SVxqwLenUp/E92RxZq8fiCrmvVdWEDa6WJ1Hsqc1of/e1eHdlgYQe2ulfWpA6lWm
         7ZmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id a17si816443ljq.5.2021.03.04.06.35.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Mar 2021 06:35:12 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Drtgf0vL7zB09ZT;
	Thu,  4 Mar 2021 15:35:10 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id 254bjqZR_w5x; Thu,  4 Mar 2021 15:35:10 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Drtgd738NzB09ZR;
	Thu,  4 Mar 2021 15:35:09 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 08E338B812;
	Thu,  4 Mar 2021 15:35:12 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id YDcYJiG_9v7g; Thu,  4 Mar 2021 15:35:11 +0100 (CET)
Received: from po16121vm.idsi0.si.c-s.fr (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3ACD58B80A;
	Thu,  4 Mar 2021 15:35:11 +0100 (CET)
Received: by po16121vm.idsi0.si.c-s.fr (Postfix, from userid 0)
	id 16082674E6; Thu,  4 Mar 2021 14:35:11 +0000 (UTC)
Message-Id: <33441f41f6ff51807c22207f213a645dc5d1d8da.1614868445.git.christophe.leroy@csgroup.eu>
In-Reply-To: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
References: <8dfe1bd2abde26337c1d8c1ad0acfcc82185e0d5.1614868445.git.christophe.leroy@csgroup.eu>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Subject: [PATCH v2 2/4] powerpc/64s: Remove unneeded #ifdef
 CONFIG_DEBUG_PAGEALLOC in hash_utils
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Date: Thu,  4 Mar 2021 14:35:11 +0000 (UTC)
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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

debug_pagealloc_enabled() is always defined and constant folds to
'false' when CONFIG_DEBUG_PAGEALLOC is not enabled.

Remove the #ifdefs, the code and associated static variables will
be optimised out by the compiler when CONFIG_DEBUG_PAGEALLOC is
not defined.

Signed-off-by: Christophe Leroy <christophe.leroy@csgroup.eu>
---
v2: New
---
 arch/powerpc/mm/book3s64/hash_utils.c | 9 ++-------
 1 file changed, 2 insertions(+), 7 deletions(-)

diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index 581b20a2feaf..f1b5a5f1d3a9 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -126,11 +126,8 @@ EXPORT_SYMBOL_GPL(mmu_slb_size);
 #ifdef CONFIG_PPC_64K_PAGES
 int mmu_ci_restrictions;
 #endif
-#ifdef CONFIG_DEBUG_PAGEALLOC
 static u8 *linear_map_hash_slots;
 static unsigned long linear_map_hash_count;
-static DEFINE_SPINLOCK(linear_map_hash_lock);
-#endif /* CONFIG_DEBUG_PAGEALLOC */
 struct mmu_hash_ops mmu_hash_ops;
 EXPORT_SYMBOL(mmu_hash_ops);
 
@@ -326,11 +323,9 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-#ifdef CONFIG_DEBUG_PAGEALLOC
 		if (debug_pagealloc_enabled() &&
 			(paddr >> PAGE_SHIFT) < linear_map_hash_count)
 			linear_map_hash_slots[paddr >> PAGE_SHIFT] = ret | 0x80;
-#endif /* CONFIG_DEBUG_PAGEALLOC */
 	}
 	return ret < 0 ? ret : 0;
 }
@@ -954,7 +949,6 @@ static void __init htab_initialize(void)
 
 	prot = pgprot_val(PAGE_KERNEL);
 
-#ifdef CONFIG_DEBUG_PAGEALLOC
 	if (debug_pagealloc_enabled()) {
 		linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
 		linear_map_hash_slots = memblock_alloc_try_nid(
@@ -964,7 +958,6 @@ static void __init htab_initialize(void)
 			panic("%s: Failed to allocate %lu bytes max_addr=%pa\n",
 			      __func__, linear_map_hash_count, &ppc64_rma_size);
 	}
-#endif /* CONFIG_DEBUG_PAGEALLOC */
 
 	/* create bolted the linear mapping in the hash table */
 	for_each_mem_range(i, &base, &end) {
@@ -1935,6 +1928,8 @@ long hpte_insert_repeating(unsigned long hash, unsigned long vpn,
 }
 
 #ifdef CONFIG_DEBUG_PAGEALLOC
+static DEFINE_SPINLOCK(linear_map_hash_lock);
+
 static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
 {
 	unsigned long hash;
-- 
2.25.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/33441f41f6ff51807c22207f213a645dc5d1d8da.1614868445.git.christophe.leroy%40csgroup.eu.
