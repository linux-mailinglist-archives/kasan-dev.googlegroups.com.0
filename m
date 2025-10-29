Return-Path: <kasan-dev+bncBAABBFHIRHEAMGQE6HPWKKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id DCF19C1D231
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:07:49 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-78376e53290sf3601867b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:07:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768468; cv=pass;
        d=google.com; s=arc-20240605;
        b=aBGwE4HJ2eavMT99r8ad8I4ZhxNFSOaWZEI4XkygLGGQVR+BljDGW6unFb90eClwSd
         vmGb4omuZ5hlphxoZmBMMQuTx1NkYQUk6sWbxhmGpq4NrKr2gYv9lnF12tBWC95AhlUU
         /66hzDMPgMA75LihJbThvfnpremAyk0WL4sRRQRRPoCRBs1XxS9FQaB8FlBi9ltYFsL0
         Dul7AdjPse7Qw0rGzlX/9+tjyykBaPq3tAegcFEoV408XWi3WznZVvb6RyVleMEfN11d
         Alw60iKwBW9iJYMvjDUDGN7Fh3rj7B7JmFAP5Nn3MtYJmJS4WHORzjdST0Uq+p0WZzgP
         W4yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=lYJQ6/Cz3dwSFRn9gBhnPXTWpGOBvxAXp0fBWglpog4=;
        fh=dZlV/6gBGA3Mn2S+FpX9xFHGvGqBPc8ndQ7MPx2F4KI=;
        b=VIJ8M4sY19vgdiVqoyyRJowz4qzjxuUk1pF5IwwsNEjXme6Lvm/cyQpzC99M/gPzpw
         gBvn6EUcCNgZNxwEt2IcwHapp7cSIpp/OOpWnsCSZzfMIYkZd0iwnX5OIH2/qm7jTG+d
         Ls3SJrmgQ5fVMpbjskpdZzCTUx4VpX6fa9QOoiucIXM7TmiQiU7jQZsFxvHDbzBlj1tz
         GHL2lepfBWpzjpHDwXryiDmdJTUegXKrc3ruE+zGEQ2I3hNWJsA7dpJAiIwsnM23IBtl
         YbnoL2aDzbE2i74Nif0nmeuv8Gn88677qnPs1iP717HNcVIjfdR0i0rdSrQ9OhnM1TIT
         BCIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=bjmx3g8O;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768468; x=1762373268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=lYJQ6/Cz3dwSFRn9gBhnPXTWpGOBvxAXp0fBWglpog4=;
        b=RdgcCPpbuvxvrc6VRES31veZwNc0BZR/xUhlHwX6ENEN+/2qUzAkg/G0eHLBT6kMIR
         B9kypL8tWjZFFXUs3620tP6379HwMXdNysnMcVRadeGURETt5w6dL7mQxfa56qlj+79n
         I1oWjNTKrxIz7JkhgCKQ9qui0Ui7xIeWOR/dJcQbJ65cEJB35anHMP158lT5/9SfdOL9
         gwLNGcQoBtsviRtcxVb/1KFHU3eJ4IyzVJ/Et4KNGeB405+JIWyPLdl8J1LsXU/NLI/p
         /qFIwKC2TxUIQTo1vP+ccacnefC+M0+E6LUndeHcv73+5fV4h6yVwvAP+UM0U+ogueTM
         KBdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768468; x=1762373268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lYJQ6/Cz3dwSFRn9gBhnPXTWpGOBvxAXp0fBWglpog4=;
        b=QuodJC5j5Zyy44zGS0ZOzLUgyZtjXhwyesthdTBPEGY7m2yMpDYPmHvyPL6sU3sQSe
         szWtvoSZcTY54djYN1MmSSP8dmPongrAGc/LnCT2+vJxQFsqFeFvNLMKidfojGPhcV4j
         i9jrNdywGyNAx9aygLfFwmZoPrWNMqpXWgGxQ35XU9flPQdk7EFcpSYNYULWJLOttJhX
         qtOY+n+eiTqoxxW7XerxzNty946VnhWG+KGSWM+/4BOKw2p0rBb4AjKTo+Z8Yer2u3V8
         5muC+uYdxxk6/8QonK+q0m6uFLdJmDVjeUBGXVzwvE0nD1EamCo/UvJaOVubqyJx7ZDK
         C6vQ==
X-Forwarded-Encrypted: i=2; AJvYcCXayffdYFeAFq20ailTucOu6GUYd6qFFbECh49n21AhhKmBXhXDjQwyHPHx3FNAU1l4oTNQyw==@lfdr.de
X-Gm-Message-State: AOJu0YxOTk05U5Fww1kgn55wWVPZK1bLn3PRqTDZ3qJ0xbGysVoSlp4W
	waoOJnjZGPlxJSgsBAAVsdAJCn8imKJQpDpcNdaAmr0AdK0wdOHz3GKt
X-Google-Smtp-Source: AGHT+IE380ll8t8NqSR+wXp8MKcWWw5inSoiKqtOun5LtVttBqF5IoJ6Mn5AzM8OEcENJ5DNDP3o+A==
X-Received: by 2002:a05:690c:11:b0:784:99f7:8d04 with SMTP id 00721157ae682-78639097090mr14703207b3.40.1761768468363;
        Wed, 29 Oct 2025 13:07:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a+Hb7hfcS/Rn/PGoTMAEYfG8hWNIlKSlGAoZhiGH7AZg=="
Received: by 2002:a05:690e:248c:b0:63e:2940:1df9 with SMTP id
 956f58d0204a3-63f835b1737ls155029d50.1.-pod-prod-08-us; Wed, 29 Oct 2025
 13:07:47 -0700 (PDT)
X-Received: by 2002:a05:690c:6e8e:b0:784:a6c9:79dc with SMTP id 00721157ae682-7863911115fmr13909407b3.70.1761768467556;
        Wed, 29 Oct 2025 13:07:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768467; cv=none;
        d=google.com; s=arc-20240605;
        b=FKwzo04i01l2W3lYZ4+Sr6tiaBBlUHi0cJFFQEhwmlNYOHdfcTNBgVfgBZRbC54nLa
         WechNX4EihM8IjMbG4WHAriH6duXJ/hlLhBySkjOHW3hVEG9uQPcam0VC2QGDPgZxrY+
         TYAW2wLHHkdZynzx4uZan0DxdNR0n0BJIAMKENgevHxF3XFR0kytQ1gsbIftRTegw4gX
         gWas2FKBe+ohJpJjE7q5j22CyxunChWLS0aPlF+9E9jFBRlJttOQEhG4bqjzJMsT7wZh
         qdW2n4S3Va/fj+QRd4zh+CmG3jhuGjmzTma+aRZwE81tlzgpCAMO3AAJE8caUyrA9bDF
         YS1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=h7bOmcRxuqO6z3MZPe9zBvs6V2vz8fOGqA1RpHhG/FE=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=G8/FHq4Y/9ruhgOvqRfGVm02gcP2lNtcuuF416R9WojvxzPdXjM8B03gKrm+gJ4usU
         mQ1KADNtALKu/V0pT6d9pf2xwtaEJOz1lEWZt2zNPZ2porBc547QlQUj0gbO/qb7CdJu
         h6WPbttL4YnPd53P70hTubWADE1aI//d+ML3r0eoinRR6SY3ys3YpG2zjLl4x3oXJ47h
         +nNEvzT2k2VVwF6Sol641fabDtDUbXHY4EKSSmBw72nqTkBIQQdmquPDGdw+fFiFqzpL
         +BbAULKHxgxuKh98YYaUCjv3QIRI9jpt3ccxrcHEglpdU84Ixkwh3QQyhJ1wEaU6IXd+
         3aIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=bjmx3g8O;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24417.protonmail.ch (mail-24417.protonmail.ch. [109.224.244.17])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-63f4cf4adc2si1009262d50.4.2025.10.29.13.07.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:07:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.17 as permitted sender) client-ip=109.224.244.17;
Date: Wed, 29 Oct 2025 20:07:38 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 11/18] x86/kasan: KASAN raw shadow memory PTE init
Message-ID: <f533bb094a566242ec196afbde222796c6d6c084.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 388931058df330f6e092950b7ef3ba7585e70752
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=bjmx3g8O;       spf=pass
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

In KASAN's generic mode the default value in shadow memory is zero.
During initialization of shadow memory pages they are allocated and
zeroed.

In KASAN's tag-based mode the default tag for the arm64 architecture is
0xFE which corresponds to any memory that should not be accessed. On x86
(where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
during the initializations all the bytes in shadow memory pages should
be filled with it.

Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
avoid zeroing out the memory so it can be set with the KASAN invalid
tag.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2:
- Remove dense mode references, use memset() instead of kasan_poison().

 arch/x86/mm/kasan_init_64.c | 19 ++++++++++++++++---
 1 file changed, 16 insertions(+), 3 deletions(-)

diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 998b6010d6d3..e69b7210aaae 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -34,6 +34,18 @@ static __init void *early_alloc(size_t size, int nid, bool should_panic)
 	return ptr;
 }
 
+static __init void *early_raw_alloc(size_t size, int nid, bool should_panic)
+{
+	void *ptr = memblock_alloc_try_nid_raw(size, size,
+			__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, nid);
+
+	if (!ptr && should_panic)
+		panic("%pS: Failed to allocate page, nid=%d from=%lx\n",
+		      (void *)_RET_IP_, nid, __pa(MAX_DMA_ADDRESS));
+
+	return ptr;
+}
+
 static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
 				      unsigned long end, int nid)
 {
@@ -63,8 +75,9 @@ static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
 		if (!pte_none(*pte))
 			continue;
 
-		p = early_alloc(PAGE_SIZE, nid, true);
-		entry = pfn_pte(PFN_DOWN(__pa(p)), PAGE_KERNEL);
+		p = early_raw_alloc(PAGE_SIZE, nid, true);
+		memset(p, PAGE_SIZE, KASAN_SHADOW_INIT);
+		entry = pfn_pte(PFN_DOWN(__pa_nodebug(p)), PAGE_KERNEL);
 		set_pte_at(&init_mm, addr, pte, entry);
 	} while (pte++, addr += PAGE_SIZE, addr != end);
 }
@@ -436,7 +449,7 @@ void __init kasan_init(void)
 	 * it may contain some garbage. Now we can clear and write protect it,
 	 * since after the TLB flush no one should write to it.
 	 */
-	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
 	for (i = 0; i < PTRS_PER_PTE; i++) {
 		pte_t pte;
 		pgprot_t prot;
-- 
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f533bb094a566242ec196afbde222796c6d6c084.1761763681.git.m.wieczorretman%40pm.me.
