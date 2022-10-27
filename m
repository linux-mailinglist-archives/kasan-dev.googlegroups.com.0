Return-Path: <kasan-dev+bncBCSL7B6LWYHBBG7R5ONAMGQEAUBVJCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0425F61046C
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 23:31:08 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id r65-20020a1c4444000000b003cf4d3b6644sf286334wma.6
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 14:31:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666906267; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tjc4oVxmxsWthh/AUIbGomvQDy4N9ot9MKMIk8TxvklThj2ZgayrifrZx9M3yIz7rx
         gqT8mGCHf9SyZj19lQ+Z8trXcsMqrx22CAfqCnUUuvFVe21uUlmPKHWGycgYHYQRn+8/
         c9BK62M5VtoJapLE7nnDn6JiZf7QqsLAshz22mIHTdIttHNyMpI5VD/8GTut+PRsGyqK
         oUUKQdlJBjJUTxG/xHUssukNJpwTK/kyz/48ZLW2MPepC/fmkmTM5YYMilU+VrtJKVK9
         8Vr/j/g4Phx9kFJ06tWLtfOkFmXP6tdA7mFHxCBjQnIMwqG4tLPU4+T/T7fNmAV7yFnl
         QK1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=fdAgW8yXF6vOKbUaUsfqrALkzLCUKUR6RcD1924S3P0=;
        b=ELAFfZPOnv6yLqmMmS89TeNyPC6utsJ4CPOSFXXWYBXnoYhgeDyUjXWXeljvQnVjWn
         KNg1pAPXk9Joe9urFF4DwEzNMVP0vsts13ZAfGwDZWahSLPRsUsFTZdzoKNt6jg01Bmv
         Nv/5a8BYlvOVV1HHlZWGhyiprzShc2xOBSHLGdnEb/03Wvo0dv89OVfjVv/8hW+L0DCl
         MZoIBojKK+47epbalCSMfdgtB/2C74mjUKprIAQUDEVWHjAgxPtdkIB7sJn01uxwH90W
         I7RS+J9zMR2PKq1K/7+RV5QmDdang1GWT5SMFhskf5ueHrEXLaP7iQuiN3JI073/D1/n
         QcIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Ur/DqlEE";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fdAgW8yXF6vOKbUaUsfqrALkzLCUKUR6RcD1924S3P0=;
        b=fqlKkVzRnASqT5+AJycQEhO2x7YSHLe2n6M/qMuTkKM1IGKHdn3PWBkak1X7Hj9MT3
         ZWHS2GCNv7vU1bUNDUhs71aYnoLwExiIXhrRlmkKYbyu0KXilil2gzjyff9zdt2imKTm
         WMzOMkJ4M28S2yeUs74c2fQE8mzriimUIslNP00DJ4/K1WgEC8tyipdALXO82FrwLUPK
         yzwkz/HPUi9OEnuKBefyKRut7332UpQ5qKhXSr4AHbSUClK5Ql8ObsA2tezb59Ue97Mn
         iY8SDGCcXEJyt4uQ1+BJT/RjFBG3lY5XZL6Y9dhQ3MFygDXYw/3H31GpjitbQ2wJpkFb
         Kr0Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=fdAgW8yXF6vOKbUaUsfqrALkzLCUKUR6RcD1924S3P0=;
        b=PBbD/ObpUMKm64Nc4elaCqblq5zWF5xBAPQaQmY7oWJQdK9cjYfPJUGk6jVWqCjgpv
         62xmsoP843Ri8hz33H1LXtYCqse1rvq7Ckx4BoE83uuuL0CZhErhWqPgZhFKaQlpI5Vw
         6KuYqL6V4OvQJOZU1yzoii2seqV0wJigkCuxFCqXIx9TCaEwQomeBOTIwmnIDPgxK8N/
         RH9jcCSjRh3BX1C19UGeL23JtKWkNc4M7/cTOezXK5dC0gEws91qvXinVsCNn0CTiffD
         2LL9HdW5+s8V9eTjiQ9hF/uu33GLoKJSxUeqUZIZNzAh+BeytbIYnp1beevJJzlP6oRr
         HxPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fdAgW8yXF6vOKbUaUsfqrALkzLCUKUR6RcD1924S3P0=;
        b=YQDTpBMh65O4Bx1qwtHkop+yNH6PcFzLA/2nbm52MeOIy4q5C71taEfM5jHNE60TPx
         gz9loviOtGIX5yRwUe22VorK1v54Izd9fmfpatw0GIvo6Yu2KavuM/yHN95Nq1FbpIxB
         Hjsui14XS9DeAPh5pPUVpNto9lD4lgo8gaqXcC+uMMp7WtNuBTu8FCanl9um9S4riRAx
         7R1Q5USd4Ef93Yk5CFDvEuWaQ1LZIeqfFiYyQi/JlTCa3yrQu9F/zsQ8XfgGdlb0QY7R
         UqXNv/TI2Lt6w63uXo6SmVLKkjia8WBr8BQA3FE6YRpBpjBpf4vACqhhGcRJpTjthVL9
         N0Yg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0YFJ2OiTzKi8VQriBxqTWJrftyivrBxpPySiALs+O+uR0FP+SW
	2NT7su6xAAIJbLqcTwfr7h4=
X-Google-Smtp-Source: AMsMyM5LUGC/svY54jY80VipNdpXE09araY3rGI9YBrhaGCjMF6iZkLfjfuO+bgq1M+Y4Y5mNqjEJQ==
X-Received: by 2002:a05:600c:3d8e:b0:3c6:e58d:354f with SMTP id bi14-20020a05600c3d8e00b003c6e58d354fmr7245331wmb.176.1666906267500;
        Thu, 27 Oct 2022 14:31:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:540c:0:b0:3cf:4de6:2de7 with SMTP id i12-20020a1c540c000000b003cf4de62de7ls627725wmb.1.-pod-preprod-gmail;
 Thu, 27 Oct 2022 14:31:06 -0700 (PDT)
X-Received: by 2002:a05:600c:3acd:b0:3ce:3f62:a8d1 with SMTP id d13-20020a05600c3acd00b003ce3f62a8d1mr7162614wms.78.1666906266193;
        Thu, 27 Oct 2022 14:31:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666906266; cv=none;
        d=google.com; s=arc-20160816;
        b=XQw5YmZprp3v/tvIApod+OZCDKjSfeQ5ri+wPuEzFpi9TGsJ3TdavO1qAim/Zf8bJj
         +cC+hHESvV6afdPove26u11MzXQxfvB/3G02g/ddOhVbApOypic/aUBszouNs+5r7UCj
         VTgWThYVjhb6oaoBz7aIaxfcUTwnb4y61EZuO90jmAt84NAe1Z3y10dezGlL1GGW0VdD
         EgJLDDR7ls6i52m/zK0Kt9ynFOJhBxQ1p2GA7KnLFQruMs+9bnPIkBkSfHQrFP/oy7AO
         kEfyXa3LxyREyDM5dTsKc2ZqrznHIZzOu5GFYNt138Qqedc/t0EdKnygRaHXEzq3uxRa
         lJBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iBlvNL5JxdJ/PzqAb968FRZUq7jJe0xpV2M3dTQY+YY=;
        b=SZRNCroN0VIKB5GvLw4M+0WcqhQVYY5SHxhtX5Ms5K0HgWSyUBqPrFUZox9+DkcTSP
         IdBuGvdAeUvX003hZxbTQNcIZZXU9QoCRheGZtK/jZ/JA5l+9TEf8Uo4ESRFrXrGF66E
         Bj7cqBEk/8kvOaId7DogVFErNb+yRzszM/kmmUySSVj6TMrcfjtEhClFaEpydl9lCqX9
         2cxB4/e9MHczUxSOyd4I3rqFBPLKb0HR+b3OYLs0+tK2MKxbfrGCRBuMlieqVZ75TxpR
         8Eq/xoisIPoW9hl2iraKqvzbTcRH2B8qIYr+Xby7LAwQ6RqX99c1tU0cUux7NtJj8jif
         aJbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="Ur/DqlEE";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id bv20-20020a0560001f1400b0022e54ade3fcsi80849wrb.1.2022.10.27.14.31.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 14:31:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id b18so5697537ljr.13
        for <kasan-dev@googlegroups.com>; Thu, 27 Oct 2022 14:31:06 -0700 (PDT)
X-Received: by 2002:a2e:7812:0:b0:277:2463:c1e2 with SMTP id t18-20020a2e7812000000b002772463c1e2mr3297139ljc.184.1666906265714;
        Thu, 27 Oct 2022 14:31:05 -0700 (PDT)
Received: from localhost.localdomain ([5.19.98.172])
        by smtp.gmail.com with ESMTPSA id r4-20020a2e9944000000b0026c5579c64csm368453ljj.89.2022.10.27.14.31.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Oct 2022 14:31:05 -0700 (PDT)
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
To: Peter Zijlstra <peterz@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	kernel test robot <yujie.liu@intel.com>
Cc: Seth Jenkins <sethjenkins@google.com>,
	Kees Cook <keescook@chromium.org>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"Yin, Fengwei" <fengwei.yin@intel.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andy Lutomirski <luto@kernel.org>
Subject: [PATCH] x86/kasan: map shadow for percpu pages on demand
Date: Fri, 28 Oct 2022 00:31:04 +0300
Message-Id: <20221027213105.4905-1-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.37.4
In-Reply-To: <864b4fbe-4462-9962-7afd-9140d5165cdb@intel.com>
References: <864b4fbe-4462-9962-7afd-9140d5165cdb@intel.com>
MIME-Version: 1.0
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="Ur/DqlEE";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::235
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

KASAN maps shadow for the entire CPU-entry-area:
  [CPU_ENTRY_AREA_BASE, CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE]

This explodes after commit 1248fb6a8201 ("x86/mm: Randomize per-cpu entry area")
since it increases CPU_ENTRY_AREA_MAP_SIZE to 512 GB and KASAN fails
to allocate shadow for such big area.

Fix this by allocating KASAN shadow only for really used cpu entry area
addresses mapped by cea_map_percpu_pages()

Fixes: 1248fb6a8201 ("x86/mm: Randomize per-cpu entry area")
Reported-by: kernel test robot <yujie.liu@intel.com>
Link: https://lore.kernel.org/r/202210241508.2e203c3d-yujie.liu@intel.com
Tested-by: Yujie Liu <yujie.liu@intel.com>
Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
 arch/x86/include/asm/kasan.h |  3 +++
 arch/x86/mm/cpu_entry_area.c |  8 +++++++-
 arch/x86/mm/kasan_init_64.c  | 15 ++++++++++++---
 3 files changed, 22 insertions(+), 4 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 13e70da38bed..de75306b932e 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -28,9 +28,12 @@
 #ifdef CONFIG_KASAN
 void __init kasan_early_init(void);
 void __init kasan_init(void);
+void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid);
 #else
 static inline void kasan_early_init(void) { }
 static inline void kasan_init(void) { }
+static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size,
+						   int nid) { }
 #endif
 
 #endif
diff --git a/arch/x86/mm/cpu_entry_area.c b/arch/x86/mm/cpu_entry_area.c
index ad1f750517a1..ac2e952186c3 100644
--- a/arch/x86/mm/cpu_entry_area.c
+++ b/arch/x86/mm/cpu_entry_area.c
@@ -9,6 +9,7 @@
 #include <asm/cpu_entry_area.h>
 #include <asm/fixmap.h>
 #include <asm/desc.h>
+#include <asm/kasan.h>
 
 static DEFINE_PER_CPU_PAGE_ALIGNED(struct entry_stack_page, entry_stack_storage);
 
@@ -91,8 +92,13 @@ void cea_set_pte(void *cea_vaddr, phys_addr_t pa, pgprot_t flags)
 static void __init
 cea_map_percpu_pages(void *cea_vaddr, void *ptr, int pages, pgprot_t prot)
 {
+	phys_addr_t pa = per_cpu_ptr_to_phys(ptr);
+
+	kasan_populate_shadow_for_vaddr(cea_vaddr, pages * PAGE_SIZE,
+					early_pfn_to_nid(PFN_DOWN(pa)));
+
 	for ( ; pages; pages--, cea_vaddr+= PAGE_SIZE, ptr += PAGE_SIZE)
-		cea_set_pte(cea_vaddr, per_cpu_ptr_to_phys(ptr), prot);
+		cea_set_pte(cea_vaddr, pa, prot);
 }
 
 static void __init percpu_setup_debug_store(unsigned int cpu)
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index e7b9b464a82f..d1416926ad52 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -316,6 +316,18 @@ void __init kasan_early_init(void)
 	kasan_map_early_shadow(init_top_pgt);
 }
 
+void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid)
+{
+	unsigned long shadow_start, shadow_end;
+
+	shadow_start = (unsigned long)kasan_mem_to_shadow(va);
+	shadow_start = round_down(shadow_start, PAGE_SIZE);
+	shadow_end = (unsigned long)kasan_mem_to_shadow(va + size);
+	shadow_end = round_up(shadow_end, PAGE_SIZE);
+
+	kasan_populate_shadow(shadow_start, shadow_end, nid);
+}
+
 void __init kasan_init(void)
 {
 	int i;
@@ -393,9 +405,6 @@ void __init kasan_init(void)
 		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
 		shadow_cpu_entry_begin);
 
-	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
-			      (unsigned long)shadow_cpu_entry_end, 0);
-
 	kasan_populate_early_shadow(shadow_cpu_entry_end,
 			kasan_mem_to_shadow((void *)__START_KERNEL_map));
 
-- 
2.37.4

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221027213105.4905-1-ryabinin.a.a%40gmail.com.
