Return-Path: <kasan-dev+bncBAABB5HJUGTAMGQEU5CXHQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id C103776A740
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Aug 2023 04:59:01 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id af79cd13be357-767b778582esf544688485a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:59:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690858740; cv=pass;
        d=google.com; s=arc-20160816;
        b=QL/ooE8DQPvWwnE0Ob+pX5nh9v0TsBRsO3uhHYborXoSOb9zVaqlKdCto7NZ9q8ViF
         CP4QFnaSlaBUXZNi4X/SWFrNcUq6GIBEIMJBhHY4fxeKZlMTzwUxUNhdgF/aLD3lOxYy
         /WLmcqkvEWMJzNo/J81oLeKDlf+ejhWPqkc8ARao7dPcpAF/73OZKthMao5bAR1i3Sbp
         5JIpVOJxJBiR2I8z/sJC7UkL5bs0RxB33uPzJuGHTV96WyV2ZEPh+jp+jdXxZU1Sz9jr
         HL4ArtCAXRn2iPf3jnnQ3wm1QTDkMwI823Jg4rIYiggiDRHwQQXzF7/1oSgIbGnxfWhk
         oo8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MufCwvwXN6pTAFsu3pbznC1y/2wN1JvJSXN9SdHuz84=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=AiDMpN7oihNXtmP3NrWvyAD5IxU0kDnpvoFTFg9QSdHieOZY6lKb5sZDqpBbBeLYvz
         P+lcUgP0TQt6uTQT8LlYbeyNtBQKhjIcveWFV82eSAowz42bBDYbOVVM6dVon6yvtcfm
         rQ/z3evpsQx/8gCN/MxIMXyEZfdEZDQl94LIlJjYuFinmIIBXtFwxIPoMw1s+/6kB7Rw
         Uy6VmLgq4FHI5CtrKztsZEj5GBr6q6urLGxjlLK9gm1fRYJ4TO+5Lbe8c/BPGXE9SK67
         4XCHokdNU4EQQglvs4g+i+AlL6Dp0XagJogkUVwWkCvrWTBIMfo2sKrzZU78OZxYdHkk
         ibiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690858740; x=1691463540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MufCwvwXN6pTAFsu3pbznC1y/2wN1JvJSXN9SdHuz84=;
        b=FT05VjI01m9hr931h2u91HPv9NGvUVRMMiMr27p+sRRn2n0AJYYU1udXDe+SJVLObh
         OzRIFbw+3yxDXJLKXVjXMIIt+ejM95y7XYwaXoMC+I0tU+0Z7gvgJZjQe6sELAz9ziSM
         6CIVCmpDs9mP+cUr5xSDZ154berPnZU0FXtqbIf0jUQZbtoOm1RkfoGre2TLEg86XexN
         e6aKEk4a/4cdBE3IehaLbwWqdrTmateM2RHvV20Hjb0b8QYzy3pXfT/WvH48byzpW58x
         2gUT0fhC7/S3VX+zca1SdS3z0xbQZ0IrsqyaqERtqhk5Cz5lESw/aj5r2i3ED0zNHrmr
         TKbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690858740; x=1691463540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MufCwvwXN6pTAFsu3pbznC1y/2wN1JvJSXN9SdHuz84=;
        b=IgF6pSZcJJTrgA4G9nE68Rfa0KAspVEeD8wu7Bl2Qyc03WzpZ12DyTQIS8PjF3JRpT
         i7tiEdemkmAmHeJt9fBZFL6oxMtBGb6QiNiazsT2SzB3vz/wRh6aJ5QZZa5P9JF76qrI
         WzZX/YDxiq5UBzyVy0mTUIU9/J7mTp3rPpm4Q6v0v7Xkx0HBhu7azfasV2Daj/TLVmzo
         mdsRKNi2Il/u/G8QRqeN/WgSXrMiF6AfoA0nUTFd+WTW3sBGBW6P2JyiSRXpUGPOfiYF
         nshcB+y1fLz1BerS3K754ocNhqAcDXCZEIbN7aGiVnq7rYGKHM56+Bb/wuVORdEloY1D
         l51w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbwcKcDGc6JURf+8hlmKjqQAOcY4WRempag7/14V/bzJidgYkNk
	uSmQNAryv2EFfWX5dl2JaPU=
X-Google-Smtp-Source: APBJJlEjc3hd4w3T0Q5PG50sDy9IreXDATzbSeajBF63JOU6yER+EWYTtq3Lj19q99MeKgEON032pQ==
X-Received: by 2002:ac8:5987:0:b0:403:8d34:5254 with SMTP id e7-20020ac85987000000b004038d345254mr12739928qte.61.1690858740603;
        Mon, 31 Jul 2023 19:59:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:2c0b:b0:403:c0cb:532d with SMTP id
 kk11-20020a05622a2c0b00b00403c0cb532dls4266881qtb.1.-pod-prod-05-us; Mon, 31
 Jul 2023 19:58:59 -0700 (PDT)
X-Received: by 2002:a05:622a:1788:b0:403:cbbb:3fee with SMTP id s8-20020a05622a178800b00403cbbb3feemr14573213qtk.26.1690858739805;
        Mon, 31 Jul 2023 19:58:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690858739; cv=none;
        d=google.com; s=arc-20160816;
        b=hx/Os3qofO7RcMaRbMLuo2Avf0KvOhVM6nePfh+b9dfWVePKQJCyXpNKkBxPbZsbAn
         dTOkoRXPe4T5BfCC0YY521GT2huoJ83CQQfuq9tUOVubW9BmC8S1KBJXu507ReAl+zK2
         tqOfmw5HW+kzYDlCd0Hs+Y3hCFpiSsqxfiPbKr/3VBPWn4mZEVv3KnuvQbtFYErYGch7
         89rZVg3H4gtZOIg3D9Nena3FvLaDwvn06WKaAwLyUhlHWb2KE0K3qLwhw4GFpsRxzmTm
         rfab5yZZ4WY8JODXmbC/COE9y5BfZrflHc821W8HyzrSfCoK12OBSUA1xRD/RXDcQwIe
         TB3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=LEZmny6//EuLIABYOVGnxXOBW3iglITl5IP+o3bNzLw=;
        fh=4qaMQtMKam1ltMqgGtEyZ2I4cIa0xnrLaOY+Yx+O4iM=;
        b=T7TRxEfbCceDvrkVRE1KYsa9IvjEALk+AFwL957Bi8SSEKHOPuEnYPRi31M4/1jirj
         lousGBB5lTT237N4dGgsbFH+Yfq8Mz6rqapAl9jjgDpCb6xdLa7nOmjIg2RNgTHLX4YA
         h95vnT20PkKinlUKKMTT4cGDlaPsALF7yVPPSbcR3GUJdtvQgyOm2DlMdNqkZZRwKfAD
         ZS12tyj/aWnVfN7my8tn5VzDsJCPKGNeLYISNSOdd5NgDzFYbbkdXm8/Ac61HGvyxmvQ
         wi6DF2zciyDrLR15pNu2AW5ObUcAAWTwZdonf16dyhPIwtuFqfNqXgE/dihmFmcv6IgL
         eLqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) smtp.mailfrom=lienze@kylinos.cn
Received: from mailgw.kylinos.cn (mailgw.kylinos.cn. [124.126.103.232])
        by gmr-mx.google.com with ESMTPS id ro24-20020a05620a399800b0076cbb505c31si133239qkn.6.2023.07.31.19.58.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Jul 2023 19:58:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as permitted sender) client-ip=124.126.103.232;
X-UUID: 00eaf5245e3442bda9c7ec9a9182a597-20230801
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.28,REQID:7e67ea3d-041b-43b2-a9c6-58361bb94025,IP:15,
	URL:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-INFO: VERSION:1.1.28,REQID:7e67ea3d-041b-43b2-a9c6-58361bb94025,IP:15,UR
	L:0,TC:0,Content:0,EDM:0,RT:0,SF:-15,FILE:0,BULK:0,RULE:Release_Ham,ACTION
	:release,TS:0
X-CID-META: VersionHash:176cd25,CLOUDID:fa48bfa0-0933-4333-8d4f-6c3c53ebd55b,B
	ulkID:230801105842MI9Q464W,BulkQuantity:0,Recheck:0,SF:19|44|38|24|17|102,
	TC:nil,Content:0,EDM:-3,IP:-2,URL:1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0
	,OSI:0,OSA:0,AV:0,LES:1,SPR:NO,DKR:0,DKP:0
X-CID-BVR: 0
X-CID-BAS: 0,_,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_FAS,TF_CID_SPAM_FSD,TF_CID_SPAM_FSI,
	TF_CID_SPAM_ULS
X-UUID: 00eaf5245e3442bda9c7ec9a9182a597-20230801
X-User: lienze@kylinos.cn
Received: from ubuntu.. [(39.156.73.12)] by mailgw
	(envelope-from <lienze@kylinos.cn>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 440130864; Tue, 01 Aug 2023 10:58:41 +0800
From: Enze Li <lienze@kylinos.cn>
To: chenhuacai@kernel.org,
	kernel@xen0n.name,
	loongarch@lists.linux.dev,
	glider@google.com,
	elver@google.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Cc: zhangqing@loongson.cn,
	yangtiezhu@loongson.cn,
	dvyukov@google.com,
	Enze Li <lienze@kylinos.cn>
Subject: [PATCH 2/4 v3] LoongArch: mm: Add page table mapped mode support
Date: Tue,  1 Aug 2023 10:58:13 +0800
Message-Id: <20230801025815.2436293-3-lienze@kylinos.cn>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20230801025815.2436293-1-lienze@kylinos.cn>
References: <20230801025815.2436293-1-lienze@kylinos.cn>
MIME-Version: 1.0
X-Original-Sender: lienze@kylinos.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lienze@kylinos.cn designates 124.126.103.232 as
 permitted sender) smtp.mailfrom=lienze@kylinos.cn
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

According to LoongArch documentation online, there are two types of address
translation modes: direct mapped address translation mode (direct mapped mode)
and page table mapped address translation mode (page table mapped mode).

Currently, the upstream kernel only supports direct mapped mode.
This patch adds a function that determines whether page table mapped
mode should be used, and also adds the corresponding handler functions
for both modes.

For more details on the two modes, see [1].

[1] https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#virtual-address-space-and-address-translation-mode

Signed-off-by: Enze Li <lienze@kylinos.cn>
---
 arch/loongarch/include/asm/page.h    | 8 +++++++-
 arch/loongarch/include/asm/pgtable.h | 3 +++
 arch/loongarch/mm/pgtable.c          | 7 +++++++
 3 files changed, 17 insertions(+), 1 deletion(-)

diff --git a/arch/loongarch/include/asm/page.h b/arch/loongarch/include/asm/page.h
index 26e8dccb6619..a256fd6cb7bb 100644
--- a/arch/loongarch/include/asm/page.h
+++ b/arch/loongarch/include/asm/page.h
@@ -84,7 +84,13 @@ typedef struct { unsigned long pgprot; } pgprot_t;
 #define sym_to_pfn(x)		__phys_to_pfn(__pa_symbol(x))
 
 #define virt_to_pfn(kaddr)	PFN_DOWN(PHYSADDR(kaddr))
-#define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
+
+#define virt_to_page(kaddr)						\
+({									\
+	((unsigned long)kaddr >= vm_map_base) ?				\
+	tlb_virt_to_page((unsigned long)kaddr) :			\
+	dmw_virt_to_page((unsigned long)kaddr);				\
+})
 
 extern int __virt_addr_valid(volatile void *kaddr);
 #define virt_addr_valid(kaddr)	__virt_addr_valid((volatile void *)(kaddr))
diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index 38afeb7dd58b..716a7fcab15e 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -353,6 +353,9 @@ static inline void pte_clear(struct mm_struct *mm, unsigned long addr, pte_t *pt
 #define PMD_T_LOG2	(__builtin_ffs(sizeof(pmd_t)) - 1)
 #define PTE_T_LOG2	(__builtin_ffs(sizeof(pte_t)) - 1)
 
+inline struct page *tlb_virt_to_page(unsigned long kaddr);
+#define dmw_virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
+
 extern pgd_t swapper_pg_dir[];
 extern pgd_t invalid_pg_dir[];
 
diff --git a/arch/loongarch/mm/pgtable.c b/arch/loongarch/mm/pgtable.c
index 36a6dc0148ae..fea8fd2cf141 100644
--- a/arch/loongarch/mm/pgtable.c
+++ b/arch/loongarch/mm/pgtable.c
@@ -9,6 +9,13 @@
 #include <asm/pgtable.h>
 #include <asm/tlbflush.h>
 
+
+inline struct page *tlb_virt_to_page(unsigned long kaddr)
+{
+	return pte_page(*virt_to_kpte(kaddr));
+}
+EXPORT_SYMBOL_GPL(tlb_virt_to_page);
+
 pgd_t *pgd_alloc(struct mm_struct *mm)
 {
 	pgd_t *ret, *init;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230801025815.2436293-3-lienze%40kylinos.cn.
