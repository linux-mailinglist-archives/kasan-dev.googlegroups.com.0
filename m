Return-Path: <kasan-dev+bncBCN7B3VUS4CRBEPV5KBAMGQEYM3DVGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EB6B34705A
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 05:05:38 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 13sf562547otu.22
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 21:05:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616558737; cv=pass;
        d=google.com; s=arc-20160816;
        b=yMWC4sMFyxPs0x89LNDX48Jm0e8kG9LkJZupCH+Wr1oxK1cTGkaCb21NYljHsqGWNf
         iShjHrLVjqXy6iN2QwWA2cC1Uu71ll7bhztoe/+XNAcx2iph9X56ETVOTjgPqvC1elhv
         GDCYYJTTbSkTa7qJfV6CcqMWQ4omQaMvEhJoMCpxD7hYLyNi4SDSiL02/TJH6Aw3C96C
         qM1BoTzAWL0NciVRirt0nzE+QAooyuY27zKCpevOmXZCYdiuoMpSFHdkKjyS5sqhLkDx
         JJgIgu8MDEmy3OrcO97IKqUgLx/lo0A9ol84EfPHpf0qZcKb+w8SSMGKGx+I6ayPfh+8
         61wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=/eDD4m7IBEbEXOKnnLVizc08iSMExP+TvbdLVY/Vtdc=;
        b=ljT/mudgtmaMAbwWLvxPPfKuiQr+HUPpqWw+HOCBpGnvJRxsJAodvzMBDf3Vs/XnFX
         zfXnIACgLuy1X1QIOj/qKkx3XQDEGbe94B4rQ6VFNYhdZsfMPOqMSWOpf9b2hKiYbbHs
         bioqqhxwBhbeAxYluJTaf1luZGhTOmkmgNOtEdnxwBJ5ROgjrYRcLv9nc0TezEATXMRt
         kJXNYQNATfgP1+O+ZUqbro4ZMlF+r6uT3Z3KyxAPSdYD64lXxGmDh92AvekGhOOCBd1i
         yCsRu4Qvb5C+3wujz0pF57HSvqNvGCjjsumEiQtuXF1jj/73ImLj8lzioJScxsdhRJ+A
         88+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/eDD4m7IBEbEXOKnnLVizc08iSMExP+TvbdLVY/Vtdc=;
        b=mHWM+XrUMQaZPu+OK1yMj5DeL8O7aiv4RG3onMnhV940Coz+p5is+WykrL+KBYM4uu
         Ght4o3hDg52wuS9cX66b7qTBr8+glVE2e0fVJDNDUqN8KFMwmgQkxNjmlHiUdihOFNVk
         1rPj21/OSeAYnMixp6mCkNjF4plXYsKqEMxGa2l522VdRu3U3mObpBEXkZc8qm1Ax9Tn
         phsxsdnewSZgxnWJbtSXXzeWqMcRxIj18Uf2WQhauhbnTCKtfLXISu0AmIRkWEilJl0l
         iXq3qsrwMIvOhYJs+5bPJEcGytkdl2k76K0a1sBjCEUN8oo3eYGdFgBljOPCWixsa/wv
         PaGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/eDD4m7IBEbEXOKnnLVizc08iSMExP+TvbdLVY/Vtdc=;
        b=LY/fbTbhGp7omI4ZJtXwPz/1eqBY7mKIF9Mj898dxBWOFSeQs27PLfsH5JlGioZGus
         Rga0liwanOdiKsIfGSVUzfR8ieN9JQH5ciY9Qz8yZapFKtZBcyTMXXSpvkOusAUBTx7A
         2zzBCBU+0sySCAx8rYGck8dGOqZHIBaY/PJQICWVhB8kBnrGWutqSO+dc1co93S09alM
         HXGuq7Ynsol+6ovsSFRt4fAzDx0K4brQyirSu9CRqKi0MtKJGHA1IYP8navZRaNXDuJs
         Lw6NAincc6yQQj7tL4Z2bQJ28l5k07Z90p3ilhXrd560R3C6oScSlyS7BxvsPcC3/ZI7
         VYAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328OaqTd5XEKP9mRcmwy9fIyYyVOs2mI9+WSpI6C6x5FsVL6JL5
	zJ5QmbsVoZGP6zAs5DaU/oA=
X-Google-Smtp-Source: ABdhPJy0J8ErIpd6WWKri1UllrI9BK9nxm8vO/TbH4NYj2WiHEMGxBMNVV/Zp4r7r9L0G8VJH8uRwg==
X-Received: by 2002:a05:6830:118a:: with SMTP id u10mr1317793otq.333.1616558737602;
        Tue, 23 Mar 2021 21:05:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:65cf:: with SMTP id z15ls253900oth.10.gmail; Tue, 23 Mar
 2021 21:05:37 -0700 (PDT)
X-Received: by 2002:a05:6830:1d4c:: with SMTP id p12mr777253oth.96.1616558737258;
        Tue, 23 Mar 2021 21:05:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616558737; cv=none;
        d=google.com; s=arc-20160816;
        b=h3J7kOTF+st3E4WDp4S5YD99fuKXigh3owXUhUwo+3M+QTvokZdLS4Us+wIQR9iwVF
         91UbvbqmDZQrxUR3fNWZXONCAOnM1dn98JDTodOVdE4YF3DpjAWO3r81u9pFVtV/GVtU
         iY8CUllG7Z+TYwG3qOdI4bsrVN8ZG6NguYJGKPS1RnkBO79bwyFHHP0PbjqEqP+C9qD5
         b/RyzE/O/pwfjua7MDWsykLcEQMG7FeSp8gmzBtA2WCpa4wCDT+ALsJI+tm6L2I7xRo/
         SZ8jftTpKgTPaShbUEFwjORL4nK7kQLc8SJl8QYZgvuTXvx9ZMG/95N34WfwlkONK47l
         ZO0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=qinYXsyWUo1XnAmWdFhCK8lfJ5CRZmi/q0qA0TUB1Kw=;
        b=D0LRJhCrckuN6eo4RwvwkN0rJN8A7CxThZn+aRVGBSTKskN+GsSY/roD1PnqncMcn/
         x6p5lzfWuazJ/5faztT56Tn+QTZiGVmkNnyYR/xqZFzmQh1SVnMKd8xQlaJf5+pwAPYh
         9dBqIzGxOO/ZIhl3AS11q5NeBoIo47X/6tEzhuHTNv8OjixxmrVCZ4tvxC/ARTCbqFpZ
         ah/wQn42B2feJuyvPJOGP9bY+rC1ETtqEm2MPNPdDL3pWFGz1TfkcEQ1zvuHLnlKSkVl
         nlkwwKbGnlPSh4Zo6sHgqO5XC2VfMxc1a12AoBJK9LRL0FXy7pUsGxoCTS5cd6OHI7Ts
         rSWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id h5si77483otk.1.2021.03.23.21.05.36
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Mar 2021 21:05:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 89425291d84d4ca3a18c5b1f65327fbf-20210324
X-UUID: 89425291d84d4ca3a18c5b1f65327fbf-20210324
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1361957179; Wed, 24 Mar 2021 12:05:32 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 24 Mar 2021 12:05:30 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 24 Mar 2021 12:05:30 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <catalin.marinas@arm.com>, <will@kernel.org>
CC: <ryabinin.a.a@gmail.com>, <glider@google.com>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<tyhicks@linux.microsoft.com>, <maz@kernel.org>, <rppt@kernel.org>,
	<linux@roeck-us.net>, <gustavoars@kernel.org>, <yj.chiang@mediatek.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v4 2/5] arm64: kasan: abstract _text and _end to KERNEL_START/END
Date: Wed, 24 Mar 2021 12:05:19 +0800
Message-ID: <20210324040522.15548-3-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
References: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Arm64 provides defined macro for KERNEL_START and KERNEL_END,
thus replace them by the abstration instead of using _text and _end.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Ard Biesheuvel <ardb@kernel.org>
---
 arch/arm64/mm/kasan_init.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 20d06008785f..cd2653b7b174 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -218,8 +218,8 @@ static void __init kasan_init_shadow(void)
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
-	kimg_shadow_start = (u64)kasan_mem_to_shadow(_text) & PAGE_MASK;
-	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(_end));
+	kimg_shadow_start = (u64)kasan_mem_to_shadow(KERNEL_START) & PAGE_MASK;
+	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(KERNEL_END));
 
 	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
 	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
@@ -240,7 +240,7 @@ static void __init kasan_init_shadow(void)
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
 	kasan_map_populate(kimg_shadow_start, kimg_shadow_end,
-			   early_pfn_to_nid(virt_to_pfn(lm_alias(_text))));
+			   early_pfn_to_nid(virt_to_pfn(lm_alias(KERNEL_START))));
 
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
 				   (void *)mod_shadow_start);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324040522.15548-3-lecopzer.chen%40mediatek.com.
