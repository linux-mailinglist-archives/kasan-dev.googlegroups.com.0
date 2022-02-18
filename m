Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBKOCX2IAMGQE6SSQHGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 346C24BBA2D
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 14:37:46 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id c7-20020a1c3507000000b0034a0dfc86aasf5935700wma.6
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 05:37:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645191466; cv=pass;
        d=google.com; s=arc-20160816;
        b=EVOVSi7pyf13nf8g1595elBy+bR7tECXiOa2Tj7sWSrBOjJewqUmgiuFL7x93tvKln
         pwPArBxRn330IQcDXP84sR3SMBwP3kr9ffddYIznvrCgw0LNJ6huZvvqdUhqpZ1j6ttB
         aeGEbi1N/KsxotClMKcivOsw6Rk+FgcJAbhibr7UYSP8VmoFZxfAJtE2K4sKFokW7SCK
         llrexygMT+yU0/Rm4z79SNsYUxFalTOFgCroXezuyeWYzAM4SoGcp5uZvkcJe4HBuJMu
         jn6imB4uadil0Tep9FOGmb4S9unfzMPWV8paTh3yf7qm6XNr/G7I0XxrZK2ttfxi/4Uw
         kf8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=VipV8RnRhuKhQ1GJCFVFP4tDqhFD0DwSaEzP5C+Wh/g=;
        b=EgNbYNQ4AICXaUZPx51eE67pO70R9krwrw1yLUCv9YXFVYcn3+pvzBPssQbXOU4MtT
         rTU/3Hc3UL0y6kCH36dutqkH3fBIBjGwiJXt8IMeGcj/dyqsa4+rYzCrdGDxIvlRHMRx
         CEIYq5006SwBf/x7TI/z6FUWRELRvuffdFnIAB4uVXhhQWfLxB6R+eJKJKR+cG1euav4
         Oa8bb3FBfS7BK7A8gzvwUgWRmm7Nx7IHrJBOM083CFCg3z1PVqBgYhSdStQiiCL9hMYm
         1EMbRb7QNUuVY4+nUMywElIK5efzAmEcDrExfPjp2jDxQMkcGHT6Gy52fjfYJZ7/eC4h
         QjMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=qZuo+9Cs;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VipV8RnRhuKhQ1GJCFVFP4tDqhFD0DwSaEzP5C+Wh/g=;
        b=Hq9RAwestxnPl33v5TPdOyPoU1AtjF8neAoVJsnOCejjXEQTnBjOfnJOOaeg8OfH4C
         qi8vTPmmvwJyaFnxl+VXDV8qNu+eSOB5cAiCFfTlho0E3+sQhJ6relstujtu7GJkCWi2
         wzhly2JUB1FJTojguwDx0YHgEZUjc6e2azxu5e6EbIlDAgvWGM08ZFAc3ZRauNaoa1Qm
         e7lCJtjVz3ZJyCkYIkSr8mJjwNH8b+Vph2yptdKIiS+J4d2prqEs7Yu66j1SRRGIIrx9
         Sw/bueg8a3EqOP8kmBnb32jvDLHJfPv3wb4J0loZEJVT0DXP0RycvGz3YVWVV8lEXY8L
         7YLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VipV8RnRhuKhQ1GJCFVFP4tDqhFD0DwSaEzP5C+Wh/g=;
        b=J2pbhUqFqQgLv/8FeU8W4c/TWrAr2LKGupCcVwGFUXylTJWUB6KId4NReVk3PneNNt
         R/ZpGQmLEeFXFIFtci1oUBWHwN4UBArxEuq4xkgYs347vGWgN1QF8Ms9zLhgPZdfSS9f
         jo0sxDZJQnHwOayIAlChRBqexwiQdEsqkr6tN+O2POi6cD8BL1Z2JPMgzWB5TTODH9jk
         qZNSPiW5T/SugojbMZP0E4t+404xIkwl6+OhYZIae1yIZjb0BQGEddrl8Zw2LX/XVkLF
         YaouVka1n9MeJ6oBRN9T6tcrlHOSDyyf3/yxk8WTYkzVfpwPc6Plp3BbDmf+e0NSrM0T
         5uVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532t0my6rrfH4g1Ty1nnfCf/gBS/OgBIIBbAHfMokOQwM0pamZ/R
	/GqsWbU78FPlAJKNaP5Ua3w=
X-Google-Smtp-Source: ABdhPJz/zYS7su76RKc8iR5LRv0rnekW9LXD4nLXBKoKM8VPQmVEkSuN+QDNGw5b6sthHItvBXKwxQ==
X-Received: by 2002:a05:600c:4f14:b0:353:32b7:b47 with SMTP id l20-20020a05600c4f1400b0035332b70b47mr11098102wmq.126.1645191465798;
        Fri, 18 Feb 2022 05:37:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:227:b0:1e7:e758:3d7c with SMTP id
 l7-20020a056000022700b001e7e7583d7cls325129wrz.2.gmail; Fri, 18 Feb 2022
 05:37:45 -0800 (PST)
X-Received: by 2002:a5d:6caf:0:b0:1e5:b87f:3af with SMTP id a15-20020a5d6caf000000b001e5b87f03afmr6181017wra.607.1645191464943;
        Fri, 18 Feb 2022 05:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645191464; cv=none;
        d=google.com; s=arc-20160816;
        b=CneElMJXupXl/rF5voleCQ2NlXsHwbi8+MJgpDnT6emIZPjJs2hazMuuJLRVucZ5cA
         S2yYFA560zLNrDcSd3DwjovzL01Se3iHlmoNtn5rDER9hAMNsAW0YgEiR8RI0giZjKY5
         UYuLCFx44TZLinljgy1O3YRHqJyh0hwoeiVtKIeUQk2Ao7YZ8oJgZXSLKw/ebM7JrMCP
         TDCLR4ZfiuiPK1SEcCiANvf8U+v7IJAQ5JqS6aXT5gER1hcPFIsxId7rHw9Ghkw37WeT
         TnxgJKxKm5Fcego92EF+rq5aSAQj7Md23JV1cgEMbC9V4IstzKlGkHZ36Si1qEGftAqi
         YDOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=5wR2inrb50SGryPV3ql5qm7RIRt9i7gNq/sby+Clcps=;
        b=rwPPO0Q+gzFCsz1GXhVBTTg566Ezwf7zlPMXio5stDCJk/7V1yBuhrnRdPQZ4rn3VM
         S3HKMVIG+8w4s+lmJ2FETetbZfXO6ss7UaAqkalrILUOR/0aICtPzw0emrkgNO/I8MbY
         M7jHOeORApWiceiEf0L2Jz+enJ6xYYJXToLlYIy7MfR5S801+qtq+DYBlGF51B+Fjn2M
         H5vNxqfg0AUUeIZCAndbu8kqxf1/vOZwMZj+vyTZFMlIPEV1Ijsx/BGKW1ZQKHdIfz2C
         txcQo8BTuDIc3NvBOE16NIBpTGMQC5WUQxo7HMGS7APW8ef90qLNgl7+76EmJkD7q5FV
         czEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=qZuo+9Cs;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id h81si276998wmh.2.2022.02.18.05.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com [209.85.221.71])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id BF0C140305
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 13:37:43 +0000 (UTC)
Received: by mail-wr1-f71.google.com with SMTP id p9-20020adf9589000000b001e333885ac1so3570689wrp.10
        for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 05:37:43 -0800 (PST)
X-Received: by 2002:a1c:7715:0:b0:37b:dc94:9eb4 with SMTP id t21-20020a1c7715000000b0037bdc949eb4mr7292833wmi.61.1645191463171;
        Fri, 18 Feb 2022 05:37:43 -0800 (PST)
X-Received: by 2002:a1c:7715:0:b0:37b:dc94:9eb4 with SMTP id t21-20020a1c7715000000b0037bdc949eb4mr7292811wmi.61.1645191463026;
        Fri, 18 Feb 2022 05:37:43 -0800 (PST)
Received: from localhost.localdomain (lfbn-gre-1-195-1.w90-112.abo.wanadoo.fr. [90.112.158.1])
        by smtp.gmail.com with ESMTPSA id h21sm4886378wmq.26.2022.02.18.05.37.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Feb 2022 05:37:42 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Nick Hu <nickhu@andestech.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH -fixes 2/4] riscv: Fix config KASAN && SPARSEMEM && !SPARSE_VMEMMAP
Date: Fri, 18 Feb 2022 14:35:11 +0100
Message-Id: <20220218133513.1762929-3-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
In-Reply-To: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
References: <20220218133513.1762929-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=qZuo+9Cs;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

In order to get the pfn of a struct page* when sparsemem is enabled
without vmemmap, the mem_section structures need to be initialized which
happens in sparse_init.

But kasan_early_init calls pfn_to_page way before sparse_init is called,
which then tries to dereference a null mem_section pointer.

Fix this by removing the usage of this function in kasan_early_init.

Fixes: 8ad8b72721d0 ("riscv: Add KASAN support")
Signed-off-by: Alexandre Ghiti <alexandre.ghiti@canonical.com>
---
 arch/riscv/mm/kasan_init.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index f61f7ca6fe0f..85e849318389 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -202,8 +202,7 @@ asmlinkage void __init kasan_early_init(void)
 
 	for (i = 0; i < PTRS_PER_PTE; ++i)
 		set_pte(kasan_early_shadow_pte + i,
-			mk_pte(virt_to_page(kasan_early_shadow_page),
-			       PAGE_KERNEL));
+			pfn_pte(virt_to_pfn(kasan_early_shadow_page), PAGE_KERNEL));
 
 	for (i = 0; i < PTRS_PER_PMD; ++i)
 		set_pmd(kasan_early_shadow_pmd + i,
-- 
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220218133513.1762929-3-alexandre.ghiti%40canonical.com.
