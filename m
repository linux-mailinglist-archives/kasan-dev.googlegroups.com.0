Return-Path: <kasan-dev+bncBAABBX6Z36JQMGQED33IIYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id F062B51EEE3
	for <lists+kasan-dev@lfdr.de>; Sun,  8 May 2022 18:16:32 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id t15-20020a17090a3b4f00b001d67e27715dsf9230678pjf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 09:16:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652026591; cv=pass;
        d=google.com; s=arc-20160816;
        b=hIxMK9y59MRjJ5aZJ2Y7gXYdC1gD9tLypVsPiwLz0vTSXj1qVleBrBX2K5XVt4zm7k
         55A6dTXh2Fx4M0uX2ODVBitO1qDqDtPHjRnsvXQbHPL+MN8N2Necznbv1gGgmMN3fHs9
         P8hdMl2NNvSZ+0Cxx0EyhGLFRy6jsPFeEkUZ9UYtngETQKCDx7B+1vBI7Tdia+95FOg1
         flzHG42f0c0iwxfuiONaGrKGfwXjwirYkNvMyiS1spzkHlGOQ38KZoeAXHQzUVBrvWQJ
         rovUXCdIbaRjrrdupQQVDXoDaz4qp0uie3fKt0YN96SNubEaq1A+UzZD4dfPD/6YiEPO
         DWWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kiv4dhicOiB1Up6mMyzbOV8WiyzjQOmn+L1vWflfot4=;
        b=XV75yvdylQiNXcW8TngB7zVdDEDtmPLN2YfWrZMgiCGbcE/ojdGZtg/6GyaZ1PQ6ao
         WhtgYEdIGYy3fOKhnn8wMY8cKhs4GJdAzBtW9s2ZltL3+g6AmBss1EdejQOiUBBjdiFa
         2hqOtX5PstUTbm40MSVpITnegogRzMDyflqG6Z4/gSpaSDjeCS1EBvl13SE/6XuimjtB
         Y28bWXXQbKsuPEWW31tZBIg3Tb3XxffmQTFEP3M9tS4EjLEGoBniEzi8ibXH0dt7xVdY
         24ni93hDHP5qlUoZCl6V1F3pcy2NhhHRYFhrj1iNPGATpafnusSmXHzv3LYYxTS0ahC9
         30fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mdPAo0t5;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kiv4dhicOiB1Up6mMyzbOV8WiyzjQOmn+L1vWflfot4=;
        b=aWrbutgG+HjG4jqDwDwFrdsu3uQ1ppMidnClOgt1AOV1PRXEKEJoHm0vYkELp2mDKw
         SVVrlN0xEo7hw9WVI/lXlCZFXfDN+4a4kCbjyG98exOtgpWM4FbVjH6X2XLlYu0HpdtL
         0KwIJtuciXbkUk9cI2PLT40yXK3Wad18a+swpPShczmDLUnuWPX5CD1DIjmX2VyuS1EE
         trs8VumSJt+zBBuqRL9gXbpMm4Hmr2H1PfZciPm6vr23aJFaSvyCLAxmQYJs0x/caALH
         cTdM7lFs7DLlXQGG2eX7Sg7AjN61+2tPSazTlVdlltQ05BvA9kSXMjcje8MT5nO+Xem/
         MYzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kiv4dhicOiB1Up6mMyzbOV8WiyzjQOmn+L1vWflfot4=;
        b=lx6dUb4Enehv2O9ElCxn3CDLH3pMIpLp6Ovmg5L4xjjTsFnDMaiaqb/QNPBxIESOKJ
         8AUre7OTB7y/Z7/kt9ExaGP5a3iuQFnemejAYpa98KbmyqBxG7avl6oi0L1xrXQUjDIz
         UvJTmWttltcpvbHKBXqzOLNJuFb+Bgd/rrkfZCmD/UIjCzTVG/+11a0jwhHNg5HYfGfC
         aCjOzJeheltpo2vPY5518YeYKCJEWYBR3/66n/2GkQUJFwensg/g424/bRd5f95BbcJT
         us0pKKQi9YwFq//Zw7a/LcoQJaftcbd6HTDD47xkz64eoKznjZig7Pgz2zjysUmH/qf8
         T5DQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530tX2CaublOse59MYqYy3QhFPJJIZR0DFrSKqzjfRGt7VqxcmmI
	+0hKOJoQUsyTcEhHt0xwdwg=
X-Google-Smtp-Source: ABdhPJz1ZjEh+XTxEUMg1cmhOHoQTGyojDfBBzVqyqHX/IesQHGz74csbu+t1Yn5kcKCb/KPBYzIkA==
X-Received: by 2002:a05:6a00:150d:b0:510:3a9c:3eed with SMTP id q13-20020a056a00150d00b005103a9c3eedmr12284989pfu.86.1652026591226;
        Sun, 08 May 2022 09:16:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:be0e:b0:1da:2690:904d with SMTP id
 a14-20020a17090abe0e00b001da2690904dls9660933pjs.2.gmail; Sun, 08 May 2022
 09:16:30 -0700 (PDT)
X-Received: by 2002:a17:90a:fd10:b0:1d9:2a41:6fe6 with SMTP id cv16-20020a17090afd1000b001d92a416fe6mr22328199pjb.196.1652026590798;
        Sun, 08 May 2022 09:16:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652026590; cv=none;
        d=google.com; s=arc-20160816;
        b=WrsKlcwFDSZ/D10cUAYTTb6LM1IDwaf1UEyIxr4+JQ36ry2b/tr2vdW2VSPURAVBwa
         B/YDyUWnJZYOKo7Dn57R5AcTzQhA56NV9iaAHXm8OF74iBMXYw9lI2OsM/Ysrq0ZUzhG
         ONxbcjauIi18KKN3JGI7biNZVJQcTKcaJOLLLwhMnUFaS7dQ42PKzWjje+KiG8lYip6q
         wPPEPCGqTcFZ9rJNz49Fumq9XmBOD8rcYmQTrDNvZqhkImab+Dv7T4IoTvbE6RofXWco
         K+aYviliBuuv7ui913zRoV6p+JPISeyiAIRtqeD2MCZMtwhxYo3LkVxK6T7sFZsIbmb2
         85qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mUybj7H/UOKVedWyWATy5/DDOeXg+iw2T9QAXkaf4Ko=;
        b=qCM6psGQKjNti9Eb5aclDLEN/kKhdapRuwEc+xkLFsJaoCjGevmWph4vhaeBHHNjdb
         Bqzf1D4mkAq20g3HhkXX1x8/zFspWtt68WnReIMXkgfIvPzVc7wPg+G1af0G28zgFRt5
         bZpMrzJ2+kNPnfy7ixT7P4VoCCF38jkgbO4RzWoG2u12gAumaZ3UoY7SdRAymy3h0Qep
         UisNotp+CQCg9ZTI83HpsIwaHc0f80FSulgLiFqteh+7/qpM7FENxBQ/T8xe34pbqSo6
         z+8rF3ooz8MahyUxUVQCAQTunXQZ5HLcokg7vibTr0rWB+YyiFDCIun0kWV7UN+2f2OY
         XT+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mdPAo0t5;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id s1-20020a17090302c100b00156542d2adbsi408799plk.13.2022.05.08.09.16.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 May 2022 09:16:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 507696121C;
	Sun,  8 May 2022 16:16:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BCB75C385A4;
	Sun,  8 May 2022 16:16:23 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v2 1/4] riscv: mm: init: make pt_ops_set_[early|late|fixmap] static
Date: Mon,  9 May 2022 00:07:46 +0800
Message-Id: <20220508160749.984-2-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220508160749.984-1-jszhang@kernel.org>
References: <20220508160749.984-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mdPAo0t5;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

These three functions are only used in init.c, so make them static.
Fix W=1 warnings like below:

arch/riscv/mm/init.c:721:13: warning: no previous prototype for function
'pt_ops_set_early' [-Wmissing-prototypes]
   void __init pt_ops_set_early(void)
               ^

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/mm/init.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 05ed641a1134..5f3f26dd9f21 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -849,7 +849,7 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
  * MMU is not enabled, the page tables are allocated directly using
  * early_pmd/pud/p4d and the address returned is the physical one.
  */
-void __init pt_ops_set_early(void)
+static void __init pt_ops_set_early(void)
 {
 	pt_ops.alloc_pte = alloc_pte_early;
 	pt_ops.get_pte_virt = get_pte_virt_early;
@@ -871,7 +871,7 @@ void __init pt_ops_set_early(void)
  * Note that this is called with MMU disabled, hence kernel_mapping_pa_to_va,
  * but it will be used as described above.
  */
-void __init pt_ops_set_fixmap(void)
+static void __init pt_ops_set_fixmap(void)
 {
 	pt_ops.alloc_pte = kernel_mapping_pa_to_va((uintptr_t)alloc_pte_fixmap);
 	pt_ops.get_pte_virt = kernel_mapping_pa_to_va((uintptr_t)get_pte_virt_fixmap);
@@ -889,7 +889,7 @@ void __init pt_ops_set_fixmap(void)
  * MMU is enabled and page table setup is complete, so from now, we can use
  * generic page allocation functions to setup page table.
  */
-void __init pt_ops_set_late(void)
+static void __init pt_ops_set_late(void)
 {
 	pt_ops.alloc_pte = alloc_pte_late;
 	pt_ops.get_pte_virt = get_pte_virt_late;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220508160749.984-2-jszhang%40kernel.org.
