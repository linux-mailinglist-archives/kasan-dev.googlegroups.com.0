Return-Path: <kasan-dev+bncBCCJX7VWUANBB6EM437QKGQECQBOT7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 862D02EFEF5
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 11:33:29 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id a1sf9774851ioa.11
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jan 2021 02:33:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610188408; cv=pass;
        d=google.com; s=arc-20160816;
        b=O3TMC2SRbaeeZj8OCRQk53/vpqpnRv9Q9mfzK9AO6EZUN8wkKB19W1qBndYvdjZOx8
         yAMAfuyrjjXiV6bX23saF680fxD0YKyAx8W5IipzSMFJnkt6MJklstGR6B6U3xgcM0b4
         fRbMJ54M7lHViWdsSfle+gY+559aHIKqog4QdCQDhZS5QsSRFAS7Fp3118dNj2gcmf0+
         GHQBEJMM1F7VRfH8YAN0//4bSgC8+4TmJg/T4GvuSLMx8DhA6UJfd86QJwrWKm3IrwU7
         CzseUbYcNurhiyeRH0itjuaJ6B7LBFPNgtOJl6jhVSmc4VNw1yzTcijKkFs6bmjSmfF2
         D85Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=l3B/E/e28KFIG2ddBttS810bPWmIVLPBJDW/6VY4JxY=;
        b=ruPlFdqJdm/v41dYO9Q0ksBReff4EP4LoHP+YMjSr8WRXlLnwL2zDKse+no7ZmWR1Y
         cSOUaxXSDVe/9j+gm8ybtnqRY/+Xc1kW/Nzki39dM/Sc8nDJPuSZru+v1X/U9UoHmIop
         oPTY2cVQKIEvMUpupkA3p2Fp8xR3T3MeGvxhxEc8QOCek/rU2o8zdNwUKAkYvRVMRMYo
         mnsoqbnjvwenqSrgjj/z0IY8P/SjfM+xaSgnGhFjs9u30ej12VTU+aV6ul9eXfvcKeuj
         xmf3WMbCyc3qArErTVJnbWm/Nzy8NoCGwnTanbuai1vLWI9ndwKxBG6n4EsCV8s1uQOz
         i52Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tIBodBVv;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l3B/E/e28KFIG2ddBttS810bPWmIVLPBJDW/6VY4JxY=;
        b=lyhwkFuPJo3VIeaEcylOJ9OgdKV4stusQUA5nZmPW3H0pIIISaQvKevdlCqRtrIvnY
         8R2Rmxm51ZiRXkPFRRgafpnOhqWz/qnxA6uGIh+uu+6rQImnD0NMwfAc6NiIgpbmBwG8
         Gr+2WDOurgkYdbsdc5CDR+VpoPDrmJzrvZ2dNmqM/GBk/eirwFLeMytFczcjRzDaS/wf
         8CfFWSgzE/uvIr2CdY9oo7Qa1EWl9nO3NqNFtRwMvukaDfrOZsmDPBPxCsJgRbVdNscD
         cuQGnRRXecaTtAaTqQxecXLgXFp4T/UDqIC8g9u/ldhy+bJin417nIu5mtJ87JZ368gT
         pErA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l3B/E/e28KFIG2ddBttS810bPWmIVLPBJDW/6VY4JxY=;
        b=AV/+0V+SunMdCp7uzCDkt77WVXoip+cAhA9p+fsSKTANEkMDOPsMTGPhobCz8GPPef
         m+JIqzlwPpjRv65dLr7/GiqQJMoyjLw6rScDyQXPUxeJYFuJpkCNmfpG2OXafAc3wRIX
         72IAzFoJTrN4SCeuORSiMcvb2FTyCLk9kS4Kj4/iWWune9yXRYNztZpVkKmi+JBrr02Z
         QVYbFV5v22G2RQIylqDqFiUPlstbq1RUg4OvqEW+2tjtt1Qg+xMo398dNIoSFB5YY9rL
         3dtRjdzRaOiHxzYj9BHjoAm4fnvtKS+HJvLneZUcy+yQgyBEcxF9LH5tjmcHiV7B1Ltt
         8EHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l3B/E/e28KFIG2ddBttS810bPWmIVLPBJDW/6VY4JxY=;
        b=Z+OI8MV7KpiZUWeg4pFG8nLSN42PPhWbMov7G9C4X0lgresoOxbfFILyZLXdSmlFM2
         Bic+BpNS4cqB9UqZdQWjp7s1JcKjJGQMYfSuTdAFfoRC17S7kEXFqV/yCRj444S7jO3Z
         PBum19qsu7yUcPqIXd7efL/SzyV9h7NnQBBhVnBNI6DhXcJGXHpi6VJl4536XCur+rtw
         DXMm06+mC0LXNyIZNQVlxmaT3YDlTuj243BTZA4k0TAGdlyFRh1M8dCRMM9xjrd7UcMV
         GxEqUtDjUxxaRsuL4vU2gboJyfyrlx08SMYWbTFe42fOZC0E4KyJoehYl5vZMVccRWtn
         tA4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531lt57BLQ56yII7hX8pO3y2ZAW27UKPCWh4Ye5Yis1nGy0NKMtg
	nk99D1R1AoJhmtusWhSMNwc=
X-Google-Smtp-Source: ABdhPJwwsAsqSi4hrQ9KrRrtoSIItomoIij37dDcWgp7xUt/Rtjf42drz76qxJgZhzwp5PU54iA+1Q==
X-Received: by 2002:a92:cdac:: with SMTP id g12mr7744620ild.145.1610188408405;
        Sat, 09 Jan 2021 02:33:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8993:: with SMTP id w19ls4035047ilk.0.gmail; Sat, 09 Jan
 2021 02:33:28 -0800 (PST)
X-Received: by 2002:a92:2912:: with SMTP id l18mr7943210ilg.173.1610188408048;
        Sat, 09 Jan 2021 02:33:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610188408; cv=none;
        d=google.com; s=arc-20160816;
        b=OZGfYstGVBsel4fKHLDL8dIRPUEGhBqJlkRiqPoheLWJo3lyrBbNVoOscBELXlThYy
         wcApnPcpjvdU3PaK5KabRLs13/5FFbYoOTDDvwIjUgqGODJ3vzokq8d8RpCzldJoMBTG
         VFUP1/Hi9U0/7rJO2SM5r89zT/XywRDA3hc/RjjGqFXalVrw+BlnVQgrfHaYtM7G85iU
         ynTek+kQx02W32NSSbnQKVv6oWKzg+J0NUlqj44lncuJ4SoGfxT5mtTD6BrO2tGmASdo
         V4sjR/kUbsMxLmPjPTgFvmcd9ETK39be5qOCJ486CHaT/DwZYAktoV+MMGyv6UToXu4r
         evOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3UgUJ81KV4RLYeQfSGzwX3AUr5zkvCkqoF7/Wom4eVQ=;
        b=kBfOepYfSntAddHPq+KZk688wypCyIXbVtr4oa5sEEfWJq3zSJ7jejHxTn5fWsqBYS
         92fWalOaSxX0qRRc5YQcL40GL4Rf/BvJ7cWdpeY1k7DyDCBmHWAAEolDRQ36sHyhG68U
         uJSv1xj9Zjvkuunp/lX2rvSoNMbBkjjqxMAwZ6ecEhMlPfsWUnPR9jqpytg/dEyWxmKh
         dtYvKkDxJJJmW7TkPppoVbrnQ/r25i0kMjyNa9tia+TUBY2FEm+0R/sOwuW5VTy0Tx1I
         X/maVQQzu6/nHoq3YBmzq9WXQoN2eZJc+Rkh8WQ0X4TPV0ufyVHufUbMDtL+LiRZSagQ
         SqcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tIBodBVv;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id y16si103269iln.0.2021.01.09.02.33.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Jan 2021 02:33:28 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id g3so7039521plp.2
        for <kasan-dev@googlegroups.com>; Sat, 09 Jan 2021 02:33:28 -0800 (PST)
X-Received: by 2002:a17:902:9a02:b029:dc:3481:3ff1 with SMTP id v2-20020a1709029a02b02900dc34813ff1mr11034416plp.28.1610188407451;
        Sat, 09 Jan 2021 02:33:27 -0800 (PST)
Received: from localhost.localdomain (61-230-13-78.dynamic-ip.hinet.net. [61.230.13.78])
        by smtp.gmail.com with ESMTPSA id w200sm11691572pfc.14.2021.01.09.02.33.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 09 Jan 2021 02:33:26 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	will@kernel.org,
	catalin.marinas@arm.com,
	ardb@kernel.org,
	andreyknvl@google.com,
	broonie@kernel.org,
	linux@roeck-us.net,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	robin.murphy@arm.com,
	vincenzo.frascino@arm.com,
	gustavoars@kernel.org,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v2 2/4] arm64: kasan: abstract _text and _end to KERNEL_START/END
Date: Sat,  9 Jan 2021 18:32:50 +0800
Message-Id: <20210109103252.812517-3-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210109103252.812517-1-lecopzer@gmail.com>
References: <20210109103252.812517-1-lecopzer@gmail.com>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=tIBodBVv;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::62f
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
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

Arm64 provide defined macro for KERNEL_START and KERNEL_END,
thus replace them by the abstration instead of using _text and _end.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/mm/kasan_init.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index 39b218a64279..fa8d7ece895d 100644
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
@@ -241,7 +241,7 @@ static void __init kasan_init_shadow(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109103252.812517-3-lecopzer%40gmail.com.
