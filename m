Return-Path: <kasan-dev+bncBCCJX7VWUANBBEHWY77QKGQENU525VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B3F12E8D79
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Jan 2021 18:12:49 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id i9sf18759507oih.1
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Jan 2021 09:12:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609693968; cv=pass;
        d=google.com; s=arc-20160816;
        b=z4wNc+HgJ8r4t0ns9KhamQHVcnVwi2vNkfd1Pt8bJJBh2Z7/7hrWUi3GrT0ZRPnVpK
         DfDyzSto9CHFqPCgfvlmHX4JPXBROJ6rTjJMkLzN+84foHcPo5DZgm1LqRZMfcqLoZ/P
         a4CMHlHqaJF+ucxBnygvZQ1L25O02B27i90xBfuUQSZtUUBF92xMDshQFs+m9tzxtlc+
         R0MsSPiwG8OAjnLqqCZO87sIIr4BWjbj5s9uZfczzMBIOz5HZgouRW+la0f8a5R1aDKX
         YTa467OVpa2mWk7CYunv1Jf7bHvuCgh6mrHIaHh94UT62Fa/BvcnJwUXhBCc8VYg07u5
         It7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=lgS36734JkogZBWrf+CeyxpCxvoqNBB/A3u6dyJsSA0=;
        b=lA7CAQCFf0YJrx2eLTQdDFpEnt2K2uFsnrhFNmEfuiGwCAOcj5PIeViHIUhNCiw7kt
         Vb0R2dPIjYUSekHL4N/IZD4vYZt+BaljuMAhW55+g4uPPU1JYWibieJLmlWS49LBXWiM
         ro21BesKeAd0P6nGBiJXdQ8Rn6Ji4qOIHjnQkcH9UBnEsTeqoJsn6p9dHhsel+/TpFFz
         R5/b/YMXxLhHAzqUbnh5yNfiuwdIGa2/zvMcWCg7VcRcoZ9vM4IMA7QvWroO+M4hyLSs
         2NwHj/ftNZMxU2XdpHvsTUfmFTWEBci4sM7RUG/Z4LJDgHl4MPbb/SlYP17F9sAhT+2v
         EilA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=OMdVh9zx;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lgS36734JkogZBWrf+CeyxpCxvoqNBB/A3u6dyJsSA0=;
        b=iPgi21FlkkREZHBgMCVoZ+dpuEwsDJdIdxTZNnf1QjWdi7VGGwSeuAnzoFpVmBO9M8
         5ph2NJvn9YtKzm4VSnl9dlDr+6VU1qlt08dq8xB9O8NJVQnEtfx7MZGe/zF1wgekD6wv
         ZtJ0o66hzdYKxO8rDel/hVvnVWCAGBcgZqAwGjLnAA0/GtG0bWpI5caPcRE4TDGhbiKd
         tjr1/iQuyMb/PI1WeJ3BrHw7/6fRId9IEr3L8YZALikjv/AzULlBBKMsD14kA57MfQ1H
         Ch4tJzsmueIV/bGgIRepzvaFfLCQE9XcSUX74TFAvGYPD4OJnueS6E/kffWM4blavQ8W
         4wPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lgS36734JkogZBWrf+CeyxpCxvoqNBB/A3u6dyJsSA0=;
        b=X1DxUnqXM8WfGB5spY2WHMZ9lkYK0nXpGilYspEJSneVHFa+hgCt9VOAUv+y3ric0a
         6yGy6AnsL0f41Saw1rjAtpP/pJMWQh9tOehE2jCv7CaMajwBPNj/Qt3dTJ5/JAomuVT6
         7ZFeuDfnzcD+1HoAOKgp4cHcHxyTyxmQgNVlB1iwCOn+24UCfbmX3FVJy4sqo+B7bAT6
         Z8sk/NmEZK7QhoFMGnXlwsGSCdbgDDJq1P99aTIZmYkTj7wbdgxy8jXvHnx2vOdaIxAA
         IZaPvCCZ+O8hgfyes4GTeLMhURFQeSO2EX1OqLAprq5DCoRYyiBujq6DanBkDmXAc1XM
         fB1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lgS36734JkogZBWrf+CeyxpCxvoqNBB/A3u6dyJsSA0=;
        b=WokuOFJbWp0FK8mLTWnVFcFTgVpGIo0fq0JOPuR9cV3tK0uuiU6FJnYPNuO2x/z274
         MyAAeOwc8HZx9fya115TVT/HzAGwlHI09wOhKzWswU8ooB0Gn4C+f0ZnTpCwkOHQtpJK
         rWk+2b2CCW/y9mAZ375IVremAk99i910uy8l1j0VCmP5tRt4OMWdhtxMvvsZWh+9zT3X
         4FGNS6B6dkz+oLVP67q6Dq5RhxCj0UL37VXJATkTqfELy9XycQJ1uJxuq+MVePe/WYDi
         vJ772e4059rcGSBW2lE0CO09/VQZskPg8XHSMt8lNEP/OYnrlrxWbUn8Kr0/gdrtXrCX
         adnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ghcfgpY7GbZL7f7GliSfKXJ6ew5bIAPchDd3XqvzkfmBv5vnD
	BQzTXHoj6lFEJXf6nI8cM5I=
X-Google-Smtp-Source: ABdhPJyyz+CSdfeTBaow9XhzkbzViPZ9MOMfPJazcRwAMxRedsgsrXGTVDJs6eTf2tT4sCsSy9xXwA==
X-Received: by 2002:aca:3784:: with SMTP id e126mr6038667oia.170.1609693968267;
        Sun, 03 Jan 2021 09:12:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1204:: with SMTP id 4ls14389446ois.6.gmail; Sun, 03 Jan
 2021 09:12:48 -0800 (PST)
X-Received: by 2002:aca:e107:: with SMTP id y7mr15590124oig.57.1609693968007;
        Sun, 03 Jan 2021 09:12:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609693968; cv=none;
        d=google.com; s=arc-20160816;
        b=LGLh4b5SJS/IFbr+9zjyuZkjvDeTuCyRqO0FGFL2irMtIlXWRAoxl2W9T1GBZ5y6rW
         K7zKBvGx/mS2gvD9s2MThpY8devvQr0zuile+mqpoKgtoC0CRBUn91JW4Oi3gesF3LS1
         +bTbomGP4hjXD7tn2cMJA619cl52D3ZJ7oRUpPDd5WDkC6qjpzyt0qwnqiRoRBYZSAqy
         S9s4z0SkhWx5KHgHkOmFkUo7AruHQPWkK8DncJECAYFuKoq1ygUfKf0GBSLjGnMZb0/m
         rV98pU/SeVICDqdH8rSAxbSSZALJFgmwuNpDtXXBF+M6NJfuOKMWg3GRtvEuLQwnjOWJ
         ZPVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+qF0SijNFO/T+7vPigxBwLWfcVu8oPsZO7isaPG+ku8=;
        b=UxKIhenTXXr88sHuahmF1RuM3LKNtdzz/zunqZaBi17mnoUt37iEPdtwwEsQwKC9em
         gPiPTAfTLVeKo7i/Xv1ss34iGFZtXb+z+Z13HPJt4ZNSu3GrEZPGZzTxpX0gTpIayNRJ
         C2TLED05TLG30hK5i3lHmisKWPvjg4hXiYgSJ1cTx9QXhkCbg26ZoHaCj/jL2rX/1KgU
         ddFWlPSO9cho47N9z9cQ/mcadqfRBbMjzPu7fC0/9Wx/zpB99x16/QBqOVb7dzj7k5bN
         +FSndxuCiKqWM35qMmk1wnXj24YOPcKdpQF8OsHZe/iUErHTjTHeX+xd3+xTyIcTnK2d
         KpYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=OMdVh9zx;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id w26si4084777oih.1.2021.01.03.09.12.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Jan 2021 09:12:48 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id b8so13176326plx.0
        for <kasan-dev@googlegroups.com>; Sun, 03 Jan 2021 09:12:47 -0800 (PST)
X-Received: by 2002:a17:902:7207:b029:da:fd0c:521a with SMTP id ba7-20020a1709027207b02900dafd0c521amr68665365plb.45.1609693967387;
        Sun, 03 Jan 2021 09:12:47 -0800 (PST)
Received: from localhost.localdomain (61-230-37-4.dynamic-ip.hinet.net. [61.230.37.4])
        by smtp.gmail.com with ESMTPSA id y3sm19771657pjb.18.2021.01.03.09.12.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Jan 2021 09:12:46 -0800 (PST)
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
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH 1/3] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
Date: Mon,  4 Jan 2021 01:11:35 +0800
Message-Id: <20210103171137.153834-2-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210103171137.153834-1-lecopzer@gmail.com>
References: <20210103171137.153834-1-lecopzer@gmail.com>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=OMdVh9zx;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::631
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

Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
("kasan: support backing vmalloc space with real shadow memory")

Like how the MODULES_VADDR does now, just not to early populate
the VMALLOC_START between VMALLOC_END.
similarly, the kernel code mapping is now in the VMALLOC area and
should keep these area populated.

Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
 1 file changed, 18 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d8e66c78440e..d7ad3f1e9c4d 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
 {
 	u64 kimg_shadow_start, kimg_shadow_end;
 	u64 mod_shadow_start, mod_shadow_end;
+	u64 vmalloc_shadow_start, vmalloc_shadow_end;
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
@@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
 	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
 	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
 
+	vmalloc_shadow_start = (u64)kasan_mem_to_shadow((void *)VMALLOC_START);
+	vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
+
 	/*
 	 * We are going to perform proper setup of shadow memory.
 	 * At first we should unmap early shadow (clear_pgds() call below).
@@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
 
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
 				   (void *)mod_shadow_start);
-	kasan_populate_early_shadow((void *)kimg_shadow_end,
-				   (void *)KASAN_SHADOW_END);
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
+		kasan_populate_early_shadow((void *)vmalloc_shadow_end,
+					   (void *)KASAN_SHADOW_END);
+		if (vmalloc_shadow_start > mod_shadow_end)
+			kasan_populate_early_shadow((void *)mod_shadow_end,
+						    (void *)vmalloc_shadow_start);
+
+	}	else {
+		kasan_populate_early_shadow((void *)kimg_shadow_end,
+					   (void *)KASAN_SHADOW_END);
+		if (kimg_shadow_start > mod_shadow_end)
+			kasan_populate_early_shadow((void *)mod_shadow_end,
+						    (void *)kimg_shadow_start);
+	}
 
-	if (kimg_shadow_start > mod_shadow_end)
-		kasan_populate_early_shadow((void *)mod_shadow_end,
-					    (void *)kimg_shadow_start);
 
 	for_each_mem_range(i, &pa_start, &pa_end) {
 		void *start = (void *)__phys_to_virt(pa_start);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210103171137.153834-2-lecopzer%40gmail.com.
