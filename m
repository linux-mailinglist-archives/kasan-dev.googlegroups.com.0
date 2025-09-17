Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBXVOVHDAMGQEGFOSAWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C350B7C3A2
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 13:56:21 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-7509629d847sf6863597a34.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 04:56:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758110180; cv=pass;
        d=google.com; s=arc-20240605;
        b=B8x5Po7b6POeEr0p3Js/3NnW6D3bXdYEgpSsS5yxXNmLiZMdeRjC/ChvPn6q3x3MIm
         HDoP8mLNn71UNX7c1rL0w2ak7cNkXmR0Zr71IhOtKfmuTKwpl/VPkDslOFfwTor6XX1V
         EP+qvWYTjf6kBlgASHLqalJRMcyPIqPbVGPosnkHJN61AbBFxMDViyIDD7/VQnvuYgGC
         9OA+Z49cpZOmMmfVr7Ii6PjCIXm0Uj4EVRGvefmePJKBhgnXvvRw8tyncJsD+N/m0KHR
         9i+WVhhoLTX/yLSRrrs+5Wpu0Q8SxBdSYgZvxRm8jI2nDhe95/mRVxPc8TBmi8OwgqCK
         //Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=PWBC65kZvD9fZWv51dJ4q4v1IAIGSBlyGonfKQEZFVE=;
        fh=+uP5sN9AoN4rbDLQcYhOKCEWIgkqIDv6utqwM8pO2gg=;
        b=hjqAc3oFcpXn2wEputTR75LB7qi6n18gm3oZOOGw1y8nbhpRGmHtmv/sRK+OQS+kM4
         JdzMy1h7bH6yKUY2v/oADAJd88yQDn+MBGihv0JYybhKXTAhU689gm4zaGWCZJ+Xm00z
         Zjk84FNbgGdfY1nmZE5+agppwdXEa5+RPYKHnaxrQWDy1rim8SRRbaA4+sF+4+2uW6W1
         i4Klqhz/bcqDYHqQdWlD+jweBHYn8UUoJlFYCfJOxbhzAehPnCe2Sri2UlZgNMD6lcq3
         iY/yx5VPbj6x12Y0uFApbTRwy2LAihyazTyBen6E5ZJkJ/EVh7SKrNoQODb9zA1cVMLr
         fi0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IuQW4qLP;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758110180; x=1758714980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PWBC65kZvD9fZWv51dJ4q4v1IAIGSBlyGonfKQEZFVE=;
        b=OBL8hj9cHmnj2v5ncTfsJrwuXyUXAZ6CWzTojA6CHniUciWA9SP2j58u+1bcFJ0aqm
         iu9cBjy0+MI1Q10jLO94HuexEeSI5BkVaAGHLG61gAEvWENm+SfKE035DaszUHNq1qMM
         7VYDnfEdUL0PIE8XseN4NEDU5lnmWRcY4vVgmijf6v9p2MM8u+/GluM0aBlQYXZhQ1Dl
         ycRVnJc/0hrT7+5+YqHLjob20pp4iGhkc4cDTowpqewZMaIeIJFK7bkr2U8R0uG6T8z7
         FtlfGcK3SRp+eBiDMFyGC0iGBpohKrsTpx3zfHx0mtM2YpoOgbq/XMO/JN+nr1W5Xwy5
         tbIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758110180; x=1758714980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PWBC65kZvD9fZWv51dJ4q4v1IAIGSBlyGonfKQEZFVE=;
        b=v2fM4VUrPEt0ECyQFIzVaWYXe2RhX1sJlpvytxUBcTOcR8EzuFSSwWPD3ZctnoSpmA
         f+9I5Zc2VdltDOGqjQBqGniNDNzeKnQRwyhdmYWDY0VmFekLYYxmyQRCgkbs52y4N2gs
         3ohGlDL7NGwWQKFU1YpChg1cyxB73sr0GPu+SniMQz8av6w0BFbh0ls2pylAJ0Jfs92Q
         fNLUFBbnU/9d0l7TNfK1nhoYIIHiGX1QrufZbNH3VPSZlJRRSzWSQIUJQSJygprXp/fx
         5LeTr29Pg8d+KB6ICBiT+1TtcTe+ywLKP8Ka8lBA3JvDyG7he+uT0e9slmJNJjKaGB6n
         bFFw==
X-Forwarded-Encrypted: i=2; AJvYcCXN61wKdb8WwC6SlYwQ+QkCno8R8RQ6MbkoAiUKaePvB6kK49zSwiglmnzbtLovZeZAvx1usw==@lfdr.de
X-Gm-Message-State: AOJu0Yy6vHeARkq40gUFwkSXYOi7r7FPZZhwTQHgqnIK/HoCBYGQfzsN
	YUVuDSSvMCZh2igkG88finfCOExqYchWx49vqEfnR/NFHoXBN5lRQrDG
X-Google-Smtp-Source: AGHT+IGfP9aRki2GCxCPZxx9mjkjqvWURdLEoooRvaUhupSCr09BMh5F2U95fV5JSnXbjTBLqdnbcQ==
X-Received: by 2002:a05:6e02:1d88:b0:423:f8cd:739e with SMTP id e9e14a558f8ab-4241a4e1019mr11522935ab.11.1758091103198;
        Tue, 16 Sep 2025 23:38:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd57NoxkFkSIjRMcQ+qYKek2Fas6QbPaaQkLZU5ho9pdqQ==
Received: by 2002:a92:c24f:0:b0:41c:6466:4299 with SMTP id e9e14a558f8ab-424010a0b84ls23804305ab.1.-pod-prod-07-us;
 Tue, 16 Sep 2025 23:38:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUi3z40JAauOGbBl5Z5DW4i/Gsrp7phlHI4preii27q78LSHloWkaQM65F43IRl4butYxQlQjEptgo=@googlegroups.com
X-Received: by 2002:a05:6e02:1a09:b0:3f1:931f:bc33 with SMTP id e9e14a558f8ab-4241a54acdbmr11021555ab.24.1758091102144;
        Tue, 16 Sep 2025 23:38:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758091102; cv=none;
        d=google.com; s=arc-20240605;
        b=dF3YdBQ8RxX6GD+eOJEAmbKE4zECQ6J1DvG1g+5sxT0G07UU7c/fzRFw4Zg4wnL+pq
         xs5YA8VdrkyopKEFDjjgg6VN9cujZevkHRBTcGGmHX2LNODBHC5lsd58nSBfSdgltXyi
         b6qngSZ/OEFkyffAr6/PUcQ72hl8wFYNhO0AO8nfpnyUYLLLyuRDNxQ8xAcw5gekxSok
         CRSe/fJ/8aGL+Xz5EbAbrmWZKDEk3sTBVjlarGSwQBILMekpH3GGT+3I8Tbgd/qPGNfU
         hJH7V/eQCRu6UiMlIybbGWRhQP74OZLzkta9wSGeAiMUhljCBwkUDdqfCmaEuUk671RH
         d8kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=MVI3HAtab8kNZWveLBryTVR4KMrizuFaCRKQXr1wpU8=;
        fh=4smB/2pAJF/5Gh0etI1CxX7xhZbPtL/kE2Eu9eUs3ds=;
        b=BQVXR64ReAk2Q8cL7EhainxSbfMhb0UK1gBdj3Ligup9VnFvVLlBiACz+EDXx/HmrU
         OxpkE4exHcHcm7+y8CbjoNHT5MPES+MzSDLB4eiXFQbVDaw5X28jFy+hgfP+Q0BRtTnw
         PHQUb+J1kpT84mkISnT1oYj92S3BSikOSh0+Vz6ku8FlnbNhVQiGAYd9sg/8RJDRSL64
         1/JRmyIVsi/P4LPP5g6VNk3T/WaALFBasWDNhGLR7sPfK2F1XclUaGwBahYwYb9f0d7C
         eh3nvlSuzXY141GckWFXPB7p2z3i5MOyeFn7IhAO3UB4XmlnntwTNS648nhAeui1ty9z
         aI0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IuQW4qLP;
       spf=pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-41dee17d767si6236515ab.1.2025.09.16.23.38.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 23:38:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 4DB69601DA;
	Wed, 17 Sep 2025 06:38:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8B8E9C4CEF0;
	Wed, 17 Sep 2025 06:38:20 +0000 (UTC)
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	kernel test robot <lkp@intel.com>,
	linux-mm@kvack.org
Subject: [PATCH] kmsan: fix missed kmsan_handle_dma() signature conversion
Date: Wed, 17 Sep 2025 09:37:36 +0300
Message-ID: <4b2d7d0175b30177733bbbd42bf979d77eb73c29.1758090947.git.leon@kernel.org>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IuQW4qLP;       spf=pass
 (google.com: domain of leon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

From: Leon Romanovsky <leonro@nvidia.com>

kmsan_handle_dma_sg() has call to kmsan_handle_dma() function which was
missed during conversion to physical addresses. Update that caller too
and fix the following compilation error:

mm/kmsan/hooks.c:372:6: error: too many arguments to function call, expected 3, have 4
  371 |                 kmsan_handle_dma(sg_page(item), item->offset, item->length,
      |                 ~~~~~~~~~~~~~~~~
  372 |                                  dir);
      |                                  ^~~
mm/kmsan/hooks.c:362:19: note: 'kmsan_handle_dma' declared here
  362 | EXPORT_SYMBOL_GPL(kmsan_handle_dma);

Fixes: 6eb1e769b2c1 ("kmsan: convert kmsan_handle_dma to use physical addresses")
Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202509170638.AMGNCMEE-lkp@intel.com/
Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
---
 mm/kmsan/hooks.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index fa9475e5ec4e9..90bee565b9bc2 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -368,8 +368,7 @@ void kmsan_handle_dma_sg(struct scatterlist *sg, int nents,
 	int i;
 
 	for_each_sg(sg, item, nents, i)
-		kmsan_handle_dma(sg_page(item), item->offset, item->length,
-				 dir);
+		kmsan_handle_dma(sg_phys(item), item->length, dir);
 }
 
 /* Functions from kmsan-checks.h follow. */
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4b2d7d0175b30177733bbbd42bf979d77eb73c29.1758090947.git.leon%40kernel.org.
