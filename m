Return-Path: <kasan-dev+bncBAABBBFWXSJAMGQEEVXJFHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 35D1F4F8598
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Apr 2022 19:10:29 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id d29-20020adfa35d000000b002060fd92b14sf1470516wrb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Apr 2022 10:10:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649351429; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhaJOr0ltDmcWnCalyU7OqsfmYl7ZWu0jisUv9Np7oCdbT6GmvavSfASg09OTKqmre
         0S2XGUNf3xWgxRclaAG14+Q9AqxjuPqJ3Wo2RSAwiI95OUm2H+098s60ZCllFSnNIzhM
         zP3amm/F/cMoW6U8ULmZAajsZxAriEkHFlm+TKhgaGK/YBw6sGThvfMjHMQWzzeghTVq
         o6HxAHL3CSvWavyzRvlK5+8wIiSl1ARbPW0wVnnpcgkEvKj0wvKpq05QAnkxJGF2/M8H
         fEbLV+jzEzNGSIfy2cZmuTS0sqZSKswSr65koHd5nXDuA7xcZN1kT49vDrm4zV26gXfb
         qjPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=zOoKm1rUmMJPVO528QBRI5kDusG6UQD847jypynkl9U=;
        b=AzOS7PonR5mIEu0FL4qWfGRScdFucku6BcUl8Fluy3HUuvSiErYzB+F+eJoOxH3isX
         D8gANHuwdXbYfKrms0/E1AIFERlq57qb22U0fVrYOQdshCt9KFaw9O/pLImOoXPDjbyO
         Cx/8WPA9QcmSm0iFnBCyY2KRZshbmh/B3bRUrQwFs5whr70sXxdjqWEyD9m+9xdKKZYC
         5zno1njIRHKDwJBS18iV6AASv31gTgxTNjIjaaHj/GtaPIs3Ms62uU4LNQTA2S8x8KEE
         fYew2Wc9vJJcsuwfoWgjGO1lr8N+eENVe8s6NEul/ciW1YcvRMHo3Of0GO9bgkNfWYnY
         FIkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z4SrfJi1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zOoKm1rUmMJPVO528QBRI5kDusG6UQD847jypynkl9U=;
        b=fA48IV3oyxOCb2WzABS8ibgIXO4GzTRWqq/LUSmJ4/m3vhh57jObIMA8byc70H7WIN
         wgk1sLhhHQ4u1maQWKQjsQkpeRIRigQWsjHuxny+FmaKJ2HfWGvoZm4ih0Ej3PFypZM5
         7KCScxDBd8Gaiu7ytwPD6JiDWZQvZWzA8MkUsWHufJImOq4FenQUC9B4DhVnCe4EWZ65
         8Bh9q4Udq4gnBQuQjo/EhcKL/nfW2Yd+eluYA2FWCGK/oSJa3wqWdaqH98rCsd0IFh6i
         OUu0YVCNX3jn4nRBTspAZYy9ZZAMNwv7SSg9tSMBCXr7wcu2r/OyCxeiAboxcZzCpTFu
         WjvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zOoKm1rUmMJPVO528QBRI5kDusG6UQD847jypynkl9U=;
        b=t2JCD/yrKy2m5LEpC/ArFB/6Pufx2SWIBkzzzGyWTp03dmtesA4NV2c50uME8J5Cfv
         UJZDJUPHQ+fn0fUv8L2Ic74tG5SuAfxALb44JmrE8R4NmBoUR2epJqWclFr2Ihe/Y76z
         HZ6tVrwbQ9ZCXpjNOd4oqn5sD/Pcop6ujWuw8Z/KzNRiymEvMhKU+D0lzC0x5tGZTMS3
         K9OuZAsmvcY7L7qGVBzPGZTCJfOt0Vd6OtJG1JNwK8HD+avmfUKqdiRAtZIx7FlUVeNp
         gjAlIt958QoYTi/n0ZRZteeHHU4Bsf4BhXVtDKVlslziqNd7CyHnYdI9WGWFxOF3AuIK
         8+jQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vaJKdP4hh2+jKIoAre9AQTmCF7oreTJL8eiNnaK8LIUUiyhNr
	CBCdnwNvDuiKp20xjuTs000=
X-Google-Smtp-Source: ABdhPJy2auN2LSoGcdiNbDmUyDJq+1w1kkMc0bI87sNipY8wjDVvjW929Hj4NlpFV+ppg9DESZwGuQ==
X-Received: by 2002:a1c:f604:0:b0:38c:8ffd:dbb6 with SMTP id w4-20020a1cf604000000b0038c8ffddbb6mr13155139wmc.43.1649351428886;
        Thu, 07 Apr 2022 10:10:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c14:b0:38e:6b10:3620 with SMTP id
 j20-20020a05600c1c1400b0038e6b103620ls1608143wms.0.gmail; Thu, 07 Apr 2022
 10:10:28 -0700 (PDT)
X-Received: by 2002:a05:600c:4f08:b0:38c:93fd:570f with SMTP id l8-20020a05600c4f0800b0038c93fd570fmr13248847wmq.136.1649351428164;
        Thu, 07 Apr 2022 10:10:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649351428; cv=none;
        d=google.com; s=arc-20160816;
        b=T8xfSRGCFWr21UtEFIlExaKXM9IyV1J4YMOL7gw1oku/HuuTWNRnsW+8Je7qH+mVBG
         lEGzH20LBoXSNGEtoNNPERFmToOrLZ4QyDM/SxKD9x16+iCPWYEHvWlHlckcDBuDHo5C
         1GJFfXjBzfmk2i2x+rTSXDsR6hybu8H3OJD4yCK5wzrr/B80wpiCDX1mLzq5EiuJeDP5
         T0KJyyLql/iE60RYsXvLkzczDe8si4h71yZ9a5PNUiybU555c5zYQOGr1aXXnN0vzQVY
         sKEmIQxwz34TV/AZUbqZlgQ+sH0U0FzAJf9DLsh35kpoEHlw5scZAfA/Dq9GkaDzz7cR
         b+ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=RKada/syRdNLHr4WO/ASA7jzsH+BuRSFKa7ozmTSlP8=;
        b=atPp4Vl3FxwpSesq8vDdGWZ1WpqoG9qR80ijUak2n4BRZjVtVBBZXnr+SNGdp1ewLg
         tNOEPGclRwK61u8KMDugMebwA7dAMClx+0OByFGzSCoyOtbRKFVMvRrgn8OKAdh+F/EP
         fnRN+ir6V1MyZKR//yKJ+LVXLUs0HQaoF80NFro+NXT3n5hRl1E6Hui6C3Ohf96fW4+Y
         5H/18WdjyO/258Guv4x14QQdQRM5XU3e73ItVWcygCmV+LbE01Vkqn5l30nnGWiHQ+0K
         Zb1560ofZEBgHJl4LKz7EUR8uvhp2CPNRZt+udddTtjs89wdWhKtmq3nKLfDKDwDNQP7
         NgRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Z4SrfJi1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id n23-20020a7bc5d7000000b00389f5a1b55asi173980wmk.0.2022.04.07.10.10.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 07 Apr 2022 10:10:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH] kasan: mark KASAN_VMALLOC flags as kasan_vmalloc_flags_t
Date: Thu,  7 Apr 2022 19:08:37 +0200
Message-Id: <52d8fccdd3a48d4bdfd0ff522553bac2a13f1579.1649351254.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Z4SrfJi1;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Fix sparse warning:

mm/kasan/shadow.c:496:15: warning: restricted kasan_vmalloc_flags_t degrades to integer

Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ceebcb9de7bf..b092277bf48d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -23,10 +23,10 @@ struct task_struct;
 
 typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 
-#define KASAN_VMALLOC_NONE		0x00u
-#define KASAN_VMALLOC_INIT		0x01u
-#define KASAN_VMALLOC_VM_ALLOC		0x02u
-#define KASAN_VMALLOC_PROT_NORMAL	0x04u
+#define KASAN_VMALLOC_NONE		((__force kasan_vmalloc_flags_t)0x00u)
+#define KASAN_VMALLOC_INIT		((__force kasan_vmalloc_flags_t)0x01u)
+#define KASAN_VMALLOC_VM_ALLOC		((__force kasan_vmalloc_flags_t)0x02u)
+#define KASAN_VMALLOC_PROT_NORMAL	((__force kasan_vmalloc_flags_t)0x04u)
 
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/52d8fccdd3a48d4bdfd0ff522553bac2a13f1579.1649351254.git.andreyknvl%40google.com.
