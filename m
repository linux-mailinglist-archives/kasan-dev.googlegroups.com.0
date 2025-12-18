Return-Path: <kasan-dev+bncBAABBGODR3FAMGQEUWORIUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 298FCCCA7EB
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 07:39:24 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-34c48a76e75sf714707a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 22:39:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766039962; cv=pass;
        d=google.com; s=arc-20240605;
        b=jdtr9HWRxaREmq7ciEd8LvVz9nZnMdw7O19hd1DwOKGkqdaq0V1ZB9w2jg3D02iTGz
         0GAyeMDc4LaV6RH6Hihbt4y5ROHtJX5P04/6RDXB6+yK1FHAcH6KVe64Mq+Ben/D33k0
         5hMSJ5KV7v/Bv30rgKtWsD+VpZKRSppv95R3YA7tYgiwVHCKPrVYmB8K+YsQNZdKBOgr
         DnfbEomF0J4jlR4d/O5ZIpjVhdjGInP3nzaCWc+VWaplSKksh6O+3jX9sMZn76HRlOmV
         PeEB828dXC+qa9SGsYyTlD3Dv+BtrFM1ned2922F6/FSywfG97jDi9ns/yLOIfH7MjxG
         VO0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wqd8P6tLbcF8pGwspKrW4trGeHYM9cjYuwS5YU+6Gc0=;
        fh=ToNvJ/+QXagMWSciTVMRtpNTl3irVPGxJwajh3FFqEI=;
        b=QIcPMhQMkxE7HuqVemWH+e7858d/CYEiMR9Z8x+w9fPTfpks6ZWvhqPrRfMFU4WUa8
         hx9u6br2GELwlwalMsKbrCHjvYFX6AUIn1JPNJqP2182scSYZIt33YVa+TZ+C9jTHrwP
         OUbDX1P9Uy0XbLTG56IZbZBRZxyAEe03RpYQPaSrMaWdHfaK7sHLa2Lx72j4xDMFv19F
         emv55phPpGRzAQmWsMxmTII8+zSop8IHCbMUdxFJif5ZhJE4rjmrk6jQO3O+BWlp/Zgi
         UQ3VB4iALsQrjfARMpCSUZiiCIJJ6NY0y/i94FAky1mIIAibr1tnMj3M8X1oH392T97D
         AhTw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766039962; x=1766644762; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wqd8P6tLbcF8pGwspKrW4trGeHYM9cjYuwS5YU+6Gc0=;
        b=axia2VVlx+aFLKCTxa9i9NldvmD1GsELtCLiLV+Iv+amMC2WgtaZpPGS4wfsTqpeUC
         +b/s/XH68jnEVnyX82ocumeIpzTBhNO0zc7bKZpCw1GAzHLliPlgJbBXB8PPr2s5IQ2N
         9PSDN3bDkb+IiY2XR3X+irWI6ako2kyqNyJZXeXFno1ZsHm9/1Hl0ZD20K9skB57oGj0
         q1VSJx+STpe45m1yGrEBa/VtNOCF+y7bJ0E0UVal9Co/Yyh9tScgzk+plz04fTyC93mC
         0yTuecGUseE/cVGdJwrCHY+MgBdIcQuVhL94azMfDwuX/NwyJpBcA90WmEK0WBzieqjw
         sKfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766039962; x=1766644762;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wqd8P6tLbcF8pGwspKrW4trGeHYM9cjYuwS5YU+6Gc0=;
        b=lW1c9Ow1dOJMnqku2qVH0h37vO4Nk5dkB8mODjgHEbME6ZO0w6w6eNJviQFeX3P9ll
         vOUM9YfdnQnX1Pt1ROLWpepTpTkO+RmW7ELBYGrfpx3umFVAeefDYqZuf2w9/0rqIUSP
         Mf2tjZ6BC88ZeUBBnLkmS75PYAnLUYvvHGg2/0+RkqpumnxP1HI/kPbZ3R80uerfEt2L
         5QyzFwPSfmP8bfxLrgbxcO2VsALdx48zK6A+ddq0rH5uHDwl7aBLvetFt7lMEQpsrI3L
         mRzVsB1aA4bUHXJs1+RWwjOB7rJMwaIzr0CyGZmfgvWqPRvhZSV2/pdqJmAunZFyb9qU
         1P2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOUYnZ3Nh9mI/vw5y0SBIIYW6Sm/n7FAttQKm32fYxXQ8nNtJpEtUKYAzlZwfuc86n/v0Vtg==@lfdr.de
X-Gm-Message-State: AOJu0Ywe1fPhMxrcSKp8kWwz4dIdk1x3fiQJ6ivFLzq1RUHRHVLZRhlm
	K6wnXMFEy3niQQMxk1u1spfHLnv1IwWObMA3MnZbyxXUZo23+h0SANY/
X-Google-Smtp-Source: AGHT+IHdQ35MgYK/epeWMv3qq3qzT8fz/UwzJ4qVs/igutH/SCMQ0yULL4+gLHgO3oLVwdFE1W+zNg==
X-Received: by 2002:a17:90b:35c8:b0:339:eff5:ef26 with SMTP id 98e67ed59e1d1-34abd76f5eamr18060430a91.30.1766039962331;
        Wed, 17 Dec 2025 22:39:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZFqKfwyY/F/FajWH9G8qeskA/G9nh5Jm94+WNKZSkDLw=="
Received: by 2002:a17:903:124d:b0:2a1:37cc:16ea with SMTP id
 d9443c01a7336-2a137cc1a75ls28870315ad.2.-pod-prod-02-us; Wed, 17 Dec 2025
 22:39:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUE636x/fcr7h9Lfnc4rsbP1cMAff0goihV65bwLJuozny+1ivS9xKVSLQD2diXMHTIzD88FSl1xS4=@googlegroups.com
X-Received: by 2002:a17:903:1ce:b0:2a0:be68:9456 with SMTP id d9443c01a7336-2a0be689724mr152411785ad.46.1766039961132;
        Wed, 17 Dec 2025 22:39:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766039961; cv=none;
        d=google.com; s=arc-20240605;
        b=PTcnls8YkY6wNtddnXVnhb/xE8dOmDacuOxjbYCvVmG2Z/dgmh2+2tvB1/csmdC73P
         g5WmSyrV/iUg6K6VXj2vLF98Fv3SfVTYds2rUzNRrpmZ2gA+OQ3bsCQMmqCaELshi3Z3
         F/ncsQS3JkPX5Cy48r6p/hNxHWnEJ+bsBBMk3km2U+N+L3LLcMfH+kDboHIBWUYtFOhd
         yWUZnbLr8ODbNR6J2j1MYeQCmHs3283/1Ay8Tx9SUUIE/XnU62dmcdNlEyJbDEmMrEUl
         kteQK41eRyfRkZvB2RX/vZGK1FezndblfCfTPXmqCuRl6Ptn0KBgcookpTUQXsAOA6yR
         O5Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=1SXi61QKvEmzRMEh+1xzYP0Tb6bWdmBrzPKuMyImTpg=;
        fh=tXyokhajkC3Hwq5fulW7liM7gDFGcDjcIYOJPNGPN8w=;
        b=A4GWQ0TyxQxkfUOL3RnCbOpdpiEVbL0htpKbBX+7+fI3/k1vfCcNdwrZpmIPP1oU70
         TWhjHDz4njEm2WwCByqqxntoIhd1FY/plkK346wCX4971HpvnmZUPzGgaolBQ/4gnTV8
         YY8FCHLKQXxpcm7qHVA2xFTBHrTLixYHTNygsMn9SmMZ2xzoJFDMYbHwCD9825VL3A2k
         a8/yiYi9IuGt/bK5ov7BerckMeVAVV5iODQBr1mHdpllEvoBSwz5kKLUVMBhbbfyHHpk
         OV2O+3iDvtF7iKHaMiInK97uruigwbu4pZOY9zpyuUizMH8kK3FBYU9hWfZq2dahMkEI
         Nrsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta21.hihonor.com (mta21.hihonor.com. [81.70.160.142])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a2d087e1c3si598325ad.2.2025.12.17.22.39.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 22:39:21 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as permitted sender) client-ip=81.70.160.142;
Received: from w002.hihonor.com (unknown [10.68.28.120])
	by mta21.hihonor.com (SkyGuard) with ESMTPS id 4dX1Ct0YCHzYl7Sg;
	Thu, 18 Dec 2025 14:36:42 +0800 (CST)
Received: from w025.hihonor.com (10.68.28.69) by w002.hihonor.com
 (10.68.28.120) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 14:39:19 +0800
Received: from localhost.localdomain (10.144.17.252) by w025.hihonor.com
 (10.68.28.69) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 14:39:18 +0800
From: yuan linyu <yuanlinyu@honor.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui
	<kernel@xen0n.name>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<loongarch@lists.linux.dev>
CC: <linux-kernel@vger.kernel.org>, yuan linyu <yuanlinyu@honor.com>
Subject: [PATCH v2 1/2] LoongArch: kfence: avoid use CONFIG_KFENCE_NUM_OBJECTS
Date: Thu, 18 Dec 2025 14:39:15 +0800
Message-ID: <20251218063916.1433615-2-yuanlinyu@honor.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20251218063916.1433615-1-yuanlinyu@honor.com>
References: <20251218063916.1433615-1-yuanlinyu@honor.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.144.17.252]
X-ClientProxiedBy: w010.hihonor.com (10.68.28.113) To w025.hihonor.com
 (10.68.28.69)
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.160.142 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

use common kfence macro KFENCE_POOL_SIZE for KFENCE_AREA_SIZE definition

Signed-off-by: yuan linyu <yuanlinyu@honor.com>
---
 arch/loongarch/include/asm/pgtable.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index f41a648a3d9e..e9966c9f844f 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -10,6 +10,7 @@
 #define _ASM_PGTABLE_H
 
 #include <linux/compiler.h>
+#include <linux/kfence.h>
 #include <asm/addrspace.h>
 #include <asm/asm.h>
 #include <asm/page.h>
@@ -96,7 +97,7 @@ extern unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)];
 #define MODULES_END	(MODULES_VADDR + SZ_256M)
 
 #ifdef CONFIG_KFENCE
-#define KFENCE_AREA_SIZE	(((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
+#define KFENCE_AREA_SIZE	(KFENCE_POOL_SIZE + (2 * PAGE_SIZE))
 #else
 #define KFENCE_AREA_SIZE	0
 #endif
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218063916.1433615-2-yuanlinyu%40honor.com.
