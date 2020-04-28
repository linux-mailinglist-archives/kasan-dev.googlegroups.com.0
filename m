Return-Path: <kasan-dev+bncBDSN7FHQTYDRBYE4T72QKGQENPHM2SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CA8961BB6A3
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Apr 2020 08:34:08 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id y71sf8547781lff.4
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Apr 2020 23:34:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588055648; cv=pass;
        d=google.com; s=arc-20160816;
        b=yYaV7uEhcYl1FRctopWo0OEu/KSDc7cQcfVc3DzMDKH27Xk5TTmcGPMiQmvw9ZGI7w
         q5lzUQkiWakYxiiFp2cVwDQrYrkchLBEadY3hoF4mvEv1kvjMSvCtPixdCaea41/3b5a
         P+YDzk4YIeUPz/MIHOhQ/U3zrKGWzx8Wqg3xZErXmYxgtHafG1X9QojITv72EN3rMtHs
         tjw2ToH/gDML57xGyG0P80pRyFiMZY2z7zzamTyEACcfAz+c1M75d3u52/S/H0Y6szEL
         yfNznTIwzU/32YDRPsJcv1BafMeilP/fEgKTRA1/qaIVigSSdheowwmQ7C3EuyPLis+X
         Aa6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=M1MtyZJ9gWTeO4a3q79eyJcALEm3/YJASPff91tVnj4=;
        b=Q4QaTP2i3TslqkNkoRFTwtDg40Tl8MLgy/4i6k4kfSKb9qfBtEmEs+HXhjbHPbsPP9
         pryqdW8+sT/MFoy9X0l2qWSyeq17dt+j1xuN3Tb3wJtC2IIHE+Elz04sGoX+/S3JgbGJ
         s9hdBv+mWontT+RQfv5woPB7OtN1PaPHu5zSLTEhsgzSFzH5FNnq0ss8x5l4IvvkHpCj
         +Fui6nEH5nRJdg+FxYRXlGofscuyZWYn/2gD3V5i4bmswv6UYTV6R1uM+2ZkN8/jMI5Q
         zYMd6CXoHlkSFRuWygV9EnEY8Cz6z3+1d9JPvDOKfhghbu6c4faskMsRYnBt6ZuaLRbB
         0uSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yanaijie@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=yanaijie@huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M1MtyZJ9gWTeO4a3q79eyJcALEm3/YJASPff91tVnj4=;
        b=jxcaFYxD3Nuddi5YjQlY6pqcetgalsHPl4v1jSaVEmvnFrGujYIYnT1Od0tUscgUj1
         uZrE0Chbcj/O5I6EonbCEU7WdqbAeIJgSj11FONiF+4iaGwvPILjTz/jSW8ZBLlm/Ir1
         0efyubf+z4vgzcwXhRtvaaudbbJgfA2b1ppVpskN4QUYZ/xH1bMcIjYlpjbjRhnfjhlz
         FvYs+Jb02I28ses+D3cFj01IIvch20lUHPSI3XoN7ghcPsSbJZopKuw0aDCFrPcrCsWn
         wXT4fztmBkkpGsKSsruxKrJ7KllVFRvZ35NbTco1mMwezFj2q+Mlx40DopKPXt559piq
         w+tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M1MtyZJ9gWTeO4a3q79eyJcALEm3/YJASPff91tVnj4=;
        b=QIl9k++5N9D2XzgBOdFSfCUa18DzFfsmxBnystBmQ9sndHdjnMwzi9UpuEdthaK1aY
         6x2grhYGVtWnvC+yrij70roSL7ink8wV7vVRYsfM80q06A/D77SzYqA4QdV0xuop9ZnS
         CHVSALNf6h09yab5AH1TOP8VXwfoQnImQE7KQCoAl/ABGyjcu5M5gsEFACJKDdUXu+0i
         SSkEO4QMMRB21FNfcihg4KQlUyVCzmd+qbkg2FqGZOCO0WUHeTska/fJ2Aqv7dfsiqUK
         xlueAuRu4aCMlyveOrNHGaeEqxR/xofQ2oNHZQ6h0G1nQILlwTpc+M3F6XhnpclBdt/M
         jV7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYET38O6X4BXPzqPJUMRekBsuP4KC/lnYrH3G8ozhILVqTGb/LN
	g3zzZkM86keik8BXyjDzBQg=
X-Google-Smtp-Source: APiQypLVshLhAsO3yWLILmcLICnC0gfTZZPeRKIcOOoWadOWH08HUd1OYRBLsT75yfOY7BVSHE6tTA==
X-Received: by 2002:a2e:a365:: with SMTP id i5mr15172547ljn.293.1588055648335;
        Mon, 27 Apr 2020 23:34:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:551d:: with SMTP id j29ls5030814lfk.1.gmail; Mon, 27 Apr
 2020 23:34:07 -0700 (PDT)
X-Received: by 2002:a19:f610:: with SMTP id x16mr18129272lfe.79.1588055647795;
        Mon, 27 Apr 2020 23:34:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588055647; cv=none;
        d=google.com; s=arc-20160816;
        b=FTh00zaeFiE6552ddSGMt0bHVg9Rbbv7s+X77qPixdQ3/LG4P/RJfm2UiELEWQzV4y
         rEZJE9MJhVZkCbT74JiWJTB2kRUhuMymVvulP0JZ022kU3MUaLakCqSeOT2/Ep2p03fL
         HF8MMOVStRjBkuYicRVs6C05xvvrmcNYoyl9L6A6xFLco3cbZoagqj2Ka3cYS7nY0owC
         IGYnhqbD8ncuh29EbTYkeffIWwIShhEHWEn+0s94lho05j0AUrZBQpN1mtUkNzJMReUS
         4xBacX0lS3hKKHziVostcM1oiJlDntQYffEnz9HJ7C8CXc8NAGNYFSfOtG8/7kDgjkIf
         Rsbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=N+uJ2FZ6nPBurFnYei9Yzh6v3SRVhgG13ryHveEeuao=;
        b=pC5n+51P9TIOprrs1CgRoihOxVlVOUjS3duD+nECWStLYteVHAe8eh41uD8zk9dTgD
         DroEahSl97Rl6X3RqDZ3GXmSFVuA0JCCCjozEXYCO/iF1gnT6cdnihH14BiJ7KwlBZxq
         wFRurwWD2s7nmM7x3M7VmLGjanXRszc1RBGhEqjXmpJgsXilITOLd57OCHrVU2rsSEIU
         jaHGZnHTYAQR4GO2jIx5X/1i1ZD6KtV0vSNstCxD9CyU+I3dOUu1f3aSSIDLIRNIQZ4v
         2x5GlbSHajbm7AlmwNkinDmnxD3YmZPYoVpV+X9MQzKH5o3eZUkR3w80QS5Ni0hN50yD
         OvTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yanaijie@huawei.com designates 45.249.212.32 as permitted sender) smtp.mailfrom=yanaijie@huawei.com
Received: from huawei.com (szxga06-in.huawei.com. [45.249.212.32])
        by gmr-mx.google.com with ESMTPS id a21si1172416lfr.4.2020.04.27.23.34.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Apr 2020 23:34:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of yanaijie@huawei.com designates 45.249.212.32 as permitted sender) client-ip=45.249.212.32;
Received: from DGGEMS408-HUB.china.huawei.com (unknown [172.30.72.58])
	by Forcepoint Email with ESMTP id BC3706C49FD3CD5A717C;
	Tue, 28 Apr 2020 14:34:02 +0800 (CST)
Received: from huawei.com (10.175.124.28) by DGGEMS408-HUB.china.huawei.com
 (10.3.19.208) with Microsoft SMTP Server id 14.3.487.0; Tue, 28 Apr 2020
 14:33:53 +0800
From: Jason Yan <yanaijie@huawei.com>
To: <aryabinin@virtuozzo.com>, <glider@google.com>, <dvyukov@google.com>,
	<paul.walmsley@sifive.com>, <palmer@dabbelt.com>, <aou@eecs.berkeley.edu>,
	<nickhu@andestech.com>, <zong.li@sifive.com>, <kasan-dev@googlegroups.com>,
	<linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>
CC: Jason Yan <yanaijie@huawei.com>
Subject: [PATCH] riscv: remove unneeded semicolon in kasan_init.c
Date: Tue, 28 Apr 2020 14:33:19 +0800
Message-ID: <20200428063319.44539-1-yanaijie@huawei.com>
X-Mailer: git-send-email 2.21.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.124.28]
X-CFilter-Loop: Reflected
X-Original-Sender: yanaijie@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yanaijie@huawei.com designates 45.249.212.32 as
 permitted sender) smtp.mailfrom=yanaijie@huawei.com
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

Fix the following coccicheck warning:

arch/riscv/mm/kasan_init.c:103:2-3: Unneeded semicolon

Signed-off-by: Jason Yan <yanaijie@huawei.com>
---
 arch/riscv/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index ec0ca90dd900..dfe988dd0ceb 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -100,7 +100,7 @@ void __init kasan_init(void)
 			break;
 
 		populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
-	};
+	}
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
 		set_pte(&kasan_early_shadow_pte[i],
-- 
2.21.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200428063319.44539-1-yanaijie%40huawei.com.
