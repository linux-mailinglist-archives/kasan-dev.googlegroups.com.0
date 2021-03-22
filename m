Return-Path: <kasan-dev+bncBAABBFFP4GBAMGQERO4XO5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id C1DEE343BE8
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 09:38:45 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id p15sf5643100plq.10
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 01:38:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616402324; cv=pass;
        d=google.com; s=arc-20160816;
        b=mRsAcQziRfLRhtwwOkrzH9+7LAsiJg3suB/liisoMYiHEuoVJ2HVj7yUrLkx7AXlgU
         NHom39o7ezqZ6+J9zwm5Z/WXnMHOe0KZEJYuNpYFf7Q6QiMuWNWvBTvPv/sgZtuE/HI6
         4iORdQSoVorXlW3A0wsmLTB4P9VD3Sd17fsoc8sG+PQO+GFr1bwFLotoWnMauFFm5x9A
         Lv46NJQoJMfKqYyPqkk8/a9RjqnSCYGcSg4ULqeTpM5oiV50nZhs1097FF36IV20Hk85
         zOT5SlUEOLfbpaS2cuVQyspszfEkuOesbyYORgbj/SDiVApO4XA7Ee7cdwZMkLVo50UM
         MVyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=ni4xDUUNpVGfzD4Y25qnkXTUjZ3t7UngG0PnkwauCaE=;
        b=BRxXQKHeNPcnZL6hSm5aVKHTJygwM4Tx0KyWuR747YOtNnJYavKBizK62LserhWvEz
         VphBZy9xQWwMJ3DTG/EPIDrknWwH/QBS3L5nQfvQdmMVb60DQXVE9hJU7hwJ1EXOl4qC
         aSGR0CQ1EttCVdD/p7jDfaRRe3Pul5xjeAWI9KgUaUT/wDJNviDCpE3J76bezBJeaQOj
         LebeD/zZ7y2giffLsw6oVVlujPyBlOhBrYPEYLgQUFRjcEoD5vKzLfS6qCOH9lISF3Av
         JxwIhv9+Nif/fBgt4FQTzGgxTSb2je11Cgp2HO5ULyl0gwKkOU631dKa9YzwyzrGHxwb
         4dDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yang.lee@linux.alibaba.com designates 115.124.30.42 as permitted sender) smtp.mailfrom=yang.lee@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ni4xDUUNpVGfzD4Y25qnkXTUjZ3t7UngG0PnkwauCaE=;
        b=NBlJDT6S0tqXg/r+U6i65jbGD653SWa0/1ustfG7vGkTZdPaWY7NLQ9Qe6mpWh+q9T
         r2XhgZqAk41Fxsux3CDeobexxK37QFsN5PZb85JTTPQEEpsPvSMewnMZikxPnF8DAFlt
         BEDyLTqRu/BDsE2QN0KZllz1u5UchzQXo+jhTseo4X0smi92jChzVUsNeBW3RdJGXGwb
         XuQqodfbjNrw6mIp0b60WpfKzo8a4i6r6GPDgFZYriYTOm1lWtZeAUsSBvWossF0sXol
         4zb5YT0Y007SmeUt3bW4MK8WvhceOVR7KoOEHJioWPP0zgbBj7uj+decESdtHGT19TLR
         0wEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ni4xDUUNpVGfzD4Y25qnkXTUjZ3t7UngG0PnkwauCaE=;
        b=lULUgvNktezEIKe8TzTX4tbnPs3COdZLUdq6LZdYObemv/qMSEo0tl5wrkBindGo44
         G7XGmh/dRHBaQAojs81UvO+B0+h6sO9N5PzgBL6NgCuVUbQEy4fxvZZFI0CewGZxJ5Jo
         NfF7Dyl+XfboQvzAkt/x/P03xjTn2+l6I1TbSC+ZnuOS8hc7GJdoFIfnmydtfHkHU6FJ
         jCq46N7kHze5Gpk5ax+ji7j0jw9tafjFaQdIISsmL+DOYsu7usisyeaMlZBjZw6YMbFG
         5XkBvqHi/o3jaxm12uIkWbS82F0dcDoLbTXtl4doaKP9j7ik3oOaMXAzEotNfTv9PL1K
         pxcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530zI6lJfg0TgWvQfJUF4I0a1fKeE3HlmA6KmtpCYfsQ76HLfpdF
	lllDKK4W7uTgt+toTcQVaho=
X-Google-Smtp-Source: ABdhPJw1CohQhv5Yl85HoELu6hP0GVEU75WLJeqnSgPLFZo8fMQtO2ZL/YOoxcqPEYgwKGVqwPhfpA==
X-Received: by 2002:a17:90b:1082:: with SMTP id gj2mr11994938pjb.155.1616402324391;
        Mon, 22 Mar 2021 01:38:44 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:71c3:: with SMTP id m3ls515187pjs.2.experimental-gmail;
 Mon, 22 Mar 2021 01:38:43 -0700 (PDT)
X-Received: by 2002:a17:90a:d3d8:: with SMTP id d24mr12130000pjw.28.1616402323730;
        Mon, 22 Mar 2021 01:38:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616402323; cv=none;
        d=google.com; s=arc-20160816;
        b=pDriJWw3+RpRAv5vvGqqRYlgP7lL9aDV7i1FGX4kYtjtYPWSWP2Tqc+y6RKdV8HN/o
         RNlDYiaSq2FWuT+APoF7Uvg8As5hsWv2FXtzQtXPc0/fkMIPcnz67B7wkZeiWFM+OmTq
         6tCEaDWwSMYSDwwUTIuHGEgnF/IShlmt8RFG6CXK7i2eOu4pD+fcA1GK5BzjEpApuCiM
         l664yr/SpY8FXu6UUOFop4VpHipSvgNg9s9CIxx/okoHp9C3Pynl/OIhqNEXzK7Jcf+b
         u7ZcUls9sSy5CC6UTsulFcxK3hXWGucSiphzM51Ggtq2SvlbL5BPekrXjbDGwJccSpaA
         mchg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=Fmy9jCnswK1DHKnLpeg1xRttraZAUkIate5AsandtJY=;
        b=SRpJSeihrMTry+goVhWUdWi3L6GB9sxTXA63E+5G1BbLLu9VZI2PEpD1HR2BQnU37y
         Z22kLXwVlgQZrPFStrU3EU0Sfi0FfVH2+JB23isgxO89DeYb0Pv6sY5/gHl9gjE8nLKU
         5a4fFR/GUzsjnx/F8hKrBW4mSmvGEKyC6dPGQov9ljjLju9d4OYsPwRsYSdyNqbXkxcf
         mkkV9J3G/htH+JnsoALhpo+ldCjSyV/tT8IZtYWaQTbU1+MRWtTAFaNuV2uMQBw47zZu
         IIxeLZKsN0ujPE6RA3Yh5+dedq9kSEm1Epsiq2UBq2JqpN4ksrV3vAu7c0wHXwzQwmPG
         6oFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yang.lee@linux.alibaba.com designates 115.124.30.42 as permitted sender) smtp.mailfrom=yang.lee@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-42.freemail.mail.aliyun.com (out30-42.freemail.mail.aliyun.com. [115.124.30.42])
        by gmr-mx.google.com with ESMTPS id y11si933636pju.3.2021.03.22.01.38.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Mar 2021 01:38:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of yang.lee@linux.alibaba.com designates 115.124.30.42 as permitted sender) client-ip=115.124.30.42;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R171e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04423;MF=yang.lee@linux.alibaba.com;NM=1;PH=DS;RN=11;SR=0;TI=SMTPD_---0USuiDZ6_1616402317;
Received: from j63c13417.sqa.eu95.tbsite.net(mailfrom:yang.lee@linux.alibaba.com fp:SMTPD_---0USuiDZ6_1616402317)
          by smtp.aliyun-inc.com(127.0.0.1);
          Mon, 22 Mar 2021 16:38:38 +0800
From: Yang Li <yang.lee@linux.alibaba.com>
To: ryabinin.a.a@gmail.com
Cc: glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	paul.walmsley@sifive.com,
	palmer@dabbelt.com,
	aou@eecs.berkeley.edu,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Yang Li <yang.lee@linux.alibaba.com>
Subject: [PATCH] riscv: remove unneeded semicolon
Date: Mon, 22 Mar 2021 16:38:36 +0800
Message-Id: <1616402316-19705-1-git-send-email-yang.lee@linux.alibaba.com>
X-Mailer: git-send-email 1.8.3.1
X-Original-Sender: yang.lee@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yang.lee@linux.alibaba.com designates 115.124.30.42 as
 permitted sender) smtp.mailfrom=yang.lee@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

Eliminate the following coccicheck warning:
./arch/riscv/mm/kasan_init.c:219:2-3: Unneeded semicolon

Reported-by: Abaci Robot <abaci@linux.alibaba.com>
Signed-off-by: Yang Li <yang.lee@linux.alibaba.com>
---
 arch/riscv/mm/kasan_init.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 4f85c6d..937d13c 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -216,7 +216,7 @@ void __init kasan_init(void)
 			break;
 
 		kasan_populate(kasan_mem_to_shadow(start), kasan_mem_to_shadow(end));
-	};
+	}
 
 	for (i = 0; i < PTRS_PER_PTE; i++)
 		set_pte(&kasan_early_shadow_pte[i],
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1616402316-19705-1-git-send-email-yang.lee%40linux.alibaba.com.
