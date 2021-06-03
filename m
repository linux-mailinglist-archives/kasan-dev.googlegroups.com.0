Return-Path: <kasan-dev+bncBAABB6V74OCQMGQEFFTPAWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 682F539A2A1
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jun 2021 15:58:20 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id w10-20020aa7954a0000b02902eac51f8aa5sf1560482pfq.20
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jun 2021 06:58:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622728698; cv=pass;
        d=google.com; s=arc-20160816;
        b=C4a0ofAPAffsyV64wAlBo99Tow6nzWRjh4tqOCFq2QKmAgactX/scyl5R/inukypy9
         GrKStY5Fre2JIbHx/A7e/73AiSXKbccp/Woqy1RxTb7SxslO5lha6zHnBRMZ2HFs1sLi
         Rj7E5pVmhdQnHRetviCICLnSAQEkY3YJZYsZURiYic3EvhbQdFpVvoHxzVMdGek5YO4B
         duWXLJBuJ3ZkzYcI88FBVW6amzxyNTilLLOjo+J8TNtAAs710WbFZCbnQMwgt2aIEoVu
         I+r04GnNUQ5BvtnQX/+UsyY3CO/lUcHlyzSy5RmjkiTYbXbScUZf11vk/tFK5nOylN5H
         vd+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=em35D4x306LevSeXxiqlQAgoo8T3Gvu7zRXkrCGZXW0=;
        b=C+jHtCVkkZ1zdea459zfXKrk2iEBgQNBOeInHomnz2lRVCeJ8vSUncR0kTvhRrbdXS
         RDRx0fQqDJQRTCqAk+aQp38SZgjWCWjlrfKk8bYLS2z49DPiHp+GypMSspC2W2QPMHFk
         H815MyQlQDVM6xNSlQpxJLNMcwCJ92aA6SR5paq2SnYigNti2iqTfu6uWoJTY9zfIIHA
         iDpH7DfEs8O8MMYbkN//+XmGzTPWlADouDPBFGeF6dR9RJEwn7MGUeffndRO4HU+49j1
         UFXEzPNwOodGVY14ZksN4tkrFMZ2aLpk1Uwd+mB+EXXloPYdrg6b9d10q31R0eDxVdRB
         KWPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yukuai3@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=yukuai3@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=em35D4x306LevSeXxiqlQAgoo8T3Gvu7zRXkrCGZXW0=;
        b=PwVRPtI0e4ADKytdOPN9mHohHUiQSLHJf/V5hrRep7RmMn1pCrrqgsYxo9UJg0KyJ7
         l95S8h1cfp8d3ZN3bF0P7HdkCs7TfjOaDpp8K9/JuWe7TJTr/4j0kOz9r5oDPmR1LAWY
         n9PyoMLeKsdfINoC5r6RgkucLCYmkS3L09QCmvnuNb/gjYrRb9SUFCVwXeu89u0hAa8m
         gvNa205YmV4OGdzqF7MZfFNCa0h+vs7tRjzfuR+Jekk8vG7wByhU/pf3kWP0/DJVinqA
         w+Il34TgmozO0pDPwU71ULdukKdlWF9CM5KHW8BFOx+9P9+9bq4zdam/zihagSQBqBMb
         zTUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=em35D4x306LevSeXxiqlQAgoo8T3Gvu7zRXkrCGZXW0=;
        b=IyYyM1hZlBqwrobGhPt2laPLQKAx0G2kso94y4EN/96WYCdbplyhkfn+fErZXwALti
         Tj1l2WRb0mBSU8uBWPmPXUtyapYKITsYU4RWca8F6LriL4Vv3xmOLAzSz0AAhulUqSjB
         QpZN2h6u0BkkdUiVqS3GOU9gPB0gLoS7k6JnJaROhxpcIb0WWmCjFk0dEX/4zPRmkKlY
         DYiKu3CVn0srwHw2GmUlLbmOotMqxzsdO7fNRdugqJD1IR8YWTGwSgDKXD7WDqmgKpR6
         PAtaoMLo90oov98TZbvL1mj6vMsFRHHXxleKouECZHuBTWxQmzS3KRqlVBeFLeSDazj9
         QefQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yTLvR7ZILpQUW190f3rFI1GxQA2hHf10C7RHJgvgfcLcKmv8l
	T3jD1aEGYSce2S84jJrPous=
X-Google-Smtp-Source: ABdhPJxp5Of5U5bj9jwGlmNErrqwuX07q/JWTHfn9mw9nhBwAGivFn03O0HGRMRpNJT89CWFY+7xmg==
X-Received: by 2002:aa7:92da:0:b029:2d5:59bc:a7e4 with SMTP id k26-20020aa792da0000b02902d559bca7e4mr32270266pfa.46.1622728698764;
        Thu, 03 Jun 2021 06:58:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:185:: with SMTP id z5ls1901445plg.6.gmail; Thu, 03
 Jun 2021 06:58:18 -0700 (PDT)
X-Received: by 2002:a17:90a:b782:: with SMTP id m2mr3196311pjr.147.1622728698338;
        Thu, 03 Jun 2021 06:58:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622728698; cv=none;
        d=google.com; s=arc-20160816;
        b=sm2EaB43SWQ8CO7pOqiJrATbjDHCbkalmK1UdOVhtAor/s/1qEFKRmcafs+xLn4jVz
         m6GEA1ZOsxsbL8GapXJeF9ktV95VvnpwtgLqMxle57b0lq+dPLYca8Vnra6+Npx1smsa
         Wmlg8jdYDktuH7v9O2ooY/GGusHlDUNs9nNjBfV12BJQpeplkWQnppvLyMv9aNspGsf4
         cjip6K6B042hbe+ybfz8UZfFoAOatI/9sDtdDSHf5s4eK++uOM3XpzRJ7j6dSlRQR310
         iQ8PIJhCgGllhKc7nlLxmzoU+iI0OSJleglu4qGIvOB/GxnJ4lUfkt8bbJ2EwRXGDTsH
         +Heg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=n46ciOXuuCdcpyM61rB+OdO74kupIAK969r00A2O5RI=;
        b=r5Arkuq7yBwh4zHaOCoPFy6F7l2oNz0rtGlrz3XNKL6Ixyme2jMDhPs6YJq+zHSRMy
         Ynzb0ax0stTYOfM+ZVVd7zosHRGal71Fm8475X7zCNbr92gGEi5AEllIzNfBVvDAcaT4
         WOYHYKotyOYAvBJXoUvXIvnsz++V0Q0MugFuSlA664BAb/OHr8F14GePmkX/Ex208CrU
         8xtNa1sFDVCfhIVvnILgk745FXKKm6DeY/63AZTJnd6Yti85UCxdeDwYEWch1FYG3UEg
         hHvghfJ/iFAHl6H/YfPfNAWVJJQyxN+QXBQ9jy06C+E8hIHWHms93CMUri/pJfPMPFRv
         xQQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yukuai3@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=yukuai3@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id w7si213574plp.5.2021.06.03.06.58.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Jun 2021 06:58:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of yukuai3@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4FwnT14zQgz6v0j;
	Thu,  3 Jun 2021 21:54:45 +0800 (CST)
Received: from dggema762-chm.china.huawei.com (10.1.198.204) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2176.2; Thu, 3 Jun 2021 21:57:44 +0800
Received: from huawei.com (10.175.127.227) by dggema762-chm.china.huawei.com
 (10.1.198.204) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256) id 15.1.2176.2; Thu, 3 Jun
 2021 21:57:44 +0800
From: Yu Kuai <yukuai3@huawei.com>
To: <ryabinin.a.a@gmail.com>, <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <yukuai3@huawei.com>, <yi.zhang@huawei.com>
Subject: [PATCH] kasan: fix doc warning in init.c
Date: Thu, 3 Jun 2021 22:07:00 +0800
Message-ID: <20210603140700.3045298-1-yukuai3@huawei.com>
X-Mailer: git-send-email 2.31.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.127.227]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggema762-chm.china.huawei.com (10.1.198.204)
X-CFilter-Loop: Reflected
X-Original-Sender: yukuai3@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yukuai3@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=yukuai3@huawei.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=huawei.com
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

Fix gcc W=1 warning:

mm/kasan/init.c:228: warning: Function parameter or member 'shadow_start' not described in 'kasan_populate_early_shadow'
mm/kasan/init.c:228: warning: Function parameter or member 'shadow_end' not described in 'kasan_populate_early_shadow'

Signed-off-by: Yu Kuai <yukuai3@huawei.com>
---
 mm/kasan/init.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index c4605ac9837b..348f31d15a97 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -220,8 +220,8 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 /**
  * kasan_populate_early_shadow - populate shadow memory region with
  *                               kasan_early_shadow_page
- * @shadow_start - start of the memory range to populate
- * @shadow_end   - end of the memory range to populate
+ * @shadow_start: start of the memory range to populate
+ * @shadow_end: end of the memory range to populate
  */
 int __ref kasan_populate_early_shadow(const void *shadow_start,
 					const void *shadow_end)
-- 
2.31.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210603140700.3045298-1-yukuai3%40huawei.com.
