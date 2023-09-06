Return-Path: <kasan-dev+bncBCRKFI7J2AJRBSXC4GTQMGQEKS3TNDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D447793CA9
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Sep 2023 14:32:12 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-68a3cae6d3asf3839976b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Sep 2023 05:32:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694003531; cv=pass;
        d=google.com; s=arc-20160816;
        b=TZuy8077O740RGB793P89OL5MFKizDKf5fIjt57z18rGrDapXEKBhGbYPW6NKgiCsz
         BVcv+/BZBYP2gZben95NO3K3a6aANlR+qJVZgPzTiySQ06TUJO00yPg1yUrHNtbVfz0t
         r1V6u0k7sp23tGspMdptWoTPw7SHE/oTAgDhdB7u4hq0CPRufwr+nwur25WP1HQ+hJxt
         lLbrPUaonPswSWObU5h5mi+oXRCpzPsCBDDJO4Gt7Xm9ayc5VGfYrvnbRlkHJmGftWr5
         PGHFkLIdsHOjXeShEviC+X64+EgOE7F+KwpYoRUUHhSw3FTbx56VRQ+NZEyibPXgVpiI
         bp5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kyY2Ya2W06dD0aDNUZhGDT3RYJxkO8wlbStni/S+Tlk=;
        fh=yzysZ59oPk5DLEE5rhyc9UX9VwoFZbo45R1txxQt+Oc=;
        b=JSNiY+l2y4zvUyoNRj27ayEE1Dgxc5h36o5gpC2LDIZ168Cr41XX89xeeaKJxCv6Kl
         075GyyQzxiVbLbXW8ASTMo28pdEEIiMFo2cIko751NDqQUalTnAM4oih3qZ+APQYNT2N
         uaiQ5vBZbwOCv/aMq283eid9oARSO1SWew17l3DpwMY4pJDEMMV9mfGBoQ1K6dzKxsDd
         ndUo49lSsygE0N8efAAlScK5gSkc2GdfGK0EfyNyQVlIxNrn+PWGmHttv3kp4QUrt3JR
         9evHrcYsg2RxupRKxI2ShxFdCpjjnMqnD7Ym/gMYx1dP6Qldbs6R/XXXq4759NwOBR/Y
         0Y0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694003531; x=1694608331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kyY2Ya2W06dD0aDNUZhGDT3RYJxkO8wlbStni/S+Tlk=;
        b=j2gTxFBVMOSIEFA3Way5C0UCuxNwufDporz/2yP6AlgGLhLg1ug24WSfYYMO+Jv3Ud
         TDUjPeEAH52K+hq8duFYAl1azkPF0Jk9IIfTbbx5zxJZ2E1kDLfHNJ/FuZe9SIzW5Bsq
         OOsIpsw9p8wR4JdEfsHsNS+zQPIU5Z70JfI7mzksfyqj6G35zjkxJosb04eRxHjhBtw1
         JS2BmhI4DV7I6lt/tgBrauoqFfv133eC7CyeMDShZZr9IlEI26Go7kHsTlqid3TIMwH3
         LeObzkajLM4FB17ANrllaZ3dljgBTwEaGSjVDF6adaDX6FkSuXajHk8708xsNkqpnMU+
         R4Ug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1694003531; x=1694608331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kyY2Ya2W06dD0aDNUZhGDT3RYJxkO8wlbStni/S+Tlk=;
        b=ilyDSU+z+8We8r2ga4yQc3Nd38lPzgpz34lX6QNsb+MEe3SC796iFiuEpsYUsdC4kX
         tdyzgmzJRK420Kbz3JFBdhNhi253kB7prPiduxIx+fWClOxPK9gSRcdePIae45m1QSJI
         7szQKjYdE248lth+GP19jR039hiZ1fUb0OGA8Hla5WP/n/zVKVz2AnsHMT31rttmb6kB
         KUveNvYm7oMPFMl0e6tWtGTeVsov3IQYCrPMmOP5lNJ/dBzs+1P+AX0y1rHGjQ8WWaUu
         KWuUU+dMFFkYeIciwTPXxvzPJU3lliCoEwpOiHR9xGcJkDHpcE6GmIOLdIV/7/q3lWzM
         eJxg==
X-Gm-Message-State: AOJu0YxxTCOSbGtc9iDk9g5xmiw6nH9HEq/680HA6AXX551Gm1XIrBz1
	9BtjMtfZDPKWw83+Bz3NuEU=
X-Google-Smtp-Source: AGHT+IGhCL+EMF5ymDfeQR7gmyAHIAojQnFN/b/cJbLhJ/Gw+hODhlHG4JTjlSzVrruMTQgRHVsv7w==
X-Received: by 2002:a05:6a00:a07:b0:68b:bd56:c783 with SMTP id p7-20020a056a000a0700b0068bbd56c783mr16511227pfh.22.1694003530975;
        Wed, 06 Sep 2023 05:32:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9481:0:b0:68a:3df5:b027 with SMTP id z1-20020aa79481000000b0068a3df5b027ls6074831pfk.1.-pod-prod-04-us;
 Wed, 06 Sep 2023 05:32:10 -0700 (PDT)
X-Received: by 2002:a05:6a00:18a8:b0:688:11cc:ed98 with SMTP id x40-20020a056a0018a800b0068811cced98mr15433086pfh.32.1694003530086;
        Wed, 06 Sep 2023 05:32:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694003530; cv=none;
        d=google.com; s=arc-20160816;
        b=ex6v5JYqSvprLkuc1QZUTgPkMVjUOUNFcZuPCwZwg6pVs5274zWAGg4q0XZSMCx8fZ
         JMOIdr9v+vMCzmUQ3/L4O0UlIc83U66gemnWSh0/U7vG3C4xQamfKt+ZTKFLHPUl0kB+
         MtOOHOJeZHcZZ0QZLtg4oIew8O6ZqImzyufy+pA/CQp6RBabtf5SzKKN1xUQtcGyD16E
         /XsN9HYr2hXLQjX/U9Asn5/gn9i8WZNvpz0NUpJExHTALQnYme9ROQtoZxsaeaVazouT
         KwMKm5VAaf4CCQa5o0/PTiMO2YvaTvRy3lFn3nM5pjNhAm6Qy4CXFjFBGGyaDpbbwGlO
         /xyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=AX+U74nr5Le0KVgJkSOr8aMz7KHIoSPWgWf306Yi4XU=;
        fh=yzysZ59oPk5DLEE5rhyc9UX9VwoFZbo45R1txxQt+Oc=;
        b=HDyqqLDugM3XlPbgj4FQUFYXnIOBooUDXWU7n4wDmaSyOwsCakzKQ2Vb3/OqhXmDgN
         1BOu/EOzdqBskA9Y+JbKgxwh3CX1TpI6pSVjNYvw7gD5KPTF+9Fjfhd7gplTOj6D1lMa
         r4+Pzp2uWDjIBzkuk68D669Ls9efhZILDhoCQ5PyKdCjyUqQq1VSXi2xxKkk3Ri1uxb+
         KgaKLYW1BL7WwhbFjvPIAD+cBtsMRB+/V1aT/7m60Zsz/yvFIHCTY1n7bNWeLrsfAEXE
         jZ6xE01qmzzHDjYkym/lJZKyTP+dbg1Y1g6M8kgjQNaV4lcsUF+RuUj19nXq6b2vA9Sg
         1ZYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id x27-20020a056a00189b00b0068e34c6b99csi109872pfh.3.2023.09.06.05.32.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Sep 2023 05:32:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.57])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4RghXr5F7rz1M96W;
	Wed,  6 Sep 2023 20:30:20 +0800 (CST)
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Wed, 6 Sep 2023 20:32:07 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew
 Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>, Lorenzo Stoakes <lstoakes@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
CC: Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH -rfc 2/3] mm: kasan: shadow: move free_page() out of page table lock
Date: Wed, 6 Sep 2023 20:42:33 +0800
Message-ID: <20230906124234.134200-3-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.41.0
In-Reply-To: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
References: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm100001.china.huawei.com (7.185.36.93)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.255
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

free_page() is not needed to be protected by page table lock,
and it will take a little longer, so move it out of the spinlock.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 mm/kasan/shadow.c | 9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index fd15e38ff80e..d7d6724da2e0 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -423,12 +423,13 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	page = (unsigned long)__va(pte_pfn(ptep_get(ptep)) << PAGE_SHIFT);
 
 	spin_lock(&init_mm.page_table_lock);
-
-	if (likely(!pte_none(ptep_get(ptep)))) {
+	if (likely(!pte_none(ptep_get(ptep))))
 		pte_clear(&init_mm, addr, ptep);
-		free_page(page);
-	}
+	else
+		page = 0;
 	spin_unlock(&init_mm.page_table_lock);
+	if (page)
+		free_page(page);
 
 	return 0;
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230906124234.134200-3-wangkefeng.wang%40huawei.com.
