Return-Path: <kasan-dev+bncBCRKFI7J2AJRBUGWSCFQMGQERAXAGPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id DCA77428CE1
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 14:17:21 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id m40-20020ab05a6b000000b002c9d69624b0sf7691108uad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 05:17:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633954640; cv=pass;
        d=google.com; s=arc-20160816;
        b=ak8m9Z93bEX3f+0Qr3kd1hX8NUSmKq7VZLVJGYMlwFLte4XDJN5NkH1fvu+OvisBdz
         3/lgc1yavk+K4lm1Eo7eNVTQcV8vc6j+ehqbl9Kk6ll7CDGcpenBh/p0/XKp7nJ4TBZ+
         cpRMYDT4xju05UDKzUJa8OFYP9mJD7wzKsY4UR4f9F7x0WcQ3OxvODpUuPOY5rdagZHd
         e166pG7AacsbkZINslAaufvckccV4CIF0/XlKhmuXsY9OOXG0uwqspaJnrg+Ylskpx0D
         l4/lhu9uEcJp4+dGJZsIqlbojBaF/uphiRGo+LjYuYJvRDUkdd0rmn8Eznj7vHocQZkX
         RuZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bxSy+kqkH4QUn+0hHd9rsdAQ6VC6aesHr+LZ/rL4Vl0=;
        b=BpKIpJXvz0wh08uwX+aVOJXdjSseNrEfXakp2MWqPSgn7j/60TP+nYQWBriU3lLrEQ
         tQ5rbkT3R1LLphj77DfoABrNktwu6WP4PKiq2AajGLpfz3D9Qr24gIFJVgg/XUH+RXbN
         LnmRM+AWs87lFJp7Sw4ahYrHfjjUdcgr8ZB5Zprpf1OYSuC7eLt2v2EsgTGF1BTx6vAE
         QRgwHeskiHnCB7EFJtORtn7EAK6UY7qheJHsPdCyvaPnjGStG3yZCAmcO8un048FNFz1
         U2avTJeSzhiHsmHHZI+L56Biw+JcJIpBAEx0Xy//kMJR2mnqQBdUsyMh/okgznoYhL92
         W2Hw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bxSy+kqkH4QUn+0hHd9rsdAQ6VC6aesHr+LZ/rL4Vl0=;
        b=I6a+uQ5LB3YbelMz71U+5LCFewzYZQpWZSYrWwHXzZZHyqW7isW6lPW2PpZUnmVRY6
         lFBbdALkdr+PPe4ihNnFBQ8rka84Yh/ntDv9h5GeJ12DAKDSzoei0b9SWKH9bHdH6s8i
         suKYoxEYfykTzz4UewPJCPWvgNydxxzgMIgjuIeog44SiOiAZsaWkyH5H8QAZMWCTETe
         aDw9j107DdYrS2mtAdq6pbHcsv1HMzwNvgBMUzwNJIzNEsztrKI954wmZu3XelVjiukn
         01QgENKuVVGLSv3BbAj6eF8xGQ/oZurrkjlw/sHZTBjP/aX0WaibWuodvYX5Cw9IS1Ki
         ostw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bxSy+kqkH4QUn+0hHd9rsdAQ6VC6aesHr+LZ/rL4Vl0=;
        b=zseyY8Ydh7cnYj8V/012ws8hcdVQaGXdV0YIEQ1e8ER1xvXw4ZUgujhmfC5YyLvDav
         I9v/dMpsQiajUYKAqjfsmaKI5i7VQPZ/X2uqwd0rnulnVa0lpEf11UFHS9ITKMQUJ+0R
         z7JiOjnsRT+Vg1VvSlmwNFgCzP2B31AA75qu5R2wzjpFNO3O2tbG1NSabA1ERptm/1mP
         WgXsJaB5HIzF7MYxnuhMeqqvukPpuZvBASS5yLNUJo6ZfxrjlkJ62W07M4eDspMso8cz
         9q7G7j8HUXsdbjG31JFuLckVotZxChWOTi2G7BCqkXT2yXujCpKLx33mSdX/kntISlVm
         RpNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cLXF6+3ctrhZHHyB/XZcewio9r/7X4bDNT5hN9q5kVMu+S2b8
	dhvy3KBZD8odThu2qsIkU5s=
X-Google-Smtp-Source: ABdhPJyOSeHPhkxu+KQ3qNVZPnGInDk2XjphuPKX2NsCz2dCL5bt2izNfqHzmt8652VrmerbLHvAIA==
X-Received: by 2002:ab0:4751:: with SMTP id i17mr14303344uac.86.1633954640786;
        Mon, 11 Oct 2021 05:17:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c083:: with SMTP id x3ls2432791vsi.1.gmail; Mon, 11 Oct
 2021 05:17:20 -0700 (PDT)
X-Received: by 2002:a67:1983:: with SMTP id 125mr22572451vsz.31.1633954639095;
        Mon, 11 Oct 2021 05:17:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633954639; cv=none;
        d=google.com; s=arc-20160816;
        b=iQGcaE2Vsu7DgEmWDlZaa0cyEkHWn9JdsZ76es/+n4NlGJ+C6s98a74/+O7HZ/0njL
         Hee/bIG5/UHqdT+W4YIT2TkwjYoOsdpO0OcGIQ43hUuTnT5LvUUXKQBa62WrTAuwfONn
         Too2wJ8I4WE+2iYvwB4AsNinXa7MUB7W8arb2lbwNJgeK7SpKPwkPKUmLGgBTrljZOHb
         +Mi7K9J8K3wwNVvnZStnQeMVIASScYdQES3cFEIkm9sJ6scy0FaF+jv9mb7QhZAjqT+d
         U6sQO2l+NWaFe/qYZG/EzVQahgsOn329P0/csgbSfsm7w4B3pKl9ZWicoUCNrxgLEzuZ
         Zyhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=P29fbCCYSVrQV+E5E5TGvjIFfKyEo/S1NyHnLC5JPTA=;
        b=uhDNRv49hQa/PQmV/tOUFSAWyZUr5mM89cF73moToaZCj/CK7TYoqHzxkXS8vCtT3O
         arrbfWWfnXS2s9PbOSnQCBWLhy0swIo4ujF+kI4aiXUYikFx8J5yvdKPb2JLJDA493Ty
         OmuQDjBXwaLtenQMhgMzgf7380HWLO1gp9lKlKjOZqk9lCwmnxP1ZxLvjqAepn256KAR
         00TRmlLqC1SahXsSSy77YMxPJ7WtL1YFdj6AF7gQsofqXWNrJvUPwScBY0slKNljdxr2
         K9uA3eUoueSSbhV3zqDW+azg79f0PMjoLGzPZ5F5DwxzrsX0TTdygSuR+B4aPOnuzFaM
         +82g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id 3si301617vkc.0.2021.10.11.05.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Oct 2021 05:17:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.55])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4HSd3N5MVrzbn3m;
	Mon, 11 Oct 2021 20:12:48 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Mon, 11 Oct 2021 20:17:15 +0800
Received: from localhost.localdomain (10.175.112.125) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.8; Mon, 11 Oct 2021 20:17:14 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: <naresh.kamboju@linaro.org>, <akpm@linux-foundatio.org>
CC: <andreyknvl@gmail.com>, <dvyukov@google.com>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-next@vger.kernel.org>, <ryabinin.a.a@gmail.com>,
	<sfr@canb.auug.org.au>, Kefeng Wang <wangkefeng.wang@huawei.com>, "Linux
 Kernel Functional Testing" <lkft@linaro.org>, Catalin Marinas
	<catalin.marinas@arm.com>
Subject: [PATCH] mm: kasan: Fix redefinition of 'kasan_populate_early_vm_area_shadow'
Date: Mon, 11 Oct 2021 12:32:11 +0000
Message-ID: <20211011123211.3936196-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <CA+G9fYv1Vbc-Y_czipb-z1bG=9axE4R1BztKGqWz-yy=+Wcsqw@mail.gmail.com>
References: <CA+G9fYv1Vbc-Y_czipb-z1bG=9axE4R1BztKGqWz-yy=+Wcsqw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

Move kasan_populate_early_vm_area_shadow() from mm/kasan/init.c to
mm/kasan/shadow.c, make it under CONFIG_KASAN_VMALLOC to fix the
redefinition issue.

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
Hi Andrew,
Could you help to merge this into previos patch
 "kasan: arm64: fix pcpu_page_first_chunk crash with KASAN_VMALLOC",
sorry for the build error.

 mm/kasan/init.c   | 5 -----
 mm/kasan/shadow.c | 5 +++++
 2 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index d39577d088a1..cc64ed6858c6 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -279,11 +279,6 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 	return 0;
 }
 
-void __init __weak kasan_populate_early_vm_area_shadow(void *start,
-						       unsigned long size)
-{
-}
-
 static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
 {
 	pte_t *pte;
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 8d95ee52d019..4a4929b29a23 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -254,6 +254,11 @@ core_initcall(kasan_memhotplug_init);
 
 #ifdef CONFIG_KASAN_VMALLOC
 
+void __init __weak kasan_populate_early_vm_area_shadow(void *start,
+						       unsigned long size)
+{
+}
+
 static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 				      void *unused)
 {
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211011123211.3936196-1-wangkefeng.wang%40huawei.com.
