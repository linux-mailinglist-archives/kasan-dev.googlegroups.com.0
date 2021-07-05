Return-Path: <kasan-dev+bncBCRKFI7J2AJRB46PRODQMGQE44PVJYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id A2CE53BBBF4
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jul 2021 13:07:32 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id br8-20020a17090b0f08b02901706e80711dsf6787686pjb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 04:07:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625483251; cv=pass;
        d=google.com; s=arc-20160816;
        b=xUYIwvVtpAVPOdZaoMoN9EBnhWiNBdRUXA6pkQlTJMQQTcIoYunJ75k4rsoqkD1AeV
         AdaBWdUTTwnQ3HKqHAYvSxkpcTTGoMNU/iKJA/pV0dC3xKh1N24WmbTpsZmSE/ydxamt
         bXe67Ye6UX0+HPCf0u0AuBmzNvKj0cbTrX5YJyZCWklRj4EAm4iWIjtKEOI5LYTgXQ/V
         CRdTED8VF3Y835UaOoafIIl+N4zttqSwxb/fIuE40WbHLkFSK7nyACasGxXDrGqsXRUb
         EniRyIrv2LDe0j9OxSlqLIVX06xGa6Eq0elVLkY1FYCgP+s36eaLyPRxRkj54u3g+QfC
         KkDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LnicEOccWRttEMIADdq2+lD0Nj2RScgnZmm3g3ZYF40=;
        b=SKEI1TvXVp6PzceVjSiamkk8y3vwl08JpDePZaw7dWMYNWzndZ5zlCtmrAQmN5nXU0
         doKvV7WuThDEPo+om4Aj5KuXMXcgKA+19j2zrZjQk+AABAmVywGFN8fVvQBDCfHeLtqV
         pClda17U14WcxU2jJnSuZdmAb99V2eHCoCWlGYwOsLTcxihRwpuJPiKN00ZMZraKjJh6
         Qf6iA+8J6htqAvJQC8hT0Q7v1kvupoUmgLm63bjkS4v4Lz3PMAHpfadPp/9M9ZZ8mnhF
         ulWOdBHsUNh740SGqqaxCpTKYS5pyC1xfDZcTd+ntzRuQS9ByMtlMjtdOzzenZdHoecV
         oDDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LnicEOccWRttEMIADdq2+lD0Nj2RScgnZmm3g3ZYF40=;
        b=TYtUe9G/FhNUuUbSQL2maLpxF3SrU0mMgLCAde9e0YqIu4hqzu+ZiidJsmDUeQOc5l
         oKmDDJ9iTkEPOq4TntMUEw9zJ1FUMeCaoPwYOFF6yGRfVwow47bPYlWVvxNFGu8a/AjQ
         zG63SXAO4KD8PXGyjMlZqmEVHU+Us7L/8ggmn9Oxs4azyKJCOJpn41dMqe8yUtQUsdV6
         tx28oNjvj32SpN0KliJNePSs9gsFwvVAle162EWwNdw0nOe9hWFduZCXuj+7B6WXsrhR
         HywENxICQBSlp8lyqhEzhGGs7ePaRi8fVc5Hv6uus6ucLF0n8OqCCT/UHDVnwvQvhU/x
         yrNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LnicEOccWRttEMIADdq2+lD0Nj2RScgnZmm3g3ZYF40=;
        b=jYUwxBWD9kyXu+D8sp4jvBUc5EhQKb4mn2JBikZgwnlfM5nVAVRHsWqYqWIIEQX/Nx
         +L8Qir3Fl3NT1f6D3S7F/QXEHBb1XqOqhT7bJaX87nfeR6M1h41Y+RXYelkhhuc1RZMA
         mejEcXBUmDpOSe2g9yKN29C0YWTbnVZmKckTC78JUm58dQAxKFIhIDJd3OPmGdXp4LU6
         AakXV3XVH9eICJ60UggTqvqTWozD2U8IHBEKuEzEB7lZEmF7xfDsSVyGBp8zpIVZ/w95
         bOfPNClWL+Tw9zJkxOfb5VLGH6HuwBA0XpwpfuJ06rdeI7IIONipbSowzyUnLuapibyl
         9N1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lJPJ94Im5BUAh1ofXZsT6EDT+k0hch5xsMOMJBqQvd7DqDCED
	WVGpuiu3/CR63J4sAazETdo=
X-Google-Smtp-Source: ABdhPJyJAjX3iC9Ym6L+syLKUpDU4M50QuShgtzy/vMKDxbQ6SlGSc2kWRHp7pns+TBXJdSY1wfl1Q==
X-Received: by 2002:a17:902:8216:b029:128:b9a1:eb with SMTP id x22-20020a1709028216b0290128b9a100ebmr12032539pln.18.1625483251387;
        Mon, 05 Jul 2021 04:07:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:3346:: with SMTP id z67ls4045227pfz.2.gmail; Mon, 05 Jul
 2021 04:07:31 -0700 (PDT)
X-Received: by 2002:a05:6a00:8c5:b029:312:c824:c54c with SMTP id s5-20020a056a0008c5b0290312c824c54cmr14354586pfu.76.1625483250919;
        Mon, 05 Jul 2021 04:07:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625483250; cv=none;
        d=google.com; s=arc-20160816;
        b=W1zxg3Llppbq3eKjMNjaP9UGcZL675qATnCQgb3L+0M3q1geGwhJx+v5ewEmV0pwfn
         tJxv2h1IYm0ErHsfwC24vvrs573Nx+100TTnA1bFy+kZxttvR9cyV279HVabLCkRVABA
         BmxOdWCShiCoaJL2YbMUwqRHw9dcMEU+E7+CgGLfu2rhFX4ISzHTv9XtDNQ1U1nHdOWE
         vyv//f0qn7dPi0Zj+xAEiH7Z2iEvGuQMPOui9gnNWh1fheteBd6UvkYRzJQpRcvKlt2N
         oLuMB6TtrLxoxno2jxAc6rJLENPDKBl23L0G6hTrACqDhcEJ0Ldwn6s34Nhy5pEuElf2
         T3vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=crhEsxlvP6MHymS30oH4t45tFzrcS7jAYSivt7vxdIc=;
        b=qRiQ9fwjm49/jrgkmmzTwOW6Sx2hKog7JDo6Y9NRBh2d/woikRvIqw3t6I9t2yix7r
         Zamod/6EwYtGb9XbznHRdDaafuaU+e0aho4c2FT/WXK6eCKoWPmeWBUaP+ci8DuqBtR7
         32OAvDqoIe1oq7/xU7yDeb+Xhxpa8g2G6Uk2MExO69NYNDsOZfGNILzmpWbUeo/NPJng
         mZj59JAt8Se0DBE1QqREv8m6mNcY+UiXBXVdPAvmO3SxjzONutZBhNgorwK0Z2QvhkVH
         BJq9n5LtsFg6nShDmZShXlpjqb3s56IOMOYKuUCZISfLQua4vlJkSMTxVrIw0sUN1Dyb
         w89A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id c12si881138plo.2.2021.07.05.04.07.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Jul 2021 04:07:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4GJN8F4p9Kz70PR;
	Mon,  5 Jul 2021 19:03:09 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 5 Jul 2021 19:07:28 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 5 Jul 2021 19:07:28 +0800
From: Kefeng Wang <wangkefeng.wang@huawei.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov
	<andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>, Kefeng Wang
	<wangkefeng.wang@huawei.com>
Subject: [PATCH -next 1/3] vmalloc: Choose a better start address in vm_area_register_early()
Date: Mon, 5 Jul 2021 19:14:51 +0800
Message-ID: <20210705111453.164230-2-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.189
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

There are some fixed locations in the vmalloc area be reserved
in ARM(see iotable_init()) and ARM64(see map_kernel()), but for
pcpu_page_first_chunk(), it calls vm_area_register_early() and
choose VMALLOC_START as the start address of vmap area which
could be conflicted with above address, then could trigger a
BUG_ON in vm_area_add_early().

Let's choose the end of existing address range in vmlist as the
start address instead of VMALLOC_START to avoid the BUG_ON.

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 mm/vmalloc.c | 8 +++++---
 1 file changed, 5 insertions(+), 3 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d5cd52805149..a98cf97f032f 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2238,12 +2238,14 @@ void __init vm_area_add_early(struct vm_struct *vm)
  */
 void __init vm_area_register_early(struct vm_struct *vm, size_t align)
 {
-	static size_t vm_init_off __initdata;
+	unsigned long vm_start = VMALLOC_START;
+	struct vm_struct *tmp;
 	unsigned long addr;
 
-	addr = ALIGN(VMALLOC_START + vm_init_off, align);
-	vm_init_off = PFN_ALIGN(addr + vm->size) - VMALLOC_START;
+	for (tmp = vmlist; tmp; tmp = tmp->next)
+		vm_start = (unsigned long)tmp->addr + tmp->size;
 
+	addr = ALIGN(vm_start, align);
 	vm->addr = (void *)addr;
 
 	vm_area_add_early(vm);
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210705111453.164230-2-wangkefeng.wang%40huawei.com.
