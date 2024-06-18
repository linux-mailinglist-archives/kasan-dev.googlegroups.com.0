Return-Path: <kasan-dev+bncBAABBZOXYSZQMGQECXHMEIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5960990C3C5
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 08:40:39 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6b062eba328sf66446376d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 23:40:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718692838; cv=pass;
        d=google.com; s=arc-20160816;
        b=dduSyZ7pU0X3iQ76XcwNAYM3c9KqCS1rx926UYgTrOWXv5xxVUPD3eWL/mv7wMd7or
         IeYQK7dBOFfywWHHJEyNRchS+dgU+YhllOMW0dxsdhQpTVA0zoEm4OQOE7DBGdI7XLfz
         786Mb9tcRSWfRpbssxLaNXCGikPl0vvQJmGbF29IjQuJT3V1L0VQdciG27Rn1D48uEeg
         S7lfP9cm2H07i4F7Vgmcz87vnjtylg93r2mDiZ0tUH+vkH0P5W4EkFF96TMffFyM0duq
         xxjfvp3Nxm+fpDlQ2PWOZDFmXWm/QaSF4KpoEBCJi3jeGVVpfSvG6DoOqcxWUxc4FLeE
         JbLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=MJqHxDQzrel410FllXJi4CDWs1T0n+7rCCXmLGNfXWg=;
        fh=m9usIosG3PmSMfblPMe9xxSZ379GZg3SvqQ38aoI2+M=;
        b=Q5gyLbHqmVOBfXTaBk1OC/7+Syr4WKXYQJrpxu9KFBtRz0XcK/Ctw/Dra4ew6/M6V3
         JBvljtYP2NpZEvAQ5th984VxY9sq4JXhzwGMfXqQuBnRQVn1zlu+VFEG4E657FoA6KEB
         wCfHAuYqGU+Nu7v3NzYxQmau/KAbD9ZTYFDlUuhpKf1EN3CKRwegpbNfn4dohquVyGmj
         Yp2nAykbTrVJIFaPxWj9fbaIG3VnKUPaLC8Z7oI1YIKZbvJ8Mbtpk/IPfqiCMy23T80C
         aveMxkKgXbDtu25+Z5oabHUeunh0h/FYn3/uiW1wt2hULwKuTnLOJhOJGYN6QtaBFQqb
         8qMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=mawupeng1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718692838; x=1719297638; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MJqHxDQzrel410FllXJi4CDWs1T0n+7rCCXmLGNfXWg=;
        b=vYKUI7uclMz/3lpImvkU+y9V2jtgp8WqeJjysYdklakSOXGB6ROOnWOa1DqqvwHypr
         PLiegz+BUrvjui2zUXqpE5Ax//6FaP6QOyEMPUgdZWhRx/pjW28SIG+XkefsF1hi4ShH
         bre+93nBrZtlwAiZF0Pc7i3Jyld44VPlV1R6kIEENhEwk6JFQiZP2dtxLqHCpWJCoQQ1
         iOn+YpDgrREWzj5UmecxhPDJvKzihxqMdKWMzTAenTrJsCGtYd2ypT/Gtffg8bE2moHP
         2Wt/V7GS54me7XnfuqtFFDZQEf2S/Dq32YsTTxaxA6z+NrYZknt6WdDJscGFhxTYJVyd
         B8gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718692838; x=1719297638;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MJqHxDQzrel410FllXJi4CDWs1T0n+7rCCXmLGNfXWg=;
        b=n6URaSK3sfACAwRJy7LYbmEv4zXTxe9PumEwwK/MaElJcdokZJ5O5sVnD2wbItpIAJ
         EFUUCJ5DYppn7g0PchCV6qcauM0BVXQBPPjewj353xtxCk+59y+OQZzgIxkzch89j4fl
         wLuEggBeeyM9MbAryZxh3qcy+GdqkRHziOj3yBi9ASUlIFHWCv0KT/1KqYOVytNc2czX
         3xg2Wt1V1Ok/QH8A8D+rPIXWwbUKW5fhaID8Mka8Tcm6nJWuEs669322TU/mR/N7H5PO
         RcRY2LDEnIuO82bPcpwSisHpmMitgST4hDgblyfBXtITT6qn5vczI1lSPXmYWRVUxV0U
         QBXQ==
X-Forwarded-Encrypted: i=2; AJvYcCVfQf3f8ZQTbyCybl6BfkUA1Is3Hxb+sj2vU8K7SgvXeIuWBFzcNHGDPedPTn8saL/DYowpCWZoSAHY9AjsrdZEQzcMTNmEjw==
X-Gm-Message-State: AOJu0Yz+Nhvdt+bNBQ5ctuN6akQyIUtUakRIIEjNswJhUFXkLbxNlkUP
	7xUo+m95OqwDqUsxIgdEHUL0/VClMhuBSkP9O8C2elqnHOD3kwwU
X-Google-Smtp-Source: AGHT+IF4b6xH774CuCxxPERlCg2T9PAXPCg31VPT6wXnKGkQanB+XVLat7+GPvSxnlIFnScD7+vfEQ==
X-Received: by 2002:a05:6214:8e4:b0:6b2:9819:754b with SMTP id 6a1803df08f44-6b2afc721c3mr112771016d6.10.1718692837937;
        Mon, 17 Jun 2024 23:40:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3108:b0:6b0:94b8:6230 with SMTP id
 6a1803df08f44-6b2a338575dls73206486d6.0.-pod-prod-05-us; Mon, 17 Jun 2024
 23:40:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVg5PIOXwD+xMKf2T/yzbPxhOpFW9y7YJCbvKVZ8/JHc/IrIOIZr4H+CryxRnKeoGWOgRFI16Q0o0Yu+FNobXYzKWRwHp2ZJlEUzQ==
X-Received: by 2002:a0c:d6cc:0:b0:6b2:cef9:712c with SMTP id 6a1803df08f44-6b2cef971fbmr62575136d6.49.1718692837346;
        Mon, 17 Jun 2024 23:40:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718692837; cv=none;
        d=google.com; s=arc-20160816;
        b=sj3474Xx6w8jJ29eDuTzGH1QQo9DRVGjcjBSBS80dvEHbx0KVDac7Nye2lhGHkvgdL
         rCVVgVmFN/bAg69+V6cfpFrhhNnWwZb49aUeROKS8j1lnIxwDlCMO8pPTi9z2kyjm/6D
         e5FV0BCnU+X2zskRakOyoetj60a3UmcBuzbYDH6FGltLxlOcRkEeaQqSkZepPFqvlRDb
         7pkCQOFYCd5Pg2ScyVgGyTJ1TW9fiA+PPbg/fRdv9ApeOHNE4+zXeo9qkkf4FNB1AP6O
         KpIcHX1b0W0HkWF9AMvxOGFM2+s8QzXrwD2QuQ/fhsjDP0/h3w5Yyra05kZ5Y+l5ObXd
         GWtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=5I8whTwiIFSJuGcU2vYQdIaMkNCL86sWL59+VsEuFrE=;
        fh=skoUzj2hzBAD40caDelPnIpgeVjS2GJ+SWz+elMAo8E=;
        b=ns6X4E8iPhRbPwgZCvL1jzXhQn9UAdjIvspcxjVbyKWVqH8j5vaO+nxOiipArQVKzU
         bj8Pbh4c+SwlzB1MITQyZ7GGZYIIAt1C3dYaJ1A1khQwX/vQg418xvXLHAVfxjwD72T7
         CqqDYBChCMA2gjACiIUl9FnLSG7/akysS7cqHzy2UGPJ0XyWzomMBAQa5uD7sZf/tj4e
         7jqrrOddzviDiyN2eHmjsV4TyJeZ19CI0+TTW2fQn6CCFjTnXGTa51FU1klVON9pWkyW
         r8IAfQgK0OD/4MsbWIEGlo6yBEUfpSj1cek739z27shMWhJMA6iH73HkZcIWSHmsFL9U
         5hJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=mawupeng1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga05-in.huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6b2a5b2b6e5si7716376d6.3.2024.06.17.23.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 17 Jun 2024 23:40:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of mawupeng1@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from mail.maildlp.com (unknown [172.19.162.112])
	by szxga05-in.huawei.com (SkyGuard) with ESMTP id 4W3HBw2GjPz1HDW6;
	Tue, 18 Jun 2024 14:38:32 +0800 (CST)
Received: from dggpemd200001.china.huawei.com (unknown [7.185.36.224])
	by mail.maildlp.com (Postfix) with ESMTPS id BD7A2140123;
	Tue, 18 Jun 2024 14:40:33 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 dggpemd200001.china.huawei.com (7.185.36.224) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.34; Tue, 18 Jun 2024 14:40:33 +0800
From: "'Wupeng Ma' via kasan-dev" <kasan-dev@googlegroups.com>
To: <akpm@linux-foundation.org>, <ryabinin.a.a@gmail.com>,
	<glider@google.com>, <andreyknvl@gmail.com>, <dvyukov@google.com>,
	<vincenzo.frascino@arm.com>
CC: <mawupeng1@huawei.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
Subject: [Question] race during kasan_populate_vmalloc_pte
Date: Tue, 18 Jun 2024 14:40:22 +0800
Message-ID: <20240618064022.1990814-1-mawupeng1@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 dggpemd200001.china.huawei.com (7.185.36.224)
X-Original-Sender: mawupeng1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mawupeng1@huawei.com designates 45.249.212.191 as
 permitted sender) smtp.mailfrom=mawupeng1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Wupeng Ma <mawupeng1@huawei.com>
Reply-To: Wupeng Ma <mawupeng1@huawei.com>
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

Hi maintainers,

During our testing, we discovered that kasan vmalloc may trigger a false
vmalloc-out-of-bounds warning due to a race between kasan_populate_vmalloc_pte
and kasan_depopulate_vmalloc_pte.

cpu0				cpu1				cpu2
  kasan_populate_vmalloc_pte	kasan_populate_vmalloc_pte	kasan_depopulate_vmalloc_pte
								spin_unlock(&init_mm.page_table_lock);
  pte_none(ptep_get(ptep))
  // pte is valid here, return here
								pte_clear(&init_mm, addr, ptep);
				pte_none(ptep_get(ptep))
				// pte is none here try alloc new pages
								spin_lock(&init_mm.page_table_lock);
kasan_poison
// memset kasan shadow region to 0
				page = __get_free_page(GFP_KERNEL);
				__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
				pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
				spin_lock(&init_mm.page_table_lock);
				set_pte_at(&init_mm, addr, ptep, pte);
				spin_unlock(&init_mm.page_table_lock);


Since kasan shadow memory in cpu0 is set to 0xf0 which means it is not
initialized after the race in cpu1. Consequently, a false vmalloc-out-of-bounds
warning is triggered when a user attempts to access this memory region.

The root cause of this problem is the pte valid check at the start of
kasan_populate_vmalloc_pte should be removed since it is not protected by
page_table_lock. However, this may result in severe performance degradation
since pages will be frequently allocated and freed.

Is there have any thoughts on how to solve this issue?

Thank you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240618064022.1990814-1-mawupeng1%40huawei.com.
