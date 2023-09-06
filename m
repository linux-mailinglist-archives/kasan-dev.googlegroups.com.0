Return-Path: <kasan-dev+bncBCRKFI7J2AJRBS7C4GTQMGQEAVYINCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id BFB71793CAB
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Sep 2023 14:32:12 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-1bf2e81ce17sf4039827fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Sep 2023 05:32:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694003531; cv=pass;
        d=google.com; s=arc-20160816;
        b=xGCtqvGbYEccS2XoQEU4OUBKmPrDHogNw/nwYNZZjoV4UWlet0RQZz7vU2T48uOU21
         CZHw8ac1+/zXFy9ZHC269Va7YSoCz+4rSM1G8wKgmTV2ScOJfP/OqCw4F4k05Y22WFLp
         aN5/cjnE8y4mZiw/vPx3mkP6fbb9fJxz+n8d3a0HdLxHKWrHNn848jD+/OzHPMxjly2j
         WGBlbIrIUeyJOvzRLWPnlZ+TvATl2WzLRrcdJgWLR29kqPqZoRA/o5k1n0VCNsIUN3p0
         MxWiIcMbTdOCPaT8duN3NFXQbGZWc/Flhiwdp2oyZ9XVuqaYenJWEeDbUlQxXTF45WFW
         EoYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=2pCb/q5ebjOVDsi0IGoTDX2VvULnqf17tSt1iCNuGHg=;
        fh=yzysZ59oPk5DLEE5rhyc9UX9VwoFZbo45R1txxQt+Oc=;
        b=v+l7SeIdBsDBLrYFFhLk51daO/XN5ALIeo5DuSF012Dt9eSCdvQkCoMh7roX4zr9UG
         2+56g0kaRuwqHgEnm7rlcKIFCq5SVajTQr4kJkKjMd3j/N3gaexHJOkW1ZwF46kqy9wB
         AMsuyzQ5jhI/M3ze1c7xAejQKWIo6Xpvob2SeJeQZcq66RpI+m5GN247Hxp8ftZ4eTrf
         ebdjYlV/Riq43Pmbp7kPMj0q/XBsY5kQgrLi+tj5vxLElS6KWB0F0EdRqiPmP/bNZBrC
         IclxP38gOYqgJHYFRTVeVBHh8eaDjD9GiQEBj/G9oQM43LDf47im4fuwzADpml4d7r7w
         jESg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694003531; x=1694608331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2pCb/q5ebjOVDsi0IGoTDX2VvULnqf17tSt1iCNuGHg=;
        b=Zc5gnixtTw4WfwFvgR8p6J6qbnHIO4MUwC7fGL06TBMg4+kf1pRizcfhWnCeY+hLfq
         8bMACFjMFOHc2qz7FHR6nvgFlJgdIOJQ8qKGsUmw14vXxnjPE21iv6dKIELGJmAjrCkz
         +jgaLE0QVQvp6TCmGwku3wUh/v66i264YIqAmERY/IEC3FG+3a7J0PE6OkUJYFUdY1nt
         NHgDk7zKovZRWLhPqWRcbwtKUGqRIqOfBiIHYn8tPNN0RiKWOqw3Z8EyMFn5t3+QAZeC
         TPHHP8sw3VdoQEtd2+lb2+7ZJMsgkUN/hnHA45dcg7p3Qlovta38lq1i6jVlL43hHqjy
         ggKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1694003531; x=1694608331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2pCb/q5ebjOVDsi0IGoTDX2VvULnqf17tSt1iCNuGHg=;
        b=R8MkhGGiySD3wdN9AVlLNoHx7jkt5tGs3UEAFt2P3R+pscC1rP+rKs27jKAADphN33
         lQJ8Jekb0LzaXZJYc4TZ/JTlfQ5Pd4mOrshfGXBlondRVIyII+Ppf0nhSWNQ6OS35dJa
         ErzOnNQeh41ADky87RB1ACbCUhVzxlALMYyYrj+a0Qvh5d92OzmjS3wv0bXPGgY/1o3D
         bYQkFy6Ktc4bjs5h5gBU6gNtw+gKn10rmtDax9VFj5ECZqXsuXKW9SCAdQppGQhLQrWC
         de3m1Piu4jlV0cjHWve234P5TT7A/zODoqREkWKXHyPEVFo+gb8T1UZatiGvi07wU1pl
         Mv8g==
X-Gm-Message-State: AOJu0Yy7Ls8bYSrdLpmf85O5LtjKKrcP7ljh07fSsiX3KNjTpSOrYDMh
	/sLKsBokX/fhqKGduSQj3hA=
X-Google-Smtp-Source: AGHT+IEj9OVNjsWOBn5CHYvRdH6kjAnjcYMGa5vnQ/EvQ6gXbMEmaRZoSsFCGB3KIMcETVQcowFmww==
X-Received: by 2002:a05:6870:c21e:b0:1bf:80f2:8429 with SMTP id z30-20020a056870c21e00b001bf80f28429mr16918865oae.40.1694003531206;
        Wed, 06 Sep 2023 05:32:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:808d:b0:1c3:e0f6:4173 with SMTP id
 q13-20020a056870808d00b001c3e0f64173ls1476012oab.2.-pod-prod-08-us; Wed, 06
 Sep 2023 05:32:10 -0700 (PDT)
X-Received: by 2002:a05:6870:a70d:b0:1d0:d9e2:985f with SMTP id g13-20020a056870a70d00b001d0d9e2985fmr17902640oam.57.1694003530289;
        Wed, 06 Sep 2023 05:32:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694003530; cv=none;
        d=google.com; s=arc-20160816;
        b=IGTgAREyHieYp29hnCTb++jNVlmPmshwSK6+cf1Lq7a9zGBWZVF+i24DgZflxIfFhe
         iPXFHC76Xsn+om7FUFRnY3EGZdVBQfrNgmmZWj2Q9lXoxG4l29NhxDu5UQlJLNfiAnAh
         zBM2Wgw2Kvt2l2qkwAwjbi+uAIbCabPiZHL+OcLUU3YWgOF2zbsMGYzwm0lfWEVtoWaS
         kRpRtcYgU9c/68YlHEFTdnzq4Mkr851O+k4rdoGMpZutmdBxDyVyxo4J3nsBv4LC8Q5D
         PQoRdFQW9kD+vwSsY5n+LYZ4PDpyouIO8v73iypto71nHB+bi9cb2JnQqppa88woDRjE
         rWlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=JToBRFxNl66zYWnBducdJrCDg3ZqDJA6CVg9yHTw5eA=;
        fh=yzysZ59oPk5DLEE5rhyc9UX9VwoFZbo45R1txxQt+Oc=;
        b=wCJljxIICu6jqO/HTvundAFdKNtZ6IB61cQ3/8XXoDFxXh5/E/wePujYetxAD3JUGC
         Ma94Pux4xKqnLmn7K+G2XfJzT6taQgq+yS/+NyuW8P1g8Asy+Ct2qXfvorOiBD1iwMyW
         dYYyjfghZk2OOA0AeIfNZtQSH4v6BtzVFAAIKVKOIeRDoo/OofxkI2EES1vFAnKfyIct
         XaGf3OhoUQJGQi9h+Jicjvsh5vk629YRIwgCWf95cclFVmZe6D+cOeiCuwkDXLfl/bQV
         4D0OleUoOnEANrhMB9MHLv1pT6/yXajmTnREe/P4YUY6WY7ObcfOjxQtFGnFkhkNj1wj
         v/Tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id vi2-20020a0568710d8200b001c52be8d92bsi1421637oab.3.2023.09.06.05.32.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Sep 2023 05:32:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.55])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4RghWt4tLNzTlps;
	Wed,  6 Sep 2023 20:29:30 +0800 (CST)
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
Subject: [PATCH -rfc 1/3] mm: kasan: shadow: add cond_resched() in kasan_populate_vmalloc_pte()
Date: Wed, 6 Sep 2023 20:42:32 +0800
Message-ID: <20230906124234.134200-2-wangkefeng.wang@huawei.com>
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
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
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

The kasan_populate_vmalloc() will cost a lot of time when populate
large size, it will cause soft lockup,

  watchdog: BUG: soft lockup - CPU#3 stuck for 26s! [insmod:458]
  _raw_spin_unlock_irqrestore+0x50/0xb8
  rmqueue_bulk+0x434/0x6b8
  get_page_from_freelist+0xdd4/0x1680
  __alloc_pages+0x244/0x508
  alloc_pages+0xf0/0x218
  __get_free_pages+0x1c/0x50
  kasan_populate_vmalloc_pte+0x30/0x188
  __apply_to_page_range+0x3ec/0x650
  apply_to_page_range+0x1c/0x30
  kasan_populate_vmalloc+0x60/0x70
  alloc_vmap_area.part.67+0x328/0xe50
  alloc_vmap_area+0x4c/0x78
  __get_vm_area_node.constprop.76+0x130/0x240
  __vmalloc_node_range+0x12c/0x340
  __vmalloc_node+0x8c/0xb0
  vmalloc+0x2c/0x40

Fix it by adding a cond_resched().

Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 mm/kasan/shadow.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index dd772f9d0f08..fd15e38ff80e 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -317,6 +317,8 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
 	unsigned long page;
 	pte_t pte;
 
+	cond_resched();
+
 	if (likely(!pte_none(ptep_get(ptep))))
 		return 0;
 
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230906124234.134200-2-wangkefeng.wang%40huawei.com.
