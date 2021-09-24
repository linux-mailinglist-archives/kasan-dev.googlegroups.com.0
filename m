Return-Path: <kasan-dev+bncBAABB2FRW6FAMGQE6WUQBQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id C0A14417658
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 15:55:53 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 1-20020a630e41000000b002528846c9f2sf6219808pgo.12
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Sep 2021 06:55:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632491752; cv=pass;
        d=google.com; s=arc-20160816;
        b=wS47YWWWPIuv2kecjN6IvZ8fxPoJOvScx15tmJNhlqCMgLWxdpruUx3zccW6F4uPFY
         bZ4TsQ9yItba4NEgbiMULVoE2TXcIaOqaePllXdCkVGNF5MyrPDanN4KN8mljjcb4PMF
         ekF9mCU1r5x4SHS8v3WXUt09pEzr7BJrEunrUfd7S7dAnNiMUxQEOYpSJ1bKTP4bIxlW
         xVxXGFGiQPszWiwi9SIxSHpBhDupEzEBfGVE7kW9ycxu3/nZvhKPoPDFgYDBacLxy6XR
         7/yiYoUq95lcRS71QIHYEI+PQ018zN4HmO+nb5FcDRUuGEYxdGoM1EdJbmj6OfQulgn0
         kjGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type:message-id:date
         :subject:cc:to:from:dkim-filter:mime-version:sender:dkim-signature;
        bh=s16j3AtVn+L8ZLP5yQEKLDqOjVw9Xz1OjuNKsVUj5CY=;
        b=Pr7Phqaoec4V/ZSNIRsyJZNWkSIUk8pKh2x+rZIjLchbxj9XttVYvuIno7u/Di8Toh
         RGkJtF2vEaPxciduGfM+Qu0GE6l1jrx027LV3PLMcJ7diwEWHGtXptEU6vHui/qD3E16
         kbuIG2BzaK+Ek4dEEmL3545//dYCDChJW0e6OTjycTNOo9UAPbpTE8+5hx3b6Zy1j5Zu
         n4vwziZ5Au4Q8vFR9wvB5ZCqueJ/Aa4onPG3BNCgWGQsSZWFkNab+yMkyyRlxzWjW1sM
         DM1noMtJ1wEYC7l97HVSPSKC2N0ltRVg7VNMBoh5ooSAOYoCcpiEBxVC7dTTOrga0uaC
         oPGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=LUFa8tWW;
       spf=pass (google.com: domain of manjeet.p@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=manjeet.p@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:dkim-filter:from:to:cc:subject:date:message-id
         :cms-type:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s16j3AtVn+L8ZLP5yQEKLDqOjVw9Xz1OjuNKsVUj5CY=;
        b=IHC8mc9D3dSJAY5I+0hU6l/sFBj0b5H/i7n3/0a4ghz7AzyCcCurSQMB4f/J7iQBF3
         BEW71wJVetkUEXhiF/m9Oi7bb3t6Klo6P4E5GVIoHaQGn2xOMjUqQxF9rEfI/AV8lXpQ
         0qGPZicEsW8QK1Dky3jVyeJg+IP+Jg8MK2IWm/jNT2SR2TopoIZ+OVhVXRbIckf3SgXh
         Agt79eqAZsX2XaumxlI4AvWzmDa99drMqEoWQN3QBEUplqPfgFpoWEo1fNHzgNQYb0ns
         XmvHFWi9W7/zOciA+oBJqm2vtFTkdvqvWBYqEvNzZgFGKjEtbPvhKJf3tju7rEC4Xdi0
         Yi3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:dkim-filter:from:to:cc
         :subject:date:message-id:cms-type:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s16j3AtVn+L8ZLP5yQEKLDqOjVw9Xz1OjuNKsVUj5CY=;
        b=W+Z6/wZBn1qnR3liQHM3tBZpinLvcl764ZCDbB+6DgBHF7RxVxYgat6XrMflbpiCTb
         gd1/xQ7Z6/MUMVPaC2nYIl9IlNBQ67F7jnFX2ZyXEexu00kdYc41pU0b26o/GwCsGwX9
         d2PiFPa6kmYyNzNoqeVgzp4TOnixyj6uc8CS5OFCRarMXgwxhNNpy98GH0xw0TfNK1Yj
         3/keVlQcxgN/Psi1x1J9meYnHVg6nLOCXRftg2kvkQSi5CLB2oismvLoJyafynXWaSvu
         hdIhZ7TI8lxdXH2ZoVAHtuWLQA5+sjX/HJzhRtWvRcnKNUiK6owLmQlQZE57UqdeOeKs
         Kncg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Uz/yUKR3hYj3ja0VJ5FJarR/g0+8j1Y6euRcL5Fl4PejWo7CV
	eHdkL0r0DwyTG6nGzGLkx5g=
X-Google-Smtp-Source: ABdhPJzgmRMECnf07l3bozrOjrzV37mPOgoH7McJQM5qrZe6o8eJgOOOBZe4ekxu+7LSsGyh+Bgj4g==
X-Received: by 2002:a17:90a:d312:: with SMTP id p18mr2365755pju.64.1632491752224;
        Fri, 24 Sep 2021 06:55:52 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3842:: with SMTP id l2ls7888481pjf.3.canary-gmail;
 Fri, 24 Sep 2021 06:55:51 -0700 (PDT)
X-Received: by 2002:a17:902:c10a:b0:132:580a:90b4 with SMTP id 10-20020a170902c10a00b00132580a90b4mr9065602pli.7.1632491751734;
        Fri, 24 Sep 2021 06:55:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632491751; cv=none;
        d=google.com; s=arc-20160816;
        b=zAxWFtz3k66N45SvMBNBknaMYG2awbTnGUkQasr2vCUDTee5kyDVL8gAYnwMnO2vqz
         oNyvMa9abeX/xu2PYG9DabkF5ckXM+d1i3pn1ty5bn7U+v9fkhc5Hnz9JX8AsBUobsHK
         mAGD6iyQYk1klNm4c1VRqPBSmYj2fLnd4Mh7lJwvAQUioDKdNRo6Mz5p/W6YmXeJhu2I
         JsIWyFz1yVzquwl5Jfwg4+itc6iAw4bM4BZpldzfOZGwlrNyBPGAYkzHj1mcpxaj5UOQ
         J2apaLMG6qHaw021tZqoivSd2Q/2/DCNoayygdtX6QiSmpYOfRKlL+lYpPTNZ+CywnWq
         n3kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:message-id:date:subject:cc:to:from
         :dkim-signature:dkim-filter;
        bh=mNQhFy+0EiS+QFcEKoyz6Gg5CkSs9cKnhKzNpsJdN6Y=;
        b=fj0bvmzJ7zpeECrYQkbUNTd6sCPYGAjOrQ/O/ase3IqpPUkyywbUWrSsm5vlp0rSle
         g/Pz+J3BRWvKt5fYvGaMOxrMZx6IlELPJNtWrbQ6qwpc5JiAPBJ3sd6FQ7VJGI4Ar/Vd
         s0hovqjzQZOBaTfthTsWjY9XP9TChKet7cZAeu6kYFDeAXc3/YSacF400EUNsy6kyo81
         3bFEHJBPDRF05rQHDCocbFDOTqHOTxjL6odaw2vqIgsOG3R45OtugnOx43iMcC8ZZbBb
         2kr+8J93PWluIAMcZq3icrqKP7Hj7Rf/k3/UJX1tg6zmKUKVu4mryandbJaX/ze4jvBF
         wNyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=LUFa8tWW;
       spf=pass (google.com: domain of manjeet.p@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=manjeet.p@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.samsung.com (mailout1.samsung.com. [203.254.224.24])
        by gmr-mx.google.com with ESMTPS id u127si811129pfc.5.2021.09.24.06.55.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 24 Sep 2021 06:55:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of manjeet.p@samsung.com designates 203.254.224.24 as permitted sender) client-ip=203.254.224.24;
Received: from epcas5p1.samsung.com (unknown [182.195.41.39])
	by mailout1.samsung.com (KnoxPortal) with ESMTP id 20210924135549epoutp016d56e5c5b8e756373f9c369711a728cb~nxpjCqkpP1278212782epoutp01j
	for <kasan-dev@googlegroups.com>; Fri, 24 Sep 2021 13:55:49 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.samsung.com 20210924135549epoutp016d56e5c5b8e756373f9c369711a728cb~nxpjCqkpP1278212782epoutp01j
Received: from epsmges5p1new.samsung.com (unknown [182.195.42.73]) by
	epcas5p1.samsung.com (KnoxPortal) with ESMTP id
	20210924135548epcas5p114c5dca6c0cb260a1e30d3bde0962b39~nxph5DVLr1707317073epcas5p1g;
	Fri, 24 Sep 2021 13:55:48 +0000 (GMT)
Received: from epcas5p3.samsung.com ( [182.195.41.41]) by
	epsmges5p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	80.22.59762.3E8DD416; Fri, 24 Sep 2021 22:55:47 +0900 (KST)
Received: from epsmtrp2.samsung.com (unknown [182.195.40.14]) by
	epcas5p3.samsung.com (KnoxPortal) with ESMTPA id
	20210924121457epcas5p39266266f9cef79177f2301a6a4f7d79a~nwRe_0fYE1848718487epcas5p3u;
	Fri, 24 Sep 2021 12:14:57 +0000 (GMT)
Received: from epsmgms1p1new.samsung.com (unknown [182.195.42.41]) by
	epsmtrp2.samsung.com (KnoxPortal) with ESMTP id
	20210924121457epsmtrp21f242e919d84fda83da496006302ee51~nwRe_AMG82712327123epsmtrp2B;
	Fri, 24 Sep 2021 12:14:57 +0000 (GMT)
X-AuditID: b6c32a49-10fff7000000e972-97-614dd8e38bdf
Received: from epsmtip2.samsung.com ( [182.195.34.31]) by
	epsmgms1p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	AB.6D.09091.141CD416; Fri, 24 Sep 2021 21:14:57 +0900 (KST)
Received: from localhost.localdomain (unknown [107.109.224.44]) by
	epsmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20210924121455epsmtip2923d25f8bf1e960d7c28e1c1f758c3bc~nwRc95v331682016820epsmtip2a;
	Fri, 24 Sep 2021 12:14:55 +0000 (GMT)
From: Manjeet Pawar <manjeet.p@samsung.com>
To: glider@google.com, elver@google.com, dvyukov@google.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Cc: r.thapliyal@samsung.com, a.sahrawat@samsung.com, v.narang@samsung.com,
	Manjeet Pawar <manjeet.p@samsung.com>
Subject: [PATCH] mm/kfence: Null check is added for return value of
 addr_to_metadata
Date: Fri, 24 Sep 2021 17:44:02 +0530
Message-Id: <1632485642-20625-1-git-send-email-manjeet.p@samsung.com>
X-Mailer: git-send-email 2.7.4
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFvrAIsWRmVeSWpSXmKPExsWy7bCmpu7jG76JBkt6bCwu7k61mLN+DZvF
	hIdt7BZtZ7azWrR/3MtsseLZfSaLy7vmsFncW/Of1eJe61o2i433si0OnZzL6MDtsWBTqcee
	iSfZPDZ9msTucWLGbxaPvi2rGD0+b5ILYIvisklJzcksSy3St0vgyujeeoC9oJmt4tjeZYwN
	jJ9Zuhg5OSQETCR6tq9l7GLk4hAS2M0oMWfaNFaQhJDAJ0aJjx+dIBLfGCW+zO5khOn49+YL
	VMdeRomeDVPYIJwvjBIvFi0Dq2IT0JbY86ONHSQhIrCCUWLWifdMIAlmgSKJ97+Xs4PYwgJh
	Eh2HF4DFWQRUJY5f2gq2m1fAVeLYxbvsEOvkJG6e62QGGSQhcIpd4uDUj6wQCReJ3w/+s0HY
	whKvjm+BapCS+PxuL1S8XmLzhs1QzT2MEj/P/oRK2Es8ubgQaBAH0EWaEut36UOEZSWmnloH
	dSifRO/vJ0wQcV6JHfNgbGWJZec3Q9mSErPPHGWGsD0kNt94xQwJvFiJyR9amCYwys5C2LCA
	kXEVo2RqQXFuemqxaYFhXmq5XnFibnFpXrpecn7uJkZwotDy3MF498EHvUOMTByMhxglOJiV
	RHg/3/BKFOJNSaysSi3Kjy8qzUktPsQozcGiJM778bVlopBAemJJanZqakFqEUyWiYNTqoGp
	/1Dko7KdWw/uuDax9KSaZ6fU/GIHu7CJjX9e3z7bk5eU5ZEXclKzU52v916l6q+by4/wn+H8
	HDorTP6OL+NXzb7XqZlmE57rSTldqxBbf+3vlYil+vrHor4dDJHcKD55yn+lbdNt/m5LaW2M
	4Y1YxLp6kbi36+1dqR+O/snMvf3m6oETzad5FApr29+9Fn/e6tP+hXm95aIDHlVvnVhrXy6s
	vLTBKEWma3OHwS6+o1Flp/azM8ld6rwVeO6q4PWi76YnN9xb9Nv0nJjSpALW/7U7HhTYpO9l
	OjaLj831KU+bg0dqx6+7HYdSTtm8PePpHTI3f4r7k8i1YvobP1wIdP32fb1YxyktfnGj25v2
	KLEUZyQaajEXFScCAFiuq3aDAwAA
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFprELMWRmVeSWpSXmKPExsWy7bCSvK7jQd9Eg/7rwhYXd6dazFm/hs1i
	wsM2dou2M9tZLdo/7mW2WPHsPpPF5V1z2CzurfnPanGvdS2bxcZ72RaHTs5ldOD2WLCp1GPP
	xJNsHps+TWL3ODHjN4tH35ZVjB6fN8kFsEVx2aSk5mSWpRbp2yVwZXRvPcBe0MxWcWzvMsYG
	xs8sXYycHBICJhL/3nxhBLGFBHYzSjyeogsRl5ToXzcVqkZYYuW/5+wQNZ8YJba1poDYbALa
	Ent+tIHFRQQ2MEqseefdxcjBwSxQJtHwWQAkLCwQIjFh4XpmEJtFQFXi+KWtrCA2r4CrxLGL
	d9khxstJ3DzXyTyBkWcBI8MqRsnUguLc9NxiwwLDvNRyveLE3OLSvHS95PzcTYzgYNPS3MG4
	fdUHvUOMTByMhxglOJiVRHg/3/BKFOJNSaysSi3Kjy8qzUktPsQozcGiJM57oetkvJBAemJJ
	anZqakFqEUyWiYNTqoHJbXHGqX+Jk57xvSx7/+JT1xXZm891IjdVnRCXYLVfvvby65jfs+1Z
	MwoDg7+mSPdnTfn1JTdpo/uUuVV3dsQocwh9uGsUWHovvcdrv4HWgVUek6+z39ZJ/W11zkLW
	KLnqT9+Pa1zfeSKP/Hz2vztB3DTkytG+K9m7xSuVDiza5Xeapym0O+Jq3luDiRtz8x+IPrj/
	+26trXyeetpWRdP4rT8NPkXX7NH2eTCjlYXvkenLD4YWGX+O+SzY/+DJ0v9SWUmJ3o+aF/H/
	9jWUecxofPl97EtjY0v2Z/8bG3V1hJ89TCudoM94d6dup3+qbRani/CyU7v+Ja6eenJT89me
	hHfsC9gixdylVv1a0DZHiaU4I9FQi7moOBEAT32yLaUCAAA=
X-CMS-MailID: 20210924121457epcas5p39266266f9cef79177f2301a6a4f7d79a
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-Sendblock-Type: REQ_APPROVE
CMS-TYPE: 105P
X-CMS-RootMailID: 20210924121457epcas5p39266266f9cef79177f2301a6a4f7d79a
References: <CGME20210924121457epcas5p39266266f9cef79177f2301a6a4f7d79a@epcas5p3.samsung.com>
X-Original-Sender: manjeet.p@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=LUFa8tWW;       spf=pass
 (google.com: domain of manjeet.p@samsung.com designates 203.254.224.24 as
 permitted sender) smtp.mailfrom=manjeet.p@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

This patch add null check for return value of addr_to_metadata().
currently 'meta' is geting accessed without any NULL check but it is
usually checked for this function.

Signed-off-by: Manjeet Pawar <manjeet.p@samsung.com>
---
 mm/kfence/core.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 575c685aa642..9b953cfa7fee 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -802,6 +802,9 @@ void __kfence_free(void *addr)
 {
 	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);
 
+	if (unlikely(!meta))
+		return;
+
 	/*
 	 * If the objects of the cache are SLAB_TYPESAFE_BY_RCU, defer freeing
 	 * the object, as the object page may be recycled for other-typed
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1632485642-20625-1-git-send-email-manjeet.p%40samsung.com.
