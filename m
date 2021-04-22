Return-Path: <kasan-dev+bncBDN6TT4BRQPRBOH6QSCAMGQEGY4M3CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 66E9C367D8E
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 11:17:45 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id y4-20020a67d2040000b029022169fd7297sf4203966vsi.5
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 02:17:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619083064; cv=pass;
        d=google.com; s=arc-20160816;
        b=SwP3XhugLr/DUmH1JTUwbDS3ijPeEAXpf1jnUqRBHqnvlzMPHzgjzymwI1EjSazh87
         yDwsXOsXzp2A9vM6pNZ++/FXuvIh0kZs81BWoSy6BiYIUCNK02/i6tj8PbXQarAmkTYR
         yfScMQoMdvKEBHIZCtrlQ75lRUi5JXmw1i2Mo0nagaUsPW36rD/QtfOAvyx4eF8KjHYu
         rByGNw4noxYq1U+RcK0yY+mbQWSrNd3zpCf1tXcJJLfwVRHNd1ytju0hHWs0vuLpSEt3
         yqHOjvRUmvNz7bZh/fISuuff1u8bPvGt/q/Ue9MRAlgzKvlNHAh18ihGZEFY6gb+dK3J
         vcvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-filter:mime-version:sender
         :dkim-signature;
        bh=zPKLQcRm66zAv6ZdtxcB1i8a5Ip7bJyla2I75dMn0Ms=;
        b=hI+5HkV4S254X5IGsfG7EZsej3uyFsj7iq4q31xJ/S7KAIDNA1ZwfkcYqhzgXlCxuY
         VfxIbOqCx8z+VFDvLhxV7xdtcpLn4FNe8xXcU7PLQBgpoHvTBOGV2sDWRQpsM/cSCS6k
         stU6LHcL/n29GX+UiGLX1VkIqsR9+TNmzkDu/rP25I7pkjq51x3jWgNZcyTdGDvGLI0S
         snFuMznaq0xylShiWRpMTbMm2Oa8wMZvVHQp/Ga1FEgXFtLJa98dBXxreJfwLzvXjzKd
         VgPjeyO08EkHrWwXIZv72a+nvoPM8Mjxz0CHZPC6IzTpdzp5PgoO7rEFhGxqPTlLKxvp
         thRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=OiKPFAsz;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:dkim-filter:from:to:cc:subject:date:message-id
         :in-reply-to:cms-type:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zPKLQcRm66zAv6ZdtxcB1i8a5Ip7bJyla2I75dMn0Ms=;
        b=dv6joVdN9ckZsUdPEdmx+Txbc3T8iIoCGE+GW6MH3QFfcIPkzCR/9CEuG6SKrRG+JM
         EPZkoH5j1D6eeRq0R5t4Rq/M55LZ6pzGIz1lUgUI61YtDvMtmmbFbDCmKcPB5s5hPfp0
         mthNHanAnPz3wl6RMSxJftvpr7fnUpzEowdJ6miqz0JPVW7dS85BcLdiFiYCgjtzS6As
         zyZvsrVdZN7lC9x3wqaXlIcnpIBpyT4HK7dbBX+GXj+7+SJnFY5X4jf4tHZ+5MDyjrFy
         /OzMQ/kGOw1ybzDXOiJkTKBtqxTP0BZvRczMyRaPYXVIqm3f+48Fs/jJenN7DF2pukUK
         cjoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:dkim-filter:from:to:cc
         :subject:date:message-id:in-reply-to:cms-type:references
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zPKLQcRm66zAv6ZdtxcB1i8a5Ip7bJyla2I75dMn0Ms=;
        b=EZ9rIuzvLADaGw0girAlU6YDSYpAT2F/g4Xu30qHENc0RwbyHZoz9mAYLRYBMeFuU2
         zxK5QhvsCe64FkLuoU5oXG3/1/3osXCRYofBoKbiFE5erc2wMHT0Omgi+aCF6WFDz7td
         vNzTTfY8eAcsK9PZza5n4Lr6lmUWAnvE2D9IiIhurTg6sYMBT9EPPPrHzJRIs2fLuP7N
         2fFI5QkE8xMI4P3zvN5kbHoJeWYluX4zkZFzoj0JagCc+Gn/ymWKO/lTLdCmKbsHhsva
         JvYeKcW/iBc72NGRa/AbSbcGViKddFot4b85l946t3/bdO7TSac/3oI7QSaOSyTatZgJ
         FzpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PiDaMUIthUrXAoCXFmCEpScgDBVvYDH8bsaj6h+pE8f5LhWsk
	NdXoVPxNbEMZ8KDuiQteG7E=
X-Google-Smtp-Source: ABdhPJyHMPYA/MQVWnrEXPEI9m+kB4NSoGUDFU8dxUc+wINKqQ5ksrqJM8Ur4J1SRB0fBFWq3Igdfw==
X-Received: by 2002:ab0:2553:: with SMTP id l19mr1515027uan.115.1619083064481;
        Thu, 22 Apr 2021 02:17:44 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:94c6:: with SMTP id w189ls380716vkd.0.gmail; Thu, 22 Apr
 2021 02:17:43 -0700 (PDT)
X-Received: by 2002:a1f:e582:: with SMTP id c124mr1707026vkh.17.1619083063751;
        Thu, 22 Apr 2021 02:17:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619083063; cv=none;
        d=google.com; s=arc-20160816;
        b=jUECYvOah6/iONf749PaNb2etONGL0paBZ4Gri5gcEcSagt5F/1DdjnZuh6Br4E3+m
         ivCvA7Jijh/eroF27p4xSJ1wtbrjnTHFBCmqRdZaAxvtScQEnhPJMieogLgg4CrunJxk
         R1wOkcWgNonwoduzDXNInx0dotDn3eGo1ijgOQSCCIz22JOu/1fkJUGY3BeAyQ9L98BW
         ZKSNswJiwyQuz9aQyquNg/plK0ez/7W8LKdSwB1r9xqJTlKxPtMr/vImR66jfKbytCfL
         y18Mk6yg5tLGvnNqTOSop1aID57ie2iPv5PvGGVJXn1dLc1q8N27UOZkS5PlVUdfUmdl
         wSVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature:dkim-filter;
        bh=s8BzLYTEBLEtM9RzCngxE570DlL/ObsHxL1Wk681VL4=;
        b=ewxBTY9MSbVPt/aNFmgcGEkhrBen6pKXFhPeC5G+1Ky6BeJeBWEEaDgRBcTKcV5lJe
         smoz0e8BbFImtLfCAlcaQ1On89esPqayGIcMI1FwpnphPix1vioQ0MV0cBmgt4bqznRg
         LYTnuH7cFITsP3N7o4Nn4tclOXNRQhMxXBLySdSiELgbNFS9RTM94sz1rG2I2IXzftTG
         pCWb4Mj2VJ6F4RSto2v1kwxdZnhgdOK3SOctm+qI0JlK6Ujpj7Zo0aRb6BB6iFPneBcV
         i7dIckMbFrWHUnQvEgzEDh2IP1p/Y6sWe2o/l0P+lsymxGF8DZOHq36Bs+aCdF/b497C
         n5bA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=OiKPFAsz;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.samsung.com (mailout2.samsung.com. [203.254.224.25])
        by gmr-mx.google.com with ESMTPS id 27si575502vke.1.2021.04.22.02.17.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Apr 2021 02:17:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) client-ip=203.254.224.25;
Received: from epcas5p3.samsung.com (unknown [182.195.41.41])
	by mailout2.samsung.com (KnoxPortal) with ESMTP id 20210422091740epoutp02b849128e85989397ea18ac6321bf4277~4I3coPw8F2363023630epoutp027
	for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 09:17:40 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.samsung.com 20210422091740epoutp02b849128e85989397ea18ac6321bf4277~4I3coPw8F2363023630epoutp027
Received: from epsmges5p1new.samsung.com (unknown [182.195.42.73]) by
	epcas5p1.samsung.com (KnoxPortal) with ESMTP id
	20210422091740epcas5p1482b5330ee07fadf943d138831afca1e~4I3cSx1TH2734027340epcas5p15;
	Thu, 22 Apr 2021 09:17:40 +0000 (GMT)
Received: from epcas5p1.samsung.com ( [182.195.41.39]) by
	epsmges5p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	E5.48.09606.43F31806; Thu, 22 Apr 2021 18:17:40 +0900 (KST)
Received: from epsmtrp1.samsung.com (unknown [182.195.40.13]) by
	epcas5p4.samsung.com (KnoxPortal) with ESMTPA id
	20210422081536epcas5p417c144cce0235933a1cd0f29ad55470a~4IBQgZAdK2018620186epcas5p4C;
	Thu, 22 Apr 2021 08:15:36 +0000 (GMT)
Received: from epsmgms1p1new.samsung.com (unknown [182.195.42.41]) by
	epsmtrp1.samsung.com (KnoxPortal) with ESMTP id
	20210422081536epsmtrp1de0da840d140ad38751af013d8c74abb~4IBQfozrL2414624146epsmtrp1D;
	Thu, 22 Apr 2021 08:15:36 +0000 (GMT)
X-AuditID: b6c32a49-bf1ff70000002586-6b-60813f34a325
Received: from epsmtip2.samsung.com ( [182.195.34.31]) by
	epsmgms1p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	D2.24.08637.8A031806; Thu, 22 Apr 2021 17:15:36 +0900 (KST)
Received: from localhost.localdomain (unknown [107.109.224.44]) by
	epsmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20210422081534epsmtip2758a1bdf3d5c6b1026eef0d24bfcf8fe~4IBOftjZv1502215022epsmtip2Q;
	Thu, 22 Apr 2021 08:15:34 +0000 (GMT)
From: Maninder Singh <maninder1.s@samsung.com>
To: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	akpm@linux-foundation.org, dvyukov@google.com
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, a.sahrawat@samsung.com, Maninder Singh
	<maninder1.s@samsung.com>, Vaneet Narang <v.narang@samsung.com>
Subject: [PATCH 2/2] mm/kasan: proc interface to read KASAN errors at any
 time
Date: Thu, 22 Apr 2021 13:45:17 +0530
Message-Id: <1619079317-1131-2-git-send-email-maninder1.s@samsung.com>
X-Mailer: git-send-email 2.7.4
In-Reply-To: <1619079317-1131-1-git-send-email-maninder1.s@samsung.com>
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFmpjleLIzCtJLcpLzFFi42LZdlhTXdfEvjHBoP8oj8XF3akWc9avYbP4
	PnE6u8WEh23sFu0f9zJbrHh2n8ni8q45bBb31vxntTg8v43F4vjWLcwWh07OZXTg9tg56y67
	x4JNpR57Jp5k89j0aRK7x4kZv1k8+rasYvT4vEkugD2KyyYlNSezLLVI3y6BK6PnzQLmgrmH
	GSv2fjzH2sC4ex5jFyMnh4SAicSTmWtYuhi5OIQEdjNKrP7+kRHC+cQocXDTRHYI5xujxILz
	R5hhWmb9WsIKkdjLKPFr1Sqoli+MElcaephAqtgE9CRW7drDAmKLCJRIHOjbAraEWWAP0Nwz
	t8ASwgIBEk8PfgQay8HBIqAqsWeyG0iYV8BN4uL2N6wQ2+Qkbp7rBNvMKeAOVH6PGWSOhMBX
	dom+KdPZIIpcJJY3tkF9JCzx6vgWdghbSuJlfxs7REM3o8TMOZehulczSmx6cR1qhb3E6+YG
	JpArmAU0Jdbv0ocIy0pMPbUO7BtmAT6J3t9PmCDivBI75sHYqhItNzdAjZGW+PzxIwuE7SGx
	8PhraLDOYpQ4sW4GywRGuVkIKxYwMq5ilEwtKM5NTy02LTDMSy3XK07MLS7NS9dLzs/dxAhO
	KlqeOxjvPvigd4iRiYPxEKMEB7OSCO/a4oYEId6UxMqq1KL8+KLSnNTiQ4zSHCxK4ryCztUJ
	QgLpiSWp2ampBalFMFkmDk6pBiYr8en3Hfgy93Zzh9y+uif62E6uxjXnVv+KiVD/GGZ3LPTN
	q8p3Wov41Wf/MFTVEZXqYS+1f1Ky4PUx57+SfvdO8Jp+mMqWcOPNrevPd0mrtn30yczYvqwj
	TXCxh22C90x/s//LHpXyyCpeW8j0L3Ju/PeFF4I6BJiPprdM+yD5T/gbX1KH34ZkpluGFXeV
	GXnjt/xw2LFYQ1qtZ3PaawuBmuVaVokhkbeuzLnXyrRyssK30+aRM6ICBSf2f246EF2UYPNX
	mLn922PxXCWNFdd8eK4xV/Owrrzk4LpVYVlcTZ85v9atSr+Jlr45sdvuF01oP5B9eeeyRIMv
	1TzT10XGLl2Y9cV9le/mnrjpWkosxRmJhlrMRcWJAGugXv2ZAwAA
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFtrCLMWRmVeSWpSXmKPExsWy7bCSvO4Kg8YEg4WzNS0u7k61mLN+DZvF
	94nT2S0mPGxjt2j/uJfZYsWz+0wWl3fNYbO4t+Y/q8Xh+W0sFse3bmG2OHRyLqMDt8fOWXfZ
	PRZsKvXYM/Ekm8emT5PYPU7M+M3i0bdlFaPH501yAexRXDYpqTmZZalF+nYJXBk9bxYwF8w9
	zFix9+M51gbG3fMYuxg5OSQETCRm/VrC2sXIxSEksJtRYsa+6VAJaYmf/96zQNjCEiv/PWeH
	KPrEKDHh2GE2kASbgJ7Eql17wIpEBKokpv/aARZnFjjEKNG7QxjEFhbwk2i6+QiomYODRUBV
	Ys9kN5Awr4CbxMXtb1gh5stJ3DzXyQxicwq4Szw9eA/MFgKqOXphB8sERr4FjAyrGCVTC4pz
	03OLDQsM81LL9YoTc4tL89L1kvNzNzGCA1ZLcwfj9lUf9A4xMnEwAp3Awawkwru2uCFBiDcl
	sbIqtSg/vqg0J7X4EKM0B4uSOO+FrpPxQgLpiSWp2ampBalFMFkmDk6pBqZNjTF/Jm4yv1Ay
	08X638vSD1rfbDPOa2QmPfvn+2LBRpvlTxMTj87i2j7tuaqIQXNJ3MrXlak2V9mf1ex8riLP
	Ome/vafq2XCXOU98G10W5HSw9oque1qptv1X+YvbUd/DpjlVOv6r379fzparrOw8l2vK5kfq
	eYnfTKbbmb3sXjzTp/XPnaV2kSJrtpRPvbTuSZViZfTP+0L9CzYsflcffvOref+ZaWaP4tVE
	zOa2n8vy83h9dILOYemFCkdel4ndNGK18jYtcFij9F/2W83639c9upOmdIu0PMu7f8eKaWe3
	RJWb7+nYSRsva2xfmNDaoflX8btGNMMZSyvXoweuftym7ZPTLxO/TuFHYLwSS3FGoqEWc1Fx
	IgCalBLcxwIAAA==
X-CMS-MailID: 20210422081536epcas5p417c144cce0235933a1cd0f29ad55470a
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-Sendblock-Type: REQ_APPROVE
CMS-TYPE: 105P
X-CMS-RootMailID: 20210422081536epcas5p417c144cce0235933a1cd0f29ad55470a
References: <1619079317-1131-1-git-send-email-maninder1.s@samsung.com>
	<CGME20210422081536epcas5p417c144cce0235933a1cd0f29ad55470a@epcas5p4.samsung.com>
X-Original-Sender: maninder1.s@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=OiKPFAsz;       spf=pass
 (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as
 permitted sender) smtp.mailfrom=maninder1.s@samsung.com;       dmarc=pass
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

store minimal information required to regenerate KASAN logs
from reading of proc interface.

kernel buffer is allocated for 4K bytes to avoid multiple
checks of sanity for snprintf returns, and it will be checked
before copying that data to user space if user buffer has that
much capacity or not.

During long time aging test of targets, it is diffucult to check for
KASAN reported issues. Thus it will be better it proc interface is
present to check for Unique KASAN errors reported till time.

sample output and verification for ARM64:
Run sample TC's of KASAN:

[   25.450749] kasan test: kmalloc_oob_right out-of-bounds to right
[   25.452851] ==================================================================
[   25.453779] BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0x80/0xa4
[   25.454800] Write of size 1 at addr ffff0000c3f1c27b by task cat/125
[   25.455891]
....
[   25.488283] kasan test: kmalloc_oob_left out-of-bounds to left
[   25.488819] ==================================================================
[   25.489189] BUG: KASAN: slab-out-of-bounds in kmalloc_oob_left+0x80/0xac
[   25.489601] Read of size 1 at addr ffff0000c3f1c2ff by task cat/125
...

After first reporting, NO KASAN reports for same issues:

[  115.078095] kasan test: kmalloc_oob_right out-of-bounds to right
[  115.078773] kasan test: kmalloc_oob_left out-of-bounds to left
[  115.079237] kasan test: kmalloc_node_oob_right kmalloc_node(): out-of-bounds to right
[  115.080056] kasan test: kmalloc_pagealloc_oob_right kmalloc pagealloc allocation: out-of-bounds to right
[  115.080683] kasan test: kmalloc_pagealloc_uaf kmalloc pagealloc allocation: use-after-free
[  115.081209] kasan test: kmalloc_pagealloc_invalid_free kmalloc pagealloc allocation: invalid-free

Check same from /proc/kasan_log:
KASAN Issue no. 1
==================================================================

BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0x80/0xa4 at addr ffff0000c3f1c27b
Write of size 1 by task cat/125
...
...
Memory state around the buggy address:
 ffff0000c3f1c100: 00 00 00 00 fc fc fc fc fc fc fc fc fc fc fc fc
 ffff0000c3f1c180: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>ffff0000c3f1c200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03
                                                                ^
 ffff0000c3f1c280: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffff0000c3f1c300: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
==================================================================
KASAN Issue no. 2
==================================================================

BUG: KASAN: slab-out-of-bounds in kmalloc_oob_left+0x80/0xac at addr ffff0000c3f1c2ff
Read of size 1 by task cat/125
...
...
Memory state around the buggy address:
 ffff0000c3f1c180: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffff0000c3f1c200: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
>ffff0000c3f1c280: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
                                                                ^
 ffff0000c3f1c300: 00 07 fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffff0000c3f1c380: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
==================================================================
KASAN Issue no. 3
==================================================================
...
...

Co-developed-by: Vaneet Narang <v.narang@samsung.com>
Signed-off-by: Vaneet Narang <v.narang@samsung.com>
Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
---
 mm/kasan/kasan.h          |  32 +++-
 mm/kasan/report.c         | 377 ++++++++++++++++++++++++++++++++++----
 mm/kasan/report_generic.c |  42 ++++-
 mm/kasan/report_hw_tags.c |   5 +-
 mm/kasan/report_sw_tags.c |  30 ++-
 5 files changed, 431 insertions(+), 55 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d14ccce246ba..2c2c79551cbd 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -94,6 +94,25 @@ extern bool kasan_flag_panic __ro_after_init;
 #define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
 #define META_ROWS_AROUND_ADDR 2
 
+#define SHADOW_ROWS	(2 * META_ROWS_AROUND_ADDR + 1)
+#define CACHE_NAME_LEN	(20)
+
+typedef enum {
+	UNKNOWN,
+	OUT_OF_BOUNDS,
+	OUT_OF_BOUNDS_SLAB,
+	OUT_OF_BOUNDS_GLOBAL,
+	OUT_OF_BOUNDS_STACK,
+	USE_AFTER_FREE,
+	OUT_OF_BOUNDS_ALLOCA,
+	OUT_OF_BOUNDS_VMALLOC,
+	INVALID_ACCESS,
+	NULL_PTR_DEREFER,
+	USER_MEMORY_ACCESS,
+	WILD_MEMORY_ACCESS,
+	DOUBLE_INVALID_FREE
+} kasan_bug_type;
+
 struct kasan_access_info {
 	const void *access_addr;
 	const void *first_bad_addr;
@@ -106,6 +125,17 @@ struct kasan_record {
 	depot_stack_handle_t	bt_handle;
 	depot_stack_handle_t	alloc_handle;
 	depot_stack_handle_t	free_handle;
+	const void		*access_addr;
+	const void		*first_bad_addr;
+	unsigned long		ip;
+	size_t			access_size;
+	char			comm[TASK_COMM_LEN];
+	char			cache_name[CACHE_NAME_LEN];
+	int			cache_size;
+	pid_t			pid;
+	kasan_bug_type		bug_type;
+	u8			buf[SHADOW_ROWS][META_BYTES_PER_ROW];
+	bool			is_write;
 };
 
 /* The layout of struct dictated by compiler */
@@ -234,7 +264,7 @@ static inline void kasan_print_tags(u8 addr_tag, const void *addr) { }
 #endif
 
 void *kasan_find_first_bad_addr(void *addr, size_t size);
-const char *kasan_get_bug_type(struct kasan_access_info *info);
+const char *kasan_get_bug_type(struct kasan_access_info *info, kasan_bug_type *bug);
 void kasan_metadata_fetch_row(char *buffer, void *row);
 
 #if defined(CONFIG_KASAN_GENERIC) && defined(CONFIG_KASAN_STACK)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 4576de76991b..b0cc95fedc29 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -15,6 +15,7 @@
 #include <linux/kernel.h>
 #include <linux/mm.h>
 #include <linux/printk.h>
+#include <linux/proc_fs.h>
 #include <linux/sched.h>
 #include <linux/slab.h>
 #include <linux/stackdepot.h>
@@ -66,7 +67,7 @@ __setup("kasan_multi_shot", kasan_set_multi_shot);
 static void print_error_description(struct kasan_access_info *info)
 {
 	pr_err("BUG: KASAN: %s in %pS\n",
-		kasan_get_bug_type(info), (void *)info->ip);
+		kasan_get_bug_type(info, NULL), (void *)info->ip);
 	if (info->access_size)
 		pr_err("%s of size %zu at addr %px by task %s/%d\n",
 			info->is_write ? "Write" : "Read", info->access_size,
@@ -342,26 +343,50 @@ static void kasan_update_kunit_status(struct kunit *cur_test)
 }
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
 
-void kasan_report_invalid_free(void *object, unsigned long ip)
+static void copy_error_description(struct kasan_access_info *info,
+			struct kasan_record *record)
 {
-	unsigned long flags;
-	u8 tag = get_tag(object);
+	record->ip = info->ip;
+	record->first_bad_addr = info->first_bad_addr;
+	record->access_addr = info->access_addr;
+	record->is_write = info->is_write;
+	record->access_size = info->access_size;
+	record->pid = task_pid_nr(current);
+	strncpy(record->comm, current->comm, TASK_COMM_LEN);
+}
 
-	object = kasan_reset_tag(object);
+static void copy_shadow_for_address(struct kasan_record *record)
+{
+	int i;
+	void *addr = (void *)record->first_bad_addr;
+	void *row = (void *)round_down((unsigned long)addr, META_MEM_BYTES_PER_ROW)
+			- META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
 
-#if IS_ENABLED(CONFIG_KUNIT)
-	if (current->kunit_test)
-		kasan_update_kunit_status(current->kunit_test);
-#endif /* IS_ENABLED(CONFIG_KUNIT) */
 
-	start_report(&flags);
-	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
-	kasan_print_tags(tag, object);
-	pr_err("\n");
-	print_address_description(object, tag);
-	pr_err("\n");
-	print_memory_metadata(object);
-	end_report(&flags, (unsigned long)object);
+	for (i = 0; i < SHADOW_ROWS; i++) {
+		kasan_metadata_fetch_row((char *)&record->buf[i], row);
+		row += META_MEM_BYTES_PER_ROW;
+	}
+}
+
+static bool match_handles(struct kasan_record *record)
+{
+	int i = 0;
+
+	for (i = 0; i < stored_kasan_records; i++) {
+		if (record->bt_handle != kasan_records[i].bt_handle)
+			continue;
+		if (record->alloc_handle != kasan_records[i].alloc_handle)
+			continue;
+		if ((record->bug_type == USE_AFTER_FREE ||
+			record->bug_type == DOUBLE_INVALID_FREE) &&
+			(record->free_handle != kasan_records[i].free_handle))
+			continue;
+
+		return true;
+	}
+
+	return false;
 }
 
 /*
@@ -370,21 +395,26 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
  * returns false if same record is already saved.
  * returns true if its new record and saved in database of KASAN.
  */
-static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsigned long *flags)
+static bool save_report(void *addr, struct kasan_access_info *info, u8 tag,
+				unsigned long *flags, kasan_bug_type *bug)
 {
 	struct kasan_record record = {0};
 	depot_stack_handle_t bt_handle;
-	int i = 0;
-	const char *bug_type;
 	struct kasan_alloc_meta *alloc_meta;
 	struct kasan_track *free_track;
 	struct page *page;
+	kasan_bug_type bug_enum = UNKNOWN;
 	bool ret = true;
 
 	kasan_disable_current();
 	spin_lock_irqsave(&report_lock, *flags);
 
-	bug_type = kasan_get_bug_type(info);
+	if (!bug) {
+		kasan_get_bug_type(info, &bug_enum);
+		record.bug_type = bug_enum;
+	} else
+		record.bug_type = *bug;
+
 	page = kasan_addr_to_page(addr);
 	bt_handle = kasan_save_stack(GFP_KERNEL);
 
@@ -397,23 +427,27 @@ static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsi
 		record.alloc_handle = alloc_meta->alloc_track.stack;
 		if (free_track)
 			record.free_handle = free_track->stack;
+
+		strncpy(record.cache_name, cache->name, CACHE_NAME_LEN - 1);
+		record.cache_name[CACHE_NAME_LEN - 1] = '\0';
+		record.cache_size = cache->object_size;
 	}
 
 	record.bt_handle = bt_handle;
 
-	for (i = 0; i < stored_kasan_records; i++) {
-		if (record.bt_handle != kasan_records[i].bt_handle)
-			continue;
-		if (record.alloc_handle != kasan_records[i].alloc_handle)
-			continue;
-		if (!strncmp("use-after-free", bug_type, 15) &&
-			(record.free_handle != kasan_records[i].free_handle))
-			continue;
+	if (match_handles(&record)) {
+		ret = false;
+		goto done;
+	}
 
+	if (stored_kasan_records >= MAX_RECORDS) {
+		WARN_ONCE(1, "KASAN database reached capacity");
 		ret = false;
 		goto done;
 	}
 
+	copy_error_description(info, &record);
+	copy_shadow_for_address(&record);
 	memcpy(&kasan_records[stored_kasan_records], &record, sizeof(struct kasan_record));
 	stored_kasan_records++;
 
@@ -423,6 +457,38 @@ static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsi
 	return ret;
 }
 
+void kasan_report_invalid_free(void *object, unsigned long ip)
+{
+	unsigned long flags;
+	u8 tag = get_tag(object);
+	struct kasan_access_info info;
+	kasan_bug_type bug_enum = DOUBLE_INVALID_FREE;
+
+	object = kasan_reset_tag(object);
+
+#if IS_ENABLED(CONFIG_KUNIT)
+	if (current->kunit_test)
+		kasan_update_kunit_status(current->kunit_test);
+#endif /* IS_ENABLED(CONFIG_KUNIT) */
+
+	info.ip = ip;
+	info.first_bad_addr = object;
+	info.access_addr = 0;
+	info.is_write = 0;
+	info.access_size = 0;
+	if (!save_report(object, &info, tag, &flags, &bug_enum))
+		return;
+
+	start_report(&flags);
+	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
+	kasan_print_tags(tag, object);
+	pr_err("\n");
+	print_address_description(object, tag);
+	pr_err("\n");
+	print_memory_metadata(object);
+	end_report(&flags, (unsigned long)object);
+}
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
@@ -442,18 +508,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = kasan_reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_metadata(untagged_addr))
-		info.first_bad_addr =
-			kasan_find_first_bad_addr(tagged_addr, size);
-	else
-		info.first_bad_addr = untagged_addr;
 	info.access_size = size;
 	info.is_write = is_write;
 	info.ip = ip;
 
-	if (addr_has_metadata(untagged_addr) &&
-		!save_report(untagged_addr, &info, get_tag(tagged_addr), &flags))
-		return;
+	if (addr_has_metadata(untagged_addr)) {
+		info.first_bad_addr = kasan_find_first_bad_addr(tagged_addr, size);
+
+		if (!save_report(untagged_addr, &info, get_tag(tagged_addr), &flags, NULL))
+			return;
+	} else
+		info.first_bad_addr = untagged_addr;
 
 	start_report(&flags);
 
@@ -528,3 +593,241 @@ void kasan_non_canonical_hook(unsigned long addr)
 		 orig_addr, orig_addr + KASAN_GRANULE_SIZE - 1);
 }
 #endif
+
+#define READ_SIZE	(4096)
+static ssize_t print_kasan_error(char __user *buf, size_t count,
+		struct kasan_record *record, loff_t *ppos, char *kbuf)
+{
+	int ret = 0;
+	unsigned long *entries;
+	unsigned long nr_entries;
+	const char *bug_type = "unknown-crash";
+	int i, j;
+	void *row;
+	void *addr = (void *)record->first_bad_addr;
+
+	if (!kbuf)
+		return -ENOMEM;
+
+	switch (record->bug_type) {
+	case OUT_OF_BOUNDS:
+		bug_type = "out-of-bounds";
+		break;
+	case OUT_OF_BOUNDS_SLAB:
+		bug_type = "slab-out-of-bounds";
+		break;
+	case OUT_OF_BOUNDS_GLOBAL:
+		bug_type = "global-out-of-bounds";
+		break;
+	case OUT_OF_BOUNDS_STACK:
+		bug_type = "stack-out-of-bounds";
+		break;
+	case USE_AFTER_FREE:
+		bug_type = "use-after-free";
+		break;
+	case OUT_OF_BOUNDS_ALLOCA:
+		bug_type = "alloca-out-of-bounds";
+		break;
+	case OUT_OF_BOUNDS_VMALLOC:
+		bug_type = "alloca-out-of-vmalloc";
+		break;
+	case INVALID_ACCESS:
+		bug_type = "invalid-access";
+		break;
+	case NULL_PTR_DEREFER:
+		bug_type = "null-ptr-deref";
+		break;
+	case USER_MEMORY_ACCESS:
+		bug_type = "user-memory-access";
+		break;
+	case WILD_MEMORY_ACCESS:
+		bug_type = "wild-memory-access";
+		break;
+	case DOUBLE_INVALID_FREE:
+		bug_type = "double-free or invalid-free";
+		break;
+	default:
+		break;
+	}
+
+	ret += snprintf(kbuf + ret, count - ret,
+				"KASAN Issue no. %lld\n", *ppos);
+	ret += snprintf(kbuf + ret, count - ret,
+			"==============================="
+			"===================================\n");
+
+	if (record->bug_type != DOUBLE_INVALID_FREE) {
+		ret += snprintf(kbuf + ret, count - ret,
+				"\nBUG: KASAN: %s in %pS at addr %px\n",
+				bug_type, (void *)record->ip, record->access_addr);
+		ret += snprintf(kbuf + ret, count - ret,
+				"%s of size %zu by task %s/%d\n",
+				record->is_write ? "Write" : "Read",
+				record->access_size, record->comm, record->pid);
+	} else {
+		ret += snprintf(kbuf + ret, count - ret,
+			"\nBUG: KASAN: %s in %pS\n",
+			bug_type, (void *)record->ip);
+	}
+
+	ret += snprintf(kbuf + ret, count - ret, "\nBacktrace:\n");
+	nr_entries = stack_depot_fetch(record->bt_handle, &entries);
+
+	ret += stack_trace_snprint(kbuf + ret, count - ret, entries, nr_entries, 0);
+
+	if (record->alloc_handle) {
+		ret += snprintf(kbuf + ret, count - ret,
+				"\nBelongs to the cache %s of size: %d\n",
+				record->cache_name, record->cache_size);
+		ret += snprintf(kbuf + ret, count - ret,
+				"------------------------------------------"
+				"-----------------------------------\n");
+
+		nr_entries = stack_depot_fetch(record->alloc_handle, &entries);
+		ret += snprintf(kbuf + ret, count - ret, "INFO Allocation path:\n");
+
+		ret += stack_trace_snprint(kbuf + ret, count - ret, entries, nr_entries, 0);
+
+		if (record->free_handle) {
+			ret += snprintf(kbuf + ret, count - ret, "\nINFO Free path:\n");
+
+			nr_entries = stack_depot_fetch(record->free_handle, &entries);
+			ret += stack_trace_snprint(kbuf + ret, count - ret, entries, nr_entries, 0);
+		}
+	}
+
+	if (kernel_or_module_addr(addr)) {
+		if (!init_task_stack_addr(addr))
+			ret += snprintf(kbuf + ret, count - ret,
+				"The buggy address belongs to the variable %pS\n",
+				(void *)record->access_addr);
+	}
+
+	ret += snprintf(kbuf + ret, count - ret,
+				"Memory state around the buggy address:\n");
+
+	row = (void *)round_down((unsigned long)addr, META_MEM_BYTES_PER_ROW)
+			- META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
+
+	for (i = 0; i < SHADOW_ROWS; i++) {
+		if (i)
+			ret += snprintf(kbuf + ret, count - ret, "\n");
+
+		ret += snprintf(kbuf + ret, count - ret,
+		(i == 2) ? ">%px: " : " %px: ", row);
+
+		for (j = 0; j < META_BYTES_PER_ROW; j++) {
+			u8 value = record->buf[i][j];
+				ret += snprintf(kbuf + ret, count - ret, "%02x ", value);
+		}
+
+		if (meta_row_is_guilty(row, addr))
+			ret += snprintf(kbuf + ret, count - ret, "\n%*c",
+				meta_pointer_offset(row, addr),
+				'^');
+
+		row += META_MEM_BYTES_PER_ROW;
+	}
+
+	ret += snprintf(kbuf + ret, count - ret,
+			"\n==============================="
+			"===================================\n");
+
+	/*
+	 * checking for space in buffer only when copying to user,
+	 * otherwise if overflow'ed in kernel buffer, it will
+	 * lead to kernel crash and then size of vmalloc'ed
+	 * memory can be increased.
+	 *
+	 * Benefit: checks on each snprintf avoided.
+	 */
+	if (ret >= count) {
+		ret = -ENOMEM;
+		goto err;
+	}
+
+	if (copy_to_user(buf, kbuf, ret))
+		ret = -EFAULT;
+
+err:
+	return ret;
+}
+
+/*
+ * read_kasan_errors()
+ *
+ * function to print all the entries present
+ * in KASAN depot_stack database currently in system.
+ */
+static ssize_t read_kasan_errors(struct file *file, char __user *buf,
+		size_t count, loff_t *ppos)
+{
+	/*
+	 * No need of lock here for reading stored_kasan_records,
+	 * As it is an integer variable, we can read it one value less
+	 * if it is getting updated simultaneously.
+	 */
+	int total_records = stored_kasan_records;
+	char *kbuf = (char *)file->private_data;
+
+	while (*ppos < total_records) {
+		struct kasan_record *record;
+
+		record  = &kasan_records[*ppos];
+		*ppos = *ppos + 1;
+		return print_kasan_error(buf, count, record, ppos, kbuf);
+	}
+
+	return 0;
+}
+
+int read_kasan_open(struct inode *inode, struct file *file)
+{
+	char *kasan_kbuf;
+
+	/*
+	 * One KASAN error will always be less than 4 KB,
+	 * without page dump info.
+	 *
+	 * Thus allocate buffer of READ_SIZE, rather than
+	 * count to avoid return checks of snprintfs.
+	 */
+	kasan_kbuf = vzalloc(READ_SIZE);
+
+	if (!kasan_kbuf)
+		return -ENOMEM;
+
+	file->private_data = (void *)kasan_kbuf;
+
+	return 0;
+}
+
+int read_kasan_release(struct inode *inode, struct file *file)
+{
+	char *kasan_kbuf = (char *)file->private_data;
+
+	if (kasan_kbuf)
+		vfree(kasan_kbuf);
+
+	return 0;
+}
+
+static const struct proc_ops proc_kasan_ops = {
+	.proc_open		= read_kasan_open,
+	.proc_read		= read_kasan_errors,
+	.proc_release		= read_kasan_release,
+};
+
+static int __init register_kasan_proc(void)
+{
+	struct proc_dir_entry *entry;
+
+	entry = proc_create("kasan_log", 0400,
+			NULL, &proc_kasan_ops);
+
+	if (!entry)
+		pr_err("registration of KASAN proc interface failed\n");
+
+	return 0;
+}
+fs_initcall(register_kasan_proc);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index 139615ef326b..0206d5f9b486 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -39,10 +39,12 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
 	return p;
 }
 
-static const char *get_shadow_bug_type(struct kasan_access_info *info)
+static const char *get_shadow_bug_type(struct kasan_access_info *info,
+		kasan_bug_type *bug_save)
 {
 	const char *bug_type = "unknown-crash";
 	u8 *shadow_addr;
+	kasan_bug_type bug = UNKNOWN;
 
 	shadow_addr = (u8 *)kasan_mem_to_shadow(info->first_bad_addr);
 
@@ -60,52 +62,70 @@ static const char *get_shadow_bug_type(struct kasan_access_info *info)
 		 * due to a data race in the kernel code.
 		 */
 		bug_type = "out-of-bounds";
+		bug = OUT_OF_BOUNDS;
 		break;
 	case KASAN_PAGE_REDZONE:
 	case KASAN_KMALLOC_REDZONE:
 		bug_type = "slab-out-of-bounds";
+		bug = OUT_OF_BOUNDS_SLAB;
 		break;
 	case KASAN_GLOBAL_REDZONE:
 		bug_type = "global-out-of-bounds";
+		bug = OUT_OF_BOUNDS_GLOBAL;
 		break;
 	case KASAN_STACK_LEFT:
 	case KASAN_STACK_MID:
 	case KASAN_STACK_RIGHT:
 	case KASAN_STACK_PARTIAL:
 		bug_type = "stack-out-of-bounds";
+		bug = OUT_OF_BOUNDS_STACK;
 		break;
 	case KASAN_FREE_PAGE:
 	case KASAN_KMALLOC_FREE:
 	case KASAN_KMALLOC_FREETRACK:
 		bug_type = "use-after-free";
+		bug = USE_AFTER_FREE;
 		break;
 	case KASAN_ALLOCA_LEFT:
 	case KASAN_ALLOCA_RIGHT:
 		bug_type = "alloca-out-of-bounds";
+		bug = OUT_OF_BOUNDS_ALLOCA;
 		break;
 	case KASAN_VMALLOC_INVALID:
 		bug_type = "vmalloc-out-of-bounds";
+		bug = OUT_OF_BOUNDS_VMALLOC;
 		break;
 	}
 
+	if (bug_save)
+		*bug_save = bug;
+
 	return bug_type;
 }
 
-static const char *get_wild_bug_type(struct kasan_access_info *info)
+static const char *get_wild_bug_type(struct kasan_access_info *info, kasan_bug_type *bug)
 {
 	const char *bug_type = "unknown-crash";
+	kasan_bug_type bug_enum = UNKNOWN;
 
-	if ((unsigned long)info->access_addr < PAGE_SIZE)
+	if ((unsigned long)info->access_addr < PAGE_SIZE) {
 		bug_type = "null-ptr-deref";
-	else if ((unsigned long)info->access_addr < TASK_SIZE)
+		bug_enum = NULL_PTR_DEREFER;
+	} else if ((unsigned long)info->access_addr < TASK_SIZE) {
 		bug_type = "user-memory-access";
-	else
+		bug_enum = USER_MEMORY_ACCESS;
+	} else {
 		bug_type = "wild-memory-access";
+		bug_enum = WILD_MEMORY_ACCESS;
+	}
+
+	if (bug)
+		*bug = bug_enum;
 
 	return bug_type;
 }
 
-const char *kasan_get_bug_type(struct kasan_access_info *info)
+const char *kasan_get_bug_type(struct kasan_access_info *info, kasan_bug_type *bug)
 {
 	/*
 	 * If access_size is a negative number, then it has reason to be
@@ -115,12 +135,16 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
 	 * a large size_t and its value will be larger than ULONG_MAX/2,
 	 * so that this can qualify as out-of-bounds.
 	 */
-	if (info->access_addr + info->access_size < info->access_addr)
+	if (info->access_addr + info->access_size < info->access_addr) {
+		if (bug)
+			*bug = OUT_OF_BOUNDS;
+
 		return "out-of-bounds";
+	}
 
 	if (addr_has_metadata(info->access_addr))
-		return get_shadow_bug_type(info);
-	return get_wild_bug_type(info);
+		return get_shadow_bug_type(info, bug);
+	return get_wild_bug_type(info, bug);
 }
 
 void kasan_metadata_fetch_row(char *buffer, void *row)
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
index 42b2168755d6..ae516e92f9f3 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -15,8 +15,11 @@
 
 #include "kasan.h"
 
-const char *kasan_get_bug_type(struct kasan_access_info *info)
+const char *kasan_get_bug_type(struct kasan_access_info *info, kasan_bug_type *bug)
 {
+	if (bug)
+		*bug = INVALID_ACCESS;
+
 	return "invalid-access";
 }
 
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 3d20d3451d9e..11c869d4ad3c 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -29,8 +29,10 @@
 #include "kasan.h"
 #include "../slab.h"
 
-const char *kasan_get_bug_type(struct kasan_access_info *info)
+const char *kasan_get_bug_type(struct kasan_access_info *info, kasan_bug_type *bug)
 {
+	kasan_bug_type bug_enum;
+	const char *bug_type;
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;
@@ -50,11 +52,16 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
 
 		if (alloc_meta) {
 			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-				if (alloc_meta->free_pointer_tag[i] == tag)
-					return "use-after-free";
+				if (alloc_meta->free_pointer_tag[i] == tag) {
+					bug_type = "use-after-free";
+					bug_enum = USE_AFTER_FREE;
+					goto done;
+				}
 			}
 		}
-		return "out-of-bounds";
+		bug_type = "out-of-bounds";
+		bug_enum = OUT_OF_BOUNDS;
+		goto done;
 	}
 
 #endif
@@ -66,10 +73,19 @@ const char *kasan_get_bug_type(struct kasan_access_info *info)
 	 * a large size_t and its value will be larger than ULONG_MAX/2,
 	 * so that this can qualify as out-of-bounds.
 	 */
-	if (info->access_addr + info->access_size < info->access_addr)
-		return "out-of-bounds";
+	if (info->access_addr + info->access_size < info->access_addr) {
+		bug_enum = OUT_OF_BOUNDS;
+		bug_type = "out-of-bounds";
+		goto done;
+	}
+
+	bug_enum = INVALID_ACCESS;
+	bug_type = "invalid-access";
+done:
+	if (bug)
+		*bug = bug_enum;
 
-	return "invalid-access";
+	return bug_type;
 }
 
 void *kasan_find_first_bad_addr(void *addr, size_t size)
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1619079317-1131-2-git-send-email-maninder1.s%40samsung.com.
