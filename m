Return-Path: <kasan-dev+bncBCG4ZMWKSUNBBCXITSRAMGQEL7VKR3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 61A2A6EDA1A
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Apr 2023 03:59:40 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-6a64a858beasf1699147a34.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 18:59:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682387979; cv=pass;
        d=google.com; s=arc-20160816;
        b=ANwFJ2OlxaYybczBDXtkxW19d44t/bykZdVslXRbD+o431JA444Gf7+DOwKPSr4r+i
         /wIN5iTYyJs3z6ZY2HR6Dko3AE6OtMf8hmmhGy3VpfFIX2u7jgpIHFgzZ1eT6hkI1PjQ
         6r3skDT8N/vl9XUxbUE6nVlEZN1ls4/vHubQr4eyAQTK9/9BsAEMC3aQU/Ctl/kLbCXD
         0TJWCeTAqCf6Ef8gZ3++S1RHl+6VDYE7Q6FGSpzrMUn213EBv8X0kgNlAKi6uZ0Q98cF
         xbpxjRSctcOBhyBfGS2b0/ubXNkC+Kj2utIT8m5BhCdjH+gqy5n9yEZmgJNMT5evDfok
         5NcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:dlp-filter:cms-type
         :in-reply-to:mime-version:message-id:subject:cc:to:from:date
         :dkim-filter:sender:dkim-signature;
        bh=3NFMqaz3WfTybRd/ILWo1JVrsOUYhuXIWj8xjbZV7tM=;
        b=FdDCamDmTCLaLNhodWfIM5x+O8xfUIrTdP9TGIh0qrFBCp+h3+xZelXbnePvY/3F42
         cmAihO4b1ki6RJDcUj5LoFmTuv8/+0f7xa6YzIcrfxYNUem9iLT6x8g3ZY7a+RicV+lw
         MJFm/mjMvglKOx71ok5CWGrWoHoknOl8IwD8fZptj3I4gSSwLD87mpb3Tafs2HGYoEgQ
         xIx1UWU1F2ztEr0wkSlhRaG8juikwrwh/pWlZ5J/8TF0UergcTtFXCVYX9EVFA72NlI2
         kZp5COTw99hLGsbue9NXdOsGZMsC4q2qijcXfZwXcWcckbmm5ZQdywUCwIt+7WuB402k
         PaBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=sqjeDAqP;
       spf=pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682387979; x=1684979979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:dlp-filter:cms-type:in-reply-to
         :mime-version:message-id:subject:cc:to:from:date:dkim-filter:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3NFMqaz3WfTybRd/ILWo1JVrsOUYhuXIWj8xjbZV7tM=;
        b=S545gMEeecFmnCLwqpfeZ5xAekMLyRl8PXEcfck5iuZnlPSysvF2qfOYgpMSJMhAII
         hG7KOr/8TcaXgLw2c+JVDGkVrRUX5oY1JCl6rv6MAP8d+p9W3TXwqrjmqf68+odnf4Wf
         Gr+zsV86+HHia50ka1ubqq/QJAxUGDHmU9BehH60/f3Ca9s/m/w+BaOmbI9LD5Q9g1oL
         spCw6imiVJxwP5YkLfnNXtf7rkIaPdqhdnWrdkBj3DvzeYcdvJSAHsJRD6hcggI1AWEA
         mpbbAUcpgzg97lLkpAOUUkmkO/un5hDSVW90860aBO3mjT6xA63gJjRC7KUyMSFSDytM
         IZZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682387979; x=1684979979;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :dlp-filter:cms-type:in-reply-to:mime-version:message-id:subject:cc
         :to:from:date:dkim-filter:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=3NFMqaz3WfTybRd/ILWo1JVrsOUYhuXIWj8xjbZV7tM=;
        b=L2VzypNSPmyHS4Ent2ajCLLGjkpW6pdD0kgaqUFDutVqOvGTNcQHniurw0cCDS5Ho3
         3PrlE3y6ZdzD3uXBI10/p9AIkBAvX/fPsMcgEuYJ55Z8GUtKXsOqtZPpXSA2rALUVqko
         njjhtIzTvQzZcOGAAMZWj1B9Zadu4yNxgqhRO39jTDrUY2OvDiDSwGkh5T7shWldH3vl
         IkAaVkMGz9GB9trXLAcmxaU1IlVOQz9c17b1fllS8b5S1ow1X7OPcjgfevdEhRhLDBxB
         qnYz0BMSQGs8gPUUTGK6GuyTmgSddGSWO8SeP8DhFewPrBoK+c45K9F1A8sOYX91LVQA
         ApkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dRqc9vCLWVa4MdL1eZTBZKXmUe360/eEkZwfZ44/rVEQpISG8i
	V3kHqF82HoOUEzzLKzd4DlA=
X-Google-Smtp-Source: AKy350aacNgs43TBpVtIegNIes7zy3gTwdyB1aNWNdwTf4a/c3+HWGXaCBrXeY9VI5ataK2ehlg4cw==
X-Received: by 2002:a9d:70c6:0:b0:6a5:f655:29ff with SMTP id w6-20020a9d70c6000000b006a5f65529ffmr4514026otj.0.1682387978814;
        Mon, 24 Apr 2023 18:59:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:671a:b0:6a4:3d60:27b4 with SMTP id
 cr26-20020a056830671a00b006a43d6027b4ls1939659otb.0.-pod-prod-gmail; Mon, 24
 Apr 2023 18:59:38 -0700 (PDT)
X-Received: by 2002:a05:6830:1bda:b0:6a4:1a86:d73f with SMTP id v26-20020a0568301bda00b006a41a86d73fmr8719244ota.12.1682387978290;
        Mon, 24 Apr 2023 18:59:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682387978; cv=none;
        d=google.com; s=arc-20160816;
        b=AX14TXb+wU6zsvoepwVm+JJOUc+VYVceYPmpcmMcGrW5LG+m7lkDhNI/iTTCOe/us1
         TM3g4o3Rc3bz6oDEbBupdC74dBWtXGCJ1TG1vmkjZJEdNqlf5lI676rwJF4WjMdhVyQ/
         1BzXMyy3t6eHTrffbk7yEwUO845omN7uhuMHlfteMb7rNn8VWSfUobL6jfAAgRKF8eit
         ljnmUCsPCY6f+nbvF7TCc2HiOTq5AIX7b0gZYahYus5cL/8950xHomt2lLOZ6FTC5ZHo
         d1drMg52ZVy77L15XENk+Tw+nMQCopHZfyyx7KJ7OXWB8ElrAqMfw4QnOfsq2lFVD3Sq
         mLEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:dlp-filter:cms-type:in-reply-to:mime-version:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-filter;
        bh=/UXNABhQ5WkRsTFRopB0tRc1q6ogB2C4U1PQpM5JTMQ=;
        b=f+KNMErfD6SA0AdTAKRta9L27NoDOI2YKi/iqsiF2tLFGZX86VjuuzYGepSxjrKEzL
         aB1mCFiYMAlE4YVp65OusUQn9U8SeKYWc8MScj5ibg1MSFgiGwLnwnaJhC44ffnDZKU0
         8NgKuMsg1FbWHevFhUQGos4yXtfrq49VYkooKF9yl9TIjTtXZghFXdSrIVXxu8IR42qB
         e89n4kGicdcBkP5IOG1T4tR7VPSHqaLmuRwqos3m918x1pk9waH5NVKcvZ+48mSJgbIp
         7YAWUbqZh1vlM/wbWf3QPEiWywTumF9NvoxNQi4nKIgdaj1hlkPxQ1dQ+9YRO76821ZV
         azeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=sqjeDAqP;
       spf=pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.samsung.com (mailout1.samsung.com. [203.254.224.24])
        by gmr-mx.google.com with ESMTPS id db12-20020a0568306b0c00b006a15693a266si850650otb.3.2023.04.24.18.59.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Apr 2023 18:59:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.24 as permitted sender) client-ip=203.254.224.24;
Received: from epcas2p3.samsung.com (unknown [182.195.41.55])
	by mailout1.samsung.com (KnoxPortal) with ESMTP id 20230425015935epoutp01b7b37924bf2b029fa117ff7417eaac28~ZCvMqFccE0791707917epoutp01D
	for <kasan-dev@googlegroups.com>; Tue, 25 Apr 2023 01:59:35 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.samsung.com 20230425015935epoutp01b7b37924bf2b029fa117ff7417eaac28~ZCvMqFccE0791707917epoutp01D
Received: from epsnrtp2.localdomain (unknown [182.195.42.163]) by
	epcas2p2.samsung.com (KnoxPortal) with ESMTP id
	20230425015934epcas2p21ef48510eab79212dfe7465f00824a27~ZCvMJhmXi1820018200epcas2p2I;
	Tue, 25 Apr 2023 01:59:34 +0000 (GMT)
Received: from epsmges2p3.samsung.com (unknown [182.195.36.97]) by
	epsnrtp2.localdomain (Postfix) with ESMTP id 4Q54tt1Mlnz4x9Q7; Tue, 25 Apr
	2023 01:59:34 +0000 (GMT)
Received: from epcas2p4.samsung.com ( [182.195.41.56]) by
	epsmges2p3.samsung.com (Symantec Messaging Gateway) with SMTP id
	4C.F5.08199.60437446; Tue, 25 Apr 2023 10:59:34 +0900 (KST)
Received: from epsmtrp1.samsung.com (unknown [182.195.40.13]) by
	epcas2p4.samsung.com (KnoxPortal) with ESMTPA id
	20230425015933epcas2p43aafca3e20469849bb467faf3d819216~ZCvK-4niF0927609276epcas2p4x;
	Tue, 25 Apr 2023 01:59:33 +0000 (GMT)
Received: from epsmgms1p2.samsung.com (unknown [182.195.42.42]) by
	epsmtrp1.samsung.com (KnoxPortal) with ESMTP id
	20230425015933epsmtrp16760bfb076263f1cc357cfa4ed00b7a9~ZCvK8s8og1665816658epsmtrp10;
	Tue, 25 Apr 2023 01:59:33 +0000 (GMT)
X-AuditID: b6c32a47-e99fd70000002007-47-6447340622dc
Received: from epsmtip1.samsung.com ( [182.195.34.30]) by
	epsmgms1p2.samsung.com (Symantec Messaging Gateway) with SMTP id
	C1.52.28392.50437446; Tue, 25 Apr 2023 10:59:33 +0900 (KST)
Received: from perf (unknown [10.229.95.91]) by epsmtip1.samsung.com
	(KnoxPortal) with ESMTPA id
	20230425015933epsmtip19ca175b2e8afd612bd21693f39b98392~ZCvKuKASt1418014180epsmtip1x;
	Tue, 25 Apr 2023 01:59:33 +0000 (GMT)
Date: Tue, 25 Apr 2023 11:31:31 +0900
From: Youngmin Nam <youngmin.nam@samsung.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Youngmin Nam <youngmin.nam@samsung.com>, catalin.marinas@arm.com,
	will@kernel.org, anshuman.khandual@arm.com, broonie@kernel.org,
	alexandru.elisei@arm.com, ardb@kernel.org,
	linux-arm-kernel@lists.infradead.org, hy50.seo@samsung.com,
	andreyknvl@gmail.com, maz@kernel.org, kasan-dev
	<kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>,
	d7271.choe@samsung.com
Subject: Re: [PATCH] arm64: set __exception_irq_entry with __irq_entry as a
 default
Message-ID: <ZEc7gzyYus+HxhDc@perf>
MIME-Version: 1.0
In-Reply-To: <ZEZ/Pk0wqiBJNKEN@FVFF77S0Q05N>
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFtrJJsWRmVeSWpSXmKPExsWy7bCmhS6biXuKQfNGNovpKy+zWXyfOJ3d
	Yt+JZIufX94zWkx9+ITN4v2yHkaLa3snsltMeNjGbrF68QMWixXP7jNZbHp8jdVi6fWLTBY7
	55xktWi5Y2qx+MAndgd+jzXz1jB67Jx1l91jwaZSjz0TT7J5bFrVyeaxeUm9R9+WVYwB7FHZ
	NhmpiSmpRQqpecn5KZl56bZK3sHxzvGmZgaGuoaWFuZKCnmJuam2Si4+AbpumTlAVysplCXm
	lAKFAhKLi5X07WyK8ktLUhUy8otLbJVSC1JyCswL9IoTc4tL89L18lJLrAwNDIxMgQoTsjNu
	rXrEXtBWULGtcw9TA2NjXBcjJ4eEgInE+wenWLsYuTiEBHYwSvxY0MAI4XxilJhw6jBU5jOj
	xJpl/cxdjBxgLX+elkPEdzFKTF+whBnCecgo8XrPZiaQuSwCqhIfPs1jBLHZBHQltp34B2aL
	CKhL9Oz6wgLSwCzQyCxx/EQXI8hUYYFQidWvJEBqeAWUJbY1z2OGsAUlTs58wgJicwroSFzf
	uR7sPAmBPRwSXy7OZoV4wkWi4VA7E4QtLPHq+BZ2CFtK4mV/G5SdLbH61yUou0Ki/V4PM4Rt
	LDHrWTvYccwCGRLrT7xmhPhSWeLILRaIMJ9Ex+G/7BBhXomONiGITjWJX1M2MELYMhK7F6+A
	ho+HxKzNCpAgmcskseLqBcYJjHKzkHwzC8kyCFtHYsHuT2yzgNqZBaQllv/jgDA1Jdbv0l/A
	yLqKUSy1oDg3PbXYqMAYHr/J+bmbGMFpWMt9B+OMtx/0DjEycTAeYpTgYFYS4RXOcksR4k1J
	rKxKLcqPLyrNSS0+xGgKjJqJzFKiyfnATJBXEm9oYmlgYmZmaG5kamCuJM4rbXsyWUggPbEk
	NTs1tSC1CKaPiYNTqoGpxnxfu+Oz25f3f1m2YL3pu/gvd8UYqrfPyWZY+cvk259ZMRsS/j1h
	UdFkYCySSJHmLFqaIJeicelK1hFvyUlrjz19uyV5O4dz58FL+4K2GBU3Zrwr2bfgfobo3j8c
	v/kCohLuiDzyaCiyTDbc4G3Hckq8NfW1s5RMUdrked4r00oLbj9vc3wcJrD6RZO+yMMi14u8
	W1b/+8q/wDFctkm++l9OVrRT/6/Kl6w7ODkUnlhwT7vwZzWXp4jV/6R4maUly9bvfLilJ7FP
	/Y26hOKW6ANl1uaLFfTk6vYHifFP+XP8f+DtnwcStP9pb8+xElnmMS1e7Jxd6hT1re9nLps8
	7axRktedX1c/7Kl9+btfiaU4I9FQi7moOBEAR0Lf6EwEAAA=
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFmpgkeLIzCtJLcpLzFFi42LZdlhJTpfVxD3FYPIuUYvpKy+zWXyfOJ3d
	Yt+JZIufX94zWkx9+ITN4v2yHkaLa3snsltMeNjGbrF68QMWixXP7jNZbHp8jdVi6fWLTBY7
	55xktWi5Y2qx+MAndgd+jzXz1jB67Jx1l91jwaZSjz0TT7J5bFrVyeaxeUm9R9+WVYwB7FFc
	NimpOZllqUX6dglcGYcbPjIWHMutOPDnClMD463oLkYODgkBE4k/T8u7GLk4hAR2MEqcfnWY
	tYuREyguI3F75WUoW1jifssRVoii+4wSOw8dZwRJsAioSnz4NA/MZhPQldh24h+YLSKgLtGz
	6wsLSAOzQCOzxPxpV9lBtgkLhEqsfiUBUsMroCyxrXkeM8TQuUwSVzbeY4NICEqcnPmEBcRm
	FtCSuPHvJRNIL7OAtMTyfxwgYU4BHYnrO9czTmAUmIWkYxaSjlkIHQsYmVcxSqYWFOem5xYb
	FhjlpZbrFSfmFpfmpesl5+duYgRHkpbWDsY9qz7oHWJk4mA8xCjBwawkwiuc5ZYixJuSWFmV
	WpQfX1Sak1p8iFGag0VJnPdC18l4IYH0xJLU7NTUgtQimCwTB6dUA9PCQylOjb5qOdy/b35d
	XCE25cQP9+d7DZb82Gu+noXn0KznWbZvc2dyCtSciWY/3O4qP3OOeQrPx2eXPz8vkpi0dKlH
	vm9hNUOH449JuaenbGt23vd+44RVaa1JgeeeTxSrPMMcu4Bl/S7jlZFTG563uZ30Wf7Kxb7v
	6rqWT4ITZu4u2PTW+tVhP674jydFGb8YrlkcdlBD/Pey6VO0xX+mmCtfY9UKCbt4bzbH2Zt8
	k3iu5nCy3+u9IPFw77wA7qcXjPwetNTvPjf3scgnaw5t3ZfuxpZcRxIXMfs8LL39+uneX8cO
	nDr7knFCUemF7mmJ1oK/pR/PMt5htZS5nmXy5VWFb57c2DxlbZPyQq2+q0osxRmJhlrMRcWJ
	AJVPS/QTAwAA
X-CMS-MailID: 20230425015933epcas2p43aafca3e20469849bb467faf3d819216
X-Msg-Generator: CA
Content-Type: multipart/mixed;
	boundary="----ZXwaXR1VMrGJfIxs4SmzhXXYiQxZRR8NOGZIw-CfqfYF-s71=_7d01c_"
X-Sendblock-Type: AUTO_CONFIDENTIAL
CMS-TYPE: 102P
DLP-Filter: Pass
X-CFilter-Loop: Reflected
X-CMS-RootMailID: 20230424003252epcas2p29758e056b4766e53c252b5927a0cb406
References: <CGME20230424003252epcas2p29758e056b4766e53c252b5927a0cb406@epcas2p2.samsung.com>
	<20230424010436.779733-1-youngmin.nam@samsung.com>
	<ZEZhftx05blmZv1T@FVFF77S0Q05N>
	<CACT4Y+bYJ=YHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw@mail.gmail.com>
	<ZEZ/Pk0wqiBJNKEN@FVFF77S0Q05N>
X-Original-Sender: youngmin.nam@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=sqjeDAqP;       spf=pass
 (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.24 as
 permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;       dmarc=pass
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

------ZXwaXR1VMrGJfIxs4SmzhXXYiQxZRR8NOGZIw-CfqfYF-s71=_7d01c_
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Mon, Apr 24, 2023 at 02:08:14PM +0100, Mark Rutland wrote:
> On Mon, Apr 24, 2023 at 02:09:05PM +0200, Dmitry Vyukov wrote:
> > On Mon, 24 Apr 2023 at 13:01, Mark Rutland <mark.rutland@arm.com> wrote:
> > >
> > > On Mon, Apr 24, 2023 at 10:04:36AM +0900, Youngmin Nam wrote:
> > > > filter_irq_stacks() is supposed to cut entries which are related irq entries
> > > > from its call stack.
> > > > And in_irqentry_text() which is called by filter_irq_stacks()
> > > > uses __irqentry_text_start/end symbol to find irq entries in callstack.
> > > >
> > > > But it doesn't work correctly as without "CONFIG_FUNCTION_GRAPH_TRACER",
> > > > arm64 kernel doesn't include gic_handle_irq which is entry point of arm64 irq
> > > > between __irqentry_text_start and __irqentry_text_end as we discussed in below link.
> > >
> > > TBH, the __irqentry_text annotations don't make much sense, and I'd love to
> > > remove them.
> > >
> > > The irqchip handlers are not the actual exception entry points, and we invoke a
> > > fair amount of code between those and the actual IRQ handlers (e.g. to map from
> > > the irq domain to the actual hander, which might involve poking chained irqchip
> > > handlers), so it doesn't make much sense for the irqchip handlers to be
> > > special.
> > >
> > > > https://lore.kernel.org/all/CACT4Y+aReMGLYua2rCLHgFpS9io5cZC04Q8GLs-uNmrn1ezxYQ@mail.gmail.com/#t
> > > >
> > > > This problem can makes unintentional deep call stack entries especially
> > > > in KASAN enabled situation as below.
> > >
> > > What exactly does KASAN need here? Is this just to limit the depth of the
> > > trace?
> > 
> > No, it's not just depth. Any uses of stack depot need stable
> > repeatable traces, so that they are deduplicated well. For irq stacks
> > it means removing the random part where the interrupt is delivered.
> > Otherwise stack depot grows without limits and overflows.

Hi Dmitry Vyukov.
Thanks for your additional comments.

> 
> Sure -- you want to filter out the non-deterministic context that the interrupt
> was taken *from*.
> 
> > We don't need the exact entry point for this. A frame "close enough"
> > may work well if there are no memory allocations/frees skipped.
> 
> With that in mind, I think what we should do is cut this at the instant we
> enter the exception; for the trace below that would be el1h_64_irq. I've added
> some line spacing there to make it stand out.
> 
> That would mean that we'd have three entry points that an interrupt trace might
> start from:
> 
> * el1h_64_irq()
> * el0t_64_irq()
> * el0t_32_irq()
>

Hi Mark.
Thanks for your kind review.

If I understand your intention corretly, I should add "__irq_entry"
to C function of irq_handler as below.

diff --git a/arch/arm64/include/asm/exception.h b/arch/arm64/include/asm/exception.h
-asmlinkage void el1h_64_irq_handler(struct pt_regs *regs);
+asmlinkage void __irq_entry el1h_64_irq_handler(struct pt_regs *regs);

-asmlinkage void el0t_64_irq_handler(struct pt_regs *regs);
+asmlinkage void __irq_entry el0t_64_irq_handler(struct pt_regs *regs);

-asmlinkage void el0t_32_irq_handler(struct pt_regs *regs);
+asmlinkage void __irq_entry el0t_32_irq_handler(struct pt_regs *regs);

But these irq handlers are marked with "noinstr" already so that we can't put them into
irqentry section.

arch/arm64/kernel/entry-common.c:492:asmlinkage void noinstr el1h_64_irq_handler(struct pt_regs *regs)
arch/arm64/kernel/entry-common.c:730:asmlinkage void noinstr el0t_64_irq_handler(struct pt_regs *regs)
arch/arm64/kernel/entry-common.c:824:asmlinkage void noinstr el0t_32_irq_handler(struct pt_regs *regs)

Could you tell me that I am doing right ?

> ... so we might have three traces for a given interrupt, but the portion
> between that and the irqchip handler would be deterministic, so deduplication
> would only end up with three traces.
> 
> It may be useful to distinguish the three cases, since some IRQ handlers do
> different things when user_mode(regs) and/or compat_user_mode(regs) are true.
> 
> > > If so, we could easily add an API to get a stacktrace up to an IRQ exception
> > > boundary. IIRC we'd been asked for that in the past, and it's relatively simple
> > > to implement that regardless of CONFIG_FUNCTION_GRAPH_TRACER.
> > >
> > > > [ 2479.383395]I[0:launcher-loader: 1719] Stack depot reached limit capacity
> > > > [ 2479.383538]I[0:launcher-loader: 1719] WARNING: CPU: 0 PID: 1719 at lib/stackdepot.c:129 __stack_depot_save+0x464/0x46c
> > > > [ 2479.385693]I[0:launcher-loader: 1719] pstate: 624000c5 (nZCv daIF +PAN -UAO +TCO -DIT -SSBS BTYPE=--)
> > > > [ 2479.385724]I[0:launcher-loader: 1719] pc : __stack_depot_save+0x464/0x46c
> > > > [ 2479.385751]I[0:launcher-loader: 1719] lr : __stack_depot_save+0x460/0x46c
> > > > [ 2479.385774]I[0:launcher-loader: 1719] sp : ffffffc0080073c0
> > > > [ 2479.385793]I[0:launcher-loader: 1719] x29: ffffffc0080073e0 x28: ffffffd00b78a000 x27: 0000000000000000
> > > > [ 2479.385839]I[0:launcher-loader: 1719] x26: 000000000004d1dd x25: ffffff891474f000 x24: 00000000ca64d1dd
> > > > [ 2479.385882]I[0:launcher-loader: 1719] x23: 0000000000000200 x22: 0000000000000220 x21: 0000000000000040
> > > > [ 2479.385925]I[0:launcher-loader: 1719] x20: ffffffc008007440 x19: 0000000000000000 x18: 0000000000000000
> > > > [ 2479.385969]I[0:launcher-loader: 1719] x17: 2065726568207475 x16: 000000000000005e x15: 2d2d2d2d2d2d2d20
> > > > [ 2479.386013]I[0:launcher-loader: 1719] x14: 5d39313731203a72 x13: 00000000002f6b30 x12: 00000000002f6af8
> > > > [ 2479.386057]I[0:launcher-loader: 1719] x11: 00000000ffffffff x10: ffffffb90aacf000 x9 : e8a74a6c16008800
> > > > [ 2479.386101]I[0:launcher-loader: 1719] x8 : e8a74a6c16008800 x7 : 00000000002f6b30 x6 : 00000000002f6af8
> > > > [ 2479.386145]I[0:launcher-loader: 1719] x5 : ffffffc0080070c8 x4 : ffffffd00b192380 x3 : ffffffd0092b313c
> > > > [ 2479.386189]I[0:launcher-loader: 1719] x2 : 0000000000000001 x1 : 0000000000000004 x0 : 0000000000000022
> > > > [ 2479.386231]I[0:launcher-loader: 1719] Call trace:
> > > > [ 2479.386248]I[0:launcher-loader: 1719]  __stack_depot_save+0x464/0x46c
> > > > [ 2479.386273]I[0:launcher-loader: 1719]  kasan_save_stack+0x58/0x70
> > > > [ 2479.386303]I[0:launcher-loader: 1719]  save_stack_info+0x34/0x138
> > > > [ 2479.386331]I[0:launcher-loader: 1719]  kasan_save_free_info+0x18/0x24
> > > > [ 2479.386358]I[0:launcher-loader: 1719]  ____kasan_slab_free+0x16c/0x170
> > > > [ 2479.386385]I[0:launcher-loader: 1719]  __kasan_slab_free+0x10/0x20
> > > > [ 2479.386410]I[0:launcher-loader: 1719]  kmem_cache_free+0x238/0x53c
> > > > [ 2479.386435]I[0:launcher-loader: 1719]  mempool_free_slab+0x1c/0x28
> > > > [ 2479.386460]I[0:launcher-loader: 1719]  mempool_free+0x7c/0x1a0
> > > > [ 2479.386484]I[0:launcher-loader: 1719]  bvec_free+0x34/0x80
> > > > [ 2479.386514]I[0:launcher-loader: 1719]  bio_free+0x60/0x98
> > > > [ 2479.386540]I[0:launcher-loader: 1719]  bio_put+0x50/0x21c
> > > > [ 2479.386567]I[0:launcher-loader: 1719]  f2fs_write_end_io+0x4ac/0x4d0
> > > > [ 2479.386594]I[0:launcher-loader: 1719]  bio_endio+0x2dc/0x300
> > > > [ 2479.386622]I[0:launcher-loader: 1719]  __dm_io_complete+0x324/0x37c
> > > > [ 2479.386650]I[0:launcher-loader: 1719]  dm_io_dec_pending+0x60/0xa4
> > > > [ 2479.386676]I[0:launcher-loader: 1719]  clone_endio+0xf8/0x2f0
> > > > [ 2479.386700]I[0:launcher-loader: 1719]  bio_endio+0x2dc/0x300
> > > > [ 2479.386727]I[0:launcher-loader: 1719]  blk_update_request+0x258/0x63c
> > > > [ 2479.386754]I[0:launcher-loader: 1719]  scsi_end_request+0x50/0x304
> > > > [ 2479.386782]I[0:launcher-loader: 1719]  scsi_io_completion+0x88/0x160
> > > > [ 2479.386808]I[0:launcher-loader: 1719]  scsi_finish_command+0x17c/0x194
> > > > [ 2479.386833]I[0:launcher-loader: 1719]  scsi_complete+0xcc/0x158
> > > > [ 2479.386859]I[0:launcher-loader: 1719]  blk_mq_complete_request+0x4c/0x5c
> > > > [ 2479.386885]I[0:launcher-loader: 1719]  scsi_done_internal+0xf4/0x1e0
> > > > [ 2479.386910]I[0:launcher-loader: 1719]  scsi_done+0x14/0x20
> > > > [ 2479.386935]I[0:launcher-loader: 1719]  ufshcd_compl_one_cqe+0x578/0x71c
> > > > [ 2479.386963]I[0:launcher-loader: 1719]  ufshcd_mcq_poll_cqe_nolock+0xc8/0x150
> > > > [ 2479.386991]I[0:launcher-loader: 1719]  ufshcd_intr+0x868/0xc0c
> > > > [ 2479.387017]I[0:launcher-loader: 1719]  __handle_irq_event_percpu+0xd0/0x348
> > > > [ 2479.387044]I[0:launcher-loader: 1719]  handle_irq_event_percpu+0x24/0x74
> > > > [ 2479.387068]I[0:launcher-loader: 1719]  handle_irq_event+0x74/0xe0
> > > > [ 2479.387091]I[0:launcher-loader: 1719]  handle_fasteoi_irq+0x174/0x240
> > > > [ 2479.387118]I[0:launcher-loader: 1719]  handle_irq_desc+0x7c/0x2c0
> > > > [ 2479.387147]I[0:launcher-loader: 1719]  generic_handle_domain_irq+0x1c/0x28
> > > > [ 2479.387174]I[0:launcher-loader: 1719]  gic_handle_irq+0x64/0x158
> > > > [ 2479.387204]I[0:launcher-loader: 1719]  call_on_irq_stack+0x2c/0x54
> > > > [ 2479.387231]I[0:launcher-loader: 1719]  do_interrupt_handler+0x70/0xa0
> > > > [ 2479.387258]I[0:launcher-loader: 1719]  el1_interrupt+0x34/0x68
> > > > [ 2479.387283]I[0:launcher-loader: 1719]  el1h_64_irq_handler+0x18/0x24
> > > > [ 2479.387308]I[0:launcher-loader: 1719]  el1h_64_irq+0x68/0x6c
> 
> This is where we'd cut the trace with my suggestion.
> 
> > > > [ 2479.387332]I[0:launcher-loader: 1719]  blk_attempt_bio_merge+0x8/0x170
> > > > [ 2479.387356]I[0:launcher-loader: 1719]  blk_mq_attempt_bio_merge+0x78/0x98
> > > > [ 2479.387383]I[0:launcher-loader: 1719]  blk_mq_submit_bio+0x324/0xa40
> > > > [ 2479.387409]I[0:launcher-loader: 1719]  __submit_bio+0x104/0x138
> > > > [ 2479.387436]I[0:launcher-loader: 1719]  submit_bio_noacct_nocheck+0x1d0/0x4a0
> > > > [ 2479.387462]I[0:launcher-loader: 1719]  submit_bio_noacct+0x618/0x804
> > > > [ 2479.387487]I[0:launcher-loader: 1719]  submit_bio+0x164/0x180
> > > > [ 2479.387511]I[0:launcher-loader: 1719]  f2fs_submit_read_bio+0xe4/0x1c4
> > > > [ 2479.387537]I[0:launcher-loader: 1719]  f2fs_mpage_readpages+0x888/0xa4c
> > > > [ 2479.387563]I[0:launcher-loader: 1719]  f2fs_readahead+0xd4/0x19c
> > > > [ 2479.387587]I[0:launcher-loader: 1719]  read_pages+0xb0/0x4ac
> > > > [ 2479.387614]I[0:launcher-loader: 1719]  page_cache_ra_unbounded+0x238/0x288
> > > > [ 2479.387642]I[0:launcher-loader: 1719]  do_page_cache_ra+0x60/0x6c
> > > > [ 2479.387669]I[0:launcher-loader: 1719]  page_cache_ra_order+0x318/0x364
> > > > [ 2479.387695]I[0:launcher-loader: 1719]  ondemand_readahead+0x30c/0x3d8
> > > > [ 2479.387722]I[0:launcher-loader: 1719]  page_cache_sync_ra+0xb4/0xc8
> > > > [ 2479.387749]I[0:launcher-loader: 1719]  filemap_read+0x268/0xd24
> > > > [ 2479.387777]I[0:launcher-loader: 1719]  f2fs_file_read_iter+0x1a0/0x62c
> > > > [ 2479.387806]I[0:launcher-loader: 1719]  vfs_read+0x258/0x34c
> > > > [ 2479.387831]I[0:launcher-loader: 1719]  ksys_pread64+0x8c/0xd0
> > > > [ 2479.387857]I[0:launcher-loader: 1719]  __arm64_sys_pread64+0x48/0x54
> > > > [ 2479.387881]I[0:launcher-loader: 1719]  invoke_syscall+0x58/0x158
> > > > [ 2479.387909]I[0:launcher-loader: 1719]  el0_svc_common+0xf0/0x134
> > > > [ 2479.387935]I[0:launcher-loader: 1719]  do_el0_svc+0x44/0x114
> > > > [ 2479.387961]I[0:launcher-loader: 1719]  el0_svc+0x2c/0x80
> > > > [ 2479.387985]I[0:launcher-loader: 1719]  el0t_64_sync_handler+0x48/0x114
> > > > [ 2479.388010]I[0:launcher-loader: 1719]  el0t_64_sync+0x190/0x194
> > > > [ 2479.388038]I[0:launcher-loader: 1719] Kernel panic - not syncing: kernel: panic_on_warn set ...
> 
> Thanks,
> Mark.
> 
> > > >
> > > > So let's set __exception_irq_entry with __irq_entry as a default.
> > > > Applying this patch, we can see gic_hande_irq is included in Systemp.map as below.
> > > >
> > > > * Before
> > > > ffffffc008010000 T __do_softirq
> > > > ffffffc008010000 T __irqentry_text_end
> > > > ffffffc008010000 T __irqentry_text_start
> > > > ffffffc008010000 T __softirqentry_text_start
> > > > ffffffc008010000 T _stext
> > > > ffffffc00801066c T __softirqentry_text_end
> > > > ffffffc008010670 T __entry_text_start
> > > >
> > > > * After
> > > > ffffffc008010000 T __irqentry_text_start
> > > > ffffffc008010000 T _stext
> > > > ffffffc008010000 t gic_handle_irq
> > > > ffffffc00801013c t gic_handle_irq
> > > > ffffffc008010294 T __irqentry_text_end
> > > > ffffffc008010298 T __do_softirq
> > > > ffffffc008010298 T __softirqentry_text_start
> > > > ffffffc008010904 T __softirqentry_text_end
> > > > ffffffc008010908 T __entry_text_start
> > > >
> > > > Signed-off-by: Youngmin Nam <youngmin.nam@samsung.com>
> > > > Signed-off-by: SEO HOYOUNG <hy50.seo@samsung.com>
> > > > Change-Id: Iea7ff528be1c72cf50ab6aabafa77215ddb55eb2
> > >
> > > This change-id is meaningless upstream.
> > >
> > > > ---
> > > >  arch/arm64/include/asm/exception.h | 5 -----
> > > >  1 file changed, 5 deletions(-)
> > > >
> > > > diff --git a/arch/arm64/include/asm/exception.h b/arch/arm64/include/asm/exception.h
> > > > index 19713d0f013b..18dbb35a337f 100644
> > > > --- a/arch/arm64/include/asm/exception.h
> > > > +++ b/arch/arm64/include/asm/exception.h
> > > > @@ -8,16 +8,11 @@
> > > >  #define __ASM_EXCEPTION_H
> > > >
> > > >  #include <asm/esr.h>
> > > > -#include <asm/kprobes.h>
> > > >  #include <asm/ptrace.h>
> > > >
> > > >  #include <linux/interrupt.h>
> > > >
> > > > -#ifdef CONFIG_FUNCTION_GRAPH_TRACER
> > > >  #define __exception_irq_entry        __irq_entry
> > > > -#else
> > > > -#define __exception_irq_entry        __kprobes
> > > > -#endif
> > >
> > > How does this affect ftrace and kprobes? The commit message never explained why
> > > this change is safe.
> > >
> > > Thanks,
> > > Mark.
> > >
> > > >
> > > >  static inline unsigned long disr_to_esr(u64 disr)
> > > >  {
> > > > --
> > > > 2.39.2
> > > >
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZEc7gzyYus%2BHxhDc%40perf.

------ZXwaXR1VMrGJfIxs4SmzhXXYiQxZRR8NOGZIw-CfqfYF-s71=_7d01c_
Content-Type: text/plain; charset="UTF-8"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZEc7gzyYus%2BHxhDc%40perf.

------ZXwaXR1VMrGJfIxs4SmzhXXYiQxZRR8NOGZIw-CfqfYF-s71=_7d01c_--
