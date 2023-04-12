Return-Path: <kasan-dev+bncBD7JBZE7SEHRBTEU3GQQMGQETIC24MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A8E56DEB83
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Apr 2023 08:06:06 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id f2-20020ac87f02000000b003e6372b917dsf25770611qtk.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Apr 2023 23:06:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681279565; cv=pass;
        d=google.com; s=arc-20160816;
        b=F5OAooOVteCUKcbKKLUFvuXsPIrhfjeMCcZszBQtdSYZFOXjbcWvseGGfyQ4l0P/K4
         kc7EA7RSOcVe3qqp6/23Xww2/hiKn/adnnTVATFt4obFrV7TMbUFMOnrIFChiGjKk48e
         fHf1ADSbdg/jgmpmshuC+kUSpioC9fGSg8WjAn6+C/PzC0SiqiQ6bEafcFpcbl+V3i6o
         gN9JeJKpIohqj3sXHZQdWMogbDnVRNRhE1dOXLbfkO4JMert0/EnL3ouR1dXkhIeAZLI
         ttYIENPupVVKC+Bw82EsZLVS3aQRZh8fBu7pGyZB3iUXB2NSpKZRbtt8ivehYDU3xRFF
         imPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:dlp-filter:cms-type
         :content-language:thread-index:mime-version:message-id:date:subject
         :cc:to:from:dkim-filter:sender:dkim-signature;
        bh=mwkCo92B8ftR2w51pya3qeKwk2HCwmjWtRxNjGME9Cs=;
        b=AQQTdKXrxoJh0ZLH4UPAQ1YICSsayzgQet2OboKVlx+H3SUrj1hxA6iVLtr4SXjN9B
         dEfl6UcTMKChXyxGS5C5ytUdywQ++Nr7NNQsRtkXonHcxq6hDUsYpHHVrRGQzlzmhlEY
         kgboisoemgIy+VP/8aAuwAM3CWFGBRCfmMs5RYteoFwbLnQoPprFGSv0BVVN4LXdwIzv
         dYQFjij5QnnmER6y1dGMS1qliOJg/Y5Hr2U+0oM/bGZCKg11smVRD11Vi5xeIsJuuq5P
         sYW011JAmNKBbtjGQAAD7ONGg0ePfxzRNdOuwbFKx+4P+N4OD05QfM++QkkRSAtLpm8y
         jWDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=ffKsvTjl;
       spf=pass (google.com: domain of hy50.seo@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=hy50.seo@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681279565; x=1683871565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:dlp-filter:cms-type:content-language
         :thread-index:mime-version:message-id:date:subject:cc:to:from
         :dkim-filter:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mwkCo92B8ftR2w51pya3qeKwk2HCwmjWtRxNjGME9Cs=;
        b=GonpmzsGvhl0pBQhX5bqdeTnznLQwXsTnlL5nzbRybgOlmZFd9m5XtkALCF5GO6hdT
         SjfrjA7YHzK9XUB/Xscvks02u1/Z5MuUCQ6LeZugH+1gEX1pw3IGr07yvczv/n8b0bdG
         oJazxipQ38t49LX9LnZHlV0tSv365hBaRGG8FKe3hORaJef7GqGa2JzXmuFX565g6jC4
         oQ/c/85ma6J9k+koheZXM2RTHuwKfe/tnYn49PLqWo4Vh+/LUqUR7GcspmAXv/PD0mmj
         Oc8y6ND8sm836D/qjmw3i0cqHG99Z7Exv2bOs/Ba3mABN/PudUg9z2vCI102oFlxlOt5
         PFfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1681279565; x=1683871565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :dlp-filter:cms-type:content-language:thread-index:mime-version
         :message-id:date:subject:cc:to:from:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mwkCo92B8ftR2w51pya3qeKwk2HCwmjWtRxNjGME9Cs=;
        b=MnSf5viqY6mdzoeMV+W79LwR9/egcuzlvq7AdZXxnRFAC0Z5NqLgp3x1pyuQ+glo4Y
         3zIN7CAodL1dhxphg6Bck76QMXfU/snfHRV2hQLp6D4A51PbnrLE5GRU6aD1C8qQ97gp
         WqHy0EbEMAcK/mfu/GumcUkcxkwLwQ+SnDUbyBeTtvc8R5/oXRrHr8Ffxwa7tm+GyIkO
         0s9FLU/hHXL+rC/d8DZ0AgMWmF+oToScutwkZ1Foq8sHpBDN5p8chm6mGr1MlC1z7uPV
         G31z7gvZLSLmIdP1D57I4vQjXUEBwG63DJQdcZ2ftTSYRtxJt/vJwoI5JktZNLSmkOqB
         s6nA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9e1pSmHqpnl07PagB1PPyYjHTkgjcQM2xZo/ozqLUObFfqLePGq
	Rk4BpFV8jwgS0ip5a6/RiVA=
X-Google-Smtp-Source: AKy350awNZ80dFhn5YsEXrMLjicuS1jGs7MVE0aOBf24iY0Mzq7cpQHYiAXJR1AhCmoOjWtexAK2dQ==
X-Received: by 2002:a05:620a:198e:b0:746:b32:a43d with SMTP id bm14-20020a05620a198e00b007460b32a43dmr4073714qkb.11.1681279565014;
        Tue, 11 Apr 2023 23:06:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:124b:b0:3e1:c0bd:797c with SMTP id
 z11-20020a05622a124b00b003e1c0bd797cls34808832qtx.9.-pod-prod-gmail; Tue, 11
 Apr 2023 23:06:04 -0700 (PDT)
X-Received: by 2002:ac8:5f0a:0:b0:3e3:98af:5de9 with SMTP id x10-20020ac85f0a000000b003e398af5de9mr23694682qta.63.1681279564542;
        Tue, 11 Apr 2023 23:06:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681279564; cv=none;
        d=google.com; s=arc-20160816;
        b=nT5jZ9XaM1wgpVqhuz26ybFaM9YrVma2FfQgSexicMnbyDgx7jJLcAIpStJijFcp7E
         fr0gCbgdL1tt38HT607fcSc6IAODgcVvcOzIMr34jqSKAyubvKRgpcOyyb7UGtic49Wl
         B5OBEURb+xgOocopv1VvSlsn0QUHBptQdf90rrFBE6qiyJ+EKhDUqsjewSOpOgwWPxQc
         eo2ARSXQsIHAzg/YWUERBN8QySczVyVS5V6LeydBKm+oivTlgE7QJ5NTpdQdeiavq6w4
         XPqbUgu3zrLNsV6/SGBnV1F42QICbJBbiOV77kJjxFXZ0vXtfoYUdoHihStL7VmbdicO
         ZuMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:dlp-filter:cms-type:content-language:thread-index
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature:dkim-filter;
        bh=yq5mp7GhrYcBNCC0qI9amcCJzqtuRuAuGhzeC4ILyrg=;
        b=utXJufNzqNyC5We0EQRXTNV1bgKDe0lgGiQtPTKAmzFIiJXL1y4r74lej3N3vTfved
         5GI9NyJaVmiP8t5sg/NJz5wP+xkcFqQAmogq0ROxQqCcp/SFwzM4ecAhof62/MfHNJxl
         w6dkE9150kS2z3GdtVU0fHrmV5viWfcuuH2MgvlvbZe0Xh39qFUxj8I1Vfww/stw2Uvv
         YxHRSHcdKPZ4e0vq6TFRodKu6RXDYG0giSNUQjfJoqC9Mos4vnPLbLlnklW3xkxWc55S
         UZA/kxoGiSkiVL6vxq9ui06vY2pKCWTWY7I5skq8Cti7/AoYH6anCHyRrSW2Fa1M/ldA
         IaYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=ffKsvTjl;
       spf=pass (google.com: domain of hy50.seo@samsung.com designates 203.254.224.24 as permitted sender) smtp.mailfrom=hy50.seo@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.samsung.com (mailout1.samsung.com. [203.254.224.24])
        by gmr-mx.google.com with ESMTPS id bs6-20020ac86f06000000b003d2b5e4bce2si1221034qtb.5.2023.04.11.23.06.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Apr 2023 23:06:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of hy50.seo@samsung.com designates 203.254.224.24 as permitted sender) client-ip=203.254.224.24;
Received: from epcas2p3.samsung.com (unknown [182.195.41.55])
	by mailout1.samsung.com (KnoxPortal) with ESMTP id 20230412060600epoutp01bd2be97386e3d17aa1c86fac8e9a3dd5~VGtpEFwZV1911719117epoutp01g
	for <kasan-dev@googlegroups.com>; Wed, 12 Apr 2023 06:06:00 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.samsung.com 20230412060600epoutp01bd2be97386e3d17aa1c86fac8e9a3dd5~VGtpEFwZV1911719117epoutp01g
Received: from epsnrtp4.localdomain (unknown [182.195.42.165]) by
	epcas2p4.samsung.com (KnoxPortal) with ESMTP id
	20230412060559epcas2p421d7d2d3d01b9209c3ecc2889b0d07b8~VGtoUSRsm2238022380epcas2p4R;
	Wed, 12 Apr 2023 06:05:59 +0000 (GMT)
Received: from epsmges2p2.samsung.com (unknown [182.195.36.70]) by
	epsnrtp4.localdomain (Postfix) with ESMTP id 4PxBzC299Sz4x9Px; Wed, 12 Apr
	2023 06:05:59 +0000 (GMT)
Received: from epcas2p4.samsung.com ( [182.195.41.56]) by
	epsmges2p2.samsung.com (Symantec Messaging Gateway) with SMTP id
	03.DF.10686.74A46346; Wed, 12 Apr 2023 15:05:59 +0900 (KST)
Received: from epsmtrp2.samsung.com (unknown [182.195.40.14]) by
	epcas2p2.samsung.com (KnoxPortal) with ESMTPA id
	20230412060558epcas2p254358bbd869eec9fb9907db6abac459a~VGtnJANbP1322213222epcas2p2H;
	Wed, 12 Apr 2023 06:05:58 +0000 (GMT)
Received: from epsmgms1p1new.samsung.com (unknown [182.195.42.41]) by
	epsmtrp2.samsung.com (KnoxPortal) with ESMTP id
	20230412060558epsmtrp23b01e7a0419ddd199bf75900699e1de6~VGtnIJin82679626796epsmtrp2j;
	Wed, 12 Apr 2023 06:05:58 +0000 (GMT)
X-AuditID: b6c32a46-ed1f8700000029be-96-64364a47ef4a
Received: from epsmtip2.samsung.com ( [182.195.34.31]) by
	epsmgms1p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	79.DB.08279.64A46346; Wed, 12 Apr 2023 15:05:58 +0900 (KST)
Received: from KORCO118546 (unknown [10.229.38.108]) by epsmtip2.samsung.com
	(KnoxPortal) with ESMTPA id
	20230412060558epsmtip24a1b3366139bb249225b7e43fc4990a5~VGtm6ssYS0489104891epsmtip27;
	Wed, 12 Apr 2023 06:05:58 +0000 (GMT)
From: "hoyoung seo" <hy50.seo@samsung.com>
To: <andrey.konovalov@linux.dev>
Cc: <akpm@linux-foundation.org>, <andreyknvl@gmail.com>,
	<andreyknvl@google.com>, <elver@google.com>, <eugenis@google.com>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>, <vbabka@suse.cz>,
	<bhoon95.kim@samsung.com>, <sc.suh@samsung.com>
Subject: Re: [PATCH v2 10/18] lib/stackdepot: rename handle and pool
 constants
Date: Wed, 12 Apr 2023 15:05:58 +0900
Message-ID: <000401d96d04$d991ad40$8cb507c0$@samsung.com>
MIME-Version: 1.0
X-Mailer: Microsoft Outlook 16.0
Thread-Index: Adls/lQR+xwTsUp4SriSKyfuc/JN4w==
Content-Language: ko
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFjrGJsWRmVeSWpSXmKPExsWy7bCmha67l1mKwf5z3BZz1q9hs3h68jKb
	xfeJ09ktenbvZLL4uvQZq0Xbme2sFgcXvGOxaP+4l9lixbP7TBaXd81hs7i35j+rRdfdG4wW
	sxv7GB14PXbOusvusWBTqceeiSfZPDZ9msTucWLGbxaPhQ1TmT36tqxi9Diz4Ai7x+dNcgGc
	Udk2GamJKalFCql5yfkpmXnptkrewfHO8aZmBoa6hpYW5koKeYm5qbZKLj4Bum6ZOUB3KymU
	JeaUAoUCEouLlfTtbIryS0tSFTLyi0tslVILUnIKzAv0ihNzi0vz0vXyUkusDA0MjEyBChOy
	M94eOslcMMG44uDipUwNjJN1uxg5OSQETCTev1rHBGILCexglNi3yqmLkQvI/gRk//vOAuF8
	Y5TYuWciUBUHWMfEqfIQ8b2MEhvP7mOGcF4ySvzs62cDGcUmoCXR/3YLmC0ioCAx9cMedpAi
	ZoF1TBIvpv5gAUkICwRI/F1+gBHEZhFQlZjcuQXsDl4BS4nrH06zQtiCEidnPgGrZxbQlli2
	8DUzxN0KEj+fLmOFWKAn8aWlmxmiRkRidmcb2EUSAkc4JJ5M6WeFaHCRaDp3mB3CFpZ4dXwL
	lC0l8fndXjYIO1uicc9aqHiFxNzNkxkhbGOJWc/aGUHeZxbQlFi/Sx8SEsoSR25BncYn0XH4
	LztEmFeio00IolFJ4szc21BhCYmDs3Mgwh4Sa6Z/Z5zAqDgLyY+zkPw4C8kvsxDWLmBkWcUo
	llpQnJueWmxUYASP6uT83E2M4ASt5baDccrbD3qHGJk4GA8xSnAwK4nw/nAxTRHiTUmsrEot
	yo8vKs1JLT7EaAoM9YnMUqLJ+cAckVcSb2hiaWBiZmZobmRqYK4kzittezJZSCA9sSQ1OzW1
	ILUIpo+Jg1Oqgck6465g5Ua1ym+uSx8kvPyWZ6eulKrku7XIzSZHKdS4NHlb+KOiTcdrLq2T
	kV8o11FwIzq0p6QyfM0r+VM/jATdvW3yA67VHdXX+NaxwsxXM/yhguXiUy8DLaIq2R+9vhvx
	edGm/wGmbtVhTBvmvGjb+0dCv6do2a5fse9uf71zep2FaEqZbGL8Ridvo28WL+w5DwStD1lV
	PleFce6f62rftifIbl+xPefmnLvmk/fM31hbXDk7+n8mb57G2rllky63zlP0K/VTqZ2xzXS+
	CAf36u9Laq+csNB7aW0ZmMfPU6q612HDl+zJj9lmvhZ3f+sc/lXiVsivaQXhHyU0Hn+YnfFX
	cdWHz/mpqjZ3zZVYijMSDbWYi4oTAej10KlZBAAA
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFprNIsWRmVeSWpSXmKPExsWy7bCSvK6bl1mKweKFMhZz1q9hs3h68jKb
	xfeJ09ktenbvZLL4uvQZq0Xbme2sFgcXvGOxaP+4l9lixbP7TBaXd81hs7i35j+rRdfdG4wW
	sxv7GB14PXbOusvusWBTqceeiSfZPDZ9msTucWLGbxaPhQ1TmT36tqxi9Diz4Ai7x+dNcgGc
	UVw2Kak5mWWpRfp2CVwZt08vZS/YYFCx/X9lA+NmrS5GDg4JAROJiVPluxi5OIQEdjNKrHz7
	iq2LkRMoLiHxf3ETE4QtLHG/5QgrRNFzRomll5tYQBJsAloS/W+3gDWICChITP2whx2kiFlg
	D5PE49U/wRLCAn4SC89/ALNZBFQlJnduAZvKK2Apcf3DaVYIW1Di5MwnYEOZBbQleh+2MsLY
	yxa+Zoa4QkHi59NlrBDL9CS+tHQzQ9SISMzubGOewCg4C8moWUhGzUIyahaSlgWMLKsYJVML
	inPTc4sNCwzzUsv1ihNzi0vz0vWS83M3MYLjT0tzB+P2VR/0DjEycTAeYpTgYFYS4f3hYpoi
	xJuSWFmVWpQfX1Sak1p8iFGag0VJnPdC18l4IYH0xJLU7NTUgtQimCwTB6dUA9OVxKV3vXo8
	DtwLuGVw2e/1PPsuKYP060snb1ucpvc5i33uIa51B1WNhZ58lPgpOM9xrtKko2dNnx9l2p5Z
	ZZq2c6dd+QnXfzOZnfIbJ63Zuuzq3GsLdmqlrm02NuYz9plff/NPVlRBbFOH4qLv/3wEP+ut
	jp+s2TE52uYEg96VI2WbDMRX5Am82s/unbH2FKt9rEh4/f2v9x1Mn0jd912za/nL22dcJ1k8
	qp56c2/mY31+s56MKy6bi5g2rPwvvnR/WNNJ1Ty5JEVLO02PCt6NuccNPzHdWvfmchj3YWet
	9XcqSpkSV++3D1T77WTztlggrFKD3+9MTTJf5aa6mLN11mzvd2w+m8Mm7vcg464SS3FGoqEW
	c1FxIgC3INncLgMAAA==
X-CMS-MailID: 20230412060558epcas2p254358bbd869eec9fb9907db6abac459a
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-Sendblock-Type: AUTO_CONFIDENTIAL
CMS-TYPE: 102P
DLP-Filter: Pass
X-CFilter-Loop: Reflected
X-CMS-RootMailID: 20230412060558epcas2p254358bbd869eec9fb9907db6abac459a
References: <CGME20230412060558epcas2p254358bbd869eec9fb9907db6abac459a@epcas2p2.samsung.com>
X-Original-Sender: hy50.seo@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=ffKsvTjl;       spf=pass
 (google.com: domain of hy50.seo@samsung.com designates 203.254.224.24 as
 permitted sender) smtp.mailfrom=hy50.seo@samsung.com;       dmarc=pass
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

+#define DEPOT_HANDLE_BITS (sizeof(depot_stack_handle_t) * 8)
+
+#define DEPOT_VALID_BITS 1
+#define DEPOT_POOL_ORDER 2 /* Pool size order, 4 pages */
+#define DEPOT_POOL_SIZE (1LL << (PAGE_SHIFT + DEPOT_POOL_ORDER))
+#define DEPOT_STACK_ALIGN 4
+#define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
+#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_VALID_BITS - \
+			       DEPOT_OFFSET_BITS - STACK_DEPOT_EXTRA_BITS)
+#define DEPOT_POOLS_CAP 8192

Increase DEPOT_POOLS_CAP size to 32768

+#define DEPOT_MAX_POOLS \
+	(((1LL << (DEPOT_POOL_INDEX_BITS)) < DEPOT_POOLS_CAP) ? \
+	 (1LL << (DEPOT_POOL_INDEX_BITS)) : DEPOT_POOLS_CAP)


Hi Andrey.

I have some question about DEPOT_MAX_POOLS.
Actually I didn't know where to post my question, so here it is.
I'm testing a feature of the UFS4.0 specification called MCQ, 
the call stack looks like this and __stack_depot_save keeps printing warning messages.

[7:  OST-Normal-13:17476] ------------[ cut here ]------------
[7:  OST-Normal-13:17476] Stack depot reached limit capacity
[7:  OST-Normal-13:17476] pc : __stack_depot_save+0x464/0x46c
[7:  OST-Normal-13:17476] lr : __stack_depot_save+0x460/0x46c
[7:  OST-Normal-13:17476] sp : ffffffc008077730
[7:  OST-Normal-13:17476] x29: ffffffc008077750 x28: ffffffd00b78a000 x27: 0000000000000000
[7:  OST-Normal-13:17476] x26: 000000000009a7a4 x25: ffffff8914750000 x24: 000000004379a7a4
[7:  OST-Normal-13:17476] x23: 00000000000001f8 x22: 0000000000000210 x21: 000000000000003f
[7:  OST-Normal-13:17476] x20: ffffffc0080777b0 x19: 0000000000000000 x18: 0000000000001000
[7:  OST-Normal-13:17476] x17: 2065726568207475 x16: 00000000000000c3 x15: 2d2d2d2d2d2d2d20
[7:  OST-Normal-13:17476] x14: 5d36373437313a33 x13: 000000000059a740 x12: 000000000059a6f8
[7:  OST-Normal-13:17476] x11: 00000000ffffffff x10: ffffffb90aba9000 x9 : 008c3feffad60900
[7:  OST-Normal-13:17476] x8 : 008c3feffad60900 x7 : 000000000059a740 x6 : 000000000059a6f8
[7:  OST-Normal-13:17476] x5 : ffffffc008077438 x4 : ffffffd00b196970 x3 : ffffffd0092b313c
[7:  OST-Normal-13:17476] x2 : 0000000000000001 x1 : 0000000000000004 x0 : 0000000000000022
[7:  OST-Normal-13:17476] Call trace:
[7:  OST-Normal-13:17476]  __stack_depot_save+0x464/0x46c
[7:  OST-Normal-13:17476]  kasan_save_stack+0x58/0x70
[7:  OST-Normal-13:17476]  save_stack_info+0x34/0x138
[7:  OST-Normal-13:17476]  kasan_save_free_info+0x18/0x24
[7:  OST-Normal-13:17476]  ____kasan_slab_free+0x16c/0x170
[7:  OST-Normal-13:17476]  __kasan_slab_free+0x10/0x20
[7:  OST-Normal-13:17476]  kmem_cache_free+0x238/0x53c
[7:  OST-Normal-13:17476]  mempool_free_slab+0x1c/0x28
[7:  OST-Normal-13:17476]  mempool_free+0x7c/0x1a0
[7:  OST-Normal-13:17476]  sg_pool_free+0x6c/0x84
[7:  OST-Normal-13:17476]  __sg_free_table+0x88/0xbc
[7:  OST-Normal-13:17476]  sg_free_table_chained+0x40/0x4c
[7:  OST-Normal-13:17476]  scsi_free_sgtables+0x3c/0x7c
[7:  OST-Normal-13:17476]  scsi_mq_uninit_cmd+0x20/0x7c
[7:  OST-Normal-13:17476]  scsi_end_request+0xd8/0x304
[7:  OST-Normal-13:17476]  scsi_io_completion+0x88/0x160
[7:  OST-Normal-13:17476]  scsi_finish_command+0x17c/0x194
[7:  OST-Normal-13:17476]  scsi_complete+0xcc/0x158
[7:  OST-Normal-13:17476]  blk_mq_complete_request+0x4c/0x5c
[7:  OST-Normal-13:17476]  scsi_done_internal+0xf4/0x1e0
[7:  OST-Normal-13:17476]  scsi_done+0x14/0x20
[7:  OST-Normal-13:17476]  ufshcd_compl_one_cqe+0x578/0x71c
[7:  OST-Normal-13:17476]  ufshcd_mcq_poll_cqe_nolock+0xc8/0x150
[7:  OST-Normal-13:17476]  vendor_mcq_irq+0x74/0x88 [ufs-core]
[7:  OST-Normal-13:17476]  __handle_irq_event_percpu+0xd0/0x348
[7:  OST-Normal-13:17476]  handle_irq_event_percpu+0x24/0x74
[7:  OST-Normal-13:17476]  handle_irq_event+0x74/0xe0
[7:  OST-Normal-13:17476]  handle_fasteoi_irq+0x174/0x240
[7:  OST-Normal-13:17476]  handle_irq_desc+0x7c/0x2c0
[7:  OST-Normal-13:17476]  generic_handle_domain_irq+0x1c/0x28
[7:  OST-Normal-13:17476]  gic_handle_irq+0x64/0x158
[7:  OST-Normal-13:17476]  call_on_irq_stack+0x2c/0x54
[7:  OST-Normal-13:17476]  do_interrupt_handler+0x70/0xa0
[7:  OST-Normal-13:17476]  el1_interrupt+0x34/0x68
[7:  OST-Normal-13:17476]  el1h_64_irq_handler+0x18/0x24
[7:  OST-Normal-13:17476]  el1h_64_irq+0x68/0x6c
[7:  OST-Normal-13:17476]  __hwasan_check_x0_67043363+0xc/0x30
[7:  OST-Normal-13:17476]  ufshcd_queuecommand+0x5f8/0x7b4
[7:  OST-Normal-13:17476]  scsi_queue_rq+0xb88/0xea4
[7:  OST-Normal-13:17476]  blk_mq_dispatch_rq_list+0x640/0xe18
[7:  OST-Normal-13:17476]  blk_mq_do_dispatch_sched+0x47c/0x530
[7:  OST-Normal-13:17476]  __blk_mq_sched_dispatch_requests+0x158/0x1cc
[7:  OST-Normal-13:17476]  blk_mq_sched_dispatch_requests+0x68/0x9c
[7:  OST-Normal-13:17476]  __blk_mq_run_hw_queue+0x9c/0x11c
[7:  OST-Normal-13:17476]  __blk_mq_delay_run_hw_queue+0xa4/0x234
[7:  OST-Normal-13:17476]  blk_mq_run_hw_queue+0x130/0x150
[7:  OST-Normal-13:17476]  blk_mq_sched_insert_requests+0x208/0x3a0
[7:  OST-Normal-13:17476]  blk_mq_flush_plug_list+0x21c/0x4f0
[7:  OST-Normal-13:17476]  __blk_flush_plug+0x180/0x1d8
[7:  OST-Normal-13:17476]  blk_finish_plug+0x40/0x5c
[7:  OST-Normal-13:17476]  read_pages+0x420/0x4ac
[7:  OST-Normal-13:17476]  page_cache_ra_unbounded+0xec/0x288
[7:  OST-Normal-13:17476]  do_page_cache_ra+0x60/0x6c
[7:  OST-Normal-13:17476]  page_cache_ra_order+0x318/0x364
[7:  OST-Normal-13:17476]  do_sync_mmap_readahead+0x1a0/0x3c8
[7:  OST-Normal-13:17476]  filemap_fault+0x260/0x68c
[7:  OST-Normal-13:17476]  __do_fault+0x80/0x1b4
[7:  OST-Normal-13:17476]  handle_mm_fault+0x6b4/0x1530
[7:  OST-Normal-13:17476]  do_page_fault+0x3ec/0x5d4
[7:  OST-Normal-13:17476]  do_translation_fault+0x44/0x5c
[7:  OST-Normal-13:17476]  do_mem_abort+0x54/0xd8
[7:  OST-Normal-13:17476]  el0_ia+0x68/0xf4
[7:  OST-Normal-13:17476]  el0t_64_sync_handler+0xd0/0x114
[7:  OST-Normal-13:17476]  el0t_64_sync+0x190/0x194

After analyzing it, it seems that the stack buffer is running out of memory, 
so what do you think about increasing the size of DEPOT_POOLS_CAP to 32768?
Tell us, your opinion

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000401d96d04%24d991ad40%248cb507c0%24%40samsung.com.
