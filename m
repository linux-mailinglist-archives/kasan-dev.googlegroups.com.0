Return-Path: <kasan-dev+bncBCG4ZMWKSUNBBV6TUKRAMGQENOKWJGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 398016EECF9
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Apr 2023 06:34:33 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1a63d87bd46sf42741255ad.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Apr 2023 21:34:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682483671; cv=pass;
        d=google.com; s=arc-20160816;
        b=LfBLnF8NOM/P83DaTxdlc6NFLkSmSLDC3zE/bkwwpFNv3ltM20pE///ncxLKBeY4+f
         XUy8pXlNa6K99ivkw7UtmJPiF2OhfRC9pFh8HOIALUavnks+VoCARIrodAHEVYj0gyFQ
         IIoLcl6sinIJzsslXl0SOEKae+as3xu+zbaVNSxT2iyHqsy3rfq0H/Jt+1Ykwq5IPeF8
         2HXVPqE3DiFg13Kc5LHbFHCiUqAk7bpSvOcWsS60HgeXwb7oFUA9yAngtOzLuEZtB3Pj
         985jF5EPzKoB0kuZfMTy0VN9DE6WjrL2yXX76yCp5AnjDy3Onb295g2u3tE4+3GfE9HX
         sJyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:dlp-filter:cms-type
         :in-reply-to:mime-version:message-id:subject:cc:to:from:date
         :dkim-filter:sender:dkim-signature;
        bh=3CxM2q/vYpwM0bYjyM6OTFWcg7k6b9LqrUA6lP6zwac=;
        b=yQrG03/d92w6M5X3mBqsrnw/H1KKsBc646v8ny/unWd73oerBH8o4d7WDQ2xTKJeAq
         5jfpARrqrL7QtZ0OIZXRwZ9fETFY7ZvH6lkQwqMltCXsMBHqftiwQf8InpP+hNhmrAv9
         7xyAGqnZVoh+Z45DjlW2eqToTpa7MsBOOtXlGVF6KwF5WUWwxue0QuEJYFDWPoiFJWYD
         S0Nkw7P5tzXs85BrztR1D3hkbTo1RH2yeYdc2dpJY5VM654XJ1S16jNqjkY28Wc9q+Tw
         YAwII5XyuOzAK5lZw+ZPjNMPOQzjfuMkOcFGhYTWg7B3GgAakMSuzAit4nDqBrc1hgc/
         SPyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=slCRiE35;
       spf=pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.33 as permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682483671; x=1685075671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:dlp-filter:cms-type:in-reply-to
         :mime-version:message-id:subject:cc:to:from:date:dkim-filter:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3CxM2q/vYpwM0bYjyM6OTFWcg7k6b9LqrUA6lP6zwac=;
        b=ITlLpg8VKSU0+lAeiupyNN/3FNLmiNOw0zTq+e0r25j0ABpHb/ddB3iK5989kLpt/R
         4SVSO9RshQJin4/+kQvcx0sApluyXTao7wEpnAquUeUiybkfsgu7h8oNHNom8uA37+Rs
         eWOAQQVCpI4U5Hm02JlFKn7/WTzsRSRvx6ncQr8YH0AEAsM6KUkBIKWsZd9sMESXfOp2
         cINTmh05wxJwDWHzHs3ilUQa8I9WvRYbpXz1jRcQY5nnDEGsWOHU/pk90TOaZ6Pa/YPb
         HW/gywoZ9Er8UNIiNE3D5dskwfgcDzdAIGhpIqO0bTJ2lbeBD3R4xAKcv+/Z9uAGtlI8
         4eeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682483671; x=1685075671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :dlp-filter:cms-type:in-reply-to:mime-version:message-id:subject:cc
         :to:from:date:dkim-filter:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=3CxM2q/vYpwM0bYjyM6OTFWcg7k6b9LqrUA6lP6zwac=;
        b=dbinKXBIu0hZYtfVYhnQd/1sqiVzn9Vn1MhP7RqR5x35Q+4oeAhxVfB8CTlcr/OMFg
         6rIpNjaKzLy1wvcU1yJ2Ks2HDy0q0fkfRd79Yv8v9MykdhfSefv7T2UaCQ5Mvv2wf8Vx
         1xAIIlSA4CdiUuV+ZStgeKpXUCy743Kpu+Kyi9njzm+n7f+MXY42jc0/njR1Ljo3ecni
         wdz87DSYR9+0bOuQ27OaNTuScT44z3uEgQLffzgSy9pPrCOslIOiHWN6JMSmy8TZUfj3
         xYUDUYQzDtj8RuWKU0Aoll/wKVK0BMM2P4koNbj1rYl+8hWZX6kMMY3L0fgctgeWe8Ic
         rlsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9edrk1bqry6jQLP9ltRn0BZ/CKHN0dSvGmotw4zxhHgab+vELsk
	FtmCrurHYqHeqdkwLL1HOgg=
X-Google-Smtp-Source: AKy350aGQe0F0bCCyXsjTNJZbld0z8RvSMiLfqDMjDR/OkLGzzlBWaTzKjGXekE5n53RX6r1GOvdDA==
X-Received: by 2002:a17:902:db0f:b0:1a2:8c7e:f30a with SMTP id m15-20020a170902db0f00b001a28c7ef30amr6311158plx.1.1682483671408;
        Tue, 25 Apr 2023 21:34:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3d02:b0:23c:1f9b:df20 with SMTP id
 pt2-20020a17090b3d0200b0023c1f9bdf20ls1107153pjb.1.-pod-control-gmail; Tue,
 25 Apr 2023 21:34:30 -0700 (PDT)
X-Received: by 2002:a17:90a:9802:b0:24b:fd8d:536b with SMTP id z2-20020a17090a980200b0024bfd8d536bmr56997pjo.29.1682483670477;
        Tue, 25 Apr 2023 21:34:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682483670; cv=none;
        d=google.com; s=arc-20160816;
        b=nDAu4lQovJyTo9qnKwmuvi4y5RlIJRXSodjwubvYzSHcFatkPjod+eQ1HSxJ5RiD/m
         UKrvA4RaHLyClI278bXj9GyJUhjUV1FtwxIRt/+Uz+DAZ4qP8LlIxRmm+NcJBCijcrLR
         b+H/XFe2UFq15I+8RUixXSofTEs8IzxHFxzk/lAM0w58IDyuxcKeXKjGa6uYETyT8sN6
         GZ3XSo4fSz2XaLqttyi08GEhAzDZj+iQ7ZaS60rHS+PReb1BFH6ctk7tcpERXfq9CxJ1
         F5X/nnOipk0WadYiyyNsvXAnJEeZtfQbpjP7DzGSUwiKFnAm9KnxWmWv+eT9tBeqZT0h
         smYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:dlp-filter:cms-type:in-reply-to:mime-version:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-filter;
        bh=Uc3iZzzNNfvg7uppIGUgZCX7utPBuOk0LcUwE4Bt/og=;
        b=oBOT2Tnh/95AfGexAXfui6Us+waSAeIE1hsrvavNOGOBhlnlfdQp+upw2w6Km28PSl
         uywrURjR2cxUNxuxdXusbScR41A34eDrRxxYtGhS5vlhwMjj+dndOznPVKsecCvZ/hf9
         A8DXYQhjMylJ5FdWDp3v9lcUfm7ak+8FcQCuWhisKb2uVxWRm5EJxubTAuyKlrxIVBmh
         wKaJwpojMcdrcICvIhEZLPvF5PgnU7OaoatnCJxPYgeC/pehzK/ggwKCoRM23b4im1Nv
         oMGDzOhvaWgS909inI64WuRHKL7cNH1QSugQnuwBBJ2aTLuurIc90At0bH9b8Kw3FKjs
         Pqtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=slCRiE35;
       spf=pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.33 as permitted sender) smtp.mailfrom=youngmin.nam@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout3.samsung.com (mailout3.samsung.com. [203.254.224.33])
        by gmr-mx.google.com with ESMTPS id y7-20020a170902700700b001a64c3dded1si667706plk.12.2023.04.25.21.34.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 Apr 2023 21:34:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.33 as permitted sender) client-ip=203.254.224.33;
Received: from epcas2p3.samsung.com (unknown [182.195.41.55])
	by mailout3.samsung.com (KnoxPortal) with ESMTP id 20230426043428epoutp0393e19cdbbffa80c81ee18d3f78435eb1~ZYftuwCQA2967229672epoutp03q
	for <kasan-dev@googlegroups.com>; Wed, 26 Apr 2023 04:34:28 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout3.samsung.com 20230426043428epoutp0393e19cdbbffa80c81ee18d3f78435eb1~ZYftuwCQA2967229672epoutp03q
Received: from epsnrtp2.localdomain (unknown [182.195.42.163]) by
	epcas2p1.samsung.com (KnoxPortal) with ESMTP id
	20230426043427epcas2p1e434fe8627622612fa468b484c54edfb~ZYftMUKz82074420744epcas2p1q;
	Wed, 26 Apr 2023 04:34:27 +0000 (GMT)
Received: from epsmges2p4.samsung.com (unknown [182.195.36.101]) by
	epsnrtp2.localdomain (Postfix) with ESMTP id 4Q5mH71G0Vz4x9QC; Wed, 26 Apr
	2023 04:34:27 +0000 (GMT)
Received: from epcas2p4.samsung.com ( [182.195.41.56]) by
	epsmges2p4.samsung.com (Symantec Messaging Gateway) with SMTP id
	7A.E3.22936.3D9A8446; Wed, 26 Apr 2023 13:34:27 +0900 (KST)
Received: from epsmtrp1.samsung.com (unknown [182.195.40.13]) by
	epcas2p1.samsung.com (KnoxPortal) with ESMTPA id
	20230426043426epcas2p1aed491a1b7ecf266ac110858aaca4e65~ZYfsQjp5_2337823378epcas2p1I;
	Wed, 26 Apr 2023 04:34:26 +0000 (GMT)
Received: from epsmgms1p1new.samsung.com (unknown [182.195.42.41]) by
	epsmtrp1.samsung.com (KnoxPortal) with ESMTP id
	20230426043426epsmtrp12fa17229fa2862520ea0608791101322~ZYfsPq1Gr2119821198epsmtrp1x;
	Wed, 26 Apr 2023 04:34:26 +0000 (GMT)
X-AuditID: b6c32a48-475ff70000005998-c2-6448a9d33094
Received: from epsmtip2.samsung.com ( [182.195.34.31]) by
	epsmgms1p1new.samsung.com (Symantec Messaging Gateway) with SMTP id
	15.E4.27706.2D9A8446; Wed, 26 Apr 2023 13:34:26 +0900 (KST)
Received: from perf (unknown [10.229.95.91]) by epsmtip2.samsung.com
	(KnoxPortal) with ESMTPA id
	20230426043426epsmtip2ddd0be85797fb5fec6f67d51aa2818cd~ZYfr7aynj2923729237epsmtip2W;
	Wed, 26 Apr 2023 04:34:26 +0000 (GMT)
Date: Wed, 26 Apr 2023 14:06:25 +0900
From: Youngmin Nam <youngmin.nam@samsung.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: catalin.marinas@arm.com, will@kernel.org, anshuman.khandual@arm.com,
	broonie@kernel.org, alexandru.elisei@arm.com, ardb@kernel.org,
	linux-arm-kernel@lists.infradead.org, hy50.seo@samsung.com,
	andreyknvl@gmail.com, maz@kernel.org, kasan-dev
	<kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>,
	d7271.choe@samsung.com
Subject: Re: [PATCH] arm64: set __exception_irq_entry with __irq_entry as a
 default
Message-ID: <ZEixUYKPr3F0Y8Xn@perf>
MIME-Version: 1.0
In-Reply-To: <ZEfYJ5gDH4s6QJqp@FVFF77S0Q05N.cambridge.arm.com>
X-Brightmail-Tracker: H4sIAAAAAAAAA02Sf0xTVxTHc98r7z3cSp7V4U3dj6bNUHHQFlv6QNAlMPcy9weBacKyBV/b
	l5ZQ2q6vNdZlyhalhTJHE9HQgTJh8jOTQFNLETBg+BEW/BncjDhYnRmQQeeYZGzTtby6+N/n
	nPv9nnvOvYdARX5MTJSa7azNzJik2AZBYGQHlXa7ndYrlk5i1Nn22xi16j2LU4PjOuqvlWVA
	1c09xKjlizWAmh7w4lTtXCVOdTbPCqi2Rz8hVE94OoH69u5NhOprmEigTtxXv51Ed53rAnSf
	bwanm3oc9BXvBEb3dFRhdG/LcfqUvwMU4B+W5RhZRs/aJKxZZ9GXmg250v1FJXkl6kyFMk2Z
	RWmkEjNTzuZK898vSNtXaoo2LJUcZkyOaKqA4TipfE+OzeKwsxKjhbPnSlmr3mTVWNM5ppxz
	mA3pZtaerVQoMtRR4aEyo2v2CWoNZx1x1/pABViVV4NEApIqOFgVEVSDDYSIDAJYF+rG+eAx
	gFPf/Q344AmAV8Od6HPLDfePccsAgPfHzmN8MAfg6VC1IKYSkG/ClbZLCTHGyDQYGH8KYryZ
	3AZrQivrbpScRuC91UD0gCA2kQdg5wKMaYSkDE62TuE8b4QT9Q/XayaSe+D47BAa80LST8DW
	9gdYzAvJfOht5PjuNsGFMT/OsxjOf1UZ5zLYuXYrzkeg60FNfJpd0PfItd4bShrhnfBlnC8p
	g9fuCfh0EnSP/BtPC6G7UsQ7U+Da6W7A86uwv7kN5SU09PVK+BeZR+BYcEhQC173vTCM74XL
	eH4LNvU/xnxRO0puha1PCR53wEsheRNI6ADJrJUrN7BchlX1///qLOU9YH19U+kg+Pq3SPow
	QAgwDCCBSjcLhc539SKhnnEeZW2WEpvDxHLDQB39GS8qfkVnie6/2V6iVGUpVJmZSk2GWqGR
	bhH+7pbpRaSBsbNlLGtlbc99CJEorkCyl8TYZKNvb/6xyDL78a+Wa66CH4KIMZIlzDu1P0/n
	KRodqppaqBz+Y3IIs6Vm+gGy97P5n1tIgqOWrF86n8n07pcvDqq6Fi8Q3C83PEe9W7evvffs
	6qfaEa1VOwXkH9htioHGy6MzjRWf5wRK57Q1X+gC27OCG+frc1vkTk3KP6/NoPU7x4vecPmL
	dw82NBcng75F/13ckF185Zw3qWrt5sHu611F+DuaMxUXwEdMyvepDWHkpWbjsZXp456TS1to
	x8F8bY8nOTQV5jx1rsO3VhbB6sLon7vcpDiYccBa2LctIuv9ZvG6U1iNHHIV1haeubOzf/fw
	J6XnT6ADUgFnZJSpqI1j/gO9PQF8RwQAAA==
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFvrDLMWRmVeSWpSXmKPExsWy7bCSvO6llR4pBofuKVlMX3mZzeL7xOns
	FvtOJFv8/PKe0WLqwydsFu+X9TBaXNs7kd1iwsM2dovVix+wWKx4dp/JYtPja6wWS69fZLLY
	Oeckq0XLHVMHPo8189YweuycdZfdY8GmUo89E0+yeWxa1cnmsXlJvUffllWMAexRXDYpqTmZ
	ZalF+nYJXBlL97xmK1hsXrFr/nHmBsYLul2MnBwSAiYSFzpusnQxcnEICexmlHjV9IENIiEj
	cXvlZVYIW1jifssRVoii+4wS9zb9A0uwCKhKfFmxHsxmE9CV2HbiHyOILSKgLtGz6wvYVGaB
	a0wSvS2z2LsYOTiEBUIlVr+SAKnhFVCWOL38HDvE0NdMEpefvGOFSAhKnJz5hAXEZhbQkrjx
	7yUTSC+zgLTE8n8cIGFOATuJEw/2M09gFJiFpGMWko5ZCB0LGJlXMUqmFhTnpucWGxYY5qWW
	6xUn5haX5qXrJefnbmIER5CW5g7G7as+6B1iZOJgPMQowcGsJMLLW+meIsSbklhZlVqUH19U
	mpNafIhRmoNFSZz3QtfJeCGB9MSS1OzU1ILUIpgsEwenVAPTxnULqiZEHVl/I8qspezqp4AO
	9abV/7YkH9W9whZypSp/6dMJYUYOE/g4Sox2LG+rmKvEvlcr/NnxZubmN1sizZk/zAzW0mT4
	cJK1oursIf3VC5SllNgvCHgfYbn6/Zvo7sWT7GeWq/CEcTncOF8v0brY+iDXlccMVs7z7n/a
	JblD/JfG3/++7xxaM4snr2Fe/v3tCoULDwtebuN9Mn2xb9Xnp36TH1kK3F2Qndt+RefN7rS9
	tfc+KUoe3m5ypbKDa/rimogTld8uu55SXH7wsxpL5f+GWMsLNYUTmE975MYxXdYv+nyMc8+B
	oGfP1ppGZYcmRN4598NTWCP0RdLkpsQ8xmmrt3+qn/+L53TtWSWW4oxEQy3mouJEANnB8QMP
	AwAA
X-CMS-MailID: 20230426043426epcas2p1aed491a1b7ecf266ac110858aaca4e65
X-Msg-Generator: CA
Content-Type: multipart/mixed;
	boundary="----..lw3wo6cvlWZB4q78b.qMrUTx.UecKfd4NgAaoOFLJBmQ0t=_8920b_"
X-Sendblock-Type: AUTO_CONFIDENTIAL
CMS-TYPE: 102P
DLP-Filter: Pass
X-CFilter-Loop: Reflected
X-CMS-RootMailID: 20230424003252epcas2p29758e056b4766e53c252b5927a0cb406
References: <CGME20230424003252epcas2p29758e056b4766e53c252b5927a0cb406@epcas2p2.samsung.com>
	<20230424010436.779733-1-youngmin.nam@samsung.com>
	<ZEZhftx05blmZv1T@FVFF77S0Q05N>
	<CACT4Y+bYJ=YHNMFAyWXaid8aNYyjnzkWrKyCfMumO21WntKCzw@mail.gmail.com>
	<ZEZ/Pk0wqiBJNKEN@FVFF77S0Q05N> <ZEc7gzyYus+HxhDc@perf>
	<ZEfYJ5gDH4s6QJqp@FVFF77S0Q05N.cambridge.arm.com>
X-Original-Sender: youngmin.nam@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=slCRiE35;       spf=pass
 (google.com: domain of youngmin.nam@samsung.com designates 203.254.224.33 as
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

------..lw3wo6cvlWZB4q78b.qMrUTx.UecKfd4NgAaoOFLJBmQ0t=_8920b_
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Tue, Apr 25, 2023 at 02:39:51PM +0100, Mark Rutland wrote:
> On Tue, Apr 25, 2023 at 11:31:31AM +0900, Youngmin Nam wrote:
> > On Mon, Apr 24, 2023 at 02:08:14PM +0100, Mark Rutland wrote:
> > > On Mon, Apr 24, 2023 at 02:09:05PM +0200, Dmitry Vyukov wrote:
> > > > On Mon, 24 Apr 2023 at 13:01, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > >
> > > > > On Mon, Apr 24, 2023 at 10:04:36AM +0900, Youngmin Nam wrote:
> > > > > > filter_irq_stacks() is supposed to cut entries which are related irq entries
> > > > > > from its call stack.
> > > > > > And in_irqentry_text() which is called by filter_irq_stacks()
> > > > > > uses __irqentry_text_start/end symbol to find irq entries in callstack.
> > > > > >
> > > > > > But it doesn't work correctly as without "CONFIG_FUNCTION_GRAPH_TRACER",
> > > > > > arm64 kernel doesn't include gic_handle_irq which is entry point of arm64 irq
> > > > > > between __irqentry_text_start and __irqentry_text_end as we discussed in below link.
> > > > >
> > > > > TBH, the __irqentry_text annotations don't make much sense, and I'd love to
> > > > > remove them.
> > > > >
> > > > > The irqchip handlers are not the actual exception entry points, and we invoke a
> > > > > fair amount of code between those and the actual IRQ handlers (e.g. to map from
> > > > > the irq domain to the actual hander, which might involve poking chained irqchip
> > > > > handlers), so it doesn't make much sense for the irqchip handlers to be
> > > > > special.
> > > > >
> > > > > > https://lore.kernel.org/all/CACT4Y+aReMGLYua2rCLHgFpS9io5cZC04Q8GLs-uNmrn1ezxYQ@mail.gmail.com/#t
> > > > > >
> > > > > > This problem can makes unintentional deep call stack entries especially
> > > > > > in KASAN enabled situation as below.
> > > > >
> > > > > What exactly does KASAN need here? Is this just to limit the depth of the
> > > > > trace?
> > > > 
> > > > No, it's not just depth. Any uses of stack depot need stable
> > > > repeatable traces, so that they are deduplicated well. For irq stacks
> > > > it means removing the random part where the interrupt is delivered.
> > > > Otherwise stack depot grows without limits and overflows.
> > 
> > Hi Dmitry Vyukov.
> > Thanks for your additional comments.
> > 
> > > 
> > > Sure -- you want to filter out the non-deterministic context that the interrupt
> > > was taken *from*.
> > > 
> > > > We don't need the exact entry point for this. A frame "close enough"
> > > > may work well if there are no memory allocations/frees skipped.
> > > 
> > > With that in mind, I think what we should do is cut this at the instant we
> > > enter the exception; for the trace below that would be el1h_64_irq. I've added
> > > some line spacing there to make it stand out.
> > > 
> > > That would mean that we'd have three entry points that an interrupt trace might
> > > start from:
> > > 
> > > * el1h_64_irq()
> > > * el0t_64_irq()
> > > * el0t_32_irq()
> > >
> > 
> > Hi Mark.
> > Thanks for your kind review.
> > 
> > If I understand your intention corretly, I should add "__irq_entry"
> > to C function of irq_handler as below.
> 
> I'd meant something like the below, marking the assembly (as x86 does) rather
> than the C code. I'll try to sort that out and send a proper patch series after
> -rc1.
> 
> Thanks,
> Mark.
> 
After applying your draft patch,
I checked System.map and could see irq entries we expected were included as below.

ffffffc008000000 T _text
ffffffc008010000 T __irqentry_text_start
ffffffc008010000 T _stext
ffffffc008010000 t el1t_64_irq
ffffffc00801006c t el1t_64_fiq
ffffffc0080100d8 t el1h_64_irq
ffffffc008010144 t el1h_64_fiq
ffffffc0080101b0 t el0t_64_irq
ffffffc008010344 t el0t_64_fiq
ffffffc0080104d8 t el0t_32_irq
ffffffc008010670 t el0t_32_fiq
ffffffc008010928 T __do_softirq
ffffffc008010928 T __irqentry_text_end
ffffffc008010928 T __softirqentry_text_start
ffffffc008010fa0 T __entry_text_start
ffffffc008010fa0 T __softirqentry_text_end

And then, I confirmed callstack was cut correctly as below.

[   89.738326]I[5:NetworkWatchlis: 1084]  kasan_save_stack+0x40/0x70
[   89.738337]I[5:NetworkWatchlis: 1084]  save_stack_info+0x34/0x138
[   89.738348]I[5:NetworkWatchlis: 1084]  kasan_save_free_info+0x18/0x24
[   89.738358]I[5:NetworkWatchlis: 1084]  ____kasan_slab_free+0x16c/0x170
[   89.738369]I[5:NetworkWatchlis: 1084]  __kasan_slab_free+0x10/0x20
[   89.738379]I[5:NetworkWatchlis: 1084]  kmem_cache_free+0x238/0x53c
[   89.738388]I[5:NetworkWatchlis: 1084]  mempool_free_slab+0x1c/0x28
[   89.738397]I[5:NetworkWatchlis: 1084]  mempool_free+0x7c/0x1a0
[   89.738405]I[5:NetworkWatchlis: 1084]  bvec_free+0x34/0x80
[   89.738417]I[5:NetworkWatchlis: 1084]  bio_free+0x60/0x98
[   89.738426]I[5:NetworkWatchlis: 1084]  bio_put+0x50/0x21c
[   89.738434]I[5:NetworkWatchlis: 1084]  f2fs_write_end_io+0x4ac/0x4d0
[   89.738444]I[5:NetworkWatchlis: 1084]  bio_endio+0x2dc/0x300
[   89.738453]I[5:NetworkWatchlis: 1084]  __dm_io_complete+0x324/0x37c
[   89.738464]I[5:NetworkWatchlis: 1084]  dm_io_dec_pending+0x60/0xa4
[   89.738474]I[5:NetworkWatchlis: 1084]  clone_endio+0xf8/0x2f0
[   89.738484]I[5:NetworkWatchlis: 1084]  bio_endio+0x2dc/0x300
[   89.738493]I[5:NetworkWatchlis: 1084]  blk_update_request+0x258/0x63c
[   89.738503]I[5:NetworkWatchlis: 1084]  scsi_end_request+0x50/0x304
[   89.738514]I[5:NetworkWatchlis: 1084]  scsi_io_completion+0x88/0x160
[   89.738524]I[5:NetworkWatchlis: 1084]  scsi_finish_command+0x17c/0x194
[   89.738534]I[5:NetworkWatchlis: 1084]  scsi_complete+0xcc/0x158
[   89.738543]I[5:NetworkWatchlis: 1084]  blk_mq_complete_request+0x4c/0x5c
[   89.738553]I[5:NetworkWatchlis: 1084]  scsi_done_internal+0xf4/0x1e0
[   89.738564]I[5:NetworkWatchlis: 1084]  scsi_done+0x14/0x20
[   89.738575]I[5:NetworkWatchlis: 1084]  ufshcd_compl_one_cqe+0x578/0x71c
[   89.738585]I[5:NetworkWatchlis: 1084]  ufshcd_mcq_poll_cqe_nolock+0xc8/0x150
[   89.738594]I[5:NetworkWatchlis: 1084]  exynos_vendor_mcq_irq+0xac/0xc4 [ufs_exynos_core]
[   89.738638]I[5:NetworkWatchlis: 1084]  __handle_irq_event_percpu+0xd0/0x348
[   89.738647]I[5:NetworkWatchlis: 1084]  handle_irq_event_percpu+0x24/0x74
[   89.738656]I[5:NetworkWatchlis: 1084]  handle_irq_event+0x74/0xe0
[   89.738665]I[5:NetworkWatchlis: 1084]  handle_fasteoi_irq+0x174/0x240
[   89.738675]I[5:NetworkWatchlis: 1084]  handle_irq_desc+0x6c/0x2c0
[   89.738686]I[5:NetworkWatchlis: 1084]  generic_handle_domain_irq+0x1c/0x28
[   89.738697]I[5:NetworkWatchlis: 1084]  gic_handle_irq+0x64/0x154
[   89.738707]I[5:NetworkWatchlis: 1084]  call_on_irq_stack+0x2c/0x54
[   89.738717]I[5:NetworkWatchlis: 1084]  do_interrupt_handler+0x70/0xa0
[   89.738726]I[5:NetworkWatchlis: 1084]  el1_interrupt+0x34/0x68
[   89.738737]I[5:NetworkWatchlis: 1084]  el1h_64_irq_handler+0x18/0x24
[   89.738747]I[5:NetworkWatchlis: 1084]  el1h_64_irq+0x68/0x6c

Thanks for your work.
Please add me when you send the final patch so that I can test again.

> ---->8----

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZEixUYKPr3F0Y8Xn%40perf.

------..lw3wo6cvlWZB4q78b.qMrUTx.UecKfd4NgAaoOFLJBmQ0t=_8920b_
Content-Type: text/plain; charset="UTF-8"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZEixUYKPr3F0Y8Xn%40perf.

------..lw3wo6cvlWZB4q78b.qMrUTx.UecKfd4NgAaoOFLJBmQ0t=_8920b_--
