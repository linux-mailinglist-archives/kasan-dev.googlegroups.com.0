Return-Path: <kasan-dev+bncBDG6PF6SSYDRBYWMQCCAMGQERJ5UDXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id E1E60366C7F
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 15:19:30 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id jl27-20020a17090775dbb029037ccdce96e6sf5838902ejc.21
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 06:19:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619011170; cv=pass;
        d=google.com; s=arc-20160816;
        b=gC82JplwoY6iAthnJn7HUI1BWiKF6fxTPFSle6IWIvE7tpPB8y/BmpJ9PzRu/zRLaY
         +wtkHEzFLjyLJFF6m2yrp1Nhy1G1Xi3tkG2u77vkTOZov9BL56VbeoOgHXVCunLp/XdU
         XMaQ9LZs5ELNqUbzpZyaViQHEX8ycKis6jbLy+uXoCtSPVW4HEf3FmsRSTltLSM5gJ60
         6G0mL6SrTBSkeNHV9L91nN4MKgSQAaGBtZX0bNFK1NkfYBH38Y6YPXkezIbt6X1EivX2
         9He+FuFIkHmtcHe/JeBNYtdmNoBeUXK2QgFIHhZtgPR1D/ir4PGxEtVm8am0aU49EyHE
         IXBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:to:subject:dkim-filter:sender:dkim-signature;
        bh=7A3zFVpKcfoNCJYFUlNS5BxqftoPkf0+aPvIvbEpA8U=;
        b=sOEsi5GwD+Gfk+OjlQpFbUSjjV5A7ble7+4z0KlwQXokxQKL/llRfVFdsPQm3exc95
         sE/b47mwaCR0cL9TzKmarfPPW890c6bzwdtejbHxA0HDVlZJ+Qu3PJirhUgkh7u1GJUv
         gEaxSKn58J+1TfSizg+KQT1dJFOEJlXb0+r+PPuUrYxrHjZkcadNRCJ121+E2WKDtnoX
         aV1OVVougtnEuzOkgU1D/JxEa7MKQV++o9tg7TfQryPHv6intAE68ASiht1h4SEKSoPv
         M1rXzVnOkrR8jQi7x7PWbfVRLNlxza02Snm76i5m6rMpsWN7Zy0OKr4nq6XrdH7Eq6e8
         JEQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=bo8eBtJf;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:subject:to:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:cms-type:references
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7A3zFVpKcfoNCJYFUlNS5BxqftoPkf0+aPvIvbEpA8U=;
        b=k4WrzBOLy6OCuVxQEtFbmdKUbEUcfQE/zeUl3MdIMSpI9SMkD6iAk9I2mRHHoT5a6B
         J3qr3yzM+XL5gGnivy2ucWP17AuM8YzpTnwYYyOOrP+mxcMbDsHOkUxNzDOyAN0Okh2W
         iWqZteVIvzZ8+29Pl/sBh7cueCqnNThzwsl5hNkKlP8Rl2PnfoYehyatiKHN2i6gOFri
         VR3YGrDWlP8zfbedCD/+dAlSQWD9DR6y0P2v3eVrvTneeDOMLgQmCUCymp1iROjTkUDq
         Q3e33CTkfjU74TCdwh+0VbXUVKaGG9iltbhq9yO0MZ34zoyyVvR5XLKFZkDXdktWbWbo
         THJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:subject:to:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language:cms-type
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7A3zFVpKcfoNCJYFUlNS5BxqftoPkf0+aPvIvbEpA8U=;
        b=OjU5oc5Kdlump1dk4/J7E7KydKVPYRvePxIAp1tB3cedRP6eDcK3DJhc0r8hc3x8C0
         IUsNgor15QM37LULdrGcWwekSSUBUB7ZJoBPkc5zmpvC1QRixeb5ulctQSs1y5mtLWjx
         hDbm1zh/jSHjBO/yQ+koiiWX7YllxDzHNOX7WVq62uLC6lwMsH7eMKRLyy0yEuTTvYGp
         X4ewjzpiKr6tU3qFfLh9eue4I0fhRm1Uisb1k9VKXbKZkFkEPhALaXa1z11w0aCNUGyK
         urI+kbY2TjfrfYZGGfTE9S2KPdny95Z23Duu72Pj4o5xgAp/EFZLx9BUX+iZhocA+O8/
         kXsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gDeec8qdzYLp6ZVFnu4sDFEryHb99ExdzoRR5mEJVHxNhJx4I
	c/dly10NKwXcGNe/avqEAmw=
X-Google-Smtp-Source: ABdhPJz7EvOFSDuaKhzCa5PBYi8RHq4nLSe2g3pxqnNI6e1wdz3eWfRXmae9NvGWfm0j3z5Azz+F6A==
X-Received: by 2002:a05:6402:110b:: with SMTP id u11mr40263592edv.356.1619011170556;
        Wed, 21 Apr 2021 06:19:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4c2:: with SMTP id n2ls992010edw.2.gmail; Wed, 21
 Apr 2021 06:19:29 -0700 (PDT)
X-Received: by 2002:a05:6402:441:: with SMTP id p1mr38657938edw.298.1619011169548;
        Wed, 21 Apr 2021 06:19:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619011169; cv=none;
        d=google.com; s=arc-20160816;
        b=MZPBEHR5/fqGm2s+yQqXPBBhr2UEze0VJCk0sE3APAa87y7oeBS/A63hkn4JlI4bEl
         osOTAhmjJ7MGI5c+TJlLFtr24u9AaUKPkTRhzbMc7/Y7bPEq+DSzrTFRgGJq621JhJW9
         e0sUT5fj04mQPE6QY2GQGdtGPaZXPqormKykJk3fGc4fjm28ze6NgbL9mn3M7kI43eUw
         vJtbniHO09k9un38sKdCi6DfsQT8nuYhbfh1sSprayWbZ7m/gkDMtoJzf2rp1JJU1GA/
         74wbD3fR8CJIVXLrgYYHIotWvyb4kOJfytsKXrOkMK9fPTHW/gI25GRPuLMB4a9iXNpP
         n+zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:content-language:content-transfer-encoding
         :in-reply-to:mime-version:user-agent:date:message-id:from:cc:to
         :subject:dkim-signature:dkim-filter;
        bh=Ot7cKGhTeJnugaHB2Siy39xRoc8Vv0ZeioxMP3AeOZk=;
        b=0IAb1BP+GIrh79a4Y4WqBcRz9jGWW16a84t/r7QNjCEy7DqDrAMcgd5s+IZndUhdEy
         Zrz6VcXuZNKY3ZsfKd64tZb1J48Y1To/mlofphQkDYiV7+Pgmv0aHFAgEybCFQbFdG+Y
         mByLw6g2LH32rDpAzStcONAJs3QBgrOrfyOPnCf1Z2Ict/WfvFPVIqc/Yqm5NZ2jo+V2
         h8oSIhYVA6J8Ra1zKgw5ERQeXgy41jq3qmnOVlPTArDOoYGexU0+n4XZuXV9fy5CFfeP
         r3Ud0SYLicXxD/vIb0RsmxzObQZeK30WIaLD2xYdGFzRG6wFQqmifM49oqxHhAJ+ygJ3
         jBVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=bo8eBtJf;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id r21si243002ejo.0.2021.04.21.06.19.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Apr 2021 06:19:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20210421131928euoutp02357e2d85497dbdee2752d83659e31cb9~34hR5PaYB2936929369euoutp02U
	for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 13:19:28 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20210421131928euoutp02357e2d85497dbdee2752d83659e31cb9~34hR5PaYB2936929369euoutp02U
Received: from eusmges2new.samsung.com (unknown [203.254.199.244]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTP id
	20210421131927eucas1p239ff193b5fbcc096be2727a577ef0339~34hROYlPf2160021600eucas1p2I;
	Wed, 21 Apr 2021 13:19:27 +0000 (GMT)
Received: from eucas1p2.samsung.com ( [182.198.249.207]) by
	eusmges2new.samsung.com (EUCPMTA) with SMTP id 91.72.09444.F5620806; Wed, 21
	Apr 2021 14:19:27 +0100 (BST)
Received: from eusmtrp1.samsung.com (unknown [182.198.249.138]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20210421131927eucas1p1d279d753b66b18836beaa4e522427160~34hQnisY81054710547eucas1p1c;
	Wed, 21 Apr 2021 13:19:27 +0000 (GMT)
Received: from eusmgms2.samsung.com (unknown [182.198.249.180]) by
	eusmtrp1.samsung.com (KnoxPortal) with ESMTP id
	20210421131927eusmtrp1970bf2f206e75b9869cc91d8c56ad61a~34hQmVok41876118761eusmtrp1Z;
	Wed, 21 Apr 2021 13:19:27 +0000 (GMT)
X-AuditID: cbfec7f4-dd5ff700000024e4-c3-6080265fe6a5
Received: from eusmtip2.samsung.com ( [203.254.199.222]) by
	eusmgms2.samsung.com (EUCPMTA) with SMTP id B7.8A.08696.F5620806; Wed, 21
	Apr 2021 14:19:27 +0100 (BST)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20210421131925eusmtip2f9a903de11ac4c1b8dce99822f4f873d~34hPMgC2u1676516765eusmtip2l;
	Wed, 21 Apr 2021 13:19:25 +0000 (GMT)
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and
 si_perf to siginfo
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Alexander Shishkin
	<alexander.shishkin@linux.intel.com>, Arnaldo Carvalho de Melo
	<acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa
	<jolsa@redhat.com>, Mark Rutland <mark.rutland@arm.com>, Namhyung Kim
	<namhyung@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Alexander
	Potapenko <glider@google.com>, Al Viro <viro@zeniv.linux.org.uk>, Arnd
	Bergmann <arnd@arndb.de>, Christian Brauner <christian@brauner.io>, Dmitry
	Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, Jens Axboe
	<axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, Peter Collingbourne
	<pcc@google.com>, Ian Rogers <irogers@google.com>, Oleg Nesterov
	<oleg@redhat.com>, kasan-dev <kasan-dev@googlegroups.com>, linux-arch
	<linux-arch@vger.kernel.org>, linux-fsdevel <linux-fsdevel@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>, the arch/x86 maintainers
	<x86@kernel.org>, "open list:KERNEL SELFTEST FRAMEWORK"
	<linux-kselftest@vger.kernel.org>, Geert Uytterhoeven
	<geert@linux-m68k.org>, Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>
From: Marek Szyprowski <m.szyprowski@samsung.com>
Message-ID: <cf6ed5cd-3202-65ce-86bc-6f1eba1b7d17@samsung.com>
Date: Wed, 21 Apr 2021 15:19:25 +0200
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0)
	Gecko/20100101 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw@mail.gmail.com>
Content-Language: en-US
X-Brightmail-Tracker: H4sIAAAAAAAAA02SfUxbZRTGfe+9vb3gOi4F01dGcNbIIrpSnH+86iAaTLyCMxITsgwTKOOG
	kgFr+jEYH0tlAUuHwHCGrQEGUgUZG6UUNhAoA6HrNjosQT4sQxyBwVYYgaHMUKW7Tvnvd855
	nvc5J3kpXNhKBlFpmWpWmSlLF5O+RMfQ5p39iaHaJGn1QynS371GIp35Ag9tVQzx0aXpMhK1
	nm/hoS+WX0Hls0V8VHT7Kg/NT/Vg6MvVHhzVFq7zkdO+Hw0Ob2GocX4GQ7quxwTq7rETaLSr
	ikSVrhUSfTf+M4bqr/fxkLOvFkMF37cTqN1aCFCZa5xEtq/6MNRm/gZHd7ZsPPSn6R7vvWCm
	uaYZMH89qQDMVvUqztSaNUz3WTvJtDWGMaPDGsbcVEwyyw4Hn+kf0AGmxh7HrPSOkUyppQkw
	a+YQxjznxj71O+J7MIVNTzvBKsOjknzlg+d+AoqW8Ozfq0gtsO7TAx8K0m/Bwsll0stCuhHA
	m5ZsjtcBnDC+rAe+27wG4LxuhffMYF77gc8NGgB8cG6T5IpVAI3DC8CrCqCPwAHHCO7lQFoM
	3fdKca8Ip8coqOscwLwDko6Aerf+abaAjoIL97u2n6Uogn4Vts+e9LZfoJPhpPNvnJP4Q/uF
	OcLLPnQcNPcNPbXi9EvwqrsK51gEp+YuYt4sSHf6wo2hcZxb+wNY2OcEHAfAJZuFz3EwvPV1
	CcEZTgM467jM54oSAEcLzv/reBe6HE9I73Y4/Rps6Qrn2u/DJZMB87YhvRtOuP25JXbDio5K
	nGsLoK5IyKlDocF25b/Y6yNOvByIDTtOM+w4x7DjHMP/ubWAaAIiVqPKSGVVb2ayWRKVLEOl
	yUyVHD2eYQbbv/qWx7Z+DTQsrUr6AUaBfgApXBwomMnPSxIKUmQnc1jl8USlJp1V9YM9FCEW
	CZItzYlCOlWmZo+xrIJVPptilE+QFpNQfpESa152wSfUj6eOHj5dXVOc/bi+bEofaY045Ejs
	aY098OLl5+8uFrQtOZ3GlF5sUU6qlU1xE0ASjf+W9NEhR6Wi1+eNBT19Qh1jsSbUB0+XV6fx
	YxKKD+RO5kZ4NuwrB2OmPWHM5w9NdSGHQ6T5Nk1eeoPJZPw1flHxS9jFY6GLM68/R2u1zkcN
	o3vlAQmiwY2ZK7dR3N4od11+8XpdMinMHZNKc4Iii+5nRY/5CURnrJ+pjZcqH5yRv/3oQ7Ik
	XhEoir05Hg+WxlzI1aQgbtzwSHP+6Bg5a+vaxStd/nbXns3ejy0zsZ53sjpDtSnRgOr2d5j2
	GU9pcpGYUMllEWG4UiX7Bz8zoblEBAAA
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFjrKKsWRmVeSWpSXmKPExsVy+t/xe7rxag0JBj9XsVt03dvBZtGxaSar
	xd9Jx9gtVt/tZ7PYOGM9q0XjO2WLCQ/b2C3azmxntXh2ay+TRfvHvcwWC1q/sFtcOqlrcfTs
	XyaLFc/uM1l07PrKYrFn70kWi8u75rBZTL/zns1i6fWLTBaLDx5gtbh0YAGTRdOyrSwWW/e3
	Mlr037nOZnG89wCTxeZNU5ktzv89zmrxY8NjVgcZjzXz1jB6/P41idHj79yPzB4LNpV67Jl4
	ks1j8wotj8tnSz02repk83h37hy7x6HDHYwe804Gerzfd5XNo2/LKkaPz5vkPDY9ecsUwB+l
	Z1OUX1qSqpCRX1xiqxRtaGGkZ2hpoWdkYqlnaGwea2VkqqRvZ5OSmpNZllqkb5egl3F0yhHG
	gvX6FY/msDUw7lfvYuTkkBAwkdj0eSV7FyMXh5DAUkaJrVeXMEIkZCROTmtghbCFJf5c62KD
	KHrPKHFr7Qs2kISwQJTEpb/vmEFsEQElibeP+5hBipgFbnJILNn5hAmiYzqrxJpZH8A62AQM
	JbredoHZvAJ2Es9f7ALazcHBIqAqsfVhJUhYVCBJ4t7llcwQJYISJ2c+YQGxOQUCJTYdOAbW
	yixgJjFv80NmCFteYvvbOVC2uMStJ/OZJjAKzULSPgtJyywkLbOQtCxgZFnFKJJaWpybnlts
	pFecmFtcmpeul5yfu4kRmJ62Hfu5ZQfjylcf9Q4xMnEwHmKU4GBWEuG9X1uTIMSbklhZlVqU
	H19UmpNafIjRFOidicxSosn5wASZVxJvaGZgamhiZmlgamlmrCTOa3JkTbyQQHpiSWp2ampB
	ahFMHxMHp1QDE6PEzcfOpQEbemqLNNrkwriZhab/uSs7Q3hKj4JPFNMS2YVbnbMyKsQM/yb0
	ZXpdV0yaJ50cvuT2nRVXdk9LdpY8Yedd4bVpmcTDQPHCNwGXy92mvSllz34vrfPprva/kOeq
	zkdCuLJkJOX2r5x8zubXUvfUj4/nb7O0umD2teSWW74zf5ieXui8QyK/1wZHG1220Vsu2mOz
	/I59JL+38ZZPr3vOHiw4c8egYXKHocuv5cxrpzMZs+cvWRFm/f3/pA7Fl1G7Fnj6cxWmrwmw
	jub7nijC8lpT1HZSHNeJeLez17c9WfBgdaN8soGJs+jpWVIs2nI++n1yPEX2m+75Lt7ZFrxp
	s0jg09mGrZeVWIozEg21mIuKEwFIrZpe2AMAAA==
X-CMS-MailID: 20210421131927eucas1p1d279d753b66b18836beaa4e522427160
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20210420212618eucas1p102b427d1af9c682217dfe093f3eac3e8
X-EPHeader: CA
CMS-TYPE: 201P
X-CMS-RootMailID: 20210420212618eucas1p102b427d1af9c682217dfe093f3eac3e8
References: <20210408103605.1676875-1-elver@google.com>
	<CGME20210420212618eucas1p102b427d1af9c682217dfe093f3eac3e8@eucas1p1.samsung.com>
	<20210408103605.1676875-6-elver@google.com>
	<1fbf3429-42e5-0959-9a5c-91de80f02b6a@samsung.com>
	<CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
	<43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com>
	<dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
	<CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ@mail.gmail.com>
	<740077ce-efe1-b171-f807-bc5fd95a32ba@samsung.com>
	<f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
	<CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw@mail.gmail.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=bo8eBtJf;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as
 permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;       dmarc=pass
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

Hi Marco,

On 21.04.2021 13:03, Marco Elver wrote:
> On Wed, 21 Apr 2021 at 12:57, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
>> On 21.04.2021 11:35, Marek Szyprowski wrote:
>>> On 21.04.2021 10:11, Marco Elver wrote:
>>>> On Wed, 21 Apr 2021 at 09:35, Marek Szyprowski
>>>> <m.szyprowski@samsung.com> wrote:
>>>>> On 21.04.2021 08:21, Marek Szyprowski wrote:
>>>>>> On 21.04.2021 00:42, Marco Elver wrote:
>>>>>>> On Tue, 20 Apr 2021 at 23:26, Marek Szyprowski
>>>>>>> <m.szyprowski@samsung.com> wrote:
>>>>>>>> On 08.04.2021 12:36, Marco Elver wrote:
>>>>>>>>> Introduces the TRAP_PERF si_code, and associated siginfo_t field
>>>>>>>>> si_perf. These will be used by the perf event subsystem to send
>>>>>>>>> signals
>>>>>>>>> (if requested) to the task where an event occurred.
>>>>>>>>>
>>>>>>>>> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
>>>>>>>>> Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
>>>>>>>>> Signed-off-by: Marco Elver <elver@google.com>
>>>>>>>> This patch landed in linux-next as commit fb6cc127e0b6 ("signal:
>>>>>>>> Introduce TRAP_PERF si_code and si_perf to siginfo"). It causes
>>>>>>>> regression on my test systems (arm 32bit and 64bit). Most systems
>>>>>>>> fails
>>>>>>>> to boot in the given time frame. I've observed that there is a
>>>>>>>> timeout
>>>>>>>> waiting for udev to populate /dev and then also during the network
>>>>>>>> interfaces configuration. Reverting this commit, together with
>>>>>>>> 97ba62b27867 ("perf: Add support for SIGTRAP on perf events") to
>>>>>>>> let it
>>>>>>>> compile, on top of next-20210420 fixes the issue.
>>>>>>> Thanks, this is weird for sure and nothing in particular stands out.
>>>>>>>
>>>>>>> I have questions:
>>>>>>> -- Can you please share your config?
>>>>>> This happens with standard multi_v7_defconfig (arm) or just defconfig
>>>>>> for arm64.
>>>>>>
>>>>>>> -- Also, can you share how you run this? Can it be reproduced in
>>>>>>> qemu?
>>>>>> Nothing special. I just boot my test systems and see that they are
>>>>>> waiting lots of time during the udev populating /dev and network
>>>>>> interfaces configuration. I didn't try with qemu yet.
>>>>>>> -- How did you derive this patch to be at fault? Why not just
>>>>>>> 97ba62b27867, given you also need to revert it?
>>>>>> Well, I've just run my boot tests with automated 'git bisect' and that
>>>>>> was its result. It was a bit late in the evening, so I didn't analyze
>>>>>> it further, I've just posted a report about the issue I've found. It
>>>>>> looks that bisecting pointed to a wrong commit somehow.
>>>>>>> If you are unsure which patch exactly it is, can you try just
>>>>>>> reverting 97ba62b27867 and see what happens?
>>>>>> Indeed, this is a real faulty commit. Initially I've decided to revert
>>>>>> it to let kernel compile (it uses some symbols introduced by this
>>>>>> commit). Reverting only it on top of linux-next 20210420 also fixes
>>>>>> the issue. I'm sorry for the noise in this thread. I hope we will find
>>>>>> what really causes the issue.
>>>>> This was a premature conclusion. It looks that during the test I've did
>>>>> while writing that reply, the modules were not deployed properly and a
>>>>> test board (RPi4) booted without modules. In that case the board booted
>>>>> fine and there was no udev timeout. After deploying kernel modules, the
>>>>> udev timeout is back.
>>>> I'm confused now. Can you confirm that the problem is due to your
>>>> kernel modules, or do you think it's still due to 97ba62b27867? Or
>>>> fb6cc127e0b6 (this patch)?
>>> I don't use any custom kernel modules. I just deploy all modules that
>>> are being built from the given kernel defconfig (arm
>>> multi_v7_defconfig or arm64 default) and they are automatically loaded
>>> during the boot by udev. I've checked again and bisect was right. The
>>> kernel built from fb6cc127e0b6 suffers from the described issue, while
>>> the one build from the previous commit (2e498d0a74e5) works fine.
>> I've managed to reproduce this issue with qemu. I've compiled the kernel
>> for arm 32bit with multi_v7_defconfig and used some older Debian rootfs
>> image. The log and qemu parameters are here:
>> https://protect2.fireeye.com/v1/url?k=7cfc23a2-23671aa9-7cfda8ed-002590f5b904-dab7e2ec39dae1f9&q=1&e=36a5ed13-6ad5-430c-8f44-e95c4f0af5c3&u=https%3A%2F%2Fpaste.debian.net%2F1194526%2F
>>
>> Check the timestamp for the 'EXT4-fs (vda): re-mounted' message and
>> 'done (timeout)' status for the 'Waiting for /dev to be fully populated'
>> message. This happens only when kernel modules build from the
>> multi_v7_defconfig are deployed on the rootfs.
> Still hard to say what is going on and what is at fault. But being
> able to repro this in qemu helps debug quicker -- would you also be
> able to share the precise rootfs.img, i.e. upload it somewhere I can
> fetch it? And just to be sure, please also share your .config, as it
> might have compiler-version dependent configuration that might help
> repro (unlikely, but you never know).

I've managed to reproduce this issue with a public Raspberry Pi OS Lite 
rootfs image, even without deploying kernel modules:

https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-03-25/2021-03-04-raspios-buster-armhf-lite.zip

# qemu-system-arm -M virt -smp 2 -m 512 -kernel zImage -append "earlycon 
console=ttyAMA0 root=/dev/vda2 rw rootwait" -serial stdio -display none 
-monitor null -device virtio-blk-device,drive=virtio-blk -drive 
file=/tmp/2021-03-04-raspios-buster-armhf-lite.img,id=virtio-blk,if=none,format=raw 
-netdev user,id=user -device virtio-net-device,netdev=user

The above one doesn't boot if zImage z compiled from commit fb6cc127e0b6 
and boots if compiled from 2e498d0a74e5. In both cases I've used default 
arm/multi_v7_defconfig and 
gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabi toolchain.

Best regards

-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cf6ed5cd-3202-65ce-86bc-6f1eba1b7d17%40samsung.com.
