Return-Path: <kasan-dev+bncBDG6PF6SSYDRBYUI76BQMGQEEPQI3DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 33BB3366551
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 08:21:23 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id j16-20020adfd2100000b02901022328749esf12118607wrh.4
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Apr 2021 23:21:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618986083; cv=pass;
        d=google.com; s=arc-20160816;
        b=tXmW23VyWlNk0oL51UFbSkyIP2xq6hnaPrFnWbvK7TDt9tHeZWLPbo2c7kaBvpfo2F
         Fz2W6zQKFoil47hfPxZRpFw2QTV3EQahjoV8rXKXKKkEPCqqw0tOhKVwoU9a276IvsJm
         CTkcSIJvMRexxTBUV40PBHaLlkwWpq3oKyUTpbY0ILsL0whrnSR6yg/QnntanknFdirg
         Ot1H2DIy4JJOdsemZa/6V4UyTz8fo+WzUG4mnCeX8DYt9mIRR+d4984GWr3bpW4y/Gyw
         u0HIlBbUs7ipt9q1GFz0ogAIDwnuObGRrTtluH1wfyTB6cQk2Cp4tBzFfquFG1bWmhHV
         vZUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:to:subject:dkim-filter:sender:dkim-signature;
        bh=4L1nvEXBSM4HnHzOZ9hgFlJHRQDm74rP6CwFviDqO9k=;
        b=vgRzCVkDV1JPigPWj2BdboZi3Ze+EjHhGrvVzSIJp44djyqowyPVqv7qW9PCBzbcUM
         ObbsPyVTy1IJqkEO2lFwz2m1V4INzbA07pQ9R31GvYnKUXWorD9z+WyHvvaq81n2p4fB
         rK0ux5DKxa2nF/8TPdhbFQvNFKOUnNR3ZOFjA5g82jKTsqvXM/W2khlxVDGuuLqEdHmW
         vZlFKA7gJyVCjUCEeWn9fLT67x8BZeU9IPyh81BLZBAxJjBFkIGBAKiU0UspQeGBoFJu
         tmmHSvcUzXcjUeRbGue+UvfKA1+JvMIoAtATY3RWKgPZMwoMD8ti6TaDa+TH4yOq4HDG
         CN8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=UUhU0njs;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:subject:to:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:cms-type:references
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4L1nvEXBSM4HnHzOZ9hgFlJHRQDm74rP6CwFviDqO9k=;
        b=e34y3EZv6+crEnr19ReTpTFy1Ccdhr+2W9F+5OYXqo8+amSF3q6870Rjo+b5IcJwGv
         i2JJYIL0o/e74ltJ/wkoB0ljbUZdl8xzo0WO8bwpB37ZVRqoyTin8ZqB1jl0OwlCbcUF
         mPEKIPkhy4OeqeG07l5iH5KrHaBclTOoNkjq5nHA71GPv3IYVIe7Oz8Vo1NAvCxYLraC
         /DuIRvtBYor2CLUBCrUxjR+fI5TYhx57eiBwHBrAS9PHuprV31QTqJ/YBVQs784szeY+
         eN2hGlFEJAkF0PwnbSckGZsnhkflGyWuD+8XQBQDa1CbWkogj9fw7V30TdI6vYss/Nve
         7WZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:subject:to:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language:cms-type
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4L1nvEXBSM4HnHzOZ9hgFlJHRQDm74rP6CwFviDqO9k=;
        b=uk25fpGZWoPdmOGSqGNhkmBFz9Bw5GHBBuzjCxnzScBDFRiBkWXuqA1t4MZ0fEQW/0
         VIvc92CHlCAw+RgDalQ6TYQWs3sR72I/Ja4xgZ3Sx8l6JIf+GGUIQRzohSAUTWhID1vK
         v4zIJonUEofHiS/zMSN/3kmQTbn9tj2EMh4FrCfmqeHkFuZW1Tb9YLI3hMLZ2U/qSHVU
         W0Go7eaVeMjr3oJWr4aWOeFMx8G4qv7l4lkgkAPTsX3trfoVLsYT4cES6K+s5/BcRFt/
         gP4yNaJQUsg9pVIUIh+n6CuOtEsQrF3DHTYDrLPi8sXYGtB7/ywPy5Z8/9CAw/axQIi9
         QmwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531C0vJlSdjhThXi9jjIscXO/PhGcDno+jJsoTm9UkIUaPJ18rLr
	QpqwiJwojLTbKwxbzWdVjuM=
X-Google-Smtp-Source: ABdhPJwHPJFZTFnvkBu9x6aZYUW5cUnyNB8l6n/VqwvCoWzcpZaI4R5POXGE6wLu79Ku7taqgeA21A==
X-Received: by 2002:a5d:46c7:: with SMTP id g7mr24818249wrs.330.1618986082955;
        Tue, 20 Apr 2021 23:21:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fb47:: with SMTP id c7ls1451818wrs.0.gmail; Tue, 20 Apr
 2021 23:21:21 -0700 (PDT)
X-Received: by 2002:adf:ea84:: with SMTP id s4mr25137999wrm.142.1618986081847;
        Tue, 20 Apr 2021 23:21:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618986081; cv=none;
        d=google.com; s=arc-20160816;
        b=pgrVourEti9wi35ArfYgR97JNuhNuf1Kub4pJRDxWT3YOp+29vGDL8UaUP+aex8iIC
         bfgIW0l1uCUk6lvOk6MVL96KRkj5h3AYR8KfwxSNylKuiy+AsV9owNx5gH2A+an7Zu7S
         5k+wEjyexWqXfU1LaK7kCod/IIYTLxLoYJgS5pq3E5vb7JxvSGfKK9M17aov62phqBu3
         2H9ygw61dMt5fc64YkOY/78DAsckIHudIBFLEwoAdmPZe47eO4F0mlry5DkMUCnmO4qf
         SLxaplnvM0wKMTkbQQY72DiJQRqlEJiJ4uKHqhI9jPt7JGWFztehAfbCmyiDRWCMYOf/
         OBBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:content-language:content-transfer-encoding
         :in-reply-to:mime-version:user-agent:date:message-id:from:cc:to
         :subject:dkim-signature:dkim-filter;
        bh=nb+w+rdoA28nzc3PiQQASg827+Bh4VZL105LUhlZJgw=;
        b=Wr6uZ3HkIeJBh9cQZ1aaWHi1diqhZYsXdsv7cWggZV7gzs+Jwh0jVL6hNO1bmcx6zw
         4GVa9ZmxMB4SLvL+DIcnxzMcYoufi66ZwrESFeTL764h5wfXqcGLW30n6IJx0X89NQaX
         0gN215vl1s/GW+/C64wYTTJP5yF4tCqsEb4NdW+qLW0f9RVtq7l2bEYOUOHoJyiLXRNB
         5CwyJRcjIxLdDmwHjdD0TaGMlCnciZr9APMIDlAI37ZXaRNU8bIeuognRLlY0Ru8zauK
         mo42zJluCYZaB7TI4zCVE7TVHPVVvSirpLu64F3fhc2GiOFJMH2pT95QzoDXVZA+HHzR
         zUXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=UUhU0njs;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id s8si169649wrn.5.2021.04.20.23.21.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Apr 2021 23:21:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20210421062121euoutp020e62cc0445bd99e0eebbc1457460af6e~3y0NvYI483244632446euoutp02g
	for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 06:21:21 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20210421062121euoutp020e62cc0445bd99e0eebbc1457460af6e~3y0NvYI483244632446euoutp02g
Received: from eusmges3new.samsung.com (unknown [203.254.199.245]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTP id
	20210421062120eucas1p1a984a46f643e04b5eac4c5ef62b11893~3y0M_791a2067720677eucas1p1I;
	Wed, 21 Apr 2021 06:21:20 +0000 (GMT)
Received: from eucas1p1.samsung.com ( [182.198.249.206]) by
	eusmges3new.samsung.com (EUCPMTA) with SMTP id 96.B7.09439.064CF706; Wed, 21
	Apr 2021 07:21:20 +0100 (BST)
Received: from eusmtrp2.samsung.com (unknown [182.198.249.139]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20210421062120eucas1p2fb703eea4e1f49cad8352006e4719b08~3y0MciFZe1443814438eucas1p26;
	Wed, 21 Apr 2021 06:21:20 +0000 (GMT)
Received: from eusmgms2.samsung.com (unknown [182.198.249.180]) by
	eusmtrp2.samsung.com (KnoxPortal) with ESMTP id
	20210421062120eusmtrp26887e0b9ba14980efdf2d7c12325b2fe~3y0MbcH_U1307613076eusmtrp2h;
	Wed, 21 Apr 2021 06:21:20 +0000 (GMT)
X-AuditID: cbfec7f5-c03ff700000024df-db-607fc4604d36
Received: from eusmtip2.samsung.com ( [203.254.199.222]) by
	eusmgms2.samsung.com (EUCPMTA) with SMTP id 77.C2.08696.F54CF706; Wed, 21
	Apr 2021 07:21:20 +0100 (BST)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20210421062118eusmtip2f32d361770b68568e27779490831dcfc~3y0K36h5_2431324313eusmtip2f;
	Wed, 21 Apr 2021 06:21:18 +0000 (GMT)
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
Message-ID: <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com>
Date: Wed, 21 Apr 2021 08:21:17 +0200
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0)
	Gecko/20100101 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
Content-Language: en-US
X-Brightmail-Tracker: H4sIAAAAAAAAA01Se0xTZxzdd+/t7YUEvZQOvlhks07MXMCRLdsXdYRFltxNwsTMmMA2KeUG
	2aCyljI1OFscXW2caBOhNDyqUyQ8BMqzhPerY0DHYwxlIAroBlnbNNRNYYxR7tj47/x+5/y+
	c07yUbigjtxBJcvSWblMkiImvYmGvue2kPieC/Gvj+j3IN2DJhJpzfk8tKrv46Py6RwS1Riq
	eEjt2I2uPtLwkWawkYeeTLZi6BtXK45M2W4+Gu0PQb1DqxgqfTKDIW3zUwK1tPYTaKy5gER5
	U04S3Z4YwdB3nR08NNphwlBWST2B6tuzAcqZmiCR9dsODNWar+Pox1UrDz2rnuNFBDIVRRWA
	WVnWA2a10IUzJrOSabnWTzK1pfuYsSElYy67RDIOm43PdHVrAVPUH8M428ZJ5kpdGWCWzEGM
	ed6OHd0e630okU1JzmDl+8PjvU81dKrwtF6/M5WmPEIFZrbrgBcF6TfhbVMvTwe8KQFdCuCt
	pm7gIQS0G8DZXAVHLAFYuDDH37xwj1QQHHEHQOeftzBucAHoUmt5HpUfHQu7bcO4BwtpMbTP
	XcE9Ipwep6DW0o15CJIOgzq7jvRgHzocZruLNrwJeg9ssqs3HnqRToD3R9dwTuML+/PnCQ/2
	omNgZ1Prxjs4/RJstBfgHA6Ak/PFG4kgbfGGswYzxuWOhK3DDwkO+8FFa92/fQLhmmXz4CKA
	j2yVfG64DOBYlgFwqoNwyra8HpVat3gVVjXv59bvwsVqI+ZZQ3obvGf35UJsg/qGPJxb+0Ct
	RsCpg6HRevc/287hUfwqEBu3VDNuqWPcUsf4v68JEGUggFUqUpNYxRsy9stQhSRVoZQlhUpP
	p5rB+sce+Nv6tAmULrpCuwBGgS4AKVws9Jk5nxkv8EmUnD3Hyk+flCtTWEUXEFGEOMCnub7i
	pIBOkqSzn7NsGivfZDHKa4cKi1t5ecIR/YXvpz0PQzSxkXWfZb1VjA8NFLruBe50YaK325R/
	aQOcxwfOa4ODEqJ6hJWuT7pCWnLL5g72xFRVK6THJK+tia2TZw6VGKI7DkhF9pr34oqtqo8/
	DLucQdwR/qBbKB9PiX529v3d03La9IdTld77a8TPJbq1c6PPf7p/LFq6NL2cZhZoEm4aMIfp
	or4958ZaltcRdWLvTnfJK4lHr30V/LgKrAqdY22iE+/sqh3c6xD9cmnX4Upjvn/u7x/ETkT5
	Wz7KjNx7OK+PlA1aVh6M8+tfSMo0nViJvdDoPxmhFo2og47EmR2/HahZaHk87nuDDW//XlqQ
	HDXLZtz8ulxMKE5JwvbhcoXkH9fSTxdHBAAA
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFjrGKsWRmVeSWpSXmKPExsVy+t/xe7oJR+oTDNrPMVt03dvBZtGxaSar
	xd9Jx9gtVt/tZ7PYOGM9q0XjO2WLCQ/b2C3azmxntXh2ay+TRfvHvcwWC1q/sFtcOqlrcfTs
	XyaLFc/uM1l07PrKYrFn70kWi8u75rBZTL/zns1i6fWLTBaLDx5gtbh0YAGTRdOyrSwWW/e3
	Mlr037nOZnG89wCTxeZNU5ktzv89zmrxY8NjVgcZjzXz1jB6/P41idHj79yPzB4LNpV67Jl4
	ks1j8wotj8tnSz02repk83h37hy7x6HDHYwe804Gerzfd5XNo2/LKkaPz5vkPDY9ecsUwB+l
	Z1OUX1qSqpCRX1xiqxRtaGGkZ2hpoWdkYqlnaGwea2VkqqRvZ5OSmpNZllqkb5egl7HtYANz
	wVHhirULprM0MN7n72Lk5JAQMJH4cnENC4gtJLCUUaJ3fS1EXEbi5LQGVghbWOLPtS62LkYu
	oJr3jBJ71r9mA0kIC0RJXPr7jhnEFhFQknj7uI8ZpIhZ4CaHxJKdT5ggOrYySWw6/4IdpIpN
	wFCi620XWDevgJ1E65d5jCA2i4CqxI63jWDrRAWSJO5dXskMUSMocXLmE7DzOAUCJQ7u2MsE
	YjMLmEnM2/yQGcKWl9j+dg6ULS5x68l8pgmMQrOQtM9C0jILScssJC0LGFlWMYqklhbnpucW
	G+kVJ+YWl+al6yXn525iBCaobcd+btnBuPLVR71DjEwcjIcYJTiYlUR479fWJAjxpiRWVqUW
	5ccXleakFh9iNAX6ZyKzlGhyPjBF5pXEG5oZmBqamFkamFqaGSuJ85ocWRMvJJCeWJKanZpa
	kFoE08fEwSnVwLT3i7mHpPEKxg1z7HzZ20UcnJ8WLOVbkhZyTk7+W5hE1uwZbm/MWOJ3FbO5
	rumxS7+82E+jwuF+wQQx8ckRdX82vkvtPzAz1VTRez+D4jFbW+ZlkYJmKS4LT3/Ynrsx1iff
	ZmXNBL3gfPEAwanN3A35l43s18r6f+PzWpVat0/4iKGHZhx3x1Zzt+JZfuEvHM5OKQ1iymIt
	Prn5x+KPL4y15dk0/K6vTZZ38Dn+7rbnzW9xN3ZMiVj3Zb139K0JbeeSfzClzZWQUBZ7miza
	HbaVJZit62qEW+KK277i4qfOCa5a9+K+/KmV+5I2Pdz0deqffeLRUkuVhFaYTDlydnKRqojZ
	N1/Ff6JnN531UWIpzkg01GIuKk4EAPvESsjZAwAA
X-CMS-MailID: 20210421062120eucas1p2fb703eea4e1f49cad8352006e4719b08
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
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=UUhU0njs;       spf=pass
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

Hi,

On 21.04.2021 00:42, Marco Elver wrote:
> On Tue, 20 Apr 2021 at 23:26, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
>> On 08.04.2021 12:36, Marco Elver wrote:
>>> Introduces the TRAP_PERF si_code, and associated siginfo_t field
>>> si_perf. These will be used by the perf event subsystem to send signals
>>> (if requested) to the task where an event occurred.
>>>
>>> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
>>> Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
>>> Signed-off-by: Marco Elver <elver@google.com>
>> This patch landed in linux-next as commit fb6cc127e0b6 ("signal:
>> Introduce TRAP_PERF si_code and si_perf to siginfo"). It causes
>> regression on my test systems (arm 32bit and 64bit). Most systems fails
>> to boot in the given time frame. I've observed that there is a timeout
>> waiting for udev to populate /dev and then also during the network
>> interfaces configuration. Reverting this commit, together with
>> 97ba62b27867 ("perf: Add support for SIGTRAP on perf events") to let it
>> compile, on top of next-20210420 fixes the issue.
> Thanks, this is weird for sure and nothing in particular stands out.
>
> I have questions:
> -- Can you please share your config?

This happens with standard multi_v7_defconfig (arm) or just defconfig 
for arm64.

> -- Also, can you share how you run this? Can it be reproduced in qemu?
Nothing special. I just boot my test systems and see that they are 
waiting lots of time during the udev populating /dev and network 
interfaces configuration. I didn't try with qemu yet.
> -- How did you derive this patch to be at fault? Why not just
> 97ba62b27867, given you also need to revert it?
Well, I've just run my boot tests with automated 'git bisect' and that 
was its result. It was a bit late in the evening, so I didn't analyze it 
further, I've just posted a report about the issue I've found. It looks 
that bisecting pointed to a wrong commit somehow.
> If you are unsure which patch exactly it is, can you try just
> reverting 97ba62b27867 and see what happens?

Indeed, this is a real faulty commit. Initially I've decided to revert 
it to let kernel compile (it uses some symbols introduced by this 
commit). Reverting only it on top of linux-next 20210420 also fixes the 
issue. I'm sorry for the noise in this thread. I hope we will find what 
really causes the issue.

Best regards

-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/43f8a3bf-34c5-0fc9-c335-7f92eaf23022%40samsung.com.
