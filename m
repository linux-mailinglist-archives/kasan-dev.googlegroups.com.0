Return-Path: <kasan-dev+bncBDG6PF6SSYDRBP5L76BQMGQE5GYGJCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4036E36664A
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 09:35:28 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id w14-20020aa7da4e0000b02903834aeed684sf12775537eds.13
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 00:35:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618990528; cv=pass;
        d=google.com; s=arc-20160816;
        b=YJw8iMH4iGisVfmhD5owSRCxmIo6bElTowxvEc2fUm/Msl790RkOP6jCFbhj+qrXfc
         qI85aYWlQXigraboLlTajrI0au4VQL8joQkErLjYAaH1sEWaqTSpt3KIR0cWyQUFsQoP
         rrhr9xmo7pU/06fXFYOMNGa5C2muUAqrkj3qU+WL7UJn74TfqkEYcuDb6nranBhdQW70
         nB6hfSsrMCTm7lmx090BMWU/uaxOluKCyjZfrZCilX2YFoSeZDPBF42+V+KdBsfgYQNw
         PjKlmdcnHvkyg0eWG6UXqYt1TE12mKT0HqTMqaNEvfdkbRBb9XWtvAbHV6U1dZkiJRJn
         +WyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:cc:to:from:subject:dkim-filter:sender:dkim-signature;
        bh=/j3eyRWRk3SOmYd3t3MHHl+mAxW9ElfeHMZ0+f0iebE=;
        b=EE6xrrrhsARY0BXqDluszPL1EGuTUIgB8Y1v9rmJDkQXyBsyay0C75Z2mvTnhxqKw9
         RyfO/b/s0lYK1a3Rvvt6hakzT3vNMt4hq/haGwNpq7tG8bQUsPGyMoFkQ2EeNWIrj7iP
         eL3lY2hucoNvPgYQ/pudBrI4u9AGRi8k/UGFVjcsOvwdVu1ofheNuZ4stvaF/mCsPj8t
         3NyAPsMtPh6dcHkZpGfSv+EuOBUvUL/w+gQ2xDNg0Ksr0xNcRjQY8vFF+E5rFXLVajM5
         7UQjAOUc7oQ9DkkisL6GrFq5MweFVzyyIypxPIQ7Cx02e6l6XiP3cxICv08yCRDGwfG0
         LZdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="p3g/qabO";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:subject:from:to:cc:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:cms-type:references
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/j3eyRWRk3SOmYd3t3MHHl+mAxW9ElfeHMZ0+f0iebE=;
        b=F0cVv3BXSITbdgEFeBpnE814QHc2qQZjR2sXArav4+49mxrImnQZDa1FlVSKD3F1PO
         W/YdQsrx1xrWp0seM+38bYgxs3uzxG+L30TdSochNn0icCIfEN+Ly8vUAT40ytzmbUGq
         G6AJJS2tXD+93Z/VGVkbnIxHV8BiPMvU9tG3gFzje1PouiuMjXnvAC573vBECX9sZulZ
         KCnf5gTVO6olPtoGWBmD7J6xCrJvgYdlITD8zCRWc1ukH+/eVvp+mBJ3D4HUtz6ZD9Nr
         x3J5oFKIXsAtZwarvLxFuUa8zzL0t9HQIfp2FZqU9E5UP1illkUJSZET4kCpJqIFi36y
         A4tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:subject:from:to:cc:message-id
         :date:user-agent:mime-version:in-reply-to:content-language:cms-type
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/j3eyRWRk3SOmYd3t3MHHl+mAxW9ElfeHMZ0+f0iebE=;
        b=QogZn94M5SDuFDqDYil/U6lBmZ7TCx5bL/eredM2uQwKu23rBdl/zZ8PRnTcofzaLS
         bLj9w9KV/94sMT5eD9UoZzhBHhemmieT66qsUkF4Nz1d+bC8BuGd/OoZ4ZfjpjcD9KKR
         TzFS+c3xflQu/+iZQPvT2fjfmA2bEybQrjpdfRgDhtIzxm8RhrrJWh/Z1BpI2z5gCYVT
         rFGtsHeed3woRCTFYjIIMcOXqoYZSQxo59JeOOonTigd4nyMfcxMwJ9bN40qPMB6FQ95
         Qj65FTrXe++VOeUa01V9qsKnWYSrPAntKixy8gcXT0VocyIhug2VFpR5eL3sJ7Ymdp2H
         9KrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5322BlLS89yB8eUWMA7SaaBH9OgOG6lT1Zf/yrSs8MlaSP1rpMeb
	vrbopqIqp/KNeM6fVyXCs8Q=
X-Google-Smtp-Source: ABdhPJz/gaR1KBEcWVeoTT1ECLbNDXW+aslZ859Hrh5ZfGPDsdetLTIMKLmL8ODi55FerONGUKeAwg==
X-Received: by 2002:a17:906:b2d8:: with SMTP id cf24mr31545302ejb.305.1618990528050;
        Wed, 21 Apr 2021 00:35:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:e085:: with SMTP id gh5ls670678ejb.6.gmail; Wed, 21
 Apr 2021 00:35:27 -0700 (PDT)
X-Received: by 2002:a17:906:a20b:: with SMTP id r11mr11669417ejy.323.1618990527027;
        Wed, 21 Apr 2021 00:35:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618990527; cv=none;
        d=google.com; s=arc-20160816;
        b=Hy3XeoAz3OKcHg6lt+VIK28IZvTOEgf7tYFIOSFEqHQtNDRoXD+5dTuBtjo+E92JWl
         x49mO/jTauaCOjBEP6XQHuicrFuKDo0FetzUxyfJJZT816DgR2qsg73DL/epalq5slAu
         ULMUnscXUTJut/ETKssBbzzwB3bLvQdntOfWrdXPbKnJjVxyCjpiRc72CLQnd86asFH6
         xzeD9RjS8r32ntl3HhqxUkshClpvCm63QGCwxXcfm0x1poObz4lD53lY+KpUt5d7PTpr
         KnTrjzTbfUmaBvZKO8A0NlazJTfncdaBt6F05Dpe9sQUBGKPWuZE00xLs67tVpCynz0/
         kYlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:content-language:content-transfer-encoding
         :in-reply-to:mime-version:user-agent:date:message-id:cc:to:from
         :subject:dkim-signature:dkim-filter;
        bh=iNC2JGm8JQHaUP5EaOW6wGw0f6laDFIqRjY1Uqk+010=;
        b=KYA+TxHB0x5tMXCvAJDweCA83gjvOUYWt9aA7Vj5kBqet/vyoMYYTSSQuBgKuPNWK2
         JoA+x3XRzw+KoUADc5muz83z+orjo+kjMOPAEl/3wvuh41JqVURyU7NjT/ypEuwkL7j2
         qioZw7sKvv2OS5U30opR4HGuBm2anKXbDURnzQZH0xhLh218fp36y8aQV5GxwX3DdNli
         J7SMbAFelUPhuZb515eLDUIppeIXbsLRG0dPg6BTK0I8rEnHF5UiH9oksxzKN1hVHxHI
         Kn9GB7sAUGCxOtHshNtpQO/jVxyX2Bp+9TaVB4kddEasC4/3M0G2I2tRBx3Sj0DfRF+Z
         EeLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="p3g/qabO";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id m18si91861edd.5.2021.04.21.00.35.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Apr 2021 00:35:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20210421073526euoutp02cc85cd3a43f5282653e5393f05e62569~3z05UUQy31505415054euoutp02h
	for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 07:35:26 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20210421073526euoutp02cc85cd3a43f5282653e5393f05e62569~3z05UUQy31505415054euoutp02h
Received: from eusmges1new.samsung.com (unknown [203.254.199.242]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTP id
	20210421073525eucas1p20a9f991a5acec3b37967fcdb969dcaa8~3z0423X791121811218eucas1p2N;
	Wed, 21 Apr 2021 07:35:25 +0000 (GMT)
Received: from eucas1p2.samsung.com ( [182.198.249.207]) by
	eusmges1new.samsung.com (EUCPMTA) with SMTP id 30.05.09452.DB5DF706; Wed, 21
	Apr 2021 08:35:25 +0100 (BST)
Received: from eusmtrp1.samsung.com (unknown [182.198.249.138]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20210421073525eucas1p2de039236195308aa06fdee8b77fe01c7~3z04M84bi0689506895eucas1p2Z;
	Wed, 21 Apr 2021 07:35:25 +0000 (GMT)
Received: from eusmgms1.samsung.com (unknown [182.198.249.179]) by
	eusmtrp1.samsung.com (KnoxPortal) with ESMTP id
	20210421073525eusmtrp18822b2b5a245e7875a4a08a4bb655afb~3z04LUbIY3012430124eusmtrp1e;
	Wed, 21 Apr 2021 07:35:25 +0000 (GMT)
X-AuditID: cbfec7f2-a9fff700000024ec-91-607fd5bd2d9f
Received: from eusmtip2.samsung.com ( [203.254.199.222]) by
	eusmgms1.samsung.com (EUCPMTA) with SMTP id A8.32.08705.CB5DF706; Wed, 21
	Apr 2021 08:35:24 +0100 (BST)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20210421073523eusmtip246be203a67bd3d460f00b7af00eb9498~3z02pxT2U0194101941eusmtip2x;
	Wed, 21 Apr 2021 07:35:23 +0000 (GMT)
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and
 si_perf to siginfo
From: Marek Szyprowski <m.szyprowski@samsung.com>
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
Message-ID: <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
Date: Wed, 21 Apr 2021 09:35:22 +0200
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0)
	Gecko/20100101 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com>
Content-Language: en-US
X-Brightmail-Tracker: H4sIAAAAAAAAA02Sf1DTZRzHe76/9mW59WViPKGH3TjlsAOCs3q0DrPr8uvZeXrdJe0qWPrl
	R/LDbS7MREEOGjtAGZY6FFaRcIBuTRgymeIo1o4xYRyhHor8CAUb3FKLqFF++V7Ff6/P53l/
	ns/7/dxD4zILFUFn5uzn1DnKLDklJmzdf1yPdQweSX3R+Es80t+5RCGd9TSJgoZuEWq6fYxC
	350yk6hwJgodHy0RoRJPG4kmbzkw9HnAgSNT8SMR8rlj0Q+9QQw1TI5gSGd/TKAOh5tAA/Yz
	FDo5PEuhb4f6MfTNtU4S+TpNGDp6rpVArVeLATo2PEQhV3knhi5av8DR9aCLRHOWcfL1VWxz
	TTNg/5w3ADZ4NoCzJquW7ah0U+zFhnXsQK+WtTaWUuyM1ytinV06wNa4d7KzVwYptqKlEbAP
	rZGsdcKP7XhGIX5tD5eV+Qmnjk9KFWfYH5tF+wLPHqgr9JEFoFWmBzQNmfXQdnmXHoTQMqYB
	wAffhwr8CMDAiErghwBeufE8z7y8rsVB6IH4Sb8ewBablxSKAIBGmx7jVcsZBezy9uE8U0wC
	1Pv1FM9hjBz6xytwfgBnBmmoa+/CeBcSJgnWTW/lNQSzBtbqRhZnVzAfwZu+vxdZwoRC9+kJ
	gucQZhM8b6leZJxZDdv8Z3CBw+GtiVqMvx8yDjG8oG+nBNtvwlmbBxd4OZx2tYgEXgV7qsoI
	YaAIwFHveZFQlAE4cPQUEFSvwmHvPMU7xZkYaLbHC+3NcNpixIRnlMIb/lDBhBQabCdxoS2B
	uhKZoF4Lja4L/6291ufDjwO5cUk045I4xiVxjP/vNQGiEYRzWk12OqdJyOHy4jTKbI02Jz1u
	d262FTz51D0Lrl8vgbPTgTgnwGjgBJDG5WGSkfxDqTLJHuWnBzl1bopam8VpnGAlTcjDJY3V
	zSkyJl25n9vLcfs49b+nGB0SUYDFlN3TFm/vfvf3WOdYRFpUkssyNTbWbyi+vEnliWub8wdL
	PRvUivIJhWohrRzr21ihWvP17uqt9o5sc9T7D642sFkKQ9Mbwe3RJulm2+3D7pdD31MHKsNS
	0yT5PxbFSV/am/ccmL154C4WPBTTmxh/sMBXuEWFP61ySTMTa+/137Unj29smvlqWdGH3oQj
	huCybXkxnE6x463IDlPrgm7ttrdH71cOVddUbdglVQ6l6NXGjM4TaOVfny3Q0Vni33qche84
	B2elAVJW/zE5Wbrzqcj8OV1ybnR3Z45pYioEM5/rKR7ZEpZYn3zn5xXt65vJFzxTq39K+eDw
	/dKM1C9fma+SE5oMZcI6XK1R/gNsDtkAQwQAAA==
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFjrKKsWRmVeSWpSXmKPExsVy+t/xe7p7rtYnGPw+bGPRdW8Hm0XHppms
	Fn8nHWO3WH23n81i44z1rBaN75QtJjxsY7doO7Od1eLZrb1MFu0f9zJbLGj9wm5x6aSuxdGz
	f5ksVjy7z2TRsesri8WevSdZLC7vmsNmMf3OezaLpdcvMlksPniA1eLSgQVMFk3LtrJYbN3f
	ymjRf+c6m8Xx3gNMFps3TWW2OP/3OKvFjw2PWR1kPNbMW8Po8fvXJEaPv3M/Mnss2FTqsWfi
	STaPzSu0PC6fLfXYtKqTzePduXPsHocOdzB6zDsZ6PF+31U2j74tqxg9Pm+S89j05C1TAH+U
	nk1RfmlJqkJGfnGJrVK0oYWRnqGlhZ6RiaWeobF5rJWRqZK+nU1Kak5mWWqRvl2CXsaur+vZ
	Cz6KVSxpvMTawLhVqIuRk0NCwERiyZa9LCC2kMBSRomXhwIh4jISJ6c1sELYwhJ/rnWxdTFy
	AdW8Z5R487CRHSQhLBAlcenvO2YQm03AUKLrLUgRJ4eIgJLE28d9zCANzAI3OSSW7HzCBNH9
	ikli28qPQA4HB6+AncSSV54gDSwCqhLzO+6DDRIVSJK4d3klmM0rIChxcuYTsOs4Bewl1m6Y
	DWYzC5hJzNv8kBnClpfY/nYOlC0ucevJfKYJjEKzkLTPQtIyC0nLLCQtCxhZVjGKpJYW56bn
	FhvqFSfmFpfmpesl5+duYgSmp23Hfm7ewTjv1Ue9Q4xMHIyHGCU4mJVEeO/X1iQI8aYkVlal
	FuXHF5XmpBYfYjQF+mcis5Rocj4wQeaVxBuaGZgamphZGphamhkrifNunbsmXkggPbEkNTs1
	tSC1CKaPiYNTqoFpR83eJUpa2Zkrth3UFmJvi0o89WLNjLY3149aqCsXrnqX+ohhquiGI0k7
	2R7GfBdmTi1J1ZFNuiI1pY9D3PJ+xcmnIU0HmNIaWounLbfcNMVO4oaPcvaR/Wwv303z0qg+
	HVEXatT8oGDho+MOij2Pykz4v8vOfPH+k0dtulO+puoMGeFTUup+Dr6lDpOUL53x2LTOPJ/3
	UCt32onLnqqpGV5HHhqLZxlq/bnt+ElgepnG/Lvv/7SI260+zCN66vIRhYlvDrgrfNeen33i
	tU3Ng26eJ4aK77bMPnMjXJvL4cyr5YwGm7ySH99tuWnlxnRpkjjj2/aJ3YV6s/fIlb9+rnBv
	pbPS1/rr0wr2PwlTYinOSDTUYi4qTgQAWVBtBtgDAAA=
X-CMS-MailID: 20210421073525eucas1p2de039236195308aa06fdee8b77fe01c7
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
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b="p3g/qabO";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates
 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

On 21.04.2021 08:21, Marek Szyprowski wrote:
> On 21.04.2021 00:42, Marco Elver wrote:
>> On Tue, 20 Apr 2021 at 23:26, Marek Szyprowski 
>> <m.szyprowski@samsung.com> wrote:
>>> On 08.04.2021 12:36, Marco Elver wrote:
>>>> Introduces the TRAP_PERF si_code, and associated siginfo_t field
>>>> si_perf. These will be used by the perf event subsystem to send 
>>>> signals
>>>> (if requested) to the task where an event occurred.
>>>>
>>>> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
>>>> Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
>>>> Signed-off-by: Marco Elver <elver@google.com>
>>> This patch landed in linux-next as commit fb6cc127e0b6 ("signal:
>>> Introduce TRAP_PERF si_code and si_perf to siginfo"). It causes
>>> regression on my test systems (arm 32bit and 64bit). Most systems fails
>>> to boot in the given time frame. I've observed that there is a timeout
>>> waiting for udev to populate /dev and then also during the network
>>> interfaces configuration. Reverting this commit, together with
>>> 97ba62b27867 ("perf: Add support for SIGTRAP on perf events") to let it
>>> compile, on top of next-20210420 fixes the issue.
>> Thanks, this is weird for sure and nothing in particular stands out.
>>
>> I have questions:
>> -- Can you please share your config?
>
> This happens with standard multi_v7_defconfig (arm) or just defconfig 
> for arm64.
>
>> -- Also, can you share how you run this? Can it be reproduced in qemu?
> Nothing special. I just boot my test systems and see that they are 
> waiting lots of time during the udev populating /dev and network 
> interfaces configuration. I didn't try with qemu yet.
>> -- How did you derive this patch to be at fault? Why not just
>> 97ba62b27867, given you also need to revert it?
> Well, I've just run my boot tests with automated 'git bisect' and that 
> was its result. It was a bit late in the evening, so I didn't analyze 
> it further, I've just posted a report about the issue I've found. It 
> looks that bisecting pointed to a wrong commit somehow.
>> If you are unsure which patch exactly it is, can you try just
>> reverting 97ba62b27867 and see what happens?
>
> Indeed, this is a real faulty commit. Initially I've decided to revert 
> it to let kernel compile (it uses some symbols introduced by this 
> commit). Reverting only it on top of linux-next 20210420 also fixes 
> the issue. I'm sorry for the noise in this thread. I hope we will find 
> what really causes the issue.

This was a premature conclusion. It looks that during the test I've did 
while writing that reply, the modules were not deployed properly and a 
test board (RPi4) booted without modules. In that case the board booted 
fine and there was no udev timeout. After deploying kernel modules, the 
udev timeout is back.

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dccaa337-f3e5-08e4-fe40-a603811bb13e%40samsung.com.
