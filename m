Return-Path: <kasan-dev+bncBDG6PF6SSYDRBLMKQCCAMGQEGOO2E3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id D9A0336698B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 12:57:49 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id o14-20020a5d474e0000b029010298882dadsf12459891wrs.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 03:57:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619002669; cv=pass;
        d=google.com; s=arc-20160816;
        b=tobT4Sz29uVP6cG6k+cencgJspEfTKcTvO71ow6WsisXp9PiSUExAM9/qEfkApTJj8
         fWa6OPn0PbWz90mTrd75+E1x/mVGlsZZVl+S9O18ZKj92LtYL9vv1Uldd0vgI2kBNgOy
         zFDRlUj2W88ackGWEMwsX/nZPoR5nScpdMizE0xPGIG78tpQiAV8q9DIWHQjCx7aXbta
         umnewHjNuw33eztEwSJoXFbvbKJ1ot45FaQcbLYXSj3OnINiHayA6tFa+H7aQKbCkJgG
         ni+cp712wBzKkdyqmussth4qiLdUa5j6EMulKX6kiDJY5V2lSU5kAm2xp1XkRDIjNsvu
         tp5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:cc:to:from:subject:dkim-filter:sender:dkim-signature;
        bh=OahrriO+fAIVjCpMzOEMXco8auWsDRIPnkCE1WkgycE=;
        b=bDCgm+aAVma6jlLqkz1SBEsDxR8xaM9bfR8KsmrZ+hWyjLDnV0iBo+/gMaKT/F2WFm
         wL52Sq1tkeg10qpk7PLV8yaBVFf4aTa0GnYbHTRSdKuVo+vdMZsSruSszpj9GyI3OGXC
         neTccvWEu0d6qmn4U8AHP8LgfGMKWEbO9ZO3YYu3K3SJkqOHYkn/nmKoFjaZAdmzSdGi
         DAUfaJMy+/2V/OlEnalCTLRgGUYkY39Rc6lrjOid+VR3pZpmM5cl5rk8+p4nSHo0lZAG
         ijvbyuHBhw6RzI1AV67/+LuQl5UrqRR7pJm/pdF8jL7A7vNttlq4l+wvNfIUOak9+pMS
         qsXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="nDEBZrE/";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dkim-filter:subject:from:to:cc:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:cms-type:references
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OahrriO+fAIVjCpMzOEMXco8auWsDRIPnkCE1WkgycE=;
        b=gnYmlHULhRnNpejGnrsy2iG+6p4Lo4Iniq90R75jsqZhR1Gr1TXC28/NqolEwY2ve9
         XI+4Qu+kA0K2uvFSkaK0APyn8wVFLCo2JjK9zQzdSCbLZLDPnJD0JkT77+T6iLOjlvm2
         5+fuexsk/WXwGiLSEK8nttQydi7vJa0gUOc7P3VlAU9+UtMC9QmL+UALMykstmLcKJ2k
         krSn8SJti3SkTVVk/Iw3pGfhYA3Mt+SW48BYyRIGIWg57TkAmWpS8TDgX0w4vunehNC9
         SxB6X9HYrczp6O5D4RucnnhZ7MH9Y6ENrTPzJW7cGKwEHrXEUOdsbOnzD7A7XbdyVqXI
         23DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dkim-filter:subject:from:to:cc:message-id
         :date:user-agent:mime-version:in-reply-to:content-language:cms-type
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OahrriO+fAIVjCpMzOEMXco8auWsDRIPnkCE1WkgycE=;
        b=Qd5qjjafZk4XPswK4ptbm2SkaAXaERcU4J9ONKCSUAEX5KP2qCIjkd8uJlIqhdZxuP
         3SaP2SeEZZ1zZqhATvnQbycibvXgExp0ZDIQnluJN9otO2VWY1nPb2W2HlnJTwmhuAIb
         dYyw8dGR7NpfKRobf2grGjumDkHNS93rdTijlzps1a4NMszhU+pEPLTV37Ux3lOM9Gsb
         w/4lXiY11VsG6VW+dMkIMpM/1+5ri/n8iKhuMohsdnjIO9rEEd7JkwIEfg1wo51Ppw5A
         JgmCrEUp+FOCs505pQg7Xp8spTbG96emxATkoAXpgrbcN71X8wdrQ7u/7L2iVX0+JTr+
         FcQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Xe8N4s0h+AG8OalWd1sWoieErmF699PMyGnS3+i2LxQN1PqdF
	/0IWsmKYyGlEYlKdN71e0g8=
X-Google-Smtp-Source: ABdhPJwc4Ax7EDGwglFlBVh/jI4uWwPT5YbJkwn/dwHTXpRvim0gjT2IsRQjPEBR9QsOtgAG1HkuPQ==
X-Received: by 2002:adf:e741:: with SMTP id c1mr26271218wrn.49.1619002669607;
        Wed, 21 Apr 2021 03:57:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fb47:: with SMTP id c7ls2459240wrs.0.gmail; Wed, 21 Apr
 2021 03:57:48 -0700 (PDT)
X-Received: by 2002:a5d:650f:: with SMTP id x15mr26438795wru.315.1619002668833;
        Wed, 21 Apr 2021 03:57:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619002668; cv=none;
        d=google.com; s=arc-20160816;
        b=EiBfZSO/glrO3BIqhyhK2wVRhuoG5DDYyAMERqGFqSjL6/DRXVacTPySTgM9XBAZ/M
         v9BuG4me+nU+mzEoalN+7aG1ZpEz7suWGANNoWsJbyllL4NMfDbtFjQU3JmCjLSe5B35
         cPd1W9Q4dREzbrhpq4YswsEyx6iAXL1PW5FmAeo87II4TYRD28YcoTHsDAy8hne1kcMf
         SaP/KL1ousfqdkP1R3fK32m+QCMpBz73ZG2J08kpxolMy2KkB/T+z7AeipBkIgfUwXEW
         7W6vBRkvCBMeFahlTFAPvEzBfQNiaDpb6H3nQ0LW8/xwYRNWIo5B/qZ09ukDLgNsKlZe
         Twyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:cms-type:content-language:content-transfer-encoding
         :in-reply-to:mime-version:user-agent:date:message-id:cc:to:from
         :subject:dkim-signature:dkim-filter;
        bh=fm1eqmpbNzHOboUTj3NSBQeDomNm2Q05nCq64X6M2Hc=;
        b=M/59QpXZhwgabt5tWaYc8ZwbhOBBBrb11ryrosIzwWL9Fx5ESumKYTrUsEslkv950Z
         iwunlkCtLPi8rIOPCXEwUrGXm20LUiIf9sBHXmyaSXZYk+AImnyQefE70nUQiQDwO2Pk
         WGNecgwReki3oyd+JL3Q72WhkEBFbcBtLmG2hqlO6zEuvJTpInGhvC02zY0Q97QDV6rO
         Fw0yA99san3mW4xcky3+YzfeE94p4YjkJgpvIq2r2RgPPohB2Im8ZPhIlcNmPQ8ZOSeC
         dSCpdhnNZGHIykuD2cMGFKBGeshuV/TbynJuMPGawogBgf7ySw/lZCgJvYQr9Pgccf01
         OQNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="nDEBZrE/";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id 5si244665wrj.4.2021.04.21.03.57.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Apr 2021 03:57:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20210421105748euoutp0225a1ed91864a22b3b05b6cea619fae5a~32llkWTS20575505755euoutp02B
	for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 10:57:48 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20210421105748euoutp0225a1ed91864a22b3b05b6cea619fae5a~32llkWTS20575505755euoutp02B
Received: from eusmges3new.samsung.com (unknown [203.254.199.245]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTP id
	20210421105748eucas1p1adc3a75c330e83af5575c178adb64d6b~32llKz6si0447104471eucas1p1C;
	Wed, 21 Apr 2021 10:57:48 +0000 (GMT)
Received: from eucas1p2.samsung.com ( [182.198.249.207]) by
	eusmges3new.samsung.com (EUCPMTA) with SMTP id A6.DD.09439.B2500806; Wed, 21
	Apr 2021 11:57:48 +0100 (BST)
Received: from eusmtrp1.samsung.com (unknown [182.198.249.138]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20210421105747eucas1p2f2130bcbed85f4972ad6cda151f0cd5d~32lkjLz4s2534425344eucas1p2O;
	Wed, 21 Apr 2021 10:57:47 +0000 (GMT)
Received: from eusmgms1.samsung.com (unknown [182.198.249.179]) by
	eusmtrp1.samsung.com (KnoxPortal) with ESMTP id
	20210421105747eusmtrp1f4730e935f9870bd197504e8e0ce1ca6~32lkiDURH0781807818eusmtrp1H;
	Wed, 21 Apr 2021 10:57:47 +0000 (GMT)
X-AuditID: cbfec7f5-c03ff700000024df-9e-6080052b1b7d
Received: from eusmtip2.samsung.com ( [203.254.199.222]) by
	eusmgms1.samsung.com (EUCPMTA) with SMTP id AE.08.08705.B2500806; Wed, 21
	Apr 2021 11:57:47 +0100 (BST)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20210421105745eusmtip2c57c80c6fb506a4f9029fd86aac48b86~32ljFqDMu0666906669eusmtip2V;
	Wed, 21 Apr 2021 10:57:45 +0000 (GMT)
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
Message-ID: <f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
Date: Wed, 21 Apr 2021 12:57:45 +0200
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0)
	Gecko/20100101 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <740077ce-efe1-b171-f807-bc5fd95a32ba@samsung.com>
Content-Language: en-US
X-Brightmail-Tracker: H4sIAAAAAAAAA01SfUwbZRjnvbtej87CUVDeAFFTlMlkZUR0r2xuIzJzauLYP5pMzKjjBBTY
	0lLnpjNsjrZrkK9lGVRgRDPsWBFWYIUGsHzIWRllKzKwaUEyGFDTTT7d2OqknFP++z2/j/ye
	J3koXNJMRlDZefmsIk+eIyVFxNX++0Nb4wQF6dtuvId0420k0poqBchX3i9El90lJLpS0ShA
	J+9Eo9JJtRCpr5kF6LazE0Oa+U4c1RYuCZHDthX9NOjDkOH2BIa0lmUCdXTaCDRsqSLReddd
	El0cvYGh77qtAuSw1mLoVF0rgVp/LASoxDVKIu5rK4aaTedwNOTjBOhe0y3BnijGWGMEzIPV
	csD4qudxptakYjrKbCTTbNjCDA+qGFP9GZK5Y7cLmZ5eLWBqbPuZu10jJFPcUg+YRdPTjGnK
	i6UGHxDtzGBzsj9lFfG70kVZg/YR/Eix9LP7K4ugAHgidSCQgnQiPD3bQOqAiJLQBgCv/bUq
	8AsSegnAyx3ZvLAIYNVpN/E44Vkox3jhewBnuTmCH+YBbB/uWneF0gdgr/067scknQB1Xh3p
	x2G0FHpvFeP+AE6PUFDb3ov5BTG9C077Lq2HCfp5eKb14nr4SfpD+JvjEc57QqCtcmrdE0jv
	hjNWs9CPcfoZaPZW4TwOh86pC+vrQbpdBPuLOZLfOwXeXKj+F4dCD9ci5HEUHDhbRPCBrwCc
	tDcI+aEIwOFTFYB37YAu++pamlqriIWNlnieToaeJj3mpyEdBMe8IfwSQbD86nmcp8VQq5bw
	7hio5374r7b7ugMvBVL9htP0G87RbzhH/39vLSDqQTirUuZmssqX8tijMqU8V6nKy5QdOpxr
	Amt/PfA3t9wGDJ55WQ/AKNADIIVLw8QTJ75Il4gz5MeOs4rDBxWqHFbZAyIpQhoutrQaD0ro
	THk++wnLHmEVj1WMCowowDJEJfqHD5McNfuoMJ3mQmFTnH5vcEpFyIujv2jgc9VvREEOO/sx
	eHvsgSnZfE7yxKWuVKvmqRPf7BS+/5F8acJtXix168zupmcX4j5I2lTXl+NUp3GbIxKsbxqy
	UjU/u99CxiG03ZcSrZKEjqRsc/0R8G1boHNWs4qSWxLVuUmfu2Z2FA1H9335biz+SBlvLqwb
	q6xVY3MDFmcZo41xrnRUjv85V5cQOykLH785YOa2b9pti2g4dOXVd7Ij849lBe1r140up73w
	enBZrGXzdMf+5n6uZs7TGHBPHWF8OUrQ8spM2srJ46/FjxX8rjjaTccEpPbJEut7p/dk/don
	bZBJCWWWPGELrlDK/wEppw4HRgQAAA==
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFjrOKsWRmVeSWpSXmKPExsVy+t/xe7rarA0JBgs7hS267u1gs+jYNJPV
	4u+kY+wWq+/2s1lsnLGe1aLxnbLFhIdt7BZtZ7azWjy7tZfJov3jXmaLBa1f2C0undS1OHr2
	L5PFimf3mSw6dn1lsdiz9ySLxeVdc9gspt95z2ax9PpFJovFBw+wWlw6sIDJomnZVhaLrftb
	GS3671xnszjee4DJYvOmqcwW5/8eZ7X4seExq4OMx5p5axg9fv+axOjxd+5HZo8Fm0o99kw8
	yeaxeYWWx+WzpR6bVnWyebw7d47d49DhDkaPeScDPd7vu8rm0bdlFaPH501yHpuevGUK4I/S
	synKLy1JVcjILy6xVYo2tDDSM7S00DMysdQzNDaPtTIyVdK3s0lJzcksSy3St0vQyzh77ipz
	QZ9Sxc9vnxkbGF9JdzFyckgImEi8+jSJqYuRi0NIYCmjRNOf24wQCRmJk9MaWCFsYYk/17rY
	IIreM0q8+/4LLCEsECVx6e87ZhCbTcBQoustSBEnh4iAksTbx33MIA3MAjc5JJbsfAK1YjaL
	xISDM1lAqngF7CSe/l0JZrMIqEp0bl0KNklUIEni3uWVzBA1ghInZz4Bq+EUsJd4fmA7O4jN
	LGAmMW/zQ2YIW15i+9s5ULa4xK0n85kmMArNQtI+C0nLLCQts5C0LGBkWcUoklpanJueW2yo
	V5yYW1yal66XnJ+7iRGYorYd+7l5B+O8Vx/1DjEycTAeYpTgYFYS4b1fW5MgxJuSWFmVWpQf
	X1Sak1p8iNEU6J+JzFKiyfnAJJlXEm9oZmBqaGJmaWBqaWasJM67de6aeCGB9MSS1OzU1ILU
	Ipg+Jg5OqQYmgXl2/159NmxfXz+lZ/bZS2lXGUsk9xQ/vdghq2q3KIRpxeKIsJbcU1P9t06I
	yOgrW71+gVBAwXmuU4p5ChqMntZlPRt7j853DFW/W5h/5MthmSe3evcGKp6uYf4t8tX0xLSe
	ZUkPreVWrHlks2uCyvrUC981k9ZM5oh8H2z2aO9v75K3p/M8mYL3H73EWF75pEv26L1FE9he
	1mXVv0/ykxGI2lAi1jP5Stb+qeeLm1d9tgh5csC7xkR6S/2lxZeirk6rcX6vZ8dUdmaedj7j
	pyvCs9yMd0rKesWlpExi+5y/16WY3+W+hnr2PW4mcwmb/AkbU+c+3XBjwyXruNs5vZqteh43
	zk894f0zXGunEktxRqKhFnNRcSIAOf2bydoDAAA=
X-CMS-MailID: 20210421105747eucas1p2f2130bcbed85f4972ad6cda151f0cd5d
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
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b="nDEBZrE/";
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

On 21.04.2021 11:35, Marek Szyprowski wrote:
> On 21.04.2021 10:11, Marco Elver wrote:
>> On Wed, 21 Apr 2021 at 09:35, Marek Szyprowski 
>> <m.szyprowski@samsung.com> wrote:
>>> On 21.04.2021 08:21, Marek Szyprowski wrote:
>>>> On 21.04.2021 00:42, Marco Elver wrote:
>>>>> On Tue, 20 Apr 2021 at 23:26, Marek Szyprowski
>>>>> <m.szyprowski@samsung.com> wrote:
>>>>>> On 08.04.2021 12:36, Marco Elver wrote:
>>>>>>> Introduces the TRAP_PERF si_code, and associated siginfo_t field
>>>>>>> si_perf. These will be used by the perf event subsystem to send
>>>>>>> signals
>>>>>>> (if requested) to the task where an event occurred.
>>>>>>>
>>>>>>> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
>>>>>>> Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
>>>>>>> Signed-off-by: Marco Elver <elver@google.com>
>>>>>> This patch landed in linux-next as commit fb6cc127e0b6 ("signal:
>>>>>> Introduce TRAP_PERF si_code and si_perf to siginfo"). It causes
>>>>>> regression on my test systems (arm 32bit and 64bit). Most systems 
>>>>>> fails
>>>>>> to boot in the given time frame. I've observed that there is a 
>>>>>> timeout
>>>>>> waiting for udev to populate /dev and then also during the network
>>>>>> interfaces configuration. Reverting this commit, together with
>>>>>> 97ba62b27867 ("perf: Add support for SIGTRAP on perf events") to 
>>>>>> let it
>>>>>> compile, on top of next-20210420 fixes the issue.
>>>>> Thanks, this is weird for sure and nothing in particular stands out.
>>>>>
>>>>> I have questions:
>>>>> -- Can you please share your config?
>>>> This happens with standard multi_v7_defconfig (arm) or just defconfig
>>>> for arm64.
>>>>
>>>>> -- Also, can you share how you run this? Can it be reproduced in 
>>>>> qemu?
>>>> Nothing special. I just boot my test systems and see that they are
>>>> waiting lots of time during the udev populating /dev and network
>>>> interfaces configuration. I didn't try with qemu yet.
>>>>> -- How did you derive this patch to be at fault? Why not just
>>>>> 97ba62b27867, given you also need to revert it?
>>>> Well, I've just run my boot tests with automated 'git bisect' and that
>>>> was its result. It was a bit late in the evening, so I didn't analyze
>>>> it further, I've just posted a report about the issue I've found. It
>>>> looks that bisecting pointed to a wrong commit somehow.
>>>>> If you are unsure which patch exactly it is, can you try just
>>>>> reverting 97ba62b27867 and see what happens?
>>>> Indeed, this is a real faulty commit. Initially I've decided to revert
>>>> it to let kernel compile (it uses some symbols introduced by this
>>>> commit). Reverting only it on top of linux-next 20210420 also fixes
>>>> the issue. I'm sorry for the noise in this thread. I hope we will find
>>>> what really causes the issue.
>>> This was a premature conclusion. It looks that during the test I've did
>>> while writing that reply, the modules were not deployed properly and a
>>> test board (RPi4) booted without modules. In that case the board booted
>>> fine and there was no udev timeout. After deploying kernel modules, the
>>> udev timeout is back.
>> I'm confused now. Can you confirm that the problem is due to your
>> kernel modules, or do you think it's still due to 97ba62b27867? Or
>> fb6cc127e0b6 (this patch)?
>
> I don't use any custom kernel modules. I just deploy all modules that 
> are being built from the given kernel defconfig (arm 
> multi_v7_defconfig or arm64 default) and they are automatically loaded 
> during the boot by udev. I've checked again and bisect was right. The 
> kernel built from fb6cc127e0b6 suffers from the described issue, while 
> the one build from the previous commit (2e498d0a74e5) works fine.

I've managed to reproduce this issue with qemu. I've compiled the kernel 
for arm 32bit with multi_v7_defconfig and used some older Debian rootfs 
image. The log and qemu parameters are here: 
https://paste.debian.net/1194526/

Check the timestamp for the 'EXT4-fs (vda): re-mounted' message and 
'done (timeout)' status for the 'Waiting for /dev to be fully populated' 
message. This happens only when kernel modules build from the 
multi_v7_defconfig are deployed on the rootfs.

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f114ff4a-6612-0935-12ac-0e2ac18d896c%40samsung.com.
