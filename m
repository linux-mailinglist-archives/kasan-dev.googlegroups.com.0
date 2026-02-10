Return-Path: <kasan-dev+bncBCR6PUHQH4IKTONNZQDBUBA5N3SZI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YMu9G6xci2mcUAAAu9opvQ
	(envelope-from <kasan-dev+bncBCR6PUHQH4IKTONNZQDBUBA5N3SZI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 17:28:28 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123a.google.com (mail-dl1-x123a.google.com [IPv6:2607:f8b0:4864:20::123a])
	by mail.lfdr.de (Postfix) with ESMTPS id E0CB311D297
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 17:28:27 +0100 (CET)
Received: by mail-dl1-x123a.google.com with SMTP id a92af1059eb24-124627fc58dsf1276944c88.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 08:28:27 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1770740906; cv=pass;
        d=google.com; s=arc-20240605;
        b=d9lrdgQG/L7C+Lb8PEK+IYNxL1SMju/tudXYHEGBlcGr9DLKnLKmks2EsACv3ZuUPa
         Qx5ZsT6eXKX6bDBcYVQj3RFh0P9d01Wul2ARTxZnJ7l7q7PcaznQjUe64zVvKzEYRFYQ
         t8A+id0nLeI8SMflEw7PXK+7JSqO5HAjbAPnCfK/OGtgavBEo+fTgysP2TNioNnSLvSR
         o+tisid3Ms/QnEheYYSUFH9lpLIHBJQqlUFUatlOaWi79oELxHiRnXVyKrPBM6ZpOl+E
         tgCMv26yhekS5A7uLIWK0J2MNwyBpTygwIZuiIJEoXV9hXHwDT0vhCh4n80NNkXJNvPV
         wA1Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent:date
         :message-id:sender:dkim-signature;
        bh=efvOBK25fOa1IaTs8o+c5nrRq3NZsKYihF2cItlRq5Q=;
        fh=gpjPmQqGIh4P6rY5HwKlcpT1MblKzkXGzZ62klP4QLw=;
        b=gDgd6NpUqz8CF0I8c2pX4Cnt+wUbJPR4etWrtQBpcV/91GP94lx5ArYmzLtZWdop7M
         B7Iwm9Caq9f9rv+6H65qfuTN4pmYcnD2RGT+tRo8M8+YdergIFeyP62zS2qeDGc++jye
         vm4rcguSlFIXP60pLywcjo6gO1A3IUUs3gza0SQKE8NFOsVYlSAE4+4uZwkOY88ijPWb
         LHv4xR1Z/OSd5ZjtCen7350GHZDO6iRM65ceqE+liUFHkQH2RiWFDkPeST2pWoA7/PJ0
         lklm6qWtly/8HmGBa6JxcIky/WulMwbvm2ii9D41ILapjirbxgEi2Xo75fsJtIgjR2AG
         X3NA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=selector1 header.b=YEz4RpAu;
       arc=pass (i=1 spf=pass spfdomain=efficios.com dkim=pass dkdomain=efficios.com dmarc=pass fromdomain=efficios.com);
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2a01:111:f403:c103::1 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770740906; x=1771345706; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=efvOBK25fOa1IaTs8o+c5nrRq3NZsKYihF2cItlRq5Q=;
        b=w9eCeg/sHQgHmr3EpjkxVzzInHj+wHq5NE9L5E9thOtwc/JpC1NLrgbmsiURdwJBhl
         MXAN8ltggXbOmJwFxkdjfBwM4iwMxMqz6XL/rPDKpawkGvKBETe5gApXj2HN+JcjHgHY
         vdXBQ4xCFJ1jM34W8MqMXBPWzrx7I/Zo6TyFw9j/UoTaHwfNzMY0zvbfEOK/c27voLqV
         YFOBSoxjSaNkcXPqbFAF5b/vpgk7SwvRfp388uH9EfM/9aKbl28SdFg8sy486EeXDj5W
         F0jD9RfrSFWOyAv3uREDBwGOfR9j3fsNjrQ46F58SoeBXLaAqcHCh8ztnnJB5DaKc6xb
         VptA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770740906; x=1771345706;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=efvOBK25fOa1IaTs8o+c5nrRq3NZsKYihF2cItlRq5Q=;
        b=vjhjk8DNLRnfzVw544pboSJ/oCOoVZGsIxX8h4GOKz4J+wY/Kh8RGZmH+FsmVBS8xG
         89Tvt1m68A5ppFU9Ayto+sTMfijyhtLS1IwqeDU837dLf+g0notfC9sk2yfnlt7Bcy9F
         D+v5GY/lHlYkzYY0j8kNlbbHwL3E4LqX2D0yhOJk1ygV5ezh5q5mEkGuvotbKj/mFvSR
         ljbfN/MGUFOKnZR5N1PrjY0RwHZLCIN+lC2mtOODnMzdioEU3ZQ4udL0Bzzt39WyB8ED
         ivqwSYBdKa9/IUZ01e3VzL8l+zj614VpOShJm9qeZhlp/vALp8z53w2sPMxqBuhaxwuy
         CytQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCU+IZSq9xV8elw3/k+tBT6zN7AHorVZxAPFViDPl3KNsXYuYkAoHce6Wbp6BLlrhUJUl990Gw==@lfdr.de
X-Gm-Message-State: AOJu0YyZsVrLvyEevFtzjl6yuxbILlIQIwc2hJK+b21I0l2kQLBijgcX
	L/mHX1NgzyZiueB4ey8tVbPDmg9pMnFOZx6czrh6rscod/lJV82y6dnu
X-Received: by 2002:a05:7022:41a7:b0:124:9acd:328e with SMTP id a92af1059eb24-12704049e2cmr5389710c88.27.1770740905679;
        Tue, 10 Feb 2026 08:28:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FDyRxVDHqsHbSIQWK0dXjDuWdzQ27hboGXrd/JWeA35w=="
Received: by 2002:a05:7022:ba1:b0:124:ad27:e005 with SMTP id
 a92af1059eb24-126fc0b4fa5ls2498866c88.0.-pod-prod-07-us; Tue, 10 Feb 2026
 08:28:24 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXUlYhaWIQDDSjz58uV5b3065ZeXHCL+6hcb/jKS5I5XFAo/IU2rkDSiSX/+iwe/ETlOyLN9wieFSk=@googlegroups.com
X-Received: by 2002:a05:7022:a94:b0:11a:61df:252a with SMTP id a92af1059eb24-12703fcdcdamr6791189c88.6.1770740904031;
        Tue, 10 Feb 2026 08:28:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770740904; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sqg7vZlTVYjFQ1NKPzaQNmD26XmVe0ck9ULKkrnnmAz5jdXx/hI+kxGnaSSYMvywXE
         izWJOlJMyG6HfHdtGX7qDXU7SBSw3fmRP4WY7NEs/jN0We3D0jKN8VFiCpnPfLLfkOgB
         8+BKewh8cp26JuCqDZ2djWE3SnhYaboOFTBfRp5CcJA8Yfb4eovbKEA8LZp69bL1aMFH
         4BmqiWEoa3lgE+7A1mQ/fPSXkpPC50oBtawgnVdNDFdxfzhPhKHwNE3+dFsJuq0tThG9
         1F6+/sKt6DYnC00qhkWnhVHbvjADoVZo+5ukLqVR1KUc03aKF9NJjCephbUERUSTKJlw
         Qqkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:content-language
         :from:references:cc:to:subject:user-agent:date:message-id
         :dkim-signature;
        bh=5eEv8ldeSGNRFeI2BxZaB+gBsXBfVVPzuNy4RvUShrQ=;
        fh=yV5NmzImx30YqsAlezGGJRt8qxUb41APYCPtnNktsIA=;
        b=ENDWerLy7se1Ii6kUivV+wl6u4NGbA/TN1aG8P04YIApjlZ0U++54o41yNRO42kj94
         zbETr/Aam6tpeW40lkTK6LkqcgGcgmVESSG3PjAXkwEVd+1HvnbpvxFPzY4Uk5JOZWFP
         wuSkAYFes/VXbDA3/oaJvjwTq+14VwDX+VVibPq7iPFcbnZAtjKWp/Vp7BsT4P5gUJxL
         rkEwmD/xzao3qOJ945gSu9FmEwFHmO9nJvik7Nk/D9oCy4HLxkD9guiyQiZUMmnSzQXn
         +/uELUc6LvXBDgUqPQPBedrlegMSBDfoYJbeLh+1+rjFLEyPKN0ukG6tUtZMgTmNKv++
         6dCQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=selector1 header.b=YEz4RpAu;
       arc=pass (i=1 spf=pass spfdomain=efficios.com dkim=pass dkdomain=efficios.com dmarc=pass fromdomain=efficios.com);
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2a01:111:f403:c103::1 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
Received: from YT3PR01CU008.outbound.protection.outlook.com (mail-canadacentralazlp170100001.outbound.protection.outlook.com. [2a01:111:f403:c103::1])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-12714a0cfadsi287448c88.6.2026.02.10.08.28.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Feb 2026 08:28:23 -0800 (PST)
Received-SPF: pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2a01:111:f403:c103::1 as permitted sender) client-ip=2a01:111:f403:c103::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=dH+KgpcQ6H62+eTFVCf2DiIXVK9dFYSQL5wSFPrMIl043a72ETMv+BwOpyg1PieNnA0RYVmuHCUSviHFTlhZwqAcWuhijRziSYz2Sef+c427yTOsrju9lHcARS0Odll9ZOEjtWqXdyUHb7ezzv0BJ7JL+lDMpfwDCP66yAwiY9tWLspV/ERO8Nf1ZdBlpX5LJR2cHfS94deVDYsvbb4W3b/K1Fk3VDkRIx2yaSfxH+d5lf4ta17ArbTiqqItQYqe4VxkfIGit7j2YI51VwSifpUOsxeVL0+scItiirSmz1rqFH6pN75fEI8/3K2jKcZKuccM7i4VDOYJDlNwin3meg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5eEv8ldeSGNRFeI2BxZaB+gBsXBfVVPzuNy4RvUShrQ=;
 b=xUBNbg5zvb4uoGlhNbkRG76DuKpFY7gEQ/ZpA7F7wx2by1AYvxAQn78omWk5qCYOWq3E7/FSRz9C3w7G5tSKkEwNlSAIOoj6eXJBKgqcoE8izta3m3yV1qmfA5vXTTu7huneOb6Fdxzo5TXzABrLEjoPtXemLkM0Lol53bwirhY8zeOta7IxrQBlFJGwNlciYqj1tBcqGWzVW3vWtekyJ2y6WR1CmPN5zqtLLzhroS7naAeoLv583p3b7bertoGRHe4IihkqeNCQnW9e9cXBVzNUfV/OkPQIepfslvQ4fXn3OyLgeti8/tNfTMogZinjBFh+CLWhcjQLo+8BGumrnw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=efficios.com; dmarc=pass action=none header.from=efficios.com;
 dkim=pass header.d=efficios.com; arc=none
Received: from YT2PR01MB9175.CANPRD01.PROD.OUTLOOK.COM (2603:10b6:b01:be::5)
 by YQBPR0101MB6427.CANPRD01.PROD.OUTLOOK.COM (2603:10b6:c01:4a::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9587.19; Tue, 10 Feb
 2026 16:28:18 +0000
Received: from YT2PR01MB9175.CANPRD01.PROD.OUTLOOK.COM
 ([fe80::6004:a862:d45d:90c1]) by YT2PR01MB9175.CANPRD01.PROD.OUTLOOK.COM
 ([fe80::6004:a862:d45d:90c1%5]) with mapi id 15.20.9611.006; Tue, 10 Feb 2026
 16:28:18 +0000
Message-ID: <38368f67-c5e4-495c-bc07-f18aac985c0a@efficios.com>
Date: Tue, 10 Feb 2026 11:28:17 -0500
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] sched/mmcid: Don't assume CID is CPU owned on mode switch
To: Thomas Gleixner <tglx@kernel.org>,
 Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>,
 Linus Torvalds <torvalds@linux-foundation.org>
Cc: LKML <linux-kernel@vger.kernel.org>,
 Ihor Solodrai <ihor.solodrai@linux.dev>,
 Shrikanth Hegde <sshegde@linux.ibm.com>,
 Peter Zijlstra <peterz@infradead.org>,
 Michael Jeanson <mjeanson@efficios.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
References: <20260201192234.380608594@kernel.org>
 <20260201192835.032221009@kernel.org> <aYrewLd7QNiPUJT1@shinmob>
 <873438c1zc.ffs@tglx> <aYsZrixn9b6s_2zL@shinmob> <87wm0kafk2.ffs@tglx>
 <aYtE2xHG2A8DWWmD@shinmob> <87tsvoa7to.ffs@tglx>
From: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Content-Language: en-US
In-Reply-To: <87tsvoa7to.ffs@tglx>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-ClientProxiedBy: YQBPR01CA0156.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:c01:7e::20) To YT2PR01MB9175.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:be::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: YT2PR01MB9175:EE_|YQBPR0101MB6427:EE_
X-MS-Office365-Filtering-Correlation-Id: 05900d66-2faa-4804-2965-08de68c165fa
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|10070799003|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?V2pWdVFJSkZrQUxMTmY4a3VvcEVTdUJTNHNtZys4STFGRjRKS29QbTg0SzJO?=
 =?utf-8?B?VHpYeExzL2xpdmRmWjdULzBLQzhxckpBQk9UdnkvU2U2RVZiblZFN3FYN1Fz?=
 =?utf-8?B?NHh6bUZiaElReklXRzhVcFZ0Ung4RWlaak9ZTGJ4WFJCa3pHbmlpb1BnNTk5?=
 =?utf-8?B?bFpMQ0FRYXUrNXpPOW9ncUxNdkQwVmlwWFJPMmZqOXorUDNnbk93ZENvVDlX?=
 =?utf-8?B?WUx2dkZuZWNOU1VUSTFvTzdnNFl4c2tsZkovbUpxVkttTWI1dCtTM1Uwb3h6?=
 =?utf-8?B?TFZ1bXE0S29PMTRlaHZOMFJQR3FncTllMGFPQnhEK3BYb0VnSzc3Nk5lL1Jn?=
 =?utf-8?B?Z1kxY2grNFpEc0l2eEJ1WS9MS2txL2hQaTY3WERwcXRkYWladks0RzE1dEto?=
 =?utf-8?B?S2FETHBmLzdJbk1nRThMbkhsTmNrcVRxNCt3ZVk4LytSdlR0K3RiUGpFOWUy?=
 =?utf-8?B?NHhZWmhUL2hMeEtCSC9obTROc21zQUt3L2VVUXh6MzVCSlZWeENRYmplY3E0?=
 =?utf-8?B?N2oxcDBqYldVcmkxd2FPdE8wZmxveEFFdTZpcksxRXlERTZOWXFCRjR1cVQy?=
 =?utf-8?B?cktWdTErT05PSEROUTdSaWNJQnJmanV6OG9GNS82MkFUckdoZit6U241WjlQ?=
 =?utf-8?B?eHBaRlFVcElsbmt6NWRwUU1KdHdhamVwMnR0UG5BNVlrQnRITSsyKy9QOGxx?=
 =?utf-8?B?TlJGRlBVdDZKbHpReHlWd2xBM1RTV0I0aHdmZkozYWtxNzdSdFJIdXZzdjBm?=
 =?utf-8?B?UXpOS0o2T01vbk5VNU9iVDMwKzRuWW9aSlVRVWVLa0R5VFRwMDgxYWI0Skdk?=
 =?utf-8?B?Y1RnZzRlbUdIM0tTZWRVWHovZmFYS2dDblVRYldyVWh5dldiZkdDWDlzaHpr?=
 =?utf-8?B?TzZLc3RHSGdvTTZKWGh6dmppVEZMemNpLzFkUmV0MlJIamtkb1RhMHR5S0Nq?=
 =?utf-8?B?YWh6SjZSQ3ZuZzVyMlhVektzQVNRTVZDRE9wTzIwS2NQYmM5MDhqVHZkQUxW?=
 =?utf-8?B?ZllObWJwVHkwNGdzYW14UGRJNU45WmNZTUpNTmttVTBKcFlXWm4vTFBSM09B?=
 =?utf-8?B?NEFQRkwycUNvU2JqdWxHc1RETlpwOFRET1IwQ2lDZFQva3JWZjBPS0NWMTNS?=
 =?utf-8?B?OWZRZ2dMb1VVbTJzLy9rdmNuMGtwMDRIZXFaa0JRSHZ0dWFBZDdSbTlCMGZ6?=
 =?utf-8?B?azlIWHd0cHZ0Q0t3NjZ0L05LL1FseVJ1UkRRVWtCMkpuQlMzM09YbHpGU1Rm?=
 =?utf-8?B?UmxvMFk0cGhKRnUwY0tWaVg3MnZtUGoyaXY1TzFKTERpbXpZNzRFOCtxVTl0?=
 =?utf-8?B?cnFJYm5sNkE3MXpYaWdwMUZOVU5GMitjaysrZkU3ZGF4THh5b1Z0aStKNTN1?=
 =?utf-8?B?RHZsWi9DOHEzZE4yRHdvRDBuTnRtQzd1dkhSNG5qdU9aNXlLNzhzNFlnNno4?=
 =?utf-8?B?b1EwU1E4R2dvbk9oTDdGR1Mzd3dGMGRJYmxoNjJtUi8wN1ZsNlhnOVdDaXQz?=
 =?utf-8?B?Y2pURVNJTDBhR2V1NUpHd21IaUJOazhtYkFYZWZpYlhyRzJHV3gyU3V2aEcy?=
 =?utf-8?B?aXJ3dWxsd09NN2hieEtRd2hLekxCK2M5VHFzaHlsWWVpcUlmT080ZjcrQjlV?=
 =?utf-8?B?TnEvT3I2Zk54TlZyVlh5TGFCNTRJbGNMWVZrbS9RekF2bkRlMlBmWXptNXpq?=
 =?utf-8?B?aS9TdmgreXNZdnhtYTFudURRdmM2ZlgrVXpGQVhGRDIwd1hRZ21jb0VReTli?=
 =?utf-8?B?d3RUeW1XMm82TE1hLzBLbEl5RWlYak54RzN5Sk85Z20zdUthc0VxZ2t1dFk2?=
 =?utf-8?B?eVZPeEhUd0ROVDN1a1QvZExvYWdhT3FuRVVLZ1k2eEZRMEJ3MloxbFdGbHhD?=
 =?utf-8?B?a2pMa2MyVHdJMWtnRUxudmNGTEZMWjFCYkQ1UmJGZG9jOWJlL1pvYll4VmVk?=
 =?utf-8?B?M2syMnpxSlB4c1JCVzk3cktCVk9xNHBwWEVpM25tT3dxdHRuTE5nUWF4WjNR?=
 =?utf-8?Q?FF2KBFhFs+vyq3eDrrrLtk+d9l1ipY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:YT2PR01MB9175.CANPRD01.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(10070799003)(7053199007);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 2
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Q3VrcHh3bEtSa1U1ODdkdnhIQzFLTDVyL1NTWEF2cU5TeHFYUklLNUlHUXly?=
 =?utf-8?B?MXhERTUxZ0Z3UDhQallMWDZKQUVLUU5aY1g2MjhZLzBjQ3JhUmprTHRMUzNT?=
 =?utf-8?B?bkxldmx6RXl4aFRkQ01IS3hWT1NBams0RDlreVh0QmFkRVFLVGNFem5GNXhL?=
 =?utf-8?B?RjVSVzFoU1J0N1hUelU1MmM4b0RzYmdEbWdLbTFjeWpsa0dTZzFBSmhjU0sz?=
 =?utf-8?B?MnVXRFVIVFF3RS9LYnpKY0ZESkVQTERXNzRoR0FIZmVNNkE2aDNldkkydUNP?=
 =?utf-8?B?N3ZhbDVrMzQxOForYitieHNOd1pMb3JRM3RCOTRsMTRGUGY5SW1VK2lyRnJT?=
 =?utf-8?B?NVA5MlZST0czK1VZbVpMRkwxWE5OMjdRbjdPK1FWQy9YT08wL3lrVSt2UWpa?=
 =?utf-8?B?cHpOcmx0aGlxZmkyNnh0ajJSVnhKM2hjMmFhVXBWcDVUZ2ZZTUEzR3lVdXZv?=
 =?utf-8?B?TEhLRVdncnk1a1FFUWc3YmQ0UjZrMnVjQjloWElXUCs2K2RObHh5OVh0a1lE?=
 =?utf-8?B?YVlWcVhUdmdXZzF2azJaM3J6dnhoWXA5bk9mWHpDRno0cXRPSXM1K0NreFpG?=
 =?utf-8?B?MTB6KzhwT2p2ZFRaUG9KZ21NUDhMMmRNOGxBKys4a1p3K01wNXlZUFQzNEtk?=
 =?utf-8?B?bW9EaG5nb1pvaUdXYVVKYXgzSjROb01UbUNJeHhoU3NwQTVyUnRweEhvck1q?=
 =?utf-8?B?U2l0czkzZmdsSi82eHQxRjdtM1lJSDc3ek1Gd2lXdEltS09OZzllT1VaSnV0?=
 =?utf-8?B?dENTOHR1SWh1c3JYaEpVZ04rT2RWZTU3YW1qMVBXczFDb093elpiVE0wOHVl?=
 =?utf-8?B?VXV5a21vbUJGV0FBYUR5WGdLcXhkbzVXNFVQU2FxNHhnNXhhTEg4V055MXZk?=
 =?utf-8?B?TnJ2UFIwVUV6eExWNVdGUWhmaFMxRmQzY3JyT3hCZ09adDNqVjNkWGdJa3Qv?=
 =?utf-8?B?WWZWdy9vZUZ0a2Q0aGgwa0xrK0VjWmhEaTNwQlQxUzlOUkphR2lqN1VHcHA4?=
 =?utf-8?B?R202SWZlUlYxZS9NVCt0OUdYeXV2dzl1OWhKblloOHRjYUQvMnlsVjZlVG00?=
 =?utf-8?B?NU11Zk91V3B2NElzSTg4NUNRcWc5MWVMb05xZktTNlJuaENKYXlMOEI4Q1Vs?=
 =?utf-8?B?MzZ5T3h2bVVlc3Z5bVJJaXpUT2Z4UzVVZEtibzI3MWlHd2pFTDRxVWltd1B1?=
 =?utf-8?B?WWp0dDhaUnBlQXBzK2VVTWM1cjdrNzFJUjcyaklqV1JwdFJyZm5sZmxVNENx?=
 =?utf-8?B?Nk1BN2dFaHQveTRCYjcwNmxYd1NYL0srbUxuSjduZEhRbkpyeXY2Qyt1VjVI?=
 =?utf-8?B?dG95aVUyK3EyRmx0ckd6akE2aFBBMHhyeThwUWxmUzNCMWFhUGhMa3pVNkhv?=
 =?utf-8?B?cEd1ZzBwaEdMTXNKZ05TdHlOc3hMRlhxNTVOTDFwTnlGWVNvQW1Mc09HTWo1?=
 =?utf-8?B?T2pUOEtYaGRLOTFxL2R2ZVhpR2Fqcko1dDFTZmRnOGdTYm9sYWRSSWlxa2Er?=
 =?utf-8?B?dWxraVZ6UnZnVmZ0ZnAwbFVwRjVhQkoxT01pdE1nMEpFWE5wUmdMTEtWWUpG?=
 =?utf-8?B?eWdobGxLdmd5eFExK3NtQUZpbXdyM0krL3RDU0l0a2c1ZnVsakt6dE1KQlls?=
 =?utf-8?B?eEdjWjdsUmp1NkdQV1ZZa21iTTlTUHdwYXIrMEY4cVFQYkFPa0tjS2FSWE9v?=
 =?utf-8?B?ZHh6dEdSUWRRRTlxZlZ4eHVqSXpCRGxPcHNEdlJlS21ZZ3k1MlNSR2tvellD?=
 =?utf-8?B?UkVhc1VyQ3VQVCtINmdLdnVhZEx6UExJZmhuYUlVS0trRzlpQ2tLNXVzTEU4?=
 =?utf-8?B?eXdhT29ybEJpdUtBblBOQnlZNWhGMVlPZHZrSFNlYmdZSlNoODc0aWRDbkgv?=
 =?utf-8?B?c0RrTFA1QkxmZlZYd1B4TnBQeVl3UnpFWnI4MHplWE1nTFQ5OU9DeW04NU1D?=
 =?utf-8?B?NWZjTnRhOWNWdEliVkkzc2ZMbk5Ja0Fqczg0QTh2SFo5MStZblhWQnV1ZkZG?=
 =?utf-8?B?RnpldVZoL1ZPcmhEM3NqVGRhWUZPTUxMOVBxZTVrQ1lWNGYxNnBSSjA5d01x?=
 =?utf-8?B?cG1lYkFyeWw2SFZPQmlmYUEwWHhaa0FNN0VSbk0raDBxQ1pTc2hwUlFHbjFG?=
 =?utf-8?B?czJtdGlCdVBpWlI4WDZ0cEJzSlFWQ0JBdVRycjZQa3dzaXg1T3J1M0N5RndQ?=
 =?utf-8?B?WldacGttMmVhUUpqMUtyWnU5UThBQ0grMmFTdnl6Rzh5bXlMdGlCQytwUkJY?=
 =?utf-8?B?OFBLaEpFUHMzNmxCd2d2TVZqczdZTjVQbXNQWllFQ3NTbjFsaXRkRGtDbUc1?=
 =?utf-8?B?NWFZOEFtakVkQm1GRFA3MTFsd0M1Vmx4aVYvRjVjVU9BUjlXN0hObHcrUUdj?=
 =?utf-8?Q?fDzn/tv1HLnO0khx3dAk4k6E7JuffU5WjB/FKIZdAWXay?=
X-MS-Exchange-AntiSpam-MessageData-1: w2VEvlv3CFpsgl4tWq4WK7gWGrWhiZ/cy48=
X-OriginatorOrg: efficios.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 05900d66-2faa-4804-2965-08de68c165fa
X-MS-Exchange-CrossTenant-AuthSource: YT2PR01MB9175.CANPRD01.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Feb 2026 16:28:18.4142
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4f278736-4ab6-415c-957e-1f55336bd31e
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ieT/HA1MuIswsguAGFheg1dQ6/kHFNPjmEWZA28uVyXOQJdi/9W1IMpn7h1X3TpDnRhWYWZSlE8PPb/INN0aylhjhDNTDu+vKlPe0hiNsTE=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: YQBPR0101MB6427
X-Original-Sender: mathieu.desnoyers@efficios.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@efficios.com header.s=selector1 header.b=YEz4RpAu;       arc=pass
 (i=1 spf=pass spfdomain=efficios.com dkim=pass dkdomain=efficios.com
 dmarc=pass fromdomain=efficios.com);       spf=pass (google.com: domain of
 mathieu.desnoyers@efficios.com designates 2a01:111:f403:c103::1 as permitted
 sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=efficios.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.11 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[efficios.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCR6PUHQH4IKTONNZQDBUBA5N3SZI];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[vger.kernel.org,linux.dev,linux.ibm.com,infradead.org,efficios.com,gmail.com,google.com,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_NEQ_ENVFROM(0.00)[mathieu.desnoyers@efficios.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[11];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[wdc.com:email]
X-Rspamd-Queue-Id: E0CB311D297
X-Rspamd-Action: no action

On 2026-02-10 11:20, Thomas Gleixner wrote:
> Shinichiro reported a KASAN UAF, which is actually an out of bounds access
> in the MMCID management code.
[...]
> 
> Fixes: 007d84287c74 ("sched/mmcid: Drop per CPU CID immediately when switching to per task mode")
> Reported-by: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
> Signed-off-by: Thomas Gleixner <tglx@kernel.org>
> Tested-by: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
> Cc: stable@vger.kernel.org
> Closes: https://lore.kernel.org/aYsZrixn9b6s_2zL@shinmob
> ---
> 
> Linus, can you please take that directly?

Reviewed-by: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>

-- 
Mathieu Desnoyers
EfficiOS Inc.
https://www.efficios.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/38368f67-c5e4-495c-bc07-f18aac985c0a%40efficios.com.
