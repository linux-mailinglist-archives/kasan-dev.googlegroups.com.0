Return-Path: <kasan-dev+bncBC6ZNIURTQNRBXFP37FQMGQEQBTW4UA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mP81Ct/Xd2mFlwEAu9opvQ
	(envelope-from <kasan-dev+bncBC6ZNIURTQNRBXFP37FQMGQEQBTW4UA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:08:47 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id A0DDB8D89E
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:08:46 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-409323716c1sf847087fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 13:08:46 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769461725; cv=pass;
        d=google.com; s=arc-20240605;
        b=XWiCQqGLmon1msK/NOy3+nnJrIJu9ncilT3136QgwvSjryMWsmPLWVdplLxfILqKU/
         Tvuk6xLAHlSaDZaJ4jfur7+DvLUBdpoaMGLZ2d1e3fMgSQxrIREDWNidxBz5g43iRg4s
         681Dm6uPGYpPM0XW6zEYoCq+eaXx1+gPqpCSzH0/+m6Sya6tu2HkclAQixaKHAT9bAh9
         y2pp5f6i7saH44FrIFpGU2Yi2Xmk/Mp3xTjyhKa37mMfdIE+xfxNFCMgW1jLHkhL9mW7
         qvy6buJD2Q639ybHXtOkxoqYn32eOXmtbK2nmMQMgktEAc0ec4ydiuXn+V648c1bB9jS
         0sZg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:dkim-signature;
        bh=OU4/zsUxnmfY1p4zf6NJqDUrkdw9MorEpfYo4wKYoVw=;
        fh=SWHy6Z9e689nSGXdPk1HlnkKHpUn2WWD40/LoKZ2K54=;
        b=QEHo5wOXna6o/3oRCKgJkyM+5Y5XMF8qfUtVSIOmu1noaZQlVU39q4979C59N1sik8
         3B9oTgAhd9taxr6/vD9tFb5udwI8EZhF2zFifRdigYKELC0VzafbqUhinlcIoC8N2WUx
         V6Y34Sq0H/Vr5hm1XnGhElgNMrohphg7bEPzDYh3Eli5bGj9Sv3IhBoTPPmJK0DQjVOw
         /VD5EtBd57qCYoNa3NSilsTzkHa/pf5ZeJQq5bSYLLOizeRW5Y8dzSrHd2sDEn0WwbcK
         bse6f4iX6E8wFTh1GvdLGMtye6I2dE33WXuuPtvVdcafDO9hUo8et9jOzAeiJbQXBRR1
         Qwdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=NsS9t5mR;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c111::9 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769461725; x=1770066525; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OU4/zsUxnmfY1p4zf6NJqDUrkdw9MorEpfYo4wKYoVw=;
        b=ctlQbLyWKXYd82W/I/GojuzNLzLJOeOxTsmDICV53AgljctNQu2JO0eOt1db7Z0BrT
         knKpCuMSx/n7kyjulA+rYzWGdT0Ex3OQ5/i82PH2wZONTMhs1200w1gzKtHdgJOcK2Zq
         bODBKBV1EbL5yNuxdp4VhBerHXAdoP8p9CB9lzyVAq/xkXAFLpNDW0dSTzRY0OkyGo0e
         FgD4lubOAXSPK6MOYKKmKwnovLXV1KQFJPqJsJqFvErzUbZW8tvFGXS8li1OFhGFw1RS
         aggHPGhdUx8+2Csv1hZyblGRY77J9DV6NeJHpB4/yseJbYJrz5eRbktEzSiJjL5pcbjf
         PnCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769461725; x=1770066525;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OU4/zsUxnmfY1p4zf6NJqDUrkdw9MorEpfYo4wKYoVw=;
        b=N/GWZCKsZE8FeIye5TkZ81stEOv4RnC1DsuS/pzdq3u4PldO0q0H65udlSGJPXTc+l
         HZYfnh2obW8GbLfxvPM+T/f4PGA8eqpxMq6InTIP28HLpkSpa4L1yTTtgU4VYIUfjK1h
         C5cnG3yl7x3FuzNFdTdLAh/zVx4jOz4W2+2cT0mHheRBuuaURj4P9x4mQYE7ANKmhPRz
         8dJgwrYiBzBqg2CosJzE4+oiOPy0+ie9Go4kJ3xOvAwsmSmnafok0sfKDnd++L+ZWk1S
         QAVHZSWnF+dL7ePQOS/O+BpjOcK5O+jkUceybSGfjknxFeJ+RCSyTFooJof+PASqoTfI
         RFiw==
X-Forwarded-Encrypted: i=3; AJvYcCUDSTFLLdOpwnKvy/bNRATt2CoNMdTCZA75ssAYBY+XNP9nZcw9bY/UmNP/NekHo6XRP6Qh5w==@lfdr.de
X-Gm-Message-State: AOJu0YzvXfJiCXRm36OuDvlKta21QodeYmDWcPsrkMxnaO7xdekAUZeo
	fZQqNgQVbNMuxlVudfbyIsc2HUCkcXgrtxpz/tNGkYiqefjHyxp3Enpp
X-Received: by 2002:a05:6820:1785:b0:662:c3a3:2dc3 with SMTP id 006d021491bc7-662e03e4de2mr2747275eaf.29.1769461724828;
        Mon, 26 Jan 2026 13:08:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HppZ950QsDwE9TTvTCNQQizYRc3i5Lr0I0MC2iAlGT/Q=="
Received: by 2002:a05:6820:3c8:b0:65d:3b9:f0d1 with SMTP id
 006d021491bc7-662c1d9c7fels1396641eaf.2.-pod-prod-06-us; Mon, 26 Jan 2026
 13:08:41 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVWOfnRPVsF6Xi0qfR8y8o+54Ozpfydj7SGkR4tP4HQp95XJFyTSCggWn1JCEyfiTWrlk/+aW0WTNE=@googlegroups.com
X-Received: by 2002:a05:6830:6d23:b0:7cf:d119:92ab with SMTP id 46e09a7af769-7d1701d0e95mr2704301a34.9.1769461721345;
        Mon, 26 Jan 2026 13:08:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769461721; cv=pass;
        d=google.com; s=arc-20240605;
        b=EssjP1cxG96CWaoMX7gmE0bfFhmfA83T4g9VhNmnRSuh6e+cnP4t7EELeTwsfi1h8p
         ZkPmblpEG/JJVgGubS7rN7MUBh7i1W7w8k/tSRespnA2waLozwoZGfBdoVDjipJybRVL
         JNJjiwW/7IpgoVJn+NI6zwPWBcPguQVAbjCPljhmnzDWBEZWMZ6cW5Aipbs/2S6leuDg
         um0igHBXvrh2FjT+mM3fJRrbZ2peA1qPBPB0ud7ow7teNuSqN9E6/a0jyc6foJOy9NPj
         2V53NY0ENla+1pDAM/5Wfv2uBYHK+O21/3yzwxvOARNOkkUIxu4w2yThTkPc7sCLekCj
         puoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:date
         :message-id:dkim-signature;
        bh=8cKFKNQnxrxxhmgP8uYGKlK6pmLuBXpibt61C4WR4bY=;
        fh=GoFk0GmCKRd6zFb9Y5rBeUfbvIWOIexWavzmhF0zPGI=;
        b=EygWF06ngxSpuOICcfbaGZaHt5WEZpUFgGyhQpJTMxsUw+PAVN/uQN+z5+O8LrxNUv
         ZiRPV0Ngk5xT0XPlhTBXDrEF37QGJLAoqMz6QQ4Y9fb3tb1pNO8U45uwxbEmj2+FmfnI
         8T5qSvrRx5jk42IL2RQVYYTH0mF08WJKuldalioYM1WfPt/FkB5zsZ8LAiMNUgb8+hIA
         wuXDOl0hzkTN32a1tMZL/fmGrme0EOSpVesyaLpacrB6edBhYAf+gs5qRF/3KFhxXO3I
         1+rLpJdxn22x/fNdzYauKeaLOm/KKOJETpXaKAvICUCTxDAjHkWHF2eC1hmFL5pr3cmq
         SYbQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=NsS9t5mR;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c111::9 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
Received: from DM5PR21CU001.outbound.protection.outlook.com (mail-centralusazlp170110009.outbound.protection.outlook.com. [2a01:111:f403:c111::9])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7d15b1e43f0si417044a34.0.2026.01.26.13.08.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 13:08:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c111::9 as permitted sender) client-ip=2a01:111:f403:c111::9;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=A0a9po22waHh66NnsB4oxzc8s3bl5vwXT+FqgQSrP+NgINcnhc3iCkxEDVPvm0SCoExGWDvAysFsdKnjy4ZrM+GYeL+b4uLbMjVxAJcJ9uwM5H/ZdNMJk215Aq/hL6iRazl1+7oWJCg22DjZR5IUYFlVlBZFG9F5mpmthG3NyuwxMc1hEWBBhw7I1WJb9ggXMrE5NSJ5BDYmQ5DSJ3jwgJtGInvbyG5IOlocIzGsNTvBT2KKLiE9FBhlgRdKYkhKEsMxqMO16LuDL2YQjgpQtdCc1o0kpgVrueY45PffH/VSqytigGalZRtBWL3u8y1vIuWhmgWFxcTHFU7VSmWESQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8cKFKNQnxrxxhmgP8uYGKlK6pmLuBXpibt61C4WR4bY=;
 b=YLSgU3YJo3R324cwi3Xtuy4CW6rAdKG6Te6An0mmg0lO4CDFbeA8cK3MZNrUkYe2F6PfsEbOTko7yFC2D8YKsI08FExQhgJaPyQp4j4IwBaTeMnR+GbPcaoy3zMH4Z6yHDBEcR6Y0b/gbF5Ewjl6GECdVnWa039mjhnMYx9KBsV4HvO7axgJqCpf7Oa/nP3hsTUAAP5eV+AO5klRtH45uGMYlvY3XiSh1MFNRKrAdiNVOxWSI9TIsQbttyXJ1sypmQ5vTOYjKz8e1nUfDl9Gd5UcX4ntD7teQ+ZWsxiwbUVsVIxjr/MLwN/eFQP6cW3jzEqNZ215hk5yKutIj18Wig==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=citrix.com; dmarc=pass action=none header.from=citrix.com;
 dkim=pass header.d=citrix.com; arc=none
Received: from CH8PR03MB8275.namprd03.prod.outlook.com (2603:10b6:610:2b9::7)
 by BLAPR03MB5554.namprd03.prod.outlook.com (2603:10b6:208:290::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.15; Mon, 26 Jan
 2026 21:08:38 +0000
Received: from CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37]) by CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37%4]) with mapi id 15.20.9542.015; Mon, 26 Jan 2026
 21:08:38 +0000
Message-ID: <be707a1e-56c6-4174-b5d8-010a5380a4a3@citrix.com>
Date: Mon, 26 Jan 2026 21:08:34 +0000
User-Agent: Mozilla Thunderbird
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
 Ryusuke Konishi <konishi.ryusuke@gmail.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>,
 Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] x86/kfence: Fix booting on 32bit non-PAE systems
To: LKML <linux-kernel@vger.kernel.org>
References: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126210612.2095681-1-andrew.cooper3@citrix.com>
Content-Language: en-GB
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20260126210612.2095681-1-andrew.cooper3@citrix.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: LO2P265CA0287.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:a1::35) To CH8PR03MB8275.namprd03.prod.outlook.com
 (2603:10b6:610:2b9::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH8PR03MB8275:EE_|BLAPR03MB5554:EE_
X-MS-Office365-Filtering-Correlation-Id: 367b4649-c931-4853-f054-08de5d1f139f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?TGRUdFdHTGhFdFRyKytrdUhVcjg5SU42VlhCejZraEdTNTB5SEo3NEtrY0Ni?=
 =?utf-8?B?MGFibDJuYXFuS053UUVPayt6NXJvMURMVnZhL3ZzMDNXamEzQzZZdnRaRFUy?=
 =?utf-8?B?OW9Wd1J4UGJMYzNyOU1PTEczdDlZVGphNmJ3ZTFkenRveTB5UFJBUkZGWDJP?=
 =?utf-8?B?KzRBS0lqN0xvcGdNY1NlWW5DcU41ZHoweTNraDNDdVVCNGJxUnRuK09pQTdi?=
 =?utf-8?B?MXB3TTlzay9pcW9ZZmJRcElMY2Q4R0xWREUwRWVEZmZrMVc2ZkhiOGpJbkMr?=
 =?utf-8?B?cVZxSXdMVkRvMnh4OTBMNWpZQk94M0lzRStCTVA1R3E2a0RoaWxrWTdBeUFv?=
 =?utf-8?B?cnUxSDVnKy9JZFk3S1JYYnk4OENJYWFGNWRhM1lYd1N2dEFoSjRjaGdBck9o?=
 =?utf-8?B?UmVTWmFDS0kwbEVyQmJ6OW1OR01YQ2x3aFA2enpJUi9iSzI0b1N2KzhpZmJi?=
 =?utf-8?B?R2cxeWZaRmU0ZG9sTi9zYWNTYlhjRkcyV2Q0ZmJpNHhOWFZxYWg3bjRieTdj?=
 =?utf-8?B?TzRVUjlpMmxtMStsRFduSWMvTmg4bkN3aFNOUUwrOHNmYUpUczNIUWV2VVN0?=
 =?utf-8?B?dEpGOTZURkF1Z2grYUZoL3IxYklwU3QwNmZlVlljWmpDV0xIelhvbTRmRXZD?=
 =?utf-8?B?eXRzYkplQ0d4S0YwN1F6MXdlMUhiOGE5OHdwVFRFWFpHemI5MG4zWWdXL3RX?=
 =?utf-8?B?SHJ5Sy84QlJKaEIwUVZMdEpRTmw0SHpTSk9RUUFBYWs4ZjBRaEJJOVFFS1c1?=
 =?utf-8?B?dmNLdFFtTGZlMGJlK3NBV2FDZ1NobS84NU5LalVQeUUyaUNERlJSbldCZ1VC?=
 =?utf-8?B?TzVaY0FPVE5nYzB4TitnZkVhT3NCaWFKV0hZV2VKbmNKUFhOM3dZL0c1WFpq?=
 =?utf-8?B?WVJyNGw5bTNMMWd0Sy9QMDZ2a3FtTUQrREhZYU5semhBN3RYZUpxK3RZNXU4?=
 =?utf-8?B?MnRESG9NVlZoU2laM1ptUUNieWpOVXF0L1JzZWZxTldtcUwvUzlSZUQyUTg0?=
 =?utf-8?B?Y2E1QTU3Qy9sSnQzRWR3VnZXOXk1cDZVVjB2S2FiTE81S00xdUVRQkhaeFZN?=
 =?utf-8?B?T2dHK2ZUV21lNWpRM3lVeWdJV0RQbks0TnBxR2dBZXl2MTFVZWVJQUY3ajNn?=
 =?utf-8?B?eVlDcXllZFJQVEM5K3VQZVlYa2lWY1doNEg3TVVoTURaRFRNdWdLR3UwR2xq?=
 =?utf-8?B?UXYzclBDRW5xOUhwUytueEdzb1hZOG1tczhUSHpOV202L1NOQ2xydFIzT3pE?=
 =?utf-8?B?d0tqRmo4SzB1WkYzM29NQkxqOEt3ZE5KY3dIRWFRbWZKTWVLMUlsRlVoVkpk?=
 =?utf-8?B?Mk5BM3dYdHpOaUw4RWh0a0V1WjFxemQ5bmtXWkdOeGtjMzFVUmhzaENNUURG?=
 =?utf-8?B?alcxcHBrZGdVMjlUR2FQdUxzaEJNcTNsSWJBOFJwUGpVeVhhTGUzdWMySFp6?=
 =?utf-8?B?Y2VQbis1eXlNVTJoQ1lSWklrU1hicnMvWXoyeWhFN2xSbm9tRkFiZmtuTzIz?=
 =?utf-8?B?R1FZL0V2bGNoNkRSQ1ZnVmkrVFFTTklCenBsa3VmOHdDRS9PTE5tY29kWXQx?=
 =?utf-8?B?NDZCN1d3YzVwLy9qQlNjSk0waUN6Unc0dEJXUVYwcmJ6aWxoQ0xOQW1EQmwr?=
 =?utf-8?B?bTBqZ3UrRTl0aUhleG1DOFE3L1RocHlzV1RwK2RkeG5KMHBtR1pTQ3B4UUVq?=
 =?utf-8?B?VGYyMHZjdUE4R3FvbHkwNEpkQyt0cWFIOFRManlEYnVpeXhuR0dqVG83aXMw?=
 =?utf-8?B?TGU4a2hDcFpkalh3a205SngrQXAzY2k4YzE5eXJuN3ZZK0Q5bDNRSTQzVDFG?=
 =?utf-8?B?azU2a005aUUzamVNd0hyVUFFZ2FsemcyTlBCbjJQM01RTGhudnIvZzB4SURh?=
 =?utf-8?B?empzV1ZBNndiUTJjM0xQNEFRNkJ0WVlhWXNOUVNFa09WMmZBYTJoRm1heUJa?=
 =?utf-8?B?V2NYZGZVSzluTDhxRUNqNG1WbktXZjBZTWhCUnhQSE92bXdDVktncGc2Yi9s?=
 =?utf-8?B?NFJ3bXlaMDJCSk96MlJoVUZPcWFwQlhGNEpvaElBdklJUHRGVmJlNFVPc1Vu?=
 =?utf-8?B?LzVCVnlhUk11R1dvS3k1Q3kxaFNTbFJadHdnRlNyRnplMWZRdkVhWnR6MnV6?=
 =?utf-8?Q?ikl4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH8PR03MB8275.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?ZFdrMUlwa2h0MFBkNTFPSkdUMWsxMDlHM2NJUEhnMG05MkRmUzRYb2liL1NI?=
 =?utf-8?B?UTBsRys5Wk53ZmcySmV6aFpYaUhpeStlcVpIVWw4d29oNW5zTk45andyd3dK?=
 =?utf-8?B?emxPRlZXUllNVWNldGtOZk1jdFZWaWlLUnpGQWs1emZIaFkvNEpZKzg0SzlS?=
 =?utf-8?B?a2k4SmZtaGw0L0ZzTFZQTU1FY1pTL3hNVzU2bytINWZ0TXpObURWQzdWcVhj?=
 =?utf-8?B?OVlUSnZ1MHJXYmdMMWFiYjVET0FwdVNQaHlKRXZjZGhNbXFBbExvNDFzUXhK?=
 =?utf-8?B?RDMvdzB4bUFsYjgrOTBvKzNzOUtibkZBM0IzcHhtUUFaL01oVTZpT0xOY3pQ?=
 =?utf-8?B?RXNheVBVS2UxZmx1SkdueGFBYjMxSVlhNm1pQWZYM0Q2WUdWYkNFVDU1dXNC?=
 =?utf-8?B?TVd2eHlPaGRKMk5vTjJ6ei8rejF0NjRZOWNuVXlUcjJQYlM3M1hrN0FuSjFn?=
 =?utf-8?B?UGdUWTVTYUFpQmo5WGxNNTFrRWxHa0xJOGJVZDl1MDdMb243VjhhUzl2VUVS?=
 =?utf-8?B?RWlqcFNPTCtHWHVlZmdNQWpKR2VWVWR6bWNKckU2bVQ3N3FIZXoyTy81MGZ5?=
 =?utf-8?B?VEU3aGliY29XdTJ1S0pHMU9yS1lsYWpiNmlVQTdqUWZoMDhBTkJ0eG1sL0kx?=
 =?utf-8?B?OGlrVmxpWGdHTzl3aEhsTkFBVy9QVSsreFJKR0daMFh2b2U0dEsrSW5hUVRl?=
 =?utf-8?B?d0pkTER6ekJpWFA5WEJ2V0pLU2RVMDRnSVY0M3VzdjV6SjM5cjJmbG1ZUDAx?=
 =?utf-8?B?OTh5MENKWlJidXdVcFozSjNER0I5aVQwd2VoMnpXK3d6UEFLYW82WXIwWFZR?=
 =?utf-8?B?OCt6WisyNE50dmNCdHZiQ3JmeFMwZTVaS21meW43UTNnU0NBb0d3Z2laWm1q?=
 =?utf-8?B?YmdBQ0lPR3F2T3hYYWUwNEZUWHhOYkY4QjlpQ2R2T3FZTjZMWE1Eb2dnY0cx?=
 =?utf-8?B?RGptblhTWXJJQ1R6UDltNm5ubEltV3I0Sm96cXdVQlk5SWljOTdDd0FuejRN?=
 =?utf-8?B?MW5OZHExa3QyWVpmV1VXZXdoeGxSQTNIUkJpVnZEOTVRemlqY2VSeXFudDV6?=
 =?utf-8?B?aVJmWVFMcjRYSkQ2ZkFmMW1lbVZpV1VDMWtqdnRqOHVkeERGaWhIUjJ0eGlL?=
 =?utf-8?B?dlUwM3RFV29HMHZHaS9BZGRFM3ZtZ3RNYVpxMXZ1aVZaSzBFa0wxTjhQeHor?=
 =?utf-8?B?QUgxSSt1TW1JUGRYdUczSE1kM25KY3dqMnV3ZlhDaHBWZXpobXVweUt3NEEy?=
 =?utf-8?B?VDVyQnp6MXBpaEp5ZHpkUlMvbjhCV1R2VGJXMG0rU3pydWR4T3NBRXlwM0Zs?=
 =?utf-8?B?dzJySmZ6UkVKbnIzYXd3bDBaTUdMaHdaSHBwK3NyTVRnT2ZHdmg5YmttN1J6?=
 =?utf-8?B?VCtLb3JZeEw1Q2M2VHl2UGpwN3RXNG5mWVVDUUk4RVBuZENRYWxwejVQcDVL?=
 =?utf-8?B?ZmFGS1Y3enE0Vng4MThuT0xWYzc0aVRCS3pOMk96OGhTbGVZTUxkY1ZXYmts?=
 =?utf-8?B?b3g2MGd3WmhRdGRjUHVzbG15Q2NkZ0tmYjhpaEdWSWtnS3BXOG5mYTJxKy9D?=
 =?utf-8?B?WkxjWkhFdDg0aFRaM01SQ3ltSEx2SkE0V2M3NDlGWi9DMVgybDMxdVE4dDJz?=
 =?utf-8?B?dDZCdHdVMmZWemFnNEE2dXB6LzRVUy9pK2lVbGxMTktZVjRRdnJNNXd6bHh2?=
 =?utf-8?B?YStwT2ExaWJwUDQ0UkpiaWthM2FlRmJYMnVBc2tpZnFkUitmSGMvdVU1ZjZz?=
 =?utf-8?B?SkhKdzhPT3gzU2tWSmNxNUViUDZGaDNOWnBRK2VMWFpzeDRMZXpjb0hzT3Fo?=
 =?utf-8?B?c0NzMjR2ZnFLbVYrMEdvRnMzNTRjTWEzQ2FRS0RxK1B1bjJOM2N0ZW53SjZW?=
 =?utf-8?B?VlpZVFV0TmtpZVRnNTBINUs0YnVTQUlMMmhMQXhEeFZzQ21oYnpzWnVkcThp?=
 =?utf-8?B?VUthWUxqa0plQ3lrWTRvejNKM3UyeSt6Q0FMeU5KK3ZURFdnOFluUEd3TjVh?=
 =?utf-8?B?Szg3VFNXU3ZjcGRwOExhL1RrOGxoNkl4WTlKNmZKTUQ5bHhpdzRDRis1OGNj?=
 =?utf-8?B?b0hWNlVtbUIyNlJTY3V0aHczaldlNzJzakxNdEdLTVlJSDhKNFB4YVpXZ0Zq?=
 =?utf-8?B?MW51WTlWNzhnREphYW9iOFBWRXIxVGpDYjU0cUZtM1lxL25mNEhXcE9ITGJv?=
 =?utf-8?B?Z0RVRGNSL2VDWDF6VXgvcXNid0Z3L0lubEVtTFF2Q3d1R3VvWmIzcVJCbHJH?=
 =?utf-8?B?UnJvUXBmRTgwVFJYdUFURUNab3ovK2dIcCtMUFZGUUpvbXp6K2toeUR5UDZU?=
 =?utf-8?B?eUorcUNQRUEwY0NENEtLYlpDRUQ4c1oxN3kya1pxQ3dWQlB5TFl4QT09?=
X-OriginatorOrg: citrix.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 367b4649-c931-4853-f054-08de5d1f139f
X-MS-Exchange-CrossTenant-AuthSource: CH8PR03MB8275.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Jan 2026 21:08:38.8337
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335836de-42ef-43a2-b145-348c2ee9ca5b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: h0hW0NxChWZY4D+YiAXigQ/dlpOrLi5JrsV6XtiNWmYqV4Xl6nGtL/9t3pBjAWixX/TH/GZ0uiLp5Ff0UP8dX0lhIitjg6nxuAbmHJvH6Bw=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BLAPR03MB5554
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=selector1 header.b=NsS9t5mR;       arc=pass
 (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass
 fromdomain=citrix.com);       spf=pass (google.com: domain of
 andrew.cooper@citrix.com designates 2a01:111:f403:c111::9 as permitted
 sender) smtp.mailfrom=andrew.cooper@citrix.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=citrix.com
X-Original-From: Andrew Cooper <andrew.cooper3@citrix.com>
Reply-To: Andrew Cooper <andrew.cooper3@citrix.com>
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
X-Spamd-Result: default: False [0.29 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_RHS_MATCH_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2001:4860:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC6ZNIURTQNRBXFP37FQMGQEQBTW4UA];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[citrix.com,gmail.com,google.com,linutronix.de,redhat.com,alien8.de,linux.intel.com,kernel.org,zytor.com,linux-foundation.org,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	ASN(0.00)[asn:15169, ipnet:2001:4860:4864::/48, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	HAS_REPLYTO(0.00)[andrew.cooper3@citrix.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[alien8.de:email,googlegroups.com:email,googlegroups.com:dkim,linux-foundation.org:email,citrix.com:replyto,citrix.com:email,citrix.com:mid,zytor.com:email,intel.com:email,linutronix.de:email]
X-Rspamd-Queue-Id: A0DDB8D89E
X-Rspamd-Action: no action

On 26/01/2026 9:06 pm, Andrew Cooper wrote:
> The original patch inverted the PTE unconditionally to avoid
> L1TF-vulnerable PTEs, but Linux doesn't make this adjustment in 2-level
> paging.
>
> Adjust the logic to use the flip_protnone_guard() helper, which is a nop =
on
> 2-level paging but inverts the address bits in all other paging modes.
>
> This doesn't matter for the Xen aspect of the original change.  Linux no
> longer supports running 32bit PV under Xen, and Xen doesn't support runni=
ng
> any 32bit PV guests without using PAE paging.
>
> Fixes: b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
> Reported-by: Ryusuke Konishi <konishi.ryusuke@gmail.com>
> Closes: https://lore.kernel.org/lkml/CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOM=
SqtMoV1Rn9JV_gw@mail.gmail.com/
> Signed-off-by: Andrew Cooper <andrew.cooper3@citrix.com>
> CC: Ryusuke Konishi <konishi.ryusuke@gmail.com>
> CC: Alexander Potapenko <glider@google.com>
> CC: Marco Elver <elver@google.com>
> CC: Dmitry Vyukov <dvyukov@google.com>
> CC: Thomas Gleixner <tglx@linutronix.de>
> CC: Ingo Molnar <mingo@redhat.com>
> CC: Borislav Petkov <bp@alien8.de>
> CC: Dave Hansen <dave.hansen@linux.intel.com>
> CC: x86@kernel.org
> CC: "H. Peter Anvin" <hpa@zytor.com>
> CC: Andrew Morton <akpm@linux-foundation.org>
> CC: Jann Horn <jannh@google.com>
> CC: kasan-dev@googlegroups.com
> CC: linux-kernel@vger.kernel.org
> ---
>  arch/x86/include/asm/kfence.h | 9 +++++----
>  1 file changed, 5 insertions(+), 4 deletions(-)
>
> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.=
h
> index acf9ffa1a171..40cf6a5d781d 100644
> --- a/arch/x86/include/asm/kfence.h
> +++ b/arch/x86/include/asm/kfence.h
> @@ -42,7 +42,7 @@ static inline bool kfence_protect_page(unsigned long ad=
dr, bool protect)
>  {
>  	unsigned int level;
>  	pte_t *pte =3D lookup_address(addr, &level);
> -	pteval_t val;
> +	pteval_t val, new;
> =20
>  	if (WARN_ON(!pte || level !=3D PG_LEVEL_4K))
>  		return false;
> @@ -57,11 +57,12 @@ static inline bool kfence_protect_page(unsigned long =
addr, bool protect)
>  		return true;
> =20
>  	/*
> -	 * Otherwise, invert the entire PTE.  This avoids writing out an
> -	 * L1TF-vulnerable PTE (not present, without the high address bits
> +	 * Otherwise, flip the Present bit, taking care to avoid writing an
> +	 * L1TF-vulenrable PTE (not present, without the high address bits
>  	 * set).
>  	 */
> -	set_pte(pte, __pte(~val));
> +	new =3D val ^ _PAGE_PRESENT;
> +	set_pte(pte, __pte(flip_protnone_guard(val, new, PTE_PFN_MASK)));
> =20
>  	/*
>  	 * If the page was protected (non-present) and we're making it
>
> base-commit: fcb70a56f4d81450114034b2c61f48ce7444a0e2

And I apparently can't spell.=C2=A0 I'll do a v2 immediately, seeing as thi=
s
is somewhat urgent.

~Andrew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
e707a1e-56c6-4174-b5d8-010a5380a4a3%40citrix.com.
