Return-Path: <kasan-dev+bncBC6ZNIURTQNRBJE237FQMGQECLTC7BI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id iCMBMCbNd2mxlQEAu9opvQ
	(envelope-from <kasan-dev+bncBC6ZNIURTQNRBJE237FQMGQECLTC7BI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:23:02 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 102F88CFF7
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:23:02 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id 5614622812f47-45ca6c30a0esf5684384b6e.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 12:23:01 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769458980; cv=pass;
        d=google.com; s=arc-20240605;
        b=QZMk8jnRlWxKiBS+PfNYpRKCm2N6bBaLYrbgtYUPY1EtksiCcKkZEGOaD/I1wqAj+o
         D+pF0lG76zwacTZck7jnNOvmmMH6dw/tKOGpgDjtl9kxqmR62uPlyIXX8GQ4Fye/7rt7
         jbkLtD18Gekhu5QpsZaste0QAoRR7WpEtOiriTib+nSdDbySwiJDrp/8WCudGH+/RFiY
         +yysOQfwDbgYCrX1mbJCayzfcfaHixSMgIJ1brZ3shs6oH7csMNzaqu0fnO62DZncakn
         ZNyw0E3yivdYed5JnwlXFYe/lfivCK9YMdnKiqh74eIlNBvXdfjNGmDY40xoXsbLAdou
         JWsQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:dkim-signature;
        bh=QIx4G3OoyoluP46kxxR/1vVLKvr/EjJ9OR8TdGcMFGo=;
        fh=tf0HWXmlVtLQsXy9GMrxLn06Eota+lF53SuANVs12FE=;
        b=SFIgfTLHlOdAACxKNYU8ZeK861lZl7Cwuj8Ucnro/FMsa31kZefJz7JVFpdOc463fR
         dVE/US6OhIEKaJfSoip0f6CVHNUETLIT3eX9ulqzLPscBVxa3eFPj6THvtDSh6ddKfS3
         8ZNkEgNVnywwqAsTrr6QLQz27ntYXEgh0SV1Kb+ADsd9zu0tiE1UfLUVmRn4MCAlFC38
         n3XjDHToSY37fBCE8QiEYqw/wNWXajvVOEt3hzox1grXxnhUgvg0YY4xTphioZpG5HV3
         t+8I7CZc2fx9ziFjhTtBEDL5H+xvwlq/wWOw7YvVW6525ebtTmuhcUu5u0ryGNZ/EzS3
         sGLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=o4+rnOd0;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c005::5 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769458980; x=1770063780; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QIx4G3OoyoluP46kxxR/1vVLKvr/EjJ9OR8TdGcMFGo=;
        b=LnkNve32FxhauFWTwklr5QHsYBM0P5KuxtVV18ZdWV8LUWS/8aus9RJ3sJRmX63izh
         TSoU4EqsbOgbOhBdtW1jIBMNuCfcGsb8C7gRFOxWCxUe7ifVXm6naYSD+WFFDbHC5RM+
         LjYC0xoQxEXPQ7dFwcWZpqbo2DOPgDq88jKLkwpPyiyaFpH7OdVL2kvUNfw4kJ5xrN27
         sQHpwanJ5qANKzyhi5ytR3W3rJ2vSOnpH8QMPFlE6ZhNWcvKO1SY0EzhaaFIhr5nTOgv
         ue9iuKDQkKoxGPxFCgx/ezNiyxBDVlHZaG9CrRvHZxwxwJl9ZqPKrtp9QqhoqAVzdsPX
         OQTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769458980; x=1770063780;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:to:subject:cc:user-agent:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=QIx4G3OoyoluP46kxxR/1vVLKvr/EjJ9OR8TdGcMFGo=;
        b=YOIL1lyJZXrga+q3E/gXgVqKfioP2EFkZEh2cuShmtOMZIz15n0PBhVZq6E9438mDU
         6kp00gBbuF5n0tOereAGV01G6j3RYGU9HYEL39YZZMm8X9nLmH4ECcFhvgqErvrHL+2Q
         oUOgylrzVou0rgzwRO+kemA7a8FzfBXyuzyy1SI128OKESAn4nA1scSZ0ke0ZYoYqSC9
         QgPv/gK8QZP7CB0aqKbhB9ipS+FrM3iLAWVOUfpgF6wnDSNPlr6yeeduqKYGky0AD01I
         DJtok01DmkfuS/eWOuFzHhM4CxXNFX4+PyhSqHlTuhzEIH2G5YSM+GEmVD40V09HgS1D
         eymQ==
X-Forwarded-Encrypted: i=3; AJvYcCXxlClzwH5o92jMiA1BJRnVqM8fQzaf1ozb+qz8yLb3k/AIWDClHB90MK+jyZxaKa2PX0y7Tw==@lfdr.de
X-Gm-Message-State: AOJu0YwmC5+LLaeiUfrEYkWhkFo6QmrRQ5MpEh9QTz4CsH5MX4pFoaHj
	B3ctC5tLHm7iCwinLJFpEC62j90eOougmTclh1vztwV8U9zaZhCP3y7s
X-Received: by 2002:a05:6808:f05:b0:43c:8714:fe3c with SMTP id 5614622812f47-45ed9a64162mr1951311b6e.51.1769458980379;
        Mon, 26 Jan 2026 12:23:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EWzcYYOL4A2q8fx08u220HcBNFpdc1MM4q+gQ+4wVyXg=="
Received: by 2002:a05:6870:d613:b0:3ff:a5fa:7cf0 with SMTP id
 586e51a60fabf-4088264dec9ls1696740fac.1.-pod-prod-07-us; Mon, 26 Jan 2026
 12:22:58 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCURqZ3z5JcuFCo078K1Zt3mNEIeaUFbwibeeHkwYDcFw20GqERDztrth6GuwRYLCimfEm0xS26mqHY=@googlegroups.com
X-Received: by 2002:a05:6870:d206:b0:3e8:8e56:6753 with SMTP id 586e51a60fabf-408f82231efmr2787061fac.55.1769458978744;
        Mon, 26 Jan 2026 12:22:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769458978; cv=pass;
        d=google.com; s=arc-20240605;
        b=RVz9YpW6G9uCSe6Ak5S/E1LJ3jIeqcpRconwQiG7RNVhALS3d5zu9Q14ccFEiDHTmE
         dwptW5okd/VDf/s0CoP+UxomxB190a9xuDIeSLRtszEZIRnXj1Ebn5yq1ABE6q6FI0sX
         a9g1DCD2U31HI+NM7QktZymAWT3518Btf72iqRemI+vBXBIbhKHgwn53HXWTIphoPOnd
         493Bn+O2uz8gEhglJHQfsl82wTgkxQIw+0lXBNCmbTx+2be4liaf5EczcsofVwjPTOpK
         v647xeA+ZhDBxn0aNyVxv5JOqRF720jT4F6/AtXENOekE3bS5I5HHl9a2lvdqh7PJMmO
         948A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:in-reply-to:from
         :content-language:references:to:subject:cc:user-agent:date
         :message-id:dkim-signature;
        bh=fqhYYn3ujR4c++rTS83m6BGQ6U+TphxnYmxzE34q9m4=;
        fh=HBd2urGR4EfvTdIkzE+v57NQ1rMjZNF/wR49BIGHGbo=;
        b=QdU7Oy3DA7xD3wYBrlZk7PMG5pWLJDDqFtrJdyXk2M1++XXzPMzn9sYH392mLA1Vc/
         6R0ZmyIybv92UBe2KU8y+WRJqBVEjga+hny5Ydlq9Z7HSXvLfeb9QJNXelkbZTqwJse/
         +8LArY4Gd58T1PHYOtpfpECfbFkMJ28avuSH/wjkmN0OYPOiSw6/xTJYc13cqnByRAgo
         R4jwCDaOhw3OvDkJ+kCfEsZO+5vea+sk+wXDTcfzEInNrCB3Pzu/FYvvD/UPMtne7S+d
         1ABqpCrFF6FwtZMNNArot5naGvzBC1p4nN7ekbMzDI/mR4BXum11I1njWJ8r0xkIyC5q
         xarg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=selector1 header.b=o4+rnOd0;
       arc=pass (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass fromdomain=citrix.com);
       spf=pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c005::5 as permitted sender) smtp.mailfrom=andrew.cooper@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
Received: from CO1PR03CU002.outbound.protection.outlook.com (mail-westus2azlp170100005.outbound.protection.outlook.com. [2a01:111:f403:c005::5])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-408afbba48asi343671fac.6.2026.01.26.12.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 12:22:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper@citrix.com designates 2a01:111:f403:c005::5 as permitted sender) client-ip=2a01:111:f403:c005::5;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=aDpOyZ4Co0Vtmf3N3eyOyGvYtb/Uub5QimEyHLHRZzKMQH3ELvO/h9xoioLQlQDyxsZNbjZE2gyMrwiCimxAXoMOOhxkWLpf1s5ysSR/MlU06jJmC1D/GM8j0KaCiKjnEiggeUz6d/tEtxo8Cvf2cNtH8mNaH6cIDduQX2TfTgd2FejE6x+tYi9ojPShPayTq+VZ/2Q5jYY+kzC54Kx476Z85BGl3nVSy9ihqSWwb5jXdv8q9k/8razt3and0UgmyXFIXU1NVaypL+3o2SB7ojaotqT/oqOkPxq2ZzzNPck7v+JLSx1QPIIw7zC2+LisE3bFQsYesD5VicJ4KfnDjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=fqhYYn3ujR4c++rTS83m6BGQ6U+TphxnYmxzE34q9m4=;
 b=PXDCMuvsuy0VvJN0Dyj7dr602R9fQLg6qbZEBm08YUWdaxekB7QN/8DPZpPqAhC4rNcfbHdy1r2xRCDXFr3ccImlMxfhKzndgpKNwT8RX7HC3T8eDMufQZ8M21KBXKvHFWmOZeyZYa4nDUheF11apDryUe0ALv1hoaD8x5y9hvB0bWKB9tYgS7kPNsO4O69WLNt27JkoOKNLQQSqLB2xsMQfEhW4QdD652GYaKtXXKqrw7ESHqNCYyGIyEpGpIld2T6aT70sNcEAOILwjDply2auFu/JX7h0xsGJ8w2wwMgK0Sh51b1XDVxO2OXI2ZsHUeQmAQGJ1hgnidW+TIkHUA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=citrix.com; dmarc=pass action=none header.from=citrix.com;
 dkim=pass header.d=citrix.com; arc=none
Received: from CH8PR03MB8275.namprd03.prod.outlook.com (2603:10b6:610:2b9::7)
 by BN8PR03MB5122.namprd03.prod.outlook.com (2603:10b6:408:da::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.15; Mon, 26 Jan
 2026 20:22:51 +0000
Received: from CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37]) by CH8PR03MB8275.namprd03.prod.outlook.com
 ([fe80::a70d:dc32:bba8:ce37%4]) with mapi id 15.20.9542.015; Mon, 26 Jan 2026
 20:22:51 +0000
Message-ID: <6adad05f-bd56-4f32-a2d5-611656863acb@citrix.com>
Date: Mon, 26 Jan 2026 20:22:51 +0000
User-Agent: Mozilla Thunderbird
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
 Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>,
 LKML <linux-kernel@vger.kernel.org>, Alexander Potapenko
 <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, X86 ML <x86@kernel.org>,
 "H. Peter Anvin" <hpa@zytor.com>, Jann Horn <jannh@google.com>,
 kasan-dev@googlegroups.com
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
To: Borislav Petkov <bp@alien8.de>,
 Ryusuke Konishi <konishi.ryusuke@gmail.com>
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
 <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126195431.GDaXfGd9cSwoH2O52r@fat_crate.local>
Content-Language: en-GB
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20260126195431.GDaXfGd9cSwoH2O52r@fat_crate.local>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: LO4P265CA0144.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2c4::17) To CH8PR03MB8275.namprd03.prod.outlook.com
 (2603:10b6:610:2b9::7)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH8PR03MB8275:EE_|BN8PR03MB5122:EE_
X-MS-Office365-Filtering-Correlation-Id: 0f0ec4ac-9bf5-4135-f033-08de5d18add7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|376014|366016;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?SDRJTnJQMWpuMURvZ0hYKzhOUk52VDhYMHNWZDAxL3EvQlAxZ0NpWHN0aHpZ?=
 =?utf-8?B?LzJJMEdtdERoRmZMeXVOdnIvb08yWWxyNkpZTVFmZ2ROVjNiZERMc0NYc2lL?=
 =?utf-8?B?cCtjOUdoTHlRanhyOGR5eUc4OFhwc1NmaEs2ek54TWZsb21RU0gwR0VjRitB?=
 =?utf-8?B?K09qMVlWYllhNTNHcEthcDBrQmlQYStFN0dhTnY5R0xBYUF4WE42ajBkelZR?=
 =?utf-8?B?UXVCdlMrUTY4bHlIZmVBVVBtcmpld0ltVUdpZ2JmM013czNvaGJEVHlpdWwz?=
 =?utf-8?B?VjJMWW9VeTNsT3ExMkxiaHhSNVEvQUtGR1F0UUU2ckhYZHJjYUp0NDZsd3pP?=
 =?utf-8?B?KysxazBNamhuZk9HSUUrcmR1VkVKaUxNNVlwWHk2aTRjNGZrZDRHM3dUWkRE?=
 =?utf-8?B?L3I5QWgrdVFzV0hhU2pxT3BHaG9lcVNBMjNNa0M5OUFQeXlxWWNtdmpPUkNX?=
 =?utf-8?B?VHZBZTJDbnU2QUEvdHhyZWQza21NSks3a1hLZ28zc1h2V1h0WEViaFN1TXhJ?=
 =?utf-8?B?eU5RNGxqMExyR0k4U2dHNFBpMDkzaFAvVXZBTHZHckRPc1hhMm0vYVJaRUYz?=
 =?utf-8?B?VjR5MW5ma3ZSUkFLNDMvcklOZW5zbXBGbU95cEFpYmwyOFVxRXFvQ1gwdzhQ?=
 =?utf-8?B?c3Q0Y2kwV3ExVGdKZlV0c1VFVU1JTy9hVkFsUFloditCMWlhVC9VZ0ovUDEr?=
 =?utf-8?B?UVJpb0JyOVRrc1pmeWRnbFFudkE1L1QwSG95ZGRVVHlLcXJDZ3NBK3ZsbFQy?=
 =?utf-8?B?OVNrYVRhYVFzNDFoaS8yZDVFM0Zab1MzUldQeVMyd0o5L25YYndhOTdSRlNj?=
 =?utf-8?B?TFRubDZkUXFFQnRET3p4OWRTOFNMOHNla3lLeE1pVXpzMlhRY3dmbXA0Yjg4?=
 =?utf-8?B?WUdIbmV3d3VMS1o5L0xVbVg1b0doOEl1S2dmM0Q2Znhzc3piYzBYZFN0Qm5F?=
 =?utf-8?B?T09TR0dZM09MTVl5MmV1SmxadndCNTg4VkMxRzF6MlVEYTVHZis5bUM4SGZ0?=
 =?utf-8?B?a01ydC81RG1UYzZ3bkkrQ3RMZmNLdzZiV083eUlDN0l5UkV1OEVaZDNrd3JW?=
 =?utf-8?B?MUh5MEN1OFFMSXI3YlNZRk51b0IveTRydkhac3pXc09sdWxZbUVpN3daMlF4?=
 =?utf-8?B?eWtlMDlZdkRGYzQ1WGVzZ2tZajZIZkhabGo1SVlMUTB5UGdJMGowMnozd2pm?=
 =?utf-8?B?b0ovRjN6N3RaeTl5QmVBRjZ4bzhaSjQwc3pMOXp4SHltSVhlVWFDckg4dmtn?=
 =?utf-8?B?YmZFalBZWTVmRDNIUTVyV1BHNE1jb0lyUkwzSDRxN1JaSmprdCtSN1JGUTBW?=
 =?utf-8?B?cWdyYXYrZi9oNmJtcW9sY04rVVBLUW5YRUxJcWhSd2VacUMyMWFHeWVEWHhz?=
 =?utf-8?B?SkY4QVp1WmVKcTJZanJhclZDYkxxNnhLMUxMVjZyelo0dTBBamtYdm5KdmE0?=
 =?utf-8?B?cTN3RkxHNHVocGlSQ1M2SDJKR2VWNWZrZ2ViaFpkcmxUZWxFQS92R1Q1QytO?=
 =?utf-8?B?ZFJIVDFHZ2pVV1I2Tk1MbkJyR0Y2VTIyMmNoZmFteTFsRTkzdFlLVGRtZXlL?=
 =?utf-8?B?N3ZiWEJjRUZ1bEk2RHkzMWZEa1NsMVpzQWozNXdIRUNHeDBaUTlGeC85ZE1Y?=
 =?utf-8?B?aVplNmpEMHR0azcwK291d1dvZU9lU3R0NFkra3IvYjRSS0JEM1VFcG5FV01J?=
 =?utf-8?B?dyt6NER4SjdQZmQvTVhHSW5ISzAra3l6NnA0SmRJaU55aFVpQnQxcXVkelZF?=
 =?utf-8?B?REZQdVE0Smd4NXBCUTNGMTBkNXYrRFF4aHpCbG9PaFp1WWoycU9jVnQ2czh5?=
 =?utf-8?B?Y2V5WjBWVzYyQ2hJeXdEMzF5SzJEajN6UHYya3dGa3JZNVRVZ3Q3UlhyWlh2?=
 =?utf-8?B?WWR5OU9oOE1LYmtrOUJvS2YreGMxdUJlV0hJMzVVcTE0THd1RnA2TVhNc3B5?=
 =?utf-8?B?NTNaMUNESDdiNHAwVnRlb1p4eEQ3dDNmM2NKTjI0b1A1aVdpalFSOEVYM0FX?=
 =?utf-8?B?S0FjejJPa1NGcTRzUW12Njh0dW53VElaZ1V1TW9IVUlHa2dRMEczOG5HYmUw?=
 =?utf-8?B?bTRicXB2ZUZUQjRPcndJY05MK0VBUERuOVl2SWpHQ1J6MGRmb0hVUkozTVQy?=
 =?utf-8?Q?1rZY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH8PR03MB8275.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(376014)(366016);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?NDI0TUhqYm9JN1lyTzNmS2Z5NFFDeVp3ZE1OK3ppZzNvaEM0Z09ubUpBZjRK?=
 =?utf-8?B?TzNHbDhCRmZDOUsyRzJJaFNkZ28yRmY3cmFWUUJVbWRBSzFYejN0RjExMUtD?=
 =?utf-8?B?Q25IK3phUC84SFoxZlhuK29IcGRZaVZNd1BURUJpbVhDNi82NXZhMi9nbXVt?=
 =?utf-8?B?VnVzRDdIR2ttZloyZUdZOXo0Y2Z2MnFNcFJockxKeUZnSlRXV3BKVEZ6dlZp?=
 =?utf-8?B?cEl6VkJkTUFFSG9jYkw3V3hvUitaL2E1WlBUbkZhNlh3dWthYm9najB2WWp6?=
 =?utf-8?B?MU1lTlJ6Q3RRMmZheGxaNEJLT2loU0pIY0NHNmNQRWJnT3htUHZ1TEp4ektX?=
 =?utf-8?B?QzBOa2QwYVdwRnNVOFlSdnB0VzR1SWlLSytOTWY0dGFkTjFQNmxPYnh2RGVC?=
 =?utf-8?B?azRMOXo2TFRNQzVucnU5VGRPQVR3aDh3a3gvOVNZdWNHSDlIUUNYUFNBMVk5?=
 =?utf-8?B?eFFoK0h4a01kMUdsakNRdVJnTFIyY0swaUsvZHV3N0IwY3MxYkZIblF1OTVR?=
 =?utf-8?B?UzVWZE5CTVRlcWdzODhvNnhicXlwempYNkphanBNTkJaemRnNFhoWkhQN3NT?=
 =?utf-8?B?MWI3MC9vNWlyOHVGclFRWW9GWWpPejNxQzhzalRwNG42bWpodEFvK3lNTGVB?=
 =?utf-8?B?RklTNTEvSCt6VktweHdFNExNVmJmUmM2M3luT2VpR2FBeHdBT0pZNnowLzlG?=
 =?utf-8?B?a3BtRTVvM2RPRE55elZFN3R5WGlKWTloK3UzcC8veTNnR0NpYk1HUktjcXVB?=
 =?utf-8?B?UGpadzlTK0xBSy9DL1hBWkVBSHRoTUV0TFNTMXBIeDJpWnlCUTdlYVhjSDdR?=
 =?utf-8?B?RnJWVExBZ3dnOVRSMXNjdlpPNll3WmNDd3NWSDNKRmFJSEd1Q1VOY2ZqTWty?=
 =?utf-8?B?VHlCOVErTFRxaTlwY3VzV2s3VXYycHJua1ZmeHN2MDBhUmRHeXlud1Y2RGFw?=
 =?utf-8?B?aXBaVnBHeStmMGZ3NkVZR0pZVGhDSGs0Smt3SElEVWFIZmx2MWRXVmYwSitJ?=
 =?utf-8?B?dFd5SUh0N3pWeXQvRzhrVFJpdTN0Q1FLdXh0VGlKamFkb2xDNGprNTJSc3Zr?=
 =?utf-8?B?SFlSeW5rLzdHMHJlUy9ITWt2RDZFRnU3MllpUzlVV0dvdCs2Q2xUNDJFL0J4?=
 =?utf-8?B?WFVlZ29jbDc0VlUrcS90aU5sN2Y2TS8wN2hWeGI2bXlpZHdrVVg5SHA5WUxU?=
 =?utf-8?B?L1BadlFHYUFtQS9vK21lTlc1OGVEWDNRZTUwN3VCL1RYNlRQRUxOeURWcnd5?=
 =?utf-8?B?blhUUVhWVWJkNW9oYzJvNzBpbnlwOG9WSllNZCs0Y1BqTEc1MTlXbW1JWlgx?=
 =?utf-8?B?djdsWjNUbm5OVzh4YzFIWjBzR1V6OHpmRUNXeTVOcTd3WmdUcWFCUGgyeUdI?=
 =?utf-8?B?K1RoUnJORXIvT2VvOGtNalUxNzA5K3JyVVRNVHNWNEtETFozbWI3bUZhN2lK?=
 =?utf-8?B?YU5YWmRnd1J2Qk1nKzZGZ3lLb1ZPeWU5UVU0L1ZHQlRIVnBabWlqREhDL2Vz?=
 =?utf-8?B?UzU4KzVxUFJEOXliL3J6c1U1VVRGR3U0ZDhJTjBDanRaOGs5SSttN0R1Ui83?=
 =?utf-8?B?cGlFVkRUOGdVNSs2YTJnUmlKOTBxOGdCc3ZlcG5Qa0tJOUs2a3UyWUJyWjBI?=
 =?utf-8?B?QkxoaFBuRFNwK0NkalROU05vTTJjR3UrZmhMbFl1NElnRGVrMXVzbGJLYkJa?=
 =?utf-8?B?NklCNFIzTmtFYWFwQWxYY0dyNnZnZUNnU0F5UW1URmJTdUUzdUpWdlQxVE9B?=
 =?utf-8?B?NzRsTFVHVDdrYjVIQmsxVWJUbmUwUkZBMmZxVHdwelg1b1pJdkVYZGNRc01X?=
 =?utf-8?B?UjhnVllJNnBlWll1elJiSkQ3REZWK2IxRjB3TlFEZFNoL3RaanduMnFvTjY1?=
 =?utf-8?B?azJxandManNyUDhNVG9LL1VHUnFXWWZZU1E5NjM4d2NZRmtuMytLek5neUZW?=
 =?utf-8?B?MCtjR3Y1aXRhSnlUVTdGcnM5Zy8xeUlPNDVFcUlUSnVvUXBlbCtGa01POHk3?=
 =?utf-8?B?NDQyWmVYUmhjWHRNUmxueFNXRGhVMnRrVHQ1QklHZER5ZlA2Z2ZrQ3Y0clpK?=
 =?utf-8?B?NXNMMTJ4ZmdJSmlkdEUrOVJ2Tmp2YnBMVnBLV1lvd01ydWxOYjZqaXpGbVhq?=
 =?utf-8?B?MldEdm9UYVZ4Y0JJcHhBeWZnSTZncWlKYzhUVnpIak1ubHJEQXlVNGExeHhx?=
 =?utf-8?B?WFR1eWVETkQvcDM5Njd0VmJJeXg2YXYwMlhFTHRNd2hnVTMxdGJIMm1FV21V?=
 =?utf-8?B?amlQNUxtSFpqdVpGbU5qWE8rRkY1c0h4bHNmTGpEbC9wSGRLWnhiTHBtQmVx?=
 =?utf-8?B?QU9ZRDgyay9lT0R0dldodWNjekZ6aVFPTGxuVWdZOERDYmxNNktFdz09?=
X-OriginatorOrg: citrix.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0f0ec4ac-9bf5-4135-f033-08de5d18add7
X-MS-Exchange-CrossTenant-AuthSource: CH8PR03MB8275.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 26 Jan 2026 20:22:51.1024
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335836de-42ef-43a2-b145-348c2ee9ca5b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Q9IXVYikJ+2N0z8QQGkw4V24ePnTeFuqYK9jvJ2md0f0PCLnvc4SCzK39fQan2bo4gHoFrXIy5wCRj8M4NeSwSathy3IF0fiO0eeyz8FNlI=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN8PR03MB5122
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=selector1 header.b=o4+rnOd0;       arc=pass
 (i=1 spf=pass spfdomain=citrix.com dkim=pass dkdomain=citrix.com dmarc=pass
 fromdomain=citrix.com);       spf=pass (google.com: domain of
 andrew.cooper@citrix.com designates 2a01:111:f403:c005::5 as permitted
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
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_TO(0.00)[alien8.de,gmail.com];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBC6ZNIURTQNRBJE237FQMGQECLTC7BI];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[andrew.cooper3@citrix.com];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 102F88CFF7
X-Rspamd-Action: no action

On 26/01/2026 7:54 pm, Borislav Petkov wrote:
> On Tue, Jan 27, 2026 at 04:07:04AM +0900, Ryusuke Konishi wrote:
>> Hi All,
>>
>> I am reporting a boot regression in v6.19-rc7 on an x86_32
>> environment. The kernel hangs immediately after "Booting the kernel"
>> and does not produce any early console output.
>>
>> A git bisect identified the following commit as the first bad commit:
>> b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
> I can confirm the same - my 32-bit laptop experiences the same. The guest
> splat looks like this:
>
> [    0.173437] rcu: srcu_init: Setting srcu_struct sizes based on content=
ion.
> [    0.175172] ------------[ cut here ]------------
> [    0.176066] kernel BUG at arch/x86/mm/physaddr.c:70!
> [    0.177037] Oops: invalid opcode: 0000 [#1] SMP
> [    0.177914] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.19.0-rc=
7+ #1 PREEMPT(full)=20
> [    0.179509] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIO=
S 1.16.3-debian-1.16.3-2 04/01/2014
> [    0.181363] EIP: __phys_addr+0x78/0x90
> [    0.182089] Code: 89 c8 5b 5d c3 2e 8d 74 26 00 0f 0b 8d b6 00 00 00 0=
0 89 45 f8 e8 08 a4 1d 00 84 c0 8b 55 f8 74 b0 0f 0b 8d b4 26 00 00 00 00 <=
0f> 0b 8d b6 00 00 00 00 0f 0b 66 90 8d 74 26 00 2e 8d b4 26 00 00
> [    0.185723] EAX: ce383000 EBX: 00031c7c ECX: 31c7c000 EDX: 034ec000
> [    0.186972] ESI: c1ed3eec EDI: f21fd101 EBP: c2055f78 ESP: c2055f70
> [    0.188182] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00210=
086
> [    0.189503] CR0: 80050033 CR2: ffd98000 CR3: 029cf000 CR4: 00000090
> [    0.191045] Call Trace:
> [    0.191518]  kfence_init+0x3a/0x94
> [    0.192177]  start_kernel+0x4ea/0x62c
> [    0.192894]  i386_start_kernel+0x65/0x68
> [    0.193653]  startup_32_smp+0x151/0x154
> [    0.194397] Modules linked in:
> [    0.194987] ---[ end trace 0000000000000000 ]---
> [    0.195879] EIP: __phys_addr+0x78/0x90
> [    0.196610] Code: 89 c8 5b 5d c3 2e 8d 74 26 00 0f 0b 8d b6 00 00 00 0=
0 89 45 f8 e8 08 a4 1d 00 84 c0 8b 55 f8 74 b0 0f 0b 8d b4 26 00 00 00 00 <=
0f> 0b 8d b6 00 00 00 00 0f 0b 66 90 8d 74 26 00 2e 8d b4 26 00 00
> [    0.200231] EAX: ce383000 EBX: 00031c7c ECX: 31c7c000 EDX: 034ec000
> [    0.201452] ESI: c1ed3eec EDI: f21fd101 EBP: c2055f78 ESP: c2055f70
> [    0.202693] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 00210=
086
> [    0.204011] CR0: 80050033 CR2: ffd98000 CR3: 029cf000 CR4: 00000090
> [    0.205235] Kernel panic - not syncing: Attempted to kill the idle tas=
k!
> [    0.206897] ---[ end Kernel panic - not syncing: Attempted to: kill th=
e idle task! ]---

Ok, we're hitting a BUG, not a TLB flushing problem.=C2=A0 That's:

BUG_ON(slow_virt_to_phys((void *)x) !=3D phys_addr);

so it's obviously to do with the inverted pte.=C2=A0 pgtable-2level.h has

/* No inverted PFNs on 2 level page tables */

and that was definitely an oversight on my behalf.=C2=A0 Sorry.

Does this help?

diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index acf9ffa1a171..310e0193d731 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -42,7 +42,7 @@ static inline bool kfence_protect_page(unsigned long addr=
, bool protect)
=C2=A0{
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 unsigned int level;
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pte_t *pte =3D lookup_address(ad=
dr, &level);
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pteval_t val;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pteval_t val, new;
=C2=A0
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (WARN_ON(!pte || level !=3D P=
G_LEVEL_4K))
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 return false;
@@ -61,7 +61,8 @@ static inline bool kfence_protect_page(unsigned long addr=
, bool protect)
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * L1TF-vulnerable PTE (not=
 present, without the high address bits
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * set).
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
-=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(pte, __pte(~val));
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 new =3D val ^ _PAGE_PRESENT;
+=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 set_pte(pte, __pte(flip_protnone_guar=
d(val, new, PTE_PFN_MASK)));
=C2=A0
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * If the page was protecte=
d (non-present) and we're making it



Only compile tested.=C2=A0 flip_protnone_guard() seems the helper which is =
a
nop on 2-level paging.

~Andrew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
adad05f-bd56-4f32-a2d5-611656863acb%40citrix.com.
