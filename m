Return-Path: <kasan-dev+bncBC37BC7E2QERBHFKY3FQMGQEXF6LA3Y@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WEFAFx6VcWngJgAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBHFKY3FQMGQEXF6LA3Y@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 04:10:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id D8BE461300
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 04:10:21 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-88a37ca7ffdsf8523536d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 19:10:21 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769051420; cv=pass;
        d=google.com; s=arc-20240605;
        b=TOXd7Xp39lMsWVo/N1ULXirrRxsuyaD+QliIVnZcwGRh06+AMBYlMRGOu1jH+7txcE
         4SohZGmoA8yo1Qdk/h/kPI9R3uPucXy4wC6LywxqBY2C4cFpv76fl/BBGsVJ2MZFatPV
         B/T+mdEdj9Jgs40Igt0D4v6iLgu7vLG7L+XMJamKKtzhrKuekLQYn1xfApf7QV3doM1Z
         bkozf6VdshcL0VrrrWteGFvRlCfpx4UkftWh6NII4xM05iqhglardrJ0RejTdO0K4Ydz
         AhN+MwR9muJhUaX+42SGaXq/a+RrsM8ZHbyn72Px7/GwszgiMaJDinnAki/c2CaMT7p1
         J5Gg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bhFdgsXfM7VcbO2tT3kKHAI5vHqgQk6+C00OWzK5azI=;
        fh=4nIHKfWpKVYkSMwSXof8bxLzRNZAgWZUKbkic7/JVSo=;
        b=YObnSSm5iqRa5yegtFsA+qTqbvJd7AwQVIcWDJu60MoplEnH6BiytuRhMo9aVriSVn
         GuDVVJOoiZdwlWX62VqVXUa/0JAXtxjGT+xpQ6a1IzvylA/xwDqJTGTVQnyb6kJ3V+ZN
         woHGxPEp1kjYnpZl2E9/GdgnUSNetzXSywnWGJ/jPnL+6uQWbjNneKuS2blvizvo5EIU
         fVK9cQQC4H3duogbiGwsbYXpUGIE16Nr9sPF/h6AR5YiQxkrsFt4d7t6Vq8bH0yRLdlA
         2MtRcp9JeVqULntgase5kTHW9k4G3N+dFvV1+DabR6DynTG0aS2hmh+zQSxKjigV4nAU
         lTyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=OrNCPQSV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Nwh4ZODh;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769051420; x=1769656220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bhFdgsXfM7VcbO2tT3kKHAI5vHqgQk6+C00OWzK5azI=;
        b=S7haeB9EkR/NZRjK6YB98VSceaIVXSYMeYzutise5r2S5YHpH8ZhJ16Jg5xMI6Hc83
         QPcwZZwy1/19FbXxjWNQfR22/9gH8BEJ3Q7+aJImN2jlh5+DOUk+s8kWSvyC8NPcLPUi
         gqy3mUXuySvlixgkvdx2RoxwB7za/guecgjKh4seTV2bmFAaIudwLiTkd+XcQRRfTlWj
         RDOLd+o66LmnluTCQ25Akb2Px4r38f3PIW55u7qEt4a/XjfHVOS7lMN412iImg1/zz+D
         y7s4SYLw6KiSDIlB/va3Ntr2XgwlsGEQ3csDFPW5IKBtu5saRJHaOGCaZJhU7FHd8DRj
         BSng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769051420; x=1769656220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bhFdgsXfM7VcbO2tT3kKHAI5vHqgQk6+C00OWzK5azI=;
        b=vAOwalL/kOsxx2uHUGrgGdNMer5pmj2liEI2aVXMw5QjfGODjt2xfixQ4akCHtoD+h
         0W3e8VeenqVKX89/c2qLd1Y4tYFAPpPI09bpSyc/LcHSoK2x3rt7louhx3o+WDCTAFzk
         lh6I23Hpdy2ayhe4LCbZTd31guOUMRS9/3L0jeWoPUeHOiA2K4wW16aTAmnH5KnDDXzx
         3R7BUuMHGvqLTe//hhCTvOgSSkEqUA41LJC0wV71UHclVvG5qEAPDQxfJ/L/OJBOc70/
         Z2eMY2kZ9y6Z/9yz0XX4DMTX/2BAnwARkMny+R3XmHSGdtruy31jcMc5/snxMkepOX8U
         kmcA==
X-Forwarded-Encrypted: i=3; AJvYcCXEHkq6gIZPO/zHuIUyr4ZQ2zyFtVYRMCFYAYzL4VKFSgheYvYtdF0pfGL9FbYS9zFyFxZ15w==@lfdr.de
X-Gm-Message-State: AOJu0Yz+KYo4cLVflV023D+U2ouTdBnnfFPzwLbTFpU/2SU5gwL14qRw
	qmTiMdGGegr/GhlFmN5gX42m5us+endvzJWEZJfPNrUz+OXLYGh4Cnlp
X-Received: by 2002:ad4:5def:0:b0:880:461d:2e19 with SMTP id 6a1803df08f44-894638fe732mr119766686d6.42.1769051420477;
        Wed, 21 Jan 2026 19:10:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HXlGPFbNVm6L2+vbo/Dyia76ZCNLUIH0HwF8hwV51wyg=="
Received: by 2002:a05:6214:2481:b0:888:3ab3:a46f with SMTP id
 6a1803df08f44-8947de05ae1ls8294186d6.0.-pod-prod-08-us; Wed, 21 Jan 2026
 19:10:19 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV/0+S4GNue4uijMKQV5qegJP9g++tCJK6gy+dVFU2SMvMc+JEdHAtqB4/BvsjSJnu3uN7AKIJgmF0=@googlegroups.com
X-Received: by 2002:a05:6214:20c7:b0:894:4913:f2b2 with SMTP id 6a1803df08f44-8946391a642mr118599166d6.56.1769051419479;
        Wed, 21 Jan 2026 19:10:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769051419; cv=pass;
        d=google.com; s=arc-20240605;
        b=lVoShunOqgEqHr5vW3hGhWeDODbL8eHHHQkllUOPgaX4CSZ/3ZgVNL/iSZQCbSe6O1
         0YrVSg3v6YZ+m5SoXmZDYy/4/hNJfgSxGFUtnNw06x5naEoO+SND+0rMi9w80NoS7liR
         wbN88BCI5wlezdS+67QmBHa7SBsonTEvQpspioFET4ktHDtAwcjnONQVbt81mVIGIaZm
         Eatah4dFz19xXq/e72dOgeDbnvMrzMNopETUbtwWIGWLQ04+tzhd6yILURi7xqBZRDJj
         7OKnkYww49l0JN9wYt6B3s5jwfs6RvFMLOjJXCv6znsMQ2ZeO4ZjustMyRStetCQZVg8
         HLww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=72OaI9b4MU31b2MbkfRLyaJKkrAvs4rMRPdCj6OoRK8=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=YX+efoFrHjhrWOqx8w89KS5VmaqrfJxzyJiRwgQOMGEG7uaS66Xm5xZtgaUj59h1hE
         qPFr03kjrJ1JsRDll9aOsY2wuGoDOurhZ3Ebsl19R9zUquZmPkBuX/OwK+puN1pt9kSO
         OqB9AZY3J/qGgczDPE5MpD2X/GVNKD9TUiPM/sjTm6dsSshP7fW9d/3oH9kGK29kxa28
         +2cwJdp8kcGPzBOPsCRfO95Xb3mdPY3tXC415xBbQUam8Fn1WztbRNtP0BDvEYaRpbTW
         slREMjiYfwRl54nPtvir+n97GZozFDFJeKOm3u9CXbXRo/n3+3E54xNWrUPEDDCE0mlp
         Ki4A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=OrNCPQSV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Nwh4ZODh;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a1d45467si5696171cf.1.2026.01.21.19.10.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 19:10:19 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60LLW82F3418983;
	Thu, 22 Jan 2026 03:10:17 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br0u9q884-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 03:10:17 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60M16jWL018185;
	Thu, 22 Jan 2026 03:10:16 GMT
Received: from ch4pr04cu002.outbound.protection.outlook.com (mail-northcentralusazon11013005.outbound.protection.outlook.com [40.107.201.5])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vc7q2c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 03:10:16 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=FJQEvLXPuP1QQ2EuWTuii7Pbhm1MAPGI1IIwn6VFgWEqPKFGvfV7Iq+rl7xDltMPZei+1LRgM8VhaSa+kQpYfXRBlzUFgmIJi9BYXU6NilhvlUORnipk+DVz4ut7/74IJr8PUQFjYFaI0JRVIKzs9/IsIhUgb95H0qUMXVJEQ2sCOxOiGPlY54Sn/YkbTnWoa3L5Y8w78aeEHnkomPWJKTNtbdJJ8+0Drbp9/WICBRephuSTfrYWk6lmEeFA5Ji7/OJiZhESDAjHDLjVbyVnJJbFNF5tquQSpJ6uCwRV+oBi6cmvNGehubWNgKM94YAaY/iG44AHIHrkRsqUSJnU4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=72OaI9b4MU31b2MbkfRLyaJKkrAvs4rMRPdCj6OoRK8=;
 b=JfYLFV0U48MmDgWdNoPTRtKFC66/gQfuqbTCdodeFGQEMQ/4bdlvk6/pAV4uz0W83SaJU/psPxKs1zClVEoTZh2kA8NU06jtsf/7z7OwzGLnenuVTlTV5RPJsOqbCgfULe42Bs1EbpV3MtHayTwvh3N/8iJYGwbKUL1gJkMhkx3ny9xf4YwWuZhfAuz0mOXehJ9XeXoV/N5gTy1btBOLPyEZZYlCaW9xbGJh4tUByYRnD+CCv8bBHWYx1o3dEiaT45JfVJ0tLkHMIQm0xek4UkoekNlH6FxeslkRUAwm15Q/nD6MA9NhJ+8qDQsiO5Dr/y0MIJHbuba/Hq0ozwu1xA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DS0PR10MB7341.namprd10.prod.outlook.com (2603:10b6:8:f8::22) by
 BLAPR10MB4851.namprd10.prod.outlook.com (2603:10b6:208:332::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.9; Thu, 22 Jan
 2026 03:10:13 +0000
Received: from DS0PR10MB7341.namprd10.prod.outlook.com
 ([fe80::81bc:4372:aeda:f71d]) by DS0PR10MB7341.namprd10.prod.outlook.com
 ([fe80::81bc:4372:aeda:f71d%5]) with mapi id 15.20.9542.008; Thu, 22 Jan 2026
 03:10:13 +0000
Date: Thu, 22 Jan 2026 12:10:02 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 15/21] slab: remove struct kmem_cache_cpu
Message-ID: <aXGVCmvvt2N3Xcgd@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-15-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-15-5595cb000772@suse.cz>
X-ClientProxiedBy: SL2P216CA0098.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:3::13) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS0PR10MB7341:EE_|BLAPR10MB4851:EE_
X-MS-Office365-Filtering-Correlation-Id: a9fd12d1-ede6-4cba-00fc-08de5963c1b2
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?hYf7o9xjwDz5DWdQhxaP94fMVt4AMlGz2YhMPOp36SJDaxQSjDX29gIR2G4i?=
 =?us-ascii?Q?D+4a78fs64uxmoYLIvVsRbIhIH4tDTIlQLpGUZjOICFRyrawR2tg64W3TMxc?=
 =?us-ascii?Q?yc+lKwKgU8NIHr/klu56c7sq7GJOTrQwPk2oXCKU0+fOiwOK81gl0E9+hVuH?=
 =?us-ascii?Q?1mkUAwQQ2JtI/9mQ3iRuNZAqHMaJmCk0aafuLesXpJE7hYX+Z3rMVjFNvFbk?=
 =?us-ascii?Q?ObcJ6hCaBS9F1wCy3l1he3wcsVelfrQ+ogm+mql3BNN8WMi6ZuasXPY3/C51?=
 =?us-ascii?Q?1mVNNnMrqAGQSywfFqFRo9BBylE9QzQiVvTlmja3AdYxQzWhcQXUagCbXujN?=
 =?us-ascii?Q?nHHgUhuN/pT0jaLkhYSJWMdBCsurB+qL9bBrzfW7uCutXr5UDbjrPUZ5ejsV?=
 =?us-ascii?Q?hNPEVejGqGEjnI8mdoZw1N+QmC46x62nwFH5xq5bFOvwQ9feJJQ/C7vt3mz+?=
 =?us-ascii?Q?fMPr6PLwfvBa4BoWTUzDQpLImMpSz9Mw9/Z93oYvMeWKEfrxCsPlkW/SZjo4?=
 =?us-ascii?Q?sSFjTaX43eMX/hHs1HGhTb8E14Dw7qrEWElTmE0nLtQeBYR6XwAWp6c+X3jY?=
 =?us-ascii?Q?KvguJqp8nKh0mT0u7NOPEVdUNT5GXUHyDUB6drffxm41sZWIvxxf3+taVnhs?=
 =?us-ascii?Q?2/oToB9PeI2pcvPHoc4H9AqRIG1y1XFOgouno/NOQcg2zyR9Kos6BI6OcroO?=
 =?us-ascii?Q?4UZhXj+A2XSLfVqiVLLjvCIq4B4vPT7+okYn/JmgY+kepnXbAkx+vQaCY6Sc?=
 =?us-ascii?Q?6sVQvGehM8T9of5yQP/Ec8PoHPyPU+lkJ8DhdmzHgl+XEh773xrYdSM4qibF?=
 =?us-ascii?Q?o9+4ZR9ANa+79KUNlCVl4zq6g0j/MIieGIOWPbMWLmBlavbtwtBqs38dsaUq?=
 =?us-ascii?Q?LgCr4KgxofdckeOZ7YZv4XOX4MnYPHiwyjulzt6gaBh9gvp5l6BIwC1YaDoM?=
 =?us-ascii?Q?lrIpT5pe41xPpgbB7u3Y1x+ZJW7SQeley/8AzywUdhy2Kknt3iSfwBm45/43?=
 =?us-ascii?Q?gzMhJFZ4CX+TH2I3OXfWZvUDOxK+c8Ie3DSdfXtCeYmoO8QT6l4sLgzFR7me?=
 =?us-ascii?Q?/qbdn6iwyBvxYd6D/vh3gouO0UJuEnD8EOaJlPDKpt6QBBie8v/nMYgt+u12?=
 =?us-ascii?Q?zIJx9CVF1Um1cdlIhURZ5+qiFFhtDPfvZExIjUVPVr8Hb7kKpFGBocE7HExp?=
 =?us-ascii?Q?vinCmjVWOk1CFdW6cySAf3wSZkKX55oInYEJe+K5soGnMqaA6Vt/6cO54Feg?=
 =?us-ascii?Q?TaX8N9RXX9bdKlJ4+xNap4gXznIy4PpTd+65OKe0/X/w7LAG+5eWYOPz8rGq?=
 =?us-ascii?Q?27Wcmc/ze/3rZfLO1a4cvuffZAPnUPKUBRX15CT9pMnX4VujuALUuNiSFFHJ?=
 =?us-ascii?Q?9X2q1G8GW3ZPboZctzRqWclZL7+nNe9wuRFFcH1qY2rmNAG96HiHdvuSChnS?=
 =?us-ascii?Q?AU0GWtEosU3tqO+6uG33HT1hYYduIjw9ZLWXKWmuBI/kQcf74rrdm0rnunGV?=
 =?us-ascii?Q?2g8IL7OH6Uhm725cVMXbl3uiV3C1emWliIWcAB0DGdVU2kEzKtnzuW+buYsO?=
 =?us-ascii?Q?01tZbKUWGKTWRYBOh2c=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS0PR10MB7341.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?T6frYYNnKLHspwTDYTJZkIY+OaF5SBAZblnc8qm6o84ABS2F5OYPJgaQ4OjC?=
 =?us-ascii?Q?bAjkt6Gh0+CE2grpRRB2QyWPauubdpZ6lPv2daOOLn5LyEAs3nahxPnizwfl?=
 =?us-ascii?Q?+VXbiK3cvttt16cmRHgRxmrdHnsuvI2I1mlX0arP8IMxyO/X9iOZI9Ax521A?=
 =?us-ascii?Q?vUFkPk/Q+KBqDLO4KmwNwBdMSIeznc4qYBLJecDgcr0qxNXLqrwE3QBNVXW4?=
 =?us-ascii?Q?yHsXMBtKVfnENPEsVb8LkAYXL6kuBmzda1rKysuIoBDutkHjs79YTF5DNL2b?=
 =?us-ascii?Q?vgG82ZcZ1Xy4nz56qbz0U9Dtx5YFpVDvMkPUVc4G6gXh8rWt+azGookLMgBL?=
 =?us-ascii?Q?D8Wjx8J2YQA9GSN8e3/kjtclax30SfHAVC0XWTgA2mZtcT8XESqb2d/tfhCs?=
 =?us-ascii?Q?AW36LprXMH6IsGT+t7QW3aXmDHjylulYqU+gj0uT4YryAbYk2FfUcar7qO0q?=
 =?us-ascii?Q?hBLb8GBlbqidvh3RBUBMH7gMsGYb6GEaxHEnVRnoR9a3PBe4fzOkBJNCEmJ+?=
 =?us-ascii?Q?Jn5zS9K9i8tg7g+tHaC0LsKFTURm1QkINcRu/sYAgaV1FMyHkbOeZtJPbiyC?=
 =?us-ascii?Q?gx/xEOi+ojBhpuM09PszmT5ghn6hkEI/jewfLhfKbsz0pVXiaVMCX2jXfQUX?=
 =?us-ascii?Q?ujMliSCXsJrMLcY9tbXU7hLU9JkCTiwIvB3LnUEz467c4po/vvD8LtiOl14v?=
 =?us-ascii?Q?LyB27Vioa6e5aMjsf8WoamRwrClNOUV5MPQzJR/8AfeRnl3w/k5PQeLGdRCR?=
 =?us-ascii?Q?2DL2NIYWl3Vr1JGgP21ONiQaIoOqEj0C8QNbqULlxnLyOrCIpkBSCG9Zcf4e?=
 =?us-ascii?Q?sJCj9fW29+mAZQJQMgrO0CLWClbP+CZlTtX20b6hB7Uallp2NK/2jvLsEdBG?=
 =?us-ascii?Q?APdEmW+IpuziWjecQV5nuLmfWcTFMdhBjCleKjEnfBHI9dPowddj3Or7Q6dM?=
 =?us-ascii?Q?PWtdXq5pRYBloCytZj8biPiJUFyPfNhycdaxRvsuu8OA/WoDWG5Y7o6K6W9z?=
 =?us-ascii?Q?ml0tkF4nuQk6LlGTdAWkBNrNYlVqulvIGiwTzqwGg4a9z2xxlO1t6Y+MeJzN?=
 =?us-ascii?Q?SdQZL+6iLabwM/cqFknlTYExxylMjBtJeZJANq7/7brikrCEahgVOC1u28oV?=
 =?us-ascii?Q?udE1kEqWCeD8TH/zXuy4QkkfapcpedXUmGG93drFHWVmCJtHLthEMqd7C15A?=
 =?us-ascii?Q?/LHCpSnSa5OlMexijVde7A4cUnWINBszj09dOIE1BpPUvN4oab9kZqS2y16H?=
 =?us-ascii?Q?kOkGGewLTYa3I26OyrDL35W5TLBKY45WjuAdZEHd4p2seubw+CNdnM+CQHTL?=
 =?us-ascii?Q?25N7Vts01Cl+eyTEbrWijIthPPfpPnQmeBiQWpRkz2i+BG5oowcCYcMnv1U1?=
 =?us-ascii?Q?R+cR7qknRmDVm2bNbkwpm9chztR5SZ8QHcOQ/8ANZP7eJkMVd3FiVzcpBaeb?=
 =?us-ascii?Q?hZ4N1F4idhAiQUC11ZH1YDoMLWI4rk3yFKe68hhNBvA4wVoLsWN3/8ulVEsC?=
 =?us-ascii?Q?xTdZb9uTNeshVBCuPekLd2K3+7aofMfr1RAfx35mmmR1pZIDjvlOAozjCphj?=
 =?us-ascii?Q?w1zdv51E4qf3Jn08BVkuKWFyR1/nCLKGdts7I72HxeCowrxdEBGWc/Q+JHHc?=
 =?us-ascii?Q?JH4+kyN28MiWDzGkpUAFbTHvWmIhpkriq6NpFuHD0cScVmSKN6aqJUwjp4AY?=
 =?us-ascii?Q?fLVZb1N4zhPjNpVdXAn+rUKAeqZUUX6f6bMBBLCFwEMgBixAA5SdrklsL4vr?=
 =?us-ascii?Q?KKDMheVWbw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: vqyMt9gN59VRF7fuJMuyp+zmmVu+LUdsfJlgWg1MA6QWDBcecsPx+zaSGlwgiWoQ8ZXSX7fWl0YFfPLNG0ZHKlHsHDkvRN4TQhfgkJHA9fuibIhRPua10treSM8snlqacMeNvtBdhRIFpv7eTFI/xadg3d7GamwDEpHv/+XWrR7KwtI+1GWCnDonViMG/8tVU/6ViAbIkmYGXdBRUpCuz+uditEuAJhKnwPgWJ/BEMRF8GSY3xqSf676tyRPIOiACsvKJ+3maF4mOZtKjRnw8idfY08+gd9VxcDcB6tKvt6A72NF7yF16S68/vCAijceyYib+vCYsVkCLO+KbSm9PrWTL9GLB0Q6EoIaQlvyEaTFT8pclJYIV4VwyONK+vZcrS1k6UlEE8XD//ikvJgr9k8swww5mVJf4j38D/W593BN63X9u9tLTrv9v51pKLHTQPGFmECWHXuVRYhvwQ4isqxB1IyzXU5TS/AgSLDD8HR+2SiKSL7QPzn+4QtwH4ewbMw5F4nU41AGURAI7UBaVTMDKRP5PEd2/U95O4kuyOm1muF6jsdNMOaAsQfwRe8RFJ15dP4wQ39YbQpimXG0SERHxhqbKO+HESEQxbPeQCE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a9fd12d1-ede6-4cba-00fc-08de5963c1b2
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Jan 2026 03:10:13.2024
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: XgDOIc4kqsD/ripoLZbHaoJcl6x7n2BustTdyYnIUgK4aWhA4SmggnLnxVGGfdATgSHV8qo7ZA+VEFpfIJ3RwA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BLAPR10MB4851
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-21_04,2026-01-20_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 mlxscore=0 adultscore=0
 phishscore=0 suspectscore=0 spamscore=0 mlxlogscore=999 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601220022
X-Authority-Analysis: v=2.4 cv=OJUqHCaB c=1 sm=1 tr=0 ts=69719519 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=-YXiLwkaz6cLH1okR_wA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: bQQIkjIhccBHOJSL85FTgF0rxBTCfDLw
X-Proofpoint-ORIG-GUID: bQQIkjIhccBHOJSL85FTgF0rxBTCfDLw
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIyMDAyMiBTYWx0ZWRfXyAKcan9IG9tP
 2IeiJYtyuEFDBfvGkzdXgb3FErPCh9+Dqm/TZX+cHWkY/eL8k5yaJVyuk9tQ+g7+v2u6EFpEsmw
 2atbP+GGG/JOS4ReZmVufE8JAEwnwPauH5UeKvxdb1UCaocIkhaWJUeAGY7u0cL2tzmiQapVvVL
 bL9qgLAjk36yqCfmuK1zgl33p+kqRlqj3MOxUM/5D1ZCNRfp8xXLuYIwt677Pe+JZvl6BFyxRgh
 6lvM+7VbQyTYuCThqbbpbiXn8cE2oZ5osNcov+qj/586midJoA2YM335/aTxeIfLKZX8bLFNeNC
 NiAL07TETb6c7puegLeMX+BDVsyV6HdbL1ieUCVB86P51bQEY32Xrh7UBIW3gTIOzhrmPq6aOqF
 sEBQoYDRzx2UW6LSa6uGI1RWx7nirvy5Sm8/AvuCexR+vhc2K4CJctBtxxwVNTmP/m0QghqqW6/
 X5y41VBOwatzgZMR37g==
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=OrNCPQSV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Nwh4ZODh;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBHFKY3FQMGQEXF6LA3Y];
	RCVD_TLS_LAST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:replyto,oracle.com:email,googlegroups.com:email,googlegroups.com:dkim];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: D8BE461300
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:35PM +0100, Vlastimil Babka wrote:
> The cpu slab is not used anymore for allocation or freeing, the
> remaining code is for flushing, but it's effectively dead.  Remove the
> whole struct kmem_cache_cpu, the flushing code and other orphaned
> functions.
> 
> The remaining used field of kmem_cache_cpu is the stat array with
> CONFIG_SLUB_STATS. Put it instead in a new struct kmem_cache_stats.
> In struct kmem_cache, the field is cpu_stats and placed near the
> end of the struct.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXGVCmvvt2N3Xcgd%40hyeyoo.
