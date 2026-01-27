Return-Path: <kasan-dev+bncBCYIJU5JTINRBKOS4PFQMGQERMVB3EY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id yDK9HyzpeGmHtwEAu9opvQ
	(envelope-from <kasan-dev+bncBCYIJU5JTINRBKOS4PFQMGQERMVB3EY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:34:52 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id EABF497D1D
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:34:51 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-352b6ad49ddsf3908967a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 08:34:51 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769531690; cv=pass;
        d=google.com; s=arc-20240605;
        b=P8err4GG2tBBNHXFyK9XDh4EMXGL4sHwrckW/h6eHbyeHHi0MYg3ptHqRHmox6TqtC
         3nU/p3O+6vZKWnmZT1s5Oxax6XQVoipbJLQydmVyPwzC14bdFxm20beNuNnTdeZZJnxQ
         TCbusLb2b9qJn9stPPGwmNowQ0w8aDkNPWmiRL3BkHraIfuh71KMRs7Zp6k+GA6Fjfqs
         HkwNj+9a5YXDsr1jrD/yBy9Wg6DGzGOI8Orgy2y7Koc5qkYKMBHEbocnPjjqvaeTv9jW
         CkIsHEnMY5h1X4pZJbdXexFbesyINmbxWbI14VQpZYcdLINYMM8VlxdkZWfVlb8Iyfql
         94dA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=crJEc67WLftYV0FIMs3mWDAcWcGNCU0uB61CzPJukFU=;
        fh=/bql9nbMxx9gqpIZ2a4frsgE3gdSA96/H/l2cySRA5c=;
        b=OZIg5eZWuZqKMAuKKgQbyGjiSWPyIyFBoJoO43a2zPXqb4XNI0q9JrCGv3Lc/uFpqp
         f344it/8qqNqGDeKR98KV3Lb6uN+UkOwSGPiErTfBZdI8oL4/D2/0kE9RdeczK6fEYi2
         ig9VrmZ4cuwsb5LTlMgDCEbF0q3hx+O11iyZysj0x61VhWpJzXFMp1b4EnXI44d5rOq2
         1VZt0wdQF453Jy0akOb8czT0NfRELecXSTXEv1HgnSAdyP53c/8TKy/m8zkVWB6PW0VT
         mrNL8xnMruKvAmh2jKPbBFrRykaErDkntN4N620pOQ9ys1GJoymlUgpmuYtlSWId3dxG
         M+LA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=d8monSAR;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=aCfA8615;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769531690; x=1770136490; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=crJEc67WLftYV0FIMs3mWDAcWcGNCU0uB61CzPJukFU=;
        b=eZlr4IsJO2aUGiU4n8AHK4+ieMSt3mi8N4DS11TrcpEljs50JaLzq9Zu3tm+sIsgkK
         EbsDDmZpGx9/CdVin22AYmNyt4vrOpSzaIqTApWszzCHS0WxCtCVMJYBd0dfqNxSTo7U
         t4ExGzCi3IGuEn7iaFnT3zhf0f7g8NzZ6QYEr+PVNonZ9vxgjyMA2EpyYtv6Oe9ykxET
         sPWMHPIkvoPDirW/IxpzHR0vFbrw6fK/U0cuc+7KqU5eaUdkGoNVIvM/BSJ8yppgvh3K
         e7IQGL3Ff9GvV5AVv47bElQ6DM9iNIIXwg/Acy08Rb7GuEfEL/T9hpTbH8tQ7TJYPab0
         M2Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769531690; x=1770136490;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=crJEc67WLftYV0FIMs3mWDAcWcGNCU0uB61CzPJukFU=;
        b=IyUBJmZ6hwkYDVje9Y/azhFD1/iZQUFMQmrDZRbxRo6o1JFYtzSSkyzSBKuYg3sE1O
         FT3mdgLFPIQ/02xcqORkJiYsjdvaIfkEWeddtzu2s+O/cHWm5d5FteocYadrAe3rbimS
         xAXzn8plmusUZuclu0ARpu7Sdogh2SyOikZvUAQT+KihVU6I+yJkVU37TI5SK0vqi0gK
         BsvsJPYtCSa5Sn2HDMoWueUKV89arIWuKV3Q2DG3gAwRp+hqnu3TthckcdbJMuRa/5ge
         l+TVx/CjJ7YnM5mArZjzb5dy1bby2LDN6yZ7nMXOtoPayeY5JO/p7wVQ7PNQDT2FjbeF
         yzsg==
X-Forwarded-Encrypted: i=3; AJvYcCWpZV58foyX72bl7FrL0rSdHNKa6Fex2U1A6HWe0l1npJ/P/GlufZ6/+1/OTdYmvRogK1zf5g==@lfdr.de
X-Gm-Message-State: AOJu0YysQ7gMopd/OYr7zdpM5u57Fuk+SQJTvY04RXwQkQMSh+a7hd24
	xMfEVR5F0p8f0yxpTPb4kMOgvH3Y3FrBSqpPnJhQxyQZAwN0XdK7f1xY
X-Received: by 2002:a17:90b:50c8:b0:330:6d2f:1b5d with SMTP id 98e67ed59e1d1-353fed87644mr2220273a91.26.1769531689875;
        Tue, 27 Jan 2026 08:34:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H4rdI968ahUSvhxZqyRtdu/HnHVZVCOakCJBlrDlxsaQ=="
Received: by 2002:a17:90b:fd5:b0:343:3877:bfd6 with SMTP id
 98e67ed59e1d1-35335c14699ls4820202a91.2.-pod-prod-05-us; Tue, 27 Jan 2026
 08:34:48 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCW0XKUuP9PiXUo+xrzKHLTqjk7E3Q2jKOTh1VnSc2SZ1jeX8nkqJNHEftTntU8KdtrpuZ4unYEyavw=@googlegroups.com
X-Received: by 2002:a05:6a20:1611:b0:38b:d9b0:a93f with SMTP id adf61e73a8af0-38ec629ba61mr2315995637.21.1769531687934;
        Tue, 27 Jan 2026 08:34:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769531687; cv=pass;
        d=google.com; s=arc-20240605;
        b=RQvKMCBnJDH8c6F+R1ltyYoLCKScXSlj/uIbyIEAINovBuisAxFynH9O/AVBHxLCvv
         ku6UNC80geDIx45g+UKKDDkuyPKcS8c+BXXaDR8Ak3KTAnMMz42LeBIdIKgn60oH+Zr5
         R0ABNAf07gfdKK2j6G71ZoW6TrJIp5k/eCdd08O5izS8ZE0/P4n5Eootfs9Epllm5iZl
         E1xkQTWdAA5I1V1GLriHmOjQoYVYYtWyubGWtfhjjrWeAEVc/QzF90V0Pq4Xf4DcRN4X
         SaXWw9ungrAyFTXzNJ1IH12kvHrQOcvoF10o1kNi2eCHgjZ64xxcpbndrHyE290+gXBG
         fxcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=PlkVN4tWIQUp34f6IseHvSIDopnx6113rtk/tejfDQ8=;
        fh=EGMhLkV3udorsQux7n/+Xk9u7IyRbMe92LwjbXHNLfE=;
        b=hP1QJjsKvpEiFxlNLVAZx5KmoHa5ZSK1lhalUFt8bgKuCp3+x9aP7JbP31LRVTVx6g
         B+tHwvySanh6LQ/kVxsvjjs06l5Y5kQIInAAVwMUqV1upPYO0unPV8FMh0jk7PeA5FW9
         h9QrGtqzr0bn1y5lN5gX2yIrFjAJwvXVBFUnU2Jjodf7BLups5cSWINNRVWCnk6KEVKF
         1Tp8d++HVqyQu8V1/t9Hphx1yvQgCzc29Y/EKUQvP23M9LMGqn5On9zSDIUTDdPYFdmV
         gmYs3GuINI1+saF21HclsCaJPJngxIxZy0pfwsVR+DyKHel8FphXhpBiVmq7Mi+anggY
         AxpA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=d8monSAR;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=aCfA8615;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c635a11fe4csi523854a12.1.2026.01.27.08.34.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 08:34:47 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60RBELXf3922781;
	Tue, 27 Jan 2026 16:34:44 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bvmgbvbar-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 16:34:44 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60RG4Gdg019819;
	Tue, 27 Jan 2026 16:34:43 GMT
Received: from cy3pr05cu001.outbound.protection.outlook.com (mail-westcentralusazon11013036.outbound.protection.outlook.com [40.93.201.36])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhey174-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 16:34:43 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ZNkVZ7ybuUDabL311x2ebno/Ry2tBhJ0SpMsTgbWoqGirHs7T3hwuoKq28nRC5kvVOyeatypls2cZui5/2/BzVXW4wnUiaMOU34s4h80tZ5CZBy0XAHlMoSDjf19LX0v4yYeWevQhbK2wOzrCqpl+ftUWzvOuViOadPUD4NRnr2pY5nonGGsheSDrPizBMDNJOXlqvBV0ZdqYe0yO2uFJmC3JxAEdlaK9G5YB2ceq5qcRKCWtU4u610feJb9gk8SzQCuBos9q1kvCDta3uX/sHhel3V5uhSQx5eWQC9XwPbiKoeIFmmNSJoXxXkRAEahJB8j1i5Zz3gXpETw/7x2og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=PlkVN4tWIQUp34f6IseHvSIDopnx6113rtk/tejfDQ8=;
 b=g98JCA1Zj+GS6nYCFZfb0CrheTY4wAMOpWLQ5C8vdIWKJkqChzYrRA6eg8U6B2kowdKpECtko5trytZqfT6hMucinRlClWVWhmznuV2LTzj1UDrZWTql13TlDfXcQdLbsp0h5rK7qcnKyBUzlpx/4/449DR6wdZf3TAVCWVx083leCy2mMu/nbsq/zTS8CmqWoOofaOAOuLpfqZE2VeUZfhXKLpZeyYBePVgNlX3YMegMY/dqdmSD4oxmivgBNoOoRiQgpO1T7lyKOLnB4NMcInJLyVPcDfHo81pKRtKzoWpgzQM5AJMzWzcSuz9BxFukWOGpdqEreUaPT8tTbYpAg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by CH3PR10MB7561.namprd10.prod.outlook.com (2603:10b6:610:178::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.16; Tue, 27 Jan
 2026 16:34:39 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce%4]) with mapi id 15.20.9542.015; Tue, 27 Jan 2026
 16:34:39 +0000
Date: Tue, 27 Jan 2026 11:34:35 -0500
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 06/22] slab: add sheaves to most caches
Message-ID: <r3qfus4j6awmixdbcopgva3lx2l3lrvlvuoqqns64q6qp33qep@2hsrrvfsojsm>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
User-Agent: NeoMutt/20250905
X-ClientProxiedBy: YT4PR01CA0289.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10e::29) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|CH3PR10MB7561:EE_
X-MS-Office365-Filtering-Correlation-Id: 78112687-2d41-4a25-af95-08de5dc1f723
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|366016|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?RqDQJwNkMiqRWeldVq+8uMYgU8B/oc+CG7OKwY8oS272OSDlcPo1dmMwRuUP?=
 =?us-ascii?Q?yZ1iJOUHSvbl62CcCaiPMy21JrdwmjByYMzu16FhX3TwGxxqDIxcr1m4tdzH?=
 =?us-ascii?Q?NJz/AcBaLVikduStvOdKDmExB5yqrgosPz+LOQU04oxA3tEhBnA7KtbgdxT0?=
 =?us-ascii?Q?37pTVHju2ML9KAEHn5gnXC/V9pClPacf2LOjwJGEHvVwrnaVGFJMBBhF/pRC?=
 =?us-ascii?Q?31GHNEfL9vIH0ptL/d1E76hVEkZWCG2mo7mvrINxN658sAhbTh0AzRNukX3t?=
 =?us-ascii?Q?z20FEZT90X69Ys30EQtF6uEJsNcnssLC2YvH7wSX+dQT/KPUUwFabLRr7JFn?=
 =?us-ascii?Q?zjB6igFye8DeWywfZyREqT8kWcM2zJjRECu0h8I5wmsQ+aI9Q8KnCVYmif1S?=
 =?us-ascii?Q?t4qiKBiXIOJJSlIDipeCyPVn15kU991fh8EmRT0sdUWOYGw9CE6F/A2byik5?=
 =?us-ascii?Q?06F280PIKa+ax/XwtXuFzkRT/7UV/4xHDAl4/wQVyQvh6RmmQSqoUlJNlTe4?=
 =?us-ascii?Q?/DQLr2LuBVaCCveJcO3h4cLg4FZ3uGDS9lcxLNEVoqh2/OUs18GiyJ49MEdS?=
 =?us-ascii?Q?RJIu+Aa3BdJLjNZte+sUGtkhKvBsuR9ynuzoOvIvDUjEGPkAABdvB4c/Spoz?=
 =?us-ascii?Q?mWd8ATKczmGem9jhC4lLiiyZ8oiKeSxJh11D09QEzu+J7Loh7T/lOnyURd8H?=
 =?us-ascii?Q?8z/mF2xCe8S8yGbRQoyP/S3PqZam9UuJrZ6GPhvQfKC99NPt2gzWpIi0/9JN?=
 =?us-ascii?Q?rlR3DuTiukDC09jf+6gMEUQugf6BmUY87zEV2py3C4ezkTplublJKHm9EDR7?=
 =?us-ascii?Q?5uzxFKLl9BdRwL6k1gyg+zY3kLUjCEXXByOjxFqfbF9q7kmorDBrHoZYuL5L?=
 =?us-ascii?Q?+ESLWsHWg7IeTK95VLRqbYY9WD6eS9IYbJt0lG3Mpkghm5RDVjGntz/PD68i?=
 =?us-ascii?Q?7KR9qh/QZU7T99IW5eXTZ1VIy0I4Mueou7yftpYQZ/jfQkARwwf2ymqbfrg/?=
 =?us-ascii?Q?SXk+Hb5uNJnoPTE8agdNn/RO4yNc36W+3sGA5g3YqdBsBm0ZseNtI/f3SA7o?=
 =?us-ascii?Q?everJhLPSbhL25Gkk9s5v24rCtzNuFV5BpsvWH0eixwo1JEgXBxyaQme23hX?=
 =?us-ascii?Q?Z+/cddGmLYw72wlkSOZz/ZPmwSXD+s4yltGH9YNM7Tv0ODCryBiI6pQqt2C9?=
 =?us-ascii?Q?z8bmc69Ouchd3QK75DkdKUBv4MQtXzabyFsNfBM48l5fjnpjBe6mLkAvxp5+?=
 =?us-ascii?Q?5J+d0P4WUU8l5igwf7vfreSdx0xME8fLSey502czBYN2kUIKtV0bIzhfESX3?=
 =?us-ascii?Q?m2JgCtmBWOU4Q+UNQkRVhQO2p4yV7rM16ILTJ7r1sawXeSJo6aHcS75/28O+?=
 =?us-ascii?Q?jOqXvjkV/3B9uVzjZ8BuxVb0sl1yh8p2e8rkGbrUNCp0mdMQmdNJ4wzBXETv?=
 =?us-ascii?Q?qYqXNS7EjDTnF7W5waxeVw0viCx+oVH90AFIFkCl/zyTVgyeyF348AezGwml?=
 =?us-ascii?Q?+bn1bEp3QWItISLrQpik70zUlyUf464oDDZIlYpLujMfXKVkwKyMh8ZPnl71?=
 =?us-ascii?Q?tcBgPib7Tn4r/qfQY6M=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(366016)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?1fj/iV29uXPFIGe6Jg/usTfPy/0J5xZ5Iairc5jS5WtOYFcXOPUpaWpbzjYH?=
 =?us-ascii?Q?XABMGf4LgemML5g9VWyZhHE2VwFUEWdFmZ6HOG5RewucyVDRebqVPx95kPsb?=
 =?us-ascii?Q?0RUBhTnLpkiEFrIYsupqHlp0aa6+mXCrqMKQNaAgvTHSU9WZBImzY06XJ4+D?=
 =?us-ascii?Q?LqZLP+ORKAIVlWWYJtsjbRmb2hFEqf2Bp4STJJzlmAM/94fZp329H8Yly0KM?=
 =?us-ascii?Q?tJiyuUx7FNdBR8scCzlw/LLdS6FLD8xovkJOUEKW0E73v7trdU/j13eJD9hk?=
 =?us-ascii?Q?Gi2bIpxtjLBE5Q4dGZ/K8+88Pf9eI/7ASoGGr5Ph1U3prbu0o2jEzcRUr80P?=
 =?us-ascii?Q?lZcGFuuS+o4KUxWLTHOLHafDOZnHIzW4XJeejmpI+EteO5XpPmfD1PbMnLYf?=
 =?us-ascii?Q?ZFuG8rXLZ8kV+wF+acmBjpu/YPfazHoZTV1kSY8uueWhiYntX95+q1R0DOaB?=
 =?us-ascii?Q?Wzxw3T9b8/FiRbm2duMMepJ1oiU3+B/dM3fzXeuwM7AGnGXlCqYo1QYNTDYx?=
 =?us-ascii?Q?8B/WGfTbBARTx0vk04bkEs3RJp+b6kZAYZsjup9FxnFYK2nhItPGRdxUEwuj?=
 =?us-ascii?Q?ws/jQaht/S+Py/TYLovysbPdvSe4cRGikfexGwUzOVGjkNaiAJfFGgXEnr7e?=
 =?us-ascii?Q?0vvuR48tYwVHYGCzQ+UirMekjDqYbKnPMQL0cv3j96PjWbjg50t4v7w25ixT?=
 =?us-ascii?Q?hvOsY562WDk1SwbhfRm3I8Qf0SPN/5O7cuv+KbOBTpED2/BrKK7ZHW9fPKXr?=
 =?us-ascii?Q?obLWInr2vMApRkiHou2is18gGAqSfhsHWMh4q4wTdJJYTpouwH+KY78s8eFg?=
 =?us-ascii?Q?NIa/ujH/thFAH1XvuCnJX6K63vNYIagdYXgDOyONLFE6qvv0XD91DBSibZVy?=
 =?us-ascii?Q?GRb0Bq3X1kBgGuAwRNmev/lp67Chpu86sz21pmAFQ88jpKoaekXokteYvxPS?=
 =?us-ascii?Q?zQPSEUAiH0zZAzMXnK/UjLnK4EEXXlzh8mhzQopi/9/vvzIek904d93oWfSv?=
 =?us-ascii?Q?jSpd4h6tcECGLI+OKdqk7w76d9XTgV1PmN2V+uz2kmL8wIcR/6cVnjII4AGA?=
 =?us-ascii?Q?gt0wjn0IgMGQ0KdGbcHMJmo+UiAXL+2jJLOmVoqJgxBIC4vuIeYv0stg5I9H?=
 =?us-ascii?Q?fXPew/h923U9RvXiPhboE1inpnyT1DIeUxIDf6NBNBG7z/izrNgBg/RxN86c?=
 =?us-ascii?Q?LCYq9goxdrtCJPPNRmq4oSCeBCOdYbBvh+1ywy8t9CSFvZQFykyoTQMmwicX?=
 =?us-ascii?Q?Tu/p+VzNZ6nq6NY3+A88RgeGyS5OWn76PAKu3bjGtkrMplQpbKycODrzHCoV?=
 =?us-ascii?Q?lroBOcUfamla9U18a5NGAjBQqA/uZFFIitqw/1IIY4r3YbRJbzxSvF0Fjlpw?=
 =?us-ascii?Q?YJt5dCuuUVmTLGSFeVCK93xjL9J6zzerJpnfRUpqD/8BQjiGpy2qKnhtw9GY?=
 =?us-ascii?Q?Rm9MCFXjpjqLdGD62j3uglfjySfSaG2WXj68dpdW+mS2LG8KNtgkWZAp+rV0?=
 =?us-ascii?Q?3Sj3u72aqAatIbk3vb7PqU/T9XhQfkujemaqCxt3cVnEuMLHO+PEG+ztJS+b?=
 =?us-ascii?Q?lZW+RUChWIpsp7pCgaWiOHv6LyfvtMOotwnAsbjZnl0igJCAew2bnfsKF+oA?=
 =?us-ascii?Q?miNyrwAk21m5ZZY2wreUFtg78TYVo3RWE2RxKSe0GUTCgyoqAu6jqIVkyeww?=
 =?us-ascii?Q?XiNNNHj9Ignx3dBgKj82t2fvTDQ7EpEsyEzs8y/p74Bx8AymGYP/qps8//8K?=
 =?us-ascii?Q?rLo0lESTHA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: WXPwWz6QK3L46iG55Xyshp7n/QsqR4sM243jJBlwXuEtFLwr0mQAwOLD2196A1bFw2r4ooFWtZXce2XJ9hH8nRn0Bf0qF145I32aEgUJ3pHEjpxxIkEMmrMh4Xhghi7hQ69s9Kx7Cq7fD+eT1mpe1KBYkknBTvkkdp9nQxJlLMxVNi+Va2PN8/52Z0c/DZi0htLbVH9R0NY3dJ+d3Cd+mn45NOnoeD2GEJASYBlFFjXr3J2Hb/dQCuWlf0eyY6yeIdYmN3zAbfiur17fv9JidOwLjj1oLx4pD5EU2S4SAJ2TBO2KpgJ5fXX0bNWbPdC/ktt2kcvhlTvThX3lddGltQYz+0YOB/gwaC1W9xT5USlsN5LX/EKBMHf65Jm97tU14OAUSDYEBiOQ0HE4D3LiMYqT1H4CDkxS4uTqINjjgVSuCZzHhkoG19AMF20o7c3bw6JiNn8EcvSeoUMqYo26zOa/N+a9tkbKWzk1ZsMuHrOu5RhGMHhF/oDBdSD42jBK4x2jKPrzSr8fMqrkLTYhKyQvVuc484hF27FLFzWkuNZpdA+jZWNBblCRjIl6kd9GYjRcWywZDZOehRXX4w34cFmYS+lP82GKFWbtcRGToNg=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 78112687-2d41-4a25-af95-08de5dc1f723
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2026 16:34:39.1088
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: D7tB9PmvNkV8l69e4vw0X3PnUeQuUsW7/DO84tGyHluMklbOGyy3wDQoGU1llUxMkvJqcf1zXvdt4jRhFaFHwQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7561
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-27_03,2026-01-27_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0 phishscore=0
 mlxlogscore=999 mlxscore=0 spamscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601270135
X-Proofpoint-ORIG-GUID: yvkRLZMN7dGc_XRMFXn8zoaGjk3FeuuF
X-Proofpoint-GUID: yvkRLZMN7dGc_XRMFXn8zoaGjk3FeuuF
X-Authority-Analysis: v=2.4 cv=AqfjHe9P c=1 sm=1 tr=0 ts=6978e924 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=l0hdsvYX4KKQlnFdKHcA:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:12103
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI3MDEzNSBTYWx0ZWRfXxCLhKihyIVNA
 x/SIij7GRsbHKza4TMgO8Czm9ZYmWxGpHwp8FBthgWlU0MNYcQ5RJoXFk9SnALbca+dNqIXhKQh
 qjfShG989sUox890Yfpkee3tXD5TEh1FcvPLTBW0hxiaYe0Dv5UKcSm8tkJ7df7lTuJEho3Qyia
 h1NwrdB4Zw+o1iRBBg2jkGiylH6dd/Kcea+pbqP45Bu0e+fgQO6WttBbPAL1f+r9NxOpsL3hmFu
 tbiqAcOzApIl/Ai4oXYp+U7VubfVgtTMrQu3XFtR4yJtfNdLeGggMBL4NZue8JnESOd6MKHcxZu
 C+F26jkthxtTxlS6LHb7AwX4ni1t3uYoZL9mXfrg5yhPTdArcm5a/91YyIfBj93Dro9jIz3H80/
 ul5wziFIaeS504KrWXaZUG9zo6sXx/yDaIdPY+yFhEvPg+jrocbj3iUpLw4vJQga0i0up7vSLvO
 f8sG99Vq+AubOzGE+tmhN/XSwag4yUQ7EHCIJygM=
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=d8monSAR;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=aCfA8615;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Reply-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCYIJU5JTINRBKOS4PFQMGQERMVB3EY];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,googlegroups.com:email,googlegroups.com:dkim];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[Liam.Howlett@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-0.999];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: EABF497D1D
X-Rspamd-Action: no action

* Vlastimil Babka <vbabka@suse.cz> [260123 01:53]:
> In the first step to replace cpu (partial) slabs with sheaves, enable
> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
> and calculate sheaf capacity with a formula that roughly follows the
> formula for number of objects in cpu partial slabs in set_cpu_partial().
> 
> This should achieve roughly similar contention on the barn spin lock as
> there's currently for node list_lock without sheaves, to make
> benchmarking results comparable. It can be further tuned later.
> 
> Don't enable sheaves for bootstrap caches as that wouldn't work. In
> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
> even for !CONFIG_SLAB_OBJ_EXT.
> 
> This limitation will be lifted for kmalloc caches after the necessary
> bootstrapping changes.
> 
> Also do not enable sheaves for SLAB_NOLEAKTRACE caches to avoid
> recursion with kmemleak tracking (thanks to Breno Leitao).
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Is there a way to force a specific limit to the sheaf capacity if you
want a lower number than what is calculated in
calculate_sheaf_capacity()?  That is, it seems your code always decides
if the specified sheaf number is smaller right now.  I'm not sure it's
practical to want a smaller number though.

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  include/linux/slab.h |  6 ------
>  mm/slub.c            | 56 ++++++++++++++++++++++++++++++++++++++++++++++++----
>  2 files changed, 52 insertions(+), 10 deletions(-)
> 
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 2482992248dc..2682ee57ec90 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -57,9 +57,7 @@ enum _slab_flag_bits {
>  #endif
>  	_SLAB_OBJECT_POISON,
>  	_SLAB_CMPXCHG_DOUBLE,
> -#ifdef CONFIG_SLAB_OBJ_EXT
>  	_SLAB_NO_OBJ_EXT,
> -#endif
>  	_SLAB_FLAGS_LAST_BIT
>  };
>  
> @@ -238,11 +236,7 @@ enum _slab_flag_bits {
>  #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
>  
>  /* Slab created using create_boot_cache */
> -#ifdef CONFIG_SLAB_OBJ_EXT
>  #define SLAB_NO_OBJ_EXT		__SLAB_FLAG_BIT(_SLAB_NO_OBJ_EXT)
> -#else
> -#define SLAB_NO_OBJ_EXT		__SLAB_FLAG_UNUSED
> -#endif
>  
>  /*
>   * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
> diff --git a/mm/slub.c b/mm/slub.c
> index 9d86c0505dcd..594f5fac39b3 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -7880,6 +7880,53 @@ static void set_cpu_partial(struct kmem_cache *s)
>  #endif
>  }
>  
> +static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
> +					     struct kmem_cache_args *args)
> +
> +{
> +	unsigned int capacity;
> +	size_t size;
> +
> +
> +	if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
> +		return 0;
> +
> +	/*
> +	 * Bootstrap caches can't have sheaves for now (SLAB_NO_OBJ_EXT).
> +	 * SLAB_NOLEAKTRACE caches (e.g., kmemleak's object_cache) must not
> +	 * have sheaves to avoid recursion when sheaf allocation triggers
> +	 * kmemleak tracking.
> +	 */
> +	if (s->flags & (SLAB_NO_OBJ_EXT | SLAB_NOLEAKTRACE))
> +		return 0;
> +
> +	/*
> +	 * For now we use roughly similar formula (divided by two as there are
> +	 * two percpu sheaves) as what was used for percpu partial slabs, which
> +	 * should result in similar lock contention (barn or list_lock)
> +	 */
> +	if (s->size >= PAGE_SIZE)
> +		capacity = 4;
> +	else if (s->size >= 1024)
> +		capacity = 12;
> +	else if (s->size >= 256)
> +		capacity = 26;
> +	else
> +		capacity = 60;
> +
> +	/* Increment capacity to make sheaf exactly a kmalloc size bucket */
> +	size = struct_size_t(struct slab_sheaf, objects, capacity);
> +	size = kmalloc_size_roundup(size);
> +	capacity = (size - struct_size_t(struct slab_sheaf, objects, 0)) / sizeof(void *);
> +
> +	/*
> +	 * Respect an explicit request for capacity that's typically motivated by
> +	 * expected maximum size of kmem_cache_prefill_sheaf() to not end up
> +	 * using low-performance oversize sheaves
> +	 */
> +	return max(capacity, args->sheaf_capacity);
> +}
> +
>  /*
>   * calculate_sizes() determines the order and the distribution of data within
>   * a slab object.
> @@ -8014,6 +8061,10 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
>  	if (s->flags & SLAB_RECLAIM_ACCOUNT)
>  		s->allocflags |= __GFP_RECLAIMABLE;
>  
> +	/* kmalloc caches need extra care to support sheaves */
> +	if (!is_kmalloc_cache(s))
> +		s->sheaf_capacity = calculate_sheaf_capacity(s, args);
> +
>  	/*
>  	 * Determine the number of objects per slab
>  	 */
> @@ -8618,15 +8669,12 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>  
>  	set_cpu_partial(s);
>  
> -	if (args->sheaf_capacity && !IS_ENABLED(CONFIG_SLUB_TINY)
> -					&& !(s->flags & SLAB_DEBUG_FLAGS)) {
> +	if (s->sheaf_capacity) {
>  		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
>  		if (!s->cpu_sheaves) {
>  			err = -ENOMEM;
>  			goto out;
>  		}
> -		// TODO: increase capacity to grow slab_sheaf up to next kmalloc size?
> -		s->sheaf_capacity = args->sheaf_capacity;
>  	}
>  
>  #ifdef CONFIG_NUMA
> 
> -- 
> 2.52.0
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/r3qfus4j6awmixdbcopgva3lx2l3lrvlvuoqqns64q6qp33qep%402hsrrvfsojsm.
