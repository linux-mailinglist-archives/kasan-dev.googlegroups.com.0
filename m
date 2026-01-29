Return-Path: <kasan-dev+bncBC37BC7E2QERBA6L5TFQMGQERDDD44Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 0Cu3H4Ule2nXBgIAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBA6L5TFQMGQERDDD44Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 10:16:53 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb138.google.com (mail-yx1-xb138.google.com [IPv6:2607:f8b0:4864:20::b138])
	by mail.lfdr.de (Postfix) with ESMTPS id 04A84AE0B1
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 10:16:52 +0100 (CET)
Received: by mail-yx1-xb138.google.com with SMTP id 956f58d0204a3-64946b1e1d0sf851858d50.1
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 01:16:52 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769678211; cv=pass;
        d=google.com; s=arc-20240605;
        b=Fm+Iwo6J3RSBwsOePPEJ+5Gi2su1iKawICcm1eia+dfXjaTZMH3dUsn/b0TerfYQFo
         6ZfTBnzNuPVFl0JuGN7nUSlbUe6jO38XGHZwZRACK5iuUxn/F0BnwDXqdC4/E5O0ztZ0
         2B74oI56e52gkIaJwSnV0dj4qjv/VUVVLhg4+yvgGBa1NvIp8UpsUU1ptS+vhBLFBmKE
         NNnavnFV9aqxqQdd3HLx6HnjUKSbcE2M0he6Ps1VNqA/ogAEL1Wi98hefIu4sVbJg0vp
         Bf75dNn4r+DpSdGg2wMgzdyIz9y0V77Bv1nFNCDc3+58h0sIfJKXEIyB39Jq2EeRg7Zn
         fXNg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=uipKHY8olWAn6acdGMdNt42PV6YzQ1lMLTo7a5CXiaE=;
        fh=uqo9mx9F0LetH+GT/1PgAUsVZqOWlUol6ckebf5Mqx8=;
        b=Y/0AOmdTfcczwvYMezqt88CAgq/Wm/ZYWT0zk/McnX+Nqr9m/AMyjCxL8fsRB7Cyye
         2hbUnjrTg/N6mJUZ6w8uCMZ/vyxXBnxQDBXs7Hl3fMnIeNlhjqUln5fQTlA5r4z4/zvh
         K1nhs5tgMzv9d2cb9fi8c2M1hoDODo5cE3P/fjNK1r1tLqdliZWCL+PIcavquEEygw1A
         b+G8pRy0tsxrc0zFV0iTlft93r1rAz2ZqvjSeftUUky8xu6G29gYlSHnqCCvsTdbmtgY
         smTjpTa/+VTTMD9YDBuwynYZcxkMKzOVlMER3d7nNmBTYATuw6X3HxR9Q1pz3Oec7ZI6
         M3lQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=AQgnJAjV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Nr1zqcGn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769678211; x=1770283011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=uipKHY8olWAn6acdGMdNt42PV6YzQ1lMLTo7a5CXiaE=;
        b=ZuNPKbDGPFlZTJRmf2KJufFDBr7F2lq4B80b3poNffkkJgKcKiMhUDKC6xlaTMKacm
         GKm4X4jENSfE8qjEtV475zLl0CVzuAX3cBLSCExVIL+R+F2r/zk2XHBCRBGeJoa8/OLl
         XAceAtNh6V4DlK/R84bluzFDcXtce/5+3Rd7DAeDP1ZrvtFjyXUbx/FRO4ioQ1ubPc8U
         mP9tqp51co82TdXDz8jhF/57LQvz8NCSyBpcsQ4BuWqQiou5NdtYhmOu5WRBqji71+wy
         nCmBPvYKmCp4XC/nZJzvMk9292VFW/+yKg7fKCcJDqSfBH+/ovhQnKgrsSGOYXUcsIa4
         AZkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769678211; x=1770283011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uipKHY8olWAn6acdGMdNt42PV6YzQ1lMLTo7a5CXiaE=;
        b=B1W/FEfrPG/piQxdIjlMIffKw0rxg/A8TitTDe8s/SaI5InR68pQGB5zOHjovly3TE
         ijNSdDr0VCbupgj8jWYYnksxU+Ep/XZyJvvMu6XVCX+OmuI3r1g8AL61wCPAL+Ko1Muv
         msm5ksVwOgRJiEgEimYCGjFH/WPJSSTXlxvzsCoTBWFxlGUXsmP1sJup666DOZi9R3G7
         eZguo3ILn1DunMIfGsjepFDoCAQXOVYcOkLPzwd4++H5mB5BB+JtMPSdJXlvqN0lqegS
         pTpOYUvS7kxYns1g1eVDHN0lqQTMkrrFfSWqvImWYcYSZzIc/QmdvMrYZdY6NC7Yun0D
         wk/A==
X-Forwarded-Encrypted: i=3; AJvYcCVwiuZa7wcIos2XU6njANyScrmpOy9Fwj4imT8SWDii45LX8KHgLjyXRZBIJIlkmn2jxhehEg==@lfdr.de
X-Gm-Message-State: AOJu0YxKa4/nh7Uvo2EH9VQM0BsjQYJav+NhjThjgXf04Dm8J7zSNPxd
	BAK2cUaYOdC9/iRqZT0Iq0xj3Wg5szNMekMVwUyOi+P5UcZQGFdW+y1G
X-Received: by 2002:a05:690e:4006:b0:644:b4b7:35d9 with SMTP id 956f58d0204a3-6498fc7b287mr5745439d50.92.1769678211610;
        Thu, 29 Jan 2026 01:16:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GSrUQND3tvYpSsEscALoI2L4MFBTg7MSG3BZs8f1nbeg=="
Received: by 2002:a53:e199:0:b0:644:6f9c:57f1 with SMTP id 956f58d0204a3-649a00b932fls453667d50.1.-pod-prod-01-us;
 Thu, 29 Jan 2026 01:16:50 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXwoo4hPn+Qf0MaWsN6bf4QzwvqBmhZTLAxiEvufbvqj5/thws5S+6ut7SUaK7SFjHEl56vGbyioT0=@googlegroups.com
X-Received: by 2002:a05:690e:1c1d:b0:63f:bb1d:e529 with SMTP id 956f58d0204a3-6498fc461ebmr6366039d50.48.1769678210510;
        Thu, 29 Jan 2026 01:16:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769678210; cv=pass;
        d=google.com; s=arc-20240605;
        b=kNXMV6TaY+IgASO3wACZJc5uKIbqiK/F14EPI6HJQWCn5HELfamhvT75x7wtkl2xsi
         7AJmOjzCfEJmvDibkIMaQdO9pBqsqV9TPIh7tEReEAAgUFQKJC5tGErTenxb6jYQqaM+
         5n9d3dIWkdkxmMWtg81SxcYUOi2ZO3KmF96D0Tw9ZCENtcGIPNg4Rg1HFpg7keBZXNHr
         BZOE7K/4HKtMxY4DXdBsBJdsQ/+lNK2vcTd6R+LxG+q4LXx/ktp8C70dUAwaedsVnVy+
         AcxCA7cS/5VZP040b5xV6DPsuvV9ZKnJ9HgQHctVOYTc6o8NTA0OxxtFYG4bYznwOe+G
         1yFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=c7k9UuCUHC+8MKMfsH/3rh0f6FcXQ9DYr5ca0mHBBiI=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=TfV14w68YYbCwqsesP5QBJfz3OKVYPtR1/YLiaEKGq4gUBtWhuiFug9TKEV7HJWEP4
         JXoPNlYJmc28DQ0AhvTvWQFJ1W+qg5dBWX+dihgMBZyRzXB8j2qNIRnnLrOz2j6xqBv2
         IL49vt82Gwd4vdj0Vh1qLjt6bt4HrLkpKlaINzG13MmxqWymnkJVKntokCWW+1l0QqTT
         C/rVu1DNeyzh/a7XxtcFJ+MWrLHRNmaFIs017Pme7T45mZ3tUu4oX65s8fhsECmb9T05
         bE+/7UWUEge6gb30DfP+XAnVozaRysdz9pOsuqd9wKVEEd40FxrgR5aiehxtFHez9eTj
         z0XA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=AQgnJAjV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Nr1zqcGn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-649960733a0si154993d50.2.2026.01.29.01.16.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 01:16:50 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60T6Hh3e1232018;
	Thu, 29 Jan 2026 09:16:46 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4by5t6ajj2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 09:16:45 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60T7AHXu036075;
	Thu, 29 Jan 2026 09:16:44 GMT
Received: from ph8pr06cu001.outbound.protection.outlook.com (mail-westus3azon11012058.outbound.protection.outlook.com [40.107.209.58])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhrcc44-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 09:16:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=VBXxDnM5887pZQ1AsOpbW/agSWZDvXU/puS+fcQ4ippeZ92Nbw0pQ5jrFtOaOtl16lOaIITTeESlXYJ0veu+pjzFEhFnYKMnLXJFHBQmFPNyKt5POqcab8it2jhawv5I2nWjhrN/vGZ3kEgLe81dzFsP0IvaMgHMDJf0H+tUdsJpaFeTNEwrzJ2LCupBNv6cqoZoHKJEqyRsfjJUIoosUpRpn7Pj1ii5IGWmTdNPom97QudaSNvVUrL7sW6SzVeX5egpTFUT1o0ax1O+wWPcfz8Pj5oyfgMvBqKNsDcD69qtkNd96JG8aHmiQrauldfTr5JXid79IXFcml0JPVw+iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=c7k9UuCUHC+8MKMfsH/3rh0f6FcXQ9DYr5ca0mHBBiI=;
 b=C1M9nMF7JyGu43odKSXXKFQrpNJ8S8wTIMQx5yNvtG/LEbfjjToAM1I3JyDYbNr1CQwuDthsbJXd1IY+E2zrlwLJyHFqTz6dakSYQ85fbpgQitKvM2CzUayQ4XSJik/bc68jQRF1iXUimlGDoy664z64KHJDFvOI3wUN4HYOeRKkjc0+udUycT+TLKMEuDUwaMj8GnLX0HoY0kvnRRr1j4gBTEwn0vJehIBgFuOTSDAM3pupbXl3NKlSoFb026OwV7xunPgKAW2P8x0cKOlBA0o5ISpQaXmGjkG3KHQmGKwmqtrv9k8DXJAUY9eNPGlVQLl7/CSkKog4NHdc/I4JDA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DM4PR10MB5966.namprd10.prod.outlook.com (2603:10b6:8:b2::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.11; Thu, 29 Jan
 2026 09:16:40 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9564.006; Thu, 29 Jan 2026
 09:16:40 +0000
Date: Thu, 29 Jan 2026 18:16:30 +0900
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
Subject: Re: [PATCH v4 18/22] slab: refill sheaves from all nodes
Message-ID: <aXslbsUK1LXfx510@hyeyoo>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-18-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-18-041323d506f7@suse.cz>
X-ClientProxiedBy: SE2P216CA0060.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:115::11) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DM4PR10MB5966:EE_
X-MS-Office365-Filtering-Correlation-Id: b268a218-4c2c-4839-c181-08de5f171cbe
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|366016|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?uhU6hyiqkC2okzsrwgL3Gz41Obn8ZhwLXVPPO+IG+iEsdbqfQ+DAK+txWiGO?=
 =?us-ascii?Q?bb0t09FpmKGNf4xAt0pvZFMjdZgWz/yuCryLFVJ6KJ2kh48p2NOavZJCFv9u?=
 =?us-ascii?Q?27pfRXf8Qn5mNyaMx9JfJ1S4Lff795Pq2dNXuPhQgoKZqlABW0dXNq8YnBsY?=
 =?us-ascii?Q?v7AhqW7H+Vd/baWLVXzlgdI0yUijTgnvo9c9J2PEv2IoAeeZx8q61K9oIY5T?=
 =?us-ascii?Q?q2mrZVnGRksheZC6rKnA9U0ykv/teDvvUvUgAsFXbXIR877BgG2Kcva7LTkx?=
 =?us-ascii?Q?wQJgQub2C7jTkMjoS8SWtY8rKlN1e3vlCn+8N9bGhNtZZYXnE9tQdZ5QsAut?=
 =?us-ascii?Q?GYlWnXOAeF4KghyEQuEk9N9DVHxDhpwosiLD1GXyUwQIGnEVPCINb0T5UcjU?=
 =?us-ascii?Q?yLz3ZnqUFQquPmUFItrQ/bieGj2I+4h312yfeJur9xfnVm/9AO6dCeVzsJS6?=
 =?us-ascii?Q?CrmOmW2/AyLoXGIAkXNFmQ4I2+DzSixprNghBqe98pbOswNuSVXtxJxavDe1?=
 =?us-ascii?Q?RuobMoQGvgDEP5fzXuGxiqZQ6sSgfM4chRo3TSVgXU0DS1NjpzBWLS8cLxpX?=
 =?us-ascii?Q?SPFrEDF0xh1hUz49vaOl52XhsiqxR8A2taWiGuo0+KyVXn+3GDsKwPpvpPuk?=
 =?us-ascii?Q?ZOal/Y+u4UWtCa77aUFjcR5x7tjYjYxSZC50bGZkK4ulwsitrFdZJdvjh7dI?=
 =?us-ascii?Q?l3B87N/GjOGKQRvA2jMTLpwi0gk/DdENa4S21YuapKgC9ZCHujf1EwbkC77C?=
 =?us-ascii?Q?ayQaQdNX/53SDD+k+JGEEJ6M3LrFCTwhSYKCb4LgRoco9qoAM5975oUvcymq?=
 =?us-ascii?Q?hVN+bL/uMvrpjZNt1PDtFkLCmCO8qX1cFzRF76RXE1Eo5vF7p9JLiRt6b9Z2?=
 =?us-ascii?Q?rk6+jkGBQip0puxzw2dUuWiCAARd7dWN1b4DPC15gfjaHff02Tm1Fw6mFExN?=
 =?us-ascii?Q?cgT9Vov1qywfTLrmy5haa7PXUU1hirQaNPnKzUVJaoU0wNXrZbIlB2fIsq+G?=
 =?us-ascii?Q?UslPOk/LOYFjdVidNppXQQTe2TKW4C3kfoGWuLbnvVgbfIC/YqiosGfCLVl3?=
 =?us-ascii?Q?uzimEVj4skuYjahyMhoKpQxIJFtC+zdmkIXabyjFXZLCehJnqWYziEk4dzsl?=
 =?us-ascii?Q?X4AbJkHSZCCQS6T9ZqnGJY2/NXvhbafxVgJF6CO58YRyFYEubb2mGxGo28Ue?=
 =?us-ascii?Q?SR5ZIkva0rTubOsGvDYzkWt1e9TdvE0LB3Tc+mDdUT8+mSsl2XBMSw3XcSc6?=
 =?us-ascii?Q?Z8TBLL6NLzhzS+KOXI7SKFiAfazgz+qQG4jlxG6rtLbjw/Nb72DmAegtlvtQ?=
 =?us-ascii?Q?hsx0006M+Vz3GoQUxjluNJ9ZTDmLKdJedLeV5XcQaHizMqLwfDLgNZdCdW0+?=
 =?us-ascii?Q?o/qce7ZmT7NNHrQANTgggQvl19ZC/D/LUIHOK12Xc8EBfAnTuxSIBr1KFLAe?=
 =?us-ascii?Q?sznIoKew1ynbT8yAG+2zli8PnWm5ecxGZkqhpxIZ+Gj1mF/tF7fimRCMrAc1?=
 =?us-ascii?Q?rjOZvyVsytOWj/x6C+WBf0geGNgweu+/qR74Z3tUWWYD22V7l530C0A8CfOv?=
 =?us-ascii?Q?dn+e5Mk6SKodWcrRSeA=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(366016)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?3iVI+azNZyxhVAo6Hm6VFApMvFzDAlEGoizFoFKALIveq2bIittHfL+e7Xwa?=
 =?us-ascii?Q?UtfEYj8lldJ/NdmIlP0CKnv5OC84mgO2t8sniarflVSn3PUVl5mrlhEg2hk8?=
 =?us-ascii?Q?4kheY39UJBxvnVD31VWHdZIGhKvPYMan/inrUBwrARCCCIljUg+GzZ9xQpsG?=
 =?us-ascii?Q?hP/eVOGLNlNlTcmxJi47kDOCR9qlIea8H78p2W9vfQ/P4sebw8jtG+ZHBP7M?=
 =?us-ascii?Q?p7de3aqL8fU4j8ic4DfKp/bBeQ6RBWs87QEdn80tXTmZL8DLP7dS142bEwd5?=
 =?us-ascii?Q?3UbQuLtDbs6P1v+w1055vIdQS0/fzgEhoFx/25q/x/XyftZL6YnH+Wkj3OlG?=
 =?us-ascii?Q?KzA8k+4WDRnheQ/OVwT4zncOon003qB0xyz0XxdvyZDjYMAZBK4QYS7dwaSc?=
 =?us-ascii?Q?JHBV1XgO0+BA5O/eB4etyawSRL+f7h5diosdQ/ves2rBPmVL5WdyUQE8SV0o?=
 =?us-ascii?Q?9/je+XYAMVsKDBza2vUJ0NSo1n2GRhvPDkBx058noqDLy7I//1SqtDN0g9rb?=
 =?us-ascii?Q?490FR05QUpa+tDzhWGf2N7pAm+AI8GdGfqzKGEkbyjlp8Lj8CGoMWIrW1BwS?=
 =?us-ascii?Q?lqFcr1B0ISkgPMNUCdvLWFtg/Ar+L3hmrlY/bvRH6E2ujP8XnfdNLCd5ZAKE?=
 =?us-ascii?Q?wv4dh1Y9zy9gUA8+mXn628viydVvB5LUcm6E3RhfTCuOhO1u6RIlOejeVXWX?=
 =?us-ascii?Q?McZO/qPd82CmjzYO2V7J99Lm7zQViZuOPHYxy/8derIH5U18r2XGMiKlqsid?=
 =?us-ascii?Q?cLWOhinqZBnKIapkqjlDkXCTL5gl4w/yJp+mAajehYfwopBcmEpBebvuo+/j?=
 =?us-ascii?Q?TGOlLkMdgXvhxe+K9m8qUW10YIWSE8UrJfWbS8LqPM2EplsLqXqgz3d1Fovg?=
 =?us-ascii?Q?H3cFh9W1gLvNTrpR+GzQLKtNMfOPsXsEqc9hoU8KFT1ulAMCOKuPRnYrI1Ab?=
 =?us-ascii?Q?OQdxIb/AF8Evb203xcQgriEyNL1FQyvyjFHxXYmCTFdtLUYgp8eJ+IQr5fSU?=
 =?us-ascii?Q?xaMPTup+CAyZkNX/PJYWOFomuvolMT5ypc6bhkbM6g3wVy7YOar8RGfuKoNc?=
 =?us-ascii?Q?Z9fiBcSnArDNR2XOJc3Y+uWMD5RJtlwqbAa7VVSqjZFXYUs2wIsAxsrKXM0t?=
 =?us-ascii?Q?OW02d8aZYmOx4Ih4pF8YnNMvzSGPjjf0Tw3TJEj7KsfPeU2rMhuyvmysiSYb?=
 =?us-ascii?Q?A7ASSVLWKENkNAuQlt/Wydx7tsDssPrMVOlLDnTUgT7uzlCURDuWHvO1wHIy?=
 =?us-ascii?Q?qPr1HlNt4EN3Mgo6mSQMkc4i0kYPDu4LyTQBLH3BhqQOA9glYyJNInNVA1vN?=
 =?us-ascii?Q?qkQgtA3YA0JlHO4t1FqrwYVcujBDAz1H7tAItO9MjlltR+5iJBcAAQsSLpMV?=
 =?us-ascii?Q?AMs1IBsFjlCjkzD4H4hjrDDpwt6S+960HYQJCEzSjCPkxo5qQKjoErDTy8rX?=
 =?us-ascii?Q?Km+dJEYgz/Mo9KTYDInuB8W6Tbn/m/Xqh9UsTvVHC1D4XCVzV0/SJeBPXWcY?=
 =?us-ascii?Q?bHsqIUu6dzl/6oKYs6PJngJosjLc5Lsn8xF6r8Sx+V5zBX99HKh0/TK0cWm4?=
 =?us-ascii?Q?pEEVIr/iDoc9Cq74/F6uDfUB0x1hBeDir5yEiYpKcLA6GiTOp4iVUu6vYjL2?=
 =?us-ascii?Q?nAFsMI3SvMV891kfOWMGBYPc8Hy4DiKd3b/++DhB+x9M8eCCQXMlTAVFS0Ak?=
 =?us-ascii?Q?Wvb+Q7epjruvlcPEKCdmY5CQ3LSf6i+YxT8bNb+3sEdNFZHqN7GosgxC7grn?=
 =?us-ascii?Q?JC5CMG/P+Q=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: BsqeqUc/p1v+jlWPj6gpj5eMdjoQur4UNZ4mXOSUwXS5xfmP+1bPLn4MRW/IKgQY48M6kdQO3ctZla1NLSBt0Qz1mlRY/Y83rhDRuKGsy04TrZEZ3lx7S5L7zc+snxtAUGI81d9kRp8yLtyuhEsw2DlcHojgTox1us/oD8fnJqW8wAnxPLqrk+l6qsV4Oo9ueP6P249piNu53Vv8OJx4JvFRjVzIke0U2ZPK/v2BRZsPs5vvd0NFYihe7uNO0y77Wts0getz4uUJzwG9WYo++8671EmVwfEKEvDAsmb6GcUhM0hec7oEntcbHucmQ4HDcxn0XKAxX+harns8vAl+yx8GXC596DU7KF5XGNx6i911Jm6o2MLWAFUo77p0udlCFDM91UTqO1CRw3/2OM6RRcAI8TObMm7VPVIpuTsrHfGGYADF+HVd6PbtZHuJjJryYF4a1wQ2BBNKkq253gDuKnnkY4uc1Kbmo+xnhMpsFFOORs001d9EkYaTLk7877hCJOyvaTNp+5Z+vXWbsnwJnbXdBC+JZC5jQvExTr6Fl6zxw6bAkPFKsjXr+WCav17QVqrJhHYwrMKVWPUhTl+/pktgSFnvrbJV4bAYn+zx464=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b268a218-4c2c-4839-c181-08de5f171cbe
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Jan 2026 09:16:40.8287
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: gH5UVRKVK00LcNS/o1iy8GOIKP27tiD+ypODtACbe2Bz/3OR8G3np8CASfMnfq6XyGBtnCvECjFDMqjCTJn5bA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB5966
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-29_01,2026-01-28_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 mlxscore=0 mlxlogscore=886 phishscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601290058
X-Proofpoint-ORIG-GUID: hmc3tpE8Ew6vowrNd5uieps5_YkpchUT
X-Proofpoint-GUID: hmc3tpE8Ew6vowrNd5uieps5_YkpchUT
X-Authority-Analysis: v=2.4 cv=IIcPywvG c=1 sm=1 tr=0 ts=697b257d b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=JuDMzERyrGprox_VUIoA:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:12104
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI5MDA1OCBTYWx0ZWRfXxZwSFitjTIea
 xOZGQPwegVZ7xhrqIYOcwAjfjfKX7bF+q4c9QIiPxGKQVnups/kkBvzVGO9LM8afYfwKSvf3rLt
 aZFQToF1z3+kL3Xw0+/NaTfkezu4189qufPxrn16RsMAy8V5f626I1kmZjgfn96xMHxOpF+Oiae
 7uzh/O6UhYrWrBjrQWT/7bK/CspHCeBqjlyinDhFR1KErqO9CM4SkUQsMy7h9vhkjwNPwKEPS6Z
 DVWUYaUZ57tGhLjZMhUeUneokuwOtaMp58PpeA3XfrFVUq6Wvid86Koc18eXLN1KdZ6BnmB+YAz
 3mQA0Olj1drnG4dwS3tCmuTkz2clK6F+xnM5jbeMDbmSsVc4JG7mgjooNjdTI+s/Tsq/PkKiuFg
 MuLE9bNXk3iHVBFbkw+dWmi7hnb/dVTdEVOnWJCRHvdGqcoL0wLnrCXpGOGB9VXyZqNklYyHKZH
 ZG/8XDVj3IuhSXURXYpINoiMiYf4Dj3i1oAjUAfo=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=AQgnJAjV;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Nr1zqcGn;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
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
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBA6L5TFQMGQERDDD44Q];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:replyto,oracle.com:email,googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,linux.dev:email];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: 04A84AE0B1
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:56AM +0100, Vlastimil Babka wrote:
> __refill_objects() currently only attempts to get partial slabs from the
> local node and then allocates new slab(s). Expand it to trying also
> other nodes while observing the remote node defrag ratio, similarly to
> get_any_partial().
> 
> This will prevent allocating new slabs on a node while other nodes have
> many free slabs. It does mean sheaves will contain non-local objects in
> that case. Allocations that care about specific node will still be
> served appropriately, but might get a slowpath allocation.
> 
> Like get_any_partial() we do observe cpuset_zone_allowed(), although we
> might be refilling a sheaf that will be then used from a different
> allocation context.
> 
> We can also use the resulting refill_objects() in
> __kmem_cache_alloc_bulk() for non-debug caches. This means
> kmem_cache_alloc_bulk() will get better performance when sheaves are
> exhausted. kmem_cache_alloc_bulk() cannot indicate a preferred node so
> it's compatible with sheaves refill in preferring the local node.
> Its users also have gfp flags that allow spinning, so document that
> as a requirement.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

My only concern is that it allows sheaves with remote objects
to be returned back to the local barn by freeing local objects to them.

But the impact of that should be limited because remote frees bypass
sheaves layer anyway and we can revisit it if it causes a real problem.

That said,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXslbsUK1LXfx510%40hyeyoo.
