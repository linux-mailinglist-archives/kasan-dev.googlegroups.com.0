Return-Path: <kasan-dev+bncBC37BC7E2QERB2OJ2XEAMGQEUITIEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2780EC55B6C
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 05:56:11 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-8824292911csf37326196d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Nov 2025 20:56:11 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1763009770; cv=pass;
        d=google.com; s=arc-20240605;
        b=BVhEYBH8uyjuUPGXDlwf3I2UO17zfFrhOXB+aU34fIfa6ZdbaDLNvENdcmIwtseeqQ
         ZOQRKIymwztBhuS/16yu3t0yRTRCK1e4mO0VGP4zlWBQtumjALb5s1pvHEkVMsVDVTMU
         5eDumPfJLe0NyfFwKSt4E1fa343nJ9IDDZmWSESrNgJ5lt5W2fpay2ec8Q+in8xVCPXn
         HGMsF+Zo6KHU6/NY36zDXBtfgPrTwNs+296ZPWEQw19nLNo47ajY8+oiV9U0cerbuhRP
         Jtr5LAryg4Sr+XsDT4i5+zajCEdZFj31j+YB2wk9XMXwwyZKJoLk4kmmbWc9EmT4xw/q
         r7hg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=2b0SR/7Dxm40vS0x1YgYiJBRLmjKzOBMM+3QuUBSxwo=;
        fh=uF3PbAn3xYgfBUcHY0L/9FgQvxepeAx3hNzz5n3w3Kk=;
        b=YlF1MSB4sd9LOXVx+Bujqxnx+6ZzESuKNFvsbOUaE9aYySvte5f2+4kj4XmRfWlW+N
         vzHONTznSzz8wyDvjv4jNbXO40M0UPi77gCPXGWQo3yDRQ4jL5nzlEFijFs94OA+CNMa
         JwgWViDWnvdz1tFZWS99ddrQDabeVZVp04s3v191BWceaElx/2MsYZC6BsErvwfD+JZg
         q2l76uP1hMpDQNXI6dviUB/ZF5udMgx8nCXvmZhO6watpkeEAOBwjGmPydQEXLmYTMQX
         syEWN9RHfFqhcZN4Db9+xgs8VnTje4QktBEgQJnwbYLfApHgxptgkw4TyLmTib9dzybI
         v8Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=r1kBEuk5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=uo7CKJKn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763009770; x=1763614570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=2b0SR/7Dxm40vS0x1YgYiJBRLmjKzOBMM+3QuUBSxwo=;
        b=UvALSy4uTo6h3ekx8fEQIZcG72zlTD42L4CtXPMnt37tCCQffgsruwB7nIlLbZe8Uh
         wVCpL49MPlzSehbDLWZM7+e2nbx/1bhrHK3bvLlWHwmnEJJ2LIiCj/53Pvt6vBikiXIU
         CU7CSPw70etHBsIejlFvBbft+WqArh5H68MvyRrxO552wXZ9P+dS9TXNqPmYOIJV82c3
         g9iEar/6kttW/F4+X19uvy5PfqjrnkJ5BVvrokLqT1dWkrlUSZinSt4vVJF6MMPYDQU+
         qztBmW22YReKFstb5jqPvqGqBZt2WhQtwfAxTm/47K48uZZ/jhn4axm560+aS7p1sJbk
         6ENg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763009770; x=1763614570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2b0SR/7Dxm40vS0x1YgYiJBRLmjKzOBMM+3QuUBSxwo=;
        b=XkNmVLqsWaTGgIrlSmOVaHcG63U/tBam93Nx+MqGb+1yWcmyH0UO1SAoj4g+0jKIo+
         xaF/ZMydV8RgB4bZUBwfNmBjTl+sV6SLvc/y4pMZRE/Au5tKcESenjHke7imaIZhGZXP
         9F4NkAplseyQWSvLZfCAz7+DitYt3uvtP8Eij31IHwQHk3eniFKKi1Eixn1AiJopo7Io
         klTIZARBDe9F/KdpAtEvG0FDAgFgQOO8M5JCfjRL+pDxiOZbpyrOqcGoWZ5y2803+5Mi
         Ake2KjsoveWR0DGi1SCFPZab67YSi+xuUp3H8dqGKIbhoQIIDEdSzTjjR+mtHm4bd5Kh
         F0oQ==
X-Forwarded-Encrypted: i=3; AJvYcCVfFma4krfUmYtLVHYz/eOSYxcz1YB3zF5USl3GKoBSkJ4I4kgGBQqJCtITjm1iBPIkZhv9EQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx2UtM0MB3u77M8PaGSpkZZ/DReUuj3E8BgNZIJF5WncwCjNGJH
	cks619wGBy3/58wEjaE4TQtBDRw3djn+IpxP2accakOHBoXkTh4uzrin
X-Google-Smtp-Source: AGHT+IE+bbeWFrY6Ew4Kf9LfOqTk6YP6PYB+7Tw3R7Z6+rLiJHLl2eTFzSknGAmrYUJPpmSfLmAr0g==
X-Received: by 2002:ad4:5ba5:0:b0:882:772c:774a with SMTP id 6a1803df08f44-8828196b75dmr30175296d6.33.1763009769765;
        Wed, 12 Nov 2025 20:56:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bJQiOZJdzkneFLbuQSxLKKjhG+xfco20LWBGBpTtkqIw=="
Received: by 2002:ad4:5806:0:b0:880:5222:360 with SMTP id 6a1803df08f44-88271a52b29ls15259776d6.1.-pod-prod-00-us-canary;
 Wed, 12 Nov 2025 20:56:09 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCW4wskonGhCARH1c711BZPdUBr/SUGh8g8LBvoERyALXBQddrvxGEZi+iDpiTK83GkWKTJNlxHCk2s=@googlegroups.com
X-Received: by 2002:a05:6102:3310:b0:5dd:a0bf:8c89 with SMTP id ada2fe7eead31-5dfb40abcbbmr721565137.7.1763009768929;
        Wed, 12 Nov 2025 20:56:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763009768; cv=pass;
        d=google.com; s=arc-20240605;
        b=UQCIMaWlJIxO21SpQrIIt2rrKm3OSPDPmtnxUMoslemyPKqJaLevwtaSy2d5IQXc5r
         nTr6fl16/wdAYOoPOUm+PMscYeTDxMTx8GGeX/canRbJsqwDKv5I5zPVp3bQPnNRbp1Z
         ABghmjwux3SUXTiEd0qL8f96nwZ1yStagOvZe1Qv8xFsQ+VKKUL47n9nTBiu9yvhcnRX
         88gt8qdRlMpiA7I6N+aUdzcOuIPrvJVC4adm/XrfciW+LeIn2r2EbqXpxdQi2HZl4WP/
         pTmHL7MWxf19dj6qJX7aUsPM62poWzbdt4Fd11DIfJo2v/OfR16vL4y7mdOHe0zfHw2+
         Eq7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=Q8K8yLEPxSsj7AeSHwFXOk9kqw/oWb/MgymSw2LO9mc=;
        fh=z9FBhjMbkZ+0JHvms5X5JUwpeTV3lUJTZoU17s0577A=;
        b=IDV0u4Ah6d6xr8HTEinBSopvxJ7J7EQwr9zAC5VNCEAqnlqXCGco+kWFqSaPUDADBQ
         lzn6SbtY2Zb+ThvJlCWShY4qx9E7F/6bY+FS28U9+9fekgvMLygBxD4ioq6cSWLmG7mL
         +YSCCyRl6sPChnxvruB3BOFyrVh4/m32Fq2QlWUCWf2dqlQE+GKj7wfIGceTwmVmHqiy
         cNrL1jzf84mgaxLJde5/6lXqEaHxY9OWRn1dx4eonLlNUcNL+mMMuzoQWxwS0LyJTAFh
         unUNbTDF0opUd75zS8UnD1AyJAPN50VTREn7VG79ysUtZC1OLKni+V5G1BmwTfnGPdW/
         IB+Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=r1kBEuk5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=uo7CKJKn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-937613bd526si14183241.1.2025.11.12.20.56.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Nov 2025 20:56:08 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5AD1gNOF030753;
	Thu, 13 Nov 2025 04:56:07 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4acyra8utc-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Nov 2025 04:56:06 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5AD3wn4v029113;
	Thu, 13 Nov 2025 04:56:06 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011058.outbound.protection.outlook.com [40.107.208.58])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4a9vafnuw1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Nov 2025 04:56:06 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BKE5hPFTiqU8FVVDt+X9QBBpeZadaQFQUhbHudsueeHjXGagjsOwMGJDNaqSsrRggYBF4KPffYpnAI34vxPxt2BzMBBhYHHbABBpIqWCMwcCXoaThG3Nnp62Xwo0P1gq4jNdvIW5bWYHcpRXRcuq4wV4UPwMXC/VhAsJxqhMwEHFkDBorMf+3rio8hqcg5Mi6Frf9WdjO5eoZn1rLlUoabKRdHsF7xJX+ZbAKbOsDlO3r4H95CdiHbQDJeRY0JKRq5dBO8GDDtxKXmju+mrPOzSO+e/n8hnFjw22Scwn5D33Q3TIunu4wMeGC90l76CsTpMDfHAesDQlcGudTnhQPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Q8K8yLEPxSsj7AeSHwFXOk9kqw/oWb/MgymSw2LO9mc=;
 b=Rrx+YDsy20A+ug2pCwL72hSxvUEONmvjmJneBQYgeAKEJko1tlP8GA6a1oRTMD3v1hjPrCZienYl8uLNZHHopb4sOK5jeYzbN/Vgpo0VzuegetmrYXiRN2WlcB3GyzQ9itXVfWlAZd3ZN/N7eOOosdKX8Lz4YDpAqwCJcNVUUcEc7cMna1dAiQq7Iztfwmn/5R1ypdkxsyQWLrscu7Fbz772CNRIe2v6u8iwu2bxbQPzNxqHfVvqzKpeyaqVHQ7who8Akxia927HIZabLi/fTcIsXLKvmguX62wgzzVTF2ohS9zNbxlT/JXIEtYRlzZBiWBc+J+YUYXlqXKJ/khCeA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CH3PR10MB7808.namprd10.prod.outlook.com (2603:10b6:610:1ba::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9320.16; Thu, 13 Nov
 2025 04:56:01 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9320.013; Thu, 13 Nov 2025
 04:56:01 +0000
Date: Thu, 13 Nov 2025 13:55:52 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, bpf@vger.kernel.org,
        kasan-dev@googlegroups.com
Subject: Re: [PATCH 5/5] slab: prevent recursive kmalloc() in
 alloc_empty_sheaf()
Message-ID: <aRVk2BXrC2b7RJ-V@hyeyoo>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
 <20251105-sheaves-cleanups-v1-5-b8218e1ac7ef@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251105-sheaves-cleanups-v1-5-b8218e1ac7ef@suse.cz>
X-ClientProxiedBy: SEWP216CA0149.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2be::19) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CH3PR10MB7808:EE_
X-MS-Office365-Filtering-Correlation-Id: 2bb5e3ed-02b1-4b3d-b4d0-08de2270f107
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?qQAEPUh43Y+6HE1OnMguCmVE2GH7N6OWN4pMoHEbTMHA5bPikiBVn3O5+93I?=
 =?us-ascii?Q?OLDwVYhu4VuJvD5t7xwYXwNlBx3BERgWiGjZSrrKg6sz5zuF7cCT1g/0J6/7?=
 =?us-ascii?Q?l7362vpfXyWsDk7ckZXGlwQ+6fdpCVURnLvU19nb304zTXYEoHMQtCoXTPkO?=
 =?us-ascii?Q?CiCbylbGsYxtUv8hpzfs2qzw0+OZK0NZH57MOMfY6gz0dVkWE/7qDP7pm1bz?=
 =?us-ascii?Q?vjGJPAp3SUEuO4kr3XoKp0iZk90tIMZ/7AMQEDx3EImPyzr7RRhjZCMlZwoY?=
 =?us-ascii?Q?ekGVCnhv2+KjUReT5fmxtP+KLd93TZp2UZdvMSuUUYsZGm9+o40DbG70/GCl?=
 =?us-ascii?Q?8tNQRkTkIYvSSKbjV4W6FryhGCV8dXwyF7KkT+2PpGKFIeP943NTHBKQKzOR?=
 =?us-ascii?Q?30mIEb1Sqss8uk3qojSPXX/pir/zD+vxpFkBFFOjW/EN3GVkz71LobAMFjHk?=
 =?us-ascii?Q?kNVVnqpjuez0ACvBbmuZVKBpvx1PrpP1hlC+qGh8c7mGTdqX6I2Itrwk3+rz?=
 =?us-ascii?Q?G7ANBipmM4gD2Mar5qyLmDfWsBSFr+HqRD/K1jsBOx3wEisp5z/b2MTa3sVK?=
 =?us-ascii?Q?mzhwuQmXoYvgH5rN3Xhhpd03joQ3mOdVRskBSnjCkXrtxk9o3rIiBNEzaSBb?=
 =?us-ascii?Q?vQGyuYxlMPphuMlgpZTQFmDpjHdOsSEZc4tZYojhBaoncpaVAkvjgNBvGrPD?=
 =?us-ascii?Q?KqHopaOHzWgK0W8hX+acmuBBopV1RmShQgBUvNB4t6KXkjDqVoj+0I4QYaId?=
 =?us-ascii?Q?Hx5XRxO6pIaIUifToO3JXEVXLbsiMejNRkA2tn5ZUDG5BlNFY5moTFbriLA5?=
 =?us-ascii?Q?w90JKcnMaxTfnq1cQY9+FQHF6B6YeleBu0e9SNIF9EhEIUWESzShU+7+IhdA?=
 =?us-ascii?Q?pGVo/PwcBIvoQdbg+0ZRX0pwOzvXPmK58IdD3BARPExg9Ec/oU66yZ0/gcui?=
 =?us-ascii?Q?Pb8dKcw1KRZ3G+iTCvZXbSqxyG9J4u3pIh7IjCQh70rlcXgp07uWz8akErWk?=
 =?us-ascii?Q?m/VkGqOoh3ESUyuhJs0Be+pmSuX1lfUO10bVBI/1ZqEqPx/C54uicIJyQ4l1?=
 =?us-ascii?Q?NoThSWe7SX0d+uas+aTf53T4P6kQXdmQasAVXo2zhBhgR7TQVhCkq12GGOWI?=
 =?us-ascii?Q?SFbR8v5k8aUQfqhP/qXrlJgEIBSfhYS+c7rUVMkYUOmK6VNK1bxdiP+h6hD7?=
 =?us-ascii?Q?tINtiq80hix0+2ekuo8cpoQOsDMztiJkgZdtGd5NMqS6Ynxvo4NxPIUVEtlp?=
 =?us-ascii?Q?uLCWs5tANQ2Zezx86zEoH4YX1b2vvpeaREMPFCflax/xg0Cxwed8Koa5sd6a?=
 =?us-ascii?Q?9V7zEFNiP4RdSekxFMQ0G/6NbbuIVe5z7EAqOcjbFTZNqXufPlrJQxpX2ecC?=
 =?us-ascii?Q?KXE9Oy9OZ784VemS9CBpeGqb8B+IYh/YLlSah3KXlxLssLmFZzwFlF/SRQ5m?=
 =?us-ascii?Q?lhiW+98gpXSYXgR4eJjgB3ckUoi/76yu?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?UkVD3wVnDeAUb61NLaNmW7vELTRlIWB+NrA2/NPO+hQYkOk9ugqw2KSYXo32?=
 =?us-ascii?Q?jtnP2Q1ckZ5CkP5uniocGtl4ILYM7yBAW0k8M/aF9oIMI84HVI+KyaAadPz9?=
 =?us-ascii?Q?iLG95Z4ZwLd21OHIZygOAAbVQ8LgFcs0quRpMEvV+t5ITzAxBz18XcuxUU7P?=
 =?us-ascii?Q?aG+WefBqpSCmlLuu6oD0NNdpLHgR50gL9rUy9itanUgSIhSk86Qt2czNRPY5?=
 =?us-ascii?Q?MBlbExrI4Qrp8wn45XwHA8ccFYhtDZY9P+95Z3MLyt3mePGA1Iduq2EPX4KE?=
 =?us-ascii?Q?OLc3y+4PpY4wsb/WBSX/MC1BI/oWPgD8XFPhkvPTOi2vOb00BLU4xDrhtc6v?=
 =?us-ascii?Q?QKWP9PG2ync7Y9nAeaCyJmvzo1GZkn8m7HV92UJNTvBG/x8hYa1JV1a//K7H?=
 =?us-ascii?Q?iRYlaScDcCdykiUCKPy67gdj7v26uWCKk5nqIGq2mox48LgOVpZDUXqz2vS/?=
 =?us-ascii?Q?zLK/mU2DO2iFPITgDtsKq+0EmuYAYav73vIUFw2ON17xzCPDE1fCZ/6Syiyu?=
 =?us-ascii?Q?sMq0rhsuraKKQU7+NGxmj7ZtXBLw6VgLV2qkI3p3+GjAKUBj7CPqgNtzoIWw?=
 =?us-ascii?Q?FzLA8lGNasGoWJiaHAnUkkNzR8gWKwDQadeetCzdhMYEsMcONU1tO+L80een?=
 =?us-ascii?Q?cDJjbP4dq00SWY3nh+sDfx/n90ucCB69hHk3XSLfTAnpKs4S+KEZs1l84f1m?=
 =?us-ascii?Q?FV5NAJgzuNG6laXi1nO3g5wB1zhrAT2ay478BxAqk2kqvwbHNgHDpf6hXxBO?=
 =?us-ascii?Q?uCn6iGrtl7/0nK4OyqeC1KCyN6GR6UMba8Rc9yYVtt6ui3Sy5LuJHFOsLiLz?=
 =?us-ascii?Q?VHvfx+Spibu369f0cvn2YCtEHwH+NU9YBfS8p7Du/0y/XhGS8iKlh1sEC8Cs?=
 =?us-ascii?Q?XfArawPuWJjB9+VO3XGJklnQuajdtFsvi8OFRBjCgXytAHbYoHm0dhgl742A?=
 =?us-ascii?Q?MMvN8yJf4Ro8LzEtmmh6mUb91shQMcKbadntsMvCtbtk6+HtVm81yRerWou0?=
 =?us-ascii?Q?VudNOClRQZattaqIKUujQHuQuvHDDeUuD1b8JPw234xMHtaH6hnEcbY8FH44?=
 =?us-ascii?Q?d6AStKQuShEn/iOra4jTN74uHnVGrN35K1qpEkLJzrEIG4cMHuO56+/8I0u+?=
 =?us-ascii?Q?1/OBB7yLfYP272k0XYR8Tf45aHoR0Z/6ZvTzl7LvvPSLT5vy/sjRoZzFO5Yy?=
 =?us-ascii?Q?K8K7vAek/NiMRucXiCQhLFaTGzw7QbI8nZ1GRT1qrnW6oFQV1t4E3UsOpqBo?=
 =?us-ascii?Q?XUI3exvrqbcg/SHKgLJ0/oOSe5TbmzfYlMAGmPomIeSHGlET10Za/s4LwLgr?=
 =?us-ascii?Q?xs73w9WRDtvscon4ZmaS6wvsizafMdrFgDCqqTmYgEdn9os7xyQFgvIe1U8u?=
 =?us-ascii?Q?cBCGNtu58O8RFDKtOYzVAHj6JDSK81k7XQGOeK3ZzyCz82GfFvaa9t2GhRWz?=
 =?us-ascii?Q?Lcr32L/3YyiW9hkcI5+hbEY3tbzampHldWvuoTvHXAi1yWfUazqj3mJI6qyk?=
 =?us-ascii?Q?LgnAfgxpQ2VYJnTHdz8MeKGe2tBXX3ch5SPEStzkVwA3w6XGdcsJmjXplxcU?=
 =?us-ascii?Q?LnftiAHLUj8ZSVItO4tNlT5bmsht5QdhaDp7DHUC?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 6bvsFaTHVZ7L9xrjTrH80oDgc3FgBwIAXvT3qtbL2SCK7AoSXvVxUiSjq5iMn3aejgj/vsq8xmsXLOb73WCc2gFsD/AYWpWd5PvDgVgDiwny6q3o+ffmzoijPfb4No2PeqVATI493nPtGiWDjcWnaWMSAkHyNTWtp1loqRa//9W/+1fmHd2sO8sPal+9enWtIsHVG4Iu6yH+z9nXvEEid1x5u4ePSvpvMcKeHpokJ5tiQSXG5Tz9oW8p3C5tATyf6UJlRbz1N32L5AXe8w61HBl6+UtJHlkxvF6hQczhZwqXnJzqdnSFZmVu4p3BMO4rlrv4FxT5h+HpCch6QKiBOKzb3OckC0TyIfkRWApxPW1mMhEvYndCLhACBNW4fM20nP+cx1K8ZvmH+B6awaPCwEV+OJTRlphFrGCYgr7OlK34car4myCZNlFnppVZt/JuN2h1qjDrXiFehHHfAqUqtn5SFrLgdjBLuqnxS3VuZTBPoDBJC7mQpREpuGxnfIimau6YmYiMxhxXra4SzOpYw3XE8fXrfjqTvvVlYEGlz2fYDz9SEZoFE5tW70PqRLeRsNDbybvmA5DyA75/slblDSQl3WY+7fAp7TN6LAjKTJM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2bb5e3ed-02b1-4b3d-b4d0-08de2270f107
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Nov 2025 04:56:01.2489
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: CP70iVoswhfSWCOJ3qBdWlCXWPVEUCGo1KE4bik3DKV7Xf8e54m1Y0DGrbJrF4YbfcqE5xj2dfNk43BPrL+1SQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7808
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-12_06,2025-11-12_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 adultscore=0
 malwarescore=0 spamscore=0 suspectscore=0 bulkscore=0 mlxscore=0
 mlxlogscore=941 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510240000 definitions=main-2511130030
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTEyMDE1MSBTYWx0ZWRfX7fYy2vmgdjDF
 98Qc5uDqVkPSq72Sjcqi7PqGLlYVbuPtjzGl/0biIL3QEpOmxIzmppu5zoohiidfh+hk+T7t3DA
 KamjVOlgiJOchW/+dp2d3wMCwrymY3/Mnx3sy14z4fSyDYaIvCRRzqWgoEPbhgn0HLwIG1m15oO
 EY8c63HE0Ftw1CxoWHXkamkCr+I4C0I7v7OaCz2u4qjFuqhUPSV6dy7hhJMC5h0JWgucjPbmHbn
 LMSdsEv1PQ1GdcOl37UvYiTrwF/gTmv8OcaNVdbDl2IB6AGnAaVb0Mq3AY7+36sD6Ryn6PDZ+lh
 MAYqWZyxl9wvtgepBO+kRG+xJnUbQ4kNAp/LLCjTsgXSCJamsG/UQ+OL848fyMbeIDzBH9lZrLB
 K70Xmn7Qmr8qcdhAKwyDjTIyuvCQu5PCzpb6Tj0QvTIugZ+5e30=
X-Proofpoint-GUID: 2PSlp3CC5rMtTGV37He7UWR9IX93yfYP
X-Authority-Analysis: v=2.4 cv=ILgPywvG c=1 sm=1 tr=0 ts=691564e6 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=6UeiqGixMTsA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=qzn9hoOiA-xk4J4z_TEA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:13634
X-Proofpoint-ORIG-GUID: 2PSlp3CC5rMtTGV37He7UWR9IX93yfYP
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=r1kBEuk5;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=uo7CKJKn;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Nov 05, 2025 at 10:05:33AM +0100, Vlastimil Babka wrote:
> We want to expand usage of sheaves to all non-boot caches, including
> kmalloc caches. Since sheaves themselves are also allocated by
> kmalloc(), we need to prevent excessive or infinite recursion -
> depending on sheaf size, the sheaf can be allocated from smaller, same
> or larger kmalloc size bucket, there's no particular constraint.
> 
> This is similar to allocating the objext arrays so let's just reuse the
> existing mechanisms for those. __GFP_NO_OBJ_EXT in alloc_empty_sheaf()
> will prevent a nested kmalloc() from allocating a sheaf itself - it will
> either have sheaves already, or fallback to a non-sheaf-cached
> allocation (so bootstrap of sheaves in a kmalloc cache that allocates
> sheaves from its own size bucket is possible). Additionally, reuse
> OBJCGS_CLEAR_MASK to clear unwanted gfp flags from the nested
> allocation.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

Maybe the flag can be renamed later!
But I can't come up with a good one right now.

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aRVk2BXrC2b7RJ-V%40hyeyoo.
