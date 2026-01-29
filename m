Return-Path: <kasan-dev+bncBC37BC7E2QERB5EU5TFQMGQELWDNZLQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +FwJC3cKe2k6AwIAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERB5EU5TFQMGQELWDNZLQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:21:27 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13e.google.com (mail-yx1-xb13e.google.com [IPv6:2607:f8b0:4864:20::b13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A9C18AC8E1
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:21:26 +0100 (CET)
Received: by mail-yx1-xb13e.google.com with SMTP id 956f58d0204a3-6492220c4b8sf821970d50.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jan 2026 23:21:26 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769671285; cv=pass;
        d=google.com; s=arc-20240605;
        b=QSW9svFbb+Vt4IIEDGqQepQDO7rgic5hQ9wVdgEGwjy1zYJ2YdHx2eMZqIR3mgaPV9
         22uMJfnSsx8E1LcL4clgHywK1rR8JmzOwBqw9AtRafX8HW69Wh3aTjvImHRmYR+JNSnp
         oNYqlCExJZZWL/FezYutgQ/+GCAtaKrdANMgplZCaHC02u9rATFXdSQ7fLv9E8hYe9Fb
         11AcjqARn+3jFaIsm+nQFYXnw0BRMD6virisiDY5T55L+1F/RDKOh9u5G9lpYE0w7T5k
         +Qdi+yN1CQaX3ywtexUaIFAF3hrtL1DywcGwMLluTPDPPt94e3aVtAf6c2yRP328Azmb
         tkWw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=+0rrsaDTMzPXL0M4jiTT66jwjAEjIlZVEj/dP0uoxJw=;
        fh=3XXhKhmYA+TCKaaQ+hxj94w08c9AHH6HOIWhpyfeXaQ=;
        b=MgmkOe023CjoV0zIQ8+aHvOQIdcm0F1RR7XJSl/Sg9crRdQSS1VY/rrzBzZUlptC+3
         bhw6hm5aZq0Nk4+bQpDmzM9Pu8Z3n09e/jR536C6H1yfpCspmeIcfA7YbUOmUA1EVDin
         QhiL/zfvhc1QA7DwyGBXJMfi9mMD83JduSI1fOtO37ppkRcdhiYFeMv3lU2toYztjaY0
         hLN66evEdnMhvt01B2JZlvDleoXxC5tSsiAiv457wNPE0yhcZo1go7e3pUCmlwz+e8q3
         789eniRvKwj4cCz5BAEHGk8Qj+XeYgcDa5GRJOO/n5f06q7mjc6LSVQYJoK5KYYBm4Sz
         qRUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="O/mZLoag";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=autX06CZ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769671285; x=1770276085; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=+0rrsaDTMzPXL0M4jiTT66jwjAEjIlZVEj/dP0uoxJw=;
        b=a25+61rZWbQtUsmuQcEkQyMIDwvmC6j4/dxTH3fCgproCAlFaM11A+vhx8gw+hSR0v
         BDmDzfMdA4HKo9L5BsOjHZ9aG74/Oh14E0o8Cr1kdxbztOCZCUz/3n3iR/03exQZTGaw
         0zWABuxExETT+2v4165+j/m6wUnfC8M1lBFss89mzoJ+/5MnsfPlGyfvK+GOiNxjud9X
         0PJy/I5pX7u8Wm8K10fxTbDOUkuT2SzykajRNIfJN78XYiPsAyFvthy7HfuU6tokLlZV
         9XIbuV/4oqn3lp/2XfDWRE/rCwWZDpk3q7GrGJyneJg8ChlFzUxtJiFiB3ldUm2ZAL4O
         P8Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769671285; x=1770276085;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+0rrsaDTMzPXL0M4jiTT66jwjAEjIlZVEj/dP0uoxJw=;
        b=uNk9eeeEsHuVkK5lbv312xlR7SvN9qtkmoMUnCeORda8QbxFhzHvCtlNIyRdgECxIO
         J/0NXknZkOoddiDt2MvV5mT2kIoF0FxfT8qd/apNvVr6pRXi+rkFB7v1Tg0cnVNNuoma
         FD1zgwDwrz282in95IwGKUyucaizB+qsJAwihz+Q7tOdkJ9l7ztyz0o4aiVk1KXu8Fop
         R57T35a2YRVXx9rI2Es/J+DxqNT1s8JUFlRfT/SSIWPxSqSGR7I2UhFa7sfjY5z3FbuS
         SZlheduMZ/wALEDhuM8fG/kiZUi1XobSxW0Yv7kNoI4WDyvC7ldLHkDPiyJ+GrRsVGUY
         c01Q==
X-Forwarded-Encrypted: i=3; AJvYcCUQYUlasj7BkRtO5t+/m3Zk+HMFyxe061dMaVmvGJIvbq+tVxM7/U9l4FVTcRpidKDNaMfU0A==@lfdr.de
X-Gm-Message-State: AOJu0YxSdA6r1whARU3hPWG+646BKMav+mO24TN1OFyleZbKcakmuVL4
	zSPxgkmCL3+IE1MdpVtnjtgqSqP6l+gWKJaKv0Qbqj/coPrz+AGf8QHC
X-Received: by 2002:a05:690e:13c9:b0:640:fabf:565d with SMTP id 956f58d0204a3-6498fc34360mr6161408d50.43.1769671285077;
        Wed, 28 Jan 2026 23:21:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GNAjXvEFW1wBDmG9JNwpuBgaW9fQ6MPqORzjGpvX+MQg=="
Received: by 2002:a53:b4c6:0:b0:647:27b0:1aa2 with SMTP id 956f58d0204a3-649a0251afels368406d50.3.-pod-prod-02-us;
 Wed, 28 Jan 2026 23:21:24 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXRHnpll9moeUtxYFc2FgQuXIA/O8mRs1lH6qEst3SjLezEwtvpkhg71FeSK/9ovLvI6WD6TnKZyR4=@googlegroups.com
X-Received: by 2002:a05:690e:d4c:b0:63f:b1d4:f9e3 with SMTP id 956f58d0204a3-6498fc13ff9mr5275795d50.9.1769671283884;
        Wed, 28 Jan 2026 23:21:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769671283; cv=pass;
        d=google.com; s=arc-20240605;
        b=OBJFzyyzygw52OsA/c45MFLO9km8jg418ggkSm1VGrThhRfIuZj0YNq0ghEMx9Q/ev
         GXoTVLCJwA4YvVhEwM5Z2E7YXpZTl+CoDcTa4bj3XkVBCQY5JBht3aeVPovxvstyC48v
         nMsHe7Mw3XtsZdGSUXn7gzCCjw9Qkm8lrmqZti903SA/85Ii4Ncq3/FkrlNr8XRE5wAT
         R25byNmW+fHqzCbyKQ/3hMrMNfTWZRCPdK1MNJloTVavkzZn/DTlFBlt36yXHLGWcxpT
         WLjnifnItxjZQ9dfoSDr0jcGEUGdbPb9cZNOPpcvGYe53H+ZIkeqQorv8oz3+sRYIwbl
         Me8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=b2Temcw+yMYlK99d3VsDqesBinZkWsuJl7w8QHN8zHU=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=SppxCuQrG3S183xsrolvjcG39DaOauTUmBNgxK8BiMZ1v3j7a6cNTUTCr3CQC6VQQn
         tFKof8f1Es3efGeFAKyKLg/dxvNS4519P2nXfp+xDvZC9y+1JAu0KhJOz1eoJaw8KsiK
         U4MP2lYiFwDWHjI2KR+Hi+5yNoif4BebyZXJrDfnguJYmcJNHE7K1AfnfRQYpMhyfrMn
         CqbY0YKJLJ+/59IA68Fb7VpGfT6PhHDHZNgWd2A0xsrAuZEVXUwJXwzg+GlPFTywjKsI
         clnDc6pkL9B/WvPjnojSIG3OpqyxH41qUlZrhDmBNcXu3lMYri0d3XkT//pdWCwP2UAq
         aJnQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="O/mZLoag";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=autX06CZ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-649960fd961si129489d50.6.2026.01.28.23.21.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Jan 2026 23:21:23 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60T56okT1337323;
	Thu, 29 Jan 2026 07:21:21 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bxx09kddk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 07:21:21 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60T5L4ND036037;
	Thu, 29 Jan 2026 07:21:20 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010064.outbound.protection.outlook.com [52.101.56.64])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhr8tr8-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 07:21:20 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=eUYRn+yogGNxcb7yOpM58n9FCcKIl1IjmVXi6ri+8kvgIZ2TL3ZPQcLWnvkrN+eFiMF0tgWLyk/41g5+hQgVQCBJD8vQQGEWMzBYOcrSc92DvTYIw7GlDxG1HiMqewuH36VwUlM4vdeeEealWKm9dz/B2nss3fvfy3sCwmXMr28DsTdoTMf3l8QslYXbk3HHGERUNNyblAoxbZNIGpBOJopDrYliw8rODhHAMnbSMklmVCfMzH1RwfZiyo/oNipCGsFCI4YVp36AJNd7funUPWxnWzROdfJ87EOYHXoXFd+fbfvxu271cr15DEtfie8wD4bKgOqIk4ogVeu09z9bsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=b2Temcw+yMYlK99d3VsDqesBinZkWsuJl7w8QHN8zHU=;
 b=TGTZma5Ma9lt7/Fba6bRtYaBMjwHgHCPjZrB98lV6VA2+391JnUNjUViYBaHWWr0gcmuesfXQgS13LgVSlF10FgSRr7qE3EaZzRtu1S8rrSOUbL1+uZ1rjHJR9w7SvZpmp4eHPVIH9fdmXVpmeIEzRiM0Cj/Fa9DN6B4CSteOyIq/AkOJ6ME3Twal0tKFZ0Ul57y7buS2ncOWN9fXwQw3pjP5aZEEkVHDHPi99gYCJHUutwK6rinCNqA0+RXq/AUaY7JP5UMYpYBWeG2t0IFxIeG+8uon8RLdPfIq0w1c5NUW71c3+adJI19psIFIjYwSJPX1K2iXnGjAGshXriLyQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DM3PPFEACE3F2B7.namprd10.prod.outlook.com (2603:10b6:f:fc00::c54) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.12; Thu, 29 Jan
 2026 07:21:17 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9564.006; Thu, 29 Jan 2026
 07:21:17 +0000
Date: Thu, 29 Jan 2026 16:21:09 +0900
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
Subject: Re: [PATCH v4 21/22] mm/slub: remove DEACTIVATE_TO_* stat items
Message-ID: <aXsKZStTX9oGHVyf@hyeyoo>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-21-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-21-041323d506f7@suse.cz>
X-ClientProxiedBy: SEWP216CA0004.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2b4::17) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DM3PPFEACE3F2B7:EE_
X-MS-Office365-Filtering-Correlation-Id: 1b506cc6-32ea-491f-4b2c-08de5f06fe1d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?2KnE0+9UuXCMWQLWLJ9vQo7ZO57uyi+0n37xZMUU49RuWVKr7Vy6HIUm7nHp?=
 =?us-ascii?Q?D+rwXeLLslG4biRvcRoBFRfg63cg3mZAHURAzSU8BFmbGJoZGXRs0UXo8t92?=
 =?us-ascii?Q?tlHlq/07KFyOIj5JMYHOzRJgVKFF9oUUuuAaVlFAzdybBfvKwlg5JqE1H1du?=
 =?us-ascii?Q?tnH5OoiMETVDH0VauKAtqapoHVjw6MKvgQId5jJO3beDg6DdHQ0RSPcORoir?=
 =?us-ascii?Q?yrb5g66VEzPlhhBFYkWuQk6tnw2ADofXG6x2WXuUOEc1IIgA3I31LEdudOkW?=
 =?us-ascii?Q?BhrQCudLK3cUkvOaMoBMFhDOvB3dbTxx9Iqli1sUP8qutt/7uSdg7vqlb80n?=
 =?us-ascii?Q?xMttEzdYv8lgR1JH+ebvb2ToI355IscbHvkznMM4ZzbYcpkUD5iKHbpN3uhA?=
 =?us-ascii?Q?Jb/zkgLVqz+4yck2MQfPAxHJ3VT8Z97nzPj8tRn3XC9bjPCQKDX/GsRwfqFm?=
 =?us-ascii?Q?X6k/euz7ur+e4Z+gFW1Wyjkg0TA1MMs3nSlWptR4B/rFPFSpHhIsrJNsiO2F?=
 =?us-ascii?Q?6Mcd2XDMKQMvQwC1rIoV3w+1jSBma7tEY62NsWiz3YpJ8D+b4nT0c0Gu6VIY?=
 =?us-ascii?Q?DOaNPmMB9GaSYd5dkSymU+Z/DbAPJe+RGaNhxxdS5IP2yuvh9PN81rdFf0g+?=
 =?us-ascii?Q?cQWkNezmqZ5ep6xAJLbajHtbyPnVshLHSI/cSZzbB0c40H2QUYl1T45xuic3?=
 =?us-ascii?Q?/f5uuHWgaL/NtuW7/q1yD7h/YaUFopZe29E7jmc4ASPP+d82c8qXGUAeDC5O?=
 =?us-ascii?Q?kSJsFX9ztc/cwhrmz02CeGFkQGp0sA79Fv82o8NoEMQRLx5JWD0Nuhg/NI14?=
 =?us-ascii?Q?8Z+7exs1dvygOZUPUfqomW6zjTsBd2LkrVHbZpXIHWR2y/lgmZJVval8b/8R?=
 =?us-ascii?Q?brha24DC21l97NwQbXAX9YA5UgupZxDufvP9APED+c9kH6yiL++KjRk5kEvD?=
 =?us-ascii?Q?sWI/pBnPgov4X7MBEnFVoL5I5xsql1PityoRY9Ym5T58YYcibhnWM3dzkxVZ?=
 =?us-ascii?Q?B4CBvFZ/uhC19CeV1UPj/Y2SR+8yyjHn5qtHUchYjUrbx6pNCz+WZzdAcXBI?=
 =?us-ascii?Q?Jp+I849aWtH2GTQ4VxF73LpLlJR/+9Xbf/JaFXLSiLs5EFc5fyrpMFpLKC7s?=
 =?us-ascii?Q?wjGNuAkxRzMz58XKB763oHeeglWzAW5fPzzK9hxWRVs8CWh4P/5d6w+LdWN/?=
 =?us-ascii?Q?r//9QVXbPxaFFe/CHgQ1eROhokQkbS0dIkZrYlo1DlUiWBnvLf9NELnMTrx9?=
 =?us-ascii?Q?sgQToYIwNgnqvYbn2Qv4RKeVeEic4E4rs4HwazaiOevfXAPPrt9E4gErA6Lf?=
 =?us-ascii?Q?/Tpgmh0BqvvKgJ3w5BAmz370RvnIAyE4+U3YJ/efemTEJyvz0RWUzac87yal?=
 =?us-ascii?Q?Cne6SYbjBip7fm8aSPwmojI2wpNAcr85Glc7vy9X/5NhrIckOqBA37+I9OvA?=
 =?us-ascii?Q?O9RVaBI9IpMfJk10G/dqlESNHxrIiU0SshM+kJa8qzfJGiHKqSLtu453ng+2?=
 =?us-ascii?Q?IDQFFmZ+KRq8rk6OyFXctNAtvxqAXrEpbOqnPpNJfZYmnr6s28a7Najk4M6u?=
 =?us-ascii?Q?L/NtADpBr0lwlne/K3I=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?yuRDA1Pt5zWzXS8V1eeAcFvUWrc9fdYDKRxGpLu81wPOmI72hVon8LKn1UFK?=
 =?us-ascii?Q?13BO5JR/PwCFW5jHKUoQ+tCDaEPGYzjf5yw89WYIsOnO9FQxHaW0G2R417ay?=
 =?us-ascii?Q?x1gPMOfQMwNn9g8xG8kMUxAz8DIpBannEHtytFUB+lrCCM/5M+Xy7TpbuAza?=
 =?us-ascii?Q?MSUlD0Fx17k4PsDfD/xivQM/OQTJzwz/GQPuS0j54gozz6HT9DXLomUdSO2p?=
 =?us-ascii?Q?KmEVY2GeDVoSvPsOYAXSczv1alE4DRf3HmeQCmhKJZjch+vjLbM+MMfuVLnc?=
 =?us-ascii?Q?KbKqJ5/Aq0FS1Juxz/TGezFmlrrTtwx7aeiAcjftagQFNNj+KOD96iYLH5l3?=
 =?us-ascii?Q?8S04PLH8ChryT4xRns7fFxxhdR8Xef4OwIuKz01cToWq6gsktvkaVEhSVX2z?=
 =?us-ascii?Q?ve2yPAMHTffyGjnSYUbLozzokfb94Xc+ObAhWY4ytQuV7yhIzcJJZ0Rfwpwz?=
 =?us-ascii?Q?SIdphAq5sv8xhczQr3sQEfRMc99TdKNkcn4cCLn4kkOhOLNcyM2SnM97Wh60?=
 =?us-ascii?Q?LWceB5QU+w4wPbC8RCqcsL6dkVOdqGjln7+mc+I2U5smAbakzDbdaPGKeVmB?=
 =?us-ascii?Q?Ru8X+joLs6W056gsUCVZqmhmtFjkTmaF87tRU8uksz58t9CNwWN4d73fny1U?=
 =?us-ascii?Q?zCEskvVuvriWdA6wDCLFw7OiksNDDtfQ0VczsqzSQdaLTyEdtAlxX7ajL4ab?=
 =?us-ascii?Q?/PLsiG0JJHmn/Hd3qG4aP8KklQRcDtJpuFlhuBEXOGMm+COwZht8DYqMlnfJ?=
 =?us-ascii?Q?Ooqgh/MU7nq7HM/4ZfiT41mRO/j84ZRmCiGTAPZKnvsRt7baWyM9ME880UOG?=
 =?us-ascii?Q?mMqPI2MLT3I8yXdKgTQZhQgjEGNyNyo5T97CaePp+DA9IdnKS4jpPFBBmj/V?=
 =?us-ascii?Q?16xAMOklPs5bxKDdG1YtOyGZs5FsLNqs2piAz9UrGe7Ta9le3Zt2ecStiuuC?=
 =?us-ascii?Q?UZirHDo0FBopGCne36ASD1EMndjnSs/5a9aI4xiLyHMi7VHGyliU6OJJm/jw?=
 =?us-ascii?Q?TMIW+6wUDC7rDgrJUEeqnBxCdOi+xDQa/dIixqAZBrvfbP5Q9/gnl4OqSGmh?=
 =?us-ascii?Q?S+K+qXbcTL+lIsxGa2wTp9HbXD76MaiZat0Fm1SJKT3dEZAbexFmVq9+/QuC?=
 =?us-ascii?Q?S7YV4VZntoWM8lAQRNacG1evz4IBf3xKvvEcM+5jeq7q27q0lk6lDYYY7DOE?=
 =?us-ascii?Q?PHxeyeDrkHpegxCsG4vOrBQhDog8XPZ1DVK2rg6E/YxF63g8xZt2DWlDSybq?=
 =?us-ascii?Q?1X9wNvmf2NHF9ejd6huRvP3tFjkqi/qJ/gEB5saixcx7rSRMCllJjLqM1EKK?=
 =?us-ascii?Q?4NYwJpVQRKwz1LzJomzyCopMda9ZJeJrI8r7J4Da/H7UYde07iNBweFwlVAe?=
 =?us-ascii?Q?Zg3EhP9AwAOS8chE3Q/UjcYBxWjr8WFA2kZ7dI2PRxjPinJuYlYMMqvrAD+E?=
 =?us-ascii?Q?qHuzrwZdWc5+jT/SpwK5Vvigo6St0lm5k1l+w5drJ08vN6tBF3YmggLehkqj?=
 =?us-ascii?Q?uVu7WmIZ3iK5ydo2nR4c6qXeEGbd85XUWQdvqlXyYFN/Ak8VE1QlDzm0C5ho?=
 =?us-ascii?Q?4d0Hv5Cr3joQsNrsebcLP6AlJnPrk9+wd9p0hMBCZ4JS/BDW+Rzv1gAaCNF7?=
 =?us-ascii?Q?1zcx68Na+eGwJMKpx1K3yWXXE058X99I3Ib/y5l5lKh23nu9erlfwigE9oNn?=
 =?us-ascii?Q?ruNso7WA1QeOce1MBbdcnVN8YIFCf3LHB4mizMsIOgANqZI2Aie0MEDUqjno?=
 =?us-ascii?Q?8SX4n7Xzqg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: ah7fGxkpb/6oh2TlhQEjiYbEoFBS0n5GePaJzxe/P2Ma3YOkoAwF/e3BmmlsstB/CzTnyq84+iuNQAy9g+8qCjvxFf6zRhKIs0avI3U9qUWOxtzAPwhMNq0qdETJ8VjxFfyGJ4Qds1Ejln7DrRkEXchTwCgvsk5XF5Ka4z1oVNZ4ehjHW/H7L1kxlTpROfZx0pBu6PV9CH3Wj8v2A83nww3Toa300JMCMxRod+/+tauI7XAv6KxvJdK4Eihrk/hJlcf7LS684e1wXcZ1uKn7wBI71P3pHSIJVGaJfg3Cf0bnnkuU/hAKXOdV3ln5b42Pc30cfhqDdKoU8l24IpTRZFZ9cA7dO9lMAZrgGg9KyjDdVjbbts6s17ICeO3dJP4TyNkIwQ8cqzEl0ZGANbLU6sVBZt/snMUyvrG5/pnFt21GnurC4q+PbyaSZ8MXsNx8STRmn/rTdhq7VW8tA+IYbNYR6mB/kfOfG47APccMD9ibRaQ/UrPS+88JLblL1y/phJOEOSuiz3EHfgPiy5ySkOtPV+F00K8qUIooYA6GlL+4m9HHTPOZFOSTtmPl4c0H+y/JIstZba7gGUZ/t9UgDwsTH0xiCJ7pLRkBrUuxRqI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1b506cc6-32ea-491f-4b2c-08de5f06fe1d
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Jan 2026 07:21:17.2572
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: R1TadAEk23bGlMwNdip7u5i89XNKIV5B5K1M95cWCyxCDV16Tj0YxVaapcHH+wiquQTftup8VwWRvYlxelP5cw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPFEACE3F2B7
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-29_01,2026-01-28_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 mlxscore=0 mlxlogscore=999 phishscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601290042
X-Proofpoint-ORIG-GUID: s9Ma2VTffzKnFPixOp7s1gm3a7XVAcEK
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI5MDA0MSBTYWx0ZWRfX6Br51AbcQVMj
 HM3vgz6PhQrWwpwanhJG+1p7JtxrEQQ+ni+FhVK4eUeF5bUoNHLCRNmnmy+QEqvOfbJIYGxIqKk
 wOuS0TXKuS4qSgEf2W4sFChFnfPVmyh1M20lENwRsWshMT+lpVFBFIO+/WXHWNvlfc2/1teErai
 1qZ18TJtHJ52eMHqlpr2le9C9UZwH1tSRl3V2/EmrLtpujoKfZ6NEICNHgN+XtM1qjvoeHC9J82
 ium+iEi8qgbVb0KQzsFJOvuYRVBPkjcVZ7dN7WvHynM0oAXF+MHSqJe5jrks37ZJddxpWcCLLxk
 /5fOl2E6pLGkWwN3KxVF7RQZXZMq1LPEO5Y5V/s8537WQIIDSTuBgVvf1F26yr4fGt2B4x3DY0U
 2G3iHfibTBvFrnHalWH05G3tCor7j3whKFi7mF8v6imc0q1oAODWj4O+GdMNWwgybNrR0Kcqlyc
 kgpBhcvdBDvsrIxhMLixICxL+PJYuM8HCenLXNBE=
X-Authority-Analysis: v=2.4 cv=Qe5rf8bv c=1 sm=1 tr=0 ts=697b0a71 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=mAjCH3kBFYbhTdjNtgEA:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:12104
X-Proofpoint-GUID: s9Ma2VTffzKnFPixOp7s1gm3a7XVAcEK
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="O/mZLoag";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=autX06CZ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERB5EU5TFQMGQELWDNZLQ];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,oracle.com:replyto,oracle.com:email,linux.dev:email,googlegroups.com:email,googlegroups.com:dkim];
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
X-Rspamd-Queue-Id: A9C18AC8E1
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:59AM +0100, Vlastimil Babka wrote:
> The cpu slabs and their deactivations were removed, so remove the unused
> stat items. Weirdly enough the values were also used to control
> __add_partial() adding to head or tail of the list, so replace that with
> a new enum add_mode, which is cleaner.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXsKZStTX9oGHVyf%40hyeyoo.
