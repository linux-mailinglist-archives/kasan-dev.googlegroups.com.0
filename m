Return-Path: <kasan-dev+bncBC37BC7E2QERBS62RLEAMGQELH5CB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 79C23C1DDEF
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 01:11:57 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-7a267606fe8sf358222b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 17:11:57 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1761783116; cv=pass;
        d=google.com; s=arc-20240605;
        b=H3YhDIfkChA/0Q0qPS5F3805Qr/e0OMiQoWjADzNHozWtXl1FY8gk7OhBTaM9Icx+C
         acyz7BggWnmd4/WD1ly8fk9WEWX/snr4xXfS6nXsCHnnEltL8b9KhCGKXg9ayIjCypna
         Q+0AYTkOrHom3AEJQkB26b0TNLOUPmqJpPvVGIloaDCgtOajZKLq1i+Rm8u4kGksKHIk
         8MjnZ5v+yZmEU8HDrWZ+0MYO63BDe2iyRG6pBCFJhoS/8axv23AUEXT0AKIoplMWXv0T
         nF/1dqANOFWr9FPpQqwKcrPrXQYVicFfh/eKS8mwUWAv8CqmL6Yce4x9s2+tePCY6jEx
         exTg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=7VO7Sgi2xV8RQfnRQ2mIy1BxpR4GaVte2r5M5qhmTSw=;
        fh=LaKSdM3KeOMm/4Lzj6ywNhqY+ajVF8mlZkCtl8SQWuA=;
        b=VQCp+BtqEKYxWXkNDtxdtMUJ/fi8z/NnXPIQl4nUCu/ZyM6rJ5tV0PELcTIP/I/pqS
         uJCjhKTlYs6TNSmzK5bi56CC660rEsET0l1BFl+02j2oroXbPhLWOwZViTWez4n26ADP
         Nd5r7k1DIIqgamhdv6/+NisXVceLFyqs8JGg607Q1lq06zI822g8cYjLgJu0MBCmhA/m
         PRL7gxgk0nM36DEs+9QFLVdvxveEJw4H8aJlTP0gGQHyeRGCSybHDdnipaBYq2cm2d6T
         Uh4VXOMqb2RYlIpPuHtywDcjsiBAYvCbGr38Faf3T46P7qbALixavB9dmTOOxEWY3sYJ
         tV3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=W2OPMs+r;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=JENtYznY;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761783116; x=1762387916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=7VO7Sgi2xV8RQfnRQ2mIy1BxpR4GaVte2r5M5qhmTSw=;
        b=NVGHW2BB9ugPo99b0iC8cA7ME+ezhlXSVAUNsKg4Ln4khMDWNh0oE4YzbhkQyVKD7Y
         Sp+WjJ8oRluLkZLpgvZPpbv3srSeJ0Pd8kPYffnO1P1iYJy1vUhOk4B5ceyZo21BqYYt
         r+/Cvb5/qhdA2a9MGDQklmp/NLvD1VWmXwZOS6w7l8qX3ICqdgrUVtj35FOZufjhSQHz
         Cj2mLPDorzs2ARpdHt8lg6ydE7INC01PC130DiBWTjtKTeaY7Z72qz3SgGQk5r6F8xBn
         23nHejTISrvqJUYVRTg+U6DLUMpjb4QVn/e9AcZbiRAFLuPo50wYyGgaB1s7qsVQ7qVg
         wkog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761783116; x=1762387916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7VO7Sgi2xV8RQfnRQ2mIy1BxpR4GaVte2r5M5qhmTSw=;
        b=xU1BXF5liEqTThdHkvQBU3DJ/ML0+t1iY15cTsuOaY2mpSQaj5xbazg6NWN/75Xu0R
         1RUO/BsRBxHdNxvpK69McykadRlq7b9pk2rJPJhPc9HzwraXR75B7C4511YVlj56Sedz
         FBeDofvBjCHRdIZhofqffNYB7W53s6y1BwUsQJ28h4VleovZFMHAngvcv4KjBN3gIklq
         Q3yBjdM03Rc3XLgwRw7bSjJc1OwKz78XhqheFAyNuJBkFtMgD6D1awbcviMpPQ/ugCa7
         0PS8U7+lv8Bwyhtfsu9TjJToJDfXBkyQ4JGBFO3MtUK456EtpPEN9yUzvVYIKj+iJYuw
         bCZw==
X-Forwarded-Encrypted: i=3; AJvYcCVNt1SoHf5UweR5UT2MqIAT9gRiN6n12cW7su8zNHFCYhjZC/+3Sv5mgrI0bpP/iVr1QLKqFw==@lfdr.de
X-Gm-Message-State: AOJu0YymOpjyc7oWsZYo25p28pQaY6VrFI/3r59fObCU00+8cZFqFvMT
	nOcr6GGtcfkVdaOMJaAueT14kP+4RQPYWJvcohBlzXGUYev0Txrj1V+0
X-Google-Smtp-Source: AGHT+IG5Ohb7LKNIMop/bDfdr7lvODNYY5iRD09JtjdDDYYlIXGzi9MbfxqmGbTAkeZuKqel2sbBnw==
X-Received: by 2002:a05:6a00:1786:b0:7a2:7964:64c0 with SMTP id d2e1a72fcca58-7a624c63766mr1507118b3a.12.1761783115539;
        Wed, 29 Oct 2025 17:11:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aBSBGiDiLMhoSLtTJFF8Evv7n+G1TMvm/wRRPkcdM2Qw=="
Received: by 2002:a05:6a00:1893:b0:780:a56d:b6ce with SMTP id
 d2e1a72fcca58-7a6357650afls260711b3a.0.-pod-prod-09-us; Wed, 29 Oct 2025
 17:11:53 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXGpAt5BUtFdXC7eMVW/sXXyozMrjuosrdCSyoPWtSsjsOMZXfPYR3JGQ0A5Yx8Pimaa7O+x4Kw5Hk=@googlegroups.com
X-Received: by 2002:aa7:888a:0:b0:781:556:f33 with SMTP id d2e1a72fcca58-7a624673e18mr1469635b3a.5.1761783113414;
        Wed, 29 Oct 2025 17:11:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761783113; cv=pass;
        d=google.com; s=arc-20240605;
        b=j3FhQung0U7PFagYh8NekGJZYXjswZiDzO5M+yTuNXnLJAGxOTXvO3Rf40voflaBsN
         9/ehqKZiOWWrGniHoeuVkSdW9AIKchzdK0acaeU2TaT+UDoELqUNe8+Xehahc7N2O1Rf
         BEErGchTcAJJjmdnTaVbCzVUMh0LulEpWi2qfjL15aQON13D9cPIepuDv2zvUPD1rGTO
         eY2863zwsmE8wRvI1izBpoY2DcODx2gdUcxMLsw1uIHjnNEe5tOFPXteAufRNUdqMPr9
         n//1QC7ik3/MTsZFV8AjlF6BUbtUiGjJ46eplrrt7reIbGeSXu5TtzlDoVD44wofFEsg
         vR8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=nWujrSbK+qE/62mSvUXPpUtLa6fvNP5eUMLJm7HZMZM=;
        fh=ndziwN/lmeFpSDyV5btdRc0hszqvDB1uukrSsGeZypc=;
        b=h0vK+rDDX/AqrWJCAhoVe6/eAXgtwyCEu4nkTMPHsTGnpjW0nCY9Imjc1dJJGvuT5b
         +Mgim+j58tXOBd6xq+kJo3IXeP1POaciNQAuL4OXqKJseXVZ0wB4OCpD4oSCVuo5kS7C
         PJy1d+k8iuI83M31NA73/4rqsUtPW8WKiM6iH41xgN00YWVjroULNe7dHHUtcocl4rQ0
         Sc7+BMb8siVn8Qqj8WrQg3WqnSIXbbw1gqmK7r8ENxjPHLFL/gEf5W3088Ucglu6hJgw
         whBRVYT/uuNu6JmPPkWB+kBRrSYIpI9OChgntrXKW1X/s8J6pqMkiHkgWFaFdAArtlRP
         Kl/Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=W2OPMs+r;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=JENtYznY;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7a415690d74si849044b3a.7.2025.10.29.17.11.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Oct 2025 17:11:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59TKKIPq009170;
	Thu, 30 Oct 2025 00:11:50 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4a3cv9afxv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 30 Oct 2025 00:11:50 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59TL4BjW024351;
	Thu, 30 Oct 2025 00:11:49 GMT
Received: from byapr05cu005.outbound.protection.outlook.com (mail-westusazon11010006.outbound.protection.outlook.com [52.101.85.6])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4a33xywm99-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 30 Oct 2025 00:11:49 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=oOKB7AHholcoHGjqIGglnxKFdL2futcn0Q2aNjXM+6g/jTkn2toqktYfZ0DJbKEqUu6e/cxKnW4/1Gpp26GGE2tDIU08QyWf/8nL2y8YqA/7puDwBII/mZhpUqsN55HDqlfMZWl0a9n42iMI3vPmrfLBIcZsBWsWhRnLEUhdGk4Gem8Aw0ZSAVTXCz2lkdJqWk+DqkNxVSBGidQQk0y1b2OuuPJiu526+AcBZ2Gz37fUMm+YchzEvOE0OteBeUfjGhlaYkxTDdjDn5wQ1b4vQeDxHGiQPYTbJu5Fv4Au0KxE8S7qFw3k8ExxYmdShnftzF/iqvtJoGe3Q+m+koDGYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=nWujrSbK+qE/62mSvUXPpUtLa6fvNP5eUMLJm7HZMZM=;
 b=OdnCK+3EtYvRtjiv+orMFLZbhr96aw4lFSjSlIVtpjPTYHhdXiII4a5jt36dpOVQ+UqEigGXuubCeV3ldpH0a6fL+E9m95k8nuVt4Vrwfue3UAULZVf+B5mbh14i1AReia4+qzCLG45t2ea4Ni1JoDDzdqD2fsVNpt7M4AO7hCTN2LpClCe4A45Z7fWg64chZNDGR7WdmzroZV3BFTtJkobN+ow5VWD6dT58FGL2UCMPpJqlvonz0rsD1mp2ZA+pnQM2ZI2chUUIDTWg6ZXaqoOYAgaNwFqLBSMI1xqaSzuD6HdkE2wbjzPLpeHe5ZbthcVRPyl/IUhKbf/+tzw57Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by PH7PR10MB6354.namprd10.prod.outlook.com (2603:10b6:510:1b5::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9275.14; Thu, 30 Oct
 2025 00:11:46 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9275.013; Thu, 30 Oct 2025
 00:11:46 +0000
Date: Thu, 30 Oct 2025 09:11:39 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC 08/19] slab: handle kmalloc sheaves bootstrap
Message-ID: <aQKtOw82R5ONMWvM@hyeyoo>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-8-6ffa2c9941c0@suse.cz>
 <aP8NMX48FLn8FPZD@hyeyoo>
 <982967fc-5636-46dc-83a1-ed3f4d98c8ae@suse.cz>
 <3b6178b4-ee0b-46b1-b83e-15a0dadda97c@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3b6178b4-ee0b-46b1-b83e-15a0dadda97c@suse.cz>
X-ClientProxiedBy: SEWP216CA0012.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2b4::18) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|PH7PR10MB6354:EE_
X-MS-Office365-Filtering-Correlation-Id: 9a12f45b-9ac1-48f1-5714-08de1748e9d7
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Ml3xS+FR9mInBC9keZpXOzjGkNjneqxI4Kx7CGSL5cYTVshBCtNSbLOnh6Yr?=
 =?us-ascii?Q?C7e7lRn5V3lKMFV2HLA65fzlVjpYi0HQB9pQVeksYCiKdxJY/waPnXth5JJU?=
 =?us-ascii?Q?DIq01gbmoJWJGadYa53GYYTUoIVl6hYzviJ3c9ty9ePz1HTy/rpD8jzJAuWD?=
 =?us-ascii?Q?YEJe0NTMBEIzLInlo9P7un8DMU4qr7H/oU+YvYyDzZchJbPD4X31AUPq3e/Z?=
 =?us-ascii?Q?d5924yYFZ5AkTAW5V0aZvRVp1SAL5TZd5LdtjePLFOF/wHQIYw+z2Ly9fSiV?=
 =?us-ascii?Q?ig2CuAcB7+8VxI9EL9AUK9t/1cjNSCjYLh13uvQ3ewXeJp2O08WFstQV4xB8?=
 =?us-ascii?Q?2zuWJgyq6rNe6qvRH4YJP42uAp5ZHUL+iD+y8e2E7GNizvYTFVAB42K0T0DU?=
 =?us-ascii?Q?p3TAqTjZ9Xs1GV8k2J6/+Q0hIj0FYl07UrYlccPcoXUsDt/aa8l1rD5hxmlU?=
 =?us-ascii?Q?pB5AIUmGNRkBoR4NRjhdGCXX16N8GRDZAHp/dYH4MG/7cr8kYR3ZTUm9rnqw?=
 =?us-ascii?Q?7zvDZeZ41zLxWvYj08Yrhsetf7DoL7HJ35sYUzFUYRG4hEkiZUkGCLEfX41Q?=
 =?us-ascii?Q?DqdEUwfS0M6nKaArm0DP63MFXtmgs1G2cqOR+jVQHrkl24LRmMx/k4pk5gNq?=
 =?us-ascii?Q?9jv0tesggrdSMkdKkq9fFB4PzfvAsB6jGvY2+1P4pQ5OSAvaUhMjRb6Pw5cz?=
 =?us-ascii?Q?8VcpGJEl+dysZXryFLSPkSV3bCuKM0hDrn1SL+ysth/v34r1cmDjeIbAiRiv?=
 =?us-ascii?Q?o68y6tNPQ+tqktjJ6uXMEFXxGdM7a75csnylK+jgHQnHyJoU0+WwnWX7StWp?=
 =?us-ascii?Q?CRSOtHCbQid3IKAuys3ZAHDKLzR/Y+zlASfjDKRgg6HxZbttGaoC4P8Q2ONZ?=
 =?us-ascii?Q?CI4PmTQO5JICix+FNapob7wmyvA2AuhnA+2rGBDzUr4IA7RZM7sdp+LX/5il?=
 =?us-ascii?Q?gYF7vlPZpEPQS464iVsNCzJDVZgNAq9WSyjF1l5OWmRP5+sLUThiXxb+vuVy?=
 =?us-ascii?Q?2ge5gLVbprEyEq8REdBXhIczrb64VvU7egTknrnf6ZLHhcJLWZ/uSlSe/ou6?=
 =?us-ascii?Q?UkK6hAg+vHuC8Ok29ptUfEMWo1zkYcOMjXvITeGF4Te1WxgUPt9iCfkW0NGe?=
 =?us-ascii?Q?ZBXI3n0BhQzL8s5mXio9WWc4AxLvMGFCs4lX0A3JAf5dn4CMCa5uOeIGCDcB?=
 =?us-ascii?Q?oj9lWLET7xruBgXrA/gk559Yv42f034NGs9l+Kx9LML6tle7B9yj0vXn19jt?=
 =?us-ascii?Q?gr61u9y2OygMsZp5sPZoVXdcfIbm6W/auAevB9+DLU2+1uR2998KmTTrfbeL?=
 =?us-ascii?Q?ja/JNkddZLpWzQfv7vUxiQV1IhTG0PF9bSgKbMUZHbpnbcFQkO/uITewZgxW?=
 =?us-ascii?Q?68Le+eczzHbSH1gjbtnkq9diTTjdvyGV2R2wT0VSHOLYB5fkniULsUgqFc8a?=
 =?us-ascii?Q?6phXgzMIN/GS2GnOqOpvXfabs8a8sXRQ?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uY8PPttl5SAui++OzHAj3WNxC05fGq13sgOLtsFCLPqBsMqM4m/0DxklLLVK?=
 =?us-ascii?Q?M1FV4s6yoWELBt+nQB/26R4xBMbRlmABuEIUVFTQYfoolkCPujrQaanSQ+Fv?=
 =?us-ascii?Q?8gaebyTnTH6NHybUGmw2AVgTFRK2KmjWFq0aKHRyx6IhBS+ntaZqFW9taWaD?=
 =?us-ascii?Q?S7CcJPIY5Z3eXmtf2aRT617OUf3uhLxOQ5c3HUMV9lvjRB//B4vzB6i9dl1A?=
 =?us-ascii?Q?tJ+6xcwFUnOg/AJaOvDnnjBEOe4moRvehcFFpUrW23mKIm35JIocbtg2UWxM?=
 =?us-ascii?Q?0wMFZrnkGFQ83mEAAKn9KML2SocIJYmH++YNE6S+cF9mQtqNyD6BR3txuTIZ?=
 =?us-ascii?Q?jwS0f6I5K30fJt+x/PQlSjahI1qBZjSzbyUp0XN8S+rX/CMRT0nZfGgEJSsH?=
 =?us-ascii?Q?CSzlfpbxFlSK/u866nLJig9udrm5hUdTcn4E8BYve3pDRoqsaGaci51K7pAK?=
 =?us-ascii?Q?Kif7/vwRpJhEiA/AGhUcQR4g3ntNkSYlh0+79J5wiWxF5hxPqeg+F5LGiloI?=
 =?us-ascii?Q?rTO5fsfiUTqYJHwAARi1OnXasi6IjM0b40QXpfgVUjB71gPByTzXy4XlpJea?=
 =?us-ascii?Q?TP/mvjDXUBxQL7Q47rkXkceqKKsXvYm/pKooB/Luta4pfT0vGbV5qKwV12SQ?=
 =?us-ascii?Q?Jz7SWQRC+vN+rENQBIhtgfA/t4z+CG1Jl5vLKXpsNX3Hlt1Mu6/gItEEbKPm?=
 =?us-ascii?Q?cfyBQ3awVyXJuBK5gxJRYS+esbRtH3bmCZ0vhKk4mSOiWJsrFgo7wsFUE+g7?=
 =?us-ascii?Q?IPii+8m9ktrjeeY8+wpG0yooOIPQdCwUFoKRBz0SZZ9c224aMB4X9wYZP3D2?=
 =?us-ascii?Q?KBev2izJBZtMdxpkfue8YpcE2xYiu11alYDAlooydehj+/esTMwaeFshWPDz?=
 =?us-ascii?Q?hm3ZJ6ZE23n7x07LrwB2Ib+imuox5duK9epHzKdDKIveR+/wdDY93y9B3uS8?=
 =?us-ascii?Q?3Rwhc2uf6pv9l0ZjuMcuzunvFoMX1BTId47L+Ea2xLIsoOon5+qn4AplXoEj?=
 =?us-ascii?Q?EPLiGv7r0qjM0qF6fkpAvBGF8IvWNiC9vaGlO2FvbDD9uPHVCzyjsYFBUlyr?=
 =?us-ascii?Q?WJ3l3g8U2LegAmsQARuuFde74FqWLfaodsf0QQLvNuQ3W5hdVo5JelqyIh0J?=
 =?us-ascii?Q?IO7PEHiQ73DJ6pD5h1nMFFVv3Q4oINInPA7zampF5sHaEHYHZ1jztM6ErO0W?=
 =?us-ascii?Q?X5ZZx7ymWOy0XHhotpJ8DkqHFstuLGdb79mdY8xoC6Wxa6kBneYlTnFCfEZN?=
 =?us-ascii?Q?W5SaWszcKZr32sIXyEAiQc4exjZ305F0BTp1h1hU2FPFz9Zj08NlsoMGEqH/?=
 =?us-ascii?Q?TYOsirUTi5hfDue8F7TnLiYYaUa2hTOf2eRO1XKSSUHMxW4UBbTL78pAILG7?=
 =?us-ascii?Q?v4JLxaD4h1cHZKX3/31z+yuXTVa5OYPTROO//n9iiJ7tyV0XX2+0VZl3GPYv?=
 =?us-ascii?Q?/ApiAXcBin6xOqstzy9fJS1tsED+Luy9AK1bZ0pc3d/ZLYnCwXVCm831jU7c?=
 =?us-ascii?Q?V2JL16iy/6ecs8W5YNzTuZbfua7PCgV3fIsPk3a7905f4MfKckozMwsYt7Xt?=
 =?us-ascii?Q?bP2PoBdi4pvlAlfkjIJMlI/pmtbIV5tVzBc7gx7V?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: dlKaLxMPlHEE3vTN4uq4pfnOow3prsgHNH8jMuLzcz6fKrB2nGaU9hsZ/DpU2CQ2KWrJryyLCEbcLg9Li+hyWMuhMnWWsAN624hoOV1wpmsgzldctYDeCCSH3PVEgNjtYcDqm9/+gDTTyLmqluufV6xD/FzdL3VOA3YJWbnxiv3LH7kw1dIn4HRmyjo5A7WJotutk6QfcakLKnLhClLZNNcDUBDlWzLWghw2t3KPpPYEUMFiI1ZmyekhfhkDXRTUTg5/ITPwLptNcj1VI9n1RKvR0V5hC/gT/uC9F7GdJvQuZRJshpOgmabqVLfx0KHaJlv6nORkUnbBsyWiJXZq/UXuzlNj2FElq2+ury75ikWX5/P5R+5zYF5D3lwrhSmV7U6smaWeo/UNWqPwX6vnJWj7grMkD95zHfZqUzzVzYgiPBQ24adMyG/+7ZqC5e6wxB7ZAlQUg0207mAOUprQ2Dls0BFRIZGOjgAgRhXz04OErdwCXU/cM6TnpYZZw6jsBgVeWGWqkN7WnBPjYCNjs5n+29Kt1h8N4Ljx2Xg743Okts+ShyW781FNOCmtuMTtyInvrBVIf7KxqV8WT78d2BHZupi+yHnGSqY6QTr0Nog=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 9a12f45b-9ac1-48f1-5714-08de1748e9d7
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Oct 2025 00:11:46.4480
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: L1FEythPwyDWxuW9l/4qzyOL0FBlF3SyFnMka3eRs65lW6KC9SdRrSu2AXnAzUc6C5DFAstyif5jideUS+CIsA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR10MB6354
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-10-29_08,2025-10-29_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 malwarescore=0 mlxscore=0
 adultscore=0 mlxlogscore=999 suspectscore=0 spamscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510240000
 definitions=main-2510290195
X-Authority-Analysis: v=2.4 cv=NfrrFmD4 c=1 sm=1 tr=0 ts=6902ad46 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=pJD_9mKSOZQm4ju_ODEA:9 a=CjuIK1q_8ugA:10 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-GUID: 4yIH-ZvDEJklu381jQoOvI8a5ZthlHHB
X-Proofpoint-ORIG-GUID: 4yIH-ZvDEJklu381jQoOvI8a5ZthlHHB
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI5MDAzOSBTYWx0ZWRfX34aPXk6zGUY1
 eaG8v7pmHycuEJZAKOUC8dDkOkUp6d70ITDhkDY7Nt9996Tuh7lvrsgDb3bXiAMPICFW/AngDmD
 bVrfSG39HrXOWhre1zt14XY3lhgvJ2L1r0qJRuQpNG9SagQPEg39Fnf/xLLZBEkR8J2sm1WIn2S
 IzFC3Ls2IBVLFHciqOSV93v91Pqj9IGPPHe7j8cO2wHnyAZ+lCW4Raai+nYIBG8WEgA6/TgJBie
 JxWVQOhSzPyf5gqCB1S/sQK9qbAwTEH8f+BtROZcplHPftFuF7Xg+qMYWHeuO1VvxpIMA+qQSbg
 gend/qlttTUTSEjg6jdsaDSkhJVC54zOXtMgO9hypeZnubgQfjoMm+EwfuczbKIqve1qMtg8oIe
 8hthiauwbEZN+uBVKebjHf1qkkHTPA==
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=W2OPMs+r;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=JENtYznY;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Oct 29, 2025 at 09:06:45PM +0100, Vlastimil Babka wrote:
> On 10/29/25 21:06, Vlastimil Babka wrote:
> > On 10/27/25 07:12, Harry Yoo wrote:
> >>> @@ -8549,6 +8559,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
> >>>  	return s;
> >>>  }
> >>>  
> >>> +/*
> >>> + * Finish the sheaves initialization done normally by init_percpu_sheaves() and
> >>> + * init_kmem_cache_nodes(). For normal kmalloc caches we have to bootstrap it
> >>> + * since sheaves and barns are allocated by kmalloc.
> >>> + */
> >>> +static void __init bootstrap_cache_sheaves(struct kmem_cache *s)
> >>> +{
> >>> +	struct kmem_cache_args empty_args = {};
> >>> +	unsigned int capacity;
> >>> +	bool failed = false;
> >>> +	int node, cpu;
> >>> +
> >>> +	capacity = calculate_sheaf_capacity(s, &empty_args);
> >>> +
> >>> +	/* capacity can be 0 due to debugging or SLUB_TINY */
> >>> +	if (!capacity)
> >>> +		return;
> >> 
> >> I think pcs->main should still be !NULL in this case?
> > 
> > It will remain to be set to bootstrap_sheaf, and with s->sheaf_capacity
> 
> ... s->sheaf_capacity remaining 0
> 
> > things will continue to work.

Oh right. it's set to bootstrap_sheaf in init_percpu_sheaves() before
bootstrap_cache_sheaves() is called. Looks good then!

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aQKtOw82R5ONMWvM%40hyeyoo.
