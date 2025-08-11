Return-Path: <kasan-dev+bncBC37BC7E2QERBYUP47CAMGQEL7K47EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 785E9B205B8
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 12:37:24 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4b076528c4asf46043641cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 03:37:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754908643; cv=pass;
        d=google.com; s=arc-20240605;
        b=cabnE1cgghQtjkN0Av6GSQTXrul87jje36mV1hykiKHdI7y0148vwgZgTA85dDmksJ
         NjEri3DS4UX5Hd7saQRMGQJw49Ks/127YYMyB4wh4qvRiGDBPl00LaoU5grpV786nmJE
         7mHoGkbQJAMOtPCq3vhQrXglyIXesTX1i39NZ+Phps0DfF870m4ilaX2sYVPK6Jwr5m3
         V22H/JJXN3MjxKoFTfYx18lWQ9RJJkh2v7KZvakZec6jdDWk2tML7KFl4aOMggv2ZV8b
         2ACgDNaQA2In7jDJmThRZq+br1qR+jJwcoSCbmF7rQBHSuzJ7fiDuoJJFWHXu7x2VMOd
         9s5w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=NqjjJMe0tk8jE/J0Ucc4gDvlvfS00SizCVUgQeJKllU=;
        fh=lybOy6jYHR2oatPD08tMjYCgjXxcRMv3uXOkSbNP7Pk=;
        b=PFfKfKIpaNL7uIhRrcVdnBQzvqaGktpOTsLRk4uU6DSgS77SIVZ3t8DsdZMrIAmsAW
         3blmawbJvDNl7k027BVeIm6xqqk+2dOHNDnXEmpmCETgE0/K3oIuzJTbRUn6i+kmoOyK
         UCX+iyGgV4+QYjdur+jv4xsOgXgF3NYpcxU19QjF5OleynoJ74UKv71MUgFGygtntv8c
         Rj3EnJxQaHf0dW+nEx4rMAE2ovQBYb8mFrYylOG62c1w0nIzjiNQ/qT7uBg2j4wRVkER
         hrwwc0dtbIyszEdOQ6gnDHNjgCMxmz3Jtp9WxTN9EFEzKM9D3/cwm40O6f3jO7wg9Izm
         dZ4A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Op/ksseA";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Da5kvDHM;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754908643; x=1755513443; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NqjjJMe0tk8jE/J0Ucc4gDvlvfS00SizCVUgQeJKllU=;
        b=TOWxguddIOMUAIrtWzujFM6pGRkV3aEFvQrNFibON4IqlBlizCybdT5iHq0vYGSfw7
         m5TUlS0h4kIeve/aTFU0rAEI3lfqLSDqjaMY9Mu64M81jWjUU+5L+93cC8W0uw3KQfQE
         blIZ53vNf2b2FAMG/+hgUXcHavhFgKgOG0UCRdpJ32PCPiObCHYnu+EVVYwvWyvzgWND
         clUkLWoFXmjzsTWGqJTEsQIkpctWHEJ9CYcaW+GkihPwSVJNVJ6oZFd0QV1rg6GmAk9B
         /te69CW6y+ccgbIbqZ6xNPfyfRnTwhDsYOoEdlcv+td5I8uXGfSTdY5aRokMHGTiOAFC
         AlmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754908643; x=1755513443;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NqjjJMe0tk8jE/J0Ucc4gDvlvfS00SizCVUgQeJKllU=;
        b=LzTuwsRMQxwtcFioUVPvRXXB5w9uh48n4dRhKYrSC1Y3kfBlXMne9RJoXDsKJl0pwB
         GiZL3XaqdmeGcxd3KN72it8lDIypKs+XBFnxoFvi6ZbVYNXVC1y8x+VuYjgAVoLza81J
         aGfM63yQGm7IsLFMiJm8TD+fKFxVgWJV1rSyMw2v41NGuBsjWZb9JoWq5nQY2LULUYIr
         SEdLVNfZB1mANZY95cSTCO+XZAkAsw/h8pksX5NQFzr56r3g8j9BgWSmb92UAy8arLfy
         PxrpGAXlJAWlYhKeK7CIR9FulmwF/Kh9HHCnJckQoCt6CjR/U/WC2OfDrMhpfbPGCdxx
         v7+A==
X-Forwarded-Encrypted: i=3; AJvYcCVzjO13iwFNc3aJ6DUHG57/8dOSh3St+fIEP45MPB2Iffdb0rjCLDESeHmHOz3cPRFvb7RqqQ==@lfdr.de
X-Gm-Message-State: AOJu0YwcojJnAhfFoHucNtHumcrmI7l20lf6ti3Y9IqNT0EAFyZuLzV9
	XjpIeO0vizdB8ogli5e6wJXNnBgpUq2G3P4LwbYjGIFWsE2Nc7Nb+IGN
X-Google-Smtp-Source: AGHT+IFmeypaoVx8k/QkMkBvBhPtlRT5PLEcDD1Gym1zIpJrJBRpl7ktrMG40d5QN3NBzI3ZQo1Scw==
X-Received: by 2002:ac8:5f4b:0:b0:4af:17b4:62dc with SMTP id d75a77b69052e-4b0aedd7c29mr142100591cf.34.1754908642845;
        Mon, 11 Aug 2025 03:37:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfCLOSv6/AmQFsl3+z59BIC+sXzbbfIC6Phhqk9FiCKPQ==
Received: by 2002:a05:6214:1d03:b0:6f8:b2f3:dfb9 with SMTP id
 6a1803df08f44-70988401ae9ls61714806d6.2.-pod-prod-08-us; Mon, 11 Aug 2025
 03:37:22 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVFmsY18nXJ1ZNzMhVtADIHe3z7PjinzSdI/EN9javxqN1uUDIQ3b+Kf2TfCKH1wz5z+jePN297Q/s=@googlegroups.com
X-Received: by 2002:a05:6214:e67:b0:704:f94e:b5d8 with SMTP id 6a1803df08f44-7099a4f2b43mr159368096d6.48.1754908641841;
        Mon, 11 Aug 2025 03:37:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754908641; cv=pass;
        d=google.com; s=arc-20240605;
        b=ePCEq5dJ7VMENByHc/g649VRtryGgvG771jfdJvjlfd8l3Yy/4Be9kC2kyMvifBfEs
         0FLLr8lUCauCWSfaVWmakX+EOQtz2uXQUZacC7IF7YFHDWMzxaql6ARRfQ5+NGBWnBhM
         qBbJ93ZSeORXQ/+oOn1Qk0PZCNf4aZS+FNf2FHIgQ7R7TvpO9M25dvAWdfphIa9PXTM5
         Pnmc+CXN7a1lWeLaSBC2VESAa8cN60/4D3fwgWTHEEsPaAX+2eYC6cx/MGsH4n7+UZ1q
         cX/cJfe599MYD+JQcTpzejbvrPNu1bHZ7rXXFEw71VdpLVQ6wVXhPP0dobWMdUcLfUhs
         oPfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=iRv2FrN0HxEbXj/+Dt3jbJbxzyad+1K38mfknWwvmS4=;
        fh=arBNNMzXNRcqE5wdMSiM4awR/ukSz85ag6ow9K19PbI=;
        b=aI4Ih1lKPYxIla6zoKbOUOi5vth5q8ga5yzqEeTq9afIiqlIGHcDKPtWBCmJMU6lR2
         3MH+njrEqUUPbKRIxS/hm/l2iWv/6NbShX6QwgN5VPAe4tOodf9P+R32F3VI8QoTWaXa
         bzTSBKHM6YY7XwVY/x58JXo3f5QxBqq5W/odAKvVKNlpFrazPKO/Tl5e4qem+HC5ZYJK
         415ib5L2QmZmjKHqpQfVZTRwUqoLzOPNiWYxdVchiiQMtyetqBMBg4kI5dCpYEUast+c
         Ql6IHIktvM4gnwFMeu18Ib6IMGWvYuAWoOkh3x0zkWYalaR695DB6yW8XQMnRAMI1XCe
         Tz9g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Op/ksseA";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Da5kvDHM;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c91d3dbsi10639966d6.6.2025.08.11.03.37.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Aug 2025 03:37:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57B5uBm1007805;
	Mon, 11 Aug 2025 10:37:03 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dw8ea70c-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 10:37:02 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57B8jqAw038576;
	Mon, 11 Aug 2025 10:37:01 GMT
Received: from nam02-bn1-obe.outbound.protection.outlook.com (mail-bn1nam02on2079.outbound.protection.outlook.com [40.107.212.79])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48dvsf0aeb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 10:37:01 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=cYCHISTkoB9AuTjLcVAA+WYXLobroI7T9fTglbZOk7djSjrAE3Yt0nNIFyAPJFKDtO5B3/XgCMEoURO+ZeYvTMxL/RSQyPF++7s+8JvySDvf4j4/xxoRHTHYz3uuVidLpkf4BDQ7iXVpijFqmiQXio7SlcAhTuimAVmoDvhjVAapowx2EJaNnlHKAYx6e45eG0kk7L0s8W4nxQqYp+b64+SaFH/EeEFzHRqTJqSPTCR9g5VVy+HzW7ekRLcLTu+BxPqXpNLmIgBnwd2yTTBgAT6RcMOe9+uNa2GCHFV22qxo5d45NewaMY1zI1Gxh6ZxxdvLoQjQ6LJ2UpVwAjN4BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=iRv2FrN0HxEbXj/+Dt3jbJbxzyad+1K38mfknWwvmS4=;
 b=Lw1+CorsvfhN9xFmoH+2vMfQiPmrCm91bIPxE0XSk2dU4O5tj+SdzZALPpTecaLxKwdpMow8Zt7WiGzSQfeWNtin4FE2YC7Kqv1nBQeqXYhM1Mz6T5FZWJ8wDGnDeYyav1K7LS8Iwkyh9g+1O+RoN1c3C6dDRjz+r6YGDGTjQ52DQNHIttx+ND2iqAHiIq8Lr76N0T8ggeGDoa4EgO001+uIsc45M4MZZiv0oOkVyeIIPaREl5e5WPXXNIP91Ha9ZvUnbK8D0kwhCSDWws696PvmOs4FIbkP+pv6duXfDLKtW1l1bG2BGUyU0CRdDqENAtEJ6fwBXzQ5ryFBzneh7w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CY5PR10MB6213.namprd10.prod.outlook.com (2603:10b6:930:32::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Mon, 11 Aug
 2025 10:36:58 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%7]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 10:36:58 +0000
Date: Mon, 11 Aug 2025 19:36:46 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Dennis Zhou <dennis@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
        Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
        Andy Lutomirski <luto@kernel.org>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Tejun Heo <tj@kernel.org>, Uladzislau Rezki <urezki@gmail.com>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        "H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
        Mike Rapoport <rppt@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
        linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Suren Baghdasaryan <surenb@google.com>, Thomas Huth <thuth@redhat.com>,
        John Hubbard <jhubbard@nvidia.com>, Michal Hocko <mhocko@suse.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-mm@kvack.org,
        "Kirill A. Shutemov" <kas@kernel.org>,
        Oscar Salvador <osalvador@suse.de>, Jane Chu <jane.chu@oracle.com>,
        Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
        "Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
        Joerg Roedel <joro@8bytes.org>, Alistair Popple <apopple@nvidia.com>,
        Joao Martins <joao.m.martins@oracle.com>, linux-arch@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH V4 mm-hotfixes 2/3] mm: introduce and use
 {pgd,p4d}_populate_kernel()
Message-ID: <aJnHvvb-lViNA5EQ@hyeyoo>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-3-harry.yoo@oracle.com>
 <1e8ca159-bf4a-47ab-b965-c7e30ad51b28@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1e8ca159-bf4a-47ab-b965-c7e30ad51b28@lucifer.local>
X-ClientProxiedBy: SL2P216CA0177.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:1b::19) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CY5PR10MB6213:EE_
X-MS-Office365-Filtering-Correlation-Id: fdb02414-1f00-487b-d75a-08ddd8c2ff9a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ygTA3Oiszu4QnQT+xFmGqzSLrUreNKqBeJsKHu1MNEdtojekcVWtxAO5s7vG?=
 =?us-ascii?Q?dUDkReKsg7DjGzWSHf/IopFhoYCvyyhU7NK3TwRBsZqmLranwUdehL5xC1wT?=
 =?us-ascii?Q?yqr3SYKjYByqU9CUowUs7V1O7foneIBug0Xzr+qC9ZWbhJFqsUU1ciJJl+Ab?=
 =?us-ascii?Q?E/Le1GmQJbm26WHGnFoI4ZmE7MqhU291VlyZpTp33YSnDW7YkoZDEWkYvc2u?=
 =?us-ascii?Q?nqq2Ev/6KFvMpyJ1vKeW45V5eNg4PaGfjwRmcWkAiTk7bsdp3YjZc/QEJJam?=
 =?us-ascii?Q?KxdgqvMp0SwKRP/etEV05ILAfFmScsJBSuMbQEKUddhvDkeapnUoZg59lKEp?=
 =?us-ascii?Q?GVu3bOAsoRjG1l1onuz0Nj38z6yiEtihX/s/kLBu5HJPwSpiM2RH49j+73e7?=
 =?us-ascii?Q?lRAkHVv3ZbVCQ3bkIRXUBzGXhB+eHBehp5Vc8cPWsKoIUL54GMZ8qqYoKor1?=
 =?us-ascii?Q?WVe6LXpwENBni8ebO4tGSHF03hkTO31LxIZDX0Zu0IBZoXeWEDUdFJgfGSXr?=
 =?us-ascii?Q?Gj8UV/f3sFvZbdKxxA2VsYNH9eS1cbH668Rawer8/vX14vHoi0zgV6Il+e+S?=
 =?us-ascii?Q?t6NG4ELi+kxYeo+g2JdGG3O5UtK4WLRyaJ/xwcUGpQlTUzuEgS1XAlxKXvwD?=
 =?us-ascii?Q?FYL4vS5LpdSbEFov1IysX43MQTsuM5XFopR+yAUmw9xVln4l2rw/jfGqrEre?=
 =?us-ascii?Q?VOIlkFheOBXcpE9YcWoUG1J34PmHO7XLth4oqf//sqhs9aLZ4twkQ0TtTQK/?=
 =?us-ascii?Q?RGBjeO5I2BzbWGIxhePTsxhMRJXiKyYQqU9eODGtyTKNF0/AVYrxz42/F2v6?=
 =?us-ascii?Q?W8Lc//g7mxyjK6n55gLjjIpfXTUvZPAFMwCB40GRW+hcF1NFoVs/oQ3MczMb?=
 =?us-ascii?Q?Wz+K6DfEkyJmRYNEl3kGnkxkVfsypIxmgrgp+XPJxb8l8YgFbaMWGsnRHAfH?=
 =?us-ascii?Q?Q/sybooK3dvGHxlH9evMpt4dd9LuK2X3C1EPHEiBRjjZQGK9MaW3q1M+bmci?=
 =?us-ascii?Q?HKaXnrrxkwQPp3UFVN8UdAk8BogZ80u7x40BUXT73Q5izd5cVQBk1KH3yG70?=
 =?us-ascii?Q?wz/oF6PrhFWz58tlEm/5nn7szUfGYBJjaY8TQRSqSu8rQvxCGiDYpzHUZUWH?=
 =?us-ascii?Q?tnEtYYQRJt8Z9GgDL2uYo0f1YN9fGf0CUXhXzf07/QZQ2IDUReCJcvwrrXYn?=
 =?us-ascii?Q?34UfNN/Vedy/cr5dsHIuot4ZTUh6p8UFLvxbVQrHVYIv7/1+QUd1oVkmJRC8?=
 =?us-ascii?Q?2zAGOb3vU2Cw+DejcCJrAhQOb9gTkoo836EUNRGQ71GfaQsOTH8yzMNOaOnZ?=
 =?us-ascii?Q?2yQ3onqoV+iHCnbJPgJRo9OK93WGtXB3t/g3Y5EBK+/PHdapHEEW9ZeUPWph?=
 =?us-ascii?Q?D2cG2OYGl7IKn19Ej6BfZqnmrEfS48FvbPkPXAhjgchwk/vI2Aysa8PazRlO?=
 =?us-ascii?Q?adZr0tChFdU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ISRtkGbC4gS9vRvJVgPiMCijYG4CW/RBhQrgpjfc4mgRw/k6uL9gywPh2cg1?=
 =?us-ascii?Q?K6BzOIAjRitmPw1noCZdRgjj51WEFdXlJ87oSUMw3fs27wosoOGiLV358Ty7?=
 =?us-ascii?Q?WDDoHvL4tkTJrTMhKhnxffs5WCQXZl7wTPaYEYfzfgGsrZ+cWAgCJuecsUeR?=
 =?us-ascii?Q?VN+T3TrvVSUdCFxHONq5klmZGq2eR6OvsFWAlF+n9NLsMC+ZzGSfuAM+vZvw?=
 =?us-ascii?Q?mb2VS1CO7MGts02ntfEI26QKnGImKf31nHu36UIjkNhS71kUF1YIdt3Lcun4?=
 =?us-ascii?Q?ct5C3h5hGe+c6EJdBBaPfUH9ZSpeqhnRQutaMgz07bQqvA0kjEsCNO57ORD1?=
 =?us-ascii?Q?xwUqj4mJsUTouH7B1T9H/sE6YGvkK2Z8g5RiUDRnnsUV5Xj43KrP47ECEy1P?=
 =?us-ascii?Q?clWs45XNC0q52cZr2yF5cz6ebTsRWRWxpu0fwZL7KQSfjBhO9nJ2sm9frDPE?=
 =?us-ascii?Q?dJxCUSJ6x2m+NWg+dpH/UJU/iufPhnZI94KET+yP1Ua/EzZqhNjy+8PoImoN?=
 =?us-ascii?Q?gslHoQz50FQfQ7T9SUyhvfxwdIclRHj0iSHA/7OAdb5QFn3vh0y5ag983kKb?=
 =?us-ascii?Q?JBRlF10WRlr4Iak1fuIUPD0ovu4Hk+bn3sBSYtpzaynYpaM6b+yJcpU2mMvg?=
 =?us-ascii?Q?ACRVR4NsZnA6cXHe5u+Eh5/4ztP6JGKQa4aaUEgNEcxVzpgZyvkjYZRvs5mR?=
 =?us-ascii?Q?lwVuIN17sZmiyOBf8ezq9XeDUxrtBp0dau4cd832263R5ILIcuLTt9mk7JjN?=
 =?us-ascii?Q?HjRQE6Rs4WGg5JUdwysCyQbHF/8Y265apkyr3lYElC+EKQRI+YDlyXjvOjVS?=
 =?us-ascii?Q?FkyjmiItNDnHDh572Ag1/4rqU5T1CRPsU4p1QIU633+9Pa5iyV/rjBVv1fH9?=
 =?us-ascii?Q?gdyfA0VTG4M8gpEaBWiNCvakS/7VfQh8v95j4gCOd3lCGIQS5X/KJud8P5Od?=
 =?us-ascii?Q?8FBVVFn8csgkgI+mJzTnC4e+UukmDsQdBy5POI9R4V7Aaofw/ZiIxAhpIJlX?=
 =?us-ascii?Q?hCOMintWtqK63jR4CFfmWgH9GG8jgOPPRa0JtqQeUzFPNKNIo7t7+egoRE1N?=
 =?us-ascii?Q?g5YVyEAcE311tolV+j5GIBXcoJXonqi33noxtbyuGxroQetsCyz6UkGdy4iW?=
 =?us-ascii?Q?UQCG7BrobgLuT2mrHD5vmhF0kgl5vq17yzJe3XxHaGufhs9TOFsNd/3Wrd7r?=
 =?us-ascii?Q?isoYIE37EjOx2Xyk0Px3zlVWvPieVIOPW6CyQHxEqCtCOd72B/y1ESJf9wTR?=
 =?us-ascii?Q?LNfrPQtm5Kq++q5AJ6f7uV+x9EwLZ/57vsOFJE1U1kzp49yD8U+2LUoAKfUq?=
 =?us-ascii?Q?bhEgxsBatECLkS9hg4kuhQVJSKqC2dKA8KGscIPuxkq49hWQHz4fEg5LuToq?=
 =?us-ascii?Q?TugRnBWtGzBDrfEY+30fabNRGiECPujvRj7R1ed0yV+HljGlZagtLY83xaAS?=
 =?us-ascii?Q?tIl1TE7ZZ7iHItqupsteoxe7dtPT5p94fBdzUR2uKqqcSXkrQqk1MRgUv6ZC?=
 =?us-ascii?Q?4d4dcnLQ3SBWsBbitqjlIaKnj6rU3DoM9FRVumFJzvlw8i+huQQ8yT3zrFA9?=
 =?us-ascii?Q?qrSOmz9khUAO6xbWW4RToHc0cfmiY+hqPUUZmekK?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: hhx9cdyUPTK/QokzRE+OsjK+Ss9MuscuNWFoTLcdTe3ruI9X4GVhJbTgXQ1PNIqcnMhAKEWH9QNVCcYC10ve+ySR3+rOE8GbT946vWC124y4ArTVaKJayDrjL4U1H32jBMLCLfeuGZ8VYbmM/SnqimEk5PP83LaLxOY8OG+kRsbCM6uh8D6mnDNyMfknYxt2dF+ZKiePj5HJf0OMMqKGZ8kZqw9Y+CrkMGUkREJVUzVeupMrClWsM9b7PZiTUxMo90VEWkGQjBIZ3dmYtbHIg+PZ4PXfVHcQj1ogZYl1sinNWncyUiUe9IAsgNtccmXSCzJfuq4NSDSy2XwqLanGLqB44qZtwwXs/RHh3eADvITMT5w83+Fic82x8e2o6kxsmYsToewr2NTSS4w3JQPpK9sI54iwiNWvVMvbSRVuQRr2Gl3ms97M/29FfN6LaoIQ253GcZU7+v8hFzmRTMIS8oySX3jb+J+CBwH4Wl47Frr9eghh7FxoTkylu4AaTrq1pkPNOWh+KdJfK4MiYmHUrOn1tnYkDFP3j3PGaRxtoEDoUjDo+xR3t0lScXlFh/dn5IJNVK8bw3auF+sQDeVTJ6iPC3ffeV8c/dFz5/7KuNc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: fdb02414-1f00-487b-d75a-08ddd8c2ff9a
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 10:36:58.4619
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Iz3xPhfBPAWJuKkA+Agk0P6LDTUDdk249g6yyjoI0wtTel3+bU/3u2P6rbuIwV7BHyOK2dqm/fkPxxEeZKX0UA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY5PR10MB6213
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-11_01,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 mlxscore=0 phishscore=0
 spamscore=0 suspectscore=0 mlxlogscore=999 adultscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2507300000
 definitions=main-2508110070
X-Proofpoint-GUID: ZYL2c7MsO63dt0QeoQgRyfHslMbvJSDs
X-Proofpoint-ORIG-GUID: ZYL2c7MsO63dt0QeoQgRyfHslMbvJSDs
X-Authority-Analysis: v=2.4 cv=ePQTjGp1 c=1 sm=1 tr=0 ts=6899c7ce b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8
 a=yPCof4ZbAAAA:8 a=2hYKtvtIEQXRq3MUDR4A:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12070
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODExMDA3MCBTYWx0ZWRfX+8UCe5yA/iX8
 ECkILkLCxKaa0pXC7rhXutt4yBTdxLFZ2hw0bnFDsu2iwxdPfinefghQ9gLWDk1VlbGhf8xzehg
 0QqJO2dTlTcolDzxuFAuDZwUOrSS3J7up0lgvqmPUF9Qucap9OtpbNDfQBdFO+cbORd9nDDeOaR
 6XH78rMH0XXT50j+np+bmjbevUkR1TCMMtEmdcWryhK76sm5g8krPg1LFaKEVkgU+ssxi49DEnp
 BdBzURzq9eESCKxOnSAfTMG38syrVxcYDkwTDKHJ/amJblM9MXrlDyCqmI/foRAm+L5r+cQ8ACD
 lowT9SEgm3oCKWaJvwIQ/E/4N+vdX9esL9TFyphLrS/Kg41Dbn206KqBWyY4A3j363dlGxjXmou
 M/A3U74gkLU6C3/8re8/znPBxWVcxyVonMDs20DzuY0gW6BQmHAzFTjFU586osIQ3jnEiyo7
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="Op/ksseA";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Da5kvDHM;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Aug 11, 2025 at 10:10:58AM +0100, Lorenzo Stoakes wrote:
> On Mon, Aug 11, 2025 at 02:34:19PM +0900, Harry Yoo wrote:
> > Introduce and use {pgd,p4d}_populate_kernel() in core MM code when
> > populating PGD and P4D entries for the kernel address space.
> > These helpers ensure proper synchronization of page tables when
> > updating the kernel portion of top-level page tables.
> >
> > Until now, the kernel has relied on each architecture to handle
> > synchronization of top-level page tables in an ad-hoc manner.
> > For example, see commit 9b861528a801 ("x86-64, mem: Update all PGDs for
> > direct mapping and vmemmap mapping changes").
> >
> > However, this approach has proven fragile for following reasons:
> >
> >   1) It is easy to forget to perform the necessary page table
> >      synchronization when introducing new changes.
> >      For instance, commit 4917f55b4ef9 ("mm/sparse-vmemmap: improve memory
> >      savings for compound devmaps") overlooked the need to synchronize
> >      page tables for the vmemmap area.
> >
> >   2) It is also easy to overlook that the vmemmap and direct mapping areas
> >      must not be accessed before explicit page table synchronization.
> >      For example, commit 8d400913c231 ("x86/vmemmap: handle unpopulated
> >      sub-pmd ranges")) caused crashes by accessing the vmemmap area
> >      before calling sync_global_pgds().
> >
> > To address this, as suggested by Dave Hansen, introduce _kernel() variants
> > of the page table population helpers, which invoke architecture-specific
> > hooks to properly synchronize page tables. These are introduced in a new
> > header file, include/linux/pgalloc.h, so they can be called from common code.
> >
> > They reuse existing infrastructure for vmalloc and ioremap.
> > Synchronization requirements are determined by ARCH_PAGE_TABLE_SYNC_MASK,
> > and the actual synchronization is performed by arch_sync_kernel_mappings().
> >
> > This change currently targets only x86_64, so only PGD and P4D level
> > helpers are introduced. In theory, PUD and PMD level helpers can be added
> > later if needed by other architectures.
> >
> > Currently this is a no-op, since no architecture sets
> > PGTBL_{PGD,P4D}_MODIFIED in ARCH_PAGE_TABLE_SYNC_MASK.
> >
> > Cc: <stable@vger.kernel.org>
> > Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> > Suggested-by: Dave Hansen <dave.hansen@linux.intel.com>
> > Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> > ---
> >  include/linux/pgalloc.h | 24 ++++++++++++++++++++++++
> 
> Could we put this in the correct place in MAINTAINERS please?

Definitely yes!

Since this series will be backported to about five -stable kernels
(v5.13.x and later), I will add that as part of a follow-up series
that is not intended for backporting.

Does that sound okay?

> I think MEMORY MANAGEMENT - CORE is correct, given the below file is there.

Thanks for confirming that!

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJnHvvb-lViNA5EQ%40hyeyoo.
