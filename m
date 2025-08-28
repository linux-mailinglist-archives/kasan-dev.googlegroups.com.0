Return-Path: <kasan-dev+bncBD6LBUWO5UMBBPVPYLCQMGQE3I4VUAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C0C5B3A8D2
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 19:54:08 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-70dd6d2560asf29989786d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:54:08 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756403647; cv=pass;
        d=google.com; s=arc-20240605;
        b=WFrgEIAjorr/Yr/dOIARMBom8T3idTwGLpASqOsttPahDCqun59rUDA3qNiDFQToAG
         8NzmVLz+umRef4Rw/1YAGALwm4fjoRwgHxPtwbDF8PoI9kpN4nTAHlFr0T5Qnj37J0eB
         30t7cwqljXXgx8/ufDvABq9vKmQ+EIfJUNgaQYl00dZG/+4GOh2USAr+2NI0jEO2OhYM
         zMiazeugu8D+e+RBG7rvcVx+znI9IVrfuOhe/Mu4ELLfuQtGkcQzxXQ21LIeE84JPE5f
         mWaPe7dmDGu+5xgeSR+/ok2r8M3sHws9/OgvEvZKCnTs34VQv+0kNqL5f9mEsAqysJFW
         tBaw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=OLKloVg96gnqqJwNgdXYwBe60cl0xaQDItasq/0/B8A=;
        fh=CROeVzSQ2xJI6jkCsffSJx/+l1JtFzMt2xo4P694MRg=;
        b=d+mN6EWXZFc38ytIghy7YwCLZJdSWU0HP1kxcQrB3s/06GvzLrT8IfMuglky6qSa2Q
         Z5kB8TmaDG5/K5Jikry4FpcppgGAbg4UCnpNu1H2mBTHyyUVo1iadDvelk0ffEHLeZxX
         egBB4UBC21Tl0enQWxQx6nmv6ONoOM9ynRn4GF565u1BfPyyviMwr9jzspw4S1reVfNS
         LngyRZV21XY0TAp2C+FL0CvBUlOwpTbYcx0S7PZk9kY9gbWhO1F7R3LN1yOQBY3E3nCT
         l2TrBqgFLuahxKNNobiU3mUI/LEqS3Ew1hA5MGtA3qDKp76LCzO0IecAp4yfzAfOsPrm
         POdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=J5tj6ylL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ImDZvnUC;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756403647; x=1757008447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=OLKloVg96gnqqJwNgdXYwBe60cl0xaQDItasq/0/B8A=;
        b=IMoJKgGG7v6f/spf0rOQUOa3pgYTluVlFiXxrJCcqE+kCc5xG+UvWTQ5KMErmpR/7k
         3oyj3AmJWnP4sXbhA64bXahPDK+PqERA3wLj8c2odj8ziHFmMDLhvvja1M4NdpZpJluH
         N2kYTWnXjR3OqilMgsnO1bYw7O7kYfaV0dSMeKyPG8mlh2ng2rV7uXceVpFHtP26pdOT
         L3SwvdAwq15rPWMYiSvbewibs6wVPqDz0C9b9IXDEI9PJhI2h3IG8E+z3BpX/KhQr0XQ
         Voy+MpmAy+7PS+t2sPEl8K6bt89f/nqgoy0wce8jCM/gcEIs8UMZ3vC5UWhKX6X8JAGu
         bxPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756403647; x=1757008447;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OLKloVg96gnqqJwNgdXYwBe60cl0xaQDItasq/0/B8A=;
        b=KIEVBrEMznSXEKUwRJ9GHYmRwywFw5rbaTXMf8hA/WX6YLne8fFxPp/5ap54tsO1he
         0z+22LYrEcNNR3zESgb60HpqWJk5JK3xx5+0dQRsGrQRe20Ah9N+gvf48wR5oFJb4J3g
         LhSPg1TRRpq6amrXhAjoh5AAqOEJIUMXXglTQyI3U/ikzsf8hdDQrE71StnxDDeF9UUc
         ITCfPNQzmy5OIOTDfrII1IT9SJA+WEV+TVIlASeo9SCXmRa/sC9WDNQNIEcCs4xKrE6u
         abYGarJKhNbj1sy2SP6Q57Gf+vhKb0ijFMAVREPsCIdAJyTNSFvN+Al5+EKSSCRCbyeC
         Jecg==
X-Forwarded-Encrypted: i=3; AJvYcCUlePZdfCNkBvQ/jsoUDbtnS+CzmP1Ab/E4EnGXpFhzgKmhQbASs3qXELW3TyvMm7JzmEgzQg==@lfdr.de
X-Gm-Message-State: AOJu0YxOl/TNVfDiWeytSRKriiHWdTklEbXHdds3a0FTw9+vhZCnjvhr
	Ae2uchh43ZULr28qkHRhCrFQwJxN9B3SETMX+G59S0G97l8VOISUYuUm
X-Google-Smtp-Source: AGHT+IFXu8ISU+FY1HvJV9pmIDsbuXKxwBaXPyyb/J0lZ8D6sVfxNCOsglsrBIGGnvBOMbGkTZsFEw==
X-Received: by 2002:a05:6214:3018:b0:70d:fce5:e977 with SMTP id 6a1803df08f44-70dfce5ebf2mr18695926d6.27.1756403647202;
        Thu, 28 Aug 2025 10:54:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcb3dsOns9/SJfe9HzPKeZll/z7gtwI4NIPerDt7D/q7Q==
Received: by 2002:a05:6214:5298:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70df04e85a8ls16034506d6.1.-pod-prod-01-us; Thu, 28 Aug 2025
 10:54:06 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUpdDd6Ve9+O2S6wKBEmAWum1vXuQ7hbva9OCiY2qda6jsSdM+2ftDdLtJom9XgDJMBp214N6yjiQo=@googlegroups.com
X-Received: by 2002:ad4:5aa3:0:b0:709:9e64:93f5 with SMTP id 6a1803df08f44-70d971e42d7mr241558086d6.41.1756403646168;
        Thu, 28 Aug 2025 10:54:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756403646; cv=pass;
        d=google.com; s=arc-20240605;
        b=N6vtb9x+D9oh14X8zI+Rw6kKVWz5fOzWw4rChy52m4a+9BSsSdAtKEvldOwcmr6XG5
         CVZnL67vvbz8275Fa8G3w2RmghJM8dJl6/4bF5n/ZktHIHO3468wuuJpVuZbHpqBNzKw
         7b6PebAOgYdCPCt5jwhArA7TNJPqdqHtbkm3Q/Ms4LnUM7IFfqe9dpNvYFOtvPZe7gVe
         qKtQx+gXkS1JjF1T6PMYkGHPcNCVPrkn6E5L229xPe4gQhUy36GysNGB9DoUcrLbruH0
         HZBCBE4MX8KRCBqov/1u7G784eP0RFTViJyV/PsziisM8Tv3ZY7TxO0PFfMq5dHcQdyA
         UmBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=CHjzRtov7ASb3u8aNLzA9FTH64jLfjgM58J3aSH1/sg=;
        fh=Jb2a8HhhQ6+g6PK23JmZi8SrkHymiXp3HfW59JLIs9k=;
        b=SpqiMjWrsvUNZFwZ/TCarSHlrNh01uRAs05tTxu/ldgf9NSfp+S3lIOgmd9jIidTfD
         dCKgR1z9xJKVDaPhyI8MoA99PqhpFdbzJYH5pc3rMbhMbX1zpxc90nrcVyDg+tidq3am
         9gRgM5hLGcYabK6hJ8Kb2nNdtWHrWWc1l84NBz2XZRCpSDg2vFMFv1syfZeT7VqDIkV6
         opqWJf90e1EYqdwfPwQY/twEQTZBDdk2kkW++bIwWhKI5dHl0PD5Ieg9u4iQGrhIh10/
         rqA2SyVrse224PY28nLeBQKaw9a4aFY19g7G0NhHrJ7DaBHH8rtqDQmTJwEovPhSvE+r
         B9GQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=J5tj6ylL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=ImDZvnUC;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e4c562ac4si16056d6.0.2025.08.28.10.54.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 10:54:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHMs88023372;
	Thu, 28 Aug 2025 17:54:00 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q5pt98a1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:53:59 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SGDKdl012167;
	Thu, 28 Aug 2025 17:53:59 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazon11010017.outbound.protection.outlook.com [52.101.193.17])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c678b-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:53:59 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IkXSUUR/avgJcIPGCGSco6n5NdGyM91PscV8Gj16mHnVIHdcEt3ei3UHH8RZNk0RpQReDvo+ROOvfxbBYARgTPIRuKK8EozOm6vziRyvZQfxlPfIMTN6Gg/Gqp/w1yE5AvOBk5ezE2GVPrYGAOlYGftPI1qH+WN02JZ3e+feF7Sz1x41Mui3siO3U1pQ+rmkUdQ6bvyo62oEuM0f7lo61pS8vncuU7lqW9uo5M30nk7tdWRl3dz9vkzcS55G5JSryd1eBtaxSDdUJyKlOOzhVoue8GKad6bi2cYfPIjrMhbKIvIsrMrOWXz6DOEZ0RdFrEbfcSo+6znkiM90lU0c0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=CHjzRtov7ASb3u8aNLzA9FTH64jLfjgM58J3aSH1/sg=;
 b=gIId2G8wI9gbKqqTe0qcrtZbZTdm4RtrBxM7Zp/ohrzwKn+6a/2feCHfPsxVPbuLMCf07tkyWAp4UtWDqkyI3cjDgr0IZDLyiTF8iJutNJOZ5FSNt4mod+gVbDPHpryjDMnk+N42cin1cBJSV619U/FkeLb82q5SGAQBuY7mhAljx8g/YGbqyjeFYFB1Ycsi7Lpt1T9B/tXKFn+aLPrdNUGpyx7QJnK01uLaEcb1VgPtXvmJBA9uFrA2vFn4/RLOamAegoiGwuwJ9rC+9JeHIkn7SXEpTQ2BBjY/D2LE9MupuISJwKJuX4ha3t60LnBkbT7IWCIGF0ZewMQCEkvkug==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CY8PR10MB6827.namprd10.prod.outlook.com (2603:10b6:930:9e::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.15; Thu, 28 Aug
 2025 17:53:51 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 17:53:51 +0000
Date: Thu, 28 Aug 2025 18:53:43 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Damien Le Moal <dlemoal@kernel.org>,
        Niklas Cassel <cassel@kernel.org>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 24/36] ata: libata-eh: drop nth_page() usage within SG
 entry
Message-ID: <7612fdc2-97ff-4b89-a532-90c5de56acdc@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-25-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-25-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0186.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a4::11) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CY8PR10MB6827:EE_
X-MS-Office365-Filtering-Correlation-Id: de09de42-4a6a-4545-9479-08dde65bd930
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?4+dbkm+C83TZgjcnzqukzPFBh93YOmezUA/9B4+gcGMSqdwGXDEtRtbJKmjZ?=
 =?us-ascii?Q?lX+B0zxXhRZSWdgy/H7harRmC8TOqAzm+w7HIInkZmJj44nFQIndgaAk9zi6?=
 =?us-ascii?Q?e66OL+Rm1PqqkuzXXSwyO89vXldBEJo9fwU46DJxHPImAJ96C3SDVBBhZ22y?=
 =?us-ascii?Q?9HSaqU9KZjMijiVctJTyJM5aQb6EDcTbqLXOMnC21wAQ6cJJdWwDOc38JRkk?=
 =?us-ascii?Q?Ag3Z72HOFLlAq44pUx2GQU2x6MvVlgFAJUi+CxQgEPW46t6qk7GcSYWsiWfJ?=
 =?us-ascii?Q?p799NyF+tlBLYeI0fZNyrTdHWoXVVYoUUc1ERJhu89/aJOrWHS92Caqi2U6U?=
 =?us-ascii?Q?nWHHggU07W/cJe64wdmYGKbuwgz2h8SY5sTKtOtbBCMHTfdVXJBm+sxF2nz4?=
 =?us-ascii?Q?qQnhvZDYVIMqnAwoiI2xZ79zFZwnSNFaUnQVCx6JteSppREbGop3xgmknKoI?=
 =?us-ascii?Q?ftJYxh09b629aDn8WQSl3XgZshRvwXN8OAC1E2/abUnSpyLjb14pPXDoWInw?=
 =?us-ascii?Q?Aj9edzrjoFL1LZspEiCqgwizusMfg1D+0Uva426eaJ6OPGOBKav+ikOmofjk?=
 =?us-ascii?Q?kwaLWeSrGxdEAlAuTxrfn5jw49bsxiAYOmO8pwWA1onUbuWFWJz3EBoPrD3Y?=
 =?us-ascii?Q?LNOrosJUgYS8iChg5czuMWSXieo2FxgOJWmwhxQ6t4dac1uuRmEAj5k1Ahwy?=
 =?us-ascii?Q?tzB3efBAWge/8GLojvSyDfXatzHdNGjz/IpKV3jKMept1ik4HocKkmu8/c8S?=
 =?us-ascii?Q?9DUlfvBF2tl9YM+hfRFrs3l/L3ObX1jLyZqdN6exZUCFuQHF7soru++x0cgN?=
 =?us-ascii?Q?5g6DsH7jFcveOERsdfry23LhZ29bcOf5wKxNmFmh3AxUPi/1qSmXyrDQpmAG?=
 =?us-ascii?Q?ugjKiu7az6FrSep7bXHMPf7h6WoGfyfIZFxVgYVQok8QMsAmH7MSYVM1iBN+?=
 =?us-ascii?Q?UbXRK//5nUnugNAfErL1Oio8CW9aIrUNijkVryc8IiU4GKzNwVKmhqL0Rith?=
 =?us-ascii?Q?Q4YTnis099s62e/NVtxUwYO750XtwpoG3TB+Qpq0llQn+rLZ5BYUZsXn0dz7?=
 =?us-ascii?Q?+EhlLzjK+m/jsgdd8/KIrpnDjEnahHjFYi9f2YO51gUIcTf58TTiKfWiQYYf?=
 =?us-ascii?Q?TfWlCI7yZ7GKjz36qFTNLhQxaMxDQKuqt6qT9/GUtG0+UNDdF+zDMCDvJOvW?=
 =?us-ascii?Q?TQ/nYQx8Ew7MrqOHMV/K0bleDdK0+HTXwLcicnLL/YB1MyEWgcdCBRuP+x+G?=
 =?us-ascii?Q?0u8InSHSP5JXiBGiy4Bi5T4uDh5D/gJKll1Kdw+oropPaPhAhY0xj4zKuo5d?=
 =?us-ascii?Q?OhuK8GCChc9cUbI6Vl1AwrtWZiszMCPIncPauG4niXmoWmh9UOrgGxtqLjHz?=
 =?us-ascii?Q?mptSQ/DK+nWzsxQkfaQx1hVLOnBjj/iqop+7MFdMnnozFWUniX6XvjsYtNxD?=
 =?us-ascii?Q?XZ66olPbFIU=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?SMPA4XI5mKG1t7E0K/pbHn/xzK1gFaZhnX3cS4T79iGeYjiUgigok0p8+4Ld?=
 =?us-ascii?Q?iYnKs5czYL/PtsGupDTgvLxLIUrD60n7tJ97S1G6tUdug9evjixbDVerF+Ws?=
 =?us-ascii?Q?6/2rVqw/lfifvkh5oGs9JzngrXoqSemdIeRMA0Lo9KX3Bde+aDCMLDvQ23F4?=
 =?us-ascii?Q?PitK3QCWPsC7eQGBfTZgEIKa+FiukTcQLTqAW3xZ5UWd0tVELelABnC4hz/9?=
 =?us-ascii?Q?kMlfbqB9xbQFkRbKXkud7xyLA6vWvpZOQd5/u0E/mg/eFrXgjYtg4YRX4rW2?=
 =?us-ascii?Q?oO+/xBDpYwVUzhEvvZ7yRQ82ySuyY2wG3sNGSNuo6t4Mw99rQ73xtTDP2D0v?=
 =?us-ascii?Q?50rdVGmzr4KsTSqTaXmeZZHp5GnpKAvEKaGle/hhPaBUu9L95QUSyVR6AQqq?=
 =?us-ascii?Q?fuLL6+bskNKqRguZXSTPYKvEu4l7VSfiaknEDhkluTgd5Yf2IUFzmNjHFfr5?=
 =?us-ascii?Q?5QqMnpbS97QM+hvt+g3KF+PT3mtDK2+c0DlxRgGxRGHKAMMJDEr0MKiznm0/?=
 =?us-ascii?Q?nn5kUQRRooNat+5JGPlzrUhgmV94CrNirtrpTLPjfAkk02BcKanKBaRjdfFK?=
 =?us-ascii?Q?tkqDkjqCGDJDEfIn8DE4cFHySuacbzxvHkMMElbv4ExNwCD43J4zGH9Nf7SB?=
 =?us-ascii?Q?yG7K5iIPlensMj86dYCZHKeCRpXdwK0nLHQhV4/rB4vooO+kQlrHhb5Q1x9w?=
 =?us-ascii?Q?pLf/pFu+2xmEoVThRlaBTDBMtZz46QOf9vK026yuI61s2jIssMj5xipxq7hD?=
 =?us-ascii?Q?bCXPAegJUnc/gymqXlY3iAtBNqS3COsjy3y0AgjUj8TBZHZK7GrneQzuxxIP?=
 =?us-ascii?Q?lf9kZHWOPL9YFlsNEkirNz6HKScPh28l29dlkq11vij+hA4sBu1VdEp5REM2?=
 =?us-ascii?Q?k0pB2buQ6ub6Q2lvVJO3VEsI7z9FNIIo7DLQEy2zv83egEMhI0/TOQCmo+dV?=
 =?us-ascii?Q?tJJvI2SBiN0PJ79z+SdUsfhg2Bbmh5mkzrQ1K/51+JQ17sjStuBLycRMn/1H?=
 =?us-ascii?Q?5HpxOIT/REQ+6cQdkyxSSKE52jWwfJBtwPaEkhjlHulesTwhhkwy+D2eubrx?=
 =?us-ascii?Q?EkW6Vcb4CsdLwewCQESocjNN8IX4mJnWcmaDTLrcAFxhV6ZTmTwHKAkbK3Uf?=
 =?us-ascii?Q?ZQUePc88krUWRvCnyuvrQQAOVkn61vhY+BLGPsKgtYn7Ejs8PQUZcIAjaXoA?=
 =?us-ascii?Q?oY1jCKDtUXHb7Lu+TEVziqyrptXALI0Qky0tD7V3siaKeC2Bj9cTgS4EtcZK?=
 =?us-ascii?Q?QoSZgmsEl78kgxc5SgWRSdR7D3wPDv1bLu7neCakn54HtPe2GJaeFeP5pg9B?=
 =?us-ascii?Q?4UWYLjP8rt5TqLVo7ELRRngyB8xiDdZFyGLwI4i6TniDqKFSQnOkWUkdT2x9?=
 =?us-ascii?Q?YreXbKFgVz1agQSkUzaF5HcAdILUns3qKYOeYF2qTpWwxG7J4V9tppebt+MH?=
 =?us-ascii?Q?oQTIKBIpniQ9hjYvqyKdD2RAeV1voGVFUfw+PkSUVbCLVLLziHtUdQkb3U0A?=
 =?us-ascii?Q?F4t0hsVI8ELbzMmO3xXPpFxX1Frte6bGXd2vmS/U6ukodqPg4R5iheHdjZhq?=
 =?us-ascii?Q?deJQ/+u1WI8WT2J/9opHcEvCRQLSGT48QTsVhe8tkW8D5sc3pbvW9RODpZPm?=
 =?us-ascii?Q?jw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: cUbwJnXQcZtcDREqx7KIYuX8y17mPcdlWXJBfsIcn1kBt4tMv9CCY6yWiQvJQ5DlL5yWUrxHFqWADENriWBPCNlnK+pmdokGfRkYh8Y3JXfSpZEXDY8PIPlIJeR4YkkT+Z468JPUQzOqmKnIwthtNQcoPJBRrM3Y4vNwwKnFF5m7+re1zkrVZHzyxbfHqCE5DundMTLkpjupa3TlUV//Kf8lkg79ny5FSm/x2w94ArNtI7P0cfdXvnLhDnxyxgD4zkbWWm+/u0rGKNLWhiFzvXPbRCpSAWqqtCRKy3SGp23g/oTEpw8c0HD5EoXAefRz4wBs5MOsaiN7MMr6Jdc7tcerl/hSYIKbXu2tFTXb9l8cCkR+gNjI9T0b1SCyEDpHq20lmlMAtLHSgEFSqhJnJTQy3WhCwlZburHeNwv4dWFDGSoSYfpSb4C1eJVzCO3wZjyEkAqJ3FM2kzaPlvZNnhapJF2E3Yt+h/4ivacmePp+FrsF9s4HVCiTaslKIVLWCH3Vxqq1zceXb0WjXwcauCMINoZg+NYt+0MfoJvOW3A5CBWAUrUZ3fCCv954Y+T0jnRgfnLtMxcbWkMEi/ZWYJZR8RycQ9aEH/wfk94kzGs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: de09de42-4a6a-4545-9479-08dde65bd930
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 17:53:51.7419
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Id07ybAe2V7pGRr4xeKv/Do2fRUPTa7euur/Lmf42+73kDeRGOzVLk86y/GAACbScOq9PxejY/FC0NoWj5vgUbM8XOERGDtKLTItGQirO2I=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6827
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 bulkscore=0
 adultscore=0 mlxlogscore=999 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280150
X-Proofpoint-ORIG-GUID: PLsxPJQ6Xr54MxrpYlpj2Hw-JWwPMxMV
X-Proofpoint-GUID: PLsxPJQ6Xr54MxrpYlpj2Hw-JWwPMxMV
X-Authority-Analysis: v=2.4 cv=EcXIQOmC c=1 sm=1 tr=0 ts=68b097b8 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=20KFwNOVAAAA:8
 a=yPCof4ZbAAAA:8 a=C_-9UH1JwaGX7rFsfx0A:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12069
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzMCBTYWx0ZWRfX5K+6m1YaVUCf
 RhIRgDxmgOQmCu8HEmDMYKGz5a25moKf+xX9PXUyNevjEBl2orKxlEmbRhqfFsuDdJIYg4D0avn
 86SeeyVEmDA955Ugu2E7o6BAg9PtwzOtyk7MvLHj9BjanzIr3ENLEzALQbUgLdHme0vzb15J9jb
 6L5YVQJPxFsrhqHHQybYtEFDPYGYEnI2cajuxFDzWs3pI6ESBw25KTncTwxnWXTy/atjjTMCo0a
 Gfdgl/zx12fOy8mXshT6gsSAPuUCkHeTAeQnogJhCFrXHp9Jvnnq5glJ5sEBP0VqhIu9LS02JRd
 EHjBJDq19ytUTiHhoo4GC7joq3yx1oKOMz6ETbmlt+Su82DSbSK+hZFs3nMe/+JOmQGO68urEGY
 IrlRefcD5hIR1Xyf7qbbbKUNO9h3zA==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=J5tj6ylL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=ImDZvnUC;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Thu, Aug 28, 2025 at 12:01:28AM +0200, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
>
> Cc: Damien Le Moal <dlemoal@kernel.org>
> Cc: Niklas Cassel <cassel@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  drivers/ata/libata-sff.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/drivers/ata/libata-sff.c b/drivers/ata/libata-sff.c
> index 7fc407255eb46..1e2a2c33cdc80 100644
> --- a/drivers/ata/libata-sff.c
> +++ b/drivers/ata/libata-sff.c
> @@ -614,7 +614,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
>  	offset = qc->cursg->offset + qc->cursg_ofs;
>
>  	/* get the current page and offset */
> -	page = nth_page(page, (offset >> PAGE_SHIFT));
> +	page += offset >> PAGE_SHIFT;
>  	offset %= PAGE_SIZE;
>
>  	/* don't overrun current sg */
> @@ -631,7 +631,7 @@ static void ata_pio_sector(struct ata_queued_cmd *qc)
>  		unsigned int split_len = PAGE_SIZE - offset;
>
>  		ata_pio_xfer(qc, page, offset, split_len);
> -		ata_pio_xfer(qc, nth_page(page, 1), 0, count - split_len);
> +		ata_pio_xfer(qc, page + 1, 0, count - split_len);
>  	} else {
>  		ata_pio_xfer(qc, page, offset, count);
>  	}
> @@ -751,7 +751,7 @@ static int __atapi_pio_bytes(struct ata_queued_cmd *qc, unsigned int bytes)
>  	offset = sg->offset + qc->cursg_ofs;
>
>  	/* get the current page and offset */
> -	page = nth_page(page, (offset >> PAGE_SHIFT));
> +	page += offset >> PAGE_SHIFT;
>  	offset %= PAGE_SIZE;
>
>  	/* don't overrun current sg */
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7612fdc2-97ff-4b89-a532-90c5de56acdc%40lucifer.local.
