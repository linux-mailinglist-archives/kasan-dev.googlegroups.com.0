Return-Path: <kasan-dev+bncBD6LBUWO5UMBBV7SYHCQMGQENBVT3XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C5A76B3A4C3
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:44:25 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-3276af4de80sf1604341a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 08:44:25 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756395864; cv=pass;
        d=google.com; s=arc-20240605;
        b=iCpVDNdkanzlUxng5m7VxTN0Jvq/m+PJntU4VQFvSU1EXsuzaAr2JAV599wgNq5lK1
         YlJHXlvKYEndITsAIEOPzXucwLRUBzqWsBm3+2j1GvD+qmqOyvHRsPhrX09wrjjEheJ5
         p5hDwB4lXBWpKLjdQplCdy8cta86Ype6JVkC8Uk8sY+S/txryfd/1Sh7TnMTECUeoaS2
         t18rPfJWHsUvskU/DvEIcfAQFhDMmduvOwMkTXmRk2YfaVq1kBTa4JKBM7a6FwqkH6Rs
         jJhA0E31TGxZ2l33wZJ4oep+XvpAhqyiyie6HHph587c5qTCT5QU07zudVM0RnRirxHZ
         ghRw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=iw8thWbNIxEs1/617QW6nmDso5YUpTcRCmsIMIUReiQ=;
        fh=SZNZFwUYZANv1PMkT4r1FIeQR3EJfd42nQBeZFJ8M5k=;
        b=Pl0QeXY7nhyuqzgwZTtRxMNAvzvb9wOvFpaY6L2MrxUKyRvnU+1+XqZCRyvi6HZmDK
         XPI3OOifbiiinpL/4+6evkdLDxZYRHOohQXzK6ifmMLBaq1CH+woMPS6cHkgiouysKbM
         GR2o3ddCxu42uBO8MPkd8/jRxzslCM2e0Kpwbki7dyb2WqHtV5CbpNt8Famn//iQ+8l1
         QqtXE5R3G3k3UWIOW7OD0ONOuCfHNLb8dr4G+MCjlGeAb0g0R9MWQh79GX6J5CTUzUnl
         3tAThB7wuP5ycCw88sClwfNWJeumphADsBFWOGIOTbRYedUT7NXvSXoAhN0lZfXtxAzo
         pCQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=TJ1nvdR8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=VMNn8kP+;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756395864; x=1757000664; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=iw8thWbNIxEs1/617QW6nmDso5YUpTcRCmsIMIUReiQ=;
        b=I57iDkOJD93hCRdpJiv7U7MdBVMcYZEbT37aBBlv3auY06z+7sgdQOKmNmqkWvwcvc
         ydB8+CqQ7zSET74B0FZSROCoitjplh/E2+e4gW1iTGPYfNhR5iXenWZBpnFJKagJKPXT
         pL1Iwr63pYIcQEH454c/mrnz6j1teKeTEPIMnWjvfeeUi/F9z82kTarM5FmnTwmZYHf6
         yC2e/eS465q0aP5/H8Yy0g9xLf9FzriPu3q/kGRjkR7H7y5lOi4l4nyieROhnvod8kAM
         JRs6SWsao0Z0Y3WQKXjhVVyJiosLJOH5894j5M4HK3uY3QAodX2TxEM+v+yeKWV/Ylx3
         8NAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756395864; x=1757000664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iw8thWbNIxEs1/617QW6nmDso5YUpTcRCmsIMIUReiQ=;
        b=gdJuolaDDVxO7iZLyNI3ZaszMEJHBayxpeOBKqwwZqG322AR3SoCwFpo29oXAetTkG
         RWgzknmuSR7pcP2kJ8oRXPK9Sg6nthrNFemo7XAykR/YDen7rqBPOGTbx2lGwnNMvTxS
         e9rEuObtoaedcA6onGiyTGELQDZMbB5CN4lpctgrw55+akEGYLYMiSq3kuCpjpmW2YR+
         Y+KimSCkt8+pUMnB/r3dQpPGdVbBoAqehxMsSJ8yAFCvD/4Pp5YCwmzwho7bmxCHAX3X
         GcjgfJHIZSHD+bvMtJXoJNELkAyceSLKQTHXAEcVkmTgZM7chofPjE3kSyvYoySInsdy
         gvow==
X-Forwarded-Encrypted: i=3; AJvYcCUThvYE8jXDghbjpfWTqlFh6fTzww0huFf9ZrobZfLmmpHnc8DnyefPbHkw82rfWu5gnZd6Bw==@lfdr.de
X-Gm-Message-State: AOJu0YxegqINlidVOyko54a4LHNb600jqSDaY8+fZA2nOMuX+nI9bTLa
	OuQcRfFcylCAt9kp/riYoxvhmdtZF0G50TdNdohcnoJvxkCu9UJJ7vhW
X-Google-Smtp-Source: AGHT+IGCcmxoMoTzrBQHpi6MKHXf4KFbMKHBZfa6DmJyrKxy2OUrXZ0Bkq4jZ74+VANcFkj7AaJGzw==
X-Received: by 2002:a17:90b:1642:b0:31f:104f:e4b1 with SMTP id 98e67ed59e1d1-32515e3c8f4mr30214105a91.7.1756395864164;
        Thu, 28 Aug 2025 08:44:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdLdlplUT1io9Ohwx3+gNRhe2r51xe6eSt2EJSwHQYS1A==
Received: by 2002:a17:90b:278d:b0:324:e4c7:f1a2 with SMTP id
 98e67ed59e1d1-327aacedf42ls1252996a91.2.-pod-prod-06-us; Thu, 28 Aug 2025
 08:44:22 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXjMKCoik0EmDhBkmO0eAZwmyzwahIdSNJcTx87qg7MSGM0WG/Yl4fyrijGHb+IwqMQDtRie/L/Wuo=@googlegroups.com
X-Received: by 2002:a05:6a20:b2a2:b0:243:9fff:786c with SMTP id adf61e73a8af0-2439fff87e5mr7786762637.36.1756395862437;
        Thu, 28 Aug 2025 08:44:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756395862; cv=pass;
        d=google.com; s=arc-20240605;
        b=FL4mrdv1vKeW6ao8D2TMvL8uR1Tojzj0t2RbLiy2Cbh+BCpZBvtIjk0xALqFKpaETO
         UHeCF6JLzd5tGdrtd8AI/UkXTFRyPyQzJcnr4JpcH1cYxx8UMDkzChiaqwVHdnJ1g7YQ
         Rux6MfNP2Zibv/6706D0NDYioFBwLnGa7GrztAnITvWdnrT2oij9HRcc5XOKPL17bhch
         IrUyAqoxU/PAOqZ7URFz4Kypz5zMeZ/HB87rfHfgB8QKsCtdBG/yRDQcisSeRCp9iaAV
         wXRuvM6YN7Ju3TVRO9z1UPOT4XcTTx+NZ1ggu5haCcD02PrejNjNrDQDQ/t4Avq/UIzy
         1mdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=DHwVa/lVACCrZEaOy+hxxXoimWg8nh1PzsZ7tjd5Fbk=;
        fh=nDVLMfpnt16dAvQHlJ/+ZWR3WaZCA+P2x3XNdYCnLhM=;
        b=QPjPxaKsX2wZRBYXHx0RuVbw/43vqD2rxi5nweHZucew5wiTvhimAbmmC+xqKVYQGG
         t5Qq/IQD0IdvUUOlfqBWYkSuaKOjVBQwj4r/9esMYOn17+kPnGQCduiBtNhqySmttdx6
         asn/tsolmY0uvcgM6wkjoGgfGrVGeigUdbvLE3bqc2+uM9B289/3DT//8emoYIP70aJc
         t7roJg0/4zcMco+BNX7Gd5L2bY0JWl8ev8QbeWLZH8AVZS6zL48m8GAEmo6xSayWPjcm
         QFG376K+KVo4Qh2CsSenzsypC4rpX5ai9lnAfw/nMFCfQj+SfH58xKymRJXdG2YK7LiC
         Tiww==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=TJ1nvdR8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=VMNn8kP+;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4c7ea9a206si20546a12.4.2025.08.28.08.44.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 08:44:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SEMxt5029591;
	Thu, 28 Aug 2025 15:44:12 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q5pt8yt9-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 15:44:12 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SEGDMH012325;
	Thu, 28 Aug 2025 15:44:11 GMT
Received: from nam02-dm3-obe.outbound.protection.outlook.com (mail-dm3nam02on2063.outbound.protection.outlook.com [40.107.95.63])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c11ep-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 15:44:11 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=MjGULiD/pca6V0uT1lfAaA0/NSi1qO/oIb8xomuKAwlKVFSeSFmrFuWiu8wg+mQLX4ZkJ4yAO0jfbh8L9PLT7BvKt8HVJYnjOnGbTpx9BfnKmj62hjAjilFqJijq+/nEjcPzFUIor42eZs4qxHjU1rTkGSvigRpjukrq7aqh3y6kN0Q74wQaoYsbcvxsPeD1p3vvPKZ9BaSBKO3hAVzYaXGuKCR1TsNuFZ/xAMeX6k+Z0fETsV5l+YPHTkU0dzpQIjqzYoSBzZJaXUIgey6Izu7d8XaIDlOh3tOj2dpbLFwg5b5UmQYvyJ9Fo4Hl5Nyr5s0eBgck3Kg2k3o8W0E+hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=DHwVa/lVACCrZEaOy+hxxXoimWg8nh1PzsZ7tjd5Fbk=;
 b=x4kmXWwYNJCxtMCISYeaZXmNqOxQtF9CNofW2c7/H6asvt1LAU/565Xam+Tw9cch4i4Vw2kC2YoMb98r6FBdhtgn7ndwLsUwTTBRu3LGlAqECa/0/rH9sf0YCf89c6EDoMgp6XzDpnUf6GHSRZBqIlUADI0f/QnsJbqOx19Aj8vqleO2kFmZCO9VPVGs2zwxoekm4fN44YCdK7bVNMMaGRXk54gZWa8I9XmBXcbIj5rJIB1yrfu+2kYQjY+32Lsm36bHzm2xU0xvN0kMrwJn70WGIFGdSGG/1vPFFge8znPSVOxp/TN0DhAV+1+swezWODJt/btIOZot9MIfngVSdA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by IA1PR10MB5921.namprd10.prod.outlook.com (2603:10b6:208:3d7::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 15:44:03 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 15:44:03 +0000
Date: Thu, 28 Aug 2025 16:43:55 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
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
Subject: Re: [PATCH v1 14/36] mm/mm/percpu-km: drop nth_page() usage within
 single allocation
Message-ID: <2ee63b0d-f5d8-41ee-ae7a-0e917638cebc@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-15-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-15-david@redhat.com>
X-ClientProxiedBy: LO2P265CA0357.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:d::33) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|IA1PR10MB5921:EE_
X-MS-Office365-Filtering-Correlation-Id: 5beafdb5-1229-4ba6-3685-08dde649b710
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?vnwzyE9PPSU8rAInLuQl0dYN0TQOuu112vJi44oLYEYtvwuUNS7t80lOOB7B?=
 =?us-ascii?Q?afwCGgaBZHkgn7dTivQrrWFM119a/FUS8kl2QvkxzdUJz45Yh2fkjUUB4L+n?=
 =?us-ascii?Q?mgNEH3+vSbocZdX01L00K+1bvlWz7W3Qk9Gafp0JSPNhoayIr49EQQF85Vdy?=
 =?us-ascii?Q?AhJk4hwY1ighdmv2uA1PqQe4Hd9VJIRWKjykysgcH8pK+Z+GlGW+avE8WkJz?=
 =?us-ascii?Q?FGC/WVjMA1zX5XraAXvQUt+wj5P65il0md26xrM4KvBMha1il2uhO2WOks6J?=
 =?us-ascii?Q?VqzJ6irlmyjs15DqufGXHlE7ZX6oiQ5mcw4+IUpOm8npEqEUihyTB/uMH+bL?=
 =?us-ascii?Q?aUWL0rbr1SlL8NJxrvLrTEtvYMBR0DoyEGhpe00hyD+Al3jXeUPueI7cWgt3?=
 =?us-ascii?Q?Ennn0Ya5KXsQCqOoB/x79ypEKMHDnUlC9AUfvKOZ3rX+PTeb9cC15R0hFqj3?=
 =?us-ascii?Q?QVlApBCIBCUP2BGlPNbKvWPFp6G7V9jk0EHB3ZsuYy3a+7GJ8Q5vr5P1GkFN?=
 =?us-ascii?Q?Ooqidjwjtm97xrgRlwI1j3AEZtImKeTTCM/FCUJzJ10x8ZEKorJWPmVG6STe?=
 =?us-ascii?Q?u+tf0H2xGuHRGfa5XHeee58WJjWN+C9PaEVOy6DKViMI+K7DW5cNo65EOP8n?=
 =?us-ascii?Q?U4mteCgd9WNDzJ8U3DjDY7741TrC0Gi4WNQK0GdDLXhgzjnhZMphCyNSOYkE?=
 =?us-ascii?Q?SeQj4BrsBqTEisourm3Nf694CQJL8GgMil4goaqOrf+0a96JAtKTl2VgHUGQ?=
 =?us-ascii?Q?Rd4sYEXO+VoS+4qNISt6nHtR1Z7+tj9w8PRbUOu+by6ZpSG7v/xOCIX2GTN/?=
 =?us-ascii?Q?W0h3urSOH3MsnjchtxpY7ekc0J5WS7jRD6oL7TLxgDm4xcFd2CUqgoV3dSz6?=
 =?us-ascii?Q?WWzWY/ZhI4AQoAEPzFvBTIObx3p96+ZFsZqEx1Hd93BRjBVlf/QYxReP+fKZ?=
 =?us-ascii?Q?7Sz8XDW9ww4DqMlMBJGF1kXe0iEmf1FTVQ4W4SKy/X1RqlyP6l0NmHx1UzPp?=
 =?us-ascii?Q?N9HgQgGYAhwTi+5fMRVA46ZhDf2TfzDUtT86KzSRaDjwdFCzjbOyWrBrqt3F?=
 =?us-ascii?Q?v+VnTWQrBPDny/pRr5qvPFuekpYfu/teuiRiGVONjO4QaS1abf9w8Y4uPmKZ?=
 =?us-ascii?Q?Yuo4klYo9nqCrw40Y80AhbZNQ7SJ60/btJ7yS5uH7laZqypMbffeYYWLWmoJ?=
 =?us-ascii?Q?X3+8NnJlkxvo+JCldrHW0CSglmQHTIrxciOrgk7LfriqSYppH1U3FrFg9HdC?=
 =?us-ascii?Q?sKXrVyWX2Zd31qOOCTxAKfFrcB/dKyPNvDwm2PJ3Vh6MFdo9pEiq5w0Ypino?=
 =?us-ascii?Q?qtrWlGSHmFmFSYj5Cu2/Tmp6MXQ2Q3iA+B9OSt8LCbdMX6w35CVI9fPkluNh?=
 =?us-ascii?Q?LjK+O8AO3dU4xNNEdSxEJW+6smFzUGp5sJ77xcKPzOqf4rc2BwomPcBO3wca?=
 =?us-ascii?Q?bp1peVuPDME=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Mpv7KamN2euzudnwsqsI+jFV2e7lUffC+17j+Co0LkVnsdM03glaWmQWuKZ9?=
 =?us-ascii?Q?wn/s36YVCdsQww5VhYUIahMXv8eGRmCzBawzmcVB0VjTNja64uaZgGbO9h7F?=
 =?us-ascii?Q?ID0vifbH335s/MyGY2YCMG0a8CHR1uGpifcznkyx0akYEdkXH/OtuyJweFCR?=
 =?us-ascii?Q?rEKrdX2C6o3mSVG7SUjNl8J/UuTPmX+OLjYqIgfKVdWwzKESr9QOUF0qJFwW?=
 =?us-ascii?Q?a37MHiCPVQEXOX9XM0JwLJiIOWU83/ZLUvk78WP22WlfTMKYURsxa0cw98Aj?=
 =?us-ascii?Q?i4aMVyEndEGK4Sq3NPKg4eG1+ic01KTQ3Epmi5ZKoHzHwT4EKHWUVsnqlwmG?=
 =?us-ascii?Q?2EGJzkVnA9TSDVxTmCMnCuLe0xlTz1l4oXUqUKVIXljq8c78lYwzhoYQMghX?=
 =?us-ascii?Q?wJctscVvDqSaSFsUbH6HDWjwbSEPE2+L7rIkyKWkdO1AH2IarP0kP9YyUmTy?=
 =?us-ascii?Q?wyfTiIOZmbekKFm7VSfskJoJqZBbPV5eqK1j1DRAw40x4YoFLxN4EqZXHM2n?=
 =?us-ascii?Q?Gg2zW4dHStTQnQILrpZwDDWHSDFO31DaN3U9ej0Gk5p8h4f73G1Bch5Su6YA?=
 =?us-ascii?Q?wfI2R5PROFTXsqbD2gVTauFTRDb72H6gH9QOUruOBjdby6BDf6qKHUDrL+eA?=
 =?us-ascii?Q?9F9RgeaORhYmElTZT37caSIPem0wTRPVJL2jJeGgaM3EMMEUmFkbArWmCF4K?=
 =?us-ascii?Q?9VDl9ECpsmGCIzG+vuVnbJ3TDMVgatO5n3VktXw7iV4r6Q+xa3oO5VpPZ8us?=
 =?us-ascii?Q?qEdtL5cMtD2QUSujkQWZx6jz3Utuzn6amph4sENV/x94DN1kUB7cbvVJCsFU?=
 =?us-ascii?Q?Ss5Qc19xDTsebd5H7H1qo7pmhPw8vcWoBnG4SzJ91fDdHIqTdUW3zZnw7EDh?=
 =?us-ascii?Q?JWz+gSFevVgcNKdaGryHqCeCErQtcHW6RlE7H1fj4N4P7iQmZlOKyjWXgui6?=
 =?us-ascii?Q?BqjLP+rxMKzdO7169s+MTs3gMfw5q0AiOEPbXeoy2Si05qKdiWwEKLW5RwXT?=
 =?us-ascii?Q?hTkLs4wPIhjjqWd9wm11vBZB3GKLs9ELzE99aqj8IukQye34Ykrzr7WdcSkf?=
 =?us-ascii?Q?3hOKKaHkr/XIuakmAeWkC8zXsE3h3XknEZVSZ0iEYrd5mstmT+hU/KOXXSrj?=
 =?us-ascii?Q?AnTCV+up7OYjUFvIcaBi2+8+tkurWKGdjiksw7c43bAvO9TUOBIPngOqmlDn?=
 =?us-ascii?Q?fP8L7vN0UzQAkeMca0210KiIq6ANAFks1Dja732Z0LrZdnkxleYnzZMJaZdY?=
 =?us-ascii?Q?R2u3FqDm0ydturng4tKY2wFc5q1CPKnWg6AauGTWnqZbPYV+kQdHgR7NQqLt?=
 =?us-ascii?Q?sYlvbG2stBZNdKqTjcC9DnIp32zGdpbiIFEgbikLLsR/xhlfSiUhpYLqG6AY?=
 =?us-ascii?Q?ZJ6GFZBcooHMTEtI4zjcXW/H91N9ETjnYumM/NbFLkx5OZN7VGK1pzfj4xFd?=
 =?us-ascii?Q?FASQ9cE4TAbN1XLdg6S4z3oEvMEvdVTV2ZFNLWS4Yk40zGo7z2IF2uQwlwvL?=
 =?us-ascii?Q?dVV5JbVMhLGQIArR56HsX8Vh49fUbl3biW7egidCH9zPxBgSwevZJNTLQm0h?=
 =?us-ascii?Q?O0KdinKEK+AdcZiGQKo54tPCDWrqUXtMg8WWIueAVpWUH8VUXlA8k7WFV350?=
 =?us-ascii?Q?3w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: xiNyBB1J0z5xUbQy9XkvopyZdYswxe/TQmf1Hkv9Kfi/jBtjgfB9QOAnnV3TT+VOzDUuLKtlMhBqUdB9y/ICigN8XNxxrfD7IDgBfZTiB4kuzpGkkWL95kJfqYYpi87tA44WNsqMxD1Mg3P5myD43oWfjMKQ6aKCNudg10rOOICUj/MB6Z9PPc2C/yzaiF8wt0odDrN1dGr0A8WkOQpUsUl5w1neUyjnCgXxBe03k+aNsvRIjloo9GdE5+MlwTeKOe2iETP2059Lw5grbY+QmaLnQN3waG5eihCa5hckFpO/KZ40ic4qj5uWFCzKzLBei5xIYD8jFbBAToMSiIosIFddFYaHE7miwoNbfnq6b96UfylIHmP7JZ9rRFpcyx1NefZa67srDOeZSKNuYBM8u9T3/9pdmEuyGZ2Iuh5WWILZxEL2l/Ceyv8Lb9/f1PdarnM/SYYVlbaTqRBME1gYpqTTueR5pr9cn5ywpNrFj6B2r4Fy1PGoTmvNGWB8OS33aU461FLv1ldYPMcRVWeUx2VxgJk0CHIO0gbK6EejzNW8Q51Kgc1Phk0332unT2wXGN3DWR+83AlJdEUuAvvFe8s9YT6yN6aThsyt9cxVMbc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 5beafdb5-1229-4ba6-3685-08dde649b710
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 15:44:03.6737
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7qXj3HFkZC0Kdr49tSPAIQhX1KfgoXA4Rv10qHeeGHODwjzf9h0dnFbJz6t2lv9J5j9vBl3ShVplxPDk/fyOp8rCSKRwle136jMNeU+JWVQ=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR10MB5921
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 bulkscore=0
 adultscore=0 mlxlogscore=999 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280131
X-Proofpoint-ORIG-GUID: ZKcug2oQWMc6riyba7y5ksFYFxG79tb8
X-Proofpoint-GUID: ZKcug2oQWMc6riyba7y5ksFYFxG79tb8
X-Authority-Analysis: v=2.4 cv=EcXIQOmC c=1 sm=1 tr=0 ts=68b0794c b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8
 a=pe3YOxSbL00LKGLRwgEA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12069
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzMCBTYWx0ZWRfXwiWT+jBmSg5s
 yG1FLG0EqGDoZk41PBHqlZntnLzC1V1QpSDMRm5TYFVpvxhSiqhBgXfGA+fTbhdXfmY+1+CAsW7
 MhAsGYPEtkCeVnwkaFSGSptaElI1HVD2Pyi5aLA/0ft+7ZesZ+42IzFnVV6ZVoVYZodZ+QnviM+
 ZnJvMftHAW2FJJV3MCVN6dmvsrao5ilQyR1FJduEMp/wlqz+xzgGb0cYx/TtvdWcYgvNGvV7YjA
 40GoJ8od19RGsZLyK6gcjEeRF93BNrDvk0Rnum5qG51uzu2xszMOYc31gdsiql9TqdVV+8P5U0N
 2c3LK9S0kdJREsQRQs1gFMqmZVY/K4SWoB64BeXDM3syh0QYjZRJhj60btIV0hlzrWUs6A2VNyI
 d5SvJiAnIWhJWogr0mmCjz4Gcq6DAg==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=TJ1nvdR8;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=VMNn8kP+;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:18AM +0200, David Hildenbrand wrote:
> We're allocating a higher-order page from the buddy. For these pages
> (that are guaranteed to not exceed a single memory section) there is no
> need to use nth_page().
>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Oh hello! Now it all comes together :)

nth_tag():

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  mm/percpu-km.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/percpu-km.c b/mm/percpu-km.c
> index fe31aa19db81a..4efa74a495cb6 100644
> --- a/mm/percpu-km.c
> +++ b/mm/percpu-km.c
> @@ -69,7 +69,7 @@ static struct pcpu_chunk *pcpu_create_chunk(gfp_t gfp)
>  	}
>
>  	for (i = 0; i < nr_pages; i++)
> -		pcpu_set_page_chunk(nth_page(pages, i), chunk);
> +		pcpu_set_page_chunk(pages + i, chunk);
>
>  	chunk->data = pages;
>  	chunk->base_addr = page_address(pages);
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2ee63b0d-f5d8-41ee-ae7a-0e917638cebc%40lucifer.local.
