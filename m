Return-Path: <kasan-dev+bncBD6LBUWO5UMBBKMEYLCQMGQETGPX5XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id EA96BB3A60F
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 18:22:02 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3ed0ba44c87sf13536595ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:22:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756398121; cv=pass;
        d=google.com; s=arc-20240605;
        b=ClfYNzrXBsvgPiC1cDwesGUvQt5C6ITvO5XqYZogXmHdk82gHgwtq1OdZX3wycmMLm
         ovEXxO+EOgQ1KgsHB5qnTvlwc0e23swUFO2NB+ggI7t1q3S2XDIwGJaGuEd8YyaPtlQv
         BhOATfdzSw6BCaVHFtxXeH/NDwu/In35tR9AZNJ/SiNVBpO2ThyhxmrGZkeznRh3IWN8
         C2mfyKRIU33RRXsKTULpu7Y1K2xGFAkiNqeZnRamDTtMeGhhEWEad7fhXr5FZevIlNqf
         aVpFoM5n0+YtfCSGcSVQ6CZ/dneCg3p/HUH6FCYbLG835N8b82ovR120DFHoht0R5Iae
         YleQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=WccVkqOvAKa9mlNCy3c2UaeyorKzhvcffAAFDgrQ50s=;
        fh=xdEGDnKbD2hpECv6d9pBxZ0UwYmRmj/spq3xnKQqFfM=;
        b=OAxl2w0nL156pPOI2c7oQzuiBoGTfvPbdC3CXUWzjjVOcgeAGikxmpIZnZzHaoYGZq
         AKVotWsdz8yy0fAcwcInZ/W+xUoZU9ktt3HkBEmYH0/cwTUZ4eoDjJ8It4icg1/qncJ4
         sEj+W69A7XsDJBt1an8sEkzbByJnSZlHpSxJE5LlnY2G9gLifwOudFElLTnHVjZBMXFc
         vXVK+b9JnDhZG5h2rAB7QmAdPNXpNg8bapkw0uel9Q3qhUpr4zAGd0xvMbdzXnDVpgVQ
         Ax4oySEb5qCYJO/w6twmNay3d6TTOXnW/LCwaS00cYV61z4F8Dzjqsz9AKkASMt3BVi+
         eG7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=RGJvCfWX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=U1twOUUr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756398121; x=1757002921; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=WccVkqOvAKa9mlNCy3c2UaeyorKzhvcffAAFDgrQ50s=;
        b=vmlsu62Dpvwt/7/IAXSTol8vO6anRmG/g6b795FjaeKayrcHfV0FMsWJqoAtlcG0PC
         RgXDKcUoGFymY7LC2lgzNtO1o4DYTPJFBFSaHo1SkNFUzI+6Kf3X00HbX+bUaSxFZqwa
         spWK4wk040Jka30xM/vQrBDeXlOln8a1n250Yr3v2T971DT0TRleaVpnWyDklOfutYmU
         K1lthwF8SJyxH4w7MQ/ZfXiKXPTF+HPuhbgLvhb4eKntjANwNtqxvTGAB+RlNPI9/w88
         pDPDnoptFN96tOIsjofLLCS5cTZm0dwpwA6aFX89zZSRWRKEYMUol1dmdzweEQEFd6zx
         krCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756398121; x=1757002921;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WccVkqOvAKa9mlNCy3c2UaeyorKzhvcffAAFDgrQ50s=;
        b=XGwFXQGnxILl3jQBmj/sWl+4YRfrV67Hv1hDCGZbR5vI1zQSR/RsJwBgpCm4wh7XAu
         Q7eb5zUNiRYiB5O6Xlt3xRgZJsDAstIRxdoG6qJYlKtUvpCrRpQLTcVPxROK9g/sIfWK
         sY/JtNtU4FN6ADOVbpk3Rlj87vXnHGMCEiSdU/w/Ui+A22qXndRXLaLSWuXOct9yqDcQ
         M/adl/STXUOyEtjMAtEHiOLXlezDtzE9l/Sqm482Bi8VmoBnysPx/vpErlEgOb6jPuU1
         QlHDMehV9Bz6GrLMNE7txq4ARyYLleUjJaDoOVBn1DKy+Oif2Z+wjjQ9RvhFpWxcYuAL
         cj/Q==
X-Forwarded-Encrypted: i=3; AJvYcCXQM1wW+LkNpsqltcgAX4+ruDTCgLchTPZ7aNEu+4s9mAHf8keiiZcPmE8fva2eJl31iPl5WA==@lfdr.de
X-Gm-Message-State: AOJu0Yzisko3TZYxE2nziYjrnQYV6vuCqr0Vg9wk5ykw16MpKSQ5gTuR
	V/9QTJcPhRnXoPK4727w6JP4020FQvj+B5LzEr1PNqt+7e1Icvu4irHS
X-Google-Smtp-Source: AGHT+IH7uJi/ceB/0iCRGpy6oPQO5/WYy4r9KFs61emc07ctyIt+rauBRGS69Y5q/9NiPya6FhCp+w==
X-Received: by 2002:a05:6e02:1807:b0:3e9:e1fd:2fa with SMTP id e9e14a558f8ab-3e9e1fd23efmr306544315ab.30.1756398121523;
        Thu, 28 Aug 2025 09:22:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfaycaxtIZfIf1B84dMbMYCZujFYnSmDmBHuyMsSldEjg==
Received: by 2002:a05:6e02:178b:b0:3e3:e743:1e41 with SMTP id
 e9e14a558f8ab-3f13b55828bls6654825ab.1.-pod-prod-04-us; Thu, 28 Aug 2025
 09:22:00 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX7bnYVA06r0WKUeAD/Cq0Qv1AMgL2rqZP75aA83Q133wnwyi5uBT+UWL6ilNR3ClNgebaV6ySYP5s=@googlegroups.com
X-Received: by 2002:a92:cd8c:0:b0:3f1:940:e816 with SMTP id e9e14a558f8ab-3f10940e872mr48827445ab.19.1756398120457;
        Thu, 28 Aug 2025 09:22:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756398120; cv=pass;
        d=google.com; s=arc-20240605;
        b=J21n/yJ4AW8x+TQx9gsH3B7cUa5nPASHD+yZl0hJAh7jFGy6xx5y+qWETEm1PiFDxp
         cevDvqC1LL99jj7n7eyH0HNR1ptHwF6P91lJsXtGUFqI/zks/Lf5RbQp43G+BNHyLRlz
         UvivdZsvHbYAhRWruhtp2fOCUdxETJyX/lMIzM4wpAupHT6vGrMCtCC++9He1I7O8+P3
         I1hw3TLYQcgCpmyMgLKvP+xpGtlZ4au4Psvv10xSKhP8LZ4v5+zVieBnjusjoE6kl0v0
         PAnmY9DiGDUbwB7Nqo1wlTGxveYfVaRlRhWyb4tmNbAKg84oxBSsMLi9YGrl7akbGzys
         eRpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=OdTdsFkHbUV7+9trQVtbV9b2PjFVec2Ez22V6EsyjKg=;
        fh=nDVLMfpnt16dAvQHlJ/+ZWR3WaZCA+P2x3XNdYCnLhM=;
        b=AJbqRgO9+gWvF5zmf52xBrOcuy4NWi+05+9ynq/+PZzb3Ndg6j78/DWBAiKpJGLF42
         4q4tNWds4cbIAyUxKnkHPq0mrT7OALfxmZRWVJGnpTP3qID6SchnVZVTJr5xJgCcnJL3
         A1N1pjJou2Xa2vMMpKnzjL+OKb/Y2BzFMdr7v9a+Sn2HatD/K0/2CPOKlNLjFwFsMdMi
         ZJxAIDAODb3zoBNcjW9rjBG7WO0nKCK8k5ag5tOkmmMchqGqceK4zlyQUP181stz9OF0
         pXjZy57dbz1ZWc+CVySXQqfDlAdwvYzTc7y9diF34B8/8QbNFJ6QfQ4KqNWIjYPTGxDi
         dmmQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=RGJvCfWX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=U1twOUUr;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3f1c6247453si608565ab.1.2025.08.28.09.22.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 09:22:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SEN13r014256;
	Thu, 28 Aug 2025 16:21:49 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q6790wbh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 16:21:48 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SEjLM9004951;
	Thu, 28 Aug 2025 16:21:48 GMT
Received: from nam12-dm6-obe.outbound.protection.outlook.com (mail-dm6nam12on2042.outbound.protection.outlook.com [40.107.243.42])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c7db2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 16:21:48 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=HuHGUNb8BH/LuBb0Tu55iEsu8066F8qC10o4GpTzmyBY4qLZgU4qBWvgqGAO+1a1z/FQoHPDS8hazXg3NX4DOCRJkeA7jJGj7xiVVtC7QFhRRrtxu0SpTgjhodRInUJydrRwIiGeKvJtxnqUZjKkXs42vNLmq8b9k39/SsezTwbmDHmr6mCQ/s3x3Yp7jV/ToRRn7Lx/s0V6jfOPvu1UCPwrPRY4uAQ4uXfqlE0uem7GXxNS20WJJpEoQRxr+4xVy3swulJj3Rcf8EXK4sqCtIoesn3+9BoXAefJJ8cXDNzDZGJg+6mxo9BC5kcuKeEq+eWCUyGDdxF9vE62HgQTaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=OdTdsFkHbUV7+9trQVtbV9b2PjFVec2Ez22V6EsyjKg=;
 b=tYYdfrUd2Kdr5UpjGTgmc252AMMUP6qFotVmHNbQqzxxlQbvjiI6gDgYXBJbMzV1LFk/m1FgPuMD6NXBTq4xtshe5Uj7sgalrr/TuFZMrOFRyyl2NRacOKpEitCVCgzn5YHwmyHsl1XmQDY2kb2h/25CkMZBxn33erEZjrO+246x8cVRD1PnjhV/tpEzhPYd/4HpOb3PPgDTNQg7tP9Yf8Src46iymTyX0nFZWmuGl/yX5/ln9raFDvFrLBSaAhy/3VouR8zpvJcVGXmTrj3wQRiOLmxNgoaANsx6nHNHDXqF8lJOLTIm1Wv4KEaj2keuUacLgkj67fW7HHrRhDAkw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by IA0PR10MB7372.namprd10.prod.outlook.com (2603:10b6:208:40f::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.16; Thu, 28 Aug
 2025 16:21:38 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 16:21:38 +0000
Date: Thu, 28 Aug 2025 17:21:30 +0100
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
Subject: Re: [PATCH v1 17/36] mm/pagewalk: drop nth_page() usage within folio
 in folio_walk_start()
Message-ID: <8842cba4-61bc-48e2-b4aa-df9619409621@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-18-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-18-david@redhat.com>
X-ClientProxiedBy: LO4P265CA0023.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2ae::13) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|IA0PR10MB7372:EE_
X-MS-Office365-Filtering-Correlation-Id: abc464aa-e75c-4474-95b2-08dde64ef74a
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?HfWrRdd1CqYOu/qDFpChE0WmCw6z2svePL7vFpdOEzKeNjawnNTOeu/bUeA4?=
 =?us-ascii?Q?1h3m+AR9bsD2kP2d+vTma8jdI16IQtaG+GzmLK568qb+5aGdFii4VwAvIZpN?=
 =?us-ascii?Q?1LEXKyKoMqQzNqQordIyvXjD5DrsLnClSmWAz+iQFD9AcYFkfBytVQKzFhGc?=
 =?us-ascii?Q?HZJu0YPIxzkHh9hutpVFe1VjmmYXQXYxT7vKWUG6bO+JTP7xpqVr1FwRuHwq?=
 =?us-ascii?Q?OrnQ5aRM+Wc/9zA0rMkWEsXaYHKmRsastavjcG86plRb4x51SwskTQ54Qhvq?=
 =?us-ascii?Q?EbqBTVSi5Yuhv5d0CxPCJY/1N9VkjsfhoBDUq1HuCTXG/lqXM/q2Hl4CrrAn?=
 =?us-ascii?Q?TdvMyqkIYlnrlAYLKEqdv+ZEAJKzHg48OpHwGGmCgHcq1GwQKGXnU6OzENem?=
 =?us-ascii?Q?eq8U65WKkvIzuRS4SdOVoi4q0aeoG9drPJxp4a5RKbA86e46uxNKvW0SKIRD?=
 =?us-ascii?Q?hSQ3VObkZEULcCAXO2DX+HFLg9U+aWl2OsPyMIAMdeF9BLOmpar04y0EiYcZ?=
 =?us-ascii?Q?iFVtigAOQB5WrIZXZ+pVE1Y/iWAc6nh/pJOurc2GieJJdcAftm8cI6DLgevC?=
 =?us-ascii?Q?ZVl966WVjXk81AvoDev7dThlL7jbidhnvVJ3rgWmG+8eLlR6Ig6J6l62lE9F?=
 =?us-ascii?Q?lOg9xhr/py/ZTVRehO1sgO479S9rnEyASe2mw7grJZ9xb0rpzcWcCO/xUmwM?=
 =?us-ascii?Q?i2JpgbNtL/KeMR8NWlVcxVBJjh7ipFNGj3UepxIPet2Yl6Ml8YX5POQ5YEUT?=
 =?us-ascii?Q?DaDVVA9t+d9zMyfSiZLzWrncLBdJSrQnxQoSVAbxjFIyNS2NzG2tQc6aL0xT?=
 =?us-ascii?Q?jNsUhNg13Zxx1MleTG+e/c61uEUqeMmCVkp3k7oFzExxz8yII9gXtHlC1BVx?=
 =?us-ascii?Q?UJtAuqX9spZX8UUwDABLOSWmhIyTVe3cDQWP5UinhR/kv2RljK8hkRwgzv4r?=
 =?us-ascii?Q?l/wu+pOXhaX6cw+qWEmwpCmPiQ+vWlrYHJQ3wWBDKekELMLSb3D8HI7EeJnf?=
 =?us-ascii?Q?IK7yktFy4UH3a6mrhNBDT7vb+PfRprAhTySIi7tOzrpu5/mZFAjOgUmJY7PJ?=
 =?us-ascii?Q?xn07yEfqBeebx7dHP6Ep2JXspl9A9BMtxM9QKhSnbcYP5oZLDzmeQdPeVLTu?=
 =?us-ascii?Q?n6epfgxlaWcoC3ld84rm0sve+TO1auhjLm5TIkOFMCpigXUWNwH97e1kt4VS?=
 =?us-ascii?Q?QQKNbFUP/Lkj/2fooAaO08Q1plLMPXw6NZYtQpJKPR5N2lwKLwpdf/1mKdZs?=
 =?us-ascii?Q?v0IhnkySphfT2tXZRkWGzgGejtWDn1xS1GkcfyDd3KeIF54sRLVfdx9qfKfb?=
 =?us-ascii?Q?lA5DRb5NaLPVmAKSIa38pQ+ZcvnYolijTt70aa5BWopXAfmNkPmMZ9QnJbnI?=
 =?us-ascii?Q?elaWErHhrtVPFATGN5jNuxyLFsXz3Ni1D5lO1kLMZu6bdX3M/A=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?L47MOAazcVX70WWUjCeX4s5p4e3YQ1OCDlLKxFYwPq66vgAF2lgj5BMqz3nF?=
 =?us-ascii?Q?8STW24wQZJSQxMi47GId2NIiuCbtEGWNx2cvGAclUz+vtFnAVhh/yzBkc6BI?=
 =?us-ascii?Q?7JBvGsxiN/8My7alUi/3u7STV9mro5LlRLTvfbRHw87mtGili9/M4NapPMiM?=
 =?us-ascii?Q?6+t1nderDYJofrXI7w/8x3TLcsrC75YSVnU3DxE3iuWDwVKGXcmhCQxrn2Bu?=
 =?us-ascii?Q?BwxQNl6QFTjoMVqcW763UiMdAYSl2QurewM7Ot7GS9qyRbsD03PPcTHfxU+X?=
 =?us-ascii?Q?hulnvY6XqytFzIkqY9JnT0oXdH0bvUGNJwmlnHtn6vnbIm0kSTdRoGTmv/du?=
 =?us-ascii?Q?Te+g0lSjsxGo7K7H8qdcTSN17IMEVCkqo4LAGIZKsR7wSKa7suEgyLqHNMZx?=
 =?us-ascii?Q?G55BNlB0BKSo4sj82NqmLt8GV/wXkTA+i9dwRglRZX0IXfhHrQIzhm7dSgiK?=
 =?us-ascii?Q?TiB7e89TtrRuxQEEryw6R6NffvCeE0yXN/FHAQ9g/0BNsYQq1htouPZb/3jf?=
 =?us-ascii?Q?XMW5y4bKx4l5TecbufJ2wM/Salns3rMXMMU25txGidsbK5By21BT9bRtmN/v?=
 =?us-ascii?Q?vfyC6CHkVgpB41Jps0Gguj8AliMPt98lsCN9WlCjYzu90APkU01I+6JLH0vU?=
 =?us-ascii?Q?A0MoNWu5ko8Z1c8JoXmBhtMOssuIfwG41H4m2Rtda/s6Innjg8Rtiqp8rkrG?=
 =?us-ascii?Q?RwJ2S+UPy+67LmvVlk3bSqTnSPjdPSUrGAu6VG+yn+NX9ZXA2KlrgJbKn56G?=
 =?us-ascii?Q?/LxmoNrvZ9Gg+ugCvclFn/fNN6Ssk1iqt6Deux2ekkey6/R7WA3L3qVsbhef?=
 =?us-ascii?Q?I0Hmq3F5lo5zvsGDjjMZ5IXNTQKS6bgL+bK09xdn6WRlznOaum9O7GbVSKgQ?=
 =?us-ascii?Q?ml5DNkWed854YSvDbBsM/Pc5gqYZlxRxG6iBO8Xxn6Bpk8zHca+3Z6F6D5P8?=
 =?us-ascii?Q?UsjoxNQPH8MJGMHFs8wzEPrlJAKp2ADB8u7WgFenOicOqc1C0y7UTIgV/9fo?=
 =?us-ascii?Q?Ss47MoyrOKHVH5QXGJRnAV+2wVks9wBBenuUuHvTFCoLeslfB8VP+sOfTIH2?=
 =?us-ascii?Q?gSC4IqCmtPQBg8MjxmobLxI1FYDJfBDrLGebeYjZ+YQrdOxQ5KiM+kpGyKXM?=
 =?us-ascii?Q?Nn/WfkCefQk4P6zhTOxKSY42AYzZK51iGkQMLSFcXSmZpR3voRsRgtbSuJRO?=
 =?us-ascii?Q?jdqXBZYF6klO0zsp6WbAZ0bUxPd/ID7hlgmQK37Sd4oN4OJXIBW/RaZMT32e?=
 =?us-ascii?Q?MyBN7w3jL+lKyZWpbCN24PKBIuN91i0z0MGTXFyAKIa0KVIrqvpV/QyrFdR3?=
 =?us-ascii?Q?QW8KxNfmu06aXKk/N/gZ6OquCWHPYm32zu+v6AvwdTCbuQY4DM00WSCQCDC+?=
 =?us-ascii?Q?4N6IPxGeoSjEqsgpWSLv+SdJITJHKq5sRdFqrxMtWj92eEUIHI6VlEIYjy6c?=
 =?us-ascii?Q?UZ3c60E/58hCtAvb1umN9oEdFWiEEBBrlOqKZbMxI7ltMrUcImBfFCueweOU?=
 =?us-ascii?Q?l5oaQHw+nC+F/YiGqp/BjnHXxJPwp/VeH/nHSOFAzfmc906NwoQqXjZceuPu?=
 =?us-ascii?Q?g995UV51f2H01wafUveJ3KiH0GRsTAcHvXyMclnPIRLYCDnK2rw4lIYZfBAB?=
 =?us-ascii?Q?Dw=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: ew99gn1WdwPbnoK1udmct3oblOjANg9pafYecPxlE5VInRD2krIiLcHEWhx/eYg75NxE2715CkIZqIE7vIjGOiRNMwCxfsIW6bXLeMu7JPzSNzaVOM1/Q05o9qnkwYXv4pnJwq5OjMRPQJgsV45eq+GN6JRK7IZfCCLbIYxE54kvTAaTYy2PTofLf3NbHXtBpxBi+nC/DQU4J+VpJy21n7eHu8Wjnih5onw1pHwZAKq3krB569COKoUlb2kbi5VGihkgyVLJPcwBOg7Pzr9b/hbEi0HUfmC2liY6BCUS1StdzNOhCM0jyk4YoP17GTEIaYpzcqKdCvn3c+LyDzX5Ry4k6s4+sPyeGxjVW/ORxyXFppp3xVrGdFAuTR6tsRssTbu8vOyNp2w40psziSWZiFkE3L6XUy1LR7xy9NMknijSxSHXAYatKB82WIkVoptBuThIo8bQs5C57iYS2Oc6kwrbPK6OjfJpaVLILMMYMTKDRGkf9KrmP8LWl9OHyoFxeraUl2ONPYfTyDMub9a8/RiYcRqcHBvQqOjW/RgfLsIdp+KVGunD9MXoWqBJX+9HP/WUJ9RjrTaQP6JMC63KYmKqSLLO6/OPzi9Qmw+BYy4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: abc464aa-e75c-4474-95b2-08dde64ef74a
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 16:21:38.7821
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Gh8tGmVeoAEfgeWR7dDuySrAZbX8nFmwNaAZpdZnvR6jYcPxuT/nVuNMYc/FP2IU3JxBzJunKcnFCYMNwvYb9SU+KM5LTv20vMVCdo5rcSk=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA0PR10MB7372
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=999 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508280136
X-Proofpoint-GUID: pyUcS4ZRZQKUcyhPGSEGAls5EjugG-im
X-Proofpoint-ORIG-GUID: pyUcS4ZRZQKUcyhPGSEGAls5EjugG-im
X-Authority-Analysis: v=2.4 cv=NrLRc9dJ c=1 sm=1 tr=0 ts=68b0821d b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8
 a=2vgbkF3zGvRlf_4PNCAA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzNSBTYWx0ZWRfX1Qe/FD8t6/Yq
 p0tYRnhJDxTjyqvqPJ8p8yHiVG+qh9g9pscLs12/95zl8ZSZDDQtufYxJNq3I9/X49HkRsCSboo
 fid+/zf6QcVOzuyZksRhRK/4yTW0l3uPjvt7wIkXozptbdFH7EB+Pzv7wklEUOZ/50gGol4lcQH
 3ure9dRv44YJcd8qpEbFbzSrZoAXVDr8nMlKpuBUpMubRSBigLntI4n8DRNghU4AaEGfm93CAJw
 F9vBlnQR+9eRkihAHbO9aUYNLmyd5AM6R9N4G526ZZ8+miL0KAJg2OLQr3JVoYthdtLUQWLaUMO
 dwkRMjkKk6AhgHjOjZqsuYfonMf8kqWIwYz+24tVeQEcBpeflApnbp7EpGHqWGKhcSBhVDWy4JZ
 4TRZTTij
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=RGJvCfWX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=U1twOUUr;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
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

On Thu, Aug 28, 2025 at 12:01:21AM +0200, David Hildenbrand wrote:
> It's no longer required to use nth_page() within a folio, so let's just
> drop the nth_page() in folio_walk_start().
>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  mm/pagewalk.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/pagewalk.c b/mm/pagewalk.c
> index c6753d370ff4e..9e4225e5fcf5c 100644
> --- a/mm/pagewalk.c
> +++ b/mm/pagewalk.c
> @@ -1004,7 +1004,7 @@ struct folio *folio_walk_start(struct folio_walk *fw,
>  found:
>  	if (expose_page)
>  		/* Note: Offset from the mapped page, not the folio start. */
> -		fw->page = nth_page(page, (addr & (entry_size - 1)) >> PAGE_SHIFT);
> +		fw->page = page + ((addr & (entry_size - 1)) >> PAGE_SHIFT);

Be nice to clean this horrid one liner up a bit also but that's out of
scope here :)

>  	else
>  		fw->page = NULL;
>  	fw->ptl = ptl;
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8842cba4-61bc-48e2-b4aa-df9619409621%40lucifer.local.
