Return-Path: <kasan-dev+bncBD6LBUWO5UMBB65SYLCQMGQEBLGHLLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 69DD5B3A942
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 20:01:33 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-70ddadde46bsf26316296d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 11:01:33 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756404092; cv=pass;
        d=google.com; s=arc-20240605;
        b=a28FA7gx+GELAXfH7DUuhh6Eu9EDQ3SxT20987dOiJ8DAZTeGFXuAqqHoXKX+iYJe9
         rRIa7iMjH9Pfzn5SWY2mYbrV+dThW0hjZKUlbB6QEfGnThAd5qlS1rVMS1h4z+mLasFe
         mVYYp+FFL1RJ12qQmJRrIOSPGXJ+jTAmMQzJfib5QlCEqPFwUGtB/9d83+Emrz2PWikO
         D9gqvlXjFw3BZ0cC3g3naDtNtyLCaE6m7onG5se0p3oiCEeLPGQLCBAErscx/WIdEStm
         Kl1s3Ydnl1gWXx3tsvePmSzT6lt5i1ek8GdBn0f2Wa6URonv5C/Ck+ILKpYAVjKE5apN
         o8gQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=jb3aFeKdkgKzpx5hwqOcOQfdNqP664w50gbQfv6QaWo=;
        fh=WVayYD0GVb4CkOvPWxEkSlY1lvAsO+jyWKiDlI8OE0I=;
        b=Hvx1zYgInm+u1KOATyMChgtiKoQaBOvEAyGzd1u6w+U1Har6kzVnCPiB1OBGLW6+aY
         4JTRtfaOxjeHiIxcML+BkQMbqouvFACoDVKyViVepSpSjTX6aS71gPgA2fc8oP1gVl44
         vDfsdEF1CZOLiA1jcr52X8/lcditkvOiGRn93vySmj0oXnT/sZlaccaU2FuImikVQZ4X
         VR4DZBYV+SmXIOChxVauOs8mGYrTDaKe+F1P7KbiY2UTlPmMzVczztoM5h6lbLoSjgLy
         luolUfxm6wtjuElAEdeXGucTfjnCqFd7y0MJB+mE3IeB619Z1LuywEt+VuQamtp5p5wx
         gNdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=lAXURZg7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=B4lZvvm6;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756404092; x=1757008892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=jb3aFeKdkgKzpx5hwqOcOQfdNqP664w50gbQfv6QaWo=;
        b=xQ94OC8YO0dnyguZyYMsuMvDoYW40OgzRIh50OAicVmUciZiPA3BA/ylC6LIzHQJe5
         EyHyBWeKonQpvMuDr1J4n9+3euWLWrfAc1z/ZyRfl+4SS8+MrlNF6HB9OOD+1XJ0RnGi
         0jbfAWZYSqSqQh35ABLyHr33ayRAYB7d2nB2+v+ikHfpmXUTdTNCYXirrELR6inHOVhE
         efMCtTOM+AEB/SLGqZgc/KNEroTOE/779XziU5euETBXIQx9zn8EFnxntRhWLUQI/ZmQ
         xyC2XJx9Ek8LRwg26/Wf7nuM9FRe2hW15eFDjsi/xai0MgwZI9ERfiw7PPm9BVj2Xxrc
         HX/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756404092; x=1757008892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jb3aFeKdkgKzpx5hwqOcOQfdNqP664w50gbQfv6QaWo=;
        b=gvl7JMs6wLF6MNze87X6yIcOdLfy0g6W46dqRRjT6QfN/+VS61zFSiYqzcFQLOTNZi
         GXuSJtyLXhhjxhQ+pDdSrlBsH6YFH1OhJ+2R9702csz7G1nNFCyTcpQ3xzhp/M/bIFyl
         LbwQJt6YY9kwEbXYoIdy5hcooZT3HyxyH5b1B+Fu9/Uk0NTgyu9TprYAAzPuJ/8CX/iq
         UR2hrQ6bOcPmk/2kvfPqMpxQXifml53bD7e9P4BE/Hn9mlGPRfA8j8/S4oDJNMZOfiRV
         jPGH3n0Fgkt47MicESgDvvrMcDgiAYC2QEykoaWgB27vkvLJqhC1VD2RrCP3p0gGeCzk
         BGKA==
X-Forwarded-Encrypted: i=3; AJvYcCXme4tRShycUmo4A5Z76sXyw9kZmae58fVidw+zvzTJaiwb48fi8PBYHKWi4A1vRRGd0H44iQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxpq/bRI8T190HHGyZ+ehwdGbuGuH48+J+sDMCqqD1FXcm8+GWI
	oKKqzDHfWLr/ncBAkuKr+QDZUIFbhhV+Tt856lvpOu+2ShUWgDHp3ge9
X-Google-Smtp-Source: AGHT+IFFSzfq+HjYsIt8ZIT8r0s7MxEtRlDAq0WOquZqnTN5cGX1VwJ3g64SrxAoYGFMfChaBir1Og==
X-Received: by 2002:a05:6214:da8:b0:70d:eb6d:b7f3 with SMTP id 6a1803df08f44-70deb6dbd61mr68260416d6.28.1756404091720;
        Thu, 28 Aug 2025 11:01:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdrfcyf5MqAkveiCJbURcYFfLmxmt50CiWOtrGDd8ic+g==
Received: by 2002:a05:6214:3002:b0:70d:b7e6:85e with SMTP id
 6a1803df08f44-70df0580637ls14718806d6.2.-pod-prod-01-us; Thu, 28 Aug 2025
 11:01:28 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUu+/7lzP3jCEXBa0E99VOh5yfP2F8KkPnFDOF96tdVhi59UAb7g0LGn1Zr68qcEVIdRKFxcvF1iRo=@googlegroups.com
X-Received: by 2002:a05:6214:6113:b0:70d:dc44:dc73 with SMTP id 6a1803df08f44-70ddc44e5c1mr91902206d6.30.1756404088724;
        Thu, 28 Aug 2025 11:01:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756404088; cv=pass;
        d=google.com; s=arc-20240605;
        b=OK1qp5uY4C46AHzBc4ex6XLhiUcEPgU28igGgnnlnACBDltrTDgKChMW5K94sRNZJn
         L8bFxky5Q/WsgTQ4RbqFRh+pGdWtt0m6VFIpYS2tTPFvQ2lop24tIfUK2IxixR6rpkaD
         UO1NSkaouVNVAaDpmcg9grPBXLK0/P7pfPqaW+MsOU0qk2ibpP49FxHwt+Twn5+KrC76
         iXD52z1530U10Pui/Awf+sA5m/ouJtlOfJNUfQAV49vyCEutmoii8Jyc2HpgawbPjXho
         48pNoJ8dgJWBdtNQzxI7AM5o54/dkBfIPxozJ6oRkTlBto6tjDhPgIq5yHQURmJMpVqk
         MBIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=DSjkgYjAwI9R657OOBxPeDUTf7mbPi1gyQ3GLari25Q=;
        fh=jnJ7bgRwpLPERRMXo5PumFIXjbiHrBJ+M36mU7f5F70=;
        b=lQmcCrdye9PhOyGWfcJXQkAKR4NTUWkx9DlasEYc2sEqMOmSoGnH4VxDH7LHccJ8br
         5WgbjJ/m8IL6MpfyS3mFePok/SUWnPf4qpU4Kb0kDyByocqp55IfyJHa04rsDvlaIlRR
         iYZpD3tby0o081oyoogHJDaU4l1mKbZXSOnNcSKayPYpesxmM8CVVC6E2sW8418952Hd
         GnYVy5mOtzh/TppxygK8m4GrNT+oMW0CLdibDZZ86SLfBEgugnixUuRA8z/mRxp/+FCz
         vajZ7+Xp2tTKtzIVsCQ5SqA98K15IiqXzs+aF1SsXLw7QqaUVDvzMiYjkGpGqjCgSsCt
         1MqQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=lAXURZg7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=B4lZvvm6;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e57e1674esi18696d6.2.2025.08.28.11.01.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 11:01:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHN8YV018291;
	Thu, 28 Aug 2025 18:01:14 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q4jas42q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 18:01:14 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SGnhvY005115;
	Thu, 28 Aug 2025 18:01:12 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11on2081.outbound.protection.outlook.com [40.107.223.81])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48qj8cf6pj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 18:01:12 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=osYNoRh4qmOSovzCb8g8uUm9QHa3lXIIStYcclvq+8NuKUWY5pNDbs1HsW8op/7bV/GEy2vAlaLCgg5HdDAMmQ/V0i0pyYvrTGMY3VBRhNKAPKYNUMokCITWZD5dvLxPVGHmNmvvAXS+k1zOx1HbA4ZLS5i2gKAOkhc68CmnJEceJeTSXd2T96nwFVsDjnesaTNRIrrzzYmX4g72gzwqDa49moPLW6kqs9lyEk1NlGUXTWPZAyye+OYWvhNgKbw2qdoe8QQB4qcKw+VQPrStUZ12sMTCp8LzDtfNHw4R6o6Fd9AzUEe2FMhwqZZAiSip81+NjDRaAG2PMgyaebPXxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=DSjkgYjAwI9R657OOBxPeDUTf7mbPi1gyQ3GLari25Q=;
 b=t1CAQCGZvL43cirxUlSF1svw48M8tOAR98oc89njt6K4B6yw93yn+atVwwoZ177gPksVrPPtR5L5K7BulYZIzpoxN+efsgDo5W6v3JQuYgnoT/88HFRyzkJp1PaFwMaL3xWmivTr82te76hxZsnj0spDmJqk0uLeDkKaVamihK1LLkBowYoXr0ePMr3OAkKltAdJsI69A2mHQuf4fl3TKOmNkmSMbJrMLWX/TSCp1Od2v41R7UnKVAH6oFCWGTBq2JxwI8iCDtBfVfJyHuTOh1KaRwkbUo3KsEjvrFtDYHfaGT90e7lM9n7hZZkthnMuXJkCNX5MbYTro1Wsoreghw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH0PR10MB5147.namprd10.prod.outlook.com (2603:10b6:610:c2::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 18:01:03 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 18:01:03 +0000
Date: Thu, 28 Aug 2025 19:00:54 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Bart Van Assche <bvanassche@acm.org>,
        Doug Gilbert <dgilbert@interlog.com>,
        "James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>,
        "Martin K. Petersen" <martin.petersen@oracle.com>,
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
Subject: Re: [PATCH v1 30/36] scsi: sg: drop nth_page() usage within SG entry
Message-ID: <795d8319-86bf-4087-b4dc-34a093678001@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-31-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-31-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0352.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18d::15) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH0PR10MB5147:EE_
X-MS-Office365-Filtering-Correlation-Id: b1175412-2b07-49a0-f2dc-08dde65cda8e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?piflfKQ108QV3UyfQq5ywYJczr5ZcRjBm/buMeOqS2IZRNWYSVFy/2rmDrqk?=
 =?us-ascii?Q?pUJlXEvx6h67hCfmciFHYQ4u683eba4FyDynpvCP8Wvs6DM6hxjyIxVPr/Ci?=
 =?us-ascii?Q?j9YUvuexbpr9JMdeAjGUuV98VC7lER8bYUEHj49G/e59Atdf4dsyVp0zzX/w?=
 =?us-ascii?Q?1ipYUS0aOy4TRcqcOgaV8px5tMMU0R3bS+V9/bldVgMbczTXi+YLTPTLCuWt?=
 =?us-ascii?Q?l9pxrb3FrVS0YsvM5UCXebFl5xjb9e8UaH77jPwmFEpNSNcvnXYU4bzknONq?=
 =?us-ascii?Q?Z46hATbZ7u3U/TC4OnhhBlNdEq/A3pIBw25TRJVEyjU/81oM3ye5mTLGTAPc?=
 =?us-ascii?Q?Sxb+NjPpRnRy0PGvLVy2NGC9H/8Bss8GumCUXtv6wncJYY3ZGVMYdun1DnSr?=
 =?us-ascii?Q?xBs9/65/ZOzkAVvnPZ7iipnlTc4eVlZY2Sk1loV7t9ge4n+9ibMDzzgpoPbW?=
 =?us-ascii?Q?lt1sb1o2iTFoi4Hr7wiK3uLK3wpZEqhSKSasElWm13lgOMheomI81lY/U0ED?=
 =?us-ascii?Q?OablbVMljDsMrFQpCAHhFdPULkGVE6Ej2gdL0ert2WykN7OVfseBFzL92ozA?=
 =?us-ascii?Q?K6JUOQaVj3ifRqQEwvuJoNtjxlc0hr4l+uYUm8AoPNoASa3uaYglQ2GIfKGc?=
 =?us-ascii?Q?kQWFUZiRxAd9smtmDnQSlmzDqrr3D3iNvqLkoCDihc3lx/tO04bKvrb9vJYT?=
 =?us-ascii?Q?X1pn1LjxBpGVSnqSRba5FKINmyoMlEB81a68Sr96OuMKT20XQ3dmRHMGkAzg?=
 =?us-ascii?Q?MDk4iV5sMAmTyrpbrX+EJ5zj9h9mtSlSVt8mr6v53xAGy55KFyQvi0e1mrMx?=
 =?us-ascii?Q?/+RheV5v4n8Ap4oyr+ZLg77YV36zmUEYJ/1PqRux9cepZqsVgWXOnHaTvx2D?=
 =?us-ascii?Q?tZzsQ1zWhDtiOs9CHiGx3OEcs+ZceBF3jvQPr8DVrLhdZAV6oEMrV/tw/FYu?=
 =?us-ascii?Q?Ws0wPt/ShL9OOdcH6XV5J3mzdJf7+U0eMiumT5mnSXKNj1mxYJjWe97gLjZK?=
 =?us-ascii?Q?xkZQ+70fwfaUa0N4jNy0btTT9+lSyiwOXbKmrPSrWY1eEujLxwmIh2qw6OCk?=
 =?us-ascii?Q?VJ1YyIu92Zrqkd+sd/KM2/Hf5lcCXljhmXoaOXjfrEZuvSSIWKTfvR2na242?=
 =?us-ascii?Q?b2EI6f6hUJYpSCy8zXY4cpoIeuVO1u4E/6qKOuTtKmPGDDxTsRTe+44Z6zSn?=
 =?us-ascii?Q?IwwLU6yE6UojdH9Dfv8fuqd4QUnOoNz0Lyp4MTamlLkXP3DLT3IfQ/2kme6N?=
 =?us-ascii?Q?rbtCN02I2mljmvzFTRzfEW8SfiU67wfhubMs1kTFQi2gtNdy9ycc9AFAoeX1?=
 =?us-ascii?Q?KFOIMTm3FDgmX2i0E+rUy8/WvYBD4OqyP4iy9td8duwrQGgjs0f+a4JOPt4T?=
 =?us-ascii?Q?+3f3c+eSnCd8NHOGwq7W5Htn+TsW8PBMjyCRdjc9q9b3gIQVJF2k5duftTcP?=
 =?us-ascii?Q?YS1+CqPd6dA=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?lgu2TAQfoi+Bj0L/0XL6Uk1deQcnC0d2NRJXRnqvBz2nyFbAumSFQtxPNmBJ?=
 =?us-ascii?Q?A1bwY99nPeAOw0WkTk+wC9VqvEb9EdjRlPbUOxDWVfEuWlOE8DhfWvOY6T0I?=
 =?us-ascii?Q?6dbVDR1ghqMIsSRuPHF4/i20C2MMSue/YoUSaulTLgOWCBlUKQs4Szh3/SYq?=
 =?us-ascii?Q?F0CCWpEhfEykhVJx1saSI+8VqVk4iTe/e8YQuW9sjObTpgZhFdy4yVmrC1Qu?=
 =?us-ascii?Q?e0uRmYLCqUwqOWPzNxilIWLES64i9yZbi8HUjz1MiDUzXiGJl4fTqZDr6FkY?=
 =?us-ascii?Q?Qc3LFwEN0QMRO72hzK6NlawV27UvQJHJgC88fbexr5Zs9SytUC8q0xNNr0yL?=
 =?us-ascii?Q?77FrdSH/xVYhgtcnz1Hr5XRFZuKDb4FwkmSo9NtD5997OsyPbJWQ0v/SC4sa?=
 =?us-ascii?Q?ivYPDb8+UFgLG/+Eh/eshzKPSyibKhMVnoVWGglLkLgdf43xYyJXYYQuoRnR?=
 =?us-ascii?Q?AFkaj0h+48vC5kjHJKQlGQtf3uZ4WprvJ5rEO+ft1VniAglt7gg2yp9iTnJh?=
 =?us-ascii?Q?1K0uapKBS6xmtrNpxjcmT5BpYZ9X7XG6rNu5wz7m3y6FdmRw6TFnf8nlOTDl?=
 =?us-ascii?Q?SmrJBMyeKUMuPzuqBWK630x4IGuRT1+f/E7EnSCZ2CHIFbXGl5yMs6gbLlY+?=
 =?us-ascii?Q?zGhqvSDwVLh8kwJAKUHgqSIzPbDoBDIXSAf4TuBGYvgOIocW1ly+5YOglZhn?=
 =?us-ascii?Q?F7PSyy0wjdvIOyRqdPPvB87p4uHIMQ71K46DrTJWikKt4E0p4RXppEmvGZMu?=
 =?us-ascii?Q?Z4Y4IF0xG68ItB1oDMkMZJGUbAklGJ9CKMv6XL1VlNESgMPiYaIzaprQoENz?=
 =?us-ascii?Q?OOIBKLLQBCFnELX6jNMfZPz8i6Nryt9tOjiM9F573pJHE4XayTUpdwc9gtUN?=
 =?us-ascii?Q?447I6Cbx7QnlYettR6u5uBh714cbx30E16a9EzH0ghR6Ak40l9Mxz3xi3/0a?=
 =?us-ascii?Q?Z7eJ4gwMH7kzoJLYtGWNwgMjQpfehxBKHuy/bnx8pKeuWVmdplR4ZL/hrdav?=
 =?us-ascii?Q?Gm+zEQNp4nsZpJN7BnoGPP2hyVPuftyGtAHOuVsOMtnBUPOjcxddHQi5ZkWH?=
 =?us-ascii?Q?TzHoTnhGL9pjphkJKILCkOKwUtt+csD4KU3BZG0NehUNjoUY3SfCySt/vR1v?=
 =?us-ascii?Q?hZG7Tpi9kFGzqVjZab5bc39vg7n3AnyvVTrCldT/0+gerPo+ENLhuosf8zuq?=
 =?us-ascii?Q?gZCZMlrGuMj+moDKg4+1/cNT5MBdHEaJJ77SGDuD8LAsgWiXRHz9xjByUfsu?=
 =?us-ascii?Q?PJKmzXNa5mrNSGdPkah5f0nXdaAYic/QC6IEIiB6yGtHBRTHIXPrGx/4ixZC?=
 =?us-ascii?Q?Yz5zP47uB+4PiGBTKqLxo58A5fsy8P6iblXIDQ/U8ZLDxFA6bAYhljZTbyzO?=
 =?us-ascii?Q?WYDtPiQTy6DyH2dvB9kw3HlhnhVYgunO1lo+bDYGuTjoxwvs+dzSRZ2NwIiJ?=
 =?us-ascii?Q?Co2uSVHE59JLeBWMqflY7s82YJ8MM33eXKGkvs3O/3KrIuDT+FruYUpZuVAp?=
 =?us-ascii?Q?1x6W3yp3H/SfwEh37oJpHB9Y6OzHv7Ob/4hky9N7nZeQevyPGezLjuUoYFtu?=
 =?us-ascii?Q?nd8y4kBReFIkLncuFR9FqoWFC2W1pkgPW/AK+qG8et1xj0zhpmWGZlOpxWHh?=
 =?us-ascii?Q?0w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: OMyY5SsUBsoCWId6bBoaGWtyCUUfs3UAq4GieGmEYkt8haCLGbVnqLcDoHkQYc3lK3AHMm/6a5gg+LE2J6mjGNQ2f7uepTr+zb1Jh6MucpGLgeVDskfArF+T9vjx31TTy/Z5xwsN8QofWnmlzdcLvLC34GEGbp4j0IqGefAgMXRKvkPNf/7ioMC+RbdvXa9wZvmTdy0aRGgTebnjl6elMIaGnhfhJRdvWqvawMdVE6+mL0BE+Bpg1i8bKkvsfyQN4Z6wBE3a19WRsm9NmhmUgRU1iDuP605aw35d2mYAnA9I8qoceQGnjUyOZElC/g1asPYi3rkXA5c7MgVqaWPbxjIM1xZ59BxLv3IB+/IV/Wjm/Fdnb+njuNzugeYW/IBMFKBfZWor9k/KH8WotH5MinFVhecz6mJcq5vu6vIHUY9PyaxTrqsS4pkn//BzM+RW8o1PH5XZ/vObP6mhsqTo6U3ftm+ma05YnAV+eEyd3PX5Gt+A4HQGn9+qVEcZH2zzZ0Yc/bjQDU8nIoFshkyT2j6fi+L4DKvuBDBjXFMDy/epxuaz/x0DtPFXv1AbM2GSfPBel8mdXcbJnde0wnNR5Ql4CGmbhvJP/uh+Mv70ebs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b1175412-2b07-49a0-f2dc-08dde65cda8e
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 18:01:03.5279
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 9vqUWcicrGGixsAiB5/BHR6sbP+pfPZ23Y85wNlBCVSgRURQHeDsCxn9YMFSqyMpSDcyMkTlCXx+VXG9UkqW35ahXxeCUMRq22ASD6v2HHc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR10MB5147
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 suspectscore=0 spamscore=0
 phishscore=0 bulkscore=0 mlxscore=0 mlxlogscore=999 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280151
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxOCBTYWx0ZWRfX167IfI+RX42v
 3WHTTdq5D27jfsb2+kqPpj5qNYU0frKTk6CmYclzT9bh/Kvtijy9EG/tpM+D19hcCum36ZRjLn2
 qhJRJkTm5sZ2TLHtAbpruv2QZqE1AZGrM84jD8/j1b30OwVbNkWhb5QGZ7NpYIg2O177fk+eQ5r
 zGCEqN4a809mJJ068vGpqPW3aHN0j18rzXIny5ilV2UhBZlHQn6tlKtohpcJu8bPcVmXIId8UJr
 J3913O284HeP+nnsDOLDMwHyg3mi4lV7ztSM13OAuriiltcrIaE5Sh6Xstjr+N65kgmYXRedsio
 fpvR9claYbWr+wM95NN7jYSFBnLuyu/wkMU6flWqEDN4nWiddGRSOCg/3fMnNd0UN06nGX5PVqh
 GD92W6d3rbZSAr60OLXU1us2+5WYZQ==
X-Proofpoint-GUID: a3a1PAJscloLKk4EUi_9fHfa6wl1sHj8
X-Authority-Analysis: v=2.4 cv=IZWHWXqa c=1 sm=1 tr=0 ts=68b0996a b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=N54-gffFAAAA:8 a=NCkSHYsgAAAA:8
 a=bLk-5xynAAAA:8 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8 a=m3KsOHZZKoR220OkkusA:9
 a=CjuIK1q_8ugA:10 a=AnMw66Xr5OuzjdxB04dI:22 a=zSyb8xVVt2t83sZkrLMb:22 cc=ntf
 awl=host:12068
X-Proofpoint-ORIG-GUID: a3a1PAJscloLKk4EUi_9fHfa6wl1sHj8
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=lAXURZg7;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=B4lZvvm6;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:34AM +0200, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
>
> Reviewed-by: Bart Van Assche <bvanassche@acm.org>
> Cc: Doug Gilbert <dgilbert@interlog.com>
> Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>
> Cc: "Martin K. Petersen" <martin.petersen@oracle.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  drivers/scsi/sg.c | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/drivers/scsi/sg.c b/drivers/scsi/sg.c
> index 3c02a5f7b5f39..4c62c597c7be9 100644
> --- a/drivers/scsi/sg.c
> +++ b/drivers/scsi/sg.c
> @@ -1235,8 +1235,7 @@ sg_vma_fault(struct vm_fault *vmf)
>  		len = vma->vm_end - sa;
>  		len = (len < length) ? len : length;
>  		if (offset < len) {
> -			struct page *page = nth_page(rsv_schp->pages[k],
> -						     offset >> PAGE_SHIFT);
> +			struct page *page = rsv_schp->pages[k] + (offset >> PAGE_SHIFT);
>  			get_page(page);	/* increment page count */
>  			vmf->page = page;
>  			return 0; /* success */
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/795d8319-86bf-4087-b4dc-34a093678001%40lucifer.local.
