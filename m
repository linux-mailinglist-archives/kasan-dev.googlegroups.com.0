Return-Path: <kasan-dev+bncBD6LBUWO5UMBBL66YHCQMGQEPNFB7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F5D0B3A333
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:01:07 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-30cceb36c8asf1141190fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 08:01:07 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756393266; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gl5Wlf+1zU5PFgrGkBf4ErGSQIxZ2tjazl1v++kAFAdRvNSKx0FQLGkfIyo/UQj5Fh
         AKxLyyePx83+/Pj57kycLQZqO3nYkeLeBzLal0EzXmjhiVhR7/txbfyNtHgNJbAIMP+Z
         BSLhDRh49tlfNtd0w2EI8I1SppDd+PpgkDrdREdPGrYCIcCxTR7mpNMyKc27XX3swiw1
         acX8sAX9dE3zAYgEUoJB4LIR+woxj0EaGoI5Vjfz8WBIUUZnonae30uQaCRVUrajfHZx
         vsFoenwLl+YSTJHqhwxw7EWn+5MtxAuPjtAW3iJWvG6TdMqVIhpRqZ7l95aQ1Y2M88Ab
         e78Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ENHYni1MKCkEjfLH8fr1tYb0XriKvh5+ee1Rw8670Og=;
        fh=6NrSODGZ1iKo7OGgZkiIkfGxAXl16TdLCl/ZPE3AtlY=;
        b=f1TH1HhNCcKDr6LgjpzN8FHVfh5EIOjbtt/itm6+COW3kwghQYSl7nUQA9LYddGnxY
         5JxIZc6ZgOk93ihRUkniQ5KEtrnVyI6wZRuYTuNPRadloeqBbgu1/B20K6hNB7bw4hL2
         CqRGrAoi8iXj6zfK1U7UWhEiGIIbr/kBlgIGmFiBqqehF1TVFwsEe/BNwsyuL03NMJan
         LvTiE8QOq2MY5Wx7+Zo1JGBkmS7dFJcrdiBwfU1XRvUBSIHUXzUzj/hAcioQP+vqZA84
         mT8PbJtXS72RXFq965SaJUd2PauLZkcgLh7cby5XAqTEiPuQzRuT4ZdSLrAcBdZcdoL9
         cmmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=pCu3UfkZ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=KfuMt81Z;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756393266; x=1756998066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ENHYni1MKCkEjfLH8fr1tYb0XriKvh5+ee1Rw8670Og=;
        b=P3n4QwfVyy5V0aXTTKLTxm6uXC4jIGtFN0l/7Mf67lPPmr0eM/kOL+Xrr2Rl0eGXPe
         wc1vZxdhk6U3B9cYooTl7voHz4UFKqCwDkaTJ2LldvQjVuutBJumBnISVOqHJyKNhjhI
         ngGcv2lx2bG8nml0GFDct+XOvhRpw243aqNDeUVXxI7nqt3xIuhO/lY/FcpVgNuKm+OT
         BZ/Z0ygPlSJxnLBVgPbY0BghBGUxsYQA3gFm/F3TipoBJqvPI1xqyp4FjnKFE8Sb8QYj
         Sq8PZatoF+57EIxQiPe390Z8brI8Xh2DfK+3JNhsAUnBgiR/dD6OWLpjqhULeDASB9XM
         73/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756393266; x=1756998066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ENHYni1MKCkEjfLH8fr1tYb0XriKvh5+ee1Rw8670Og=;
        b=W5vUyXrI0yA9anospiHaRapNLsEZcokABVfjUxnrhZOFe2a94+aYPwPXfoiDBZDkbp
         UtBjChU2lhLxlz/fK3BKfP+1fxvOyEOZGhcFMIUSWlIOoZLab3EIGyuz8jQK0PAGFV8D
         Uu+oNvIrPaNHIciJSOskq5q8AVg1jowGfx6htFDAVGv0Y+F5VjNo1DiIrx61I4sVriMp
         j0SCkwTZsZGJd3OuA8ah3qPeUxtelyP1aUKMs93O+uj9Zccu8SB/vbUu8gx09azrPKN5
         tPcnXDW1hcH61ijxHMfOMvesBMeTqVJcEScRmhDuCBkxSLEpZwplJmpz8fscnOTCprgV
         sN2A==
X-Forwarded-Encrypted: i=3; AJvYcCV0RPUY/w/5X1m6VhYn4Ig/IUu2igSq8lnHW8MLdaZkJ29h9V/6ibUVEAiVk8hmJO62vM3wMg==@lfdr.de
X-Gm-Message-State: AOJu0YyPzh4DDuGfzg7Bf8AstMcFmFq118O829MngYmoORrMydBnHkAx
	GEihX+D16n1PvIZ1xM92GaSRPFqTC4GWklGXKH+R1MgMDABer/8dJZo2
X-Google-Smtp-Source: AGHT+IErVzSJhf08xTOzWlCude/7XS3/Wmq40rv19tjsokHLtqjYoQdkN3USIKwcZaWxVxCmwNajIg==
X-Received: by 2002:a05:6870:6c0f:b0:2d4:ce45:6987 with SMTP id 586e51a60fabf-314dcad7d07mr10847612fac.9.1756393263405;
        Thu, 28 Aug 2025 08:01:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc2EuDmDKy0kIGG4kcDs0gWnZSzlVgQQ07VGtYE05ZS6A==
Received: by 2002:a05:6870:8183:b0:310:f792:61cc with SMTP id
 586e51a60fabf-31595c69e73ls381869fac.0.-pod-prod-05-us; Thu, 28 Aug 2025
 08:01:01 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWXC/6IfzZj5wHyc2+9oVXNWxoAybGWwZmwCRhYRoXRLion8Q/LgE2uM9WtqOvEN7aXioPzKLMyKT0=@googlegroups.com
X-Received: by 2002:a05:6808:1490:b0:41c:127e:3531 with SMTP id 5614622812f47-437851b43d3mr11922959b6e.13.1756393260613;
        Thu, 28 Aug 2025 08:01:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756393260; cv=pass;
        d=google.com; s=arc-20240605;
        b=gRN6qa+uwsvCs4TD82lbN7qpOGcAHZpdbYeNh91RPDbs7LORCa10Enfztc4o242k0d
         XjxepbOBv7HYdh6q+LveFu8uvvhdRrCiNLRq7LnALMlb3kk1a7t2N34URzrTfxvtUUSQ
         UIiubRUmv+9eHl2pdvi1fTae5tJQJAWM12U8QqZINK+KAh7UG1FDGcNVnImNCYnhgglw
         BPXZTZQuh9RDlSmonPurlLsYtTy4S4jv3sEnnelH6R3z6y0+h9SItcU8eh0Yg52a1tia
         1M+q4ZRLBaH/glWZvB/lwDUqSLDYxerRPT40Rd9ohFm8GjdGNAgDpr7DiQB3L2y+RvzP
         +9ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=gh0s1pep3p1Ef05Yk6agcqIM4GTdWmOJhAIw1GNk0g8=;
        fh=5dY4eYNBEIKzJB7gwWuE5B80X0wrUhVJAA65PLzPjuA=;
        b=F/UvzXl2EgU8OPS678SORKd5hmOcOlnzRjyr0q1g+4tejAK4/EgjYz0f2S+3RtyU/v
         ehU4qLuXqrPA/Rp5RWK+BO0vu20dVeb3ffuYs7oKB2E9XT6IZfwJwIq9vRMLy3QQewMm
         AEjXwqpjJS6QbuhPxEY3LifqsrDrmQnMu/GYVhgg4DgXrlqd7YwxOiuBrkJp09zaX8o3
         iTkzP3RhH3xzWOpWtUQKycoMwUYlc/YbEqayqEOIwQMmc0biv2/Mz3BCk36AUBdu2nNC
         cvP+iZsZYRGPcimVMrWD/S6q+hJLlgE/WUsIiWzdY2YXmBd66Hc5x1lBMy/fmoPoq0ja
         FMOg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=pCu3UfkZ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=KfuMt81Z;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437968d1c38si618775b6e.3.2025.08.28.08.01.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 08:01:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246631.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SEN8MS031320;
	Thu, 28 Aug 2025 15:00:48 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q4e28u5t-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 15:00:47 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SDuu9m012211;
	Thu, 28 Aug 2025 15:00:47 GMT
Received: from nam02-dm3-obe.outbound.protection.outlook.com (mail-dm3nam02on2044.outbound.protection.outlook.com [40.107.95.44])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43byh0q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 15:00:47 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=sPnz75ZiYIXoqJNBRosjX6QQ5sWHZCShx8GLcjAVLHTpurq8a4SfMYFYdn1eMr+Cr0QE7XzLcHJvqCFMBITYl565QSwb3lCcCMPoSChqz/cQN17PmDsExHWISAn8O4p9xhUXRA4En5JfQBXM9Q3f5w3HRFe94LohuURoZhM/fHQfVU09NnewHUoe1UdsxXJk4D8eYsUVzAU7V+q2FgFSdOTaVYtN1s274eIRmh4CQ7+bONeoE68Z+RDm8zOX5LGA4lKb1spUqA8/3nVps+03RoPHdJwVISmC/xpEgYRQsx4sJlWjwZOvjUXbK84TxYJJIkc6uYuTmKK2AcKYx3GMxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=gh0s1pep3p1Ef05Yk6agcqIM4GTdWmOJhAIw1GNk0g8=;
 b=DOxoxG1MrOKpOXzByQDLhwOIEzaO5DOlfrUxzoKdTLX3UjJQdgIvNNHTLzECOgY6HUtwaAsyqGfzWcouM5FgTu+stHj6BIxNVJ8ZgFuBwSAvD+PBnCpNkC+UaUwUogYTFWIQBSXlRrBYQRjfiLROHXj81XPFNlQV0P87NPAU4HvoNfV9780sizdo0dgZLyMuQAP7RSwCYB0/5GUmRE8l9L/Yx06fdjnl9ETq2TMqURvfelm2I4NBlw1Q5Ey/ahn/S7r7D1gwwIzCk1Z7tv42Cbm5eNZod5x7OUYwcoDsSV2ug8qMFg5QrEv1eYpiU+6djBXrlPuHCy+NcLqZjDhnuQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by DS0PR10MB8173.namprd10.prod.outlook.com (2603:10b6:8:1f9::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.20; Thu, 28 Aug
 2025 15:00:40 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 15:00:40 +0000
Date: Thu, 28 Aug 2025 16:00:31 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
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
        wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 10/36] mm: sanity-check maximum folio size in
 folio_set_order()
Message-ID: <f0c6e9f6-df09-4b10-9338-7bfe4aa46601@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-11-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-11-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0353.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18d::16) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|DS0PR10MB8173:EE_
X-MS-Office365-Filtering-Correlation-Id: a2e71c24-3e93-4c12-b9da-08dde643a747
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?BtUUC5aiTA9aeWOI8NZI22B06kRUU8QaYE/9DyMmZc+vXjZxVGvlMw31A+NK?=
 =?us-ascii?Q?rhQdgNqIGAD8+eOACi84hLuX/rQBS2LvO1ukPwhLp2aAWeXEhiAf0eURQ8Le?=
 =?us-ascii?Q?hAallR9WH93NWeEExo+fFCFUb58lzSh7QzBrYE3D6gRGLaHd9GEnnA+jdJrb?=
 =?us-ascii?Q?EzBdaPZxZpVpg14IqKzHuaq40zSNUgrohVkaZR/HVmak81O2BicxTf+Isqlj?=
 =?us-ascii?Q?4k2LTcYfvDnwKFB6yPK/hm+LTfM5mbZnCvmU38km8mBioqfZNOHwwhDyj7wc?=
 =?us-ascii?Q?Ot3kWop6Q5nNAMUvdX3pgPjQgTlM/OR9kxU1/6e/Jm8pO4ajVIjmdzS/4Bdo?=
 =?us-ascii?Q?DnD3BT52msdKRsZrEG8F2SabgfvL8fHaLwdfzu5TKNbmyxcAD3gUC9GYfBf/?=
 =?us-ascii?Q?27vA/kmdKA2Oo/r7UTjdSpN34dJe1jYqfFUB91yvExIRldwueLY6LLHJgfH7?=
 =?us-ascii?Q?ZWspXfwq1VfiThsTuJ76H5pijXgLK37pEBeDO57RBDLXQ4Fj8iau3oaZEkLB?=
 =?us-ascii?Q?09+c51fSwAUbsUKUkhpadrZ+Ep9HeZVq9EvyBrluf+JNVG65Sy7z7Xo6Nr6A?=
 =?us-ascii?Q?88V4Pa53c6XqDUTYFpyCmbCtIUCn8bG8PfUmS9gwanRd0aDbMOl6zpWNa/Pi?=
 =?us-ascii?Q?2p0LNvhVG3177elOBF6EbsZvIebk6uuCViTZjbJq27UokVGRynt+lJpLgNuV?=
 =?us-ascii?Q?YjP0v8QZbW8hzPqohA8iyMCvcZRhK2uJbOhYtjzvwwvlnpqGeV00rq37R6VH?=
 =?us-ascii?Q?R5dJ5SWSQHvqSeLTgGCNb8M5F3dMRiS4cOQoEzmxQznyuZVHU+gbEBoGdWwQ?=
 =?us-ascii?Q?NG/61TY1yk2nVcdoejePgRbxRC02CoKjxSFuiOv0/xAA89uFlwSSICO48+cT?=
 =?us-ascii?Q?37Ipw+KJoPWGjpqasjQVfgdlLZTMZICpStOmtgl2Zw2QZoTGhw9y1kGLhiU3?=
 =?us-ascii?Q?rNl7YH3C/htf9gtFTkzUZ2tr/1eRxy+tu3E+fXLP3VwveVmNpG1wzOGoDHTf?=
 =?us-ascii?Q?HJ1tCQ87DZM7UY9CqiIgdshGQkK/7JXUzOQPMj19yvSMDUaXUnIwzqQkzgmw?=
 =?us-ascii?Q?skAY74GYizIaJwEsr5HxsCHTmuz/KAY9rt4VksoJi1Yh1VSmunSw+RIysHbq?=
 =?us-ascii?Q?2L3rPzerzcpgHcDOC+3jd8GE8h9Caua5qmF0APD+5wBPGP9r/Wb+uBIhO2qo?=
 =?us-ascii?Q?Q6iewXJTGvy9TiA8wDDCmxLHIPfVC1uEGx+z5DTYxqyKDoVK82byOeMY0D0F?=
 =?us-ascii?Q?cQ5UXFWRkdTDuG4reRe6j391t9vK5OAopanpabRzVMq/N3qmuAD+rHaTpgBT?=
 =?us-ascii?Q?ssklLBVN2iMQFzisu46ndCq0EX00rEL0BVcAGFRWF3BsC/jKnmdzeNhBobrN?=
 =?us-ascii?Q?jPbLO9hlyjmXGq6cWrW6h5Yu3psB4bfKlp/JRjJVql89s3wRU1Y0XmhwuoPI?=
 =?us-ascii?Q?PoX3vVQ/kLY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?BIs9/FMXULxY9RCTEti/59F/aTvgMxS9aW++pY9Hn5ONXxNtuNao/YIKvxPD?=
 =?us-ascii?Q?MbG8Ro2Fg40XluK/7yEHL/M5ebppMrIMxAMQLW2EfwsI0BtNnjiz8oQx8IvG?=
 =?us-ascii?Q?2od/f+cwMQyr2T7u05TjKt7b2uj3Qy8YTAhEGihtfZOhq/bH4KhZruyqib0u?=
 =?us-ascii?Q?vSba2RtJ3zDX+ppU1/zPuOPXPQe23KMb70ZnWKHJvHx8oKj7kIkH40/TRAqd?=
 =?us-ascii?Q?bRSaCVd4e3pbHlpfaA18Vyy9o8JFWntXdK3jjqnJBox52J24jv4w76K0FhP8?=
 =?us-ascii?Q?wVH7GyFHcP1V8JcPEQWvQoUZLm4mJe5M/6tcfFLSb9c00P3kO8CsY7n26K9z?=
 =?us-ascii?Q?pYei0891FjemaauSzImDf0nsfC9O4ISgtjcs33yLfZvJ+Bjxub5N/9M+xLKl?=
 =?us-ascii?Q?npp0s9axYb/aeCBlO4yOLmqQZYsjrVxo80A7aNP6356vE0b0b5appwzvRuD5?=
 =?us-ascii?Q?8gb1mez9tD+lF9u2qv9m1bsIBKC7wsFI97bdTGwmK0S3cFS+98U8x6GK6822?=
 =?us-ascii?Q?RXYtGjgrAy1Va+BRdsBsKcmJX5M9HiN/Uyecx4miXY3DdOa/qsuei1winrVJ?=
 =?us-ascii?Q?/hBYnEH41vmpcIAAc/hLhvvTy9nOvFclvsTiUxNsmdag3Q/WcydAs7X6TwbP?=
 =?us-ascii?Q?EwPag6nKbXqlcA57E+7XXMt6ir14HizUWwR2fSfTTgzKQ2YFUQqjIjP6XryV?=
 =?us-ascii?Q?yBG5Pv06hczNRlUls8HTKpzEXmE1izIxqksypoVaJ3YqrWSckrWMVhsLAmu5?=
 =?us-ascii?Q?wKRTDa8f10bN7g09DSj/mrtXeFNFa1+jVP38AU4mkwkJzaUH196xJaYe0zyW?=
 =?us-ascii?Q?iZF1Cm6hPluoSs6wYnAJ7W+2jH+Bu+hw5JPVmJtki/axseUJjQxRiq8N3/aN?=
 =?us-ascii?Q?HY02jEZLpQ4cXF/yh+RO7aUIyPiEYRHjmWMUvuDcK+syfP7NzAAMlvVOw5sH?=
 =?us-ascii?Q?QceFNl9ffAXwGac7MumZeWviwKtb3W9F948uWegGj3UKoIvw1gW/ib8IjzbK?=
 =?us-ascii?Q?Fn6u3rVWmCku1T1aDT1tErsHOlz15inrju70D9BeFax0k52fWwOJfeIKCAHc?=
 =?us-ascii?Q?hymMHza3PnUJTYtn22j3QeQxP7wXl2qxyKQ99cfdBBRjnwLl3BI8kYobeTiI?=
 =?us-ascii?Q?3IOL2UXQvxBVX2XnalTrU8cu7y611Sx3MYEImY5cQJZLHp94oAyu2h+FRotZ?=
 =?us-ascii?Q?eyFJH7CKpGy7A8LwRlxutAoaym2sIAPD1FggYlSfHe581jFulIe729eYO/kK?=
 =?us-ascii?Q?HLMtAV68ZY+cGEopNBFq2p8V75uRKnMqTE9xdcd1khQl7zQzUL8PCw4dUDwm?=
 =?us-ascii?Q?H+unjd68R9Uo5MIElPZj+cT4E6drlIh23rxVNzEfRtR0sVleRbBTtq+ddNcb?=
 =?us-ascii?Q?uVvAzgZpm/u69DeEiUJQLErqpOa/u6UNA9hHSx7DG5M5+ZcXcGZ0hAV78AQ9?=
 =?us-ascii?Q?Jq43CoWh6B0KtSo66KbU5p5wyTEDMpImjKoD8UDthkGmmRsCP92XHHJAsdpL?=
 =?us-ascii?Q?ppVsEkAodnQDn6tukFCOYOhysEDNDBoquvhMSLZ/0jg8NvgXMqbwkFMX53y5?=
 =?us-ascii?Q?GcV3damRGir+j2eiKkVx8SIuMh2GL/Z2dNR7GFOBzTKIWZPPGcuFat4mDCQl?=
 =?us-ascii?Q?1A=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: nUHwkWijYdRsZYN7UXk9gBhxffZG9h9qOOuO0YUa3krPjxnsXxufbBl+aTWWzfNNdnBP6d1AWQQjAVzGLc7k/eTBjfwJP8W3+umqjtu8XuySmmvH6hFR4sJIukcdNIjcUXAKATpoHbkapuEs68wK39x7o5GNOjhV7qPrw+c/qpsHbO2geTdfkgTE7KfkcRxzZCX3jL7e7JU9CUvV2Cy3j/+vZ0TVAN14/RaBDaCehtAU8xpQwF9Q7h8/FwbX1XAyxpu521FCY9ibXuoK7F7ksItr2TBmk37I3NXut+ijPKbNGvYAAU1cGJz8Ny+cIduRzy2aQv0XT2zGV9t+Kg+SE9gxKtcZ2NzlgLe5mlOOf2Mznv7g0WApl/1UDaWP0FsikCoW57EVmmLpMvL0jdJ76zepn/dXVif+dGZggoXMM0lK/NWB1vO4WkixoMme5nUwfwj3n6wyKluzOW66sp5OWm3t9L+A430RJeplIVVK81ksmPW55NPHVgl8XTyuC8U/MhIpRt+jR0EMHAbxghAkPBJN9+QZMJlddNNzroL5LgVS7Tec8beXVDV5vXmpF0VWONiuJYuh/6wlqfvG34diR8EBsj+XTO7xY8w7TZfMIfk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a2e71c24-3e93-4c12-b9da-08dde643a747
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 15:00:40.0807
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: joYl3YjpIuloxqDYHJGs7E0noppuh1wgQrfRhLOu0QlOojrzvJ+VRZFTxcOCvFl5MhdubCeLn1UD/yjbic9Cj8iBTcKLpRbi7b6qfSeqA7c=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR10MB8173
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 bulkscore=0
 adultscore=0 mlxlogscore=999 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280126
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxNyBTYWx0ZWRfX1iFBYIyNUSWq
 3xvtbEzQ8KaRFzs5FNvX9ee5xMff9T8K2UGlKGoF12Gj45aDaiKvcSm8Njm2j5u1VvhCUM6OLBK
 B1sN0BUB68wsNiWg695zgUN9QxLvicvcYu5gjJlLD2WzQ87yDbGETeN5/jN3oKEJAp4CZ1IkPSQ
 5mWpDEFBOsF+AOOXp+mfyB8y4K4txNR9pPnVYaonY7OQKr/428yrKpefMQjfNtlfWWyQvqSNOUR
 XCa/pryNmtTpyCmbK/T3NVycdTk1RQXPFB1wUPXYvbkT37tj4EwfZnBCPzNnTm6nzlMAPTydmuy
 X9u+OE25vRVr0/DmZXzuJoQATZpDwczmCEkn6aaBmt1p9J1C8kx5KdVaw6CnBozlNFebpMI/GgR
 HfWXJO0hBevJ3cHWmX4RG4aRLjFqUA==
X-Proofpoint-ORIG-GUID: sBOrTaqn2oy2glCCVAAd7nVgkEF6yb_6
X-Proofpoint-GUID: sBOrTaqn2oy2glCCVAAd7nVgkEF6yb_6
X-Authority-Analysis: v=2.4 cv=IauHWXqa c=1 sm=1 tr=0 ts=68b06f1f b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=Ikd4Dj_1AAAA:8 a=20KFwNOVAAAA:8
 a=yPCof4ZbAAAA:8 a=hxZD7SQwFA71348cTyEA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12069
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=pCu3UfkZ;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=KfuMt81Z;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:14AM +0200, David Hildenbrand wrote:
> Let's sanity-check in folio_set_order() whether we would be trying to
> create a folio with an order that would make it exceed MAX_FOLIO_ORDER.
>
> This will enable the check whenever a folio/compound page is initialized
> through prepare_compound_head() / prepare_compound_page().

NIT: with CONFIG_DEBUG_VM set :)

>
> Reviewed-by: Zi Yan <ziy@nvidia.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM (apart from nit below), so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  mm/internal.h | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/mm/internal.h b/mm/internal.h
> index 45da9ff5694f6..9b0129531d004 100644
> --- a/mm/internal.h
> +++ b/mm/internal.h
> @@ -755,6 +755,7 @@ static inline void folio_set_order(struct folio *folio, unsigned int order)
>  {
>  	if (WARN_ON_ONCE(!order || !folio_test_large(folio)))
>  		return;
> +	VM_WARN_ON_ONCE(order > MAX_FOLIO_ORDER);

Given we have 'full-fat' WARN_ON*()'s above, maybe worth making this one too?

>
>  	folio->_flags_1 = (folio->_flags_1 & ~0xffUL) | order;
>  #ifdef NR_PAGES_IN_LARGE_FOLIO
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f0c6e9f6-df09-4b10-9338-7bfe4aa46601%40lucifer.local.
