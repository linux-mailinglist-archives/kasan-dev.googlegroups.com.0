Return-Path: <kasan-dev+bncBCN77QHK3UIBBD62YWUQMGQESSPRD6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 56F207D00FC
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 19:53:21 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-41bef8f8d94sf41769741cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Oct 2023 10:53:21 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1697738000; cv=pass;
        d=google.com; s=arc-20160816;
        b=OBKUnTbxxO8gBqA+RAeA5IDNrww9NZcY1l8r8mRrKTvyKrhVW5Tp2xLxovkIu9/S9f
         uZOrjy0RS/uTOR1jl82XUCZBUxCiJ8n1Stjle9j2Hbz9VvLdcHwWWRgSUdsLV29VXL4W
         Y6ghScvEIABv+r0gmVIYt6QirTALSTCr0+cOaAIiBEeaZs+z/P9HpnceEE1CPjlQG4dB
         vZHBPYK0/GK88TwfGKxuKKai2SKx6Swgpvt7SaL6xy5eAGl9t4ry1GW3Qo2RAJUJgvvY
         3umhnV4YJ5SCfGrbWINyb4gRnRD4w9R5xFm4gBL56VZDaSxwZ+0AIBuELRAq31Yg9FWo
         yPnQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=h9fuw6dbEF4LgC0xKnSMDHybGoqpABXESF+IO2qd8Zo=;
        fh=3OzLO3zS70lC4B1Po3YT0WCUPDe47H89bWy64rfFPYE=;
        b=qZ9WZRuh/mwCa5Y1P8bPjpoBB0WPqc1LTiulW8Lx7PkXId7H7Oag/u9sHHPYqj2nCJ
         lPLFVPVhMMnlF7NYe01HY253RaOiNPE6XoGRD9tjNlGWTraCWPmYYPhUiuPJPyuH/Sxw
         Cu3ShDpyQNDkao+EiupuHvtvwyhvdM6v8qNRlk0yCVk6RqP0qmMafjXW89VCcPSnJmUh
         ijkyNYvPD9OVjzMGZ0eCgoa71rd9yLOrvgx5LxEuedpUEjEZAy0A3FacWi/Ws7IEg0pO
         2Q7/wCtOWwr8CLlraq6BFQ4fZJm4PRZ8NTb1FI6ghzCq4RVGurstu3xbyZ/M/QOhF9AD
         Qc0g==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=r12voj0r;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f400:fe5b::62e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697738000; x=1698342800; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=h9fuw6dbEF4LgC0xKnSMDHybGoqpABXESF+IO2qd8Zo=;
        b=ObbHmve59K8DWEdeioEIEBwaN4YHYb6aAYcw8zbeaW0IM8ZOixndK7bQBUARg7ghJS
         xCvs+NywBtTa+NaEXqSLh93WLDuehTXWhFddYNx2+UfL4heMKnytm/CZGRqzhM7nR6d0
         B0H5CYWSqMLGwocVkAI5x28CKvYqC+JH0qVnUSzW7DOCZKV71v5VbBu8BXBCCW53jwZx
         m/KMaECdgnuwx409hCYX9onytdbERF4K6LmdXVHeVd2+nyTmWNQWOtzZBdj2AxDfj+Ne
         6aOkJ8ihdOBnuVNPw8O6KMbsRwBWENpom6doQQ0pELPrkeZYR56wndUQyjfIdzFtYZ5J
         pMJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697738000; x=1698342800;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h9fuw6dbEF4LgC0xKnSMDHybGoqpABXESF+IO2qd8Zo=;
        b=vtKVrtzIBHGYfnZt98cxu6sZ2h5yFhNJZZubr2IUvowUX9N7KRr56JHfJiDSW1LlBS
         PvUgDMwtxvFc00nlam+a/5ydDrDLndeb3NdV/m7VPSBORNVV4auda8KTEPCy9FxuK51i
         Ib0RflOH87cZlbmsXKaC6aj2V4xwZ2OE7xR/MyJFLLq7eD2927PF4YWr4t6QTEi+lLDN
         RZ6/3o/rCkReSdVrWSRPqWcCWkgV6Qhk/7xwyxs8q1fxwMQq4hi8fz5lq+G2Rlp/qm2r
         txdMlN0UZE/mdclSkk9on1q3qlDoxlfZRwB4CMw7I4uJSvvUqV1YzRiswmsfP1G86Ks3
         EHmw==
X-Gm-Message-State: AOJu0YxRWfUvq7uP1S/Gxs79VRm+cDfONzTfzCEowHStxjask6WpcInh
	sAn5ufJ7JO+F3l5JOgVyyec=
X-Google-Smtp-Source: AGHT+IGEKTY6Tgj3aZuNQ6jr3Q2J1H2ewahFqrwGmIvCLa1GbYqZIz7bHdvB7P8Wn59smkaaeUL7lA==
X-Received: by 2002:ac8:5fd2:0:b0:41c:bc52:69a5 with SMTP id k18-20020ac85fd2000000b0041cbc5269a5mr3751413qta.28.1697738000092;
        Thu, 19 Oct 2023 10:53:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:598f:b0:41c:d29a:af8c with SMTP id
 gb15-20020a05622a598f00b0041cd29aaf8cls200996qtb.1.-pod-prod-08-us; Thu, 19
 Oct 2023 10:53:19 -0700 (PDT)
X-Received: by 2002:ac8:5ad5:0:b0:417:b545:e962 with SMTP id d21-20020ac85ad5000000b00417b545e962mr3393559qtd.7.1697737999074;
        Thu, 19 Oct 2023 10:53:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697737999; cv=pass;
        d=google.com; s=arc-20160816;
        b=IBl44sDlOTgN1GK9eYmi9m3BKjORDzniO43Tc4WagoxYbhHUbEUQcJ4d4mCHrRJgae
         pXtDFOhiRS1sdUtaHsLqWnxjHYPeuG/FD4OTiVLFI3IaQGhYRV04Cm+v8rWZC0wjF3Mv
         BDnImG1gBawTVcN5pC6PYA0p6NUvDCvb//W7uAhq5JVuvAyKwjinoTtbqQY7dPYB6aPD
         1mozG2klP42bWHAjY1QUbocIBxD6/Ajk/FTAauULhMVCXRJg3R3o5eF0VdWMN1uf6L3W
         g5fs4+6NkQR3jXhvb7Qc7TQHkfqXFifqNWODcfnwLaEAKR+K6lGr51fnOkdFFiM8X/Rs
         bG7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=2/Lo6PKaZAi5CyBGdTwpGsUU/MgyO9/VRaolcqdNbGM=;
        fh=3OzLO3zS70lC4B1Po3YT0WCUPDe47H89bWy64rfFPYE=;
        b=dehmHxO5aVGePCP5IONRswSPp71MfRVEHl1Wb8JP7jKCiwKptu1WI923bsmYQURGte
         YhGm7bSlecdjo3LP29Ot6sUGkv5jj6myo6Uq7k3P5mzqK9Bf2FXQxsQ6Wz/lb1v0HseP
         +z/LbpHLbBy8vOAUbp7BIBKrS/mQCLoz2z17IHSSeJm3JumutbcQk/Il1+SWMPEPwywI
         9iUxHVMyXvavr37gaOhhpPvVgacnKtu2BpYhSZm6WU0xTXD2qu8+xdG9f1l6oemrAybQ
         gF6BDqh276oLB+wKEWTHYReEuIUQUsoVciKON1ZOmABox3gFpFgXjFyJCigweLUDFDGf
         JF8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=r12voj0r;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f400:fe5b::62e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (mail-bn8nam12on2062e.outbound.protection.outlook.com. [2a01:111:f400:fe5b::62e])
        by gmr-mx.google.com with ESMTPS id p8-20020ac84608000000b0041b19567edbsi236863qtn.5.2023.10.19.10.53.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Oct 2023 10:53:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f400:fe5b::62e as permitted sender) client-ip=2a01:111:f400:fe5b::62e;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=f908naztD4B/MbSQ6lrJxV1DD/EIMSqhKnHiEZ+CRT81CnF22a5dKrFnCRLWoGJSnn8v1lRfW+9+TctU/88Z4gs7Tm3Qpb4nPburi2CHc1l8uhn60uz3YQ06A6KdY/0RsEUoh3SXKe4BU4MaIm7+uKzTEcnM801h1dixISRBVAsZUW2EOp0cW2tOkBqrb7NoG0wEPWjfYor/dh7EPmJu3IwY0F94QcLDSJEoOG2z+hNK6Tq7sVHStCP23DkO/QiQX5vZH8el5nRaFrangWKWhNgu2nypVQG8GGC3zabjI8Oi/bzhbfQbqtSIJhCpg5MKJflvbXgVxZRrSB9gMNhJdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=2/Lo6PKaZAi5CyBGdTwpGsUU/MgyO9/VRaolcqdNbGM=;
 b=LacPEJZIREQ+lX2Xvh59RiQjKTbR2rvNEyNHIOpueEwTK6hd6APHVDfwUbIyCjSVq4ihTg5XrfrqejhqoQN+3pDdueTjGZuD9eReGw2J3O8iieAiDIC9l+dXXo5dyYJfK4G8DO4stXaINnOcJVHsFr0FWSmFZzj1HP3TsZGYNyQKcmBsP5CvgVlRpzF5Fmh1T1b3rAMdebcnOkmyXYNnBE6mBug7md6TX4Xr7GZEmLYu4uE/4OCucUxD0X4FrcVmkysoePKbR9O33XfVmznRGhLaNlvkA3DORMlQECHoY991MhJ1e1Lyq9VMmnbmAX3DwQ2S3/+a6mC0xYK0uHetjw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from LV2PR12MB5869.namprd12.prod.outlook.com (2603:10b6:408:176::16)
 by IA1PR12MB9032.namprd12.prod.outlook.com (2603:10b6:208:3f3::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6907.24; Thu, 19 Oct
 2023 17:53:13 +0000
Received: from LV2PR12MB5869.namprd12.prod.outlook.com
 ([fe80::3f66:c2b6:59eb:78c2]) by LV2PR12MB5869.namprd12.prod.outlook.com
 ([fe80::3f66:c2b6:59eb:78c2%6]) with mapi id 15.20.6886.034; Thu, 19 Oct 2023
 17:53:13 +0000
Date: Thu, 19 Oct 2023 14:53:10 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Robin Murphy <robin.murphy@arm.com>
Cc: Chuck Lever <cel@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Chuck Lever <chuck.lever@oracle.com>,
	Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
	linux-rdma@vger.kernel.org, Jens Axboe <axboe@kernel.dk>,
	kasan-dev@googlegroups.com, David Howells <dhowells@redhat.com>,
	iommu@lists.linux.dev, Christoph Hellwig <hch@lst.de>
Subject: Re: [PATCH RFC 0/9] Exploring biovec support in (R)DMA API
Message-ID: <20231019175310.GU3952@nvidia.com>
References: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net>
 <3f5d24f0-5e06-42d5-8e73-d874dd5ffa3d@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3f5d24f0-5e06-42d5-8e73-d874dd5ffa3d@arm.com>
X-ClientProxiedBy: BYAPR05CA0053.namprd05.prod.outlook.com
 (2603:10b6:a03:74::30) To LV2PR12MB5869.namprd12.prod.outlook.com
 (2603:10b6:408:176::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: LV2PR12MB5869:EE_|IA1PR12MB9032:EE_
X-MS-Office365-Filtering-Correlation-Id: ca7d0bc2-40ef-4ec8-e1e5-08dbd0cc43ac
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 2xihyvNOSjeOgs9HAEYwRc0dG9ap1jycO+7qbuMdfkw2i707atQP5Zadjgru8UTsNU579YddNT3dMpNX6gA/h2fL83t1634YrSFH17RJNvUDvLR6U8SWwPAWblRFPjJ2QNFqQqraFFvTMourX6KvAwhcyKGsylagfAYgPhvALv1wYN+oeaiM5gH4XE29wTiyozuq9qdXVJCYbCGnSX61WDcAYcaa9tlXg2wgNIAcNTu1KDHMxI+BAT3PEo3UAo8z5vbbVgcCDsKLNoCYCC21U9LaI073wRqjuFcdYPVKrJtkcNqHnBoG4WsJ4efv9Uxo+Ob5lgWqvVG+kb4DU8F6FAirjvwqNuUI4c8h5eSUaIjmpeHIQLqT1BDL2YKGsYosQ2NrIVX1G6wHo5zT7bxehFiAx4NLsA26bLKpByXaXuLR9W05z1XzTNOnPJCf4uvghweayx8ql3JDdbn0k6dSGmbKzDnAa/jJCHrnCM8LUfdsb3PUvd+PCe6jWOnZyDd1jkVTYdtExySJePvUPMpG3kDMyFZJM2A2FGh99aIe2WYu4THXeQI56nrBDQwXR1WD
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LV2PR12MB5869.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(376002)(39860400002)(346002)(136003)(366004)(396003)(230922051799003)(1800799009)(64100799003)(451199024)(186009)(7416002)(33656002)(86362001)(4326008)(8676002)(5660300002)(8936002)(2906002)(41300700001)(36756003)(6486002)(478600001)(2616005)(26005)(54906003)(1076003)(53546011)(6916009)(6512007)(83380400001)(316002)(6506007)(66476007)(66946007)(66556008)(38100700002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ZZACtE7RA2NacJBplBZDt3RJZIRS5ygh4pF+T38m5kATThromWjhHwOE9eSA?=
 =?us-ascii?Q?8YQKw0++EX9cQ09+EteaWwaqjxMKrtcGuv02z5DbBSg5kLEJH0B63m79YJXX?=
 =?us-ascii?Q?9m1WeWB57+CRyitx7gJP8gGZsZdUEyOUwrLYYMW1eljmKKwfZ5GsvATFOvS1?=
 =?us-ascii?Q?nt/N5Al6Fm1ZHI6ibfbbUkwp4eah9RQh2ffZtrmVEXlFNBnLSNd4xcJbTvPN?=
 =?us-ascii?Q?JIQAbqSaCsZ99w8cJVn5f1R+eGes8YNhGVt7LhFd9yWyAy2ywnG2xYUtqRWa?=
 =?us-ascii?Q?RgYljLPK2c4gM6jvtne85BbIBUTNt3Mv4+AZB5UHlVSoNAcFOEWVhz8V7wZ5?=
 =?us-ascii?Q?NDyhNlkjc0xyT31xCTx4BGnNDl/vxOHm0S03tb+UJhPA05551Y8vYDZp0BQN?=
 =?us-ascii?Q?R2+LZrgCt1L+htu9nJSnX76AK2eR08sTXhHcDNkS9yXdNWmyuVSlwoN6a/W6?=
 =?us-ascii?Q?TqPbzdL5jNeAIpkZvxqO6BPJIpHAxdcORQ/RL2CRTyvM26zX8nmyZCQrgYbb?=
 =?us-ascii?Q?gEhzSQ/TxnZHMB8MNs68Wmikdp+GkvuXMII91JuzAI26H0yk6YLPwtRACcN7?=
 =?us-ascii?Q?sJVSii1P52wuy1DZiDRZIfeyKQn++frK0efr2EurfMXmLxi/rL88mtXKRdWu?=
 =?us-ascii?Q?XHV9pzaRNBcm++12Md/utoaeL7ixxx9MID05Fs0egp+AIKFGx+LRfOIFVFB2?=
 =?us-ascii?Q?bp4u/rXWpy2rJarjgbYd6J10gq/AgCmQEXD69TTR89lYkZ9FL+EptSn0H/Dl?=
 =?us-ascii?Q?IM1nx/baPUbSl9+bYj4L9VJFQ3uQn6cNkhLJooknJ5pLvFf45KRjkjbIlRSY?=
 =?us-ascii?Q?HRhHcjgA1U8GuXQ3x21LhZClgyl2hHajb0grt+pv/5hE2TC/EKCHZVpgpSE7?=
 =?us-ascii?Q?w3W9BvsMoKLxuiOC4Piu2pGoTg3nXd5cbLYTIDhWbyPUaZNOjIIBtlDUc35x?=
 =?us-ascii?Q?hHE2qSJSjjzDTsfIS9s/EKsJpTgYRCJ50uAzChyx6lxXEv+6vgpTxQoiVjol?=
 =?us-ascii?Q?OOVtHD8DeovbkI3Nlt5HFeLPfnF689F8rIrW/3HEUmDyIMLGHmIxAgFxc1iZ?=
 =?us-ascii?Q?gcVBYdhWnhv4uWeW5IfBuGewsbBmXRC7OTGNllW4pOoCGSCd1aAd6sjaEPAH?=
 =?us-ascii?Q?EsqHMVD68OG6SoP86+zHUGy1JZfKqhWXQ2tFd8/5giVAWegsWAvuSbLgfODx?=
 =?us-ascii?Q?bjlQE3/1LqXx5px1MLv9Cw3NA9jwPY/7PWuN5sqFLkGd8N3qrqErYd3dHzZe?=
 =?us-ascii?Q?3XZaeI2GvMAdurwGpkgb71FTB6cY9qcRWnKZIDoULGZcEnc8pqSadVMvcMbi?=
 =?us-ascii?Q?PrSAGfpTprMerzjm6uKIvlL1XwiIAxQQ7LevKIfLkrl6l4tLj/i9heBpps2o?=
 =?us-ascii?Q?Q7jjZNjxEdNo1Uno5Y+OLr+aiug453fejWWKtcsIVFaA5d9pIXgf3jkvt6XL?=
 =?us-ascii?Q?qpusJgamRlwCwchOIp371B3EP1ta9rFxcd583vfuFL8yknPic04flBPX/PCv?=
 =?us-ascii?Q?axyKlOKqU1zT7VLtisXn5MLIcoeK5nkCXSJMyRCSQXOiwWQ/nAKe14eIWoM1?=
 =?us-ascii?Q?Q3OJ5X6OIDaZsCncMY/D2p4xy35SayraKE3Gh4g9?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ca7d0bc2-40ef-4ec8-e1e5-08dbd0cc43ac
X-MS-Exchange-CrossTenant-AuthSource: LV2PR12MB5869.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Oct 2023 17:53:13.1548
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 9ERGeSDoqO/rUv64Xau28oDM7Qn6ZuLUOZHVijPol2BJCVlk5Yv4xPJzMer/0TfT
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR12MB9032
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=r12voj0r;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f400:fe5b::62e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Jason Gunthorpe <jgg@nvidia.com>
Reply-To: Jason Gunthorpe <jgg@nvidia.com>
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

On Thu, Oct 19, 2023 at 05:43:11PM +0100, Robin Murphy wrote:
> On 19/10/2023 4:25 pm, Chuck Lever wrote:
> > The SunRPC stack manages pages (and eventually, folios) via an
> > array of struct biovec items within struct xdr_buf. We have not
> > fully committed to replacing the struct page array in xdr_buf
> > because, although the socket API supports biovec arrays, the RDMA
> > stack uses struct scatterlist rather than struct biovec.
> > 
> > This (incomplete) series explores what it might look like if the
> > RDMA core API could support struct biovec array arguments. The
> > series compiles on x86, but I haven't tested it further. I'm posting
> > early in hopes of starting further discussion.
> > 
> > Are there other upper layer API consumers, besides SunRPC, who might
> > prefer the use of biovec over scatterlist?
> > 
> > Besides handling folios as well as single pages in bv_page, what
> > other work might be needed in the DMA layer?
> 
> Eww, please no. It's already well established that the scatterlist design is
> horrible and we want to move to something sane and actually suitable for
> modern DMA scenarios. Something where callers can pass a set of
> pages/physical address ranges in, and get a (separate) set of DMA ranges
> out. Without any bonkers packing of different-length lists into the same
> list structure. IIRC Jason did a bit of prototyping a while back, but it may
> be looking for someone else to pick up the idea and give it some more
> attention.

I put it aside for the moment as the direction changed after the
conference somewhat.

> What we definitely don't what at this point is a copy-paste of the same bad
> design with all the same problems. I would have to NAK patch 8 on principle,
> because the existing iommu_dma_map_sg() stuff has always been utterly mad,
> but it had to be to work around the limitations of the existing scatterlist
> design while bridging between two other established APIs; there's no good
> excuse for having *two* copies of all that to maintain if one doesn't have
> an existing precedent to fit into.

The idea from HCH I've been going toward was to allow each subsystem
to do what made sense for it. The dma api would provide some more
generic interfaces that could be used to implement a map_sg without
having to be tightly coupled to the DMA subsystem itself.

The concept would be to allow something like NVMe to go directly from
current BIO into its native HW format, without having to do a round
trip into an intermediate storage array.

How this formulates to RDMA work requests I haven't thought about,
this is a large enough thing that I need some mlx5 driver support to
do the first step and that was supposed to be this month but a war has
caused some delay :(

RDMA has a complicated historical relationship to the dma_api, sadly.

This plan also wants the significant archs to all use the common
dma-iommu - now that S390 is migrated only power remains...

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231019175310.GU3952%40nvidia.com.
