Return-Path: <kasan-dev+bncBDWMT3UBYINRBZO4X3CQMGQETFVHA5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E5F7B390EC
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 03:18:31 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2445803f0cfsf4818845ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 18:18:31 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756343910; cv=pass;
        d=google.com; s=arc-20240605;
        b=PShCGsMOdkxCMCorAdv1lYb/uymzn0l1WErU6qdtkQ+bUh/NgHkl1yfU8gwIln1ST8
         tilJS9IOjXnYr9YVgbb+aOSCtasC7nnXcPW9XZ0aHys09llGnLPFXD33Oz3lW+ARZLxo
         9oUt46zDSfg/4cXYJT5bFOyIic2ju0dk6CQBOgq7nGQpe5VfSzmTMRZK6aByzCR/lfA7
         Qqu2PSydtAJsB+FiSQzZmgJvigu1AH96+GlOMEx9mo2hktbB8Krdt21p2j1YoXygGO1N
         30s+YuRepRadjBl+PhUt0rbT792cpHktr5Usl5HDRUR+QY6jpYnjy2buDs3XwlQaPRAs
         zS1w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=XUtLlg8/mneiXwG2qYmiD9XNHUCkdH5x5V7iSrEvtR4=;
        fh=AdWw27czBJYNJKbPMeOJk6rn+4n8no0glZNspmShw/s=;
        b=ZnuWC/1peHQl7no6Urx8Gy89ZGE2Mjjo4DV/55bUrfm+S/NzP6X3RUPVF3TbpFzz/J
         8+DN2iziBRKQ8T7wi4fxS/wVClqHwtqjwf25DPVHv5xAiwiVB0h+fzqD/bvgdKMbWdCG
         x0rqcQnUAPB5u+evw1XNFx+U+KkrUbsAWqZfcKAucBjywP4IGLybk+CFQdAxaOiSFljo
         c4/ftjBW01tEN/3uQ7C//lulLvXkhZ5Gu5oV9yxZLMfU/aYHVEf4WaivlIP0BPT93GGu
         X/0Oxhf20OFi1zhB/6LF+egs5LrFc/Hx1liuF2S0EcI+Esv36hBj0r6s12zYXwTn7MBR
         66UQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="SO/zxCy3";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2412::604 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756343910; x=1756948710; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XUtLlg8/mneiXwG2qYmiD9XNHUCkdH5x5V7iSrEvtR4=;
        b=f4A8K0yMrtX5kL2p39YAtEPSqNT9+AaDJHAGJZb8HPBDH//VzI5/wMUu7NzxIQUUl4
         Rm2GZ4tV/l+fcgoEpodT9ygYQf5+6n91/CNp467J1V1NejKXw2gtn+W2jhFMXb/C5VET
         /oaVjCPTwzE9htAcP2TEwcG/y86mTZfOS6nyFoFfzqXY4RgDMD7eGW3Rf+rvgdWZ91wq
         cljEVOXs+w0krWV/5kPZlWZKTdOQCmlIOMNTJ7fFCVmcOqZlbb+lJTnG7vIi5eHDLRQ+
         SsrpV/Ib3Pq2BihKKoX0z68hqLSVwPpI+bHd2VSeWloqLy6ku2tlQa9yMqe632YfmqFL
         zEpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756343910; x=1756948710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=XUtLlg8/mneiXwG2qYmiD9XNHUCkdH5x5V7iSrEvtR4=;
        b=uY0M6rn8vzDAreoCAWhZ+EayFkflqE2dya8JapSU8d44pO7MxzOmc1rVbIiLy0tLGr
         p/wweUXXPbd9ZjIhfDh2coCwqqpYDdEJd7DERg7IGwd0zL7GGMChntQVC0u2wriIh1g8
         u/BwrZLxMwqMLWtIsJ4mBLXrGFKk99Tbt7O5jjPAIg0IJwis+TaCp6VuA85P/oAnnznV
         BxGV8IGzmtgPEZfD2CJ8Y1a1M2BdWgPPXyzBP0xBZ5WzK26Nr3tJFaVeC7jlWiR2F5Ni
         JFxnR60ct0vE6DUfsKRCPD9LTR2E4lm3FoC66mqtPdmH+SOzJ9zE25v+v6s/Coc0RIue
         GxVw==
X-Forwarded-Encrypted: i=3; AJvYcCXDCLW/Ic58wc/8dpabOCloX+ip7IwMY9PBgnzQ8/1GqIoOGQ6nbTmJQ40DLJqp91dXQuXErQ==@lfdr.de
X-Gm-Message-State: AOJu0YyPdMDUlEci9Ck65D65tdCl0wtruFqFWZUzEpdkb0xcZ69HGuP9
	cA2H1f1Ym72saZWl16KvgZh4rBJL/LOT6TBOGJencai2qTvWsfW4nLy3
X-Google-Smtp-Source: AGHT+IF1JlKBAn1yPq2ucm8qdKlD9n5wYPlC+NNX/1+s/o+ytJV/9UFJHkYMj3kG6pXofWCFF4kwuw==
X-Received: by 2002:a17:902:f707:b0:246:115a:e5e6 with SMTP id d9443c01a7336-2462ef4962cmr295353345ad.42.1756343910064;
        Wed, 27 Aug 2025 18:18:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfOYXkwK0shZcOE1IN+P/5RiNORabZXdtpP7Rx5uxVi/Q==
Received: by 2002:a17:903:2845:b0:240:9e9:b889 with SMTP id
 d9443c01a7336-248d4e0a518ls1830025ad.1.-pod-prod-01-us; Wed, 27 Aug 2025
 18:18:29 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWyAvXxbsl34D+i92Dn5qNjWsVXde9f46Ptkbx5LY660fefDfF+i28MPTxezamW+yt422i1xpAnTwU=@googlegroups.com
X-Received: by 2002:a17:902:ec88:b0:240:6766:ac01 with SMTP id d9443c01a7336-2462edc0134mr317280115ad.2.1756343908704;
        Wed, 27 Aug 2025 18:18:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756343908; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZgHEf97cMm/Dl8ygaa996UfFnfWocP6RvwnaPUTnTnmC4TYJVXuCnRxhprTfuJFXVn
         S3n63dlmoTdUPl4T/wTI80VQXe1tp5CYtXo7xR373wfmEL++yOfWXokstQMz2sYhRHtc
         Game5oIURkeCR7LP+MyNryJeXS7iygPkljficzD94eVfFHUPxMOPYNPqikeMYI2qUDLE
         QgI3NO3oSNwT7zOfNAIJL3ZJyzr0szv6ssElQuL55Q8ZhcJr7+sCY4VfktVosFAfHkDU
         ydEHY10mA5Tmqzlh3R+SZoA5ekYIqIEDj+ZnC07UpdIxq6o+1nNtQMFJwhtvDtOxt1ox
         7Oag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=f0z0GspihNSSfeTybTglosJQYVAZScewsE15DFtKC2Q=;
        fh=mkkYPuurUY7GUu5MdEwXZN672Dpu8wx5Bk7gstqa7/Y=;
        b=YiWhOoR6qbxHgkctcI0Z/YlLC6VOvSoY/USUtsGhmoXc1U6fUTRE21CTnHnTOhnWkk
         fX9UpQd/ZWPkgJxvevXvKozxGF3r3xJ2rXoyaCNKJIr+tB97EnHUKNvn+K31xq/lCbn0
         hNMaM2Y4VnhCeuW4/ZqShq2b72+byjgjnZHKRowlo/Wa7FQjo75tXfn51iLV/ash0yJM
         Fr9uHH5rPuyBBfuYGl/gnPmqKVRTAOqZinwpXaTQBZzqukXnFMv8v8FXjawNlPJJAtCX
         bTuCjFp/huMBfjEYg10/r97Hevxia02qYZSS0Ga6qYqF4VjQg5vkY8cwGE0E+bTIQozX
         wUJQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="SO/zxCy3";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2412::604 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (mail-mw2nam10on20604.outbound.protection.outlook.com. [2a01:111:f403:2412::604])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2466884ab84si5578445ad.3.2025.08.27.18.18.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 18:18:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2412::604 as permitted sender) client-ip=2a01:111:f403:2412::604;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RP5KFazG5jt0wRDpY5RUlYPJeRQ1i0iTWQTsu5rAGB2yMLjhWiVNoubqnQJHdxkskQr6MjSNLPf5R/l4aaR3lzokPPXe8nujnQmUh76tpFy5CJVR+vhLSpyktA+OuNjMey6gn8aJ2czUXLqiSiRJDwhHasDGDD60wnLqM0mzb+6QbBCvpUDAkIVLi6bg+qAKZF5W7S0RPNLkqW9dPKPeO34pWbUCrZTHMroC31wgqHo6SDrh1/fR3t9ZhHQvsIRd5MQ9/H7uoiUnCkY8nXgCt4nL3M6ck9yEC2piTIJaEKOlCyxeCY9noZcGQNEUxlceBmJjkM/Lr5TCxZ05T8sQuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=f0z0GspihNSSfeTybTglosJQYVAZScewsE15DFtKC2Q=;
 b=UHIvvRpYJgCfQ8VxeuBp+qe/WcxTzkoUEZQ4lLDhu5MT6gmLBN365eKTRAGk1ODbqH4jGRif8jdQgeIW5687g36hU9gyXuBk7tbesjnzcOYgNTX0+twhOgWCN1ucY8BnfHtt0HZKO9NIWvCS9UKIZc1gdcFHWd92stchW8cuyy7VP1GxIMBw5nN93+1+3YNKwKQwfmJKjwOQuinAgw0z8Ypbhi8gW0BWSRVX8cuwUstiJG7ocIF2Z7sPuLmowmuW9xtz5dnp3viJ+c3SNJMqe8jj0PUxvkVNk/ISDAPBfGQi/pdfurm+ElPbdYoGakhDng3XezUeZt2Ld1nzAQwHhw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DS7PR12MB9473.namprd12.prod.outlook.com (2603:10b6:8:252::5) by
 DS0PR12MB7825.namprd12.prod.outlook.com (2603:10b6:8:14d::13) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9052.21; Thu, 28 Aug 2025 01:18:26 +0000
Received: from DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a]) by DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a%6]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 01:18:26 +0000
From: "'Zi Yan' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 16/36] hugetlbfs: cleanup folio in
 adjust_range_hwpoison()
Date: Wed, 27 Aug 2025 21:18:21 -0400
X-Mailer: MailMate (2.0r6272)
Message-ID: <22900121-30DB-4A1B-88A2-E3D158E009E2@nvidia.com>
In-Reply-To: <20250827220141.262669-17-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-17-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: MN2PR06CA0025.namprd06.prod.outlook.com
 (2603:10b6:208:23d::30) To DS7PR12MB9473.namprd12.prod.outlook.com
 (2603:10b6:8:252::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS7PR12MB9473:EE_|DS0PR12MB7825:EE_
X-MS-Office365-Filtering-Correlation-Id: 011d6e5f-b108-4c67-6566-08dde5d0c9c4
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?anuDnOeBHohnJ67dJqfsbZG2Om5PvfX2R/G0mJZJutrEWiFCJsCoNoNBTXyW?=
 =?us-ascii?Q?Rx1OGMepNnj7VQdMMoT0k7OkLbyZr1gHVvLBYUjMqnYuIgMujFcsg0S6hVTe?=
 =?us-ascii?Q?bzR7Ici2ncRdLv6Z8w1JKbAdT/5SxJs2vjEm6eQBOapBZHH6pTX4qr7Q4fDl?=
 =?us-ascii?Q?FOj77WVwottXVSharV18MyL4eXuFdEUCQ8my6kHchU6qrwjwZq1hIxE0nzdW?=
 =?us-ascii?Q?w91lfBgk9xI8RWHAGwTkwVWHMuloM+LIM5dU+M67FjH2hcWOQWjmBpbTvgGG?=
 =?us-ascii?Q?GkTVQa7cYY2FB+ghC/pDnT44NMsVeiwOSuFTANIuXMbt13Yj2uWAbauO+/Gh?=
 =?us-ascii?Q?TVzM2bGiwFDVcGAJHR50HjSgCqGDKlsROhurpiOn1SE51l+QCutcvTDPn8cF?=
 =?us-ascii?Q?8rwhcDp/6QD/mOy6TeILTGBmDp4GQjhowCx2QrkGxcLBUL0xBZnob9hKr8fe?=
 =?us-ascii?Q?wAYiWhqGcsOzoSnAlZAc4eVB3w9I7BKQQX1YwZ0RaiL7LF5Fizf0w2lyv2ek?=
 =?us-ascii?Q?9t+zxb5WTK6umfui9Ofu2xuL9eFds7tMW5hz5VDbDYRQS6Wjr7lWvsGe0AiR?=
 =?us-ascii?Q?zZnLOIU2g7QZ4ypzDRvdCAkqU93inPkFUjfolL7LS4/rQbKi6uoBFEl+4FWK?=
 =?us-ascii?Q?XuQFXy+LH0hbotWnxMYBQLSD0w/w9Wpdt7adacB8qLn/fndN5wV2MwqCda6X?=
 =?us-ascii?Q?ZbjI3p2rKEBvsYc7ni+p9GEpPG5YfQgiAeTgqUO9ug0rFOGR9jg7XHcyt/Gn?=
 =?us-ascii?Q?6Y7eSQ2OdXQa1c7wPjunC0/Shnn/zr1OxTDP2/zl91sxmrhhrfqh9JdN+5mD?=
 =?us-ascii?Q?J+SEl96fE/LqLmAPrIIXH0qbRIx5GtRqbwORM32K4SArsBFNcmFnfSn4jZO1?=
 =?us-ascii?Q?sxLixGlpueCTjj9dkz78e2/H1I5ZIm+oFqMSAyariDHrC7C7dUnp4TlT6Pzn?=
 =?us-ascii?Q?CkNvy0oQb3VIL6XGHZjB9r0oMzmJdqE1CZsxTVpTrEzKjQLh9QtuBKlvwT2f?=
 =?us-ascii?Q?qB7XqnsFQsJFGfAk4Qt9/usPAQArZ2RWRc/S4RQBFbMQyoLm/YziX0phPFEB?=
 =?us-ascii?Q?SA+h9yZ4phYgY4madHtpR0FGTW7h0KhfOkJKPzjGT4RAHzj0wgRWKI4kGKb3?=
 =?us-ascii?Q?GYzAhPVZ1DqSYuaSgl+MQEw43YVrD7dv/852/3c1Atx7/hOck3Bznh/UTBpW?=
 =?us-ascii?Q?TUcns7lE5UkL2Xsi+Hjssr+2/NS61gmhxboqIsVeErciZMN1TQciROeM5dBJ?=
 =?us-ascii?Q?srVs0FffB504LHiJH/u+ykPhLFaA2dkH/fu6qRXXVLRhegHzVkObgc7JeoIY?=
 =?us-ascii?Q?L1Lsh81F7hgncghVIxaUJocmHCiXRHkQkhRb9uqm0f1IEYAKv7HUftdJQtvP?=
 =?us-ascii?Q?PuptyPRpzwmqVHCC2gJJCpo7CUmRBWlUomx5wlnjMWSfXKGTEUnYOHYpkrGZ?=
 =?us-ascii?Q?cXt9GYvfqVo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS7PR12MB9473.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?iorvuWOtIzYyTz1Y5tdMMXd4HQLh73OM8fEEUVhaCmYH+a3Fwm/nwXXAbYpw?=
 =?us-ascii?Q?zZ0y1Z3YhMqi0S+ghhB7C5/cnQKvPSHYGkl+HF10VtayOYFw3iQzALbJW4wo?=
 =?us-ascii?Q?pYegPGgjaMSqDDOtlOk4dsou35D/5WCGZV5s4sguq4dYRK6RbfD1aToVmctx?=
 =?us-ascii?Q?axyE4LRVgUxSiun0WCndPOTIndKRmTAKMvCMuSbS8PJKYVU2EyCxRu4/4qh+?=
 =?us-ascii?Q?TumGsAjcqY7vCnaDVlwuZHG5b/VrsGKs+bimUB09vZXq4LpcxISdXoQwJRWc?=
 =?us-ascii?Q?2RjN8IV0G+EQmOahufcFwKxZAgogkp/eSbnfgnZVgJP10SK98e1FtGNic6hv?=
 =?us-ascii?Q?FAXnClYBjWZqR9+rpOjfAGDk495pdgW+rHAifqxt6wgbDO1akIlHA8KBXONW?=
 =?us-ascii?Q?NVjEgPdX/JU6k8dOwHhVyjTYI+uDT8FMavojfaiEA8EDvcUrw0T9a+uStEOD?=
 =?us-ascii?Q?U82IijIw9IDkN+hLEyiDxa+xQHzSLkfGKD8w/GHtXFAO3ByGGXVmhAq9M0oO?=
 =?us-ascii?Q?GkpCNZr4/qayC3wlb3vFYQ5SFoGoNZ7Qpql7Er5DuzKHZEf3YWLRzZlKjvfa?=
 =?us-ascii?Q?8hPXLuXsDHKMGHbr6hHUKXTg1KldFH+y5XJejBJtTlODsRRw2Co/JzD6aM/d?=
 =?us-ascii?Q?3kIjf/jIKAZ/muS9votPMhf5tt4bTee7IHmur4dwux8Qf6HlXDEoAQyj07Y4?=
 =?us-ascii?Q?gDkUgKugZ55IdL5d5r61I1E4lmojpC3bWGuZQvCPhiJSYkXyLMYdKzcAEAVb?=
 =?us-ascii?Q?pT0C624l9s1VQtcgfzPq+m9fdVtuQ2IKzbQlxGyyoj6na0QQZnfICcJv3zRY?=
 =?us-ascii?Q?VkgwXGO0Ij8+qhkoWH+0im0X7W5/WL2Ijck4fKtjzDxLnsY/XkjgHGCa6xte?=
 =?us-ascii?Q?7zT8Ys8FZUd/KZ9BiuqLQciO46tal6/qL0Vf9vQSjFt3OMYkHIyZeEOfydq7?=
 =?us-ascii?Q?aMsvG5c276Qp7DH75alL4y7WA1KmeYhA8LeIfZN+sER1eGz6bPxTlroQwhoK?=
 =?us-ascii?Q?BAC75rSWWGBjTE7YE1ZbGQDR2Uz8N9d+XtPjYydyz++qAJr5upYBouiol7go?=
 =?us-ascii?Q?RaLNaA2wJEzf1d5r4uS7KUzu5Cqkjd9Ak/bPhlIVrdhWC7qqixYmt+dy77QO?=
 =?us-ascii?Q?I+NmXQtRnb8E3rrHJsDvHRsXCIQYAekr4J7ckmX6EIbpYHcBueVAWvRV38CQ?=
 =?us-ascii?Q?5JekFs2UKbU1cLnKGJuM/R3c5Tvpz/srbrZcu7GHHb7ZcAeRxOjPvTyyppB5?=
 =?us-ascii?Q?6S0mpd5xyNopp/XNmyESEpTnLhQ2xr1uBNXdceXmwuXw2uapGscVRyl8DG02?=
 =?us-ascii?Q?wFiQoQg0PA6YGjxiHzghYhQRjDfvI3/7DxrGr9bzgrELZbdei6SEP6+QwfE/?=
 =?us-ascii?Q?N3wzIpbcTCyKyz+mb3sEtLZS9RurDFdRV21Wy3t8qL/vtngaB5EqjRQiDy3R?=
 =?us-ascii?Q?7WH/3i7ikwq94x/4dn3eB1kS3XiGAiqsfZdzKDxZ9uYoKta1pwOT4MiqhYDU?=
 =?us-ascii?Q?DCC/NXY6ENfbLLd0BtNu/Wly45mwvkbn09u7zWYyWxUH9mMCmITO2N5b/vjY?=
 =?us-ascii?Q?J3ofjQx9O3HVICBIjwo7bsNUClembdhtDvQiI8Z3?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 011d6e5f-b108-4c67-6566-08dde5d0c9c4
X-MS-Exchange-CrossTenant-AuthSource: DS7PR12MB9473.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 01:18:25.9047
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: UF0Ue62x+n8oaTn5s9htiLbTjQUtfbOemw40/1mhrxlnWfwDqqZWaepMNo7yAr8j
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS0PR12MB7825
X-Original-Sender: ziy@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="SO/zxCy3";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of ziy@nvidia.com
 designates 2a01:111:f403:2412::604 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
X-Original-From: Zi Yan <ziy@nvidia.com>
Reply-To: Zi Yan <ziy@nvidia.com>
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

On 27 Aug 2025, at 18:01, David Hildenbrand wrote:

> Let's cleanup and simplify the function a bit.
>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  fs/hugetlbfs/inode.c | 33 +++++++++++----------------------
>  1 file changed, 11 insertions(+), 22 deletions(-)
>
LGTM. Reviewed-by: Zi Yan <ziy@nvidia.com>

--
Best Regards,
Yan, Zi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/22900121-30DB-4A1B-88A2-E3D158E009E2%40nvidia.com.
