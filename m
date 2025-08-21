Return-Path: <kasan-dev+bncBDWMT3UBYINRBNEAT3CQMGQE4LEHYWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 36FFEB304DF
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:23:18 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-e93427a1c95sf2180039276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:23:18 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755807797; cv=pass;
        d=google.com; s=arc-20240605;
        b=dkolrWOR2qfpwwQx3hKLA6zdpIgTktwdy5zcTrcT78uX+DjY+KFMDRPIRa5LOgwCbJ
         /aGlfxUm8BcR36bMHNmGXrr5MpcQ8+3l6HckatW2e1CeHHQQDe1L+W0vu94G6qYRcGRK
         cGser2nElsHgzWG9Kfit46OKT1FqtOO6rL/NQAYr56GXZOS5Vw/2pE90Gr6ICKKtLS5x
         Y9KNukLN/JcIMhKGFzX9PU28bAOoMTp18AhZJABqwA0v9+U/KAS81NeaOV95iiaP1sW5
         o+5tlOUAhfjPzD+dKxQQESt8GVDGZU0aex8af5sV0nm32DQYKeb6Sh77UE1tOx9j1ygI
         Sr5g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=T/hqE3coN2lccczSVDkYojpUNbVCQVNSc46Ydg6SZxc=;
        fh=fe4cXXE5GfQW/gdkXbzoUEiXQNmflKH68HBgHmJttk8=;
        b=FVC06ARZriN04U57lZNs5mK0l8LZsrD7vfYUKTvSUyoW3SR675SHpfPi144ASCAfvo
         /qqVUGmKFHiooLRo6+La9q1nZCYwtbCi2eN4sXkpBNuzC6l7yAXrO9p7toMw4YN793yq
         iZ7a+w85I5nMAo3VGd7NfjO5NswxSpdcd60Eb8+tpftRLouhjmeHgcWP8LomTGH4+OYK
         Rwr9e6a1qsrUZJWP1Ob4jUyZsQiqpD+fALnsqMVLOwhBm2apIHN0PCHSN8yxZKCbi0fZ
         yPmp0qWhbMANyXsoyt/6U8SyxLeu6ChaAQa3uKCSoYxYImP/1ZyWxCF9dxfyCw8Cnjc/
         /9uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=MZiG0IB2;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2415::607 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755807797; x=1756412597; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=T/hqE3coN2lccczSVDkYojpUNbVCQVNSc46Ydg6SZxc=;
        b=aBNKAE9PluyXrC9mDLVOkc5dn9ZxGKLVAKpZiXBgWPkB4mfccSOgv9iKiL1bW7X5PP
         M1pIkkFC5KjT2hvbMm4+xct3/JmcXl2e9V+w+SLVdccgULWTNKoXwmGbnUR4aDOK6Xju
         InwogfMGZwC9ZQVmIvdLQXQRzNPIfUzf6epty/d1ENlSLDeJu/1pHqyBjn5ZOFFQyHLc
         3wH8vC5BiYlTZ7JM1BkuOVlAHxEuQ4712jijweC2QJQwY1Ztv8km5OWmh2k2hH781RWM
         qfZgSXX5Sz7XBMDWzU6S0z4L0P2A6HFQu63NhBSmPIDk6ryIhGNkB8pzxe/vjG4k9x+k
         S7EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755807797; x=1756412597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=T/hqE3coN2lccczSVDkYojpUNbVCQVNSc46Ydg6SZxc=;
        b=mfcC5cfXfjUk2zP8UHzLJLE3GRviFvGFKw8a6jze7AWv8oIYZNUMc0/D4vubAZlglS
         72D3BXLBpIhETnunqR+tRe/H6SnKhX6WaO9NKc25GJ/qSG0Byx7E3nx0APzOSjMtFF9Z
         jy3xAPjggU+JpctYvuwOB+2ZeNkdmQeibreNUZcL1FjVqJgaafy53cpFiBJF/xg/MSq+
         ME2aTCSlZoR5+3rFk5pF1RLLBdYjkeRRTY/R0juykuXoGieQT0k18yc4qQ5TQpSESFwi
         AicytfBxwt6AD2KEtTYWYd9umaA8CapR+zjwQCoOZWx8jzpzQjDWG96dpGAheQ7ee8qM
         swyA==
X-Forwarded-Encrypted: i=3; AJvYcCUW4Gu0zZlgT2yQ4utEvMQhn+BNj/KgZ3CqvrvfHpBMpDARgBBCCFmGhzae4tUHdO3ppQ5uWg==@lfdr.de
X-Gm-Message-State: AOJu0YxX12HTdSEfar/G07tQaPV6/C+TwzNb1/84DGvxyzcOMlWeq/t0
	p3K3unXuSLLo4sjjwzWANcKuEnLod4BwBmS9PGOVu4zWS3WENYP1k3pr
X-Google-Smtp-Source: AGHT+IHKHh/ZAfBEEKZ2c95MRwy7eKZq/t6AvazGgBcazNxkcpOzm8ogEv4i93wzo5qyIxAKSpExHg==
X-Received: by 2002:a05:6902:2605:b0:e93:3be4:9723 with SMTP id 3f1490d57ef6-e951c21000fmr924708276.9.1755807796990;
        Thu, 21 Aug 2025 13:23:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcWUWyFg256wmsbt+AK8doC7J4+gpWjqXYM4RfzTebavg==
Received: by 2002:a25:b208:0:b0:e93:48cd:3a5f with SMTP id 3f1490d57ef6-e95046dcc7els1157256276.1.-pod-prod-03-us;
 Thu, 21 Aug 2025 13:23:16 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW7yt5W6rEW/Fs8EHxfgR5Kc35KRnLOO/nzrq3h84N7Nd2NyTzjYT2yNV9U5ZyzVBbPRRjJnqFNj20=@googlegroups.com
X-Received: by 2002:a05:690c:4a01:b0:71f:b944:fff with SMTP id 00721157ae682-71fdc53b56dmr5939667b3.50.1755807795988;
        Thu, 21 Aug 2025 13:23:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755807795; cv=pass;
        d=google.com; s=arc-20240605;
        b=ksXj3+3zOYlswfUT0NjUdZoUnTJNynWqUr+PzqpBGOkMJ0q7D5WdNAjTHeGuf4Co+D
         DZ+BdevXlznOT6clriQvbyL5Bz4qKzfalk2FlH4zFbNg/BsiphPzSz8P40qY2BA46DZH
         INC99buhwaujbVKB8En48VClMchdI5/tjPgjcJfRcfOxNg/LQKrvDI/SUuV7sxecHVlP
         FQj/BCGqLda1telrlDQKZE18xJQuTgxkuxzOO3mi0O3W5Df6YtpdXWFLT5OM3mMghsZ2
         oMTN80/+UGWE1TvJdOL3ge+JBGbOwcNOoGzedaiCWWhEvcE/GCmpcinaYi7GmMet/g+B
         zhqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=WgmiAibO5FmTDZwywRZ2ZsbC9r/pbgm4izdfkPSm79A=;
        fh=mkkYPuurUY7GUu5MdEwXZN672Dpu8wx5Bk7gstqa7/Y=;
        b=g3aayVrYMmnsBlrms6aZId9rValDxuOYvmdInqWYc+ty0YC9kzC9FLH2gNZyb832Wk
         UAE+6YkDuO6lhP63rlHIjyfPKpl/iYCInKeT9fL8ku8RlaSIEQqIlfE+3EQr3AihhxSx
         8QtEoXq6QOJon9EsRupc/sfPcazHmgfvkTfj9ZUqmpJYuWzUpRxAUMHz2H23/D0FpH7e
         rhF1RCjaQV51ValfdcdSNPd/OliURP6vnog9TPCNXFpoguoZApeJK2ce8OHolQSkXQfs
         Kavl5EnIrnKfZ9QwPKBIWh6NMWt2B90HnYd+DHdaiZjQX2vWqj6UikNL/OejWzGov/US
         vK8A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=MZiG0IB2;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2415::607 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on20607.outbound.protection.outlook.com. [2a01:111:f403:2415::607])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71fa513c048si3029517b3.0.2025.08.21.13.23.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:23:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2415::607 as permitted sender) client-ip=2a01:111:f403:2415::607;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=O30FOsGVFG/gk1k6oGa147BFnCrgeSa01x0ssDZtSvQ0KVpSAiL1Nm3ZJSvqmBBHNKHjgbXy26lK6IXhwQQpLH2oyS5Gh3BqGfFyDxpye1RLxu9YWtGrp4vdSmAyoBz7WPyjKT6KSohpExt4oSquEs/Fvm8XcJ7QVxfxmdmEJBA1q5xXvhWwC8EskShvXfm9Gv5GR3liuPrdVDLT6TanLlhHAlAa6AFpLtVvkTaInMklDjD2gcYdzcX+raJ/Ao60FbEtVtHaJpY6qU2V6lla2Hpr7byGWH22r3TPkaPp6zTAG2ZthgNoRsQ5v1CPn4JRjwbP/AwS05hQC9zFmQb96g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=WgmiAibO5FmTDZwywRZ2ZsbC9r/pbgm4izdfkPSm79A=;
 b=AWaV5HAsB4p73TWokCt/T/9dmvzZ5V76rMicMchv67FdCJJAhJ3LdA+C0Dx3pyBuWymUus77CyQd1RNte3JYDBEW+SgAKSd6qxr2ty6VmAuMhGh0FIc2PqCoQyZcwsV5OdnQjIw4JMV1XyBo46/FMhMFJedDv+XFWrWR8bwyJrfxhIyLVn36w4IdVxFTWrBsppY4GT+hq8xB+S9QuY8CNQLYkkA8Bp4+bDrGdPvm5TEsFpkkXEdJj/9vOH6Z/L/JR4ptJVIrL7Z9aLtsOuksJ72HcnJVsOvW8FfBITtfMtj5k1uznf93Ko/M9PmzAi1o8ZcHJV/7ZZ17GTPsujUO4A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DS7PR12MB9473.namprd12.prod.outlook.com (2603:10b6:8:252::5) by
 CYYPR12MB8704.namprd12.prod.outlook.com (2603:10b6:930:c2::19) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9052.16; Thu, 21 Aug 2025 20:23:11 +0000
Received: from DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a]) by DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a%6]) with mapi id 15.20.9052.013; Thu, 21 Aug 2025
 20:23:11 +0000
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
Subject: Re: [PATCH RFC 06/35] mm/page_alloc: reject unreasonable
 folio/compound page sizes in alloc_contig_range_noprof()
Date: Thu, 21 Aug 2025 16:23:05 -0400
X-Mailer: MailMate (2.0r6272)
Message-ID: <E2F739EA-4779-4C4C-B4BE-76AC64B42EAF@nvidia.com>
In-Reply-To: <20250821200701.1329277-7-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-7-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: BN9P222CA0028.NAMP222.PROD.OUTLOOK.COM
 (2603:10b6:408:10c::33) To DS7PR12MB9473.namprd12.prod.outlook.com
 (2603:10b6:8:252::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS7PR12MB9473:EE_|CYYPR12MB8704:EE_
X-MS-Office365-Filtering-Correlation-Id: 039e2a95-75be-463e-7dad-08dde0f08c84
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?2SOcjnvQ1yc8CYg8StAZLMCyN87BeaFK26J6AIrwdZ3OW+UWJgN801R3CUkM?=
 =?us-ascii?Q?U3pK1n+Wh7pW1XAuyED4fbNqncdJj/4gtlqibHT7kXLeav4+7Tj2LlGRwQUj?=
 =?us-ascii?Q?a3Fj+2DExo7LM5jEXZJKGjv1xU52PYZH2GrXI03bzX/3FPvKySauplSz9Lwl?=
 =?us-ascii?Q?Ab4wAGTd4ceW2WbUg1HTYrkp7zkNcm7U0fkv0RaMcNWdBOz8X91EJtE+UjC1?=
 =?us-ascii?Q?Gne7xhOI+XxFHfEP7HPu0NVTr3McSByMyT0c9IY7BzjLok/0FGqPQzuSUnGJ?=
 =?us-ascii?Q?ODP6GOisgV8IITn7xeFMdf0COYYHgykV/cxmUjQoloc6tcKOQFmu4gu95toG?=
 =?us-ascii?Q?4PfY7IC1sNdCpn6odiU3I6X09TWaOrL0FdCmJW5YlqoODFGWg4RIran3uWC5?=
 =?us-ascii?Q?cjUDAhzvss7eVYXgGcWHG0bk/0vr4umZu/OIIJXU+alepldeZYwthwCdCQuQ?=
 =?us-ascii?Q?s32bciYM5g4rvWzafzwAFKrI2YOuTbzxedOnSUJYAJwQb+xskJscWe6VDrDc?=
 =?us-ascii?Q?U3DZelFs6ijSxo0ceB5DKh9m6IcVuvpRGXcWSYLR3NazP2EROl/gKGjzIpox?=
 =?us-ascii?Q?84qEVs7ToGiARIo518v/wzNgNgToFcSkfDLqT9QuYGHgn8zB77aLR52WQhnJ?=
 =?us-ascii?Q?x500VtWduznBGQQ6a2YaGvPpKkcuaipEZt5eswX6Z7TbiySM75GnEZHI9sr5?=
 =?us-ascii?Q?63HbpLWcHe5uJj1MMENCzVCWwvmXTmbkzdyj3mz5L8Rzs4aOEPewYtrb9USO?=
 =?us-ascii?Q?M18yFMq31MxnONUsKs/kU/MDPAlQJrI2rmNyRF1Qv9BBvhziVc7ApCUKJjpn?=
 =?us-ascii?Q?CsZawx7m2RqQZfnmPPYBw/9XrKVub9uelv+6Eil+Q1T1raAzO2q6Vje3RsXF?=
 =?us-ascii?Q?h4DJcSxNW2c6vc4dscS9LoXsOGhWdBBzD6MBmXDP/ryhiLErw5FuRRfxvqSk?=
 =?us-ascii?Q?ZbAwhgD6i+sc7Kk7CgqAP5VYAnc9MojYgqzxTGmwCoAo+mTxkqOEiFRXxLUC?=
 =?us-ascii?Q?2KI/DQ4DT3cscitkbbeOpigPluGCWQpT8hoUgRKn8OBDUtNzx0Rr7bDWBaKT?=
 =?us-ascii?Q?srEHLHl8lVDZ/VW+QiEMDDZblVF29FGzOrVSz+LJ7eB8vsEqrW+E0InWZwlF?=
 =?us-ascii?Q?S6PAVUr+vvi+y5ogdcdvnw6oMyg2e+SiQZiEeFHk3aP+F3z1L3DyGZS8d2eV?=
 =?us-ascii?Q?Hdy5q5p34rKnpFJYc5HdClg/h85vOZMkrLN9K+v7MjYu0mMoX0e9yqyZkx5M?=
 =?us-ascii?Q?izWTzP0oabvbUEgFy28xJrrb/jGqFV37lczVid1sgj8KGsh/Stj4D58U69Wp?=
 =?us-ascii?Q?pbo5tGJkl15oOtSf90C3RBgABc3LC8ClNZCPjjK26XLKCVcoAKS66f0o+Iu0?=
 =?us-ascii?Q?XmPJoUJTEkNCtCe8Y+RwZ3pwV/fpSL40JS1G+uNHguzd1hOeQW/zWxC7yR2A?=
 =?us-ascii?Q?/YkNMLG5vWE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS7PR12MB9473.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?S2GqQDZvFkJz43+K3qaGBIwLEm2BR5AOngTWzbbIW6Yb++v3CG2aApiWuoAA?=
 =?us-ascii?Q?VUvtQohyYeJknrmkTQd84aJICtjYWZp+v6tG1OQY8YCYVS/V4dBt3iL0zHal?=
 =?us-ascii?Q?96ziL38e5fhh0JUvGlDGD2vqe2V3LKMcgVgezw9OwdfBnFyUufGulinAeciu?=
 =?us-ascii?Q?fD5ju4Yj1qdodWIDkLI2fB1GL1/z4nzI2CuCqCQv54o7yGV3lg4FZsEbbT/b?=
 =?us-ascii?Q?x9WmcxZ5/L4G7LanEyKE/Ebhwl8Cd+saQ8PVubu1sftDJ6Ok+wNx7FF11Prw?=
 =?us-ascii?Q?9JnMpO3t4jyX+l4lHxAfzrB3pHIneVSXR6EMZHXwmI8iAT+pBPQ6H//ZWSi4?=
 =?us-ascii?Q?rq8AwaImlUZ5iMnO+GJEO7wcDXxu9YmIh6UaIWJl1ph5RJiDx3xPFw+cXyRv?=
 =?us-ascii?Q?BfED479qTRd4f8i0iu50CbJvLhhjDcN/an9GiM6dNlwf1n4Q4dI57ZnnuhBp?=
 =?us-ascii?Q?2LwvizgB0SlXYY6JjjkbhjjH6xp+MfCcTQx+aExSsvLjc/jj7sKwOVq4lvRc?=
 =?us-ascii?Q?RHXUKIop7tJlDJtkoLl06scUoTWoldGVgtryBCVUrNa68axTNNQAAeWYycex?=
 =?us-ascii?Q?1ZxJ1WzoQiiWobngqTFESwkivI7eQiSFuoIMMz4CFfVkyqZI26P7NGD3Udwi?=
 =?us-ascii?Q?89Ajcl3UUKdcAAS1VPDD8dalFHaUYlqQoAAiq4+JcjKbzf7+fE/sQnjyi3vM?=
 =?us-ascii?Q?Va9Ydc6dfisNr7jPt+swHml/Z6mENJSDMOcVObQWiechwiLxQj/yocfWsam/?=
 =?us-ascii?Q?kKbpOs2CmzSN9m3XvcSf/mw1GyQ/BjsspjjYgKhelPyPYYIanyPKdN9OcIyK?=
 =?us-ascii?Q?S5Pz0BIzWaNNi225F0ojJtpP9RAnWAQw80xens+/C/gDUvyNIotB/h6v62d+?=
 =?us-ascii?Q?Vj1M/8qZ/Tr9y1VXUEn8qloydfSXdH8kilS0RE+5I3zw4dulWB4v83f5Jz+2?=
 =?us-ascii?Q?iBQ9FE1xbbhszwUGeeKj7hXM7b2V1x1mAvMH1yQvXMnNaHfHGppy0wpoj2+a?=
 =?us-ascii?Q?+jNJGSm55uCBUrbBphh/VHP0JpjQnXeL7qQgDhoh+40FvHDJRNGzNuIRx8ub?=
 =?us-ascii?Q?3EwGIoDjEHMp0Kqy+jBhAbtS96mmOJVfggUncxaLlIU5TRmtGC+9eQzoFbtT?=
 =?us-ascii?Q?KFCTA7APz9/9/8JsMBvRnDIFq9IXSue5QmXn5YdrjrdR7uw7G0ppq1kCp0bJ?=
 =?us-ascii?Q?Vv3FEX1nw2HxGw4DUZ+MepLKFgDDI8RokTe70VOyypQMw4XERpAe2jFkrOV9?=
 =?us-ascii?Q?oRNuNuVi5ZRiH2HnuoDP2lIFDGcGvVflz/kXN2Rp3oD48sOBYiZGB1a+KQl2?=
 =?us-ascii?Q?P0kb3vZkqPgDwPf7Z2H4HeJX6T7X0idfZuyeWfOdO3tD5dyWB6S7axACx3Rg?=
 =?us-ascii?Q?QvsJ7h3W5Lxy9Gho4ojaPlYzzJxn3HIoKv+31YLNeH2kTrYDrR2Vsnu2ZaOG?=
 =?us-ascii?Q?sbFt2COziGbzDW87XRwXnoAxgLRtxCehUrHZbLwQDq0FUmxj/Y5oEAM0YAIN?=
 =?us-ascii?Q?0vQIrYOWfZDjIgfSEn4Zysg8Sd7/bA6MrkgiOO+IwdBJTmeALkvirhrgXOR7?=
 =?us-ascii?Q?j3Vg7C2LFLgFs5ZsH/6U0x/MjWTcF3orvpGfFj7D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 039e2a95-75be-463e-7dad-08dde0f08c84
X-MS-Exchange-CrossTenant-AuthSource: DS7PR12MB9473.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Aug 2025 20:23:11.1958
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: sTerHDDlxLFxjl7Sd9flN9RH1j2PaxmBGjwEz+JX2CPWfBdtkFsdyO8NMiWs1ANy
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CYYPR12MB8704
X-Original-Sender: ziy@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=MZiG0IB2;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of ziy@nvidia.com
 designates 2a01:111:f403:2415::607 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
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

On 21 Aug 2025, at 16:06, David Hildenbrand wrote:

> Let's reject them early, which in turn makes folio_alloc_gigantic() reject
> them properly.
>
> To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
> and calculate MAX_FOLIO_NR_PAGES based on that.
>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  include/linux/mm.h | 6 ++++--
>  mm/page_alloc.c    | 5 ++++-
>  2 files changed, 8 insertions(+), 3 deletions(-)
>

LGTM. Reviewed-by: Zi Yan <ziy@nvidia.com>


Best Regards,
Yan, Zi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/E2F739EA-4779-4C4C-B4BE-76AC64B42EAF%40nvidia.com.
