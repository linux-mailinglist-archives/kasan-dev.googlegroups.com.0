Return-Path: <kasan-dev+bncBCN77QHK3UIBBMNSYHCQMGQEUCLDO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id D54AFB39ED3
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 15:27:14 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3ecc8a40bd1sf22156165ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 06:27:14 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756387633; cv=pass;
        d=google.com; s=arc-20240605;
        b=CGespzVy08phLQ+QA9I1opsRTSahpL0s2C9+o/ArTjXdECr7GnwQa0e/lm8BXE7rNU
         mQafmQ7wzsV4Xt6yTcbns3WJAhmchDO2HVWESNXjHs9j+JziSC2PsVA1eVX1jnlHwnOz
         ykr9k0FUuWIqvJhIzzZjYC4l6d4VgL9dVGW51ACuD6sKkmTM9AGIoGRochGxUj9ewbf/
         vjAZ9kdTJT9oJFGxdj+x3RNsb+2JofQSZI+O2D4wuzbAsdqc2mrJYUxVJWReN8fu3BZu
         FjPiwuzywslAWtZcyvokyoPL7+gOP0mnU1LGNfzhT9AxVQe53fuhYRxvEDXjgOzsdGGz
         up5g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=M7ByHWYCKyqYzCHswptL1WADsM7CLJNqGUCup3NqAQM=;
        fh=N1KpN2n/+0UhJX9WYqu+xtNXWViqMTqpZiusYSD/bAE=;
        b=FdtIRNkkI5/XO/K/QIHKWPyxWnVPA/FmMrgf6DtU7S4RJ3B1H4lQwhliV/c74Huewp
         gWkurcON2RVJdfOYb6ZXGh++pg9wnjL35YCyV/yO8lPXpZj2UdT4fZ6UsR+6W54N705G
         i7kSgmIxjWTFAiUMzIHjl7FXX5Bitk5QlXTaeoDVG/3mOxi6xrtMV3MrR1zet8PejfkD
         KQbCiP7LgjRXxq9EzqIKHotcsdS44IFiCZRHtxAl3HkhxF8pRo3N/R+K2RXhmxhe9PtJ
         fPjyAFoGWD4v+w1W+86FGIYvZE+etBHc2+wmwOs6OQb21BWvK1xQz6UwUUb7reijXAbd
         Mj5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=rQpn04c6;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::62a as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756387633; x=1756992433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=M7ByHWYCKyqYzCHswptL1WADsM7CLJNqGUCup3NqAQM=;
        b=IKByrRQUu9Kg41+KpWGWWaU4gXC/rn3vOk3kUEh1hBUm1z6IJ4njtlwI9Wqc63cNeO
         gQAJJTZwAt/QIMu0LYVnbhPvheGlqNAOFWm6R1U9hZnTm6lwTdQejKJZ5opCR/spVXv3
         j0zxLGMArO59zdsiyxV2Xci6c1VMO5Qz9XbS6HT61VkPbITaovVhSNLXsAGVQ/wPW5sG
         q7VMxOj2EQxouSPkYeSjkFG9uHorkZftGQCnJvIQgDcwg60O2W+gu3uqNrnQKM/lhA9Z
         LCFppvEfQ0YBG84XzPDXuT0oO4pSD1+5khvhfMRNWz7bCYJp4Hwygdc/vQHEUF/wy3U8
         vs+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756387633; x=1756992433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M7ByHWYCKyqYzCHswptL1WADsM7CLJNqGUCup3NqAQM=;
        b=v6eXEpZgDeA0CKaAywBmLNI9jjCO2EL46oT98Gi6tXH/VWnaOpyS5/9UiMXhGyPpy1
         +JrTrBQ1Ia00RmMPOMAk8U+DaAb0rr5b77cpW7cJJX4Y49usvI2dgeJP+NCjnq1D3vXy
         cBlqHlKpNtM9i/VFg6YRbgQgXUd1hpAkU/T465CZEBwZpAO2cuRu96pBpWZxq+cmDqUE
         IEY+x+GfuD5dhj6VGOZGthONKUsH+507HMKMc+DBSmkfXQjNywj5E9Co7JUp7PhD+UFw
         6dAB7KSrBoiw3btTm7KsTbeD0gYKzhsO2q6+nngncLr+WSUD/6fm8znHSL0Z8wArg9qy
         hHgQ==
X-Forwarded-Encrypted: i=3; AJvYcCW15Y+Zqn2erV5JlliCaFGxgpKvY+4xbLGe5Lwzk553J23yEeFjaKThVSWvz2DQ6vsxjDQodg==@lfdr.de
X-Gm-Message-State: AOJu0YzJ/0yn8+woWh871GSucrlVcEwz/1/Z7pxP3gxFix+i2ibPXxFw
	v2X3OHshaPuNsyObOazH5QGjliTxaf6pbifPSJLUP1aah4/dTlCl/QpG
X-Google-Smtp-Source: AGHT+IE3ptuW4HHawc9n79ddHB4KF3c4BDGMfSB/MMP6BZC3KkVWHBq+acSNPJcNOyRxCWlWSYFkSg==
X-Received: by 2002:a05:6e02:188f:b0:3f0:5ca2:1f1 with SMTP id e9e14a558f8ab-3f05ca2134dmr81043385ab.18.1756387633477;
        Thu, 28 Aug 2025 06:27:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfl8bB7PzLu6DuQsqEeZk6/scmAnPDHahxoMXMk/AiTVw==
Received: by 2002:a05:6e02:1194:b0:3f1:2181:236c with SMTP id
 e9e14a558f8ab-3f137a63beels7770165ab.0.-pod-prod-05-us; Thu, 28 Aug 2025
 06:27:12 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUy+MQ1WrNV0U46bcN82HkqpNzObaHScXDWeFewWN0cHAhF30e3girJXe8XwGCYQQFj2njzzPFedFw=@googlegroups.com
X-Received: by 2002:a05:6602:4087:b0:886:c49e:2837 with SMTP id ca18e2360f4ac-886c49e2b92mr3155359739f.18.1756387632452;
        Thu, 28 Aug 2025 06:27:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756387632; cv=pass;
        d=google.com; s=arc-20240605;
        b=b6upwKeZUa/akm+L1ZhF7b5SRlesywX5n3cbnW/OBLtsFGCF+t23B0NgFQ2riDPvF+
         R5JKpL5Dc4EbalEihpaXWUJUEeOvxp0FGhNCbA4QqNERRMRccPMKLnigy1iZXog3OQUo
         sm3ttDPYbA3Wu9HEYQ20LAmOIOnpmogRAGEYNLDVvYpJh/ovs6o9w44EcBTGI9AfiMkF
         uyDnAqxnBob7JFTpcDEDfSHRGxjwl6KdPlWz3QdPKBibnm9g3Zzlbj8pfbSCkW0MnE7k
         RaadYdN1mpi8vnR2/+DFFMGiAE2nzeqPGyNZLE00zG5rLw0buYjrQQr9F8k+87jfWWRV
         Bm3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=TLwGmU6h1uV0qCtV4HRWJIIn0VTSZ/dqI+IK434meUc=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=g8cWbCIQANs3gBKZoiWe4fG0nH1eqWzUv+/dxPHp/aea0fpuQA7dGEOGIZGfCzicuS
         kMpF7sPxU4O9muVnFyodAlvhik9gbzwjsQURJRKQOy5Ik6c39mtmcRe4hQm2tmq+NyfB
         dpoMkQHt/L0bhlWrd5NCjdSVMrxf0tPZDYRqbT8Jq2JCMo4y2Lk+CMSzBpiJ/djquSWA
         Lcaj+wI4pIufNF0//d7myk9qcXnj6z2Dupa8hSoIMSrz79lZ/tE+pRBZlCOP3+IhFsLg
         1yJfvsMaIW1r65+4bjoj8If2lbiyyxiw33+M1vJkiK6vufVCnClML7k7zhbrXwX5kQYk
         gpYQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=rQpn04c6;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::62a as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on2062a.outbound.protection.outlook.com. [2a01:111:f403:2415::62a])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-886d85baa27si58207339f.1.2025.08.28.06.27.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 06:27:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::62a as permitted sender) client-ip=2a01:111:f403:2415::62a;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Gd9eEAx6A2rAYOyJozqfEX4RV8pU71nHjjF8ahljVKWx1NQMvRardEdElvB/WLJWdGfh1iWphfsop7gmU4O83xGqhwKe9CMp2i5e2ww7gtcmDzTPUhIKFGmVqq5F2Y/aY4iyTFcqZReAKNjmRMEtEXVaenDa1+AR0NhN6rqkys7BYzP5lU8Jxd7NWmd9eR+pKxlYB7YeT/MTZ9ecVbk4NAIjOvBSqjE4QBOl9F8HkU75w8bfq2ymm9BUHal42r04VkHnkOsARFDL4T73ds0O89kh1jHQP40/eugTRr53dwFEuVUo2NbjhoAq98tw99MHu0qQEymri61OZ8Pg4KEuEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=TLwGmU6h1uV0qCtV4HRWJIIn0VTSZ/dqI+IK434meUc=;
 b=coRESzXsKw6oIUoaQOkD/Z2Hb/qmwWanRcWqsFG/bil84hSJg2sWTljACrFB20kddSUSHDJ6RDvQNZsJJNejQE6C3asVyiCy+RLXL+nAD+VZSxLSgOlZ0KHoCmX3fmjAV7NWkAZ+dWR5dwLYJKd+2REngROjN+WlYAdMbdJ/yBCKUX/ZvH0aLUDOdwqXs9oA9IM9o/xgthMbD6qAQO395y0BF4TGMKTzBqprQ/1AoidryjoluftRdfCK3fGNLWuZ5IbImpCh2bzBeEjm6+zxXvLIN/yqrFhDKd8maQ84tmqsPUV3ig6nvXgIt9BcnHnGm9yqB6EpLk/MPpCEITFOMA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by CYXPR12MB9280.namprd12.prod.outlook.com (2603:10b6:930:e4::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.21; Thu, 28 Aug
 2025 13:27:04 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 13:27:04 +0000
Date: Thu, 28 Aug 2025 10:27:03 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Leon Romanovsky <leonro@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v4 04/16] dma-mapping: rename trace_dma_*map_page to
 trace_dma_*map_phys
Message-ID: <20250828132703.GC9469@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <d7c9b5bedd4bacd78490799917948192dd537ca7.1755624249.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d7c9b5bedd4bacd78490799917948192dd537ca7.1755624249.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0293.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:10e::21) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|CYXPR12MB9280:EE_
X-MS-Office365-Filtering-Correlation-Id: 297629e9-d6a0-4274-26f4-08dde63693cc
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|366016|1800799024|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?czdNvlljPZsTPbzSSuugKdYWnNsYJthpm6ajyxrlWHCasD/3QUWoECGQ1E0T?=
 =?us-ascii?Q?jRhPZXNnjd9X2r7rXqWMakMIm3CMLyQzWXxiji5gNdlJvrMkg9r2sHbwk70d?=
 =?us-ascii?Q?EJTKr6t7B1UHuLxbuGZ89kzikre2Sg1AcVozknNd7eo+XihYfGlGj+b4MrP6?=
 =?us-ascii?Q?VGriNtg77zKiRNfyrOfRDm6XTZjEPiZW4w1tCqc1+I4XdGR+NZjPbUUqIbhA?=
 =?us-ascii?Q?XTl7CdVtpHFrzdIFiKePkXujr5QyRYFspeVDWq1tRTJUO3w0UJ/B3jfYNkvU?=
 =?us-ascii?Q?PSiC+7tyCX6m9QO8TKAgMUXNsA6uj51FE/YlyI23728UMh6Tb5/lhs5rwnyJ?=
 =?us-ascii?Q?FviOLoEdR0Gysx1R+sLsVQ+QFCkb7h5br+DAjgW/dz837ikefNnNDvxnI50f?=
 =?us-ascii?Q?WWkyqwA8hF4HbkP+v6ZtQZwiMiJFHKUc82muWM9mrCU+CYGmkmYiHe9cF+Nu?=
 =?us-ascii?Q?cq63AcRoVoumS5h61MMx2QaBkGg0y24V8DNYrWP8lms78qrS/Bgisik5aYtm?=
 =?us-ascii?Q?1qIAP7bvtoBqMYXfNRPdBi6UO1uA/U47dWUojABKhRrTiz45gRhyNz6ra/Lu?=
 =?us-ascii?Q?U22LAfdCRgdDD+bcIWfVTdSPNjO37bg6EjKQz7x2lpo1Aborn4roOKrC5oTn?=
 =?us-ascii?Q?r1hIFhETU8+TYUi7U2X9alkuuss1FxJRxiHsJ4C1pc696ZDJiLb9tGGzAOno?=
 =?us-ascii?Q?SJ1Z3Z/5OK6GQkzSIfrh4TxN9DAOLxDF8491hljTgmQrMWki1eVYjfrQElE4?=
 =?us-ascii?Q?hU3yqGMsWsgTnda4ZD6iFniASa2cqo6hOcDSTW7TzjYiXdMY9NMZH8S9xT2i?=
 =?us-ascii?Q?ZItA0IwZQylPwLeZWr5EDDWLxmk9LHYpw3kTCSIqAKaU00dt4MWV8m4sXZIh?=
 =?us-ascii?Q?h4I6rPAJUth0U2gcJjonT0PwsrQV/NxHbV4VZi+GyB7jZsCEe6JVGoswD3yu?=
 =?us-ascii?Q?KG3hkuEiHT28V3bsajfefAdO5ti3/kqmhYJ55asM7+edmB6rhH7+IRXXZXd+?=
 =?us-ascii?Q?f+KVlyoR5IdWUtw6ScaV0SSH94eUXDrOflNMU/qaYsQWFVufY7xOXl+6P9N7?=
 =?us-ascii?Q?FSCMzGhv+nz80nqIIInjMYZ7v3/FP4A2vbGJ/Mcl1JkF0701tFtRJQHyEo2M?=
 =?us-ascii?Q?rM+Mu44UFIpfiaiVKVELFHCf12vjrW3ddKIsMhWWMKvvhsiveTG8OxjPEZnq?=
 =?us-ascii?Q?Yv0oD1SWyaeynNQZ6rpJAFtHMYy47sl3akZOs653VcHl1qcODZ4LPbnsRg/8?=
 =?us-ascii?Q?C6f9IdwM6mgY6zLzaj09wJV+LDYIZEWNBZLZSEjA6e/Pz417sBpIVWU9nzsP?=
 =?us-ascii?Q?rEeKG92slLYu+hEPVkPg6Rb8U53kZ7oCm3UzgsrX6SX+sFnEwCuBuvH+vocQ?=
 =?us-ascii?Q?kpQPVWVQgBdWZ1AdnmVFfX4C+IUR8D4PDIQLI69skou5Vw0Tw44kgP9KPXLm?=
 =?us-ascii?Q?sOiL6Nbe9uk=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(366016)(1800799024)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ZAKmjLWoSz34gFmZnK/Uz5xPsr89Vcmg6Q1YT77QQxenOMeXPtDZ02X0k3T6?=
 =?us-ascii?Q?DG3OI34wAP5iIQkS/U4S7ya39155iSFgLhzJmeQnOBEKzOhR4Pi9Ozjg4pY+?=
 =?us-ascii?Q?K6hiepGCVodIn8tdfiCuf6a+SrWI5EHPVfkXoFQIILjJrYBQwzTa7jm+AgWY?=
 =?us-ascii?Q?9kS4Td7ddLAue+67qgmUTRv8BFFBwAi7h+AGAvo/y4rbGi3rR7hAXom6Y7cT?=
 =?us-ascii?Q?eFwMu+2o7uDeQNo/9sd7PkYcNvwVTSm5IgyNd5ZUXuz2nueFL1YKn+arh9K+?=
 =?us-ascii?Q?HjvkxOsaq9RFsWke+hB/3LA1kWO49y7DdJJGvnAcs7N9w2t2GNjY4Pv93wIk?=
 =?us-ascii?Q?6ilj+2AGI8nvTTX5HWUyJPZ/d1MO/TLKQe9rB55cleSlIT6E69RJgCyOLKeN?=
 =?us-ascii?Q?60xwGpNkCePzmIV5KYEJMcdDDYe4doYTMNRX/kzkNzNWrV3zIDY1vCwWgvnW?=
 =?us-ascii?Q?WG4mUE4bvSW170WTSDPb6V2ZnkUX9qhtaqoOjqeDc6QosbMHfXxt1hYKHPjt?=
 =?us-ascii?Q?rEJ9Dl1+hS04/VOmMqitUchhBJREEVoCd1amnMKOgT9PZnb3KBmTgeTQYbw0?=
 =?us-ascii?Q?54HrYK4YEoxB/6rpPe6KuGlcOFFgOCyN1IS3IQpz6g5aDOVPxRfvpA6WBVWy?=
 =?us-ascii?Q?UvkNDmlEquMYXfd1jCBc69iKHCqS3JBIZWCkOBaxm+YEjhORgByTuEZaj3zN?=
 =?us-ascii?Q?K/iIsUPmXRzUn8xIzuw9tuDHO2DKkNZohFrxVd0XxEtuid+tteoYGS64L1/k?=
 =?us-ascii?Q?oXeMH2ze0CXia91priLXtYAS822ItxYkcGe/mXIRc3YwMnnzXYmLddBBGzox?=
 =?us-ascii?Q?0ua445bUBZxYG3XpnJHW5se02szr4kukMu8xMA+S94P3No78I0o8wGKfOMgW?=
 =?us-ascii?Q?4/Pu/ZvxzE3RZICBYBH35cdT+UdXe2koKMnO06xwLEMu3QhLGo6RpB2Av66q?=
 =?us-ascii?Q?rxaoMAyQr7jlpLC8FS4+bpv1m46ptOYSnMLqZhw0dG1Ur5epxtL3CZTuFF67?=
 =?us-ascii?Q?zMQFAIVQus4PusJbVFUfWViaM9z2LdUb8qOKEVc9yHFSKZVhY4tMXQU4uelB?=
 =?us-ascii?Q?WIno3jK6BDm6Hzf/NrwDDsUXAFiQH5N5gDla1kh5yXNWssmvSKyR6nO1hKL4?=
 =?us-ascii?Q?lRngphKojir5/gDZy7DhPndm3G/Hoj46qaOo59FgXNnY+z0h4gTWwbEmLhDh?=
 =?us-ascii?Q?ZQKNRj8hEJEJqtv0MACzJMQI1tvS8G0CIw+ilHS+5uArgY4VKhcrNoZhCqiB?=
 =?us-ascii?Q?5MnnBDvglG+IfHWu6IMcX9t0KZ1728gzLjB833lLBE4qYcpD9cnES7T3Tuw5?=
 =?us-ascii?Q?dQeW9DjxbqE1ILRGOLB0/CsOFrKncHc6CxXHX6kxfO4QDESQ6qzHoD6bAHkr?=
 =?us-ascii?Q?P8nlsRBhh+eaPtkNqgtA/azmq6TpNKZxMQnn8eN8V5KuLioq7n4cjlOx0rNb?=
 =?us-ascii?Q?LFdNRJMc5g+0l5xLl7wWc/W7AnMpocDfyVDwUtkhrEY/S+Q5FoWzIL+ayFwE?=
 =?us-ascii?Q?VmTpKTDRNfqHN7SR91nghMOKa3EZk/r3karcJCmOXukZez9mlZ/4F6IgFrlH?=
 =?us-ascii?Q?ZO6xPcvjZRXhs6E3ap8=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 297629e9-d6a0-4274-26f4-08dde63693cc
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 13:27:04.5221
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: QGO/7rFcEAJDfFVtKqdLW+l6RopuuLnfoyI6/MoVuOOAhziHFak0TU6alJ+R6uUz
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CYXPR12MB9280
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=rQpn04c6;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::62a as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Aug 19, 2025 at 08:36:48PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> As a preparation for following map_page -> map_phys API conversion,
> let's rename trace_dma_*map_page() to be trace_dma_*map_phys().
> 
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>  include/trace/events/dma.h | 4 ++--
>  kernel/dma/mapping.c       | 4 ++--
>  2 files changed, 4 insertions(+), 4 deletions(-)

Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828132703.GC9469%40nvidia.com.
