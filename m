Return-Path: <kasan-dev+bncBCN77QHK3UIBBJWUVTDAMGQE2AOZTCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 81863B81FB0
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 23:37:44 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-82e5940eeefsf67306685a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:37:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758145063; cv=pass;
        d=google.com; s=arc-20240605;
        b=KgchWj6s9J4emEyRx9MihmmNcYZUxkxnhQqXySIeIRtHYRP0QtHc/AcGhusSpKmQn5
         f5e7rAp+bFJyQ5y52QrZ731lNRLhN3aRzFyY6ksAmrJJIM5izasMOO76XB6MAcWqtmfU
         +VztFNR0vnJJL68HcDz06GfCELSFiCqCZOfLSLLhtFE3lISng9+KSe9u7lxwbp7t2X/G
         59MoidDE68M4K2t/+zG4xvvGOZB3lOwJDdJQXs1v+R+gxVky0qIvL3VNq7f/KNWM8JXw
         wdsI5kne6BhfzvKhfG4H0j8GAKCceKyALscHeLugGelEPcUanip3dnTweGjFeRfSOHeX
         Lq7A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Uz3zLq586hdYneeHu1Dc4Lpp+Q9MV4RYTlT+gXVM+tQ=;
        fh=SI3MClDfL2K+Bkg4riLo2ANikA9S4+r4frjzP8CjfA4=;
        b=CjAVsh2xkSZORTIBfGyY/8YJ4Vw6qSYoCI+Krzc01P6NfX3y0ZzY5HxjxjEnKjTGXL
         /2Rg4Riug7yOdtMULJsRM/4H/CJ/yp3UkPK/MXVw4LfpsFDJw9lrAaq7wnytIuWNsOUN
         jfIb40+heBJ6Tfr1J2KbAyiGYoYwCAGNMdheHFP1kEuIzohE92yQwzzhQlvx3qV0SQHk
         UjYG/9NbiP9u1QsMfxHjIOHQIV2vgh6srsQEme1slW0K8wVpLq54ThxJWngEEKUOrVVA
         zXeDntjxG1TsmyvYaE7lNwHNdzBCVZjalhcl3aVNoNT9czskW4zOczN0DKc2DpONk2wD
         g/RA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=YG7+MQIp;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758145063; x=1758749863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Uz3zLq586hdYneeHu1Dc4Lpp+Q9MV4RYTlT+gXVM+tQ=;
        b=aP33HEyVQrQ7xB1nE6u6nOAceZSqviJyLTyRMG3Uf/7HD1l5MuFCs+Cdk6ODpBXhoB
         j37wdce1PiUeuaEOJI91IRnmzPh7QLE0gzI45xRoYuJrPjJO8i5GIyrqAm5Opnkpkj1t
         1eNO3d9RB0i6iJDs+vEUpZBCd3R2SCx7YkyyM3OUdIi9nhSWatHGsNO9fpROk4eHjYV0
         Se7XcdkIm/8vcxHBmSJe3yOQAgQWZbcItOpegDrTsUQjHRer5ErWznf96bPn0W/OVTAg
         2UZHsxbXWHtLz3n5uEf5Do3Gszes9nGbKRhHUv7h+FEfqUSSRJj4xfJ30zlsQo7GyWUd
         v8hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758145063; x=1758749863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Uz3zLq586hdYneeHu1Dc4Lpp+Q9MV4RYTlT+gXVM+tQ=;
        b=sspcuz8J6Uz8kpz51APaaG/qTnc3hRX7hkwRspaPWgXgtLOm5NF0jFVr3ihqoWf6vu
         malaGCVc78626mhJEJMagnK+gAUmjsYCjSxVemCXauEZ4KRFKTono2Uv7SVlCAYpjoXm
         VAwkdGXeVfmWKf7lkj68ep7H94dJIpSWD7aW3sgQTwaPat8J2w7jEjj9U6eBiq4pXAVN
         UY3AdViJSJDg6AMRDs2V42AjJk41uu8OUAiWqDp2HRU9VnJzuw9RdIMz/Wd9PrHuPogp
         /Lsv99RrYVBiSmavn+rZ6W+q+M+eELg+yGsGEA9KPUNuIlwaGIVicA+rqAjha1ZKyEr6
         laIg==
X-Forwarded-Encrypted: i=3; AJvYcCW8sWWGzWmydqqSCq4Rc+FwZu1hbNP2Yiu4lfAscV4Rwm1GL2dNSnr4r46JY5tV6Bx0r0G+1g==@lfdr.de
X-Gm-Message-State: AOJu0YxubO5/WMr/CdeH5WZGrLVb0f2u6hWPYGRNbMz/qMakbbuXJWiw
	ktnwEYrYKpXhsS0Zcpkp4DlAwgtQRdqnvKGxuDX71PxC8m04juh47qwj
X-Google-Smtp-Source: AGHT+IH6RYv9lMlIelCTCqMHGz0p0PhhDh5GFOk0lIBagrOyHjUwcx28Naw4Dc8jm1sXNKfgXqvMvQ==
X-Received: by 2002:a05:620a:c4f:b0:817:e10:b40c with SMTP id af79cd13be357-8363b2be1f6mr138743885a.43.1758145063143;
        Wed, 17 Sep 2025 14:37:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4G2o/n5Z3AmvS2Vn39ceBgWFTzp6ewKTtPCBnTMsp8Gw==
Received: by 2002:a05:622a:5918:b0:4b7:a79d:1601 with SMTP id
 d75a77b69052e-4b9bbbc22b8ls10052761cf.0.-pod-prod-00-us-canary; Wed, 17 Sep
 2025 14:37:42 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCU0WhgOK2ivjUGHgibYETovN1DkJ0nr/bl/HgdPlV+/yxv6Y6t+KYro6NeyzQRuQP7LoZTUWaKWrqo=@googlegroups.com
X-Received: by 2002:a05:620a:bd3:b0:805:d2df:54b2 with SMTP id af79cd13be357-83631a7f861mr123504285a.6.1758145062328;
        Wed, 17 Sep 2025 14:37:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758145062; cv=pass;
        d=google.com; s=arc-20240605;
        b=BsQIukgEMCszAMAjMBMJw2KbvOmGkk3kOI913iunHvkvGnZ3vHqXuKBO3MIPlf2fp0
         nIMMm2EGbEwRYO0btk2h+kIvQwE6dMymQxNSE9l+KtiqQ6oadMlRlX7mZBJc0CIiHshx
         dXKyW0/HhG41x+V57rrl0u9mUY+4Tm0QdXNezBRvZmR1b8tiHYPB2Rccrixh4sMLeVIi
         2iaa+9Mk6/i2cvSrJLga1V2pO5LmWTGZesg60lbcROCg0atSZ7HH6j+N/ikql5HT4lKG
         DJEiZKiLEDehrL5YUczCKCWbxVw3znRrQd8O9kO10QgaWKYhml7T3wbs7uMkoOvG1ZzC
         gqzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=zyW1gajqOgGqtroSrfGhdC2kP8n3cxZwZeFbKWpdqT8=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=BsqEonsLbUMD3sa16nFjDVi45FARTpGbvrZOSQsqoX5xA8+2ugUkSoQ92HDhF6eUsX
         BZVE3jotxm/LY8AHjuCyzZY/y4JeZPU9Km/EdRifz0Ts8UorKYrL6fB+ftJuTnQBs1qk
         Mwf4TqJE50JMtKP3nFwk7uO8OKXSmoKzdHSFJsFi/5injIURALkxKcUzapTLkwIWDi1q
         ws4lFILrKeduV6VjcD/2e/bRXkW2w4U7pQ9wxvobIkXOKdcEtd54L/t3mUMeD3kwDqw7
         n6RlBt7DeEZorBK+9cOR6QVb3pOLSa5Oi73XwfsHGYcq6NPbfS0NszrHuEA/uMbK/iBS
         ouyA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=YG7+MQIp;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CY3PR05CU001.outbound.protection.outlook.com (mail-westcentralusazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c112::7])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8362f909afdsi2938985a.5.2025.09.17.14.37.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 14:37:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::7 as permitted sender) client-ip=2a01:111:f403:c112::7;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=B83OUBzgkp/zFKQwJ1fIwF2SWVuskrW6GGd7meOfpBDCvtJJSpfdEgoaZQ0VvqKWEg1IuAPJZ7cIQAzlraIuAHIAWpe2GYv2ATmcAP8pPIIFBgsEaXJAbPPuuD8B3YravtRAav2+FlDzegY0tfMv5WBMv86FSPBK+95lJxGJ6TmnSreifbwxq+jpM28Npfng5YoCOEAA1nMNduQXwto7rApxvYMP8p/UHO302V/vbAOsHDC2K4V4hgd0xpZn0vNhrvCB5c/hl1LV1WYVGB9lj4J/0W7Gz3RnYM3KQkjKkPXgVN9W55b7S0Bv/kCRvsDd6dRdXqZqgLSIKvdsYWp7WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=zyW1gajqOgGqtroSrfGhdC2kP8n3cxZwZeFbKWpdqT8=;
 b=i01nfw+e9mJa/oNCq9rh5sCxc6dnR5jf90X/h7ZNzH7Id7qnpHv3E/uYokcrrbUco5U51r16lS/L7bBfxlbA71FaB7XUJCw9Zxo5oKkPGc+ndtPsZK/7XZUcsgbFy++6LUJdxNxO5nzDqx1T/WOm/Fo3FfUE3OkjcBLC66NUEZuNPIDyhoszr/q8AUZ7AT0eVNUSSH1nwD62BuYKN2KI2PAmK1Pz1zJGyaZIyBw6b2e4AmovbWXYX1gIREgZKQLqjKAwwlpfoUQz4/PpaYzKBWmSJzIdRGzLSessMZ5MwWpx3VL89Do8F5iqh2TEgNVJKZmeRbL13pWkWSJiNRDewQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by SA0PR12MB4464.namprd12.prod.outlook.com (2603:10b6:806:9f::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9137.13; Wed, 17 Sep
 2025 21:37:39 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Wed, 17 Sep 2025
 21:37:39 +0000
Date: Wed, 17 Sep 2025 18:37:37 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Matthew Wilcox <willy@infradead.org>, Guo Ren <guoren@kernel.org>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
	"David S . Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Dan Williams <dan.j.williams@intel.com>,
	Vishal Verma <vishal.l.verma@intel.com>,
	Dave Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>,
	Muchun Song <muchun.song@linux.dev>,
	Oscar Salvador <osalvador@suse.de>,
	David Hildenbrand <david@redhat.com>,
	Konstantin Komarov <almaz.alexandrovich@paragon-software.com>,
	Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>,
	Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>,
	Reinette Chatre <reinette.chatre@intel.com>,
	Dave Martin <Dave.Martin@arm.com>,
	James Morse <james.morse@arm.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	"Liam R . Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>, Hugh Dickins <hughd@google.com>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	Uladzislau Rezki <urezki@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org,
	sparclinux@vger.kernel.org, nvdimm@lists.linux.dev,
	linux-cxl@vger.kernel.org, linux-mm@kvack.org,
	ntfs3@lists.linux.dev, kexec@lists.infradead.org,
	kasan-dev@googlegroups.com, iommu@lists.linux.dev,
	Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v4 09/14] mm: add ability to take further action in
 vm_area_desc
Message-ID: <20250917213737.GH1391379@nvidia.com>
References: <cover.1758135681.git.lorenzo.stoakes@oracle.com>
 <777c55010d2c94cc90913eb5aaeb703e912f99e0.1758135681.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <777c55010d2c94cc90913eb5aaeb703e912f99e0.1758135681.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: YT4PR01CA0214.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:ad::21) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|SA0PR12MB4464:EE_
X-MS-Office365-Filtering-Correlation-Id: 3460132e-c223-4b7a-8f5a-08ddf6326cae
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?rPyoMde7amoXc9+S+TGTIwt9Zpsq5kbJnnBTiZcpTMEs/S0UHV4CB1UZLzRR?=
 =?us-ascii?Q?gb81MHVY0ahNle83MSg2u7UdytCN0yUbCjMVwlAZdwKjx1qK22SWDYjuc98B?=
 =?us-ascii?Q?P2G+Am52tikIxkR32SVfv3pGek1NrlRr5LXsdoID3E5dct8/qB9vGLXgnsQb?=
 =?us-ascii?Q?7x8AFk6U4ANZyKYcHdQubGo0jgNMujImLwb66Ru75qsXCYHmchl8Vijiplbf?=
 =?us-ascii?Q?TUXJbVBqh0kDlBuShmHBcJhrNvwzN5+XKAqf/WXZPeX6YFtbs3zu4RH4K/X5?=
 =?us-ascii?Q?BenbFzasq0sLDnWWg7akBD4wuCuNC8towZwJur/vVsrTkgxLfFdZyxE+f+aY?=
 =?us-ascii?Q?Gsx29waWXLHkz0DujLxRBXa+u2F/U+bwRW8JjF6m4fU0CxzO2v22K4of0/Cl?=
 =?us-ascii?Q?ziQIddebN5K8Nqd3T8aliQCPaRfF4wjjmXcCBLUF0aEkYYOb+sHRcjb6LUPr?=
 =?us-ascii?Q?AiuTlTlJiDZMG38veNFBQm4646ty4L9dCtfCq3Mc7v/dE3Kuu+1k+s30iCWq?=
 =?us-ascii?Q?AGf3motScYNtJxv6+p7toc599HJ9PqQZecYsHK+xYr1BWFv4KFk7JNuNTcKM?=
 =?us-ascii?Q?OBuzy4977lZxZcXicy0nMLETJP1G3x4RfEC4VhHPrX9S/ldTfUiH2Nu8Ob7w?=
 =?us-ascii?Q?P+uAQga6zYVf2Uscm40lR93NKkr1ZU7QudbfDHIFesQA9Yuxmdi7+ScHne7g?=
 =?us-ascii?Q?wPQz8o9ovkxPmGrJQjnmcxwJGXJv5/f+jjaUsR5WpdZ7xN7SdJEOD6+LCS/Y?=
 =?us-ascii?Q?XU9kk8ACmJR0w3vMex4QsdViEBWQULh+oE0WJKsCoMbjHsNJOLAmyke76PzY?=
 =?us-ascii?Q?AS0F4nNkHxN4+SBZcWInSIFi7r8/1a99idrna60cHqDjUkdgmozLJlnjO9iX?=
 =?us-ascii?Q?8aTv6uRhGtbmmV/AIKZfRMmeDH+fpaL8ZZeEjnGT79DoUuGIkz8xBN3Aixqz?=
 =?us-ascii?Q?JzovJfhvHtzMxpQ+efPsc7Mnd+bhCxIIKVgSoAWLZxUdplWE+0NQMcRWU9Z6?=
 =?us-ascii?Q?8NXorjsboLIJkGKuNj1WKFZPmy9WhFKBYRc9XV2jnMVdOvbrNxXDvHhb+3Ro?=
 =?us-ascii?Q?kBqkaunnu9Jx1ZTXs8PWPlVlOezunyl2kkLlpjgx6i7z+zaYc0g8iUrXb2yx?=
 =?us-ascii?Q?YC64cRhbXbD90qB0vdwdDWUGFsBFsbLTIErVyc7HaIF/GAr5M/KAPvHQpiAo?=
 =?us-ascii?Q?7kO67iJuahL7L0+jLIbC6Z2zwjhqD1/eVwLfWBDSqrcdMvfOOsc/mJc8PHHN?=
 =?us-ascii?Q?ZBXo8K4KyBm5m0n8+Q0K/zw2yiN3Y7hj+cdLZ/nhTDYrWNfdUn7GYTJ+uB51?=
 =?us-ascii?Q?/6L2qCJzLx56SHncvXh3m4hkmJYeuarRFqElCx2jyA4AFuadHN5I8m88kJQm?=
 =?us-ascii?Q?IvVMI9kcUcyX6SfmXg9EqnEkzjVxp2+iJygjguhfbw160SYbGA88P/2yj9ud?=
 =?us-ascii?Q?EpcDabwQIaQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?7hyemk2U4JASYXelMhmF2K8F9ZEROpD3kn0pFo8FkYqJyl1BDWKwZE0QwUns?=
 =?us-ascii?Q?rR6fAdCePBAllUsMP/A1Y4IIm5Y0II4nCB9o1eUMDUeqAMaUeiRXHm9+KNH/?=
 =?us-ascii?Q?nGirTZysdGqbRJm0Ag6H0Ky5pMlid/KmlezCoQH2sPI6veiF4FfcjUGGh4V5?=
 =?us-ascii?Q?jA9ye4iSu8V7GNqcgIACzQvog2CPY6a812xRw9CrX8a8rFXhAcnGiMaMSbis?=
 =?us-ascii?Q?J+QtEGN60ClrGGbg7Hqi+UTw4pujgwe4eOgdgIVoty31dG/djTpVO5NebL/H?=
 =?us-ascii?Q?XHYMstz8g+dr8L4ov7rGBi4nZfLtx13d/3lwYJjGHPzSCghS4yv+lvr0o3p6?=
 =?us-ascii?Q?/IO74807b6yzYH7CHlHn7sH0P4oRR91JbNy5vXMBjwegpgVlKxE7Gy2OdyDp?=
 =?us-ascii?Q?mOUiEvrBFHjty0alKyjtk3k2oid7Ku0+oubjYtH12K7aU5YXSROZgRBHLp9w?=
 =?us-ascii?Q?vdVvlKAq+OWznZCUaLvl+AZPMOk95/icF30I4xzAprcsM2sB2/T2wplEqRlf?=
 =?us-ascii?Q?xxjfsB8PiPzv4rpF6lvwuBg/bIcewo+/1V/9vM5EUH6MTC9kVQBsAkF8p3ae?=
 =?us-ascii?Q?swhELocpdXl3/pBdPICyoZyDN8fL4pD80eYjSblRxUggd3xas72btVglgfRI?=
 =?us-ascii?Q?UNzyu1FNgaMuuHStaoDASTfVjMJVJmDbLl7NLOzU7p0P+IYhDIYlHd87/grm?=
 =?us-ascii?Q?N8dp1IrDt3nBaqybqI4cf/o/EXimDixnOn/FQEIztZMLEZmPXQz8Uhv0WUOv?=
 =?us-ascii?Q?HqcEbrlud5negwFlPeIJcQWcFT47no6N6l2rfRrdC7WRNDnI6rskLk9yBd8D?=
 =?us-ascii?Q?UAlC/UQSnYzSeEaiCnptfHwuTJcvl9KQAAT84xxyAzhDV5cY/Y/fmnZQc4pq?=
 =?us-ascii?Q?vO0elGencVpBkfn2y/WwdjTKUQ+1XBH5aaUfYk4Ah6fNfkBEaXA6YLwnPSdh?=
 =?us-ascii?Q?2pr04njvsdjEaThmFv64BU0lUB1jdIXO1uXBTUQmK1Ka58TWHAQxxKIAcZfM?=
 =?us-ascii?Q?YDXWXCrk8cuf92Z415qDPR8cVmReS8ZeEuGFTfvLvvAIEoAFvx8UiURnbubk?=
 =?us-ascii?Q?cvMyoQOYvCzx9evQVNEmVC/5NdldQmWNuLP/ZUwZAW8pAQp+RwuYvMTyzF5g?=
 =?us-ascii?Q?sOg32kX/E1WYJUf6M17a11QXtUiXAYY9tjdn7iQZfmBy0c1wKzCHnOsJc1E9?=
 =?us-ascii?Q?Vxtnsv9mQanJ2CDM3ipEPzkxfMpjomz8MjKov2lzwDo7Jo/i9hEuqq6EaTDN?=
 =?us-ascii?Q?uFlMBke1+BJtnLEvld/HNTCdoc3Mi4PsbMpn47C3n63Q7aa9JoGHW4J+L8ud?=
 =?us-ascii?Q?6ifj/BUm1Nou+04Fs1uEAMtV8yJrPWSIuW2NLXZGxkZ9xN7EbKGCN2Aqz0B8?=
 =?us-ascii?Q?PDcBFp38HxSudLXs1ZjoaRHR+nVV/4q4m7YOIilA8Ep0c8H8GTgcS8EboVSS?=
 =?us-ascii?Q?7vbRhtxQLyL6bWmjzAFq/tD5/9HEwClXfb+hiYuTxg6CFLbJYcfV9L+HwVEA?=
 =?us-ascii?Q?HHPvqdnN6c/t/Lh+Sx/ibqRHGgRB7bSDvPxtwYJ+HtJf+Y9SVetK9wpohWOC?=
 =?us-ascii?Q?c9+bIwhRWCwQPJkCoLo=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 3460132e-c223-4b7a-8f5a-08ddf6326cae
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 17 Sep 2025 21:37:39.0092
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: kaoqNkjssdF4tWoj5ha9v78KGw4VtHo3ONsxUfl1lBNSFyHogO5gZRag7FlE7+81
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SA0PR12MB4464
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=YG7+MQIp;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c112::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Wed, Sep 17, 2025 at 08:11:11PM +0100, Lorenzo Stoakes wrote:
> +static int mmap_action_finish(struct mmap_action *action,
> +		const struct vm_area_struct *vma, int err)
> +{
> +	/*
> +	 * If an error occurs, unmap the VMA altogether and return an error. We
> +	 * only clear the newly allocated VMA, since this function is only
> +	 * invoked if we do NOT merge, so we only clean up the VMA we created.
> +	 */
> +	if (err) {
> +		const size_t len = vma_pages(vma) << PAGE_SHIFT;
> +
> +		do_munmap(current->mm, vma->vm_start, len, NULL);
> +
> +		if (action->error_hook) {
> +			/* We may want to filter the error. */
> +			err = action->error_hook(err);
> +
> +			/* The caller should not clear the error. */
> +			VM_WARN_ON_ONCE(!err);
> +		}
> +		return err;
> +	}
> +
> +	if (action->success_hook)
> +		return action->success_hook(vma);

I thought you were going to use a single hook function as was
suggested?

return action->finish_hook(vma, err);

> +int mmap_action_complete(struct mmap_action *action,
> +			struct vm_area_struct *vma)
> +{
> +	switch (action->type) {
> +	case MMAP_NOTHING:
> +		break;
> +	case MMAP_REMAP_PFN:
> +	case MMAP_IO_REMAP_PFN:
> +		WARN_ON_ONCE(1); /* nommu cannot handle this. */

This should be:

     if (WARN_ON_ONCE(true))
         err = -EINVAL

To abort the thing and try to recover.

> diff --git a/tools/testing/vma/vma_internal.h b/tools/testing/vma/vma_internal.h
> index 07167446dcf4..22ed38e8714e 100644
> --- a/tools/testing/vma/vma_internal.h
> +++ b/tools/testing/vma/vma_internal.h
> @@ -274,6 +274,49 @@ struct mm_struct {
>  
>  struct vm_area_struct;
>  
> +
> +/* What action should be taken after an .mmap_prepare call is complete? */
> +enum mmap_action_type {
> +	MMAP_NOTHING,		/* Mapping is complete, no further action. */
> +	MMAP_REMAP_PFN,		/* Remap PFN range. */
> +};
> +
> +/*
> + * Describes an action an mmap_prepare hook can instruct to be taken to complete
> + * the mapping of a VMA. Specified in vm_area_desc.
> + */
> +struct mmap_action {
> +	union {
> +		/* Remap range. */
> +		struct {
> +			unsigned long start;
> +			unsigned long start_pfn;
> +			unsigned long size;
> +			pgprot_t pgprot;
> +		} remap;
> +	};
> +	enum mmap_action_type type;
> +
> +	/*
> +	 * If specified, this hook is invoked after the selected action has been
> +	 * successfully completed. Note that the VMA write lock still held.
> +	 *
> +	 * The absolute minimum ought to be done here.
> +	 *
> +	 * Returns 0 on success, or an error code.
> +	 */
> +	int (*success_hook)(const struct vm_area_struct *vma);
> +
> +	/*
> +	 * If specified, this hook is invoked when an error occurred when
> +	 * attempting the selection action.
> +	 *
> +	 * The hook can return an error code in order to filter the error, but
> +	 * it is not valid to clear the error here.
> +	 */
> +	int (*error_hook)(int err);
> +};

I didn't try to understand what vma_internal.h is for, but should this
block be an exact copy of the normal one? ie MMAP_IO_REMAP_PFN is missing?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250917213737.GH1391379%40nvidia.com.
