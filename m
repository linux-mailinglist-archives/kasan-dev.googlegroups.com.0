Return-Path: <kasan-dev+bncBCKNVUPER4CRBDVIQTFAMGQELC34FNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D10FFCC17C0
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 09:10:55 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-8824292911csf94584626d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 00:10:55 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1765872654; cv=pass;
        d=google.com; s=arc-20240605;
        b=j+xo0qbsWOzbU5EW8ADKoX2dgbbuZhXx484Bg+qwt70tbTETSvBSQH5vwuJP3P1Fe8
         +9vGT6hy/HHiVL5KzVruxDLp48JspVfL5WEIgah0jrEcCHBnMNlJH4ob5MoAPx0z0tQr
         R276SXM/ka/MQdhN86zPc9yxLWTuXfn4q4wFCB2sTAjmjzxU7gSv68K2v/ppdio3NYaZ
         +yoXVcQfbTGUeHOxnZrG0NMaAS+Ln8pjF17VSJroH/dNKxqxYegWolOdtoUmzIXRGwSR
         4U9+69jfTmNir/3rv1tZr98CSxLJsR+E/87QWzgGhMROgzxaHuZatIOwRpz3WHHddD2W
         QKfw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=niUYVnR3GTW4W9L+EkDN9lMiiPKRFsX17VVjl1QMvnw=;
        fh=5cDO4f6bfhVnQO2rcYaIqGNgtaAbeyYF/WEcY9pEjoQ=;
        b=QlTSX3PToSaHvagSYLwPJBtqLKHIFXX0s2+23UKudkYa98YYn7ncxwppG3AZbPfSNV
         Lu81DjoeK3PC6upauMOFdkf1nc3ywsoTnxTJHcNifIM1NDCdJDJ+LB9e5xiPUpZoHgtw
         8uGSVesfbqgFCe43L7EE6mVAd8eqPALFj8lvdalBUk5ZdX4xMhM4zcVuqfqTo+hUDd9N
         2zEKSjycK/kpVmeT26RWCplkcv1fV+ORMMg7uK3OopIxAQEkKQtKio0d1m/37GvYLdXp
         toYfnkXEY+4ufc+TeXBygxOtqYQVww+cS+6ll72thPZHn6D0IwUx+7lS0w3ltIOnXXPc
         qyBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=TnDfFdfS;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of idosch@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) smtp.mailfrom=idosch@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765872654; x=1766477454; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=niUYVnR3GTW4W9L+EkDN9lMiiPKRFsX17VVjl1QMvnw=;
        b=Ilu+aRjGbBmq7tMlhJNTla5E6ImOXgEpgpzQ+wD1UBYsUQoWJJ0MKk99BZZcvofLoq
         E1Nh4pqM0aLzGhIGUARZpE/dz3/YwG5aXPlAUbHMYzIMhdZfX4/hgvWXI5OdHYLIhcDN
         cRcG7ksMw+9cTlu0UASXbyNAQD765uJYBd8rdMUKH83KPragW0Uhx5OCHLkaw+nYLf1p
         dZCLE6g8d5w7MP34ekT4ELyPOSGCemYDg479ZxbhZhxS9NgxNFbYytbaTVzezR16/+NW
         HsciFPFp0R7WIlIxsD1CaPS3OkO0wnWxhGa5g6ONFJQJEXNXlivOZVGj8gdLgq/dAQ1n
         YXMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765872654; x=1766477454;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=niUYVnR3GTW4W9L+EkDN9lMiiPKRFsX17VVjl1QMvnw=;
        b=ImpPdnbI0xw9CdwFYHYlDEIbv/FpaVU9g83OgUuz+8xyTZvXuhgYHj3d1j6YvrAKBc
         vV5poBGvSOuJAkc+rkL2x0I9eiYhBRCCom5j0RdR9ITOuxBjOQ/quBH+dMRj4Wnd0eIx
         T1zqSrEr0ln9JTXvWK3OP8+aUhMqfavLhhQmoxQWX3iB4D6Bseb+tQ0w8zh8LHcBnLw0
         mYbDHz079qOn+oh2ImP1mFZxrmvPEtmHzCQl/3WD6yjM3Ejt73THEUSVVU/60XAT/Cru
         NwvcVRc4I9+AL0zhF2w2osDHt8fOhN2INegBwBwQ9KuEaSVwW+hoOyktK6JvvwQsGLyZ
         dgsg==
X-Forwarded-Encrypted: i=3; AJvYcCUABNyyEc5BZ/xv8zZ55XBLOBq81kLX2aPdc0/1wRG7BDr0mZ/2fWik6kcd1Z/Vy3qNFYt1Jw==@lfdr.de
X-Gm-Message-State: AOJu0YzLbCWyMsotc4wchku0ua5IMiTcbs3fvMxMRdbPLhb5LFubHg/o
	efmH6ILJq+Im82ZZhwxox2JJ5UDYOdy+CWrvx0JyiDYMd6brXwErGeeB
X-Google-Smtp-Source: AGHT+IGLcjcgo7uYd9IupDKvw7YH0u1yBQr0ZufmL4qvszZ7nQqbvAF7s7Zpb5HNLrxj0jAGFidw+A==
X-Received: by 2002:a05:622a:4d48:b0:4ee:ce3:6c9c with SMTP id d75a77b69052e-4f1cf2c4b90mr175042741cf.2.1765872654607;
        Tue, 16 Dec 2025 00:10:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbRq6qj0srNYIQg1D3oMd3pEncH3G+QvIO1d6FIt+xjOw=="
Received: by 2002:ac8:4559:0:b0:4f1:83e4:6f59 with SMTP id d75a77b69052e-4f1ced9775els25780691cf.2.-pod-prod-00-us-canary;
 Tue, 16 Dec 2025 00:10:53 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXAVAMHKx+lTGUoX5bOkftYlJHICjBvYrSaEljAvRL1ncWqXZ0CzOr2V++DHU1fcmNYUlSfOTnZzQo=@googlegroups.com
X-Received: by 2002:a05:620a:28c9:b0:8b2:e177:ddb0 with SMTP id af79cd13be357-8bb3a0ffb12mr1698078885a.23.1765872653608;
        Tue, 16 Dec 2025 00:10:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765872653; cv=pass;
        d=google.com; s=arc-20240605;
        b=SuN5IrQqZLaRAdRLAMdWB2ISzzAqlOP3WvN/LMqwUwx3CM74Im8j8pfobgHvJpPkGV
         4fGtv4oWlExXo0e0c4W6LJWV0Q14fud9JI5Tk5o/omrJnNy0BRltwIOtokrQYRLb1Q4F
         wneabYWUiFmYakoTLA4UPZ6WKRIpK4uYBtO7jvA/lK+ZUVb5mhqqmXBuBBL4lJgfkK9l
         2nfp5oXlBL+u5nd/El6XasKNlRmDvKY00Sr8wWTrxZn3xYIF/v4UZICPPGycPV01OcvS
         h6IlfnfHgXKOSvumnXotxbyjKFhiSgbbaK/whRrBwzCLZqyQ4daUnKniUQdEE121r6dn
         +nOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Ml4hLnysdu+pRUQKE1SCNbox8jlqtOFBVtq8LGX5IgM=;
        fh=oikY8iR0g8Osv84G7pgx59KVi6I1j+77bsPBP0UGwsM=;
        b=afwju7tw0b3X7RP9dbej3ZRs+Sn6fho/jhOeXwAjQv30TYZ3+JTcRRe9SHnSiGq6aI
         jQy6Gzm7GNbIm59h1BD7O8tROVXURoAo0nPXFVnj3qaB1P9c4rWwkO0u0NCOQTw9uX3X
         P8rAnolX3naZ6rymuyOUVdcc2sG7RoKg26TVJRWaeM0+bSuYFUIbgECUaCCNrKE577rn
         eFwWxxguWHHJ6T5VZbPCDueIKXY7yQX1dL+djuyW/pyQCijUFz/TKL/CfeG/kdDQZnRf
         yTHRTnBuDd5roGtmoEyGdSiEWIQiAtoVMmumbHwvkKLgIYctv/PjNU28l6gNMihP0YF1
         exTg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=TnDfFdfS;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of idosch@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) smtp.mailfrom=idosch@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SN4PR0501CU005.outbound.protection.outlook.com (mail-southcentralusazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c10d::3])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8be31c5e0ebsi7979485a.7.2025.12.16.00.10.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 00:10:53 -0800 (PST)
Received-SPF: pass (google.com: domain of idosch@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender) client-ip=2a01:111:f403:c10d::3;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=mXve7OSXvtv/5gSaMxTLRaj+HGlQauenyDMEKfLQQbCJhvpnPU5Mnk7HWYTejn3+LjIFconj42qi6wP47GjFomeaAXYDouKq1dQixVwwwqGTl+yKXVaSDhovK5dinP6l+ilsz+umnCJcZSoSPROb0wvbOub7KRet+EtzcUVmdABTHV67MAjM2l2ZVUy8qVBbU/qbEESEOliVuKsly/zUSgKdNmCtsiP770L1vc6aT8FcxAMUErz2rAlXKs/zvlG07WHGFusrEEpsk8xjroTyhVwco7pyUS0jqW01u8rO/ECk7KVim5avmXZ8USA2eqGHV01HLcmdxFH6/Ys8E5NUyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Ml4hLnysdu+pRUQKE1SCNbox8jlqtOFBVtq8LGX5IgM=;
 b=uXTkU9JNrhAdWziNwi92hy34E4hmxblQSZJf8IoopqE/gpGd3whtIfdLuMeQvBujC0Wu/FQgw7kOeuZXkNBoliyuemsSvmq88iHgHH7NkR3C1j29V3j4/wjUZ7mJwkpRZBUpI18Ehjdc0710javw/4SdZ9CtHMGzxhEoH3MPoYqcWL0Mkum7rNDyaRdsOl3oIEcfmdLRQWJWxKd4+egjc5A/CBZ9X6PdS/9pH6KKKXcwMNhwZOKKpy11beCniaaK6v7FTO5cNa47lpVX7Z62WObesn4EQaIGL/TmyBgJr6j8thQ+5vPNTI/y5dM//FyF5eXlpqOB84x1/FdmrFdbGw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from SA3PR12MB7901.namprd12.prod.outlook.com (2603:10b6:806:306::12)
 by DS7PR12MB9476.namprd12.prod.outlook.com (2603:10b6:8:250::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9412.13; Tue, 16 Dec
 2025 08:10:50 +0000
Received: from SA3PR12MB7901.namprd12.prod.outlook.com
 ([fe80::6f7f:5844:f0f7:acc2]) by SA3PR12MB7901.namprd12.prod.outlook.com
 ([fe80::6f7f:5844:f0f7:acc2%2]) with mapi id 15.20.9412.011; Tue, 16 Dec 2025
 08:10:50 +0000
Date: Tue, 16 Dec 2025 10:10:37 +0200
From: "'Ido Schimmel' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
	Linux Media <linux-media@vger.kernel.org>,
	linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com,
	Linux Virtualization <virtualization@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Network Bridge <bridge@lists.linux.dev>,
	Linux Networking <netdev@vger.kernel.org>,
	Harry Wentland <harry.wentland@amd.com>,
	Leo Li <sunpeng.li@amd.com>, Rodrigo Siqueira <siqueira@igalia.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	Christian =?iso-8859-1?Q?K=F6nig?= <christian.koenig@amd.com>,
	David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Matthew Brost <matthew.brost@intel.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Philipp Stanner <phasta@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Nikolay Aleksandrov <razor@blackwall.org>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>,
	Alex Hung <alex.hung@amd.com>,
	Aurabindo Pillai <aurabindo.pillai@amd.com>,
	Dillon Varone <Dillon.Varone@amd.com>,
	George Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>,
	Cruise Hung <Cruise.Hung@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Sunil Khatri <sunil.khatri@amd.com>,
	Dominik Kaszewski <dominik.kaszewski@amd.com>,
	David Hildenbrand <david@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Max Kellermann <max.kellermann@ionos.com>,
	"Nysal Jan K.A." <nysal@linux.ibm.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexey Skidanov <alexey.skidanov@intel.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Vitaly Wool <vitaly.wool@konsulko.se>,
	Harry Yoo <harry.yoo@oracle.com>, Mateusz Guzik <mjguzik@gmail.com>,
	NeilBrown <neil@brown.name>, Amir Goldstein <amir73il@gmail.com>,
	Jeff Layton <jlayton@kernel.org>, Ivan Lipski <ivan.lipski@amd.com>,
	Tao Zhou <tao.zhou1@amd.com>, YiPeng Chai <YiPeng.Chai@amd.com>,
	Hawking Zhang <Hawking.Zhang@amd.com>,
	Lyude Paul <lyude@redhat.com>,
	Daniel Almeida <daniel.almeida@collabora.com>,
	Luben Tuikov <luben.tuikov@amd.com>,
	Matthew Auld <matthew.auld@intel.com>,
	Roopa Prabhu <roopa@cumulusnetworks.com>,
	Mao Zhu <zhumao001@208suo.com>,
	Shaomin Deng <dengshaomin@cdjrlc.com>,
	Charles Han <hanchunchao@inspur.com>,
	Jilin Yuan <yuanjilin@cdjrlc.com>,
	Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
	George Anthony Vernon <contact@gvernon.com>
Subject: Re: [PATCH 14/14] net: bridge: Describe @tunnel_hash member in
 net_bridge_vlan_group struct
Message-ID: <aUET_bbW6KyxtQKB@shredder>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251215113903.46555-15-bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251215113903.46555-15-bagasdotme@gmail.com>
X-ClientProxiedBy: TL2P290CA0009.ISRP290.PROD.OUTLOOK.COM
 (2603:1096:950:2::10) To SA3PR12MB7901.namprd12.prod.outlook.com
 (2603:10b6:806:306::12)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: SA3PR12MB7901:EE_|DS7PR12MB9476:EE_
X-MS-Office365-Filtering-Correlation-Id: c99754f8-7600-423a-a605-08de3c7aa003
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|1800799024|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?qkXm0BjdGAi9VT55N2GLH1J6bsnNuBFCBwMBR2yCqs75pzLJpg/epURp95hP?=
 =?us-ascii?Q?YmOlmW/O/zn+f0hpeky9N9he5zJlc4nxJzHKgvEG7Q0KGzO/dzirkGSHjAuE?=
 =?us-ascii?Q?WMnZo4xaKWnFaxo7D1OBZKZfIRZenW9US7H025qI8cEZ/3DQzldcIhOELmKA?=
 =?us-ascii?Q?osoQ/4YEy4G8pZDXdBy2/947Ej7xXUB3oS68VfUgnhBpx4W3cS9YaVufWGQc?=
 =?us-ascii?Q?b6Nmmp9E8u+P0JhgUtT/6mmOZdWVOF+k4Wi4djLL6lNsNHcS9vhiYet5UU++?=
 =?us-ascii?Q?/DCBYdih5WGqI6s91PMWPrnaadkiGBcCIkX4n6bh+cWYrYOf74UV4knx4NK5?=
 =?us-ascii?Q?hW9I07m5vtwHwKuHYC6GnuEOO9nqMDYuzpALPDEHvaKLJwqYRcqL+Td576Js?=
 =?us-ascii?Q?aKlFrwfFQbH6jqbUcEslnKy46ovXktUB02A25U0RZpUl2Fl3KfeLaMxyjS2W?=
 =?us-ascii?Q?PJ5n2gviNK+d5kTifykm808oKiID98CN8rrtTUltiiAt8Z91Y4L4Yy39n1/d?=
 =?us-ascii?Q?hoLPqGSDWm5teJWwRF0wo2pgUQU4z8bQMzZHkiECN3ZlyM0sIMEY9m3QPHhc?=
 =?us-ascii?Q?3MNp364/b2wsPSlSc4Rww2WmfovQF52rmo4HcX27GNlZ+AvAQJCIpp363TSe?=
 =?us-ascii?Q?+9R1nAlW8pTVanabC5+dgQAdGg4kkcKgnzunxPhvmnQ+9mozeuuByC9Z6lr9?=
 =?us-ascii?Q?SjwZIht8+h6IFmp1+6SyQ8GT4M/PHTkFIRbo8sDScjFCBWkP+MxMQVRFJwNy?=
 =?us-ascii?Q?FjQHtXP44rlUxgcfyZPWZ1lzt7hIzZT4jVxLA5inmyd9ystdsbTCIs68lcLX?=
 =?us-ascii?Q?PMDLBZp4p2NdasmZ5NggNeurU78GWsTPQqp5EivXk1RH3t/at6lFpEP8arET?=
 =?us-ascii?Q?Zi+tOSpetzmFuZrxqc0nOmVq0bq1sdtTnfphk41AbDPhe7m1TSwrCV2OsxLr?=
 =?us-ascii?Q?GZDJjYYCY0BJ6CoqrpXfdzPGc13IPTT1G0AEt/YTJ0GVQ536S59VzBf5AHHq?=
 =?us-ascii?Q?SBX83ugiI1nTcRwd2qC4ncQr6p84RhyAqTTUG7l85anUfcvghLHUStY94ugs?=
 =?us-ascii?Q?l7yyJOxMalgJw43lmrO/LfxcCeN+KNnFOTWRUTM7pyNsPUR7R8Y4BZi6QK4R?=
 =?us-ascii?Q?s3hSFS4R2EO2hHb1Qo6D6Cbe9ICeKDpvW74fdGODR0dljLXduMdRfQ6snUep?=
 =?us-ascii?Q?C4iiLxdLxdDPske0KRKRRQbBHX3ljrWJkcvfZIE+gpaEdYAXfgcNm7jdh0e3?=
 =?us-ascii?Q?iG30ianLApDBUb87dMvNdYDeWDl8N3sAFM3vuxY2bNXbkNn49nJo8HDsRpIP?=
 =?us-ascii?Q?dyng77uq/GtwqnaAuLpwkpype42rXNVv5ZwKgIlRqN44gIjFHXk7X7CvveH2?=
 =?us-ascii?Q?teXf81LuKCRipSXtHR1P0Q2F+w7DF2GZoM8XBA0a87r929nl3qRfj6JPpOzP?=
 =?us-ascii?Q?/vqI651aAm0PksX5cYuSQNeeqsqhFtRW?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SA3PR12MB7901.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(1800799024)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?GMR1rsjwA+mZmoSMlv2Zqg5PhqQvwG8PoT76TB/A7KZed62KBuWIauK+iQUD?=
 =?us-ascii?Q?uqpmWREc30w6mRNi5ZM+SjzSTCLZkPr7JV+KMTFQe6swH7d5vHQ+zf0dpYEt?=
 =?us-ascii?Q?GIu2nHe0s1+O5gi3kbCSy4YVOPvlhsWt7HpXf05B24SpVoI+noihEmsQWPnJ?=
 =?us-ascii?Q?ILZaQm7+mm3b7LyanIN1PbEQTmA3+P92L90GLscWYjn7YmX2SfAEZabSuwST?=
 =?us-ascii?Q?EjzvPmwUggnpTDt1TC2ihx+at7BwZdyEs0eUyFNvKGwjXTz7/hC62JXuJQg8?=
 =?us-ascii?Q?XoUrra5DhVrRL3aw+Hddml8cPqNRCa5l9abdCYsXe0uQo1F2O9/1v5+zNlNW?=
 =?us-ascii?Q?4DU6Q9xKfxVXNzYRGLxrdf85/q7erU9E21eZeE7pGRzOEY/mhnaCk/75vEkt?=
 =?us-ascii?Q?QH1OpHfZit7YlGftmEmS7aEiqIjnFUPlqF98rweJ3l/V9DIfjuXuqAJ5PBj7?=
 =?us-ascii?Q?UnsqzCJQp60swuQ+qy2Ba14FIGUlM9BSBOiyUNormsAzpmmzzoaJDu8DQxAu?=
 =?us-ascii?Q?L+16lHUrWCg+mkcf+8lciTm7bpaWrqbBsmlpYBILrgRtdngKMchSkQO0CPZi?=
 =?us-ascii?Q?F/oYlyxHw4x+R90OERWWufHHpvkwH0A3mL3LllKG39XTJMaoFNWxT8w4mB0z?=
 =?us-ascii?Q?i2B5+voSnM6kCEymaC867AKfDsXAG5sK9R/9+kV8HabwMYND7BSw8/38zRqF?=
 =?us-ascii?Q?DNSAdyi82jDhA48jTTCObFQLoLfQVODKyD1VAzp1sCn6CT6nONj/DTK/H0uN?=
 =?us-ascii?Q?Vx1sQS8aiEG6QII16LPjMdpXowgqN77vM11t+g0ixxdpZRTBWBXOaGDdW7Fd?=
 =?us-ascii?Q?dx2gNtLpzxqMWhz7Y43E6QHY5HzYiiSgThF8JzGT6YeuKjNvQRAp4SWC3CUr?=
 =?us-ascii?Q?tnfcoFBpmqJZDOps2W/r6TJ6PWJw337aiqNbSXw2b3eg7F2K0DS/2IS4kRXv?=
 =?us-ascii?Q?YQV6Yc3vwaT9z6yvPk4kGqcZsou6p1sHC47KJm3mLwVaJscJAk1ciDNvRNU4?=
 =?us-ascii?Q?vmiHRt4ek71JrydTLI8KdF07jnu36Sr0WPFWVjCcdGBLQtbsQ31Wdezm0ecI?=
 =?us-ascii?Q?JhYsNwavM2eC6zIceUUh6fzAx463Pt6R1+pO4Y8FIPVTvnBRry/btE0aTsB7?=
 =?us-ascii?Q?82aUOmogWVosQj0I10Z+Pmh/pS1bd5H+IBBhirjKJJYFmmXvqquDHgdx4KJ+?=
 =?us-ascii?Q?hiFN+omF4jz/iGrIrIrbOJpICy35rsfB5zJy25Kh5B/niJnHDoJFc9LHwBnh?=
 =?us-ascii?Q?U2PFkdA1AfchKfHeOL4THF2tbpnjA6eLSlpBovdzTLvMRm9yQTpXhycJJOPV?=
 =?us-ascii?Q?D2uTb0krBVKe6qgTZ50sCTfhoI3YmXH4JfAhXVsknrQbZyygV6sab6SoBwCS?=
 =?us-ascii?Q?/5FDPaa7Q3yttccbpijFvir4egNbEwBU9KOM5w5KWM+V5JIEVz5ZKf5pU99s?=
 =?us-ascii?Q?Ud465tArDFqI/avl1KA009dDNBLcOjYElirDsKEl6Ye3S1O1texnMUWKO11d?=
 =?us-ascii?Q?frEIMFMUdr6tjl00pNuvfiyGoJ5yWrAlXM3Sddfs6wLYPs7T0SV/2dhN1HKF?=
 =?us-ascii?Q?ny1xJLWxk2w+I+uF3fEkAqZW+bWWRVolqxRSdDKC?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c99754f8-7600-423a-a605-08de3c7aa003
X-MS-Exchange-CrossTenant-AuthSource: SA3PR12MB7901.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Dec 2025 08:10:50.4122
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 9Jn1GRAVl7fWR6i2nOitnqAdyxeLG+agMppQMoqRYGdALbOZFDDkQLF4Y8PSVW8MdLCtX3o9nK8w98LWXl102A==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR12MB9476
X-Original-Sender: idosch@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=TnDfFdfS;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of
 idosch@nvidia.com designates 2a01:111:f403:c10d::3 as permitted sender)
 smtp.mailfrom=idosch@nvidia.com;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=nvidia.com
X-Original-From: Ido Schimmel <idosch@nvidia.com>
Reply-To: Ido Schimmel <idosch@nvidia.com>
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

On Mon, Dec 15, 2025 at 06:39:02PM +0700, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warning:
> 
> WARNING: ./net/bridge/br_private.h:267 struct member 'tunnel_hash' not described in 'net_bridge_vlan_group'
> 
> Fix it by describing @tunnel_hash member.
> 
> Fixes: efa5356b0d9753 ("bridge: per vlan dst_metadata netlink support")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---
>  net/bridge/br_private.h | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/net/bridge/br_private.h b/net/bridge/br_private.h
> index 7280c4e9305f36..bf441ac1c4d38a 100644
> --- a/net/bridge/br_private.h
> +++ b/net/bridge/br_private.h
> @@ -247,6 +247,7 @@ struct net_bridge_vlan {
>   * struct net_bridge_vlan_group
>   *
>   * @vlan_hash: VLAN entry rhashtable
> + * @tunnel_hash: tunnel rhashtable

While you are at it, I suggest making the comment a bit more useful.
Something like:

@tunnel_hash: Hash table to map from tunnel key ID (e.g., VXLAN VNI) to VLAN

>   * @vlan_list: sorted VLAN entry list
>   * @num_vlans: number of total VLAN entries
>   * @pvid: PVID VLAN id
> -- 
> An old man doll... just what I always wanted! - Clara
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUET_bbW6KyxtQKB%40shredder.
