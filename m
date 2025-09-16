Return-Path: <kasan-dev+bncBCN77QHK3UIBBCUKU3DAMGQEO7FE7AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C987B59C4B
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 17:41:00 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-31d8898b6f3sf7719168fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 08:41:00 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1758037259; cv=pass;
        d=google.com; s=arc-20240605;
        b=c35BuegFKhKihFlZe9c0Jlo9q+mo/y2ikd0KqbsfFzq8LacEIk6408iLqRqzz6uba3
         AFbPoGu/8zNQWwXA9q0VUT9/FsM8OuoF3+4VX0+XYmd/Fli88zwajSTG9GGssakkRKPW
         h9ZG8iyl3mExCkN0G/yOOmdQtpe1RSMYo6ZOaSs+Hmt6oB/Va7KmarG0+WMWNrlgKB3s
         geDjNHLcREmkGdzbhZ0so4Qq1hmWBLso2q81XPPzoPbC8wrYXIWd0LaqL6hAWurY1HMm
         By/LGmu9EU3x5lema7TyAbVcy1MDH+pG7LZx+rNT5YebSor4Vo3oqfPCs0RgF076uq7q
         +6bw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=jruixmfILxhTWdEOoQFL7x5GnCngrfxv+gs2mfNz488=;
        fh=ASSS7oZKKPJPjI0R5Pa4cKvxDYL+mSvI55qcNwjCsqU=;
        b=aOha10Z3gucVuD3G/HNaN775xWOn+NrUGRb/CzrU2aSeee3jKw0ye0K/tzWvFUOu1d
         VhZYd2aW0J3/rpxlN0IC7Rg51fxaPxOWLlhNbv1zeVQB6xEvmrKMjrQhR5O+DyyYFqbz
         Lzm6CYwAtwbmwr+VAjJnqe60qee9b3PPThDfl6y88ajl/e28Nrai2nRyeJ8WFtGqGK76
         Hugq9JgmwE4cP+4A05gZ6UzZ8WQFgBiTmIWUT/oeLjNkDqKIZWLdydjO1Xmla5M6hNfx
         1lhEfFElXzApHuBwcB732sIxPja8XzhZ6xDfMEkRhKRWuk6WH2RfDc39omr85zF6dqIo
         ETdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=PQqmStqF;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758037259; x=1758642059; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=jruixmfILxhTWdEOoQFL7x5GnCngrfxv+gs2mfNz488=;
        b=IwZ4+1Mw9YMcUOx85lEqmAJp+SQ7GZpdq16TzvnSBadz91P9Uxm37IrIrrNFVorOl6
         +SkIO95asTNEd0CjfR6JGaMRmTqeq0W26YtLzUpGQP4wtewVbdKqiSBrgcLMlLVFJLU6
         m+ZXEQRwyVcFsVEQ6iiZ1rmsVPxfWk8yLtsVmkOYUgC2UBmvOlx0+mMuJpmsyy7nJIma
         ZGdf9mt0m0dF75HmmVUqp0jgxnDQGlx/NT7KypcXCMZjrbB4qd1yFBEjDNGaK/0usM/c
         chwcbbonruL6KOtnGem1DL6hphqzOG3/pmPTd2klvYeBoY2+NuglSmpmCrQVwukLlhpg
         5uDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758037259; x=1758642059;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jruixmfILxhTWdEOoQFL7x5GnCngrfxv+gs2mfNz488=;
        b=pxfpLkMSpnij0qID3bM5Q0KUo1Ky6lPIOZ7bcpf3/gw1tT7xbd2fMiG6O5X4pBjzh3
         AgkBJqRNdT4A8UV5KXbLa1GsbibYuXwAgMIxzRdjf34t6e2cpdXHYOKuKq4yvXdEp8c4
         oje6RUFTvPNN32OCTk5bdzFjtT0L7B/xhcA/6gPt5aqIel5S7RrScF99dKDt43gkg8iB
         NvtgP2j6+D0KyuHq8GD4rAP48ScrRmqebWLdv1pq1qF5B+tPu0B7BnL2dPLnlvpxIVAc
         bf9fFATniVa1LphTKDfXyQcPAmHReLINbnRBoNTcYUbVD4n4uibsdLusRgu8HPW8ZYFU
         5HPw==
X-Forwarded-Encrypted: i=3; AJvYcCXdx4AB9TJvO191eqisxPL6qYaqexE8kF8JeBRBGgFrH48ITGj6Q01YPwnB3fZVfnzWt+qpwQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw1H0FjzTSBZtkp8DK7L7G87lq/QKPKqTH5Rg17ymdCAo5NSP2g
	GAkuTwUeiF4SbrKWbPVv66OcW/eMRhz48/Dd1vXvGg4Iq1o13yykIL1C
X-Google-Smtp-Source: AGHT+IGqEt3fRW81o1kULDvPRjW6rNMHY2QWRjNh3CVsEkVh+sQyAvE0oz4yhzymMExhbuBN2VTubg==
X-Received: by 2002:a05:6871:330c:b0:321:fcf1:e841 with SMTP id 586e51a60fabf-32e54d874c5mr9088158fac.6.1758037258707;
        Tue, 16 Sep 2025 08:40:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd75FAfqUzLuLxuALbnHtdsIK6m5HX2WMPaY6Cf1VBKMTg==
Received: by 2002:a05:6871:260c:b0:30b:c2b3:2130 with SMTP id
 586e51a60fabf-32d06213b3als4352818fac.1.-pod-prod-05-us; Tue, 16 Sep 2025
 08:40:57 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWzwytD5ND1Nx4Oc4XsCXJg6KRO8ui9A6CK36DGwgI9IHwN1QZB2hUrNGAbniPSLwBx1ayaVjvZ95s=@googlegroups.com
X-Received: by 2002:a05:6871:330c:b0:315:a259:ca5a with SMTP id 586e51a60fabf-32e51b249dbmr8464191fac.0.1758037257117;
        Tue, 16 Sep 2025 08:40:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758037257; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zub54ZyjMAHCgVz8SPVv2LBe4AL2OABm8rK7n4Xp2CWAUvx3QN4doEb9Fy4EznoU8y
         W2YYNGxWleZxpxbZEEc2Ga9FpdZxMaPOqE6t8iS540M7M4c1HkMkwghAy3W2wtKmqdUg
         LRc9jWzoSiWgOs89sNUnHsT+EJbKvip6eHnaX7tcbzTdexD3KW2v9WPS92rYLCA8hwD/
         0HssNwR0cnLDbjMAc714PvjHLGosLVMZM0XQ3ruqTB8UbwL/T6wEgIVltjgXUGHUen1a
         kJi4uwQXUqIHovCUAql2oiMv5fNS/rpbtrbxJTBQMkOVzvn2UiUMFwWhJ4LnSYQxwNjx
         SNdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VltkXuJ0ImjrM7c7KPvn1ZthaTNj+cKDQbDPexFsIHc=;
        fh=nO4lmbI91Cd31jtT7S+K6JSqWZhE5/XIxuOk2pq6Ep8=;
        b=guM0rGNsv0TmtdrZr8SLM/hxWshBpB45vKFTpIsDm2H9knzxEovxD+0YcgKKcRYdHE
         XyGoR7LdIIbSX2cLajfJb+RF7vOW7zjbJ4CkAlUx1GbVyrRbPwZYF0FNVCQOVOQ8BAGd
         ZBgoN5buPsZQ9iw7oBSRTTcXycDj7mKBjp7Q9CyI87Awpgq4LsCYBUHEi3sQx9at3fHS
         OYaG0EKOHnmHxTQcc8O/PLQh1tb0UjjbCFCOmQcjBKzELHR6ypeoS/nTVvfWfsF/WvF0
         x1D5YBaBxTWSmB1dvZQrriQw5bC9PAxYdDdVMobAdPNP2xThMt4cnKKe7OerR6uBx+bc
         +vVQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=PQqmStqF;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::7 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from CY3PR05CU001.outbound.protection.outlook.com (mail-westcentralusazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c112::7])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-331f9428a0asi68253fac.5.2025.09.16.08.40.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 08:40:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c112::7 as permitted sender) client-ip=2a01:111:f403:c112::7;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=bLTwAynldedBX4sZgt1byCkrI4NnigL/A7j1qBqTSpBywBw/BOZCfuIl7ASkL9aRAUrVVx4/yVW6KCTbHeUeJrcnxn5gZfKTQBM4kkQB51bYWHIl41s4OjoX0O2lL59TmbltVUW2wS9cBVz09PWMmx1qv/VV66sI0dJhDqz8whJbw1p9CIc+kfUmuPwut60mU5HK+DLgdzb2ChXO1VygXANDErqh1B2U6/abM9nCBRZz9AzRF194X4LiJ/q9P03mlXGDFm7In03BQOdUC8LaTdqYZ+8WEHj/x1U7AsMH0brtT+qg3o8ZJXeU/NcRK9FryxfitCEeQpP5cpoVmVRBwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=VltkXuJ0ImjrM7c7KPvn1ZthaTNj+cKDQbDPexFsIHc=;
 b=ugBAz+TpMPWChM+jQZdxSTyTQtDgX5BPaHxB927KXFsbW+IPmssmVRDmYpdHkYM0a6RikFe9dUvHxXkp2BMcg+x2xKnm1gwDDe19Uktbb1RPckG9hpH2m49xJ2cIMeVzY9RFHyI2MVU90ub+GJJR51Rdmntk93oztnrPdaFjPV/VBp4la9uaK6y/QWY0Emg//xvBYmi37gVaV3i69dgDDHu4Eue09wT84I+/z+RUTEy/jfzQOBaml4s5hpDQe/CqmcaeSJnljLfw0sOqgRNrC3gBkjridGZo+q/SeFFSntWTA2OtxBc6EChmGz9xPx53kJsx1nBKcjYGrshYcEXWRA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by SJ2PR12MB8884.namprd12.prod.outlook.com (2603:10b6:a03:547::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Tue, 16 Sep
 2025 15:40:50 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.022; Tue, 16 Sep 2025
 15:40:50 +0000
Date: Tue, 16 Sep 2025 12:40:48 -0300
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
Subject: Re: [PATCH v3 13/13] iommufd: update to use mmap_prepare
Message-ID: <20250916154048.GG1086830@nvidia.com>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <59b8cf515e810e1f0e2a91d51fc3e82b01958644.1758031792.git.lorenzo.stoakes@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <59b8cf515e810e1f0e2a91d51fc3e82b01958644.1758031792.git.lorenzo.stoakes@oracle.com>
X-ClientProxiedBy: SJ0PR03CA0226.namprd03.prod.outlook.com
 (2603:10b6:a03:39f::21) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|SJ2PR12MB8884:EE_
X-MS-Office365-Filtering-Correlation-Id: ee55a480-3326-4e41-f0be-08ddf53769b2
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ce2Mz8DSMAopEgZmeIDmN4byvpznM16vBRcdr1M2kl3tp4iZ3yWiXbDc5cin?=
 =?us-ascii?Q?SblfAJFTzErsaTtl0IJJRrZ61QuQ7FgSKy7UE5OZOLhcUwBaPC53t8QVs9hH?=
 =?us-ascii?Q?hUVYJ+DkE6C6OdmNrD8BNowE0+uUVOnH56MQBd57PtJ4/z/VMho/GsqcuTX0?=
 =?us-ascii?Q?WNbysaDBV50/gGBDvspW6JYIC6mEXX/OsHP7IyDuWltQElc2nAZ+PEDBAC8q?=
 =?us-ascii?Q?xQYX4Tbuj/tcKjspANRGBxwNEn0U3LzoQt1MKXKEbXmxLYSWR1dZRpXDeoay?=
 =?us-ascii?Q?29+np9q6c3bn6K8zDsmBAkNNR8m2L13+St4V1WheFwaTBgLbxZgnTnhypvav?=
 =?us-ascii?Q?t9gnRyy9Ssr+vYn/SfsKl855y/hgigVlWp0wBA9tQRVelBJegE0pMoA8ifql?=
 =?us-ascii?Q?CJP04TD7TGLatoUYpORNEONZq/17ahR42gcXVp1kTuffd/5ORgN3iax98FGY?=
 =?us-ascii?Q?0q7//+GQOoTZfhJ+y37r+7LRbdN3RTJFCfshMZ85p2tVGf6RySWB89SRSXOR?=
 =?us-ascii?Q?Werz8s4nlCEnv97Y3zszyylskny4yy8QbvlogLY8S5I+kJ3wfF6BcfuRdvos?=
 =?us-ascii?Q?os2mS/qIjBAmthpUsDxu9X0/4SpYMLNENMlF/sjNeHMazSZm97bmGl5Nlz2Z?=
 =?us-ascii?Q?gChnUyU6jYIqDLRacOJFWOPij1OJu2w3YAyzOkb7MOppmiDfgxA/ZpEaWY4t?=
 =?us-ascii?Q?p8js/vd+q40BdR/qBxqKev9x6duAAeQ/HX/GdGibHVfHzqAhFDzip0vw7urz?=
 =?us-ascii?Q?+TSSG0tkMgE4GTDmlPPLBFKd5NBwuh3y46BLUUa0ZQZb7lZxUYsepB4nWgLk?=
 =?us-ascii?Q?nkqM8EYRlG5kDm4+/ZTmGfXCAi5/LGLdUuOUm8Hz7z3VWVXnQuX9JmbRM1V6?=
 =?us-ascii?Q?d4TWWgH5ANoTRAyu6iTsqscylg1n4O8NCmBsdAPfTLSFIIh0l79pOm0XOrZd?=
 =?us-ascii?Q?Cpc6ZB7PCce+lxEcn1uQemTGV7i/ZOXylNbec3huSiz8mazuHvBd9LdiS/tP?=
 =?us-ascii?Q?H6rQz86PkinNQWx/PkELOE+i7iCkZImrhstqMJMcQfoFumQskVBSsUDlFE9q?=
 =?us-ascii?Q?PKS9QxV713ki7dsilxDz5jb1tvg49dbKNimSL19CLYVf0L9xwDz7z+4vInQs?=
 =?us-ascii?Q?fTU4l9xlg8ZDSTh7xJ+gy9aYP/GDHAsTix/ihaXQHmudeWmAlohcbqnkHrdw?=
 =?us-ascii?Q?XTkFCecB+tw4xgnqf1GUOiDZjFNfv9aSah/54LQSFDItN/LCe3F/er/yZKbN?=
 =?us-ascii?Q?zcYQyLdZe0oguLFS6PL3ZjK1pf1lja07nxrmEjVbuse31STM1+Dc8fi5jRQ9?=
 =?us-ascii?Q?CT56QP3kHpnQ3vpKVGLDjt/BKSEyElZMI4eh6rIjWVYowuBiop91PI8MyZ+V?=
 =?us-ascii?Q?LZbUQFaWxgNO8+/pbAJB9QT5FE/PFbE7SEGCFVksha1xn4Ct5Xi4csoPTRjx?=
 =?us-ascii?Q?T+tR4jnOJuY=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Tp0myZQNRFAOhXwaW47uk2WNGg0VUX3LAp82/xqo4uaMpEEzGMLFqXRtGiSR?=
 =?us-ascii?Q?q1Jg+KONxrN04RRHtMY3BYaalRQsiG7hApre/FzQ9wG6eF8q4Ufo7FbMPzfX?=
 =?us-ascii?Q?FzXuth7YOq5Fz/AoxH4zgXdwKvIfMVZoIl/wPjJuhjYtaCa3Xtz4drDBe85/?=
 =?us-ascii?Q?fwAtttqYA5SdxYSR6WkVp4Ow/Ho3+gjKuq5JyM8h2sLhYtocWF4gWlAd5AOz?=
 =?us-ascii?Q?vNwcuGqR6/a9C3NKp3wptjcT4EcvCwJR900gaaAwm6qn3fzNgRK6Dkbx3qp6?=
 =?us-ascii?Q?GoIdUhpSug2eeh04R4em9NYcgot7QzlTAFGt2nI1B6wHjUS51z5C++0f/1/x?=
 =?us-ascii?Q?ytzS3/Duw9ftOkfriclKgL1k+9j4NSs3wQYCMlg/oSxFukaLUGNCTSg9EjUD?=
 =?us-ascii?Q?BR1Bh1jOQatCJ21sqt01f7TSoBtXM9EnpeZHQJntfMg9wblz4MCmhAvsOMvc?=
 =?us-ascii?Q?WAjxNroqqc7OYxwLL5Whq5qwGF9/M4iyicQskWWjmsUacBDy0kYkSzK6rQUc?=
 =?us-ascii?Q?Iskr5PRP72IcAjq6VUnsNrDciejKwQO7drOwSyGBlqVBp0cwifwrQHoD5SEZ?=
 =?us-ascii?Q?yL4grKZTDuTkonTGJ8n9XxYkQhmIWM7ipCooPanH4j38GpymE8Sx09ZkcrzP?=
 =?us-ascii?Q?KoW+r7QuPPsotonAl0tISayRdEPCDVQPdch7AAMiXIcIiazgzXhTcjtkM0eR?=
 =?us-ascii?Q?R2vzkEwPaBoaioR52H2aoAcWdtgdQrEpUJb0UgCEEnl+Xrc+F7pU8UpeN9eV?=
 =?us-ascii?Q?/VQD3hPNVnKMnljB8AFjEYG+PP733CCNYtpt3iyNn1pJXna5FRzUemH0MN8Y?=
 =?us-ascii?Q?UWDCA3OoRdpoZCe2uJ320lROnZ+Ur92xC1IOYGmB1sL01i66YSh0M0PfbN5/?=
 =?us-ascii?Q?vmlKBLker0171p8tKQFe5hZfKTT6wN5CDF5Koou24Fj8ePWy67BWUYpzviG3?=
 =?us-ascii?Q?DSvRgmpix0LMoQ94aY1y82KkfCIrezsOZmliPoydIhjTeIOvPE1mzIUZVKYU?=
 =?us-ascii?Q?8vJJUkgxZ2pNoC15H6ak2cBWkp2CYm/NXrXw2FuYV/09E6bFq3wAvj+Nvumg?=
 =?us-ascii?Q?vRorUnsaQb3V9o23FSnuEjBTuVS0m90bosNwiFTZKF00C1V2/LIWyxu3tK3e?=
 =?us-ascii?Q?XFhGU2MgUPCq2kLf2dYRf3y/Ncv+ZjJyWzLvaZ8sdZvPAot4XWRtCq73ELI1?=
 =?us-ascii?Q?oBq1CcLrsqpBRPcgPIyVr0DZwIAKopjdRp9SZzjqB7MD4YaoHjjrEoyQUp78?=
 =?us-ascii?Q?sk0r0cQwvvokvzCRHP1E1nG4EnKTxCcJ6a4vrohFJQwREtPkD7Gs7hCtGLBQ?=
 =?us-ascii?Q?4Oqs9YbCe0TCPdtvLc/dAAn7IBMje5gkm/yx2X6UBEkQhRMtgBbbZLInGIwm?=
 =?us-ascii?Q?r2SCRo601ytkfK8FxrTuaOkWSDN15WpevyzoLM86sHf9OpMU/ws4b3Mj7Psq?=
 =?us-ascii?Q?vxGU/qgFnNNayzGTFveGvqGNLlnf/HH06cx+Vfv1bIGRgDqoJZLnDWB33ftT?=
 =?us-ascii?Q?He3g+db924waeyc0lJM/YlOTWF2t+wI4dG40Lw8I9Iy3d97rG3SI+edw4vBJ?=
 =?us-ascii?Q?3chGd/hixYsZCf9Bfw8lU8Sn76pxBtbOiyccrUfW?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ee55a480-3326-4e41-f0be-08ddf53769b2
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Sep 2025 15:40:50.3991
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 0T6KufBqHiV0EbtumXr/qd8XAxcjvD2Ozn4M7Wg66C3o2g9lfgFNYf0WMI2c4rm8
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR12MB8884
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=PQqmStqF;       arc=pass
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

On Tue, Sep 16, 2025 at 03:11:59PM +0100, Lorenzo Stoakes wrote:

> -static int iommufd_fops_mmap(struct file *filp, struct vm_area_struct *vma)
> +static int iommufd_fops_mmap_prepare(struct vm_area_desc *desc)
>  {
> +	struct file *filp = desc->file;
>  	struct iommufd_ctx *ictx = filp->private_data;
> -	size_t length = vma->vm_end - vma->vm_start;
> +	const size_t length = vma_desc_size(desc);
>  	struct iommufd_mmap *immap;
> -	int rc;
>  
>  	if (!PAGE_ALIGNED(length))
>  		return -EINVAL;

This is for sure redundant? Ie vma_desc_size() is always page
multiples? Lets drop it

> -	if (!(vma->vm_flags & VM_SHARED))
> +	if (!(desc->vm_flags & VM_SHARED))
>  		return -EINVAL;

This should be that no COW helper David found

> -	/* vma->vm_pgoff carries a page-shifted start position to an immap */
> -	immap = mtree_load(&ictx->mt_mmap, vma->vm_pgoff << PAGE_SHIFT);
> +	/* desc->pgoff carries a page-shifted start position to an immap */
> +	immap = mtree_load(&ictx->mt_mmap, desc->pgoff << PAGE_SHIFT);
>  	if (!immap)
>  		return -ENXIO;
>  	/*
>  	 * mtree_load() returns the immap for any contained mmio_addr, so only
>  	 * allow the exact immap thing to be mapped
>  	 */
> -	if (vma->vm_pgoff != immap->vm_pgoff || length != immap->length)
> +	if (desc->pgoff != immap->vm_pgoff || length != immap->length)
>  		return -ENXIO;
>  
> -	vma->vm_pgoff = 0;

I think this is an existing bug, I must have missed it when I reviewed
this. If we drop it then the vma will naturally get pgoff right?

> -	vma->vm_private_data = immap;
> -	vma->vm_ops = &iommufd_vma_ops;
> -	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
> +	desc->pgoff = 0;
> +	desc->private_data = immap;
> +	desc->vm_ops = &iommufd_vma_ops;
> +	desc->page_prot = pgprot_noncached(desc->page_prot);
>  
> -	rc = io_remap_pfn_range(vma, vma->vm_start,
> -				immap->mmio_addr >> PAGE_SHIFT, length,
> -				vma->vm_page_prot);
> -	if (rc)
> -		return rc;
> +	mmap_action_ioremap_full(desc, immap->mmio_addr >> PAGE_SHIFT);
> +	desc->action.success_hook = iommufd_fops_mmap_success;
>  
> -	/* vm_ops.open won't be called for mmap itself. */
> -	refcount_inc(&immap->owner->users);

Ooh this is racey existing bug, I'm going to send a patch for it
right now.. So success_hook won't work here.

@@ -551,15 +551,24 @@ static int iommufd_fops_mmap(struct file *filp, struct vm_area_struct *vma)
                return -EPERM;
 
        /* vma->vm_pgoff carries a page-shifted start position to an immap */
+       mtree_lock(&ictx->mt_mmap);
        immap = mtree_load(&ictx->mt_mmap, vma->vm_pgoff << PAGE_SHIFT);
-       if (!immap)
+       if (!immap) {
+               mtree_unlock(&ictx->mt_mmap);
                return -ENXIO;
+       }
+       /* vm_ops.open won't be called for mmap itself. */
+       refcount_inc(&immap->owner->users);
+       mtree_unlock(&ictx->mt_mmap);
+
        /*
         * mtree_load() returns the immap for any contained mmio_addr, so only
         * allow the exact immap thing to be mapped
         */
-       if (vma->vm_pgoff != immap->vm_pgoff || length != immap->length)
-               return -ENXIO;
+       if (vma->vm_pgoff != immap->vm_pgoff || length != immap->length) {
+               rc = -ENXIO;
+               goto err_refcount;
+       }
 
        vma->vm_pgoff = 0;
        vma->vm_private_data = immap;
@@ -570,10 +579,11 @@ static int iommufd_fops_mmap(struct file *filp, struct vm_area_struct *vma)
                                immap->mmio_addr >> PAGE_SHIFT, length,
                                vma->vm_page_prot);
        if (rc)
-               return rc;
+               goto err_refcount;
+       return 0;
 
-       /* vm_ops.open won't be called for mmap itself. */
-       refcount_inc(&immap->owner->users);
+err_refcount:
+       refcount_dec(&immap->owner->users);
        return rc;
 }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916154048.GG1086830%40nvidia.com.
