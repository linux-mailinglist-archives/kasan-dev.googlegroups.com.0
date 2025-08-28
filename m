Return-Path: <kasan-dev+bncBCN77QHK3UIBBAFPYHCQMGQE6PBLKEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 16E8BB39E93
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 15:20:03 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3f20528fe92sf6268915ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 06:20:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756387201; cv=pass;
        d=google.com; s=arc-20240605;
        b=AS5SFC/CEuZcZH8ayzJs1qW0tm7gAkDZTjik3KxBrkaWOBSZZDAqLN90u6kmcIGQlx
         hMLXkA5h0pVZ0752ck3XcefE9tgIsOe1Ork2CdYQo6F4P61Rjub6MFfTYksVLmLNTGJ5
         TTj6QIG9uxjLl13odipBQNyPpjq4/q3v4d11mfyPogiJ1NsEvvYtRI5stUyPIJZYQciY
         PhGciFBnUHmP7Yi5qf5J1w65b2hhqwAVncfA/2L40QeCxDEZNIgWAgVh4T6+Df4TezU+
         Fsi8kTcKK90Pt8X8ScaGK75i8JOXTtWgMVzvItUHariJbFeuftgf0GhBeR1NExZeFsZH
         j1kw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=6ZNx3caqZg18Mhzj+o5u5Z09ybmvxoKCxPV7UiZ+JPY=;
        fh=yCVd+jABJ6TVpy0B2weM1UXmRCbfLyEiavcFcmDdLbk=;
        b=ZAiBgXLaZeI5DwF6xxxVLoi3Ndrftawkot98XC4cXkqiQb3KAPw2deyELOb61FreN2
         CZokz8yv6JMqX6MPVMKImZSTL+3arBSNLNxGiojoDyDkljhqkBXk/FQb6wDBlAZ9UVFK
         /A43qs/5L2BkAbn/M4mnZK5fWcOMH54Xj4Q91Pkrz1h/70ZH5lPAfRPk3aAtx6TbVvCR
         LBDOeNe1Mxe+M6cORhi8BKboAFf3DoJ8fM6WnZY5yEUdqVT1NbA70MuBw4K5FlKaBOnv
         fCCSWQY9i4QxLcaycC1aoxylOJBpx4uOz1tCruJEMVtVi/Bd/LvEj6S5B4j/T2FBA6Uo
         BuCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=JT+bc4m8;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756387201; x=1756992001; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=6ZNx3caqZg18Mhzj+o5u5Z09ybmvxoKCxPV7UiZ+JPY=;
        b=kxUM+A1vaY4q2rTdxQ8ayvLAj3NABVuZOpwQgs0uk0a5f63CJtYvrvaP/Uaou/oiON
         2mJQvq12i8AFM/R3C4fYdGjXo26wPyfZEm9ZQ5n+wwp7zAjRVwMvnvEWUZPKbq1Yif+Z
         Qbbxd6IPNyYoFRmxB3TgBw84lOfhO7CXDFrakK3BHKK7Lq89qY/IpkHCNiH3OwTntBu2
         2gUDvTtbnOGgKyNNwV2VYPhWRF3ZWyXQz+En8fOjWvPGMS1QU9yLpYLb+LaDgMfgD7Q9
         naAGCrQEuTUdAS5xO+YSi9rl0eAWbMZEsarB1kDtQsaEk5RGZskAuZnNb44jabAORFqy
         Oc9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756387201; x=1756992001;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6ZNx3caqZg18Mhzj+o5u5Z09ybmvxoKCxPV7UiZ+JPY=;
        b=RtBXEKBRO02MADaQDyR70MXP4XkWo1jUJjcAXcycPBGjDMeoDtOqehVDshqT0yx5zm
         geWUc1bxlqasEm7gB2Ad5o3jW+9Og+xhy0hsyqTdmK06myOpgV7iDsogWgpveNtxJRi1
         UBJHkASWEDYHJcT36Mjppp/9ZYaGTzptO0Xtkcchhu3868wUD8Y7Dl+IvmIc83SFe3SO
         cyYz9XXlMxTwqyKf6N+PF2341MMV6e9K9vPMCovech6xvhNzyROEKuEKkh0aOC04WF/c
         ezeOHP2Xn3Pmyug1eyG2kzKWVeSgYcRwXKIOw8CjTpFUIj9c/5RJnvUNKKZ6L2mU/KYu
         ZUvQ==
X-Forwarded-Encrypted: i=3; AJvYcCWNMWbA2s+hK5CdkIAe21kffurn5RXQ/kTgzWNC91rPH/W6b6W0ghlMzHYLrOoFNeB/psTu3Q==@lfdr.de
X-Gm-Message-State: AOJu0YzV9Mf9JEPfRmEt+TSCGpXVbHH42MxxlTW6St7Zp4PkuhxeSl24
	sfr3FpfuhCRrzoQyVbpLWPHza+uZAzVdVpcNRsFI0o566Bx4qnxUNOuQ
X-Google-Smtp-Source: AGHT+IGZU4iAN43ZHJCysa/KbUOu+pBzmHe3sgIzjKfwL5T+MoDJw8raWzxCAcgXS5xy0atmaHJLGA==
X-Received: by 2002:a05:6e02:12e9:b0:3ec:248b:8760 with SMTP id e9e14a558f8ab-3ec248b8877mr255423525ab.18.1756387200794;
        Thu, 28 Aug 2025 06:20:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdAY27p1jf2qXwRg8eQIsI+8eynrAAAwkQa09phPPK9iQ==
Received: by 2002:a05:6e02:12c2:b0:3e6:6d07:3b6 with SMTP id
 e9e14a558f8ab-3f13b933967ls8269285ab.2.-pod-prod-08-us; Thu, 28 Aug 2025
 06:19:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVw3L0M1QGooQCI7xXZFLS/KHCbkFd89iEpCBj/oXi8iSaLFkbWQTvrT8uqn/nZjGv91NFwgg8sg2o=@googlegroups.com
X-Received: by 2002:a05:6602:13d0:b0:881:94db:6c1a with SMTP id ca18e2360f4ac-886bd13f3e5mr3721627739f.5.1756387198859;
        Thu, 28 Aug 2025 06:19:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756387198; cv=pass;
        d=google.com; s=arc-20240605;
        b=FgKgrQ5jWZ4udRqe53RX+ImlWRq8RhuUbp1QwI++7HPdRQ85h3WUyrQzatvJfefTct
         KfZSWKAFqoqNpsaGZF0YCfPnDaRRW4ReJbBbcnfuDGVetUgxwNrupXGqqKzOaIbqOS91
         HrNNMNYhI2z8vFs3PUf07eVf0g6UA7ImVwlth3G8Fhjj3wGtbmyGGSfGmZTK+JnWNiUE
         ZRQYcUO+v1usrS/PEFGyE1eF9JuSlTMjrI+7jAaJhfV2hiq9sWMKikELKyLAu/Qk3YaB
         CZKQ3Jc2GGq7IiljMyFgqN98BoQ+DVtC0bbgzsupU2AJGkr0tsLeWh0eA1y8iFEREP+C
         ruwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4bzh3sRdiHvsU1MRn50H4G6O6O5GsLWJ8BJxu5aE6rE=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=eT4ra3HbKUOWRi+WvjCSwVTLZ1OLAGQcMUSxrP7YPVZEsq+GSITYPvfzYs4CbLg3sB
         jxDmoLZv2x+eIeacXyVVC8WuBEjui9F/cIDjUbsHQcEN8MuvWjZghrKynDV2ZcKM+KJO
         Cb9g98HEaBccSZHHcD+d23k406UBi2YtdEclqkrrqIcxQ10YNGKy5TQ6q9cV1M6H7Fbp
         b0nHsyNPuKPWVdE7pkxbeNkF1VMpehBh43EUJnPrj3vizoCI2xmwOF2/o/qZ4Y193Vp6
         YC/qumXdMS6zCSK30UlJZTBQ6+SJx7HDapeYbaewVK4UGUuRaq4CgFImTYJoLjkzwVeP
         SJ3Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=JT+bc4m8;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on20608.outbound.protection.outlook.com. [2a01:111:f403:2415::608])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-886c8e4ca03si62998939f.0.2025.08.28.06.19.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 06:19:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::608 as permitted sender) client-ip=2a01:111:f403:2415::608;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ZzQY3SPMdzJcRH2NaxYMCUGh1smdZKe5L1ToOK2d+c3BXvnXfTQDM35T/Q3uhNGL36zhEdenj1cLdMClD2+iZh4KFqGkZNkiQZ2N8JUDIwUQ9okBuaw2OSkjbhghzIoHzKm64CMiG9/C8ucCVaVWJV2GRqFjN1NHXxcWIfMYMpoe5Vq13pqNPugBJKczxq35lRwELJr4DE2PKbxg1Rg8wpaJqYPcJXTAXnjHT5hCovxdCI9E51l5ZJGgVtojuHZNFpkDxvqah9v+qTFfwpTuotJ4W/g+E2BbMgfvgBUIQZEMUwfeXoEruOzImto5RVR02ev/tJBtk9Rh7acwOOc4tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=4bzh3sRdiHvsU1MRn50H4G6O6O5GsLWJ8BJxu5aE6rE=;
 b=e2cbz7pe7MKWyTsnjrApM9DHOpl9dWJrgSkd/hXfh+yV+uKAOPQycuD9KJASCjdg0UPuvnvqF9NAqmJQfD9CfpaJSbuvThqe/+OTMpqryG6GUy4QnS3AiRTBT+KlZ095atJlI9301Qo4BhOg0SmQdcmbAknVVF5lKyc6u3pVUhUH6VZBbhAzpJzvMpgNrDxi7bGrTtUsOshPcFj/PFNDt5R3jowHwUNY/NKROJQRoFpq44cpRqQE+mp/Tm1yzN1RF8LHYfA8ZhR5If9xVmqHU61luaXAMqTuATkWh0c5tZXNOaKxXwGWOsSstptqQX6TYsQHBOgRDZxE/pt1/tGj1g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by MN2PR12MB4454.namprd12.prod.outlook.com (2603:10b6:208:26c::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9052.21; Thu, 28 Aug
 2025 13:19:55 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 13:19:55 +0000
Date: Thu, 28 Aug 2025 10:19:54 -0300
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
Subject: Re: [PATCH v4 03/16] dma-debug: refactor to use physical addresses
 for page mapping
Message-ID: <20250828131954.GB9469@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <478d5b7135008b3c82f100faa9d3830839fc6562.1755624249.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <478d5b7135008b3c82f100faa9d3830839fc6562.1755624249.git.leon@kernel.org>
X-ClientProxiedBy: YT3PR01CA0117.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:85::35) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|MN2PR12MB4454:EE_
X-MS-Office365-Filtering-Correlation-Id: 98e0bd0e-7a54-443c-025d-08dde635944f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?k+8dDmD8jCsh/xvM6iISMbsAkoTdIU5KrL7/zcpYogAL+67glalk5Ih8gQuz?=
 =?us-ascii?Q?oLJxhj8wo+YkIIdJ6hvDjHstEHxz0urruEcYWpLQ7JeySOnkFx0/+F8fZ9Oq?=
 =?us-ascii?Q?r7ujl+dhCvU+5I5EbziGGjIv3pP6VJkVJqAQkddiJihCj81f/ho17bVZQgid?=
 =?us-ascii?Q?aaE+dT4UUjC3LoMDYFboLmrN8qBPFQXMCNGSdtWsO3wZ7AYIo9seC0jFdzEZ?=
 =?us-ascii?Q?jxazmREApbwCqrq4GwCkfKd7dI/+VR707BG483jwbiu7l8NHS9gt7tpuWOL0?=
 =?us-ascii?Q?Bh0tVbGJ+QdljSOx2D7QJy6VPT/7+GS5iO3DVFAhRCGNrFWU+XYQWoT5YUpl?=
 =?us-ascii?Q?7dPtAx+5VWBvQxOgCjofme3WBrzNtI2p5kdMldEmMY0G8qhFY5zZXta5qyF3?=
 =?us-ascii?Q?tpThNBuITD1WVtZymQ+eRIvJqc5lf8zJDB73/4EQcQHoVpG6I50V4IamNga8?=
 =?us-ascii?Q?N1CZvd5DhIuu8yia7ZWBKaF8JgZUebrITgfiPgjuYXYA9WPcmIJ1uBqnvUHZ?=
 =?us-ascii?Q?7QlfKq+0cOxlE/JzwuZQsdo2/mAl3gV+FrPXE6NHxEZVmcbZLpazPU7hMZwo?=
 =?us-ascii?Q?yzCCjjKG1L33ioCNKBIq6eyS4Sdt5g1YWTGFbV6Ze28CskqsSPcvnyXXXiAA?=
 =?us-ascii?Q?7Hz+qWxlupJE2hiMPNq/zLPwEc1pyTE6MLslknxXk83UpJ6NW/Wfc4qbrYwj?=
 =?us-ascii?Q?0A6DfteJIY8r4uRZzYnQksc320P0cLHfNIHL7kBaqKCmDIIStWIiy7+FTY/b?=
 =?us-ascii?Q?TFtsVGsVY9x/dgo4fdbbRxdHdDRmJUVGejeD/UehSuPYSl3BLnOHoX2a5JFy?=
 =?us-ascii?Q?WtSNsS5JzyWDjyVO6VkSu9XwNFL7Zt4acd3zBlGaCzo7bpz9Pxa7yEnPvzF8?=
 =?us-ascii?Q?viqiTCDo7mJyiSldpo91TyvV1w98iIdpeUFJ8a6ZKgh0AO2nCTNa8Cy7uIOp?=
 =?us-ascii?Q?GRkVxtAXNdtCmp8yfjxreP/plGfzufiB2cxzHNEx5aWvsSUZlM6fSfhYD3fJ?=
 =?us-ascii?Q?bGNuGc7xFkNw1vp3GRzrm3KRk5tKxe8puue7Vm0CInGyxoPCN2/z1ynXRRjW?=
 =?us-ascii?Q?FZ6le2i02YbHWqh925/Aq6MdIp455kADNHJEuQkbDynujsviI92USMG58SFC?=
 =?us-ascii?Q?qQif0FLJBZxFbVS219j5LfraP8gfnA51s61vsM650No/ecfrcTH+HhmbJKM3?=
 =?us-ascii?Q?L3r7RNFrRABjgxvOSLmIbRAySkSoaaTBPEH5ycKt7u8BDQ8aT/dTIvbw1dvB?=
 =?us-ascii?Q?l0l7gBDdAJRW14UubUajha5bqYMOjc7LWNPJD3gUVGSp38Bug+svKZaM0cAd?=
 =?us-ascii?Q?hgSd4S4h5UBUEn1oI+mt73c/+KayUGL7xTfGoTK44Wn6Tu1aGC58Z8bAAN57?=
 =?us-ascii?Q?ld1x5ylpJco4tPeQ9miQKs4p3tYFtzTb/xoK1yJ8VmjHocwnI7rtnd6g6136?=
 =?us-ascii?Q?lllLg9etUOI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?G49m0TxMaCSR9+sEhQY4qbirLMqcHfa7aWh9Pb5nBUAj3+Jf8PRe5VZdJ8eK?=
 =?us-ascii?Q?skj0tb9amp0ku1st9QwxXegm1XcHOVAbA6yIVLsYZyLL84jj4zBhZWQBCw+S?=
 =?us-ascii?Q?nwCGf7bTuE6nOet9Z1OxpAMwpcWqIBCxTvPTOPuVvaGLaJ/pHNqHd8gG/kAa?=
 =?us-ascii?Q?u3g7uHSvwML6mIIwWWceBUQ99oG7rOSC6Du9DuyWoaVUmSWkJDyfZz5HUW+Z?=
 =?us-ascii?Q?BxtMv9/l21mo+96FOwaCV2QxVYxVltihhZoSlvI+2J+4GJwU3oHCR6ID82fh?=
 =?us-ascii?Q?Q9vLYwN5xyKc5tBYwvf7VKijbnSyzT8bJJRugnZjAqU1kc7MQjb+/+Tpwnv5?=
 =?us-ascii?Q?lzMR6SVDi5Z/6h7OV5VKt8kYJ8eIk38G8vCTlhZYfA6DFc4BhtrYg8HLtRf1?=
 =?us-ascii?Q?N6E8Ad9VT/oS48kgXFc1wbrhqbyPNxA+OkeMjEbs11DCqD6QDds+OrHYsWQk?=
 =?us-ascii?Q?yih85IVfFagRSVADbCYxntfxSuXeRgrzKkYjnvaLGNy0/6rvwLeS2c5qPwN0?=
 =?us-ascii?Q?0EZG92eD1Zr6eKoaFYnZrd4gcLSYOyTk+jmBrD3NrEcZYtnyTUSgQuhIdwW2?=
 =?us-ascii?Q?G9IMgG/+M83mhPvjdgSTuYxVX9shYm9UQFcVY00wKCJvkNhNx0jMKqJ85HrV?=
 =?us-ascii?Q?MPULToD73DvqB+0i2F7j3MQOaJNnqw5jOK199TFM1xpZxBY9WnczApuUEMzH?=
 =?us-ascii?Q?cBuZjJVhtOalLTXim+p2lS2phyeACB0K2NbJngATxOyNvf5W3FZ9xQRtC4bw?=
 =?us-ascii?Q?zHf1AV3hcXIR+DJLaocdT1I5MokwvvnqknEzb3ZrIJxMKdzlJB8OWPsO20K+?=
 =?us-ascii?Q?dmudEfNTS7OxBBjA/x/x0/PmNf5HNNoSeTaia2U1P7TsY0Toeo+bO119FOy9?=
 =?us-ascii?Q?M279qAiM3G9I+J/c9DJXru3Iy6UTvxADrbfQ+RFz2Qg/XXFEdM8yS/TCDD4I?=
 =?us-ascii?Q?N5PmLWdUgV/LO9lzoRtKgdkQGoOkAjoMcDXJRuYtDS3KR6nqY3xSWhYTSVxY?=
 =?us-ascii?Q?0UHMKubB881KtR75rVblPrN6RezbxQfGbTBlkattBZKe1/iDTca6w5rLV+8b?=
 =?us-ascii?Q?e0Ay4TLuK3C3HGm0vsf8DhqFW5V0GU3cX6v8W9oY9S9QudiMzs73xsT7zzWG?=
 =?us-ascii?Q?1gS+SHfO2887AHfz4EhjsY8OdtNxszD1uRCIZ6eBwA++BMeUvSjhqTPemG13?=
 =?us-ascii?Q?I1DrfQi1k/yXNHkrg0ynt8FoiobhBBFDCLQiQGN+CfasucIGRIJCLoXhYil+?=
 =?us-ascii?Q?ouk16WqTTQjFH2PNlv/jWYi83XV9YO2V1YJMYFDLxAM/ycX3ztfjalAYXfCN?=
 =?us-ascii?Q?vblNawnFDJG8UnqBI/LQpoekB7zGkcmXbAjU7Eon9BeHzwybxlHoDLjRUHTB?=
 =?us-ascii?Q?TQq0IbiwnjmjKPa0cIx4L43qmwMcPn+h3D+okBvd7Hwu4h53wFGX9kU1lNdH?=
 =?us-ascii?Q?Nnu7JmD2+ljRcOUGZscwfzlv0qyfWQ9+oUpewrOA5syqhvI9WfSNNsKZ298q?=
 =?us-ascii?Q?kjydLlwrld7DdisTxnbc9HAM6tSaRbPJ+yB/IuiE7cOS9iRAKd5/jkNy/zKh?=
 =?us-ascii?Q?sixdG//PUfxq5oWPwPQ=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 98e0bd0e-7a54-443c-025d-08dde635944f
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 13:19:55.4513
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: bfVAJKqjXmKqW2jIhU81Ah+D38AfCDhv/W/9SURBzpKwO4cwIbxbEnM4n+rS62qC
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR12MB4454
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=JT+bc4m8;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Tue, Aug 19, 2025 at 08:36:47PM +0300, Leon Romanovsky wrote:
> @@ -1218,19 +1219,24 @@ void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
>  		return;
>  
>  	entry->dev       = dev;
> -	entry->type      = dma_debug_single;
> -	entry->paddr	 = page_to_phys(page) + offset;
> +	entry->type      = dma_debug_phy;
> +	entry->paddr	 = phys;
>  	entry->dev_addr  = dma_addr;
>  	entry->size      = size;
>  	entry->direction = direction;
>  	entry->map_err_type = MAP_ERR_NOT_CHECKED;
>  
> -	check_for_stack(dev, page, offset);
> +	if (!(attrs & DMA_ATTR_MMIO)) {
> +		struct page *page = phys_to_page(phys);
> +		size_t offset = offset_in_page(page);
>  
> -	if (!PageHighMem(page)) {
> -		void *addr = page_address(page) + offset;
> +		check_for_stack(dev, page, offset);
>  
> -		check_for_illegal_area(dev, addr, size);
> +		if (!PageHighMem(page)) {
> +			void *addr = page_address(page) + offset;
> +
> +			check_for_illegal_area(dev, addr, size);
> +		}
>  	}

Not anything to change in this series, but I was looking at what it
would take to someday remove the struct page here and it looks
reasonable.

diff --git a/kernel/dma/debug.c b/kernel/dma/debug.c
index 06e31fd216e38e..0d6dd3eb9860ac 100644
--- a/kernel/dma/debug.c
+++ b/kernel/dma/debug.c
@@ -1051,28 +1051,28 @@ static void check_unmap(struct dma_debug_entry *ref)
 	dma_entry_free(entry);
 }
 
-static void check_for_stack(struct device *dev,
-			    struct page *page, size_t offset)
+static void check_for_stack(struct device *dev, phys_addr_t phys)
 {
 	void *addr;
 	struct vm_struct *stack_vm_area = task_stack_vm_area(current);
 
 	if (!stack_vm_area) {
 		/* Stack is direct-mapped. */
-		if (PageHighMem(page))
+		if (PhysHighMem(phys))
 			return;
-		addr = page_address(page) + offset;
+		addr = phys_to_virt(phys);
 		if (object_is_on_stack(addr))
 			err_printk(dev, NULL, "device driver maps memory from stack [addr=%p]\n", addr);
 	} else {
 		/* Stack is vmalloced. */
+		unsigned long pfn = phys >> PAGE_SHIFT;
 		int i;
 
 		for (i = 0; i < stack_vm_area->nr_pages; i++) {
-			if (page != stack_vm_area->pages[i])
+			if (pfn != page_to_pfn(stack_vm_area->pages[i]))
 				continue;
 
-			addr = (u8 *)current->stack + i * PAGE_SIZE + offset;
+			addr = (u8 *)current->stack + i * PAGE_SIZE + (phys % PAGE_SIZE);
 			err_printk(dev, NULL, "device driver maps memory from stack [probable addr=%p]\n", addr);
 			break;
 		}
@@ -1225,16 +1225,10 @@ void debug_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
 	entry->map_err_type = MAP_ERR_NOT_CHECKED;
 
 	if (!(attrs & DMA_ATTR_MMIO)) {
-		struct page *page = phys_to_page(phys);
-		size_t offset = offset_in_page(page);
+		check_for_stack(dev, phys);
 
-		check_for_stack(dev, page, offset);
-
-		if (!PageHighMem(page)) {
-			void *addr = page_address(page) + offset;
-
-			check_for_illegal_area(dev, addr, size);
-		}
+		if (!PhysHighMem(phys))
+			check_for_illegal_area(dev, phys_to_virt(phys), size);
 	}
 
 	add_dma_entry(entry, attrs);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828131954.GB9469%40nvidia.com.
