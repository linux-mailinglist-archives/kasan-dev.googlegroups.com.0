Return-Path: <kasan-dev+bncBCN77QHK3UIBBQFU2LCAMGQESCWJH4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id DC962B1D7C2
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 14:21:22 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-76bf30ca667sf2006166b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 05:21:22 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754569281; cv=pass;
        d=google.com; s=arc-20240605;
        b=dmO9E1cOWTgGvIjJYxoOEi3tE9El0rFYxw45ZmhUYBNNkLj93Q1FCh+JDxUAN7SOXX
         lJJ/LFpD4x+asKIuu7UgkZTsNB9s9CukwTD0XEZ5InPkSIKDlkH6/bRoowWki77yjbgm
         dF7fc/qWKoQdnD8G6Y9CmEIV2FHpLHUyvONS5D+/in2isMcud0bBw0U8FDWs6TGtTfBH
         jXio29Zc4ExNL+UwfquC0qBKamS1vacAMCzgltya17AScEJoubm0cGUvtV9J/lWGdbxU
         5L4cnqGRDCTTXFL4Y6Ojpos51QK8a63uKtl+tywnqoJX/ZwZsMs9uQkDFR5QoEAVaavG
         cpdA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=qYoTfNQI0y084+5V0SswlH7Rm6ms5B/Qqw3S3uLtkGQ=;
        fh=d8JtuSUNR38kA69ibuen1cgkOzlT6SeJxv7JV2Gs06w=;
        b=bNAmhh8+Yz3OodGaenP3FEzI9SwCeveAOgLS/MHvkVnXLK210T1uDwM7Ein1cGMqae
         q3bZs2gah4XGzZM3yv3g1hLRVAsr17WDvpoe4/vqNW8iCmh/RlFogaNPyaaAg88gdGzl
         uBUNn3e+9QHvuVB5rsWEBtxcH+QZ0UU+UaTZ86ZsGoXHqtpyz/5PUcbKA6WYoisj0/U3
         0o+HT1SRlKEs+lQLmEXeXMHTbwsI25wNQz5FFwlH0WkuIZlG2C3HTx3EwVxBcmjnraZu
         +AnCS4C9INH+Gcucbqi/x1xUgTdGalTVU0LsI3ukum2Qyv8UaLsM2jy7iluiuhXIgpuI
         vT4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=DQup7Rl0;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754569281; x=1755174081; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=qYoTfNQI0y084+5V0SswlH7Rm6ms5B/Qqw3S3uLtkGQ=;
        b=nl7qYXC0Jvtg09dwniST2aQsJ29gLjG/qesXo+kJ2rLgHQiej3iHRztbXoJwdy+/jf
         ee9o5KFtlhUEQJFNnJl+KcU+mGq98egk05NTomhJEsrswN9EL4ViMIHT0lCICOMalEb5
         WsJgT/i58Sq2GeEqA6k/klslDg6LTCiIs1/sZ1h+toXCSuC0G+NY/7VTMhxk6mMl/XSg
         jZx83n0zp3/36ShiChzbrRuQ82k3AMmeJILskivhRCdzAMJnzDhYlGMF2B9pjCz+8gGk
         GblkuyztJjzwh3iXtTzRSl6DHXo3zPwDyfsfYn/0JycLHT2+/+c7dSdrXOe/2VdcYYwa
         WpOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754569281; x=1755174081;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qYoTfNQI0y084+5V0SswlH7Rm6ms5B/Qqw3S3uLtkGQ=;
        b=bLVoluCCJOQw/j3JSX30B34BX7kB4sHBKPXMpl0M6qaALwIg1qYLmMjhxg7ZgWdA3N
         OasfYMIUNnyXftHIgfLj9LzZHz1JWDZnurGnE7Xx0zOz5B6XDfQLwKsPmR9IWhigNToQ
         qnSrhp94omxbDEQQZCvFkzauFqWLBSH8rC8dI6glNpFhyDKeDChAFCwwJTxt71o37K6J
         moPpNozknmktBTEAwMDra5EpYcN7III2vTD/0L10OOxKK35C+X3yEbTjzKWgHP1wkH2s
         GYmultflgQpNvd03MEtmQB9XfB9acO9A0vzg2zagJWqyhJWk+KANFukKXX4blFgu8Ysf
         fDMg==
X-Forwarded-Encrypted: i=3; AJvYcCVJPkI+Aho4dVr5fUKYz22z5s6lgOxu9UTR/6vdrL+2ux36eVXtMOndIpXySghpY+RxcbTeQQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw7OIFFYRdMzhZeIeNeuaTHx5zTeSn2mC/LBXDZhlwH/KNniUlN
	wl6nqO+XbWrE+q5S8aF3wpn9wMqVQo8subdQ2eIpABTy4flSikOuufLk
X-Google-Smtp-Source: AGHT+IHyLiEkvaM+LMpwkC+v6jt7NMu0Bncsyrw0VP4EO4NLNGOnfWOWKWQQ0b5LXqwObUfTl6C/9Q==
X-Received: by 2002:a05:6a00:2e15:b0:76b:d746:733a with SMTP id d2e1a72fcca58-76c2a936514mr8386105b3a.21.1754569281056;
        Thu, 07 Aug 2025 05:21:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfvRXBEazjBjecONo7b458k1KYMg0xEyRtG9Npqb7UdUw==
Received: by 2002:a05:6a00:2e2a:b0:730:762a:e8a with SMTP id
 d2e1a72fcca58-76c373099d8ls1189110b3a.2.-pod-prod-03-us; Thu, 07 Aug 2025
 05:21:20 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVw7kVT4K4BuMJlm8ae8J6nwroB07pgqok/fDzdeP8yqOp40A9zCFAZIud1GqLTOeRw9hwhKVOBwlY=@googlegroups.com
X-Received: by 2002:a05:6a00:c89:b0:76b:e868:eedd with SMTP id d2e1a72fcca58-76c2aa4132dmr8556200b3a.24.1754569279728;
        Thu, 07 Aug 2025 05:21:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754569279; cv=pass;
        d=google.com; s=arc-20240605;
        b=JqJK+rCFFqW7dQP6ho0T7VKGriOfTEjWvxOP3yCa38s4whSbsTGcm5CB2UyrzDmLBQ
         sCke5p8KrLRHKPJ+olhGVp8OEFQSsBhaNZVbvlsJhkba8l4S6FyJNOkMWLk0xJRr1kAJ
         WTW5v/ghCetIU0CglLenjz0MhVF6ijNZ7QdSBrNQptgEANWzeQDiN22gZ76I1nXXnsJn
         akWjUWM9G5WuyYIp3Mewh7HPOGIl6E7uFAS6XR6M5CWiSj4n2HA7iXI9j6S27NsxwOnC
         i3Wp3e877lgr7S0tk2CABuCl7avUoMVFrbfrbvwj+SpGaCyGWdL7KJpnqsKowPm/1Agq
         zVcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iIwrg5hZVD9n+qTLo0PvHeRDi9M5OxJeYXC5xQMGF9Q=;
        fh=VMfw2gzyREGX1JofMT1gcCpWqKSLg+gjAQJxJFK9/B0=;
        b=cZZLQ0yWr/tXakx+oQdDLATiaQDgQMUtmooZxt8pfnOD3iDntQuZEMypW4lh609anc
         TNLNR7H8ItVWaWxvW315eO8HO5ZMZpx+CMUMHS7lw+pb3/u1sBT+HYt36/5n9LvqQ643
         JYGTQ4xi1Oz4rtLhs4OaIYKvnBT+J5IZZUJJO75PO19L5x/bA+GvqrvEfQ/BOSJFpuHc
         vozjHWUEa7f0XP1t/sM+328Do8ShR5WDyyey1h+aBltzRZs6ie7ugaL4e2QiVN0nXkYT
         hI/rjs+ZbZCunvu+Me/sYaDGDZfoEtwhRkasm/GmTXZKNp5npdXUSpysfaBot7mp+AMQ
         ajnA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=DQup7Rl0;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (mail-mw2nam10on20608.outbound.protection.outlook.com. [2a01:111:f403:2412::608])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76bde87104bsi554282b3a.4.2025.08.07.05.21.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 05:21:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::608 as permitted sender) client-ip=2a01:111:f403:2412::608;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IEnBLU6Fn+bvJuFhXrDOfeHZfZZJoQUlnjFqSU03DmEaY9Yg1dFXTziUDvd/KWouXotCCxOmhxm0KA4hRUofvg7E0TGwICjC2YD/taZ0W5TziXaOIHDbqvjbm1a5AypxMBpknPjxcTrgi9oQS1+Xq4UO5BXlILBEwR/dumMdLmVtAvleshemuIAw8HiOMw1TB3PpbXYyA1ASxPQNUsx6utSMluw8LtvxV2hbzLXjDahxr8QqIDzKBKDOYifIDni01kVBzAgH7uuZ8iDzAoOkc290QmgVBrGpn0yE1Z/bJtlag4IDf2e0d7//imy72cj+VSnuCmoBQRkVlngN9wsWyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=iIwrg5hZVD9n+qTLo0PvHeRDi9M5OxJeYXC5xQMGF9Q=;
 b=iwE/xLTfCyrC8ee1vw4uEG+h34Wn34VeltBaXYu0i2R1gGo9E+A164UBEkCPjYt50rregiXdeh0ja+goDDZ6BiAaUqe/mDjdNl0UQR/M81wN9t899qhRS6KFPNRDVxHnxOYLWMp+InYZ0b8bAopRHOKt7PywTQ63lCxXQBCKkofpy8ooKCYQ9MH8FH8B6G3srzOKf4JVyw9xMQslbXDy+YL/9F1L5UTjI0R0cVkhiHYQzggro9YNqOyXwuFdN9vjsfF+9F3t3uF6tDwgXC51K2O5hcaGOQzDKrAF/8BkQaEV7Y1s6+u9s5ku2+vpT6hS1xAlxSWne/hWbBxGI7xDYQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by PH7PR12MB7017.namprd12.prod.outlook.com (2603:10b6:510:1b7::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.21; Thu, 7 Aug
 2025 12:21:16 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.017; Thu, 7 Aug 2025
 12:21:16 +0000
Date: Thu, 7 Aug 2025 09:21:15 -0300
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
Subject: Re: [PATCH v1 08/16] kmsan: convert kmsan_handle_dma to use physical
 addresses
Message-ID: <20250807122115.GH184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
 <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: YT4PR01CA0406.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:108::22) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|PH7PR12MB7017:EE_
X-MS-Office365-Filtering-Correlation-Id: 59e07372-234c-40d3-7ecb-08ddd5ace814
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?QcmCtkqecLuYtDCnDoRlhvSKgTT5O7jY9fB7njAfEKgRuCXn50LnrysE5XVh?=
 =?us-ascii?Q?HHHAN7z4/J5xvUWNAd3tJhECZcp7Ql+pgNOvcReDfVhuleC4cKTABMpRRtoh?=
 =?us-ascii?Q?aY3QpyTNWixXI0gB/Y4bf1i1lT8HgfkH22q3+mhuQjKup1cVCn6hVl1BZwTM?=
 =?us-ascii?Q?mQpTYRAobaFMQ+OieoSqdQ+Lxj/3WOZ5z1/Gf2LnPEJ2GRKDAbWCU3iM0ud8?=
 =?us-ascii?Q?YC8EqhMwZSSB/3PBhrlTUGKhsNGF8BD/w4jfVA9l6wu/Uk86IG6ge7vWCFyo?=
 =?us-ascii?Q?kys6scYUZbPmGVPGrvywN0OU0G9R7C8fFpcYWMS0mwqVs7RJUMf2j43gIgjb?=
 =?us-ascii?Q?1fkWj8FpnK4bqhJ6pM20nVi0Dt7MNeF0YXVC6YN3C7G4+tfDc+/0gbvqF0Hf?=
 =?us-ascii?Q?usdP28UmpouMZ+UBUtbvL5o+J9Jj6e7EqtPy7C3deVPbXbtBcEveSdekYWWp?=
 =?us-ascii?Q?eaBvTB72MXmZ0735k5aAjIQ8fovIiJhhQejPXveYmqemQduWz25ThPoM1eqZ?=
 =?us-ascii?Q?hvUfKNSh3d21kWNdIOJMdt4WJ0MVo8r+zlHv62h2e2nTLgea8irXlEXv99+t?=
 =?us-ascii?Q?9abB1hQHhLLE9Tfh2wR7W3Hv4Y5lDpziV0LihEpXZevtAXNlboY+/0zE57IU?=
 =?us-ascii?Q?eXAFXMryprJkz0Obz9A0FVlXqO7sNxgYzuodXDJwyagnQSPjhduZXH6990zv?=
 =?us-ascii?Q?A+EYPTlyDjqoZ7HLgtD5T5J9C8MG72WhF0RuUZ7lA0rRbCDq0JZIeEWucW5V?=
 =?us-ascii?Q?Nui9RZGHtiFjRBW4RPuPXgXYypDKxdIwo5LThSu18WEPH6ps/qKfmDYuhW4L?=
 =?us-ascii?Q?6ZMnKQFL3GSt7CUeR26oVB9QFDDPOl/8kKyQivG6jF1zRVwRx995/P4nDTpF?=
 =?us-ascii?Q?bc6sVQoQedRLp3XQ+lU4t3UMcQUXd/b+fvekmRIAzNfKiyGTRfyAp62p89e2?=
 =?us-ascii?Q?7GK5Fu/VExPANjI47G36RPW0wJib+9pK+2+trRdzfYAVg30PXQEVXXXJtfhR?=
 =?us-ascii?Q?TngMZsI9z808iwIf65gqVo6z+OnVmGE+VyNH29KQrQxEylaWxnnfsPvCa+dY?=
 =?us-ascii?Q?xr65GLLJ6QJPeptcsV2b1pN3feRXI/KS4MRmpbV7S+7SeriXKufdylnQ0np5?=
 =?us-ascii?Q?wT4DGlcCFyqgN67yx2P0pHr31Rr6xVoHlhz512Q7+gLbRoRtEQXwCa8vWE0G?=
 =?us-ascii?Q?RJjmlFkvOlyEIUtxEsuQ5PpEzFd+k421rblnu+aj8YpKBCxVDbDzZxTrqvZ/?=
 =?us-ascii?Q?UK2nUKn6Wr2rC3kP2pJZ0D4D2wM0vgGYWhXl16x6dEh/DWhyd/7bOhqKnbKa?=
 =?us-ascii?Q?VNx7NF7SvFys0FhkSckJWJ4fbB6HvKOfE9kd8h4YHoZ2g1ofRjy+wSp3vrL6?=
 =?us-ascii?Q?RxlnheXz0ZYQJjEeRGoG3MIG8njgEYIwj4HY9Pap/obbXlLpfoBKGKw5lLH0?=
 =?us-ascii?Q?pWbcsn5FYYQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Pc3vrtdK7uQ3bBQh4HJXdZhAoMLJBbNO+o6b6SQK7JlS0PAL+ZySFf4fmVdb?=
 =?us-ascii?Q?mIfceakcMfVDPHrfP45m4OdncIOaahvpJDFi6KaQUZtVPWJHpIS/+AdiZ2wh?=
 =?us-ascii?Q?9Q2/0qvT3Hmnvhwy2IhfV6Kpk5iVzD6zVFL/9u9FOb2bzU77MAoKSsLFWTH9?=
 =?us-ascii?Q?ZqKyce9MRdpe+RIaTD5blMdKNW/wIIlrtUNrkctASWqipNngYLPc0h8xIct6?=
 =?us-ascii?Q?fV1b8QUAI7TEqblWMxtKN52Vw4lshjLvTsnYS1/fupCu9PQzHyzdmc7BMag/?=
 =?us-ascii?Q?9USsKZAU+mpsX9xyjtf1piM1pDFFYZBGzPppZl9HrgnKeQNcSf/tQpG5OVK3?=
 =?us-ascii?Q?p4kAkYoFaMt/n+ktLk7aKmt47wM9YYjxIhNp5pEd4xHC3EfLwljN3wRqvJ50?=
 =?us-ascii?Q?EXJjKlCI/PJ6iL6IM8I3PoxGPy1I4I/aWl+oz7JH5Pc/o73gOlCL/NelVW4J?=
 =?us-ascii?Q?vR5M9oaGlp1c4HGfhB4uPSMXRASguqiRAhlCMFxGHSpaF8eFzv/K93QZ+W2h?=
 =?us-ascii?Q?mPLhw8Nae/i12HukegIW/6hQDtyd3Xa76UsmmJWTF1hL+NMt0s3ehRtfnulL?=
 =?us-ascii?Q?/mWRDfidY3adfRrJ907pVXv7U9bY7Stcz6kr4LwpeiYUZ2In36hPj22VsY+V?=
 =?us-ascii?Q?+GfoOWGYYmaE5XwMZYD1qLBrK6CIe2bNHmA727jh+sjvPWLG7f+ZZ3GN559Z?=
 =?us-ascii?Q?jYdEBUb1etxVXR46PCFUJ4fHOSV1glLwUmqpkJ0Py15dbLxyYAZh93o2Iz1K?=
 =?us-ascii?Q?xpPllA29goRc3asGj8wfcdb0rQ7YLFCFo3rBMIoBJCsSaQYphu2eqFETyMjA?=
 =?us-ascii?Q?+QkoLVY8A33MyqAB1Iw0tsxu8b+xtrwmr1hxZHMzJyWooM7TdUaSDRkY7lZD?=
 =?us-ascii?Q?FAgXFW9f8wKN51QniBbbgDXkKECwNCXwMu3zH/FFqpQq0C9MiGhECUySmL0o?=
 =?us-ascii?Q?UhMPaQSlMgKqJm+aqgTyGXBDX8mTGT115vrv49BVv5pm6F0atvp4UpzP+nIu?=
 =?us-ascii?Q?q9YHaZYPAXY5q3fln1otyE6eZ9w+u+pdrCDj1yqm1fvNC9jMRfs/vD3IvjdD?=
 =?us-ascii?Q?AkxPl0GL2pZjdEQihDiiY25or1gYy1d+an+dG+QLiHqa4UQ/XBaIvocRDJ3g?=
 =?us-ascii?Q?YdUQgpoSERS7ydpHFp2ccuOJ6JEBUU0/jK7BN1HNQFapRgSsQn38Cuh8nZqQ?=
 =?us-ascii?Q?6p+AreHWoxfwdlexNCoF3YxozoqVWr0am8wJbLzVAZ49RdRgrZygj1JY5v0V?=
 =?us-ascii?Q?B4xCyWa9sLxVoivN8PL2coCjhGr/mi49MWlHpa2W5fejSdZFUhWsWXgfOqJC?=
 =?us-ascii?Q?S4iIvnAXHxWF3bWS2PCpJz7OXmmnsg9IgaSwXrgG0M+eZDZc16V8JpcCO2mq?=
 =?us-ascii?Q?UFnD6SqIs6zN9IqGVGwtUp9tdG//QjZQGA/RH+6hKwFCsumcaMWK6lT3Wo5D?=
 =?us-ascii?Q?9hjlxhWz6r0yvZ8JevHtLQ/0kVB0fUqbPpmV2aIQq9VgY1o1Fc8/x6h4KltS?=
 =?us-ascii?Q?2r8lBtj8ktp7EwM5dokDtJNHLfRfLiefxas8cMFz3Q2Uxigb/bfiMpCa3Zui?=
 =?us-ascii?Q?mY6Q9aoX7ek+jFqDOXk=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 59e07372-234c-40d3-7ecb-08ddd5ace814
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2025 12:21:16.3528
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 1JO8XjpfI+n/ktzlAxi3pKObP/UQ+HQjrheHHMFaNuRrOBpujcfgJK85cLbLXwHW
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR12MB7017
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=DQup7Rl0;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2412::608 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Aug 04, 2025 at 03:42:42PM +0300, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
> 
> Convert the KMSAN DMA handling function from page-based to physical
> address-based interface.
> 
> The refactoring renames kmsan_handle_dma() parameters from accepting
> (struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
> size_t size). A PFN_VALID check is added to prevent KMSAN operations
> on non-page memory, preventing from non struct page backed address,
> 
> As part of this change, support for highmem addresses is implemented
> using kmap_local_page() to handle both lowmem and highmem regions
> properly. All callers throughout the codebase are updated to use the
> new phys_addr_t based interface.

Use the function Matthew pointed at kmap_local_pfn()

Maybe introduce the kmap_local_phys() he suggested too.

>  /* Helper function to handle DMA data transfers. */
> -void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
> +void kmsan_handle_dma(phys_addr_t phys, size_t size,
>  		      enum dma_data_direction dir)
>  {
>  	u64 page_offset, to_go, addr;
> +	struct page *page;
> +	void *kaddr;
>  
> -	if (PageHighMem(page))
> +	if (!pfn_valid(PHYS_PFN(phys)))
>  		return;

Not needed, the caller must pass in a phys that is kmap
compatible. Maybe just leave a comment. FWIW today this is also not
checking for P2P or DEVICE non-kmap struct pages either, so it should
be fine without checks.

> -	addr = (u64)page_address(page) + offset;
> +
> +	page = phys_to_page(phys);
> +	page_offset = offset_in_page(phys);
> +
>  	/*
>  	 * The kernel may occasionally give us adjacent DMA pages not belonging
>  	 * to the same allocation. Process them separately to avoid triggering
>  	 * internal KMSAN checks.
>  	 */
>  	while (size > 0) {
> -		page_offset = offset_in_page(addr);
>  		to_go = min(PAGE_SIZE - page_offset, (u64)size);
> +
> +		if (PageHighMem(page))
> +			/* Handle highmem pages using kmap */
> +			kaddr = kmap_local_page(page);

No need for the PageHighMem() - just always call kmap_local_pfn().

I'd also propose that any debug/sanitizer checks that the passed phys
is valid for kmap (eg pfn valid, not zone_device, etc) should be
inside the kmap code.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807122115.GH184255%40nvidia.com.
