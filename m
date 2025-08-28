Return-Path: <kasan-dev+bncBCN77QHK3UIBBB6XYLCQMGQEK7URVHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 45593B3AAB5
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 21:18:34 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-70de0bdb600sf25521156d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 12:18:34 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756408713; cv=pass;
        d=google.com; s=arc-20240605;
        b=RxWk2lp4zgPstBNh+1MsqcxOby5bc8FzPx5Ll0gl9cy+tKYsv2bkkJsk0MY5C7oSO2
         +HKRxZa+VKzwOcds043wXeNFl4jSCCl5ZNr9C444DD/aleermZWulLw7SAB0Q79/P3xU
         U83AYdJ7fSCPA0Cs50XD8Vyn+WB4+SlpRDwjMuESrExD25/8uZBwJZJjEeXyrEPsuUS9
         vmj+06rxAyK8g4OOxoaWPIQ7sXfpb3v7/OEZ+ah7rVwPb5G241yNSu/u0RqPXF2525bx
         wK5naSFnmG360AeAG7G+rhJA0kEuYtCnTpsFfhc5gKPoFNjTNefuLmY2ruyzgGRYFmuy
         PBbw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=UapAph9UaowSzGFkk6HZKzLCs9SKb2246Gp1ilSqaGI=;
        fh=wkgaBuasWolVXM/B//NX6XYq2kvGjuETdUXanqHjSSA=;
        b=FfZiaQaNyc9P0IC7jm+Izwvup+D/TDxXbfI4NoVxnZZ3dv7awT2hQX6mgI3Jcw/Rye
         tBqTeWyh+MxAU7LOlMDY2HmOrfXF3a9HsXnXCyKw4BUyw4G1kGN4k0Kg0MJVxa0eiOes
         kvfhIDQBXg0cyAGODdFA1jcKkD7SbiJKcv48FXU0XbI/a+6Zg38Ha1RmryO3dfm2uZ2B
         dN6A3T0J8ppKuv5V6EnuugMIRrnybHgLtVoZIsdfwvSY4Xl8BlpBpkNttm2j+7Bl2ur9
         eSAAbSGb0mp22w15P2txjGizfdTVB2u1o6IOvTb8517bX2bCF2v0ZIAHCILTgzsR0tC7
         HACA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=kUdpqfjk;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::61e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756408713; x=1757013513; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=UapAph9UaowSzGFkk6HZKzLCs9SKb2246Gp1ilSqaGI=;
        b=CNVhf4jabXJHJXp/PnUwJqGqYec9Qg2Ggeo2kcZcK9YKDfJQNlgqbU78zuzfZrqxdF
         ZP0MDM1wDIJOaSZxKhZ02wLHo3RPqXssOK39VfVfxOSaVRy6upw43ikF7hEzbgmV6mZ5
         qdApWNQs4bHKm1VDGC5IjQM1/ohpovdQBticJ9yXjueXxJses/A2N4svEn26juZAjIDx
         DDjUZf9zoE6/2uYZD1p1/AGtWzr51RlwZyfi1kF/QpPP4sTstjT2UkinJqXMgRKWs2Fz
         yXfARrFTIDuPgBEXMzW+TlHa5mrD2t36FZ6BPjq8erDe9aKzUeq3CxKbP0CLlq4d8xf4
         WTtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756408713; x=1757013513;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UapAph9UaowSzGFkk6HZKzLCs9SKb2246Gp1ilSqaGI=;
        b=X3ygbpsLgnk9bGsShgd8EAfxBcvFuVPP/SRkK49aFG6gBZJu3n0DES1hz5+Irkqpfo
         3eystpvBn046vYyUCs/JSFTeMrMZhYXHRms29p2PVbYqMEv3uKsQyqgYjjjKYoe6io9r
         s6w7HXmWgF+ZggPn3x60OfUSXxKC/rQbcCYF+U20IrNmBrxe+VhaFjgRJCrXkZo5Frcc
         wC2PaZSzurERiNZCLS9yMhVOKH0qKz386dLqBW9FyKfhRHVBh0d/H2po4h1a/f0tCqZd
         ndgPO2eMg4qUevkDKkv5NCLaGcrjefqu/FMZXbBstCLlc1O6eO7uoI3TX6kRFZciIR0y
         CPOA==
X-Forwarded-Encrypted: i=3; AJvYcCX5d4o5EpcvK8yct7f+2ZXYYmUk2bkRklyYCbIncQf7vVb3ZCTG/E2fvZX19vZMEBD3OvM/UA==@lfdr.de
X-Gm-Message-State: AOJu0Yw0Gdvo9FxUYdPYHZZ5RClltN3anVyuPYDmK0IUXJiDZktvYuzR
	3VRwb/FHkEF9WWMivdIbXfgy7Z3GjNGta2HTA8Oa7FnKRikBfY3rFroA
X-Google-Smtp-Source: AGHT+IEMLNTeigwxSo4WGxcrvQEaQp3cYJZDGdnMcDqS+z1q74LP0hXWRa30TwuZ2SQeOWG4P5/Y5w==
X-Received: by 2002:ad4:5f07:0:b0:70a:1346:e50a with SMTP id 6a1803df08f44-70d971e9195mr252244926d6.35.1756408711647;
        Thu, 28 Aug 2025 12:18:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcP3ZHM/ucmH/096K3AkolX/H4cb8i482w6JnWLu+59yg==
Received: by 2002:a05:6214:301b:b0:70d:e7ba:ea21 with SMTP id
 6a1803df08f44-70df04b1e47ls18477316d6.1.-pod-prod-09-us; Thu, 28 Aug 2025
 12:18:30 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWmmdGXvN6CRrudvXALJfs8Ko4V73+9C4sNzOp4PElU4KQwAvRWf5U7+p9ETZjeqidXYKHnpFWUnbE=@googlegroups.com
X-Received: by 2002:a05:6214:20af:b0:70d:ed1f:38ab with SMTP id 6a1803df08f44-70ded1f3d53mr57216196d6.15.1756408710151;
        Thu, 28 Aug 2025 12:18:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756408710; cv=pass;
        d=google.com; s=arc-20240605;
        b=d1LKBQnS2pMpwCa1ZGV88ywRwBJQBJCPbh4EeQvGr3tgelgakfDOmkwyxehQkvmMdn
         /rdpXkLAbEL2mA+0iWlr7h08S28oZBoKJHFYOmIjlihddzYpmnfghLhZzEPQouGZ5lrj
         b70ica23JzZNvhyvE7O2mOrwPVWV3vsPmhby+50Zr33KdRZsziLf59f8zN03KtJGIsY9
         xr/kTnSVGGX4TtAj0mbhgA7wDzmT01oW/UAgMLSApQlSRY1IWK9dZUWY0i4btgHsfe6O
         t+JA7sQuEAHksHp11w1kaT7oV3ba/rEgJPjbic43T8pvGowUbdFI+QukthFwAAVyivKg
         BHwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0mgqg7jv533EByceZHfSmVEnFe8pbA07e3o/tOscS54=;
        fh=KNrcxmkEXOCGvlInKu/iFbEeiPtFjj53/K2rpPyAzag=;
        b=f59yC01Pt9aa5W0fMADJs1FOoJ2tTBo0VlA0wL+y0idrkJ1cABgAmQ97KOZaWhwZp6
         b+4XyfzNRsAbGUDcjCm8RKe4QZw8Db3BII2VbCYTSaJQ3dh44TyQQobW1cPaFDv/kQMO
         bL5xkmMV+B9XCSlv7nYQ2ClzKr53izxlDt9eo0sL8FW5StoDpeJiYTROO35Ja/UeeVEP
         VmHLAgqAL7aqd7Mhie3kHA35vGvYBDaG5tfF4LrKvxsg9nL4zT1IrPX9eqUQva2CTCOd
         JxLR3upT+AoZAZRUoGn9OH22K9lGe7tvEAci8EmaL91KkXqJ15D9fHDUg9zQDPUQO0k6
         yDAg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=kUdpqfjk;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::61e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (mail-dm6nam11on2061e.outbound.protection.outlook.com. [2a01:111:f403:2415::61e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70e624c3c2csi54496d6.8.2025.08.28.12.18.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 12:18:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2415::61e as permitted sender) client-ip=2a01:111:f403:2415::61e;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ewH2ieH5LDzBiW3oheyBFwIa/Nafy26BsTHhGXxP7b7oUC14NAtvTcoMrcTe/vUn3asLXce8N7ZgywJeBWvbYuqtVhk8LHfBS14S/3ApUUQJAoxzcMIrv8UGGtdiXt3PIk/3AK/ZM4b5WUg1vPLXt3REDtkapOr6yV0q9GHLjiDEwejVKMtAM8sCsEsUEZaOUMdDzDbYSynev5JwfpIiOHFliZ8E1Kj4H3F5xp17cI49SV1htvUuGW/AhcQDyAI1yR84Rqn4omafTb3RS/siwn/lNZSgQuBICE7YiCC8yAT2+LanLJ9QQMZaqoDD1GDDVWm5JZtJMKigGAA+ULBaCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0mgqg7jv533EByceZHfSmVEnFe8pbA07e3o/tOscS54=;
 b=X/7wBUXT89nTZbGqbEYuSk7vOfv4nCYGYmap/KinegRe3Rv421Q/5BOmPy1DsUX0ZMSRf3qBc/2fdRB4g5y2NI0ZqHw6QonCPIyyX4MxS+WNjkPC/5Fl9cQSPlRvR79DQiBitxLE8WWHv9XhLh1j62d+C5QYAn/gPMP4q/r891Hz9nq5CTkNmLvbgqbNqYa5pPcpKPxYz3gti1wcdWoKNPULQC9cVGv8fEDezkmtBEEqpkNkFKnX1dLkuLj4JGL3RvjXYwfiAQJ8od2bpzAzM/jexnkcb8vdnV3vc1qP6FoP7NAOGAUE2wylRptmaubaFD9o5RL3yCfElffu0CDaHQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by DM6PR12MB4483.namprd12.prod.outlook.com (2603:10b6:5:2a2::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.16; Thu, 28 Aug
 2025 19:18:22 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9073.010; Thu, 28 Aug 2025
 19:18:21 +0000
Date: Thu, 28 Aug 2025 16:18:20 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Keith Busch <kbusch@kernel.org>
Cc: Leon Romanovsky <leon@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
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
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <20250828191820.GH7333@nvidia.com>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
 <aLBzeMNT3WOrjprC@kbusch-mbp>
 <20250828165427.GB10073@unreal>
 <aLCOqIaoaKUEOdeh@kbusch-mbp>
 <20250828184115.GE7333@nvidia.com>
 <aLCpqI-VQ7KeB6DL@kbusch-mbp>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aLCpqI-VQ7KeB6DL@kbusch-mbp>
X-ClientProxiedBy: YT3PR01CA0075.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:84::15) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|DM6PR12MB4483:EE_
X-MS-Office365-Filtering-Correlation-Id: 52013604-2e30-48de-7d56-08dde667a72b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?tkzamAbH5/chdWZm3ke+JvfeqA3hIcFqXbx+r0hKEizINFNE62neCHrkqAKo?=
 =?us-ascii?Q?GQw1qGDwSs3TS+26QCrA6PZpWQTzbU7LKQ83Uk3UlOHPCCU5xsrzJujNvddd?=
 =?us-ascii?Q?OehQwAUTsfK303zab5MCQrE09VBsGUPilNO3T1aJNCEGxeTULuJSZ++yxYJl?=
 =?us-ascii?Q?FlgvgSF4OFzaaJgeeBlol1BfkrZ6JutsedecnGm4fadF5v5qKcKkWiSbYaJZ?=
 =?us-ascii?Q?Q7KjhQ6iuhaaGW/HzzlIcBryVYIb0zhXbiWM4yz4pdVBAHmsOWn6fPztT2xI?=
 =?us-ascii?Q?CgRX34Dd+L7XXIfkzThN7GixgLCdVKm/6H9auCcYq/eKzShWVUTsPEydphF0?=
 =?us-ascii?Q?hEK3AkzSkOoGpwwvg0FLHnLPk0TD00/jZFYa3uDjrMy5OulejmplpaRvV4V6?=
 =?us-ascii?Q?1NbZOuS4LbRXHz00PF7LNPB4tvbLwjY3oMDtREd6DhcoP/FkIIGOzeePZqqG?=
 =?us-ascii?Q?WkkGYvEVecOnHOOSSoW3JNtWVbVy4dGBpVsFLSE2uKt1GcFUimdOxlgnSWCT?=
 =?us-ascii?Q?n1sEZlVQvw0hj9aWIErVnvFGFktiZpBDhCD2fu3frqGLedE3pDmml7cC+ReI?=
 =?us-ascii?Q?cMsV0hImSgwvs8E/AnS50UBlUAyolgVsq6eH5ZH1jJOUragJUXshbOpfXba5?=
 =?us-ascii?Q?cPQhE4fwX4mLT7FjuHd84RtUJREUcfXJWWyXODHoCb1YzVEB0tBhPKDwq7cp?=
 =?us-ascii?Q?bySTSPdaFAusmpRom51YWvAmn6Hp/6NrJxjapCZW1yJrpVK+BMVN8gxGE5Cc?=
 =?us-ascii?Q?DZyKydvUnj16k6RLTbxAd1leamkUiJZDWOxq05NnolwwWkxjmqjFEu8F9P/D?=
 =?us-ascii?Q?cvMezD4FVJXuY8ceXcbif3j0PMPr3UQ7Eb1Rww7DEshvjDp7lq0FVtGrmYyx?=
 =?us-ascii?Q?Sc0Zw4f3m+YzB/F+367AXTigA5Te45yigKc+JeHBCMBmoxnKTLDaBZNr1sqA?=
 =?us-ascii?Q?ZmXloRKJjUp3ynhRIVRkYhTwGxSnnJdciu9/ZTrcceii17N/AEDJHfIKbOLT?=
 =?us-ascii?Q?/Hb9jteFnXzwUZmvAVv+0RB9OI+llcTWo9WTcTQ0e1eVKPAEJHe6Q/XtWOkc?=
 =?us-ascii?Q?OeEcZpGJdgTn/n84ku29rld2xou+WiWBYXA/H3vsJ1OTobb8aiJwPwbPxGtD?=
 =?us-ascii?Q?yaAffWzTS9fNe4HpURb4JmcRYfadnPNLI1BKTRyB3MspRKVn5YNcrYJpsdzB?=
 =?us-ascii?Q?6RXZrdUiV1cE4+kPAYl/AZ5U4TGPKYv46MdftVKtqd7hjHbCc1iMk6Q3PZ7C?=
 =?us-ascii?Q?E16vp2SHCkKZhX0qaRcMz7wlPlC2FtYSSrXBmsyKzcKZJLsu35FPtenmIy79?=
 =?us-ascii?Q?sE/+9vfZTDd5IuPwUz2p8tCwsmScDWcRlJ9fgzWu3Z6D/chLmAqP8VgcK8nw?=
 =?us-ascii?Q?G0RW1qpUFifPjZx5cixCprrw5GfKMKhHdzQbEFARFE5AhBor5h9+bECVAmYX?=
 =?us-ascii?Q?o5aUVOB9LeQ=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?5ky7gd8aT6zgXZ3S9u2dQ9wfKPLFRzCut7RGugI01Pf4Eog4OrfHb36oULUM?=
 =?us-ascii?Q?lQvuNDmGms0FsQm7SQAbJXvnFC2FBGxUqSisCJWTxG1ACYv3V0xKN0dTF7SE?=
 =?us-ascii?Q?yZQUEEGvX5PoOXyQz2eNsEDzmPQObvhzReHlm0bxhkUjW56bHpTHH7EwuKBO?=
 =?us-ascii?Q?1/FD2o5bTIp/+kHebgvLj9elgC54ARBPQVtbai5ZtYiSiOOvGRzeSOfC+FtM?=
 =?us-ascii?Q?sQif8EXHeXuZlAXZ53QAbPOs8Xl11PauIjy0sbinkp+ArJVGXqXqQmd1zeCb?=
 =?us-ascii?Q?aXLppKpxeIoNIJR++6stE6QMJdsPMPgHyaQoSSUPKImjqz80YZi2wVie0n36?=
 =?us-ascii?Q?ZakI0sqTWwh5Rkjou+uZG6R2ADTmM48hr/zKeFcIl1Z7cYLpGMfccJWUKxXU?=
 =?us-ascii?Q?ZKQk44HnnxbvyW57MXYfjwxhrjSUmIRVldoky0tEKDSJfzTLziPOy3V5OyYi?=
 =?us-ascii?Q?sXOVBCWqmMb55IAzG5VxU90BGilWh4lthyWGVDyN4c+JJpn/DzUNkbIgOEt5?=
 =?us-ascii?Q?wtmLF6Mt+eoEZ5njkBtUAbfPU44Iwat3iOLVTJIVf/WS5gwHMC5EoOHv5H97?=
 =?us-ascii?Q?gUB9BJfHfcY6sDZw6mXn857jfuIABDcet8nLyDqr18sdyk764gI31BdGI4NV?=
 =?us-ascii?Q?oVBrIahCpllgByOuio4OUUlrjXx6LrGXn22qthTjwS2vnK36xgjlfurJKFoy?=
 =?us-ascii?Q?+yOdBxt5KD2hw8/SdbYNDXrsZkF/SynBCKk8fHB9K5nBDDP/evgule554rpj?=
 =?us-ascii?Q?3sMnqD5o78y7mOIP9EUfi4YsWNAhib6Pb9LoBFt5ChmCISM9//zhPKSil2Ux?=
 =?us-ascii?Q?smPk9BeuFpSkfasaiNlnuJ/5NkmprQafGR0xa44/6Q40vIKgDIzWsFKSDd6+?=
 =?us-ascii?Q?oO6J1DfbJz7fGz2bwXX0/GqrLCuVj9V0oowgXGDa5aCN0S3DFSGmc2EkQxfl?=
 =?us-ascii?Q?UllYeNA7AM+ttA0/FbHgkD7h9actDtyrlsBNKtBS1L/JfLRTUlNGBbj4XHVU?=
 =?us-ascii?Q?9u1l4DuMFLq3GivCBp1rZOd2os/O4iAvukZ422zqAuYLSQu8BSExUTOEvtiR?=
 =?us-ascii?Q?39g9mSg3Z535dtWBdo4nP32e4AHmvrQe2SLI/1Zz0FD2CbGwSGZuW0DtQM+A?=
 =?us-ascii?Q?frdJNMjWVCbo7AxfwIFSPhy5G3IOVygXoRBQ4V04M0wfBpTVJ4KqK3pgULAQ?=
 =?us-ascii?Q?0CL7r6hi5Fl0+yoNYyD1Ohwow+fi/3TGY8RJtNHC9AetvMra5ckKM6cRuotU?=
 =?us-ascii?Q?wLKR80vFplmKVrRTjgMQCVUSMQ5eTRZ1qaPH3k8Up+5Hx0c+oSmZCcN7tQOY?=
 =?us-ascii?Q?2/cN3Gj6XPil0H1Ik+KhKjq0rJ9o49M7L9fITJUQ31uMPDEn3Ymg5H5Z+YLl?=
 =?us-ascii?Q?PvRGSfqJwpB3FJmweuifLM1Ek+W5g4JGeM0xcWzd5hCEZHYIGbt4JuyRm2Rb?=
 =?us-ascii?Q?84vjpS3yma0Dv0io44RAe1eO3CHnVzinSkzulYRLZvA7PgTCrAG+JR18Tgtb?=
 =?us-ascii?Q?/xJj0RtMfBIYhpyZblffBKIRpMl7noh10yYTlcjabPOIoXVPPHSpPkM6n+R4?=
 =?us-ascii?Q?vIw0P2IDKKahN6lpEoM=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 52013604-2e30-48de-7d56-08dde667a72b
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 19:18:21.9042
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: hHBOMGpozkeIevL9wLHwQhy2eRzFmZhbRTFbZweAUasp+caHeKpopNq0/07EWPc1
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR12MB4483
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=kUdpqfjk;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2415::61e as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Thu, Aug 28, 2025 at 01:10:32PM -0600, Keith Busch wrote:
> On Thu, Aug 28, 2025 at 03:41:15PM -0300, Jason Gunthorpe wrote:
> > On Thu, Aug 28, 2025 at 11:15:20AM -0600, Keith Busch wrote:
> > > 
> > > I don't think that was ever the case. Metadata is allocated
> > > independently of the data payload, usually by the kernel in
> > > bio_integrity_prep() just before dispatching the request. The bio may
> > > have a p2p data payload, but the integrity metadata is just a kmalloc
> > > buf in that path.
> > 
> > Then you should do two dma mapping operations today, that is how the
> > API was built. You shouldn't mix P2P and non P2P within a single
> > operation right now..
> 
> Data and metadata are mapped as separate operations. They're just
> different parts of one blk-mq request.

In that case the new bit leon proposes should only be used for the
unmap of the data pages and the metadata unmap should always be
unmapped as CPU?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828191820.GH7333%40nvidia.com.
