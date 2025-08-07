Return-Path: <kasan-dev+bncBCN77QHK3UIBB6PL2LCAMGQETOH56IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id BAC84B1D9D4
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 16:19:39 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-619b502dd19sf1093472eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 07:19:39 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754576378; cv=pass;
        d=google.com; s=arc-20240605;
        b=PnHromxe5xEsYrXvhEnG6yUGs8DL1nd1Hb3Jz2qR0D/8D0zVqIQkO2OyaI85lGpyen
         7Ivt84PCDVaCbtAdWgDIV0d5xdibir9yIE9yXsgEoiRduqrJUK/RNuD0TnjEj5HPYA7B
         kUTQ1PxshUY3TXr6Sw+o7wCgCB4DmCVM50QWcB01s+04SiRuvR3zZDf65KER0HcbLJsV
         CbERXQBRMBgx8etfIPpwCIjyhWkZ7D3ud3cLuixPxbmE0OHBGIFvgz/OullJ+TmV73L3
         4vboSzlDxCOxaLjynw1vX/Gc4/aAZtJ3IL/KsQOnbhUHfkO7IuDB7XyV2hd9DA7mvG2o
         v98w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=87trSBynjMxlBYgCU8TSuyxWLfBsr6Qu067ySHH6TCU=;
        fh=CXIkN2ypSafO5LhdqPn6lxLzlvtI5WcwnncQ176qI/k=;
        b=OB6/mkhQk0OU9Z2w726QG785b4U/+qfoddIlX5rnFh2owdZoK5A4+XD2LXndUuZryP
         rdni8D+i1e0S7HXaesUML1ymkzklDRLz3K0r9rLBoSgYdh5YVKgfg0HudKQTayljU29A
         ebQUPcOWYaqSd15M2cdZ92mr49Jurfn26uZ6N7hgOZevwVztVBeihg1fqGGJxPFCEokv
         KwEPfaqgBKJMy/mVu35VIJPzgXmZGPorzP0WnxxG7gnjzSomga1G4IMf/brGsNrxavvN
         TX6YDsFuV5ZlUwCj9fsgRp/oVfKR6Lv0x4Fu9zIH9s+QsW+KXZhu50wPKYhPjI8yyfBi
         fk9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=UvWxmJcX;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::628 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754576378; x=1755181178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=87trSBynjMxlBYgCU8TSuyxWLfBsr6Qu067ySHH6TCU=;
        b=ClEflswB+haV+055tk9aHEkikdk7bdURR5D2mtosOaRiq798x6eLkPqK1ipSFz8i1h
         i/gMIBSKM8qtoKksWNUB85/ledbydqElBc8oh+V39hfIPe68ihCiyG0zdS4IzkHNmNLG
         +ql941TcJ8y/pCS2lulLirlGsbMc06UaMXYFhzKS1E0obk15UVEmFxlIRLP2oOHgsg/c
         J8Bxle2QFwGCBYVk9h3+H94T9wO03vCvJubX9ysVv/1fB/zih5VIJPNJVpvtVlHyTIpk
         QjX5WCRdmrUuvN8CAv0azYDnyaEUmonBERv1SptMsbg17Hp7C4fjq629qlWdef0oNivT
         t5XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754576378; x=1755181178;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=87trSBynjMxlBYgCU8TSuyxWLfBsr6Qu067ySHH6TCU=;
        b=fs9BXujOvSpiu3mNqmnEz4v1aQW3ekjVcL6UO8mrPcgIWOCJ4vYDotA4xzWxXX5L9q
         blsJ/udyJQNisl6TtgI0qr+4MSGAbxibndlNlrWfDZo4WfVrAsNupV4q4Q2wPOM9fjGw
         BmrbAEb6Jk8509tz3fWnLhCGCc7p1rhDhr5Hep3HVMPexbehp91o+D5AKAeFynzKRuED
         O7MZgUon8mtT+J1yfnAaWL4fVLHiMgRx5N6jrkRxZSLhtT3mv98sAYcSzPh4a530tmbN
         43EI94rLrcmMz5qMHAlHIIWJ1gCIh+gA26EI30DbIdW2Govg1cW1PG5iAx2b5FFMysyd
         8O+g==
X-Forwarded-Encrypted: i=3; AJvYcCV/uaTNt2nrtJGXcHZNLiyaXFGy5kr/9rlVBdtzXa/0FQPP08g/h1fxKPB77F1azLVDjp7Giw==@lfdr.de
X-Gm-Message-State: AOJu0Yy0cyYuWh5olwc1qWaqqjp+8EiYfLUM6bmQ1XUyHfDVSD5yYpQw
	0Uo1XmxXF37B9dr/z+zwFtrwU5X7o0ael68CPvZ9mlazfabEXmaO6AGx
X-Google-Smtp-Source: AGHT+IGxhAAMsMurt1KwehAVVHzpBX7C6N9h0HhlkcNc6Sw1/MJLXgEoSGLR8Op+khpRsETvzUePlg==
X-Received: by 2002:a05:6870:181:b0:2eb:ace9:197a with SMTP id 586e51a60fabf-30c0032d0a8mr1837650fac.5.1754576377890;
        Thu, 07 Aug 2025 07:19:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZchkHuzPVgqvPs6ozzmn3HCGG4qk+OQ+GqB7q6LwLggKA==
Received: by 2002:a05:6870:2050:b0:2da:80e4:fad4 with SMTP id
 586e51a60fabf-30bffec9711ls355528fac.2.-pod-prod-00-us; Thu, 07 Aug 2025
 07:19:35 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVYYF+g1ABIwP/tXqaOYpkbil9ZqjnjSdnRLp/wDpa6V4nuj1oOTOiwwq2ECX1KNYzWezxI5XIJuuk=@googlegroups.com
X-Received: by 2002:a05:6871:2214:b0:30b:972f:a930 with SMTP id 586e51a60fabf-30c00348508mr2405484fac.3.1754576375651;
        Thu, 07 Aug 2025 07:19:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754576375; cv=pass;
        d=google.com; s=arc-20240605;
        b=XEpBCbGQsJotAm45NZYKwwNT4GE7/r6RNDrVmREmwEoRwjX0EWqdjIGMqN9R+9I9M8
         59bp0WG/Zaac8RTJDMV39+Qqg2cdGKmSc+CURxHRoUgsG0kwfokCp3Wy7kJ8cQ2z1QkQ
         KrQQT/avUwmUzYqrFtmXhJn+lAzWTe6Cd4DNeMeIMRTURGFu6C44JKl/AX8RATXzktzZ
         IvvufHgrwJQS2681dH0w6OczvwZ0V1QSwRM7X1WY0/65ghpfx/L3Xz/eKEhEk88U9Z6I
         VPAa41vTVu9O0sa2FRlgTaIrVdiFKb2j2cYjlfNrlNr11NBnJBYlt6RyK5JgqKhC5kDF
         0YIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=V4HzQPlBoiRj3TiTMS/fKOC7xLbLGVXzngTW/oiL3VM=;
        fh=7UGQiPUstHBdMrT+/gotlrsKf2dFOYLPDzCPmdRVN7g=;
        b=HLB5LMMbC4FrmbQhtZg1AqFrwU4AeLGNQn9aC39FGAHGzk0pG/MNd/SKo0oXM2tuS9
         dRgxsmFJGnC+gIxq8+j3pek9uX3xkhfXv7lmrI8LCeDapYk/SLDX/GXTQc5jrbWjQqO8
         vGh4dqsmTLdkfz/6tbLM+l7ywoQQkhahObUGm6SRdRYszqz4ZnMtcmIa0vgSQ4wKiRJZ
         2eHi0vKaI/Gzbi2TLMWvujpTten9WzRYqQqW0bI16Gn529W3A3ZAFZQzuT2Uulm05+32
         Ignhv332E/or5RTWIEJEwFwKKJy7/uQfD8jyeZxZArZg1taGHRGvY0ZfadQcCLTOS2Fo
         W7ww==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=UvWxmJcX;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::628 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (mail-mw2nam10on20628.outbound.protection.outlook.com. [2a01:111:f403:2412::628])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30bbf723243si372124fac.5.2025.08.07.07.19.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 07:19:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:2412::628 as permitted sender) client-ip=2a01:111:f403:2412::628;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Ux/HYFV3SrMs+NkvAGWaBPvM8dPG+iYroa33c0PdCqfPrAoG0ZRgrGME385hE4yAA1k7fv0fA9zHUzG3M6GMaWwSZNjdsLQs/Bnc1Qyr9HVWXoun+kpz5R6qHBeJqmJZUhhG5VTp0TyqI/X0tosUuUfRu+ietnHG5YdkrEQNsZ8x57bzleIvnjcntYu/Zg/rJdEhJBXAAPwOgXkzxVXVXHdVXzQaormdnei/p136nRj+7JltuFTHc8NSXWPD5bLvWQMZSwHVDF8Xzb46T5dCCmMBDRzxayy+pIj8Ekdc3l5iwN/MbJwOM63CF4iS0aRW0h6v2Qmduc8xwq/S+A7NPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=V4HzQPlBoiRj3TiTMS/fKOC7xLbLGVXzngTW/oiL3VM=;
 b=Pxnf4cfrY/mfaH5i1PlrKlv0lgqq+NICjmiOL+s5flU99eGje3dcKGfsMCklWXvaJipe2UtNSQwj8fFDb4a+eRyZtCI1WhaSy5U1/MLk+kPNnFx2ZsdZDqEYsUG4VLoykEJqKfnV7YvPkghSqkm9Pd/va5qfXmiFP5cRHMXxGzWP9wk5QRHltHq0FN4X7jEnBDUKjjvU0EZsBtbWza1Na9r3p4lLtDr27eoWAFm6LzuscpF29UO7O/l/y/VJyTO/0T7oIUz2zdxR8DjCCRhIiunG9N7N+S2k3nNxvTV1jWNF6HbpFh1u9fQqsWErYwoeSbYb1aJ4g3R68R7InzIs+w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from CH3PR12MB8659.namprd12.prod.outlook.com (2603:10b6:610:17c::13)
 by PH7PR12MB6588.namprd12.prod.outlook.com (2603:10b6:510:210::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.13; Thu, 7 Aug
 2025 14:19:31 +0000
Received: from CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732]) by CH3PR12MB8659.namprd12.prod.outlook.com
 ([fe80::6eb6:7d37:7b4b:1732%4]) with mapi id 15.20.9009.017; Thu, 7 Aug 2025
 14:19:31 +0000
Date: Thu, 7 Aug 2025 11:19:29 -0300
From: "'Jason Gunthorpe' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
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
Subject: Re: [PATCH v1 00/16] dma-mapping: migrate to physical address-based
 API
Message-ID: <20250807141929.GN184255@nvidia.com>
References: <cover.1754292567.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1754292567.git.leon@kernel.org>
X-ClientProxiedBy: YT4P288CA0083.CANP288.PROD.OUTLOOK.COM
 (2603:10b6:b01:d0::19) To CH3PR12MB8659.namprd12.prod.outlook.com
 (2603:10b6:610:17c::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR12MB8659:EE_|PH7PR12MB6588:EE_
X-MS-Office365-Filtering-Correlation-Id: ae70dbcf-4d4f-440e-182f-08ddd5bd6d0d
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?B9tNliylgIkVWzk+gttBK52S8uyZSnBPrdlqMANarwihh1iz5HDw9DuT0/hz?=
 =?us-ascii?Q?pPBvqHEDsFN1CcZA780EFUfOwQsxZf6+SovYZmu5SFpEdEKOqhzE7ccvwPXB?=
 =?us-ascii?Q?d9fhcq4vqA7B3VHHEr2QwNktuaHgZBg0mfXUO27IJQksn1GUv467eV9m3kYp?=
 =?us-ascii?Q?zeRZjufwMXBqEmp9lSxyAtI/FYEOwl/OTRaqLd4eUkBmR9iR11+zVCTyjqJX?=
 =?us-ascii?Q?FyiKBpgUCod6UknHqNUjeSk7xpamNtDPyQQXQJE5gyLHgII/gtRgwMPLs9rl?=
 =?us-ascii?Q?VJYaoI4XHo9LXlfjPNp1b4xV8dIR0P4LFtblPVPnGJ2pu6pUa0nXMZMAEPZL?=
 =?us-ascii?Q?txAR349UNH9JDuLSeOsF/6Am9TLe2PDjhcUZbrVMiFPCKVnrC83/BkwFkjbs?=
 =?us-ascii?Q?rhlDU0anUP7S72xxxONN7M111WE3/FEe6sz5sz/sNAXEPsxnacAsv08auES4?=
 =?us-ascii?Q?xzXTWb4AKhEn+At91sgj1F10XViQgPYlyGlYBkD56hicheFWE7MFTM2u0brm?=
 =?us-ascii?Q?29DmF0LPvmGbUa5rh179BXi2MJhDLHxxB2efSrDClnB7SakzahAsv5Rwg1Ow?=
 =?us-ascii?Q?7XegQvTCTKmpr10T9O7pN6miwGjQKLZOPameOzZBL6XiatNnuG1zuG+Sectp?=
 =?us-ascii?Q?GZ+AsVklJT5rwto+1nrg/44LcA+ZyVWOaJgkRawWO+XcVfjKF1Xit2S+S9Du?=
 =?us-ascii?Q?A1SitDf/YwAA09E/FJoMsAUplJo+yJVwgXAmEhp0FguJY/87BrkrEilXUZFs?=
 =?us-ascii?Q?AieS+FH/9jm/nwhq+ZKNyAaz+g9HOB5bzB/5v/HoWPc2qEnGs3uvA855ekvw?=
 =?us-ascii?Q?UEEBZWKzIgzhEdtspN/8cEa7pL7k5TbuELLLA3M2UsUMuP4yH9QqD44PXnlk?=
 =?us-ascii?Q?le02wZa+SROyxt1IvH+0ijUe0orkCw/zx8gNVNfGD0Z6979NDYnLMkJt4bBo?=
 =?us-ascii?Q?W8iuYrdHd3iqY+yDjKvVuHatC68t9hy4ypADpVdUGGmaQiDbIj5s9R+0An3T?=
 =?us-ascii?Q?zdeiuGpEGlDnXnEKq1V5moJfMcrDIUhZkYa6iUTwi2Tc1OQRAGIDSpWA5GUv?=
 =?us-ascii?Q?UjuyoQyWRTwKUkyvL3wnYpaDirtZ31ipYZuXbcpO4M1VTVRX+vK2aizHG5a9?=
 =?us-ascii?Q?IHJPSag0KP9F34ghLBieq3CcgYiXrGCOvca3LQtQupfiyI4YdOGx7fslTLEV?=
 =?us-ascii?Q?kNJL+GjtvJGIsltRq5oZMzq11CbPr7lnuV2a6DAB4zYGiztXp5fUlC3Mri28?=
 =?us-ascii?Q?X7CCp200e/89Izyr0VXRbjylVbzandsTLZxl2kR0on2rFyYuPn5t452MNVOE?=
 =?us-ascii?Q?R7H2RPUiB9YPz/+ryYJPDjM+63qObob1RQ4SnjRIM19oCho5cIbByzr1uDeb?=
 =?us-ascii?Q?MB2xgadEOpgIB6FlWic93IL0kZw5lZR24NBphD8wRZjdcYeNLkqOCW1/Sy7j?=
 =?us-ascii?Q?bmMRergMvaM=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR12MB8659.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?7m6qQrIZoL6i8N1g3znV2tQ4KvfciEiqOZZQJRQTWtnU7WjHOMjde+QydDME?=
 =?us-ascii?Q?mUDUrpS9390oTKIfGFcT1mK7xvkdka8xIq1GJ3tKVpq9AOXSJgip45vUgFVg?=
 =?us-ascii?Q?9Ap3Ju3KeNAui+8i5KuxBd9n0HVmsQOgGrjXMt1tthaQKqWfHX0hlsD2n0Lu?=
 =?us-ascii?Q?UYsoG/7OfcfDropPkCiO5jJIt8eQr16Y0qeLUfiaDKEev6Gfk4lCeTlkOc25?=
 =?us-ascii?Q?rloak9Msam4Zb/dD+/0xh85vsH1j2wWzl8WiTczYETvD4G4n5fTge+xlBGCr?=
 =?us-ascii?Q?kSxmPgaA9/FNrdgmYMBR7/uiJPFEVnj/uGGrcAUDb/DF57Xda1NjRUK85nMv?=
 =?us-ascii?Q?UzNmzIFE7q84UO1TwMPdwsfbNAHGnupCl6H4I9K/C1GX/eONUBTaRh4vqZaK?=
 =?us-ascii?Q?yB2G3zjrBMcBepTPvHWFibWD+IBiBaIEzIcc/vBWeJfzzOjQ4hEBkVByM+6j?=
 =?us-ascii?Q?r5qPqXrzooA2DznqgbZ8TAkI2PCHxHxssmHkUgZD8HPBT3QoKAhNrzB+o7vS?=
 =?us-ascii?Q?2TW8eQxB1m5+1cN1Bf91i593KBtbwCDpBoXuOkncHgGROWmXG2eJMEKs7cnU?=
 =?us-ascii?Q?sYj0zrV22wFh5bY8svayBlI0rvc5EMS+iYgk5HOpUGdYnLk3korFArvyKmk7?=
 =?us-ascii?Q?22reQMNtSb50vHSCfcqHSoNFJ+vs+K7Ys7jrs34BxjHy0vMdfBvc4KmcKl4y?=
 =?us-ascii?Q?mE0i7FauCtty4ncc2WgEgmFQQvdFX7UwJcJR6S+qE7u+IBIt5D7NYEYGWj40?=
 =?us-ascii?Q?recr6cmcvAqLxSVHgQDFKyKRsldvR7oVH4m6GeAYeOtbuTMu2nq8krRSqMtB?=
 =?us-ascii?Q?EQb4HCJKcBUKWVPH8HLAmxoZ5ROfTcHBfZAeVcgNHsicFUNzwQ3JMkPmSSu0?=
 =?us-ascii?Q?aaOHUzcGSqlNQ5twDziT3rbncFCDiMP8P5gSqUxNn/BGjVAPOGwvd3PM7jIx?=
 =?us-ascii?Q?SLcHnkVuvcwWUBNV5D8O66rCSjufmnPQM4jcKJ2Rxhk1hdsbUUtuQQkQb8Mx?=
 =?us-ascii?Q?mmMVDauvokCEO6PZXd/HBz2i/Kr02SlhFRYMGFxwSgJTO+sXJSaW+KJ65n3I?=
 =?us-ascii?Q?grd1YaWpy2pakSEIU2G9sntmYLb5l0KFETaWtV8JwnOgkchkV79twXudlNJk?=
 =?us-ascii?Q?bTbogLkAO5iSod5dvtCNVRvjrkzVjgpmkYMmpdGn6uWgEAPm/UeEz/VG3qJz?=
 =?us-ascii?Q?bg3s3HfFw1uns8n9bOMufjcok4uhvPyMtNRoIep3oMqjZx4Psy4R9syf8+hi?=
 =?us-ascii?Q?tUfHmEfaQ+Z5H0POkQ+MBujb3hmZxmlxRxLOAz0l3Y8o2WOKksiLE+0RJIPH?=
 =?us-ascii?Q?s/1Vqg0OAmeKE5T4aFFjEY7EeFCc5Ugc0k58pmMIsy7I8QQ8Xo6esmGMaoMV?=
 =?us-ascii?Q?VOpJqS9TBJjsX/1bPmmyt9pSqM2b1e27HUPvpB0T6VFRm083/mlNeVJEjqrm?=
 =?us-ascii?Q?jbtAii7eZV9BuHSzPWMywLvWewoicgmdNDQ9EsSG24u64A/PxV7Nxg7WMfll?=
 =?us-ascii?Q?T//RyKhtL5IDDp+sHf+4frB50biC1Z1Asn9WPfG0tIa6QIWfIpTYkm0JRK0U?=
 =?us-ascii?Q?3TrdqWdPk8GkiiaYfAc=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ae70dbcf-4d4f-440e-182f-08ddd5bd6d0d
X-MS-Exchange-CrossTenant-AuthSource: CH3PR12MB8659.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Aug 2025 14:19:31.4180
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: +coMWha09t2B/DL2OsRf4sc3LI4FnlUef4SJgqADc5IZdZrEaYGExrUCxRibJwt7
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR12MB6588
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=UvWxmJcX;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:2412::628 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Aug 04, 2025 at 03:42:34PM +0300, Leon Romanovsky wrote:
> Changelog:
> v1:
>  * Added new DMA_ATTR_MMIO attribute to indicate
>    PCI_P2PDMA_MAP_THRU_HOST_BRIDGE path.
>  * Rewrote dma_map_* functions to use thus new attribute
> v0: https://lore.kernel.org/all/cover.1750854543.git.leon@kernel.org/
> ------------------------------------------------------------------------
> 
> This series refactors the DMA mapping to use physical addresses
> as the primary interface instead of page+offset parameters. This
> change aligns the DMA API with the underlying hardware reality where
> DMA operations work with physical addresses, not page structures.

Lets elaborate this as Robin asked:

This series refactors the DMA mapping API to provide a phys_addr_t
based, and struct-page free, external API that can handle all the
mapping cases we want in modern systems:

 - struct page based cachable DRAM
 - struct page MEMORY_DEVICE_PCI_P2PDMA PCI peer to peer non-cachable MMIO
 - struct page-less PCI peer to peer non-cachable MMIO
 - struct page-less "resource" MMIO

Overall this gets much closer to Matthew's long term wish for
struct-pageless IO to cachable DRAM. The remaining primary work would
be in the mm side to allow kmap_local_pfn()/phys_to_virt() to work on
phys_addr_t without a struct page.

The general design is to remove struct page usage entirely from the
DMA API inner layers. For flows that need to have a KVA for the
physical address they can use kmap_local_pfn() or phys_to_virt(). This
isolates the struct page requirements to MM code only. Long term all
removals of struct page usage are supporting Matthew's memdesc
project which seeks to substantially transform how struct page works.

Instead make the DMA API internals work on phys_addr_t. Internally
there are still dedicated 'page' and 'resource' flows, except they are
now distinguished by a new DMA_ATTR_MMIO instead of by callchain. Both
flows use the same phys_addr_t.

When DMA_ATTR_MMIO is specified things work similar to the existing
'resource' flow. kmap_local_pfn(), phys_to_virt(), phys_to_page(),
pfn_valid(), etc are never called on the phys_addr_t. This requires
rejecting any configuration that would need swiotlb. CPU cache
flushing is not required, and avoided, as ATTR_MMIO also indicates the
address have no cachable mappings. This effectively removes any
DMA API side requirement to have struct page when DMA_ATTR_MMIO is
used.

In the !DMA_ATTR_MMIO mode things work similarly to the 'page' flow,
except on the common path of no cache flush, no swiotlb it never
touches a struct page. When cache flushing or swiotlb copying
kmap_local_pfn()/phys_to_virt() are used to get a KVA for CPU
usage. This was already the case on the unmap side, now the map side
is symmetric.

Callers are adjusted to set DMA_ATTR_MMIO. Existing 'resource' users
must set it. The existing struct page based MEMORY_DEVICE_PCI_P2PDMA
path must also set it. This corrects some existing bugs where iommu
mappings for P2P MMIO were improperly marked IOMMU_CACHE.

Since ATTR_MMIO is made to work with all the existing DMA map entry
points, particularly dma_iova_link(), this finally allows a way to use
the new DMA API to map PCI P2P MMIO without creating struct page. The
VFIO DMABUF series demonstrates how this works. This is intended to
replace the incorrect driver use of dma_map_resource() on PCI BAR
addresses.

This series does the core code and modern flows. A followup series
will give the same treatement to the legacy dma_ops implementation.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807141929.GN184255%40nvidia.com.
