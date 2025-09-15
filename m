Return-Path: <kasan-dev+bncBCN77QHK3UIBBGFBUDDAMGQEJXAZQXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 767FAB57C73
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 15:11:54 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-25d21fddb85sf57388745ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 06:11:54 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757941913; cv=pass;
        d=google.com; s=arc-20240605;
        b=c4sNZdGICEVuuxjZmCXQdPaC96IZ3F6ACGclbsXZRqTqyLedAlHXjKU9IGTRheAIoD
         aS8U0I64LHBbC8gZSobixR7Mv/RxZXHHjFdaFTmZspgSOUBFPKI1e1LoE6rkHqeaXkQh
         VXiwXxTXWwsC6NwhxMeVJ5YsUMNDJB4dL/ksrddxchSkHZ3EpC+GxdOm4GWQ15NzhqrH
         VHlwJODc5PKzUdF0t08jpCI+TStb6/bZeQzk2QF34Say2yTjhS2mpOuHOQaIiQaCIptw
         04ltjRwg9XWv8B4Rdmo/YnbEgLADAKdAYTM20ndHVZmugkhdQk5Ciuqh4kbxJjrhWKqG
         7ARQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=gJE6rMg45g/iVkKJ4NkwMIAOwTahTmIBSe5ShIM9NSQ=;
        fh=G70UI+f5Fu7UAeeKgdfOt31uCBSn9iN/+SzyKqrqF/A=;
        b=adYbetPAROKTdemrSrMmzeJI5wCkTZjOQuYc7D1C7GxuadzwGwiviSA3SXYbVK7zvX
         bOwNt4GWoeFg5uZeMHNvu/EO0Dy9wJwNq2SquWOsKRM2wCQwi/vig6OGnY2SbO5JiiZ3
         DugDUjS+WeScR/vo0IF/DkNjx8hFLOAO+Ig9ycf5HYloay5XF+6GZwyBxcQ+kEBfdN/f
         AF3GMhbcD5fL3cyP04ZagJsX/2C1t6k6a3Ds7vMtJlglVEWEcUU4sue8WuL3FbRHNOSW
         ciL+6Faol8Jkj/tPL/udqOdZ4jIf2v31pzYxGcxvmBaxjmyFf8diURBWNqwpLm6Nt+Kq
         CkfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=XVqFp5y3;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757941913; x=1758546713; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=gJE6rMg45g/iVkKJ4NkwMIAOwTahTmIBSe5ShIM9NSQ=;
        b=oHn2wFkbZ/MsopmpIqdfuGMIKGvvatBfAX+EGt6tG3lLAUT+IJv+Uze/bYwQgtuDCb
         4AptE3ufH4fOgWjPvqiwGkbhcoAGTnO7HXWsDGscrJ5YYplilEjY0mBjiRLlZ33NP4s3
         jO/LBU1FNovZaXEro83iRIdWQqp+WIyT3Z+pXcLw6RZtRuPEZofJL+KFF+FWP4BKXtyE
         g/+igvem86lQdht0jx+rdT8AncZzhl5mlmEqa9MCr+8FaKEeCg/2lyRvgrsXq2VRUNui
         DfDIEafHuoR9J8Gdg/bqtNSuhqU8kusRGsU3VJVVR7rheLLYmuUX0mzg0xrVmWGGBOB9
         dFCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757941913; x=1758546713;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gJE6rMg45g/iVkKJ4NkwMIAOwTahTmIBSe5ShIM9NSQ=;
        b=fUztktHLiuOX25u7HZEc8larsl/U5SrIuEnGryDBxMUHJT3Le4dLmKxVGn04Ygb24P
         UGP1U1iK7f4G/dYjrfwKTqJeRrA0Ac5kUmea5t50tNVPOas4c1z0skes/Qt8X3EQNkAE
         69rIC0VqO0GF4o5/KnYs7iwM+rHv5qjs7kWGHUcxjiNc8XOZfDLD9Rh8MCxIEZ1nE+jo
         apoHC7KaaydSLRxAxSizExhzdcHwT7q7SfAN8A1d1s+YKCSVT5AHy8h4JhnjL3n/gWDR
         kxBvGTI7GuKGpk+pD0t6vgHXBsg/jg5rGt0AVNTwSdnLFQC94SeuWqf45ql72o30WNwZ
         JQ0A==
X-Forwarded-Encrypted: i=3; AJvYcCWeCUNKkRcEywQGQ+PX0SBbWV3DgAlemw4vuAbuF0C5FTWW1aWA+sZ+vERlUCyzwvN1WALwOQ==@lfdr.de
X-Gm-Message-State: AOJu0YziUsyb4bFIUmjPljzxSut2GN+KtDwrh2Iiuep9wDlHaKFMKeDo
	SH+nFt4xIfvcoD5qJ/KeYTFUtCyAoUxEFrZ2FRarMNDDrWwwM17P+GhM
X-Google-Smtp-Source: AGHT+IGofMGDV5CqbCLj8BuvpJaxAev3NWMybUpWDjhlnbAC143n8GoaBrNDkKn0w52wqMMl9+hAhA==
X-Received: by 2002:a17:903:478d:b0:265:acc3:d312 with SMTP id d9443c01a7336-265acc3d46bmr50620475ad.43.1757941912694;
        Mon, 15 Sep 2025 06:11:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7BO+swp+MCYxH/M2AUYsiQLMOAH/SWgM4/pvQ1Ow9kcw==
Received: by 2002:a17:903:46c8:b0:25f:f621:6131 with SMTP id
 d9443c01a7336-25ff630adf0ls25169345ad.1.-pod-prod-03-us; Mon, 15 Sep 2025
 06:11:50 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCUyKEAfrsUA3/Bp4Ij1+7VsyXdvjEIdbInGFZwIQub/E/5ixZP0lvt8Hr5e6mIMEhzQSuTlTG3Gavw=@googlegroups.com
X-Received: by 2002:a17:903:3888:b0:248:9e56:e806 with SMTP id d9443c01a7336-25d24100ebemr151455555ad.12.1757941909704;
        Mon, 15 Sep 2025 06:11:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757941909; cv=pass;
        d=google.com; s=arc-20240605;
        b=OL1zG01aR/xyWbtnnu+bPHr0jego+yKuDpfL2o8HZ7Bak+WIYbLjBnyxHZ9J4zamMl
         SX8X7hr2UQbhe4vNW6CQnNSopw309P4uosCBTcA3JcIsYL8/QRKjmeGlKQiHITHJ+Dd6
         T94Zg/7vbkYLPter68anWmM4e9+mKckOnqR6Zh1MWUx3kqU3C/ia08aMwAvY7RsXTCBi
         inxqQmHoRe8T3/M6Uw+/qOFC4326aXYXBZZ1kYkZA89ZLFKKoZrC1QK37xPz644lQQgs
         6h6/EjhzHLQ93Mm4y9W4HuK70UJX1mr98rYOfs0FpeOeBqaCxjy4Dz9xJnI+hWYdDxTG
         f5WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=F5FAocx9qzl2nBgyJDZFuTLoX3Jt1ZtCO1BToWqTd6I=;
        fh=TquJHSLgMQz17Ceh3wGNBxHeq1rkT7Iu0EMiZtmW+X8=;
        b=DrfSr4tjoKwjF6AMouCWYEEEoLIDlABgGQRNT9Mpfzyx1kCad4lrppOa5ueJAwf9R5
         VZF4JwQI4sTgLMwI6kHzatZTMCSQEmAN1C8qUC52c7CkWS2ZVLRMeeUaprCzNU18kr5a
         YG4iFNSonkK0o9Qxhj9UKDhZfTRtGqpDpJcBM5bP1RVwzA6Wj/+b9PCXHfYUIoQEFOqB
         VKCKbvbuAXG9cUSeVB+qlwyKZC3MBoc2j43hCG50jb3RUY0sJ6yBrqNPmK6sbMLTSDAz
         qDqS5wBhLxCHtCEGaMsiV01B1NM2ik6RCMcocDc/NQwA6bbS8YtFeJVFQzqjS4/asSgJ
         R33Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=XVqFp5y3;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from SN4PR2101CU001.outbound.protection.outlook.com (mail-southcentralusazlp170120001.outbound.protection.outlook.com. [2a01:111:f403:c10d::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25f31869f46si2485895ad.5.2025.09.15.06.11.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Sep 2025 06:11:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@nvidia.com designates 2a01:111:f403:c10d::1 as permitted sender) client-ip=2a01:111:f403:c10d::1;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=VEkukaV9dWdYlGYACJfwPUv8aT8rf9VzkipmE6XrXnJrW2foTRsZ6VjQeascmjZddMglRpESn/B7udLukfAkJk7MEECWPVBNz18vhYrKnouQKM6Q+BV+Eo+cbKjUgzMOutlJLzQke2ncwDCdtIHNFwTyZE18gAR+/EgAJJwR/sJpwKvgQ9bzDPCoPGpewNDNNlaKUgF8DpkW5SSYpfSnbzrRA8xeY8TSS4vu8I4SI2FpvMsE3AvHSEHMNHxT+PAIy34mAwp522nQMlRzb15jv6fZ3qMP5sn3pZuPUVuyLWJh+UF2re/YHP8Xz7ewTB5lSDWrR7krPO6BjQHKYc2LeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=F5FAocx9qzl2nBgyJDZFuTLoX3Jt1ZtCO1BToWqTd6I=;
 b=BCoGEyOr08OElk1yUVia1tSuMkXzZDWGuhX0HRuvyofSEbspXMPuKDEeixlmNNNHNEC5UM6ZVj1zboyn5XmO8n//yLy5MWB9+ekcZQ2KRR8Hi4ACBrdVGAyDUTvr8AMdo2rHF4a+S6udWAF2UtssMgnylAKf4a4X04T8U2Q/TZ0vv/VRtAQ19b9cM8atFAOR6oc3kwiB4rW1lMK1mrUH18vKv5DO6+H7Rviw8ohqr0jxX9A3mLu2UtKINdAuQqDLSIaa8lUxoZtZGbpoUW8faKEDLiy6yk+3dfXQaEN/zEVx0GKXNp8+kBljaL+PKTmlhuHmy+pG5tvzHckKYC1kgg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH7PR12MB5757.namprd12.prod.outlook.com (2603:10b6:510:1d0::13)
 by IA0PR12MB8087.namprd12.prod.outlook.com (2603:10b6:208:401::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9115.21; Mon, 15 Sep
 2025 13:11:45 +0000
Received: from PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632]) by PH7PR12MB5757.namprd12.prod.outlook.com
 ([fe80::f012:300c:6bf4:7632%2]) with mapi id 15.20.9115.020; Mon, 15 Sep 2025
 13:11:44 +0000
Date: Mon, 15 Sep 2025 10:11:42 -0300
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
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 08/16] mm: add ability to take further action in
 vm_area_desc
Message-ID: <20250915131142.GI1024672@nvidia.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <d85cc08dd7c5f0a4d5a3c5a5a1b75556461392a1.1757534913.git.lorenzo.stoakes@oracle.com>
 <20250915121112.GC1024672@nvidia.com>
 <77bbbfe8-871f-4bb3-ae8d-84dd328a1f7c@lucifer.local>
 <20250915124259.GF1024672@nvidia.com>
 <5be340e8-353a-4cde-8770-136a515f326a@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5be340e8-353a-4cde-8770-136a515f326a@lucifer.local>
X-ClientProxiedBy: YT3PR01CA0102.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:85::21) To PH7PR12MB5757.namprd12.prod.outlook.com
 (2603:10b6:510:1d0::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH7PR12MB5757:EE_|IA0PR12MB8087:EE_
X-MS-Office365-Filtering-Correlation-Id: 708710a6-b90b-45a9-c956-08ddf4596b13
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?9koqRD9AzRR6S4AySeWb6Akwl+RuPa/25iCSfjk0Dv0k7EkFp6Vjc0BNoDxA?=
 =?us-ascii?Q?U1CWd4XiPlWHy36pV7Nth97fO+5Tylq3uNWkjk6CyRSCJlrzWIxHYCxG5pKw?=
 =?us-ascii?Q?VZ4I2MDma5rcfpJFO3148A39jX9oMqFt0+QHOOvSxLYBaXrezXP5ceYJe2qt?=
 =?us-ascii?Q?jZm96u5ziCAZY/eRzPzDuY8ih1Qa0Tt9FyfaEhoR89sdMK3OnONu8QzT86Hq?=
 =?us-ascii?Q?PuzvghxP3lAaO/YtSLTRJ2haXC8fXk5TxbT/K5g787LU23eGy1zECY3mx0VR?=
 =?us-ascii?Q?7tYGvAdrwf2CKj5KNlJ2aJkUEh4S6uF8EE7fyrrEwDMBJhITnCRwD+qhtuYP?=
 =?us-ascii?Q?QloLbgZw1G4/OcY2hln9dbWwuaERCyqjlxq+eKlwUHAL1XmETumaTwaY+TZ1?=
 =?us-ascii?Q?j2VgVuopv+IZKKce2NQfS3GuS24tuVOlLnDl5t9jJhQeVUM/URSEPw0gQAoz?=
 =?us-ascii?Q?/WEsIrx38EvMKo4FE0eXiXd6zKlqbjKVvS68VKewjTOPjUFT+gb2O7v388jv?=
 =?us-ascii?Q?AV8PWUpZg1ULcHn2z30MBszoUehhZapDHHX67C0RZUViACLqOkTRYh/Po6A6?=
 =?us-ascii?Q?Hh45mrQOzCCkEMuAacRobfe7EldcOSdv6SE1vdqnsl9zAfRJM0jv8r828/LE?=
 =?us-ascii?Q?Afn1eyEVlGPe/Dph2kzxDUI3mhZpfNL8J6kAtDnuIrornajsYlw4ZDIIPcud?=
 =?us-ascii?Q?4HBzsB6N1AiZN4Ga6uplweokNIuHMp5q1NXtH2sZfZtw62xnhl0+8USNkDoL?=
 =?us-ascii?Q?v6i+rPeNBzoPYP4QnuEFtWM43DMTEeSUUp8dU/C8qkqY1dKps2jMiCH5O8LJ?=
 =?us-ascii?Q?g4fOvZGk8PkLTjhnSH8lboWpdS4Ug71kneICvny1M3Wepo989ztGECJauqRf?=
 =?us-ascii?Q?+f1Db8dN/zpR9W42GbY5+BrMlNH2SXHfRJu16jyabzI11MD6S53NyNAZ/BRk?=
 =?us-ascii?Q?aQoTk+ZH+zzkKtTf9pjLtqZzEVh7QwccuxG8U3oAbguVFlYH2o4GkQFWaCmy?=
 =?us-ascii?Q?JuR5ONeimFcWR78YeGbMY5w5gFVBp5NaNg2T7TYg5QOiuNUAwgLzf5hCXrbP?=
 =?us-ascii?Q?X4mxlVqMKRwFm0itxP9irJ6hXBCL2U1OJuL4d6U4ucMC6eM9g+vKQTTXlaO8?=
 =?us-ascii?Q?nudC+eelK/fsWNtYMGSwxAhWe9+JIYiB6+MfXS3D1G+c3hJqEUzKlOwIs2LU?=
 =?us-ascii?Q?/nKhL+yDNrwxX2smulREO59TOLoP0nUl0nKxVK69ziWVxbKHPMP4ZtpA25/r?=
 =?us-ascii?Q?8bL0xVwF75oSklpF8gDMx1yDg4NiDxAM8k1N+WhkBSnx/9ZymOKLWbcBbvBQ?=
 =?us-ascii?Q?aQOfXh6Qy4jjOY9NGZL/5hM4wgzZGbvPZZVBTfxPJVHuC+L10NSt0pRk5aPk?=
 =?us-ascii?Q?ZqWmHnadIXic6erzxo9BcUvZ/E31oPFNpy+e32oiHt0C6pUqRipFytOoezR7?=
 =?us-ascii?Q?9gR55hE5PQ4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH7PR12MB5757.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ME4HzCajAOXx0ZX7EyyLd5RHfF8oqX42T6cE2R7BMue9xRIOafc8iNCrxNjV?=
 =?us-ascii?Q?5vG5GbDm7dFO5GdrqIZ8unRvRY7YDGMkxAU0Fe/fABjx3mnvtwnamv2hm/G/?=
 =?us-ascii?Q?2fEyQpA8kPLbUid+0vLjWUnfkThWQ36NEt+RwV9VKvEXi42oRb4zvWGzyyqW?=
 =?us-ascii?Q?Gg618VFQhfwRvqlHailHOTDJsOiqwzSoCQHPoU7umd75mQIARaiRJMkYvKLx?=
 =?us-ascii?Q?oV2+jxkDQ/QWopg5Jlx3NoB6AIhodY1+QIhVyTeK6PzN/jvtwxMWeAjJGrJO?=
 =?us-ascii?Q?5JiBlGhy8TQAVvc0JX5JUNUBij4WwFAs6KlESOBDf5HBaqXqTSkD1ND5HTaC?=
 =?us-ascii?Q?jdbMlPfl2r9SQIV5dZrs3BlTV+TpFhTTquEAWoOTBJnDZd/3t2a6ytFA2Sz2?=
 =?us-ascii?Q?3EJUx/7/SW24xB2V0VyxpGoOnwyOZbOOZpHsJ5It4IPxv3OM2Uqr2kwwVJlr?=
 =?us-ascii?Q?KjxTjGsKgyknvSoATBpyiKTB0wFGVmketL1pg1IsWojwKZcG/U3r9IJtFgOQ?=
 =?us-ascii?Q?8tyyIGAOFcnA92nSzbC3xG6Kr/waqbAlr8y2NE+tnUjZq9HveP+yRYN7xTyM?=
 =?us-ascii?Q?7hahnaDnnoA0TCuoRCjfqrEK+Bydc/VuGgEesIAKycMBgiIsnucbxDDZXjmu?=
 =?us-ascii?Q?Rxj1Wyiu60WBG8louC1OuW6AcT3ak+qcrsX0dpMT+enArsZ3/tIRUoBqzz1D?=
 =?us-ascii?Q?XWjG78BWsUdIBzsjTjTgLrXIl8squMRxaQlU/BPX+9YPtuKk9yzAUsfPP69Y?=
 =?us-ascii?Q?gbmKgEow+9EZvtGoMnvpblmVApl4i2dbozUD5w99iAmBm+glxBw3b0tlIVER?=
 =?us-ascii?Q?/bmTEFXIE8yAebQdU+Y8+ztco30BF/JT/9NkYZgk5lfLh+5mGpIPan9j60pu?=
 =?us-ascii?Q?C9G4d+knPGgiPWcetO9iwg87BR7kigHY3gex0vTcqogkGSeoaM56RzAnvnHp?=
 =?us-ascii?Q?Km/FQL6evbO7hJTCEXJId08z5uaN27UxHUMNTKEjcTCwX70EgiTAOcMnSz/I?=
 =?us-ascii?Q?5RAkl451cTU70Xz52NynWYXnA65rVl+vEiOTOYpHjKuS4UChFKNJFujeDUU6?=
 =?us-ascii?Q?i6WIhy7ETMRvjGLBAyaCfW+GW0K2knE1QFhV92hPdbngL+9SZ5g7fdG5AJ6q?=
 =?us-ascii?Q?OX9m1nZEJMC/vIvqkCzR0jKYqM2Fqak0MWwUoMjjJgcMn0yCjicYcm1XtwU0?=
 =?us-ascii?Q?9grk8VGEN/kann/hs0SofUWWUE5VYe6BFQfIkHm5KUwMzs+DOdcAqoOHWxCa?=
 =?us-ascii?Q?KV3iayOvehvNDBkU7XBmDUatXta0PGBkzk8SYik8RRaDfGKJT/A0uZgUxv79?=
 =?us-ascii?Q?Y9jlq8anD+AQSWpxFyuoVAgezF1wQWJjt3bEZTdWsbtw9i51ptj5s1SGxWTT?=
 =?us-ascii?Q?UxcNoHWlTMlSw6XhbV+haw1cslwRHEG68XDtiHSeOjZPT+BWMbWxvHkz26yt?=
 =?us-ascii?Q?J4Q145rgwHhBLog8ff3t1fxXuyowaAg9P4xWkpHwZ+f3Vqof3UX1hEF5lyzQ?=
 =?us-ascii?Q?iUkqLvMAtIgEmLNSuiT5KCgUuKdKcMZst9a6Iz2dIwwC8X/CGdVm+jSoVn1O?=
 =?us-ascii?Q?khAM5W4GBbSyJUQLIfU=3D?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 708710a6-b90b-45a9-c956-08ddf4596b13
X-MS-Exchange-CrossTenant-AuthSource: PH7PR12MB5757.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 15 Sep 2025 13:11:44.4247
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: R9ReDV4PkYt20kbwYORhZwWuwB0tMw+3sd/Gj6EsFeDp+trQP4jV0XV5RXaaqGYo
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA0PR12MB8087
X-Original-Sender: jgg@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=XVqFp5y3;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of jgg@nvidia.com
 designates 2a01:111:f403:c10d::1 as permitted sender) smtp.mailfrom=jgg@nvidia.com;
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

On Mon, Sep 15, 2025 at 01:54:05PM +0100, Lorenzo Stoakes wrote:
> > Just mark the functions as manipulating the action using the 'action'
> > in the fuction name.
> 
> Because now sub-callers that partially map using one method and partially map
> using another now need to have a desc too that they have to 'just know' which
> fields to update or artificially set up.

Huh? There is only on desc->action, how can you have more than one
action with this scheme?

One action is the right thing anyhow, we can't meaningfully mix
different action types in the same VMA. That's nonsense.

You may need more flexible ways to get the address lists down the road
because not every driver will be contiguous, but that should still be
one action.

> The vmcore case does something like this.

vmcore is a true MIXEDMAP, it isn't doing two actions. These mixedmap
helpers just aren't good for what mixedmap needs.. Mixed map need a
list of physical pfns with a bit indicating if they are "special" or
not. If you do it with a callback or a kmalloc allocation it doesn't
matter.

vmcore would then populate that list with its mixture of special and
non-sepcial memory and do a single mixedmem action.

I think this series should drop the mixedmem stuff, it is the most
complicated action type. A vmalloc_user action is better for kcov.

And maybe that is just a comment overall. This would be nicer if each
series focused on adding one action with a three-four mmap users
converted to use it as an example case.

Eg there are not that many places calling vmalloc_user(), a single
series could convert alot of them.

If you did it this way we'd discover that there are already
helpers for vmalloc_user():

	return remap_vmalloc_range(vma, mdev_state->memblk, 0);

And kcov looks buggy to not be using it already. The above gets the
VMA type right and doesn't force mixedmap :)

Then the series goals are a bit better we can actually fully convert
and remove things like remap_vmalloc_range() in single series. That
looks feasible to me.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250915131142.GI1024672%40nvidia.com.
