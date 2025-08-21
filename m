Return-Path: <kasan-dev+bncBDWMT3UBYINRBYMPT3CQMGQEG6XQNHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 19754B3074B
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:56:03 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-2445805d386sf16985445ad.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:56:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755809761; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bf6nL0JcodiTrKrHDjH9lMAYFOquDBBMU5/3Srg0ojtdO3SQKwG/ywbJNYXRiL6jTn
         cdZZQHfYbFKZeSaMA+axHTUJoUsNRD4uM5W+1q1luJviCsrTFuC/PNavlJZtLapoh2lP
         /UHhd2jfP2fur7OWqmUcZsuZJNKoCcCCbOvIwj2akAwDF+zFW7dXLuk6ix/pFwC2UK1v
         U7o8vQbP5NyuwC+h5fh47KhYuDDZF/MWle1QlTZAf6FFqr3wrLg/8tA314gGbubJhmWl
         rsdSb6s/iQazoGfLSyckxZquLrxspcyRaYL0hMJXJUX2DLBqrEDmSFFRXt+0wQYZRjFw
         WIKA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Na6uQJKtqLirCPOvPENDmVHhzM941AMjeEkz8A+i3wE=;
        fh=YC57diKwMSTuQe/wh2zv7sQCc6hMCfnlZ2URo787Lc0=;
        b=hjXtb7ycAeUGppX7/EMCocuA4II7S5KS+Q36qQRQkDpDMLJ2A3828mQGOJXZ/XtUh9
         vLQ0EAGpbdabDYJIugfkDTfKXv5nzznqUM/AJ8Gtj/CzFp6Y+oHPWfWzihzsaGHbojbq
         w4R1jCxXuuvTV4+4PczlnBO1IapkVvR8YBraCi6oAK4Mzn28DAuDRCaAsE2EzUZeSw53
         GmAoP/qwMXasotyhewJSbOxEjlbrTmFv/bUyBcK+FF3KL08CaPwWYJhfTdevvQCk87AU
         MyOsyp7UVu+O4P3Vfl8D48qsC/gqzEAkgy3C9W2lISTNIFnDcZj/GMs3psjaGK64pDn5
         3cQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=ZRAMTS8I;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2417::631 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755809761; x=1756414561; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Na6uQJKtqLirCPOvPENDmVHhzM941AMjeEkz8A+i3wE=;
        b=FAm+tB9Dl35ej9zoTq/dIuzlNXOPfCzULriEqLsPYOTBtoc9+Ik8VIjFMyZLFEM/NW
         bQpP+Q42SwWp0lgBkPmjFOlu/RTgoeCrIpqeDt3Fgb9fOpeioq2qzmfT39E+NWiwTOpi
         Y07qIHevGneMkxwAiS4woGhO5L3oQ2UxnZmSKn+gwYDbllsK18789Ov2vNSrzbjC4KKr
         qqww1yZeWwyQl6OpWE85UiWJ+hA4ZcLRXZE8UC6cpeDPCoE7Kq1qktJuON4wBoscG2oH
         jaWN+xNYa/nOW8DflnB1RXecbjB2qhgqdtaPsK9Wr059ldksVMjzeLWoT8dUOhT1oG8Y
         wRwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755809761; x=1756414561;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Na6uQJKtqLirCPOvPENDmVHhzM941AMjeEkz8A+i3wE=;
        b=V30aE1djAcj+Ppxu4Htj7wDpBYeqZ7ma+Uhzczd5F2ucxN43Iot86nNhYyqrqq2Oy8
         PAMiBkIsXDLfcwP5wXJ0sW4UjgBDYoWOm0orq9s0R6xlue0COHSN2dZyVWa0YNsujt3K
         lXUeiRv0rAHwOAhAAUTKA+Ih0Ujw3pd8SdiXCzrT2kG6NTEgF54aN75LbtEk6s5geMv7
         /2wfK6gTX5Bjmz5b7jbnFW9iG1lJRENQV1BM4IVsI0UyrobUNlm4C2+vWc+e0zf5Wtbf
         lm1jSRe0sqBhs2rkyhQScmBJs1PEK2pw/pjgnOPz7g/4VAWxRBIMsjYEbtGYdKLI3Phu
         KdXQ==
X-Forwarded-Encrypted: i=3; AJvYcCWydzOj0dukhUIie/bRUb0nmTNkuEgEOxULjuLT75aaAkCgHDsVQCR/99IfbaHdCTE519vlYA==@lfdr.de
X-Gm-Message-State: AOJu0YxyP4UntYsym7+XgDBgjRe3iUEAAnjolXgwMeNlzm4bdMoO5ycN
	jbwQaoOwgso5xbEpq7LTQEmAJEJ+UJOAtfgiH9zEv9s0YkvX3KqJReLn
X-Google-Smtp-Source: AGHT+IGKXTJb7q6arM+Yv31ECejjwZt8cumb3Gz9rrHkdJX2NZn/eMpRbP67GDHyDbrKw8M9Tauehw==
X-Received: by 2002:a17:903:2ecd:b0:23f:fa79:15d0 with SMTP id d9443c01a7336-2462ef6a787mr7681955ad.46.1755809761642;
        Thu, 21 Aug 2025 13:56:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc/6gh9D5TxU2k2Fk65Z1PPHRYy7xspd5fAJg2Y8SyDjg==
Received: by 2002:a17:903:8a:b0:23f:fdbc:de3c with SMTP id d9443c01a7336-245fcc83535ls10785045ad.1.-pod-prod-07-us;
 Thu, 21 Aug 2025 13:56:00 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXWwBHxbmUk74XgB0gSM+kk5mLroMh2OpUsJklk6mbq17KF+mHxD4PiaXXSIXHOFZEyhJXFGeNaQbw=@googlegroups.com
X-Received: by 2002:a17:903:388e:b0:23f:e51b:2189 with SMTP id d9443c01a7336-2462ee4579cmr9595465ad.17.1755809760341;
        Thu, 21 Aug 2025 13:56:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755809760; cv=pass;
        d=google.com; s=arc-20240605;
        b=W3u/eezPsTSj4P5+YPJXIMbqQya1e5cK3AA/oIXeB4UZK31zjo02VoQ5/XNijgRl6I
         fMr3nvK3ggBL/fk4yq63SkTF/C0A4vaE5l6dqijNf4GuFQongkNRZeT0SOE3MuzqX2Br
         vgC+8XM+pDjHWQjJ8ggTqnYGY05qsTET5UOuoiN+Q8jlfhANZrZ3UhqLZeq5Ubws0sch
         GbYhuTKMZEbIzNRgfjwhE8NHshihPiXsAMS9BrIAvGkvsICKMlt1Gy14RTrYwViV80ap
         hxvY0pvAZk3IDw6PwW/clzKnx0kKAdOjubm516AKzP+ZeJFiHiP5ndVdzK/oP5G4WJ8A
         juSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uD6U2yYEcuK6Q08U/iYV3O62S0ShleTOpomGqDgXsYI=;
        fh=mkkYPuurUY7GUu5MdEwXZN672Dpu8wx5Bk7gstqa7/Y=;
        b=VbvV5MudlqElCyV97IpND09s0j9BPnU/GGpx7tO6rNC7RROfUmieIFI9FXx0MmVXbb
         y2Uc+/+vZO1nb1Px+rLoKruGgVPV8Ny0uK+DPcZWdq3BoEOKAuAj0lqlTcYkbDjEx0s7
         dPi4SoDny07Rnnd6+yg2MMgruVgACfQBq6oHKCm5gU+41DhXP/3VtY4mksmqnA8+n7Xg
         hJ9hh0z+CRck6cg1c2hpFpU2d4RO2mhu90X/8C/mRVKkpyx0zwhfOdJlvLhrHmsGgSNs
         16jgPpwihXiVrdcis6fiG6mUKkrrQ4yVZ1BFnPy3aZ1LulfeCooQ0xDUWIdVLTBar6L0
         KBhA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=ZRAMTS8I;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2417::631 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM12-DM6-obe.outbound.protection.outlook.com (mail-dm6nam12on20631.outbound.protection.outlook.com. [2a01:111:f403:2417::631])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-245ed30cfe6si2605945ad.1.2025.08.21.13.56.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:56:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2417::631 as permitted sender) client-ip=2a01:111:f403:2417::631;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=BGtO701Wpp3SQ+JSkp12FhJBwkI2qSfgJktct3ITnhgZBnN0rsZyHsVHVxvjiLDPOEPrNXM1FygvVPiZEqoQPWVo0M8gYBbbkQDuRfQbS5KBJ7TLweeoGkvYJm+Bd8LAROewGgjaork/dkQUpTOEbPYAMWYzguxuuxAX0RqpL5vF88gROU301kXFUx8CHSCdST25Tqc8QQFMLRH7Czsl15KM1izzNpJ15LXoYlOnGDJDwWTTDjKMdmI9I/zp7fLyCw3JFtv2ClUtAaI+FN2S+uwfqHznJnBZRnWE2RwPe3ZV+n4DnJaB22LRV/xpaj35dbxxhgBxDM7qKdumfO6EuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=uD6U2yYEcuK6Q08U/iYV3O62S0ShleTOpomGqDgXsYI=;
 b=PleA2I5UJoDSA2Bvc+l8O3eT6+0DyyMoq1gnYvzJdedWt0Kbaqo31PGHgN7+9tgXTkUC7uPPMJGibIDUazLnaC4oZsCvtA1y7sErGwgw3/tnhwYXmyja8Zuca6OQoAfYRuIMfySwrpU1J6mQKi7AwtlQI9SMLbXCEUkNHSCw0WQEHL9HlgrFDFrHXDn2bz2mJDrT7WmyiuEGSEIRBLPHv4TtgR33lkUE95ef0Je6OtL9FgR3l8QyxtYgK62vTPYPJ5e5DVyG9JVYfJDnM5gwbgezuALaMRycuDlX5kyQHghh+sJGC3z39pnRUceFeXQXJhVRrUPcwapomRxmu2YHcA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DS7PR12MB9473.namprd12.prod.outlook.com (2603:10b6:8:252::5) by
 DM3PR12MB9435.namprd12.prod.outlook.com (2603:10b6:0:40::6) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.9031.24; Thu, 21 Aug 2025 20:55:57 +0000
Received: from DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a]) by DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a%6]) with mapi id 15.20.9052.013; Thu, 21 Aug 2025
 20:55:57 +0000
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
Subject: Re: [PATCH RFC 13/35] mm: simplify folio_page() and folio_page_idx()
Date: Thu, 21 Aug 2025 16:55:52 -0400
X-Mailer: MailMate (2.0r6272)
Message-ID: <E1AA1AC8-06E4-4896-B62B-F3EA0AE3E09C@nvidia.com>
In-Reply-To: <20250821200701.1329277-14-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-14-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: MN0PR05CA0013.namprd05.prod.outlook.com
 (2603:10b6:208:52c::7) To DS7PR12MB9473.namprd12.prod.outlook.com
 (2603:10b6:8:252::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS7PR12MB9473:EE_|DM3PR12MB9435:EE_
X-MS-Office365-Filtering-Correlation-Id: 53f644a2-a6e9-425e-f5ac-08dde0f52088
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|366016|1800799024|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?SLASAnWO5dsLJrJaGcvQK8asVFX5uUU6DChGG8O74SKblEWes73GHfSEq5cy?=
 =?us-ascii?Q?5Jsbz0OMROVpE9y8CEHztDg9Vz9/3Q9eakouNUIaZnxCuAUGA1b8rOopJI2G?=
 =?us-ascii?Q?QqjMZ5JvUQ3ui/vYkjjwylsH4eAhfKQjR7oBD7+yjs7bXFu1hw/SAXMes/uK?=
 =?us-ascii?Q?mnUsSpTbOMD/oMLKkQT0J6/7WyMa3zF/mIo8RjMYcskl96e/hpdVONJOYeQR?=
 =?us-ascii?Q?oCwpWnGlrqZ/mwF2Sqyc7+tZV6qSbIOPGfV3L6sogjJbNImuV1jVr43JJMVX?=
 =?us-ascii?Q?8kOrN/vYfGQV7wwX5C0RlDJyrzsdekkt+xTrArBx7IVRA/xrImmyLtV8+PEI?=
 =?us-ascii?Q?FfUj+TFTWkXufCfGS8c950TIFJPnH1Dxt3OF3Ar3V7HS1RZul7ph3y7FcOrQ?=
 =?us-ascii?Q?ngUOH7uGjJV1/xjw3bPFYEtxcYOGcMwuYsQii5bU3g4oDOX61/EKKVF50YlG?=
 =?us-ascii?Q?raeCrN2i6KYXwHqRfDHZtTT9D6JGRRdcG1Xf7xbqWg7+bGPCLh+TsWvbkTy4?=
 =?us-ascii?Q?WHiOwVrr90S/zev7FmHbk1aRKkEE9bmsr5EVenGj7jUdX/w0og9VhvE8T//B?=
 =?us-ascii?Q?Zl/Xzb4DqvzlNlDSijTxplTQaSVGsyjQzYJlPsAiuM5kGC4L2Ssph6/sE6jc?=
 =?us-ascii?Q?+JgIyDYqfABy1McMPqEMGRm+Rql2vyVpr9vk+a/DRHdcqYuZrFSi6qsA0c7C?=
 =?us-ascii?Q?WKQt78MmjQmozUkCoTFaK8UfDroi1fu6PzYebdu6/FkcgjVKwS9Hx0ypLn0o?=
 =?us-ascii?Q?2dCb99incVd00aTYigJE/C2Um8YDQSEhd0GbXMf5mdpmiO51eTaH4POmvrey?=
 =?us-ascii?Q?pLrwz4VG8AwiOtHXOsGkwOq4yKhMUjyCZBRnpOhLt9nXwM/hPjhb4ZqiyVN1?=
 =?us-ascii?Q?TUTW7VFsA98GcuJ2RZfFtZKIll8BJ01lMikki5R8ybxikLkq6XtMUbkvqNMX?=
 =?us-ascii?Q?O2HhX9W2HaLsCnmVGNVeMrW9PNBNREZke58yQNg6/hlUMyzCo7+p2NSWUsZS?=
 =?us-ascii?Q?DJthMMa9qbnk2fHL5t4QnBOGtVXfqeQeqlLVXmt+6JV+Q2rZx6DPw04B8v7a?=
 =?us-ascii?Q?6mvjy0LE+LWRG10EaUk93JNqsRkuAA+vOpF6SC2qljzQ5XdC441g03scFcoi?=
 =?us-ascii?Q?P3jjwFaIZJeCoSHkBGiIarnL2nrtDi6u6bD34WtJzRCukFxhSF+PX9zJn6lJ?=
 =?us-ascii?Q?ZAVFD7DmL0c4lhpAyAUtrdHTP2k9LkFjbXxCZHPSzAn2O/C+Et8g56oBXUzz?=
 =?us-ascii?Q?3nFGxQWArrbHzzhw95y6cGMrjzZthlczlAsJhMAE5JXS/lb/1kRCPKWvQGMu?=
 =?us-ascii?Q?7yvxHYdFAOzvhZdRjDMQUC4+msaBw1PeUr8/Icqxq0ozboCK4FABZhppSFJI?=
 =?us-ascii?Q?Sg6H7OA2a+SpVufQ33b1aDFdmcyzvXzDcFIieiwYsICuwdrCebdlYSR63JqR?=
 =?us-ascii?Q?F4Q0HFqgous=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS7PR12MB9473.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(366016)(1800799024)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?GCW3TSWvDDZgtPRu0mapa8vVSPYB0lARyPKCbDeWnthBZKcVQvKVJDBEuDgT?=
 =?us-ascii?Q?OH9lwPa67imtbAZpYy+vp4DVuPjsF0rZaO72T8QRQjn6+CYzHTzMqEbT0tqk?=
 =?us-ascii?Q?9ViWOdSuFUtXntkPdm47L+HxhOLAuXVTR4nTEmx3MpDi4hqLDxhbA/61fnBs?=
 =?us-ascii?Q?hhN4i7ESnS54wzxChkLwiTl1R6SHKdCF5kUucT9XJ7YvIFe5KXFfzenits3J?=
 =?us-ascii?Q?TbeTCmZY+DX6g8MCi5dhLwZeVwXpxPZpwuHDTJegZ+E9OwBsLYKUwKZEEFys?=
 =?us-ascii?Q?UL+RFy2sArsjRv5F+vs8ZMjuy8WIQQssYiyf8AdHXmRfO8LvYvy6knWqUqtK?=
 =?us-ascii?Q?084R8z1rKGvw9kR70ZpYqasX/R86HMkK1aBp4uZO61CJjtGI0X6ndAw1TD2c?=
 =?us-ascii?Q?ZBg6p5cESNvDK0riuIMTmfUjbxi7zmaLbJpO/Z9zycx6vikb14CM/MJSemOY?=
 =?us-ascii?Q?ncNDBbAXw4tJoI/hSCkcTaVSUTaRsTnY/Gwr/NPou7YJAjuksXi8nuVviUu6?=
 =?us-ascii?Q?kj3al/GAeElizyH6e8XxRzcPRKL/6ZRkWL5haduotRyR4+Y51LuuOHfm8UkZ?=
 =?us-ascii?Q?nHsXhH0Mz7FT1LNUuEX3rk0VG0bDPS26oH2FPLPJjNCAfbjI04Fxt0Lem2I9?=
 =?us-ascii?Q?IbLwTDQFoZNCxijpHYeVmztjLxHY+sNXQTqwrE19WQgsOZzc6cylv0TOmSmi?=
 =?us-ascii?Q?KkJHT4q0oA8V7w1eoZl4r0vn1Ug0EqZ3X4FrUfpVu5R8tYfst0DAoHmRvSBy?=
 =?us-ascii?Q?x10cHiEzDLPP11Nx4+o3EkABxq/IsMQRLoVBPIL4V1DqBTn488DX2Yo7Cvv+?=
 =?us-ascii?Q?0T//OE6bTA5vG8c5qEgpAin/J3SYcUCn+/g8As009rDrZu5l3UjWbzboRBYK?=
 =?us-ascii?Q?SFnoLevLyh8N+5KigM7Q0IkyTVNVC6ELt7VswA2FMAWVxY3AVgV/8svceINs?=
 =?us-ascii?Q?pMDtHDeomlH2ZrZcQmR9+Uid0dQL5JkRnN7g/lgzh++4f9hR5mDIUOmev/o9?=
 =?us-ascii?Q?E5V6rC6h3FKsF7GSOFVkoNr0UaVnVWUCvc+jFDLnAsObwxzq2AW5rzvrIFm7?=
 =?us-ascii?Q?AFXxc1LNuTXYjKDL3NkO7d4vwnm5GaN6Nuj1mV8MMoUn4pHyh6iodeH1IlQL?=
 =?us-ascii?Q?IVPvevRSZXw7FH/nBMbi4RnCfGJCBgYy2KvmJdBNCzun1o02laQrqZDigbLa?=
 =?us-ascii?Q?zuWFPQQB1Ky9GxS+c/uj8rBdD3sIeyy+Lq5oht8bPLy9MX3YaUkB+u3/0HJr?=
 =?us-ascii?Q?CbVlAcRsTCIAHGDXlefu2u+y5He9/s9YB9vNRiKMN8W+bVg9FORSWy1jsJqh?=
 =?us-ascii?Q?cXF99coGunlp16CeSjPuOfXXoizrD69nwrb7m3XE3XiYbU+RXVR1QDlGBRqz?=
 =?us-ascii?Q?ad79/45mmr3x/7c74ailpgNZoag/C2hzTkfNsQWkzAcSXZSojRYB8pSpYMLE?=
 =?us-ascii?Q?Ci4i/fET8pFEtYTlhp70B+rdXmXT6sVvCAx5Z0pKz7/56YeRfqf7jfs/f8tN?=
 =?us-ascii?Q?pyP0zzE6EZ4PJgwJV79mwyghO681WwuqqCN5B0hIBV9laUYEWlwHFXWRnaRu?=
 =?us-ascii?Q?9wqyvmGu2ju7TcU4mKnUrDeFknZdseYHpIYYwFdE?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 53f644a2-a6e9-425e-f5ac-08dde0f52088
X-MS-Exchange-CrossTenant-AuthSource: DS7PR12MB9473.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Aug 2025 20:55:57.5860
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: l98mhjCEPP2PIcqstFN7T4wAHLpAWbpLGr/OMjiznshiERwmm281INsYH3GPRneT
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PR12MB9435
X-Original-Sender: ziy@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=ZRAMTS8I;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of ziy@nvidia.com
 designates 2a01:111:f403:2417::631 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
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

> Now that a single folio/compound page can no longer span memory sections
> in problematic kernel configurations, we can stop using nth_page().
>
> While at it, turn both macros into static inline functions and add
> kernel doc for folio_page_idx().
>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  include/linux/mm.h         | 16 ++++++++++++++--
>  include/linux/page-flags.h |  5 ++++-
>  2 files changed, 18 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 48a985e17ef4e..ef360b72cb05c 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -210,10 +210,8 @@ extern unsigned long sysctl_admin_reserve_kbytes;
>
>  #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
>  #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
> -#define folio_page_idx(folio, p)	(page_to_pfn(p) - folio_pfn(folio))
>  #else
>  #define nth_page(page,n) ((page) + (n))
> -#define folio_page_idx(folio, p)	((p) - &(folio)->page)
>  #endif
>
>  /* to align the pointer to the (next) page boundary */
> @@ -225,6 +223,20 @@ extern unsigned long sysctl_admin_reserve_kbytes;
>  /* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
>  #define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
>
> +/**
> + * folio_page_idx - Return the number of a page in a folio.
> + * @folio: The folio.
> + * @page: The folio page.
> + *
> + * This function expects that the page is actually part of the folio.
> + * The returned number is relative to the start of the folio.
> + */
> +static inline unsigned long folio_page_idx(const struct folio *folio,
> +		const struct page *page)
> +{
> +	return page - &folio->page;
> +}
> +
>  static inline struct folio *lru_to_folio(struct list_head *head)
>  {
>  	return list_entry((head)->prev, struct folio, lru);
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index d53a86e68c89b..080ad10c0defc 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -316,7 +316,10 @@ static __always_inline unsigned long _compound_head(const struct page *page)
>   * check that the page number lies within @folio; the caller is presumed
>   * to have a reference to the page.
>   */
> -#define folio_page(folio, n)	nth_page(&(folio)->page, n)
> +static inline struct page *folio_page(struct folio *folio, unsigned long nr)
> +{
> +	return &folio->page + nr;
> +}

Maybe s/nr/n/ or s/nr/nth/, since it returns the nth page within a folio.

Since you have added kernel doc for folio_page_idx(), it does not hurt
to have something similar for folio_page(). :)

+/**
+ * folio_page - Return the nth page in a folio.
+ * @folio: The folio.
+ * @n: Page index within the folio.
+ *
+ * This function expects that n does not exceed folio_nr_pages(folio).
+ * The returned page is relative to the first page of the folio.
+ */

>
>  static __always_inline int PageTail(const struct page *page)
>  {
> -- 
> 2.50.1

Otherwise, Reviewed-by: Zi Yan <ziy@nvidia.com>

Best Regards,
Yan, Zi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/E1AA1AC8-06E4-4896-B62B-F3EA0AE3E09C%40nvidia.com.
