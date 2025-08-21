Return-Path: <kasan-dev+bncBDWMT3UBYINRBK77TXCQMGQEIMF4NOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A3B11B304BE
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:21:00 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-709e7485b3esf49784526d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:21:00 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1755807659; cv=pass;
        d=google.com; s=arc-20240605;
        b=gvZE0saSpNsEXQ2X9gWcdbuOwY0oADJNkhDoRFBSJ0wJzcwsKnjjxwPIYzKxDBW7DN
         J3ETdWb1FLwuTzyaaDPmEvQbZmaVO1J95P9MvGDh6P1Qi06vjU9GhOB7K8k+Qtqlah72
         cq4NYFz4SJDkoqtPr7X6iAsB/74Mgzq8sFAeUqOM5vAWlmYgWRpEWBF+IopZh8zFr7pP
         LtC78RevpiQLonzsqt18jcauEMkzQYxpRThcgZIUSXRVXVXxzdKDyQzOLWBJ4vXFih3N
         L7EckME7XUz0ON0Ea/PONvuKv7+YSArPiJyZnNGbWhIfp9fHqc7Jjz0LVCww/27D+m8c
         T0Ow==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3tdu6K7SMU+uDwW3gkmArmHxKW7jZ8KpPxN6X91kO88=;
        fh=n8nxoy4K4RXDREujAZOqnUk6jFDR1AjE5YXtIsdwPH8=;
        b=d60VN2CaG3Utr/mlFsmKDZnFQRiEjdqATCb1s8VzVAM6djj/YYQLq/rfH+L8BNcsRJ
         pXRPyFD8N54+oVdmkQLqyOJBeCKOAQ0o8kgAxYhLgS+xpFGDds03M66nRJsZftMlbadZ
         DwU40a0xIIkQKwTwUFPXlOwFGD3S62Q4fGdLf0lVegGiyMQvHMV6aF0Ld9p8lzryJh6v
         qB2kRcZYsH03sR7YrU2CZQjN/BeGdwf/Hg5du2jjBTi6umShBqzhfShlFhKXtCbDoDkd
         gJtfDxM2rr7kT1qgVABOGcHpKWBhKllr3UoIPEYOp0cH6rY3My/ICtVUi6SwphD2qeFA
         PqvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=SjduOVIm;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2009::622 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755807659; x=1756412459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3tdu6K7SMU+uDwW3gkmArmHxKW7jZ8KpPxN6X91kO88=;
        b=U1fTB4t5saJ+czJXPkOAevmzekWykyI/rAssj5xjXpHcmhNa1q6efR8F8Y6KBhr5cU
         3bvdNH6lkGPipQHn8pladSE+0bNRvAVYs6Ro3/bgLEsEMggN9gL2bja9lfhI/1vAXUcY
         Gvz8F06q9JhozHkGQLNqY4oKTFKmp1Dr+CpaMXr33Ds3yXCu2KVzE2RUyzXCIZ1SO2SX
         0AgFjK2oH7Ssu4e0Z3wZkWU2IrwejsDYR4JUyMcZozdRZfy8m6Zn2YdAEchQ1tXIk7Zg
         gSPfwb0bt609ZBTNzyI3pGnUQ8P5oBdIW9jAl5wej7CwnUwDOOHnE0MGWNxtStesMlb1
         rQTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755807659; x=1756412459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3tdu6K7SMU+uDwW3gkmArmHxKW7jZ8KpPxN6X91kO88=;
        b=JX3+dKKymp7QWsmI+XdkXOdYb0XOpR1l1ZMsOwDMXhTAOO1u+LuRvLqOF/t8hiJOFt
         274eXREg6gl7wJRhkBzKABF63jVZIp0CA+CkQ/HWk14iHQ8zGPwhnVh4Eq0ggKxdhbfC
         LRbrqY/3/XlcDW3aY0FDASrXLZPVEwruFTQHRyiNBqxEecTtRQzU+OS6xJ4CZDJPtpQo
         qsirWYSOiEyBbEgHhvsEv7IHbNcEwd2zZIFpgymswunvEeLBBl0EbD3K/Iy7hW/RD8ES
         CdzgQv7F9pYjYmc1Am4upHUOuUAjWRITNa/5q+4XsfRF3mfxxxtsbSjwkPZmmiswHDoh
         E/8w==
X-Forwarded-Encrypted: i=3; AJvYcCXBQstiyWV0h1OmnyI0Wp54fQZzZrGthlICWsPvI3V37j98uCaqZaRpuPE9HMXRk/l+4GLLig==@lfdr.de
X-Gm-Message-State: AOJu0Ywvdbl4DjD+jJJFWU6Kgq4AiH4foFSl5hwKJTr7VNTsWmWhWISf
	fqTvu/4fMq3WBlpWPK9LJHwVzox7mx0zlSPKnXzmMHImPq9fvp1HU8qZ
X-Google-Smtp-Source: AGHT+IH0mWhfS2sf/ExMo3FKbSNoChjmpI+2VIzkd4g9nz4A6kBALSn7GDzW0fdPRb0kjbxWmv+PmA==
X-Received: by 2002:ad4:5946:0:b0:70d:6df3:9a3c with SMTP id 6a1803df08f44-70d8961b082mr43754776d6.29.1755807659245;
        Thu, 21 Aug 2025 13:20:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe/7OmHzzXdcaMfd+JI3J+Xl5nj1v6e4Eq+4ctUmK9cGg==
Received: by 2002:a05:6214:3107:b0:709:642d:1566 with SMTP id
 6a1803df08f44-70d75c0d700ls13724576d6.2.-pod-prod-00-us-canary; Thu, 21 Aug
 2025 13:20:57 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVlbxNxhFqDGZtcf6U1yx+vpdH0yaFGO1loSi+Q2qP/puTPz8mA+t4/sByF4pmW+eadyko1091IvBE=@googlegroups.com
X-Received: by 2002:a05:6122:5119:20b0:539:15fb:9f20 with SMTP id 71dfb90a1353d-53c7d6a7949mr867805e0c.6.1755807657432;
        Thu, 21 Aug 2025 13:20:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755807657; cv=pass;
        d=google.com; s=arc-20240605;
        b=cD/HdEoKFiQ6zPa1QnIGbL5kqc8129B8y2QkO40e8jI4ql60bsOjunEQdPdgWQ39Zg
         AZD4BGu4sf6BWOHxoEMGMlai+qahX9LqbcPqKwV//ci+ifui/RZz661btYTaECZ4ezUM
         p1tS1U5jiYJEh+XDieFH1daP6uy4ZlBLbRK0GdTHG7lOP037VNaKK32RE7r+KrD82EU7
         YPe18MTVFGkXRIAA9j+1o+gBAWIoD3qFJch2nBMwrsnHO5qsGhucBbPugB98C1YSEwlA
         6VdUi0gNGhKUObbdG10RRydCK+ihu/gSk02Z5F745U20g6TQZRh7RZmqhmjJqrKNdoRe
         YzuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=5LsCWXH2/2V1Mf+JKRuFmpoWPyhjz6TsTO+1Eky5ij0=;
        fh=PJK8wnsqGkTlnaikqq5nuWjg40RlbH+TZzmetxpxqmo=;
        b=lw5YgVABuemZPvB9AAPzmRWuh0d+TbN0D9JEb1NkFk2lWm7z2UYD2LjkQMtKqfLNHb
         N6LNz4tPTH6+lfOdw59SFZIpXYbWR+ay7m2A7uvKtZ+0rSU0gNofmEhjoykCRbTiWvrb
         usdHFtufqE4upe2c1ENTjoklB+XKni6f8s1DMdwZBDbKcRh2fOEuTfsI6O7RBCQVWMoI
         1HJeennPw4eK2Bv69Yj5AvIe+c+befAtQcsOxc5ykDqSKg0fhiY9mVy65Dc7osOSZD27
         kOuAPgW+vOYyjZbzzohejI6wJ8wUMvgkMI34C/AgU5cciqVjmnKMkGY6T2aVmo+6MYYa
         CQpw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=SjduOVIm;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2009::622 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on20622.outbound.protection.outlook.com. [2a01:111:f403:2009::622])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53b2bf52835si771077e0c.4.2025.08.21.13.20.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:20:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ziy@nvidia.com designates 2a01:111:f403:2009::622 as permitted sender) client-ip=2a01:111:f403:2009::622;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=wl26AXQUltoo7OVE436mwjXQ4iSO7o9p3JNyEkXZsqSICr/QRthpazH+m9Lri6brjXYXswoTde+qIbF68H0LR1EL22WPkqn9+SlFFwCXKY0/dm+ChSgYkGh5966wLJq3HYi3lnuWt825dbL+drcUt8fGn/pU7OE8lgI73z88zXWVxM720PFpt8zcZ7q0wyv+Z0WCfjHE2EMYfGO4fJu/CqdhOOEQ5gtyEGgB1gxpMhxh5kLlYSUenjO/o0aXMCnk3+MI3s1cRyGVwra7HsXCe4DP0FmZKLtjsfEfNcJhQnHcIn1sdB0p7XlLYqcefVGhZu7xORYpwZxPDpJVZDMcrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5LsCWXH2/2V1Mf+JKRuFmpoWPyhjz6TsTO+1Eky5ij0=;
 b=p16SuRHBUAq8MzcNVc31bD3W/X0n0bk6Y0gwASDJApQsnwfXEtIw09Nc5CWCnHgf0XXnn6wraLN7tWz0AG09urGq/I9KqWS5x8O5I83NbYmGLzVbLuuNuqltEXL732abQ1QAdYDEPamVTFO7Q0afDUnJLAg5YgkfyzNLiyNBZ12Y4Rk6J7ucruJtvmrVoq16fJvIjuJvW2208pEY1OWJw+5aJvJrBCkhvcT69DdxWXWthBgU90oy0QYFgRITbvjx8hGtJR97Nc1+KDtmpbVnLRiFlbguh5F9y5KVCE/F4BlWvRCNIslk3gSGW6sw1g8LgGzKnB5IcHZoKJmtxbqxEA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from DS7PR12MB9473.namprd12.prod.outlook.com (2603:10b6:8:252::5) by
 MN0PR12MB6002.namprd12.prod.outlook.com (2603:10b6:208:37e::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.24; Thu, 21 Aug
 2025 20:20:54 +0000
Received: from DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a]) by DS7PR12MB9473.namprd12.prod.outlook.com
 ([fe80::5189:ecec:d84a:133a%6]) with mapi id 15.20.9052.013; Thu, 21 Aug 2025
 20:20:54 +0000
From: "'Zi Yan' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Huacai Chen <chenhuacai@kernel.org>,
 WANG Xuerui <kernel@xen0n.name>, Madhavan Srinivasan <maddy@linux.ibm.com>,
 Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Paul Walmsley <paul.walmsley@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Alexandre Ghiti <alex@ghiti.fr>, "David S. Miller" <davem@davemloft.net>,
 Andreas Larsson <andreas@gaisler.com>,
 Alexander Potapenko <glider@google.com>,
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
Subject: Re: [PATCH RFC 01/35] mm: stop making SPARSEMEM_VMEMMAP
 user-selectable
Date: Thu, 21 Aug 2025 16:20:48 -0400
X-Mailer: MailMate (2.0r6272)
Message-ID: <7169DDE5-A347-44F9-A6A1-707BF9A314F0@nvidia.com>
In-Reply-To: <20250821200701.1329277-2-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-2-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: MN2PR15CA0031.namprd15.prod.outlook.com
 (2603:10b6:208:1b4::44) To DS7PR12MB9473.namprd12.prod.outlook.com
 (2603:10b6:8:252::5)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DS7PR12MB9473:EE_|MN0PR12MB6002:EE_
X-MS-Office365-Filtering-Correlation-Id: f619df36-2515-4ba2-b3f1-08dde0f03b24
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?94SELf5U2sNfP7OiFIZT+KX54w6OibGahhp+ocWf82oNd0GpqeivdqHRHVGK?=
 =?us-ascii?Q?uItD8QqcuT95QIQ8nQs3LOvvq51TiyXWNTIs9hd5knXWbrX1lRxEa7+GmA92?=
 =?us-ascii?Q?1ipcg4zSZG4jBfNSBa1H+/kEbIU6A/x0oXpqxPczCeOmxXxQDOprVy5gdZI2?=
 =?us-ascii?Q?ddD1NgoIwpIZ9UWsApYlA8HsuVwQ7h5KxzFdjAic6JmUxZlUKVtHgsTRxuJY?=
 =?us-ascii?Q?v4hpse9scVINpz8kHOPICZ4VGfdmDZrrsIn76KaD9FusH/zg2IHsTh3P3HjN?=
 =?us-ascii?Q?TWjYNgm5mpyeX4Wc8AQuwZ0+kU1hzk3YDRhc6fgAySiruetFFidd/Cn0sv2F?=
 =?us-ascii?Q?FQmo9Hk1O0b2AuuiM66Blg/FaTEHqR4022QS5wBcG5PLiYJd0oY4wlKy1hGU?=
 =?us-ascii?Q?EORGiOHqpDTrjQpgt05PNPGlkQ/Q7I0WrfZv58CuvIN8vPhi/dTOkLPzJgyD?=
 =?us-ascii?Q?YpOqBGTKYiBpR/i5uiuhFLcb6ffFUueXaBZpCfPzoBT985L0iWzeS3yjyNIH?=
 =?us-ascii?Q?9p2GIZsZ+OlFDkYYfLj0E2/fhOJkr1Rwb4h1Ksq9T7Zpdkmi12C4nRm8JBGL?=
 =?us-ascii?Q?McQnP47RlGckCSZl77ebgjK+1LnkMadQkeYcS0Jrq6xMS+Koom8gELpNCr2c?=
 =?us-ascii?Q?nX8xBhVF4h4xrgtr34Lhk4XElDVzpQ+h7VsNCSoZGaDYmOOaToImZKNeOZvh?=
 =?us-ascii?Q?vXg45A2gSWjh/iiyvNPKa28BoDsGdE5VGpJ19J19KSh3FXZpcKL951imRV+c?=
 =?us-ascii?Q?jEKY6JqzC1xCy9fT6Et7Ly2U+LV64vFumxCZWMiPy33feabaBgoQBzXIwPwU?=
 =?us-ascii?Q?rGUwEmyHsBx684GxKeSdR53uy3Me7wNXnDthX1p41Edken/gvgD+o4q33AaK?=
 =?us-ascii?Q?qrL+RffI/XZIEPBnIG6X5FaFYjPFV1TS6GzAniixEiHPRwf9WKf4wAMLY/Nl?=
 =?us-ascii?Q?szOMeGh3+9Xgw8RP4CktSa7MYSc6ppqrakT7Rrw0cO6Sh04SLMWIaVqiBQbA?=
 =?us-ascii?Q?3/AZzMPxzfsuB7Fg88Z+l5MG9mjDUWwgv9Eh/4ZAtgAhLt+uKXVnsQvZ7MYm?=
 =?us-ascii?Q?jHBJDTzjWMZ1T9ZupZj1yLmfCtFvJ9XZIXBIn2esFx8TnELqLPhobtUzXJZo?=
 =?us-ascii?Q?48uW6TK51KbDwz5FN2RTHEKKc2wkHQ9axmEFUVBcSErHPUEJQyzmtgQTB5Vl?=
 =?us-ascii?Q?TDuajQxbSp/bZySk0+8tuvIpMu5rKsY+ho2wVNvTa7g8u9Ne2NK8dfwjEOCQ?=
 =?us-ascii?Q?tCQBBGSK6d2HVZs84wW+npsv0rnY9To+p6PkYc/XBV6EleZWB1PQTqEykojm?=
 =?us-ascii?Q?Cqk3E9Nr/dwS2IPg7TR2LNWYPZM756maQsARAt1wJf5lHOG0PVV0L1hfxpWW?=
 =?us-ascii?Q?za0rYCAaXWW+YlS1NAR+VD+DRgz2F5VKdbsnp6ZwV3/VsPA8wocKtOHL+zQi?=
 =?us-ascii?Q?Xt3+uNWpX9U=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DS7PR12MB9473.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?6jIehKUcneFDG1zDKFaFkuxUaQsVIZNcI+dmwYK7640S4s/tY+bvSg/50FWw?=
 =?us-ascii?Q?OgOAFNtX/CO4VGRdqqM5SOGtww2SFOQnFadF0GQ8vYTR6GIDlkK2xsaAJ8UV?=
 =?us-ascii?Q?qqsTR3ZYkW3s3iDMKCoCg0pkKZjiv7CI08Havf8z6S6wJbVbpilWN0RWhb0m?=
 =?us-ascii?Q?5pLmS5dB4cPaUP8Grpw4mT+9lxsDLHgQNmoEwEMbd901MtyYtH7XDmjb0yD5?=
 =?us-ascii?Q?GDdQwAbaULjHOICOrUV9EeM12JusWXEi/HRjWpt+IxG4w8i3Xu8YbKTITsXT?=
 =?us-ascii?Q?PtRGepn/eIp10wfbvWHVxP6QoHo2mq/sEGSTlUAmgCdYw+rvnyiMhA3qqGKd?=
 =?us-ascii?Q?EKNoi5aMGlL6fCbyIKLgZNL+wbiX/JPPccTJALw6n+VrUZVTJjemlNStqS5a?=
 =?us-ascii?Q?CRvp8MxLNDo5uwfbVxapMtxV9hWeTDOHon5xg4sQVduz6B/Yk9LpPosWSVUT?=
 =?us-ascii?Q?9qnTRhKEqyzu++t+K1c9Vezr8xJ5AljQuIE8A+YlupfuNm0Pe3c/56N48cOb?=
 =?us-ascii?Q?QoLSqAPtMVw76SSpKpUONG6zkxl+VYhtUrj9ZXgMRDlclsjdHbLutYzXwJfY?=
 =?us-ascii?Q?SfDIlVyypRuwY7L1seLlXfG2oGZNC/sSy5hFbyJuX5Oo7TiQ135PIBZMBF/0?=
 =?us-ascii?Q?Ip1EWpglfVCpCXSHIjMbhVcWNaAL5GWjccIzRX2Qp1QkWNl9TA6rGlDRJD+2?=
 =?us-ascii?Q?7x3madmh5FPIDh48tKLvFnhIUklPbr0O+bzFF8YikclBb0prePGMfZoVzXBF?=
 =?us-ascii?Q?z2ZoRJSPV+Ju8ji1WeA0xpJ96GTlVhSzvHiZHOUbCN/uMHcsoCiilIvgChGc?=
 =?us-ascii?Q?PZVvy6oNLbemQARoWfkhXLspee6IGZ0lx9Z5ncKcdRV3/UgMU4jXpDCBJdjG?=
 =?us-ascii?Q?0hpfyb/+wmnuDkccKhw0MGNJTGoengp4vbh8JEnG0Ju/CrrBsapVu8aSrcDv?=
 =?us-ascii?Q?3FkkCgIExLy6ElmTqDU8IRUpB4UY7OpWWZ077kZHDkoEPewPUloyWQKHKj8i?=
 =?us-ascii?Q?tIRD/pL9SiYm6TBSJh6sEfGWRGwm7LBxbVWtPJrf/pflW7oAnPpanP/GyZ20?=
 =?us-ascii?Q?YbvT1cKBrwnaqpGqTorzD31Lrvk4a3X38O4FH60iqH6/XHoaBUB/svd6oMGw?=
 =?us-ascii?Q?D7dnSY0BXwJnaKMI2pt+DeIdaT68q3C91IrrYdY4BSyzHJj720eGaw2UKctA?=
 =?us-ascii?Q?vz26eYXhL6d1RLp/jMrQ4eN64i0NdxQlKKf1mxyjLVoH1mkfJXLU2FEGcj+E?=
 =?us-ascii?Q?TaWJtFDjj45GM9qD5hkhWDx4s8mVG9FBhIQ1E/4gG/evJ57msPCdTBC0sB/p?=
 =?us-ascii?Q?MbRWFpV6Rwprx1Yd0z9ev1St3bm+QnfvxtKWPOc+12Sy5sy3luOZxmo6jlI7?=
 =?us-ascii?Q?JNvHDKN85NpAHTb4qbbJQakoi50tDtkIqyT3Vqc4lIqZ6jH6QqMbQrCjalaO?=
 =?us-ascii?Q?6ATbrAQ+tas+oHjRzp9E/SDBEdGh9JRbA/czc3RXoDnQcYnFnUmh20GFX6Bk?=
 =?us-ascii?Q?2xqPE6EnubM2CFTxpHIA0C1jGJKUqnHaI0uuBa/HKvGl00pxD/jQJJqucIch?=
 =?us-ascii?Q?IpC7ht5mX7OwBmcPVkKPUwJX4yB6SorOGno3bLPp?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: f619df36-2515-4ba2-b3f1-08dde0f03b24
X-MS-Exchange-CrossTenant-AuthSource: DS7PR12MB9473.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 21 Aug 2025 20:20:54.7076
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: y9Fke4yeWvHxDD3HPGMFf43Uf0a/h+ZaKyS5tFV4TnJDPSmOfCjHaQFDFZiDBtKA
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN0PR12MB6002
X-Original-Sender: ziy@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=SjduOVIm;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of ziy@nvidia.com
 designates 2a01:111:f403:2009::622 as permitted sender) smtp.mailfrom=ziy@nvidia.com;
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

> In an ideal world, we wouldn't have to deal with SPARSEMEM without
> SPARSEMEM_VMEMMAP, but in particular for 32bit SPARSEMEM_VMEMMAP is
> considered too costly and consequently not supported.
>
> However, if an architecture does support SPARSEMEM with
> SPARSEMEM_VMEMMAP, let's forbid the user to disable VMEMMAP: just
> like we already do for arm64, s390 and x86.
>
> So if SPARSEMEM_VMEMMAP is supported, don't allow to use SPARSEMEM without
> SPARSEMEM_VMEMMAP.
>
> This implies that the option to not use SPARSEMEM_VMEMMAP will now be
> gone for loongarch, powerpc, riscv and sparc. All architectures only
> enable SPARSEMEM_VMEMMAP with 64bit support, so there should not really
> be a big downside to using the VMEMMAP (quite the contrary).
>
> This is a preparation for not supporting
>
> (1) folio sizes that exceed a single memory section
> (2) CMA allocations of non-contiguous page ranges
>
> in SPARSEMEM without SPARSEMEM_VMEMMAP configs, whereby we
> want to limit possible impact as much as possible (e.g., gigantic hugetlb
> page allocations suddenly fails).

Sounds like a good idea.

>
> Cc: Huacai Chen <chenhuacai@kernel.org>
> Cc: WANG Xuerui <kernel@xen0n.name>
> Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> Cc: Paul Walmsley <paul.walmsley@sifive.com>
> Cc: Palmer Dabbelt <palmer@dabbelt.com>
> Cc: Albert Ou <aou@eecs.berkeley.edu>
> Cc: Alexandre Ghiti <alex@ghiti.fr>
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Andreas Larsson <andreas@gaisler.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  mm/Kconfig | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
>

Acked-by: Zi Yan <ziy@nvidia.com>

Best Regards,
Yan, Zi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7169DDE5-A347-44F9-A6A1-707BF9A314F0%40nvidia.com.
