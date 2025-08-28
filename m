Return-Path: <kasan-dev+bncBD6LBUWO5UMBBNGOYHCQMGQE2DC7OBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 775CAB3A1A4
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 16:27:02 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b109be41a1sf42746441cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 07:27:02 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756391221; cv=pass;
        d=google.com; s=arc-20240605;
        b=bUr3wME5gXNUnLt1n0SFA9oOzSZ1xdsG4dkzEwroS6c81uzER9yrGw7a1oZJSduOyi
         QOwLf62f+yUFwlxTIguNnJcqAFyTR00zuyBSZP8NjzuRrBOV6GaahDfRsrP7JkY2LIf0
         1Ja4v57p/TkvylSJTWdDzMWL8FYTWek123oJb9JFRoXabiUgBZRczpEOUaZv/GUWopEp
         2592A1RRLq+J3BIOi1QD6xTbKKHAQo9MgUeNSEE4vEcUL1TLoDkWJbkezLhCflPST5CA
         of0r1unjLe+2XHJrgFDLEaK21kbUCvyibDdHOkW2HKN0r1GGDqrw9J7BC8QMHxdbO6ZW
         yy/w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=l3tobFq4bJa9Z+M9NUP4HbCVYob/BTlpioFIGOP0xaA=;
        fh=7bABegLyEIltbc83qdIUYbOBQaNY2IyaX6Zsoj/vfU0=;
        b=Y3KNGHgCtewjXR2MUFWhGXNYAVFlfN3mJWP545uW60W14dsu60RKW7mOeFTBm7sxlY
         KWTPktEhddCmYWdQiziMzr5S4WYMKOq0igjle8zXTxsIVd+WaNeISntcMonhKqXMJd3P
         /NzvaXOL+XN0fLdC+xrinnn/AXFFFsPt4wHtgfzDalra+t7busj2xcYsS2Hh9/PoGnOU
         grhHC0Lh3l0LQEaTgwh6tVjnyTwwKXECsq43yMwxm6EME5hGGOh3UAc2xmImwtd9BEL1
         1KzJ//nAXInVfZ+4oixLQS1Ql2yUKq2GJggAq/D3tFpk2z9lyYNUE0D2OQthoKgyHIoe
         RzAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=he5bWClL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Urbu8g9q;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756391221; x=1756996021; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=l3tobFq4bJa9Z+M9NUP4HbCVYob/BTlpioFIGOP0xaA=;
        b=OnK6iFOPkIvPutxDxr2i0e3ywnY1eNlDpzyiPYzjzMzWra889KckvM9ri/ds4xiuDD
         oiLIoFoQdfTioLlAl2QStshOttRadk4AAhQIUBm0YTJv0OzfiCNnq1YahA5inplmYPaK
         C5MnzryEcCYb281P9bIIjogRDAwMK0005HZvVagJ3reuelmkISmAqFir5rRcyRWYAs8B
         0PTIU4zPCUJgqFk9iPG6286sWmikk/6Oy9hGCOp0Wx8J33JtLHuCpy7XNuT9J5+NaYc3
         CsDqqc+oMEMIIXeLUdizgZAyinhXWvg01mbTt1CEDAtjXKQXfz7P2IEPF7W41HhrRKL0
         padw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756391221; x=1756996021;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l3tobFq4bJa9Z+M9NUP4HbCVYob/BTlpioFIGOP0xaA=;
        b=cQFlQabxnkEmGJ0+oe3Y0iRcHtF6mDCMECePDLFLMkWwKeMbfJQW9sJYgw37a+TyD+
         uo9Mt6s/V57Fz0J/vHyK49tFQNy9d5J0oFDXUn8WFwEiCk//n0WyDnZlCZdQ5Gqn7CP6
         Vw1dQ7Ist+Rkp9kQmh7dZh/UUZJglt5FmxOvDn7BNBPVWupDvzer6G2+Wr9aqOBmcvON
         cc8xkBh9h3g/Zvo7klBNLyYy/yQioRXs+yLIjC2s+TCsViEgHf1cGbWkbDioR8VwFFd2
         yW0KabgOcjqqbd+PP0g30IBOsa1Fc9oJBvIhArizsaHAWwqBzlCssnsontclEyVEi7AX
         D7kw==
X-Forwarded-Encrypted: i=3; AJvYcCUa5LtU071pE306pAkq9Ndrf+igYxXj6a2U3ip5axV/CLMoRSFMFhJwSt7aRy87lLzrDHETKQ==@lfdr.de
X-Gm-Message-State: AOJu0YztPZzeA5Xkrm7uLvybGHN8SU+GzzBmk1wqj9eMjBRXsLsZZA7Y
	5Y7m5QYfk8qLF9cdWqtIGDP8XyKfcJQZYjtGPvWpnSyunJ2dhw1/XnJr
X-Google-Smtp-Source: AGHT+IFaUVPxdra20IJGwKFw+qoeVP7mY79YTx/znU2g/lW8e7zQeIdgn4o4pAOMDksNkCAiVVb4yA==
X-Received: by 2002:a05:622a:5e05:b0:4b3:940:e41d with SMTP id d75a77b69052e-4b30940e497mr4705681cf.69.1756391220706;
        Thu, 28 Aug 2025 07:27:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdJ7ff7ZMY4DJeAmsRH1Bj0Qu2oLaRk0xuklTgf1X8vCw==
Received: by 2002:a05:622a:593:b0:4b2:9b6b:2e97 with SMTP id
 d75a77b69052e-4b2fe630658ls16419721cf.0.-pod-prod-04-us; Thu, 28 Aug 2025
 07:26:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCV1Y2+g7uEe3FguZIbEqugsqlQXiywzYrZb0U/3OWt4Cu9oPvlvu+Xq/UxAXl6R5oHBuJs8WmEx8LE=@googlegroups.com
X-Received: by 2002:ac8:5a8d:0:b0:4b2:9620:33b3 with SMTP id d75a77b69052e-4b2aaa6d0c0mr260201431cf.34.1756391219568;
        Thu, 28 Aug 2025 07:26:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756391219; cv=pass;
        d=google.com; s=arc-20240605;
        b=cxhcGGYmVAB/cAsfblwqQhxVZpvYmoYqbQI4Er1PXF7LUHhvz9FbGRtmfT2ZmiLJ4P
         GQrNB8dIILjGQqTNicQGverkq4FxX3n1acHwpm/YJrrSJhmt5evZf43qNJ86Smi/VIhD
         HEOJQCZJrrBBu7CKF+GOMYoZGK/DchnHayD+QWRCIrIXNrsWFGMZMP13WSv15czrlnXj
         I10WvsbhBV6uAJrHMpeoHGvuwtSF7Im01o1QiKBoct0cwALKDXQvI8TXU5NZ4D+zNfCT
         09OI5QDPM+HL2h2OZr9uXbSu1jNtL+Zhju1pt4ZavDBk/1vccs7NITN35YxR66UJGsUa
         EPtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=NcBY6W4NVuSBfhnIa/YurWyaxTFQfwhL9r2T6fOyp3A=;
        fh=E7ljrpHbhodNi8S8rFdFo5WkMRT0KnYRrL2f65CAq1o=;
        b=jpuwLB0/DvBP3v0PItMG/jIebo+WIXllwIkYvnhHIshn8MoxOFg9Q276PQEvkxfexf
         toXyTc1W+ScFfHe21iuqJoFwiuhie3ZTVDW+eIhG7TFpw/QsBP7ME/Tg5eGAsGhOsO+V
         Ylu4cR0NrtfvKvBkjGUwQLwYktTSSXWqbxHAJzZHh6GKDzcYJaKUO40xfzUcl7YS4LfZ
         c2gcsAA4iMCnrj+z7TDRN8FOWdh6BtmeFo8E2PqW1ZOM0JtCu5lQKbHQffxCFFv+LVNY
         MqLrwI0Zx4zdapgwHKjQKukQnloOQxcMHZhma7lCIC1bV94eS6IiuIlZd5KICukSQywf
         8qyA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=he5bWClL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Urbu8g9q;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b2b8c4f53esi66011cf.1.2025.08.28.07.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 07:26:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SENCig016276;
	Thu, 28 Aug 2025 14:26:53 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q42t8g3q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:26:48 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SEDAeX014521;
	Thu, 28 Aug 2025 14:26:48 GMT
Received: from nam12-dm6-obe.outbound.protection.outlook.com (mail-dm6nam12on2060.outbound.protection.outlook.com [40.107.243.60])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43by0na-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 14:26:47 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ozQFjfTb3NbK9cD7k8c8KX96pjkqO0lLG5YHG/XU4dFqckW13/oxCbMHzWd6ZIGXPKHbRUwmkEIHuLBwT3LCm0yJYZTjmGOJFIO0AKBBGUysNjLpV0269AOczwC0bUrc8nC+mrNp6hwx3YdZdW00hBp65GYpg2eruH1BGnL3ft6ZidrAYMaF/unybsgQQlrnVko2l8A0t9PotvGx+wZrq6eS4lLe14rj3PpUCwmJgR0E14bL/WlbadHGgHlPIiBBiXyaYEZdFkgxU6nLLFFAYd7HPg0cpXUDDEpicYdmPP78nOOACoDuJoJatslYlcIfS5yboTr9E8L/2LiscSDCwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=NcBY6W4NVuSBfhnIa/YurWyaxTFQfwhL9r2T6fOyp3A=;
 b=gFKfqud/+TwIDzTuqBxDgBFhtx7b023DkqAuMxITJzbAspQmr1Wft3bUyRAuitdOyL9GADE7m7oMc0Dj2LeW/BaHqAELRRhxkNKQ1B2nwOZzlqOaQi5PUc4TtTFEqNoqxKZffKdygflIlsdmm8Bppm17vN224QcXAwKXUI/AzVwj4EKcNjzvDnhIAU80pQlll8Y3vvd5qhdno8B2PMgtNljixK+whAl7j1u0z+2DNeLrSX+BRde6TbO0e6E4xV2V4ZKttvFnsWGtniwGDcWtL52/bUeBUogax1+PQkmwaAW0fL5FpubBIVamKNTn82vPOIsSZumTFcY6iQ+a8A7g9Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by SJ0PR10MB5647.namprd10.prod.outlook.com (2603:10b6:a03:3da::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.15; Thu, 28 Aug
 2025 14:26:40 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 14:26:40 +0000
Date: Thu, 28 Aug 2025 15:26:32 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org,
        "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
        "Jason A. Donenfeld" <Jason@zx2c4.com>, Shuah Khan <shuah@kernel.org>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org, Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
        netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
        Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 05/36] wireguard: selftests: remove
 CONFIG_SPARSEMEM_VMEMMAP=y from qemu kernel config
Message-ID: <544d9592-403d-4b4b-b00f-250acb593c1b@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-6-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-6-david@redhat.com>
X-ClientProxiedBy: LO4P123CA0362.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:18e::7) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|SJ0PR10MB5647:EE_
X-MS-Office365-Filtering-Correlation-Id: b045dcd9-7f0c-4a07-2dcc-08dde63ee7d4
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?4rP+BSTNZglU4x5fp4JbLBq54ws3Jm39LjAlZ5W0Egi2olQ/O15XuZ9tahux?=
 =?us-ascii?Q?p3efaXnzdXv9ibsKp+QrVRVPN+6L55cnqhnF5wD/rA44eboQisDGrTRZR1dC?=
 =?us-ascii?Q?NE5KgozGSOH11G9knOu9YS2Rb7LC436Bhee1FxgfbbmdXG8e08+LYCmsrQh2?=
 =?us-ascii?Q?b1yXtFfMXoNvUgNRt5pAouz1PLB5UaRgHMmk85ti9q88BRt7iMgyq1Dsf9j5?=
 =?us-ascii?Q?qDdOtmKz+FxABRGwADV8b/afkZKGtcXVe3FRkXctvNxgd9WGpEowRGJW0OPs?=
 =?us-ascii?Q?ZuOOlPOEYVwwOsOh8HX5Il/MSG3pmjlOJlOqRO+1U099v0l3uBm89RA7Y65t?=
 =?us-ascii?Q?wjXHdW6RSelrWQcAa+5J8YoK/xWSxKVJIJW2wubx8/Quh1PaaeFiMRIk60zx?=
 =?us-ascii?Q?gufcfpRrk8uic+mEwcIDnsGdaYDH5TaW0Pk0F2ceBZYAf92Y4Rpjz/U3bIWo?=
 =?us-ascii?Q?QaoJXWRcdGOoOEIsa5Haeysp1iZPoiYWMjdHuLlIGbY8LQE4TbLfarDId8fu?=
 =?us-ascii?Q?uDuX/vLTRUvrK9NIvbNGvka3ACS9xy2ecXA1NiwR4qTHDGA0UEQ7h10Dc79B?=
 =?us-ascii?Q?bVKHeuJHgO+bRJVp5kJaEuhA09MgKjbj0msNrkn4g5PGb7qLUuZt8f3Xmd8d?=
 =?us-ascii?Q?k8myA0yVZnq5RXYip/oUFwNoI0w45HwY/bfYM1jmswZ7gTurUO6gxIZ4F//Y?=
 =?us-ascii?Q?6H9k3YD5yNGv0L+JR5cKZlLARRu9pC3tV73HBqYHcGaYJKBt3ujqgYRNR6F/?=
 =?us-ascii?Q?O8l3xN66oKXpSMdQcABRU5qW2cWHm9yVyrV2l0ReLv2FWt8Wt33DZ9fXM3mq?=
 =?us-ascii?Q?05l1wJN1qJt3cU3VSYylEfbu7RsfMZGKDFyssgHtQbkajhlJ3z8hG6ASBN5M?=
 =?us-ascii?Q?m/HZTxgE6jx5H2jRUMp3+YiFVwId270BSRazSwyfuZhsaZXv54+kbPd26h3q?=
 =?us-ascii?Q?bLQoPNy1FRpOx+j/CfenSkfYB7oo52D3XRZ3XOL3C8kJQK23NCRGvJ9txhrv?=
 =?us-ascii?Q?EhHq1+Z3bm0HQFz/hQ8nHdBwJ3avDBkVSVPUIHCoxglkjwhkiPxGS+PA5e9i?=
 =?us-ascii?Q?zV3aNQ0XsIhPBNJzFzMCIQmPt6oIzdsBAceDgpUe7jzIJfsQ+8V8YPUI/Xs0?=
 =?us-ascii?Q?lyQWzkLExWHF42TbYsNRn3TwwTOD2hbzBz6yzLsMeC8vnB43iqbLH9MBUazD?=
 =?us-ascii?Q?BdATDCOZeVPuP9fFntVfsZ9YKI15RD5yGsfuWs6TesNlGRz0sqxozXK6eO4Z?=
 =?us-ascii?Q?CR/96T3GW5c98o/JpSwbIjUbVVL+OOe5ZRU5Ga8UQJLf4WeSjn9DegEqLSnK?=
 =?us-ascii?Q?SX0idhJl8mIAxHRBw5uN9tQyvS6kWbx0sONggCO6h1FpWl9EOTuWocijNvDQ?=
 =?us-ascii?Q?o2rsEDRdM8WqPxByt2Ym6UgPoxmrXETxO9cTKOBYs7YmKvh6yQ=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?cGVrPkKklTEghKOExLt4QtXeBZrrM4EqpYqHTFhXDjWZpXo9fqox3zlaOhEc?=
 =?us-ascii?Q?p2qJcTQgzHk9E9wb2a3hQnr3zs9Ca+9PU/YfpH/DBpcfgCPfjD7eJlflSPw6?=
 =?us-ascii?Q?n0SeGIiFcGe5MuWzXM88MKgorNAorCYmx2ivoDidUeAqgNzx4p3ZKLwDoCKC?=
 =?us-ascii?Q?jp0fbuPKYCFWHJdthln05JfK2Pb2zaK+ln1lKdB7lOBd7KZdHvIVzF+g8l7O?=
 =?us-ascii?Q?tqh/h3lSLLFPUe8wZX+Tr7QTLWEDUmSS/5uRHCzV9hYPRYVFpBbrF+jp24CT?=
 =?us-ascii?Q?r82FYN1quMqR5v20z8qmU3afyI9CK1yGxjp3CpEuCuTPKU2dVW4Ul9J5lndG?=
 =?us-ascii?Q?j8W3tVqf8c5ASKrEgbT5Ksb6vl68NHM4hJKaCkw/iGqtvGX3BsPXTqb/dS/2?=
 =?us-ascii?Q?ISWjRXDXR3oKqtGWf3N6JJkCPDhydtD1FlzlVVEmsmbo3Z0OSL372aAPpSja?=
 =?us-ascii?Q?5ldrdCcxAOjLpTSNwFGi8oQcmsg99H15lHkuRHroihtIKZrzJzsIep7OcUYm?=
 =?us-ascii?Q?M2Bfalt4Veg9kPnGMsoYsfIYxNgH13ggBq9I4hOIqldTlt6Jol8cwNVbspRY?=
 =?us-ascii?Q?esSOBGzkU1bvRHZ7Zw5kkRpKJZci5LIMI7Yo/bWKFFAL7UTjKD9ETkIB8EeK?=
 =?us-ascii?Q?xVL8T7vJQzU20pBTSMfEdiMg+CIWcvqGwBVqpRcVpxajZ1O3lWM9jSAp19Xj?=
 =?us-ascii?Q?rFf+HVbVexr17/Hu/B1+BHw93ud2+xTfkeOIWk38ucSquHz6PN/f7L2YEuPW?=
 =?us-ascii?Q?qBLHkxPWrbDKw5a3n7FDMJFdzg/gNDRyzbqKpgOimVfcngXk/0RU8GD2rYDc?=
 =?us-ascii?Q?r4zzWV4IfD8qiK2IjHsgpu3L2GG5qvjN5tOSWt+QZ3JFXnSu8OP929XVLKje?=
 =?us-ascii?Q?10Gpm7wN+VJf0yALvh34DG6JK7Twfq3MXzESUKKvmCVheFIHsWYi0gf0kedK?=
 =?us-ascii?Q?Uv41NFmRXv2K8WDanDs/m8Kb/BItt9H5XHHHJDvNS1t9tWftahOXYOwwwRIG?=
 =?us-ascii?Q?pdsp78RlKQjHYbzDO/qXcuQLJs5lpX8U6B5l660sjusL3d6FliInfnXuA3yp?=
 =?us-ascii?Q?0KE6v7ECNBtIxIP1ZzkVQ4Syaj14MKaIVpmnfSv7kTmFG/vZFVwOop8W++h3?=
 =?us-ascii?Q?+8TOnlDjqF54Sgx/EBpZDCRa50I933eNBxqwWiozKhNUSo33xZcjaZU552DX?=
 =?us-ascii?Q?TJ2v5CcsGtcSV3lBFxZmuI0RHyYOAwDB6WOiV2RQ9Fia0n3HoBeD0CdYi4YX?=
 =?us-ascii?Q?iyVZd/9yX7ThSYlREil82xnsZt3xaFdiTeWXYkcxy2x6U0knDmNikiLTWZAB?=
 =?us-ascii?Q?gJqoaXGe7Sg78YOfrES/hkB3yfriPEiAdHS+Ncqk+C+ueF7GiWf9aTuZMKuP?=
 =?us-ascii?Q?jGtTqLqToxWJnZyJwvIAMYOU7Oz9XlmcoUwtJzPVlyUjM530IX1vGEJBZ1AS?=
 =?us-ascii?Q?nyBLCV1rpaQccvImYNW7aoDCOKXpw4M/EAmuvXFC18R8szfJG91xf3HhmX6d?=
 =?us-ascii?Q?WR90wkWI3YxIOln2vjPIlodcRZaRXC4FNT8jIUWC278/Snbgc2Au/qO8B/Lu?=
 =?us-ascii?Q?/GQ4t2sgMT7I2ysPcrI+9Qzsh9GQyvYUUMc0h/PY5UY6ec6ndOXd59yJLk6H?=
 =?us-ascii?Q?Ww=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: pYBbZZ6TjeYKiW8mGOEyeIGeLxvgBhSkDF3h3gajV5kuD6u69P9Bsk6XY+kLfKRVQxWgJISpn3cseskbY/ChvxsUDJh2PPHFO7ruSvYcosW+pGfpUxWd3A3r71UZQpi2vVkuiKVe42XTrD6ziCWb/cr047mgs3eU04i+3V0faYveMm89UFhsHSUr+IhX8H6zXtUauusCPVlsUc4LXXBLDguqO1VQk2xgrrKPw8iF/JJAeMNYMZS6TEArommjHan18YeUUEqgdL6tQXqXZZCuZJYi8ysNPzOKf4jVFJvDPBEZdbZk4I5inuONNUhd2eMj3hIfs38jcZnq/w9v0vZJmecBwahbWvmT+p0MlEY+/sIQ5jCTXSUX+s6deznVJ4TNzgun7G+ao8aO1M7KPDEnKPY7H9yyqDNCjU2LjAkzdg+LV7WY1XC82L0Fqtk+XD7kK5v7EhDALPoDID+dXjoJtJctxMqMwmbsfgIgu9JQKmST8oOHZMTNMb1tTSxx2hUi8J5E+gYDUo1GF1YhZCfOzlMClMyavamtaPm0Crxgkmeirt6GLw9V+Fcugxsh5qRHnS03mbdJtHhb4bsLzquUbFcw2YPdukCqgTl1h0j2QJk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b045dcd9-7f0c-4a07-2dcc-08dde63ee7d4
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 14:26:40.8979
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: djPX+92949goFzOQYl23OYBylVFv4oj3LvcLEG0OR6PBDX9/kS6tjYBwV6sH8bINYrWkPmqppNXQ623MzHBIR5r80EUiUFDO07sRb3v6RTY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ0PR10MB5647
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 mlxlogscore=999
 mlxscore=0 bulkscore=0 phishscore=0 adultscore=0 spamscore=0
 malwarescore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508280121
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxMyBTYWx0ZWRfXx7o7tltbpd42
 f+nsP6XFTk7CBCMpHQkuWIToo0nhJJQY65f+/yQdbXLq9YDKrJV8ie7OUtkwB3sVKCRJ7XTPvrU
 X0z5g1KawbVSgptNFi/zx4vete0O/sGKQue2T2BppYRp3CAUMHykCWDsihPFAUZFsd7Kh8eosPV
 Wtp1R6kWjP8Zl7YRUIINFnAgPbp99hcbdJVXQCfxRwi2NjhOP0ORUtyI6bwlyhK0Bre2xyk7MwL
 ijGHYAdMXoxmHuLRWvoZnFK0tCOAlb9QnwDhGvED94yLf6H+ByHHE8M8EUR2+7zsJuopVvnDcuo
 lNH6EK+AQwYMxJ2fIx0BGzL5luGzkG2hHFEL1vQ7kHxCsvfg4zexVw/4n15P1A+TVusVBZpGqja
 Pcyns+2sKmeSsdCsb60SUTMA9Md3Nw==
X-Proofpoint-ORIG-GUID: i2yGBj8ahjgvWWiB2BnmajodtLdOpqfe
X-Authority-Analysis: v=2.4 cv=RqfFLDmK c=1 sm=1 tr=0 ts=68b06728 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=UGG5zPGqAAAA:8
 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8 a=1CnO9tvJ3YM9nC-8erkA:9 a=CjuIK1q_8ugA:10
 a=17ibUXfGiVyGqR_YBevW:22 cc=ntf awl=host:13602
X-Proofpoint-GUID: i2yGBj8ahjgvWWiB2BnmajodtLdOpqfe
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=he5bWClL;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Urbu8g9q;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Reply-To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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

On Thu, Aug 28, 2025 at 12:01:09AM +0200, David Hildenbrand wrote:
> It's no longer user-selectable (and the default was already "y"), so
> let's just drop it.
>
> It was never really relevant to the wireguard selftests either way.
>
> Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>
> Cc: Shuah Khan <shuah@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  tools/testing/selftests/wireguard/qemu/kernel.config | 1 -
>  1 file changed, 1 deletion(-)
>
> diff --git a/tools/testing/selftests/wireguard/qemu/kernel.config b/tools/testing/selftests/wireguard/qemu/kernel.config
> index 0a5381717e9f4..1149289f4b30f 100644
> --- a/tools/testing/selftests/wireguard/qemu/kernel.config
> +++ b/tools/testing/selftests/wireguard/qemu/kernel.config
> @@ -48,7 +48,6 @@ CONFIG_JUMP_LABEL=y
>  CONFIG_FUTEX=y
>  CONFIG_SHMEM=y
>  CONFIG_SLUB=y
> -CONFIG_SPARSEMEM_VMEMMAP=y
>  CONFIG_SMP=y
>  CONFIG_SCHED_SMT=y
>  CONFIG_SCHED_MC=y
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/544d9592-403d-4b4b-b00f-250acb593c1b%40lucifer.local.
