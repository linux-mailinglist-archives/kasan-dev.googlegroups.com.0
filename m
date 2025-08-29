Return-Path: <kasan-dev+bncBD6LBUWO5UMBBXPZY3CQMGQE643WJKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F2E7B3BE3A
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 16:44:48 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3ed39b8563csf49305875ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 07:44:48 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756478687; cv=pass;
        d=google.com; s=arc-20240605;
        b=PUekeudq5bH0FjFFpnA7xlXMM2EGoBLpMB+K51vFR80TpI8FuXiI4sh2K64+2Mai3H
         717wlgGS2cp9hYmK4713aJR0d/VsGVfn6OnMx/Q7xFvOKIt7Ivf96FiBzTU4Q0wI8uJM
         qbRsz/Cc+D1kZM//0UTUxsafHhgOBKAWxQjPaeGximfXua82Wx27eYrbZ1J4tXDSGOVk
         ek8nmsdlfOrza5I0EOjGyeoGdx6Ycue1Y/HYTUQctlg/q7zMxJN3m4Maf7gpR2p2kRyQ
         Fli2PSvTWEL60iuUbLrxSxKJX9MbhA4i98/T6Bacd+6mhZoEaDPkh9911I1IRmxUs/yt
         GvPQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ZHXbuz0Vc+scLVys8duP5xsM11zpFVtH2qDvvVxk2QI=;
        fh=1cvUaHHwwUW8DICdyK+hiqLyWJjDxVb0NSkgDW2QUt4=;
        b=ib6QVfrlITlxRMh9mHZBZrUcgH17ul09QmhCYEx8SVOB1aQjlfArN0ORHkIDp0cE+p
         UMiOUc63mcwApPNiqnKc6x5LUlbySf/M+nXgSpvUJNetkJ3o98a0QvdNgGZDvJbwCXj5
         Htkf6Siy9Un3HVDQQFu4YEBV2hphTWgmSyuGDi6lN7pXagK9rW9KQXCd8gQzkZ3fFv6h
         uzenKWadGft3oQJK5PPLFPdbPbMIYqSOHVJZ1MASfw6rT1xf1L5R42zoXEZiXRIKUB8F
         uX9kDTAL0vB6f/k9Ql84rJRBtR0zN/HpDl0rX948W2QoeQvFfK063X/AiI5reO05O3Xt
         9ofQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="bLW/tg/5";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=nsWAJNdn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756478687; x=1757083487; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZHXbuz0Vc+scLVys8duP5xsM11zpFVtH2qDvvVxk2QI=;
        b=sH3e51W0MkXo0QzyxT2Z3m9Tc+FLRDQq58A+cKLHsivxrRqhH1L10h4XiL6wJKGQpL
         8FMalnLfkC6+5g73SDRA9VUQGhTt53F91UbMd8AUDBBYb/VeH8PXZNsVMRppEEqH3gV+
         2CP91Aca17u5QcX8L6OmmUPX6EKmdwI0pzBbrRdrmMmr8LM7M4B6vTYvb8Y4hyi1En5g
         rekcYKtS0d80bRXbrm5jygKKyeoOTA0ifi+3+rMRzgosrmT3gsaHVNlklLOFZ6mqxZ7u
         iC/r0ar/AKrZ/0LXdrB+StRb3z544d35x+HoAqFV4o8PkYXGcxdP9SMH9Uk6oYZ0IuBz
         8vtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756478687; x=1757083487;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZHXbuz0Vc+scLVys8duP5xsM11zpFVtH2qDvvVxk2QI=;
        b=J0UIJxq9ZYGSKXLo7nuLIMHZtbOH+OzYdSw9f5OAWrQR8pCDj7Nka65XadE5OUVsQM
         gMpuZ62zkXFEcwJZQfw5d8mUkyFpXtpP0VCYgEnS8A32D2Z0xF4AYGPFoY1RSEKQ5DDY
         exl1yEkJ5hvyTiN7pfs0nGonmhrFfe7P2kI+H/BXOT0mTm3D6dN1JjNQKuqOdMipQjLH
         RAq8AUiTP13C2hWA4rNGFUR6SH4WBWnffQhCaArHRcMAHhmFQiSNzpEGEfv7DaQZb4yq
         mvqGNAqwNQrrk7QLdxJLCd8S0sJZR79tyvCAjVmab03qis/sg4b6JRaNUZxg4jfWYXZt
         Jkug==
X-Forwarded-Encrypted: i=3; AJvYcCWTjgZAZOlTRMB0N1YSNwzZFmmKOZurU6XhTQG69BWvDX/MBlMK9jLeJS+Wzn/wS0NOvAcjig==@lfdr.de
X-Gm-Message-State: AOJu0YxvpbXRDgfiCWk54jzFZKG7rrKCeNE5jAH/G4nBPj2En3xfweXP
	7gTlb+l1MyWIDiuhc4ztTJQmlBPSYse1mRSjdDFG6T/smftUOPhpPEZf
X-Google-Smtp-Source: AGHT+IGujRtVy+SB0+LOafkNnFC+zEFtEm9fxcauAy84dkfCjKDQ2tNWuQfgrV9C0/VLOv/R7n0PbA==
X-Received: by 2002:a05:6e02:2165:b0:3f3:180b:cfd7 with SMTP id e9e14a558f8ab-3f3180bd2acmr34406505ab.15.1756478685826;
        Fri, 29 Aug 2025 07:44:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcTnaA9RUeoEETNKbvOT+/yPwPPr4hGPsv2sshOKibcRQ==
Received: by 2002:a05:6e02:1546:b0:3e2:b055:6934 with SMTP id
 e9e14a558f8ab-3f13bb1e949ls19099005ab.2.-pod-prod-01-us; Fri, 29 Aug 2025
 07:44:45 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXpyErnYlTTVvBAin17MPc1VND71DoqxacKRoxnBUlGjrLjRiSR5xTxe90ePmuzaGpICQ0kuJrMMUU=@googlegroups.com
X-Received: by 2002:a05:6e02:2589:b0:3ed:6502:abc5 with SMTP id e9e14a558f8ab-3ed6502af4fmr204395005ab.21.1756478684941;
        Fri, 29 Aug 2025 07:44:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756478684; cv=pass;
        d=google.com; s=arc-20240605;
        b=FK3piTWYJlnAwO6YW360ffwaTiF2AhdQGpGj2+jumFR3M5YIEiVgr1WN2sRktyZlwd
         vD60z0FIidoyJRLcWEhy5sdJiaMdUDSZaj4R2Yv1hMzLk8m5zAvZs4mMC6iSAGsGQG10
         IawFq/dBSQRI3qA8ixt/KINIApQU3PhTyi4+MZ/JyIBW+Q1rmAXZmytHBEvHlqAod+kR
         y2lVvyID4eqxndlDcaWfiGVs/agJmqYeDB1Eo+68q0FDJAtVhlMJ4yAectG5dt7nm75P
         jov1phdf+OOazWyl3BaYqlmGZe7KEBLlm5F+EBZVpOovIN9ZFLfawVudNTZpPnLF64K+
         QOxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=uj6OrTQ4wFKg/KfhJ35mUWIkNj3n6F0HN0B8kXPqQBQ=;
        fh=+xTNNBOamASgnCRT4K1yFqtdeDwWZrhIqy+ukx7GsME=;
        b=X7g/OQYsCBYQthaiYIywwARQFwCaRJeUlKlOVrgpospKdRJowf53SJGCa+O+uNmkkj
         aAzfnK4UMWA53NR0avsWHDKu5tAEXC8trxZCCTLaHP/ZOUrhcSly6Zy9VN8u1emGE9d4
         CTA56qVpadMN7Xdj16nltqVV6PvOy/bboEnI8ZUOa/oK5IztTk4H6gGe86dx4BOakoTP
         kDNEs4LANhJ+/e0X53ISxsnsUlo8Vet9IOgFXFnISDon3eNpHSDTzhlQiTdsHyo6yC0m
         HeX7cSzLprSsL5a9XRD+Ktk3m+WbZTXjjF22MbQWa6oLl6+rh8IhxY4EowCaq/l0SAJB
         cxjA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="bLW/tg/5";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=nsWAJNdn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50d7be499c5si75312173.2.2025.08.29.07.44.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Aug 2025 07:44:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57TCtjuI000564;
	Fri, 29 Aug 2025 14:44:38 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q42tagk3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 14:44:37 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57TEOUMA018987;
	Fri, 29 Aug 2025 14:44:36 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12on2071.outbound.protection.outlook.com [40.107.244.71])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43daega-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 14:44:36 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RQCdrQQwOnTAyrPIqbHuLX5uC+vb0GYql/MmHIVeGshboHuF/kOU5UGOon0EHa2ORn71JSgEqqmWzWhy2orIOcXHCIeLWFU4ZLGHBIbonBoaDc3MAsPQvUKfGikpQtiMLYnuK4whwmx+Rr7B8IT+tM4pVgJZA3eNlmy6OEKIUKAd4SQdsU2JYrx/l4vAIq5OvhlPUkS3Vny6PSLCmAXBG1h7HH9KQp/f/8+awuGqhS2Yqynmm3pBtfJOFtAX9mZR6kAUVTgHfjmvYlunmHO2iR/JM9coMDh6VFtk3sCj6HP7cqyIwB07hs55vq/zP8xvG24CewiwPaDsHM3TqXuU4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=uj6OrTQ4wFKg/KfhJ35mUWIkNj3n6F0HN0B8kXPqQBQ=;
 b=iXg2ympZu9SoXjAX5N368DtlOKTfpoMDNQeqVhwCi2nambXVVSKJbhoW6wbcUO97R6qgWLfbTbbpHFaQSTKB9Ev10JslAdDfIAS0lvkfyGnKuJsl6ATY2m27xafP5zxKadDUpgZazmFY67+21kLbzkIqtpm4XI+HbZbj8MCS5XQffG79T3UexvTKALuQOXRMYgnicDUFpkyS6UmToiJ4QZgZzVdP/lA1CWTouT3xthpLTp4AB4l9qafjj3tRYcKePZLD3SbaHIv1xNrA7/pgBLfrg6DY4sj3GiFxuYtEklrLk0QSVhXsUeGUsi9RY+K/RARuxjPP278sEpNHebw/WQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH2PR10MB4165.namprd10.prod.outlook.com (2603:10b6:610:a5::24) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.21; Fri, 29 Aug
 2025 14:44:28 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 14:44:28 +0000
Date: Fri, 29 Aug 2025 15:44:26 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexandru Elisei <alexandru.elisei@arm.com>,
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
        Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
        Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
        Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
        Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 21/36] mm/cma: refuse handing out non-contiguous page
 ranges
Message-ID: <ae9412bc-45ee-4520-b9df-65b8faa52e8d@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-22-david@redhat.com>
 <b772a0c0-6e09-4fa4-a113-fe5adf9c7fe0@lucifer.local>
 <62fad23f-e8dc-4fd5-a82f-6419376465b5@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <62fad23f-e8dc-4fd5-a82f-6419376465b5@redhat.com>
X-ClientProxiedBy: LO4P123CA0592.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:295::9) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH2PR10MB4165:EE_
X-MS-Office365-Filtering-Correlation-Id: c01110e5-ea76-4b8a-d69f-08dde70a8e7e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?UrOVPkfOUX85RY6jlwECgHuENImuF+KSddRu/GH51kVMeGb30YpU/iRN6tym?=
 =?us-ascii?Q?DwqRfrxunw3itb0nxFf79DsSY+j/tjPPv+6AT4w0fyNH7Lt1Jbtb/HUc6cKf?=
 =?us-ascii?Q?VXxhwUubq0JV4vXzeg3OPic2WvMQMe7oyez00cfrhJQHBgePGZn8nQfS8v+L?=
 =?us-ascii?Q?bK8rwBC/mgD4hN8Upq2wVTWfRIXZlRv+paMdT50ClIVLOj3i0FltLwBL+buC?=
 =?us-ascii?Q?AFpuPMKoScpMJ9qYtk0peda91YZskZ/sb3uDmedM4sNLnipODbAaSTMXMDIu?=
 =?us-ascii?Q?t4l8c+KTEwOQfC1gqQOBmoREobtwU/RBa8Ymv8Qx440KFndkLB5EJI86M4vK?=
 =?us-ascii?Q?/+ojfKQNVFd5Y4162XmKW5T8tW0boz6rlCmWaewD+JaJs7GFcLtjmZbWHYIj?=
 =?us-ascii?Q?pyjbcOdMh2Xx3eiBN0iNVdTkwhC0+TvfGBsxc2slMu643fTo4xxywgBh+jBK?=
 =?us-ascii?Q?M9FP2Bk94qrQHYYHZPDZY+WK+AdMNXPz9Q+wdeubym1d765vEcxaABWobFvC?=
 =?us-ascii?Q?o0M6SjyyH1+MYOxwIEs114Nv34/D8O4FwZxVI4C8RhnehuDI61JJGixpPIF4?=
 =?us-ascii?Q?S5dN09bUWmA6qNS7tDul6En/U8Ed9pW7vitrDB2dkhP+mivXUsrB/HtSSzem?=
 =?us-ascii?Q?ClgO/s3kvwOrEGhdQz0piWKDcg3K5+f1LorvvdO8qGj/WGHZAZCR5ddbXdiC?=
 =?us-ascii?Q?zcWdUPpWoAhM7NI/48yxzCufH2LhzYZTsO3TxgV6s5jKrp1UN5UQip13QrYJ?=
 =?us-ascii?Q?tBMd86ARRb0lrNGl2DWtRsO9WRarkLKCVgytX+6XDOzkpZXAfPm/3ubpJ1IP?=
 =?us-ascii?Q?ykeHdWDTY8CRHEbgFs3sdDxYJdSYpFI0zJv5wPD+D2GKkDjEy5gGaUeH4jef?=
 =?us-ascii?Q?70jP1p6EIPmoQwNNy1XN/t0WgvaMAYChJgGgDk3qZ9FitV610Mk8QgmViOLF?=
 =?us-ascii?Q?uGRdQZNaJ0qdGinQdIfzL4/Po4tgFpXn956pYasXNXwX0Z+d6YSbXLf4/Nwh?=
 =?us-ascii?Q?Z5kfjJiQ6GSGM6kcwlET5109t0iKIUEEiuM9QtcMI9mKhsyk9SsyDKWqxLX8?=
 =?us-ascii?Q?ua0GpP59HG/MQrTf4fGJoWZzRm7t/GJgNXTALObkMHU75tQ/+GybmiS6pxA0?=
 =?us-ascii?Q?P8o8xachwSrKTwveUt9YCXi7Gm/ADpZ3TV/W6JmM/zVgS/vaW4mbQmrIqjt6?=
 =?us-ascii?Q?IPp8xmnIjyl0XXV5/TcOKfKM1Dg/IcbCzO7O6RxskUFanUCYNqy6E3tJlhz0?=
 =?us-ascii?Q?2U/E8X++a6gI7N+L+cknvYmAJdOqzpavkJncaJT5t8GxVAtW2NX1ZrXCdWVn?=
 =?us-ascii?Q?SF5+zCQjvJD7z/WL1qiwx0sCCmk/NsJwkCtB8CAqMzF6Ulwh8UmAsqh91wTw?=
 =?us-ascii?Q?e5CY17zlIEyTFcya4F0jNyhp8kcC7Zs87FHln3Pp0R2aiQi6sQ=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?P87gTrNvlF5s20yRVu8Mrwcfc89ASoAAskTalSNuWSXlDszHMSSZNQ2+9Vft?=
 =?us-ascii?Q?LA6+dR1j4/0BvEZdJdItrCtC9ilrzzghXoOYjK/I1FxC+QU/hCu6kcP1r+0X?=
 =?us-ascii?Q?rpWvRa+eWdHTepfpVq3GkT7eo2yL74ntiDekLiNNCObuWi8XPZWULtz4mO6h?=
 =?us-ascii?Q?pFny2S+kbytRj+zfJyIOktUWgfjbrevVWxo6up/1sCzjGw3AS0lYDIYZwJaw?=
 =?us-ascii?Q?IEVehaT7I2WVl0UhAtJey9i2UOgsekJ+QP81ppGIpxIl/lkk3yOUMSOR08u1?=
 =?us-ascii?Q?gy/zzDRVTc5R4J+5CJK8MAbYmOPyrfiwVIS7A6C/V179pigOxs+Kam6w8edc?=
 =?us-ascii?Q?Pnna6VWF2DF7W8ihGBINelC8Aua5tAz/WX5Q9ThgGX5HnJu7guaUou6l8eGb?=
 =?us-ascii?Q?nK2TLCyde5UBTpmlERcQlQPiYZhA3PwJs9SdepTlJOzyfmg4aOjqHKCr7zR5?=
 =?us-ascii?Q?8lVfNQD+OZL2TWENch3UUsLGw84t8EA4SdhaHNxJzQRjnlIL1aWsslXKq244?=
 =?us-ascii?Q?bz2EjQa3xHHMukHduIKVMGeQTgIohpWqiPKLYwXhoHrIO+IgCtfcSR8dLkVv?=
 =?us-ascii?Q?Afnv2Fii+Jm+B3srZCeC9el50cB8oNfo+ivjPgf3sjP4WVUK4PIw0We4BluB?=
 =?us-ascii?Q?jzfpPq75kbIdR9I2x8ygQKFArcLxDGKFBS1wXcESYWlMf7Aw4VLtGMz3jHAw?=
 =?us-ascii?Q?6EcKiFJq/itKtIGfwCayAI0ea5RAkJGqGpVqWhU/APNkCn02jTiYGv1MkXbZ?=
 =?us-ascii?Q?xwEw1IlzaDdRlK4JMnB6XVphsbibSZPwgXKzQBiFTaSRkqrWtkwNiMXdBF5Z?=
 =?us-ascii?Q?Wp+m8qZjZTF6WHI37Q7MPuH0/A4Yf65QMxCksa+uj2bwi1qX7PgZUAtFioK6?=
 =?us-ascii?Q?lEEr7+ohD3SSmyNP+eznn9yAj4rHsJtBsbPuqrxbk8WfSItPFltxtDzvQmWY?=
 =?us-ascii?Q?hNF/IdV4Icp6gfC10YjhsaGbPS7K2uLDLNZyOOGccKKUCXbqs2zdkWzvwRxx?=
 =?us-ascii?Q?r76ZzwMOhGbIHEQ0bJ+9ABpVMZkP8UH5fCSfxbG6HVnvTf6tZkCfTYp93RRS?=
 =?us-ascii?Q?AgQW30Y1ne8HpOt4ytTzhSZPOFaYcStyehuCvZeYU/U0GqZzw+f1TrRJnoeG?=
 =?us-ascii?Q?4woCOt2xiYa3P3hunehcJqL2qGaSsCW6KwLtBusDF1ODNpUcsZEJYB17NtCP?=
 =?us-ascii?Q?oTV48ydCoS+ZWcroeDUw5VLFJQyxiF6m2wHvxls9H9iPddS78ilw9nz1Mu75?=
 =?us-ascii?Q?Acu1aMQ2858cqxAiugXkVhVex3wCfa1nSFniywJq5mSyE7f4u4BkBPdE95aB?=
 =?us-ascii?Q?mGhBqJRc69p61KLaPxsfVIhiOTymxuGLvPcq/c9i+lwF6PySZ+DZtsYDMigU?=
 =?us-ascii?Q?Ic8rOktiLanuNyVJSIR7hNiFUTd+tIhkrxmYm4rhEfdrab1nWI/Hpf/841Rj?=
 =?us-ascii?Q?qg7pGeN3gdFECV/cvkMygsmGteNjuLFIZg3+KEEmidsa1AM2Zz/g51Q846er?=
 =?us-ascii?Q?Jt4wym+iU1l81uB9NZ8kEzZfeH/L3wAJgre++rVvY/HIP1s1FclZdieEWz48?=
 =?us-ascii?Q?jN/oMnM5dQpFVil6Z6vUEv5HWULowlcHH9jU85jtJHLxbMK5yX1+4EpotxMs?=
 =?us-ascii?Q?2Q=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: 5Tdm8it+V+HExrkNXFnEPZ6fgStCuDlM9BkM5oTWwVzh8Z0zbThMKl/aRx2ZmuS63UNHfP3sPRobOgYLP59CF7TA6eAaa1g3wtyFW9KC7S6TVwujojerGnSiaUZna9FxvsCsw/IFHqS8Kxc0tYnTHT4cREyUy4t/JoX+RV/s2UvArURgMnpp7PB48v6b1lHsj98LgNIM01q19xVkyXvjsxsS+PBYJLEk9Q3V3l/FpfBzlk9L4Knb8nRgaWIfKFINcaQnmrjYl+Qx38r+Acagrpz5cvMajCI19JucLJh1f6BCF5pJ/Lifr0IbjT2xUyoiFWD9V4FdHYyEQ2BqtEw7dZLvpDQ7OcrMMTf/pj9D7UDyfihmlweF/jW4zXGa4OKSf1skC53gC6u5bH8A9da9l3LxPcxy9tdRvutVexnBHs7QjwuBiHlUJiqdPlUP2xFORUIh6A7QIKRIihJ3Ikyuklyf2HjvXSmO7Onp9IULETCAB4IZAXaya7cA749hudauhIR/HHRP4NlYiEKkKuk8ra/FNWIcVK16C3fO6DuTUtSgi7zRvUpk6ho0r+2FhhFJJRX7yjgjnn4cn+/4Gi2bEALOmJ9rpsCDlw93USptlCE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c01110e5-ea76-4b8a-d69f-08dde70a8e7e
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 14:44:28.4559
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: X869oi7uS8ygclHf8mvm0vZD6rd3qLq8zsSv4yFRjWc5uOfp+vc3YnK0PYvtMk4nAh+pKG+VXQ0RP4dt2rBmhYtb29rfdY30O18WqD4VPCY=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH2PR10MB4165
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-29_05,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 suspectscore=0
 mlxscore=0 phishscore=0 bulkscore=0 malwarescore=0 spamscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290124
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAxMyBTYWx0ZWRfX+Mcc/l27mv7u
 PiGIObLxzSX1s0utr5DmZwkqh8NixBA0RqNVzTAI20r62gLumVGE4iGVsnRXiowQMOl9/kZ7Fmx
 8LkCqyT2uLooP1WBhQm5GzESwJ4d0oJB8CHnyvDAUbipbU00gJHsuqhS7B/mhXrm7qb43zpPGo9
 8FeOjTCIM0oqp7YK2FEVRT8OBqrZDc541QWc1R9Qxe8PF9cwD46a52ALzorv16o/9f13zlHlyUb
 5FoOr284AmbLTMg0rj0fjVH/RyiHqdIgC7jqkV2MiKxdjMR4kb0Xp3FMrWwLXVl6TXcibfTqKpf
 KrSGxBsmKUGzRGikwppfR6VtTU0zMZ+DsV/mGFtkMPPLy/MTW2WiqdbgkaHSRl4UwhGcFbf+5Mg
 ddfmhVj+
X-Proofpoint-ORIG-GUID: RXNLFA9YcQOdpUaQnmB-t6wQOEulJM3U
X-Authority-Analysis: v=2.4 cv=RqfFLDmK c=1 sm=1 tr=0 ts=68b1bcd5 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=7CQSdrXTAAAA:8 a=20KFwNOVAAAA:8
 a=yPCof4ZbAAAA:8 a=tpO3Aoaa9ue-Jl-dp4cA:9 a=CjuIK1q_8ugA:10
 a=a-qgeE7W1pNrGK8U0ZQC:22
X-Proofpoint-GUID: RXNLFA9YcQOdpUaQnmB-t6wQOEulJM3U
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="bLW/tg/5";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=nsWAJNdn;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Aug 29, 2025 at 04:34:54PM +0200, David Hildenbrand wrote:
> On 28.08.25 19:28, Lorenzo Stoakes wrote:
> > On Thu, Aug 28, 2025 at 12:01:25AM +0200, David Hildenbrand wrote:
> > > Let's disallow handing out PFN ranges with non-contiguous pages, so we
> > > can remove the nth-page usage in __cma_alloc(), and so any callers don't
> > > have to worry about that either when wanting to blindly iterate pages.
> > >
> > > This is really only a problem in configs with SPARSEMEM but without
> > > SPARSEMEM_VMEMMAP, and only when we would cross memory sections in some
> > > cases.
> >
> > I'm guessing this is something that we don't need to worry about in
> > reality?
>
> That my theory yes.

Let's hope correct haha, but seems reasonable.

>
> >
> > >
> > > Will this cause harm? Probably not, because it's mostly 32bit that does
> > > not support SPARSEMEM_VMEMMAP. If this ever becomes a problem we could
> > > look into allocating the memmap for the memory sections spanned by a
> > > single CMA region in one go from memblock.
> > >
> > > Reviewed-by: Alexandru Elisei <alexandru.elisei@arm.com>
> > > Signed-off-by: David Hildenbrand <david@redhat.com>
> >
> > LGTM other than refactoring point below.
> >
> > CMA stuff looks fine afaict after staring at it for a while, on proviso
> > that handing out ranges within the same section is always going to be the
> > case.
> >
> > Anyway overall,
> >
> > LGTM, so:
> >
> > Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> >
> >
> > > ---
> > >   include/linux/mm.h |  6 ++++++
> > >   mm/cma.c           | 39 ++++++++++++++++++++++++---------------
> > >   mm/util.c          | 33 +++++++++++++++++++++++++++++++++
> > >   3 files changed, 63 insertions(+), 15 deletions(-)
> > >
> > > diff --git a/include/linux/mm.h b/include/linux/mm.h
> > > index f6880e3225c5c..2ca1eb2db63ec 100644
> > > --- a/include/linux/mm.h
> > > +++ b/include/linux/mm.h
> > > @@ -209,9 +209,15 @@ extern unsigned long sysctl_user_reserve_kbytes;
> > >   extern unsigned long sysctl_admin_reserve_kbytes;
> > >
> > >   #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> > > +bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
> > >   #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
> > >   #else
> > >   #define nth_page(page,n) ((page) + (n))
> > > +static inline bool page_range_contiguous(const struct page *page,
> > > +		unsigned long nr_pages)
> > > +{
> > > +	return true;
> > > +}
> > >   #endif
> > >
> > >   /* to align the pointer to the (next) page boundary */
> > > diff --git a/mm/cma.c b/mm/cma.c
> > > index e56ec64d0567e..813e6dc7b0954 100644
> > > --- a/mm/cma.c
> > > +++ b/mm/cma.c
> > > @@ -780,10 +780,8 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
> > >   				unsigned long count, unsigned int align,
> > >   				struct page **pagep, gfp_t gfp)
> > >   {
> > > -	unsigned long mask, offset;
> > > -	unsigned long pfn = -1;
> > > -	unsigned long start = 0;
> > >   	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
> > > +	unsigned long start, pfn, mask, offset;
> > >   	int ret = -EBUSY;
> > >   	struct page *page = NULL;
> > >
> > > @@ -795,7 +793,7 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
> > >   	if (bitmap_count > bitmap_maxno)
> > >   		goto out;
> > >
> > > -	for (;;) {
> > > +	for (start = 0; ; start = bitmap_no + mask + 1) {
> > >   		spin_lock_irq(&cma->lock);
> > >   		/*
> > >   		 * If the request is larger than the available number
> > > @@ -812,6 +810,22 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
> > >   			spin_unlock_irq(&cma->lock);
> > >   			break;
> > >   		}
> > > +
> > > +		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
> > > +		page = pfn_to_page(pfn);
> > > +
> > > +		/*
> > > +		 * Do not hand out page ranges that are not contiguous, so
> > > +		 * callers can just iterate the pages without having to worry
> > > +		 * about these corner cases.
> > > +		 */
> > > +		if (!page_range_contiguous(page, count)) {
> > > +			spin_unlock_irq(&cma->lock);
> > > +			pr_warn_ratelimited("%s: %s: skipping incompatible area [0x%lx-0x%lx]",
> > > +					    __func__, cma->name, pfn, pfn + count - 1);
> > > +			continue;
> > > +		}
> > > +
> > >   		bitmap_set(cmr->bitmap, bitmap_no, bitmap_count);
> > >   		cma->available_count -= count;
> > >   		/*
> > > @@ -821,29 +835,24 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
> > >   		 */
> > >   		spin_unlock_irq(&cma->lock);
> > >
> > > -		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
> > >   		mutex_lock(&cma->alloc_mutex);
> > >   		ret = alloc_contig_range(pfn, pfn + count, ACR_FLAGS_CMA, gfp);
> > >   		mutex_unlock(&cma->alloc_mutex);
> > > -		if (ret == 0) {
> > > -			page = pfn_to_page(pfn);
> > > +		if (!ret)
> > >   			break;
> > > -		}
> > >
> > >   		cma_clear_bitmap(cma, cmr, pfn, count);
> > >   		if (ret != -EBUSY)
> > >   			break;
> > >
> > >   		pr_debug("%s(): memory range at pfn 0x%lx %p is busy, retrying\n",
> > > -			 __func__, pfn, pfn_to_page(pfn));
> > > +			 __func__, pfn, page);
> > >
> > > -		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),
> > > -					   count, align);
> > > -		/* try again with a bit different memory target */
> > > -		start = bitmap_no + mask + 1;
> > > +		trace_cma_alloc_busy_retry(cma->name, pfn, page, count, align);
> > >   	}
> > >   out:
> > > -	*pagep = page;
> > > +	if (!ret)
> > > +		*pagep = page;
> > >   	return ret;
> > >   }
> > >
> > > @@ -882,7 +891,7 @@ static struct page *__cma_alloc(struct cma *cma, unsigned long count,
> > >   	 */
> > >   	if (page) {
> > >   		for (i = 0; i < count; i++)
> > > -			page_kasan_tag_reset(nth_page(page, i));
> > > +			page_kasan_tag_reset(page + i);
> > >   	}
> > >
> > >   	if (ret && !(gfp & __GFP_NOWARN)) {
> > > diff --git a/mm/util.c b/mm/util.c
> > > index d235b74f7aff7..0bf349b19b652 100644
> > > --- a/mm/util.c
> > > +++ b/mm/util.c
> > > @@ -1280,4 +1280,37 @@ unsigned int folio_pte_batch(struct folio *folio, pte_t *ptep, pte_t pte,
> > >   {
> > >   	return folio_pte_batch_flags(folio, NULL, ptep, &pte, max_nr, 0);
> > >   }
> > > +
> > > +#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> > > +/**
> > > + * page_range_contiguous - test whether the page range is contiguous
> > > + * @page: the start of the page range.
> > > + * @nr_pages: the number of pages in the range.
> > > + *
> > > + * Test whether the page range is contiguous, such that they can be iterated
> > > + * naively, corresponding to iterating a contiguous PFN range.
> > > + *
> > > + * This function should primarily only be used for debug checks, or when
> > > + * working with page ranges that are not naturally contiguous (e.g., pages
> > > + * within a folio are).
> > > + *
> > > + * Returns true if contiguous, otherwise false.
> > > + */
> > > +bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
> > > +{
> > > +	const unsigned long start_pfn = page_to_pfn(page);
> > > +	const unsigned long end_pfn = start_pfn + nr_pages;
> > > +	unsigned long pfn;
> > > +
> > > +	/*
> > > +	 * The memmap is allocated per memory section. We need to check
> > > +	 * each involved memory section once.
> > > +	 */
> > > +	for (pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
> > > +	     pfn < end_pfn; pfn += PAGES_PER_SECTION)
> > > +		if (unlikely(page + (pfn - start_pfn) != pfn_to_page(pfn)))
> > > +			return false;
> >
> > I find this pretty confusing, my test for this is how many times I have to read
> > the code to understand what it's doing :)
> >
> > So we have something like:
> >
> >    (pfn of page)
> >     start_pfn        pfn = align UP
> >          |                 |
> >          v                 v
> >   |         section        |
> >          <----------------->
> >            pfn - start_pfn
> >
> > Then check page + (pfn - start_pfn) == pfn_to_page(pfn)
> >
> > And loop such that:
> >
> >    (pfn of page)
> >     start_pfn                                      pfn
> >          |                                          |
> >          v                                          v
> >   |         section        |         section        |
> >          <------------------------------------------>
> >                          pfn - start_pfn
> >
> > Again check page + (pfn - start_pfn) == pfn_to_page(pfn)
> >
> > And so on.
> >
> > So the logic looks good, but it's just... that took me a hot second to
> > parse :)
> >
> > I think a few simple fixups
> >
> > bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
> > {
> > 	const unsigned long start_pfn = page_to_pfn(page);
> > 	const unsigned long end_pfn = start_pfn + nr_pages;
> > 	/* The PFN of the start of the next section. */
> > 	unsigned long pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
> > 	/* The page we'd expected to see if the range were contiguous. */
> > 	struct page *expected = page + (pfn - start_pfn);
> >
> > 	/*
> > 	 * The memmap is allocated per memory section. We need to check
> > 	 * each involved memory section once.
> > 	 */
> > 	for (; pfn < end_pfn; pfn += PAGES_PER_SECTION, expected += PAGES_PER_SECTION)
> > 		if (unlikely(expected != pfn_to_page(pfn)))
> > 			return false;
> > 	return true;
> > }
> >
>
> Hm, I prefer my variant, especially where the pfn is calculated in the for loop. Likely a
> matter of personal taste.

Sure this is always a factor in code :)

>
> But I can see why skipping the first section might be a surprise when not
> having the semantics of ALIGN() in the cache.

Yup!

>
> So I'll add the following on top:
>
> diff --git a/mm/util.c b/mm/util.c
> index 0bf349b19b652..fbdb73aaf35fe 100644
> --- a/mm/util.c
> +++ b/mm/util.c
> @@ -1303,8 +1303,10 @@ bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
>         unsigned long pfn;
>         /*
> -        * The memmap is allocated per memory section. We need to check
> -        * each involved memory section once.
> +        * The memmap is allocated per memory section, so no need to check
> +        * within the first section. However, we need to check each other
> +        * spanned memory section once, making sure the first page in a
> +        * section could similarly be reached by just iterating pages.
>          */
>         for (pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
>              pfn < end_pfn; pfn += PAGES_PER_SECTION)

Cool this helps clarify things, that'll do fine!

>
> Thanks!
>
> --
> Cheers
>
> David / dhildenb
>
>

Cheers, Lorenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ae9412bc-45ee-4520-b9df-65b8faa52e8d%40lucifer.local.
