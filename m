Return-Path: <kasan-dev+bncBD6LBUWO5UMBBJNSYLCQMGQEGFII62A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id C9893B3A92B
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 20:00:06 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-77057266d0bsf1771973b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 11:00:06 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756404005; cv=pass;
        d=google.com; s=arc-20240605;
        b=TJy3moTgna0W8iUn9wfWun55jir2FS2EbZJiEJqn69gO/Tso/VzUOiC42U2Y4Ynoy0
         1dtJJ1KLSq7lmiW1WhgPFz89H3m9ZEJXdA3tq59QiY/eGIQB6tRcHhsWW3ghmaAh5fFI
         BrBTsSbGHD4slcjJ3HLAg03sr9cQxmoVvoiczgLWm2uZTIhQoI2xi3KAR3oPGg0malLR
         OeXdXCBJ4w5NnMgBgVDKoSjWD4kKkWM6fZaaIjY6NJ/GCAH/5HUKpssrCbsN1C4J1sqb
         7P5J0ojY077hH2lVEodGfyHuHG4/2pBG4ikNhoybnNFZjw4bWad9HrFq8HqQai26ah5J
         dWyw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=+gyWoOoB9XEl1LB31gfG+aXT/vM002ssZTIk48onrTY=;
        fh=eU6es3OoM4njh5MAoLoxWkVRgo7BVpFTqzPYXm53Lvs=;
        b=d7aZHj5rZFWjTms31rtkp4SXMrXh14xtw7CT37Xl4mHC25kptYPw0AGtnOVaQ6sC9S
         BxeZ/jowRhe6qpHjsDZwQHHcABYEJ4dGj+9+NxfSgMzHFDNXlCjreHK4sqbFvdtBYGU8
         JT3wtt0rRg+yBer3kg/tlfngA7HCaeQmQwBJmHDlI6t9Vz/tC+BwtcCBhlp1+3SSkMKX
         niurkjH+PZ3GIBpSN0P5eXo2QknQa8ZjX7oJUb+jNdVV41gbmnZ1mv3G5AQGPRcD85GH
         IkMu65gZIoj30SXIi4ftzSp1UHUvsrSzFE1KO3QaUF/p+kzLBZQ6QM6+sO/fndrcGEGf
         bsBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=UPGdT7nH;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=c36bSQNu;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756404005; x=1757008805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=+gyWoOoB9XEl1LB31gfG+aXT/vM002ssZTIk48onrTY=;
        b=ifiNj7pGkQHbCE0YEGrsxq3TSoFCoqckVqIRDSWlfbLJR/asLM5apLMNS1d2TPvprf
         jauYAfgi9nQl+dRuZrYJXxHMwJW16JhcNmBlJAqgDJTV1QVygMro+IeE1Ft3djR2FAI6
         VZL81c+pgnSY5511y4UM5LpmXVuIvfVFwQ+GRXM9hGFnaMACsQI0pTMZ2JUXF33TN9Kd
         cDn8howtL8CRMExnF9t8TX3Vjk2Bg/od6PAa/6ndpcKX1Gb8EediBZ3/iukdLFhtbk2y
         v51F7T8wsUSuPERorn3N/12vSM4LDrGCm7Jyy0IQWn+PEI5un2nVSUhm1//WZglkFXwy
         106A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756404005; x=1757008805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+gyWoOoB9XEl1LB31gfG+aXT/vM002ssZTIk48onrTY=;
        b=oqfybtO3UbcM5kqrZmNHbCv0r8fDNxHEuvLsWYS/mguRE/GpPUoUm+HR2U7h2pDFJM
         VXM+Le4/VIkuI0XTnc5Pgsai/gznTiAhZZu9rAo4g1aJTdxmd6OML5E7gdHZrN3g9F8g
         2rkTOa4hias5rI46LV317weXcpaX9Pp+j2AP0hTKutu4lMfV9WOeMLchke9LvLDuxMdZ
         0DTPt0tbXxeMtz7yLQOETk4S8Bb/AY2W2NqfcsMbsNww/T6+x5YOhl7bWaBz8Sp5wnzS
         6lYLQm39rygOIRodVdHmcxTgI4W7IFlMo2iNwQTR6zsHcyhrH5PulprAwsnDGojhiYA5
         gPKA==
X-Forwarded-Encrypted: i=3; AJvYcCWpBKhJqSmneryCMymHgsfYHUNqWtbDg9qkLY/e3oDWFWC8eiGqsPQa0TRNC4ouW697KTfwow==@lfdr.de
X-Gm-Message-State: AOJu0YyMC0ZbPh9B9KhSkkgO5fuuqLmbvYQY57WEqZyBOAfxp1KGbBDO
	H0ygTXYZ16Hlj1WLyXmo/mXI5bb89pK2Dn76GUg/HwHFLsXiP7gk9odx
X-Google-Smtp-Source: AGHT+IFgTVvnNMxPmMC2eU9xWlf4Y8e8+CjgPvZ3X9pcnO/NP5aJCaC2UapkLzqn5FZQ20NwIRpUCQ==
X-Received: by 2002:a05:6a00:bd12:b0:748:2ff7:5e22 with SMTP id d2e1a72fcca58-7702fa057b7mr24710194b3a.10.1756404005255;
        Thu, 28 Aug 2025 11:00:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe9pBZ3EprkBi1t+sLXblk3oAspdhUt97xG9koe2kebgQ==
Received: by 2002:a05:6a00:21cd:b0:771:f2f4:173c with SMTP id
 d2e1a72fcca58-772181e0550ls1141267b3a.1.-pod-prod-06-us; Thu, 28 Aug 2025
 11:00:04 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWg7jTlPbIQhkiBJ5Z/CqhtNaqneWiX4kxpOhx2cZK/mI0V7OUnrpOAlL3mDe414D3bbs38Cf0IROY=@googlegroups.com
X-Received: by 2002:a05:6a21:3181:b0:243:71a8:85c1 with SMTP id adf61e73a8af0-24371a8953fmr20945676637.11.1756404003838;
        Thu, 28 Aug 2025 11:00:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756404003; cv=pass;
        d=google.com; s=arc-20240605;
        b=ObgkhV36V/KkGZHx2t0urn4f/y2yd5mglOutJweUdNkscYhfJkokRGZs50JXE2extH
         vd+OucFjYB17e7enpz7kXfsLsGvjkXnIHb6Tg/eK5rRWTnVZmiUw7u3KIqBXblcITwlB
         S9VTLLjTAsaVuK+HpCgONyYPzdZWkkX5+rjqDrgKMZDs+NuKI2yOThFVRFZ+gdO7bTf+
         aMu4dzCm/YtaB4lcxrDJykEydYl6b7RzP8qn8JmplFkZLcXVf0M3Bq1Q2mPBsGbaNv4v
         6F3xTirguefGQfY04GBnoJ8zEeQ0h7sVq0cznV6i0kTu3xm5pTk3+nMUv7ixCXCOrXgL
         hy7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=qQzUElC6pCUB3XbLm2x+LA+4L6Azg/Rd2vAT4sjIF9s=;
        fh=xucJAPuOgj+g8zGV5mH6iUgMBTQXAngNoCa//9jm33w=;
        b=Hl15C2Yw5R5q51IEZZFEz+wh5jQmAwKjARHZenwSOKU/Yl7Hmkq9rz9BEPgCefdAey
         mIN/fBuTuIibGkdmxLraApq+eeBQDy1Pbp2+VysP1DlqLE5H3lO45+CMl1I806jey48o
         OPmDPekJR8mF6pnUU8RmRm7pVSg16iRWPZjji+Y+44lkgkT/F3nizzcitVC/E6wmziOZ
         kIjo35uKELVKsimusqR/Z2fC2SxoAxrA3fELV5009C27dH8ppUqAfKtztnzmYaUluMnc
         HBDPnGOG7tam5zW3yIakUru05/8dvSrwRyVQ50XbHvBCqEwQIgV9LG/bBeyRIPBiQl4c
         snNw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=UPGdT7nH;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=c36bSQNu;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-327d1ddee9esi38151a91.1.2025.08.28.11.00.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 11:00:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHMwRk023482;
	Thu, 28 Aug 2025 17:59:56 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q5pt98jn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:59:56 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHLApm012211;
	Thu, 28 Aug 2025 17:59:55 GMT
Received: from nam12-mw2-obe.outbound.protection.outlook.com (mail-mw2nam12on2051.outbound.protection.outlook.com [40.107.244.51])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c6e6x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 17:59:55 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=et9HlDmq5eBqpM42b+e64ZZVEnkUlbSLJlt65KYRLoaguEp+DrOM+BYuetBC37wHj9puXd9nXr6BfW42saAZOZdWHSmN05BL9FLVbItg1P1wtxqKfYFdMbFkCDBZRfC6MXtX/+4yx+Gan29UYrd8TcP7/gJCETLLu6lHM+raHj4STpK/ZYKE69ZY0frbm9dJp+PUTw2Nz6twoZ4F6KRFQTWR1Xxp+Dls3kUI07m+mBX3NGgJFdPm8+dFlTC7XlIXJ/4HjX0qdOso7s8Py2rqVmP5b/wwr8oismc2lSHquE7aQeVzC5Xttf0pgwoesquCceUEflWlZn9eLOB3GY0EYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qQzUElC6pCUB3XbLm2x+LA+4L6Azg/Rd2vAT4sjIF9s=;
 b=TfPAZigmEo2vS7nwDN4EWnKbSZlxY6X9Xs1+/XkPsTwYAzDKeo6i5W4ra3S4DAITTLmAtHZdPvFGZ0lGh1HfrHfNgKoZarh8EihNQSJrEUO7NsqJyAT8clxCTYLxXYK0c6dzLVrV1JouidyWCWZHjBHjGpgEpnzKo/oTHt4td9SB0/zdw32w81b6/sUloqiGnPu7wruMyrHAaIswFIDQpTb5/JaThM/ZOCfrlBRGlhUuNCmn+B58yMADhzShxDmyI6k9l4P/MJj3Xsdo63r0/TVtDVkFqSJiLa+D8TTCmbOaqXYH0xR0KzCTnD3R0c5vW+05bmv2KD43hQUhhUU3qw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH0PR10MB5147.namprd10.prod.outlook.com (2603:10b6:610:c2::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 17:59:47 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 17:59:47 +0000
Date: Thu, 28 Aug 2025 18:59:38 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Ulf Hansson <ulf.hansson@linaro.org>,
        Alex Dubov <oakad@yahoo.com>, Jesper Nilsson <jesper.nilsson@axis.com>,
        Lars Persson <lars.persson@axis.com>,
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
Subject: Re: [PATCH v1 28/36] mmc: drop nth_page() usage within SG entry
Message-ID: <b0ff494d-9e34-46ea-8b32-bd650bc3b74a@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-29-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-29-david@redhat.com>
X-ClientProxiedBy: LO2P123CA0063.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1::27) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH0PR10MB5147:EE_
X-MS-Office365-Filtering-Correlation-Id: 0730e9a2-7a91-4992-1dab-08dde65cacfe
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Vl5cda6i8GoQqy1IIA5YEyiqnp4fCJzrVLrAaC97a/W/yaQSrKlu0DwZBxAl?=
 =?us-ascii?Q?9TCz+t+16CMf/zefYpQkTYiWvW/+Na9oorKos3vGKTtZk8GwjPFOvk3Kg0dE?=
 =?us-ascii?Q?YVYL5vRARhPdsmUEujsRUmZuuBQ1mPjrr/bjutOH96FPTMKwSfNnoUZmo+Rk?=
 =?us-ascii?Q?x1Ep1rPiT6W8gCS/ZMAZpj95Jh8OYI2dURfejeuWI15Hs5f3Ql93Tdhr7iSL?=
 =?us-ascii?Q?sFWg7nacgR1YomZsrBarhKV+NrPHSO+/fh3EtNtT+prwH8pfhtY+uwb75FkR?=
 =?us-ascii?Q?d23b3jAJTHKZJo8hTJahtgBusrrpYgMnAgrqg8LktEr6UbbEnr9w//iCs4tp?=
 =?us-ascii?Q?fLVj/YvNvnBP/uO1KH8QFLYlP95CFzzN7cSl/qxU6bIn9dar1qiO4X6Mmc7z?=
 =?us-ascii?Q?xZwW4SUnVgaJi8vgyCnFLHz5xSucStT8a3HcHFdvLQ+NZmqt7YCNUTDR45gu?=
 =?us-ascii?Q?eZ2zoMnEbGDIMuuFJ1/lm/Qq0HWeyNtFyXZTgudpUdX6kjv5jr8PI49TP4OL?=
 =?us-ascii?Q?65b/2UyH52FmpFmR1m7uupHpU8+VSUGLrJgNaUJKHt82hIGxBqQiUZ4/SXJj?=
 =?us-ascii?Q?PY7jl83UZCWhlYvKMfs4CBhqYeqxkcLS6cFwKgOEg1aZbai6hINwi2byH9ah?=
 =?us-ascii?Q?TaMKGbXeOEtG7wp53aG081xmmfTCwpoOC9ofKDUlqKRFhfky7X7fz1l7cfiG?=
 =?us-ascii?Q?cQO9kUJwtY02s1W6CF+Dcvc0zvuYL7naNCQjTTY1YWpsQUt/4TmCIb1DNleM?=
 =?us-ascii?Q?5Ys0BXagrcGdDUofp8ASdbWxOpzL2g2lYRscpfPj4NMTnBFUIiracl61q9Gd?=
 =?us-ascii?Q?MOHIPasUwriAnq1I13ciqNAyHQ0MVkiAJKMrOjoLtpmNwI13tFkVHaZmgyd2?=
 =?us-ascii?Q?pAxfMp4igwfMMgzvjJRCuZC8j428AALHe2Yw7lfP2qvqA3kpnkICluL5msUu?=
 =?us-ascii?Q?knq1Jxf02kCVDiNinKsS9A9PjpvfamBVPhQAMdWEd0jCQasluSTUrKj5v4+V?=
 =?us-ascii?Q?UKMwBxV7bOMgBNhM7pj56AjaqnQW6Z8rn6ju4NeCMMBzy3w0euWvg8erfMCq?=
 =?us-ascii?Q?Hq03/OFPZAdM5w5mDV534pfqNgU1A78fCAP9NVUOd9RnQXMCf9t5DuFczX6v?=
 =?us-ascii?Q?3fRazDNbh4xKYjrxKEv048uPKv2sHrt1A9zDycDSeVvPiCXNaibeLciL8nTE?=
 =?us-ascii?Q?sYC8Q0MoWQqEecdaW5p/ujpOwKr9Uenhni9Zo3HxsCOTbxd8cf1M4O08se1H?=
 =?us-ascii?Q?Bg3ySUsBmU5Kk/cPy0eApZhIIrbWRAgZMSORj55i+/th9Olku5hdHG0XXhPW?=
 =?us-ascii?Q?9SglojtUkuY/AWYcyu2FcgNN4K5mwhlHx/GOG3cwt4aPpptR3zrcunI35p5A?=
 =?us-ascii?Q?teyFPtZieNIuPchKEUMWNSjxpqiGK1pT/5VVxItoiua5t+21omg5xHEsvmoL?=
 =?us-ascii?Q?/iEeVj0exbI=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?dqz1yiI94OtfmA64SQLjdOornQ+bKNWQ8EjWr5WgUS7ZrdWeoBHcjevzqsS/?=
 =?us-ascii?Q?py65BpJ2RTmijA8hfCz6vcLXiGi65gMD5Q4KS3ol2mX+iEapa0qhbAZfCW/B?=
 =?us-ascii?Q?Nu2hHwNnCOAIUzbADlCGktVZNe2kLAmWjV8+wx90xRm+PzIl/H7rYWUATPfZ?=
 =?us-ascii?Q?SQ7AH1LYqN3Aj3r9Nus2oOrTqBR6yZl/vXHmD6ziqlrfiUEEYwVFqfJQ/BxD?=
 =?us-ascii?Q?v4AutK+wcHiTikA5totdGJjUN+Y56KEey+gBu2Fa6fGYOX+met0GHXL42LG4?=
 =?us-ascii?Q?pumSJup9I6e6er3dk+9Vl2jVtglG7r0eCGL+NANqeYHR1gcTyVcTLJErQV6k?=
 =?us-ascii?Q?9XbqUMfAOHUZ8Cs3LowAYUpXMezWrM+Vi5vXXZPMXiSIHj95Fr2OtTVNbJyE?=
 =?us-ascii?Q?AkvFgUEvEvZOFoN+uexFKoN+8+VhKBH25RuC72PBU2jnrydbvNsZsElsgD44?=
 =?us-ascii?Q?WC2vsvYzNykUROBNmWV/BaMlT7xWpF3hTSKWlcbXkE5OTjK3mIqm3+VzMf7r?=
 =?us-ascii?Q?GozHDni7KoCM1K2UjL+6b/pnetdqy3WCSKzkIdjO1yF0oDhGE8rUbqRQecMZ?=
 =?us-ascii?Q?6sYdHmDCecmfpdLPQ8kCMxLl1sTLJQ5gZ3vtb+Kn6KBHt17VOMELhcjuIUuG?=
 =?us-ascii?Q?BL3NSrwVuht7AfqZtFcDI/vlCElYXsLLYzHt+wAq9AAgcqG+B2gQw5SKclob?=
 =?us-ascii?Q?h2+4YSnFxMJZAHYBTcNX4rc0KrB8Rt8hcxQcQAu8BaVIR5UbE2CYtvxNg/J/?=
 =?us-ascii?Q?s5om76c+uGRwHREnEw5ZToSqGt27S2snTzq1E3kkt2CHcVM9oSEREsEYnm2B?=
 =?us-ascii?Q?vCyVrjNKjgkPnEC/rTTtXqllH6fIsgHha2n33vqLT9K9WCn3C42KRIKuF8XK?=
 =?us-ascii?Q?AAV7oehAtt5kZJgByUyhruiNnxzmXlR4Q3u7thUk4x2KtO/ZeU7KlcuLbd46?=
 =?us-ascii?Q?ZIYejFQ0ehCQs6vXm/iOGpsqdednkGLkNPUY9wpT8XVV5EBOwoSsbIItXACk?=
 =?us-ascii?Q?a6khoQ9hw6BpZpcbs5HLvawPIbP2O5CN8hjNU36xeslDosCFEopsHODjl1rm?=
 =?us-ascii?Q?1VFSsRpPfhd7MiYSssZjCX/SmRvUq3bg0XksWf0TJOzY7cpvsbG0lvMW4zXP?=
 =?us-ascii?Q?vjjjTjsa4oHM86skoHP1Oc6QgcVJn+/YDTyfR+EKAMBgtPS01vzvjtzdMbsp?=
 =?us-ascii?Q?pxjDbtVbf+wSu/O3gg1bA31LB3qA/CFrbV6ZW2axuE1EheSiRJO5M8HBuUj1?=
 =?us-ascii?Q?GUTYByVCTbD/21vxJiMRo4JGTm+MMcnJt6ZgletYlkWOOlbwC0UKb+MX/rZs?=
 =?us-ascii?Q?GcxkrVr3wapdLXRSrCqNPRJhkliBwZF7rOg4SXX6Xt5Fo4YW6csJPrPDIMb1?=
 =?us-ascii?Q?KHi6LjRRPAWaqA6yKncCa5dx6pPSH3XGuAZfpvYaH3T/B6BiUZI2YEpT0Ele?=
 =?us-ascii?Q?q4stEqK2WfPuO6w0GvFeDVOrSFldgCAPJpOqoy5RBSiWbEKhITO7yDAg7pQO?=
 =?us-ascii?Q?vzzMIbac3BYWcEQUVUqz/hQXJJP5fVyW4Z3O2lrBx2VPco9gJP5XoxdVDd00?=
 =?us-ascii?Q?UlHZaYUJtQCD9Mk688t8meML8Yc8RWGT99qRWAy4XpOqrpEEjhg6BaptWLKD?=
 =?us-ascii?Q?kg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: u8VR+8Yp0JVZ8yh+xUzBCUgOKwZEpRwCmfIlOMZIUgGdiXA3N/Oa7ieflPnlwCUzbYmpRy7KJslsQPiCn+fX9tybxQ/o1emQu+3yxMuykuVJS84GjNFwQYRaPRy3H0xh5+2wzhDPq/sumaY7EwCcQPVNtyiao1jexRuFefNl+ZrFmaFHg9FEPiqsdrQDZhl/e89k4dGPW6TsQmYtxh7DdLfZPm26Y605YK6ep8bl9ePi1KLMWf+sX0f5FiVDXpERA3aUOpisbZHFyS7WcWDmJ3hG8w+iPalfbJ9/q/HZh0PWbjBp/PDEpOSlv2FX/vBIt+0RA0wAvUCBStdEyh9Y4+kxhOQ0zVttPn+keBXCJ6VVnDP+Fy5zBqg4TapZUeHwOy2u4k1R/XudvYO1vxqJFlN5EWjS7ZZHY4+3U8TklEo6GCiU077NbX8f5iFenpXtC0All+rLpy6Jl7nv7HFM0ziqqWLfsvfQ75ttv3l/6Jz+dxWl/shI9h6yickOmsMDkIZW43dfD1373LthcdUYV4fZlOWMReOF5sqMdwEMtT052OqwPwVEkpa3HAyeb3vUyYHczeyf6EeyMom610rodCiMw1lDqB6xWjnumvRnRAw=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0730e9a2-7a91-4992-1dab-08dde65cacfe
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 17:59:47.0938
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: WiiyKdUBOBRvxCEqv3S1smNsqim3UknNZrPJPpSlTfDU7ss1npDr2RYUqoSFY5RR6G5OIkghr8Ck+tMTjYmw2rHUPdlldxcGbBAOSQY19js=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR10MB5147
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 bulkscore=0
 adultscore=0 mlxlogscore=999 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280151
X-Proofpoint-ORIG-GUID: hL4O1qHn_UB_By6q-HsMp_neGp1F759l
X-Proofpoint-GUID: hL4O1qHn_UB_By6q-HsMp_neGp1F759l
X-Authority-Analysis: v=2.4 cv=EcXIQOmC c=1 sm=1 tr=0 ts=68b0991c b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=KKAkSRfTAAAA:8 a=CjxXgO3LAAAA:8
 a=3-RhneuVAAAA:8 a=20KFwNOVAAAA:8 a=yPCof4ZbAAAA:8 a=yANhqKo5vcweqC94BmkA:9
 a=CjuIK1q_8ugA:10 a=cvBusfyB2V15izCimMoJ:22 a=VLVLkjT_5ZicWzSuYqSo:22 cc=ntf
 awl=host:12069
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzMCBTYWx0ZWRfX607QxTUu38Hs
 2C2cN0Dy1lW67Q/90U9c7AS7/brf6GuzQtTM5BMPQugqvIRccTd96/d1QuVon++C20U3i9adb0p
 8i3RnvANQmVjMe+hgPCNU3ialBiZ0Lyp4XcOpVhZYLSp2kbyMa0XEhAgxXIVp/zgrpvR6z+ChMn
 2kcWEmp98sO/yeW3VYL66d7PN9SzYiwptNoluY2uofVd2g7FtQ5utnaP5FjqiuMPSP0lwhIVR/6
 RbLi+GXiIhM+WLM7fmQRyXtEUHJ9wCuBlptTMt8aBZbdOY29X2MhMHSOeA7waNg3MmSBEVafszY
 LuCtew/e8FzEGbvFU5itb8z9Nw4VrW+wcuuABWKzyTDdYpJrOY5OAfFbo3PR2841rkJz5QKpUu0
 c4bhHS9fG0oFopFjybNQZErXF1zKFQ==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=UPGdT7nH;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=c36bSQNu;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:32AM +0200, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
>
> Acked-by: Ulf Hansson <ulf.hansson@linaro.org>
> Cc: Alex Dubov <oakad@yahoo.com>
> Cc: Ulf Hansson <ulf.hansson@linaro.org>
> Cc: Jesper Nilsson <jesper.nilsson@axis.com>
> Cc: Lars Persson <lars.persson@axis.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  drivers/mmc/host/tifm_sd.c    | 4 ++--
>  drivers/mmc/host/usdhi6rol0.c | 4 ++--
>  2 files changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/drivers/mmc/host/tifm_sd.c b/drivers/mmc/host/tifm_sd.c
> index ac636efd911d3..2cd69c9e9571b 100644
> --- a/drivers/mmc/host/tifm_sd.c
> +++ b/drivers/mmc/host/tifm_sd.c
> @@ -191,7 +191,7 @@ static void tifm_sd_transfer_data(struct tifm_sd *host)
>  		}
>  		off = sg[host->sg_pos].offset + host->block_pos;
>
> -		pg = nth_page(sg_page(&sg[host->sg_pos]), off >> PAGE_SHIFT);
> +		pg = sg_page(&sg[host->sg_pos]) + (off >> PAGE_SHIFT);
>  		p_off = offset_in_page(off);
>  		p_cnt = PAGE_SIZE - p_off;
>  		p_cnt = min(p_cnt, cnt);
> @@ -240,7 +240,7 @@ static void tifm_sd_bounce_block(struct tifm_sd *host, struct mmc_data *r_data)
>  		}
>  		off = sg[host->sg_pos].offset + host->block_pos;
>
> -		pg = nth_page(sg_page(&sg[host->sg_pos]), off >> PAGE_SHIFT);
> +		pg = sg_page(&sg[host->sg_pos]) + (off >> PAGE_SHIFT);
>  		p_off = offset_in_page(off);
>  		p_cnt = PAGE_SIZE - p_off;
>  		p_cnt = min(p_cnt, cnt);
> diff --git a/drivers/mmc/host/usdhi6rol0.c b/drivers/mmc/host/usdhi6rol0.c
> index 85b49c07918b3..3bccf800339ba 100644
> --- a/drivers/mmc/host/usdhi6rol0.c
> +++ b/drivers/mmc/host/usdhi6rol0.c
> @@ -323,7 +323,7 @@ static void usdhi6_blk_bounce(struct usdhi6_host *host,
>
>  	host->head_pg.page	= host->pg.page;
>  	host->head_pg.mapped	= host->pg.mapped;
> -	host->pg.page		= nth_page(host->pg.page, 1);
> +	host->pg.page		= host->pg.page + 1;
>  	host->pg.mapped		= kmap(host->pg.page);
>
>  	host->blk_page = host->bounce_buf;
> @@ -503,7 +503,7 @@ static void usdhi6_sg_advance(struct usdhi6_host *host)
>  	/* We cannot get here after crossing a page border */
>
>  	/* Next page in the same SG */
> -	host->pg.page = nth_page(sg_page(host->sg), host->page_idx);
> +	host->pg.page = sg_page(host->sg) + host->page_idx;
>  	host->pg.mapped = kmap(host->pg.page);
>  	host->blk_page = host->pg.mapped;
>
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b0ff494d-9e34-46ea-8b32-bd650bc3b74a%40lucifer.local.
