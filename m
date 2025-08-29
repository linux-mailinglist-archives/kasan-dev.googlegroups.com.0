Return-Path: <kasan-dev+bncBCYIJU5JTINRBSHIYPCQMGQEQHN4FRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F543B3AF3E
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 02:28:58 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-248fbfc35ddsf12049855ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 17:28:58 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756427336; cv=pass;
        d=google.com; s=arc-20240605;
        b=dnBoS89nbAvhLvtSDgVG0CI9Y+AYEaC7ZNNLvLqHueCeyAWsxCP0NILkDn+JzT3Vxk
         PxVRwKWJLQ+TN0HcldAipype8CdVuCLQsIPV80DSFRsU5oUBuM7ePWEQLNUM/7TmqfXF
         ca51lY8GbujmPhGlGXyVEOJi2+4cOgMknHvNONR4rMAp80syp3mBKvf3h8uW573gSPk/
         +0tUM/nHnsTRyutHHxYA99e/8gM1f518QCnfO8lNanN4K4AIiXp0cEuNwsMlbY02MfXj
         gSNzavr+SswgBLIUNkefeTB1VbMWqUcpwu7+N8DpXVn6nfNsrEMtDxNLik5z9p+HwbHV
         hNrw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=l5hyO3BS6UPulmKz/yyTc/o7MsF4ETcHF5aaFQeTGCo=;
        fh=pO9ZINpy0eK/jp2nHjv1hbyQLLY7kKzHLc28Qqm5t/w=;
        b=XvRTkoc+zvNxq7d3g/Ip/+hsE7OMAVVOjvMqLG9FTkd7soDBbpEgJ0tsg3tt64kaoI
         Q7FtLfLnVigErLeJr+E5L5fwo/0BqYkXjajmZSsfO1ZJongGRGZ2K7guztSygMicF8zo
         FqRkJkZ/FboaxEw0F7cWerqJc7SYCjBhyvNt9p57UoVDvkPry8t0iJjfa/lsnMT+V2/W
         cj4fsq3P1J+H+SCPulQwGWTbzdkBnjeERzq2DZQb8VnOEcdAeLSYIibNPMdqotIa76DU
         fZCORuFHafhCuk+/zs6Kgcd0lkPfnVQvquANVVo1fW4LPKmKMFY/d2APBr3C0MGpVeNC
         NY0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ti8JGuhs;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DUR3gkoZ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756427336; x=1757032136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=l5hyO3BS6UPulmKz/yyTc/o7MsF4ETcHF5aaFQeTGCo=;
        b=GswclESyiAHh31tmq72yeQYXuOkK0hZxAXayt4Ktm/492URnCZ9I1WqeZXymlU/O23
         xAoYjB5kXXDFM33bwYyO5R3Xzh1TDeT+m3qYxGiafkI4a7irTFiWRFkmXmn1p7OY3gWA
         yyltHoSrwxWrS67661sWDflzalXHRs8AqiQAN3BuqPgipvKMIgoYUBYJHr50By/whurE
         fnOL8Zhf7C2i/ZCN0QUm9400UifWbZeMLgYL3Zj5A9C85MntroLzTtK05l2OFZ4KnQ/y
         QZ0Aiqty0lEq5amGH/DPzaJRkIACH5rxyOauDqk6MltXSfdMVefxEGer1Np0gKzGk/j3
         EAKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756427336; x=1757032136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=l5hyO3BS6UPulmKz/yyTc/o7MsF4ETcHF5aaFQeTGCo=;
        b=Eqm8hqyrSRAyFL0G7x+Yk9y0ijn9VSHYq7NLA+p/A44pPTOnwQYlXArKlGQvcl9Ghm
         1o/3dI6yfJKY2D1g8cFxemVNJJifYlDRd14yGL9ddxZVVUTIx6sfOtUGhYmYZJOUhEDM
         eAzednhzkfDEVsCGcnE6RrroOGv0G913CfuUtRFAgPVmOSB/QFA4phuqJNDDTutMHGRn
         CkAswfI49YQk4PmMAztDCbZPIiataKnEP7Ws0gvphpdXZtlSwC+z3gw1wZuuSYmF+DrS
         phBmzZjNpMI6814WebZHwYsh/yDpT80oe6J+0SZzxNyS4nti0y+FcE+7pSEhgoMCr8xq
         vLsQ==
X-Forwarded-Encrypted: i=3; AJvYcCXmF7XhNtiPtkkimYHO6fVOc4QPu6qVwaGqIvXJ4Xzls6h6hBY6O5hM4+cGQNRpHaklS/Ygmw==@lfdr.de
X-Gm-Message-State: AOJu0YySkrZfyZ6GlGNvBMyH7jCmqJsab9OdaakqQvbSQ4R8DptSCV2l
	qLqaTqoxedCVEQlE6k3pOrJNO1k5XyZGjdp6/Avly29aNlvJTk83HomQ
X-Google-Smtp-Source: AGHT+IE1l8u6zIiTCEsvpwlR9pJ6UUhd1zCoX1xtPSCitQd7rN99fESvMQ00lg6LTjWhdmf8kTgsFg==
X-Received: by 2002:a17:902:f689:b0:246:d98e:64e with SMTP id d9443c01a7336-246d98e0aa8mr226125695ad.36.1756427336580;
        Thu, 28 Aug 2025 17:28:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeohawKD4fJpIirSXotoFFfa+eH11LmBozdqmIp82QD8g==
Received: by 2002:a17:902:fc85:b0:248:8490:feaa with SMTP id
 d9443c01a7336-248d4de702cls14608495ad.1.-pod-prod-03-us; Thu, 28 Aug 2025
 17:28:55 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVt4FIgBy6R34+FKYgV4ELj6uH3LATSmVXjZcXPWMCU9WsGhSVH8NQoJ+wqjJ1/PTw/7XBdwiRUSP0=@googlegroups.com
X-Received: by 2002:a17:903:3bac:b0:246:87f6:4ce1 with SMTP id d9443c01a7336-24687f650f4mr299526805ad.24.1756427335272;
        Thu, 28 Aug 2025 17:28:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756427335; cv=pass;
        d=google.com; s=arc-20240605;
        b=EoN2wlBdlKtz+zOwOWp4APwqGNa/AbDysU6xjv15iNQb7WBIqLJMNmzQzbRQOsviDA
         CDCO0JsdBcLmfg1JZ0NwFhpPMFqIPEANNtF1dF124vEmnFMqRagqHWzNQVgx2+snGC5W
         uFtIki75TRX0B2L/+2kh2r5DGlnLALGadZ4vtS2iOIYfd58GEgTUXUqlg55iWyPLlfO5
         ikM9pemJNh0qlPE7ecw+yYYQIaI1e1q1DHZIUEXbeTJ/S+CNYqrbq9AoTqou0XiUnNb/
         KOoM9TZiQUfBnZKt8ZvuLTt3g8Y2gUFoxEKg/obmyrtAhh+A0eht04O5N5iLOnVR5KDw
         QSGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=lqutLdcBPO8kl3/S0mYwIHT4kDlP0mAzom40But1s2w=;
        fh=8D5kJP7Pnke0xx4Me40fXMkOJyR1clCkNFpbApmz5KU=;
        b=UvTIfxuGkW39tM+spdHmgcbDrknMi4CCY7KO+Nu2xUg2nsnPvVFTGp5ti8a51H9MpX
         6OSEHq4VZBsJT+R2kXKeuFR2HmOAPqMY1BxPxnUlw4ZgkqdKDK23Y6KMM3ipqOUsCkFV
         eD8znm9+XgdogFZr6vJiVqGQPdZG0Nnsg9A2gNBQbB160xKyR1l+V3/WWQILScPMwIAb
         VbF3D8M5jAPjYJr7dGhjozHUyp0JsL4CXEyRO7FG5zP3p0796QCO5+cxfPzO/t4Ktuw4
         fzazogPC/qMu8fMD7Kcekehp44Q4rcEbNQT+TGN63NutEr/qFGOMMCxZB5KD7h6UXoOR
         uZiA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ti8JGuhs;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DUR3gkoZ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f538490si219242a91.1.2025.08.28.17.28.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 17:28:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SLUsm0010137;
	Fri, 29 Aug 2025 00:28:36 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q5pt9rsu-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 00:28:36 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57T04Of6005562;
	Fri, 29 Aug 2025 00:28:35 GMT
Received: from nam10-mw2-obe.outbound.protection.outlook.com (mail-mw2nam10on2068.outbound.protection.outlook.com [40.107.94.68])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48q43cnw17-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 29 Aug 2025 00:28:35 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=JJup2BWrG2rc+Zqy9EdoHZp9evkbmdvHdwHUZV6Cf9nlK+N2BU1A0PVYdvgIy/Q8DeHeuGkBpXmGN+51t3WbMCtyZtFxz4vVN6Yf6i9/EbtVkaLAsi8Y7l9hvAhpl//fHQ17ELAN/PPY5PYGAcEU8YEmP+sJkx1Tf7oR9QfCANQcBObYVvYw2Df3qiwqAOf5Jf0mKgTt5Rg1qZIp+FeH6hscdkgDFCGtywqa1TS1LilJqnhkE+I/sDIKT+AZqoH0dgOTIyNg9J3mRz96U1yB0Q2+o4wTu9UQ9ygpa4zVznnAYExUT4MyssDjNcyDBpLsDx+u3nNcVUcX0T09OVzz8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=lqutLdcBPO8kl3/S0mYwIHT4kDlP0mAzom40But1s2w=;
 b=bJYEXeeqcj1dCnhULjqjPkpQIw+F4A2XAkwGv1E4uCRT4Hh49WqY3VZPmWUNofpe8JDrqXYac/yYAbNIB9GDlIsFJx9esfo1gwdYCMC0M4JoGJUtFPLZN92jgYlCUAHyz56lNXlUGY42j16aCZVIPLYwAzVYXn5L0kEKVrE1zqUGxS4sQHsvxNkWhK5pCZEe8fp6/9g8sFyo1KfXywpP19brGgO2fjM/SS54COdLvAl8VTVcZct6mAlNoJn5ySVgND8MjIvXqaCuTIk4/4OyFW0ft127PYpDxfT79NlnglSfzlxObUk0DCXkps/inphCSAeCkaCNAFRKtruMFwsakw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by PH7PR10MB6481.namprd10.prod.outlook.com (2603:10b6:510:1ec::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.17; Fri, 29 Aug
 2025 00:28:17 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c%5]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 00:28:17 +0000
Date: Thu, 28 Aug 2025 20:28:09 -0400
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org,
        "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
        Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
        Alexander Gordeev <agordeev@linux.ibm.com>,
        Christian Borntraeger <borntraeger@linux.ibm.com>,
        Sven Schnelle <svens@linux.ibm.com>,
        Alexander Potapenko <glider@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Brendan Jackman <jackmanb@google.com>,
        Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
        Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
        intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
        io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
        Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
        John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
        kvm@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>,
        linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
        linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
        linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
        linux-mmc@vger.kernel.org, linux-mm@kvack.org,
        linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
        linux-scsi@vger.kernel.org,
        Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
        Marco Elver <elver@google.com>,
        Marek Szyprowski <m.szyprowski@samsung.com>,
        Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
        netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
        Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
        Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
        virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
        wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 03/36] s390/Kconfig: drop superfluous "select
 SPARSEMEM_VMEMMAP"
Message-ID: <sulfte6cczeegb4lkmhflb2wp657ijsmyit3osicqmv43ypxmp@pmmcxdi2l54p>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org, 
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>, Heiko Carstens <hca@linux.ibm.com>, 
	Vasily Gorbik <gor@linux.ibm.com>, Alexander Gordeev <agordeev@linux.ibm.com>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Sven Schnelle <svens@linux.ibm.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>, 
	Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev, 
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, 
	Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, 
	kvm@vger.kernel.org, Linus Torvalds <torvalds@linux-foundation.org>, 
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org, 
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, linux-scsi@vger.kernel.org, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Marco Elver <elver@google.com>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, 
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, 
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>, 
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev, 
	Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org, 
	Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-4-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-4-david@redhat.com>
User-Agent: NeoMutt/20250510
X-ClientProxiedBy: YQBPR01CA0088.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:c01:3::24) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|PH7PR10MB6481:EE_
X-MS-Office365-Filtering-Correlation-Id: ccb34583-8279-4f2e-6391-08dde692f306
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?XlGAmDhbcRq3fUGH5DeNfcc2ZyiKLDc3FZGhqu45ueXzyHIoBHgxvUmqkTv0?=
 =?us-ascii?Q?APo93/BSh+UmHLIyee+EiNaU763sWjzLfPrNzfTMus16OkdJumfpqsxe/W/6?=
 =?us-ascii?Q?T9fYheHBDCr53B7clfVUkXAw6c0hiwd6u7hAIqCv4eE4GuwjsyDV4RF+4hze?=
 =?us-ascii?Q?YPc0ow1mgW7uXIVdvVWGI8DQf4rKnNvwJL63u7hkFZX3zszqj6frUlKqF75b?=
 =?us-ascii?Q?KWGkYBUOM4ZIzAjuJ3xXFNs2u+6Mt5m66zwIc2R75FoTnn6byE3zWdVrSrRx?=
 =?us-ascii?Q?qZLrWzirtSs9l5zC1yk6KipYCNrYs+YpHSypfQXXyxbRwm9mIDDllqyuaoEE?=
 =?us-ascii?Q?Yl4aHXGfKYI3nRieXhYJkAaIYACRjfQb5tyRkQKSl2WnDZYRNCZTF6ZOoz4k?=
 =?us-ascii?Q?/dbWJHJkBp6ctDaPvbGCqeSRT/nnrT/jfMAWty7lB0RENPn+pPaMBUWSdDdm?=
 =?us-ascii?Q?CEkGGUZI1i4AVl65lom7kHDE0sOKttIwn46N6iDtlTttEUQz1OVlDddUO3gy?=
 =?us-ascii?Q?6Me3u2f6IkLfushOpeSR04siX9UXf5P1vot1lUgE18CG1P4SyGl4qdlFoM/1?=
 =?us-ascii?Q?TtZBK5pCriuW9+hL1NcW3AEt99ZCcKX9hzaANS/dsMx+ovfOh/DtChdgTTL7?=
 =?us-ascii?Q?/OZI2skw8zY/ZZtyxjLcdbdDejRMdi/x2ZaANWwssmtvP//ooYaN/WKG/BqN?=
 =?us-ascii?Q?xMFqF4672TueqCEYJQhJvFV0rj2Noq8O5jHIS1vn0iX9AxUY7aKdhBgDX9PK?=
 =?us-ascii?Q?kzc/d0Ts9YOQHS8CLgRbdPCsX1LFRnafDsde/5whR9M5/5rBa/pPFjouQ+Rs?=
 =?us-ascii?Q?ffMZtS0n4bVSaWl5i+ScyG2ErcaQ7ppxTj4XCUsvc+bDMTXJkPwTR9zKr6z9?=
 =?us-ascii?Q?jtILAMWBmtIPcvfX0H26ncMiPEjS/WNH9UXpUhgfwANpNWlRspH5B5wA1Tti?=
 =?us-ascii?Q?S3AgvF6JKzTWivarXhbzINgFHeBSzfPP4rHn8evQ9xBJ/DxvT3NOzSrGvPkr?=
 =?us-ascii?Q?ltnBNQbx88oDn9mONe9Ns+N/D11WDJpLo6YuwAJ4OaWTXPWEU9um42ita53a?=
 =?us-ascii?Q?ncriIPNjJtF637wcIuBeyFJzlPfA5KPgJhpj3PxzoY7u5hyzdiAw8/PQDWj+?=
 =?us-ascii?Q?CN2t9HCBmXdoJi64MIo35qZUX+FdwDpUAoIt9D40UjTwjODIrXXVlDLtwb4U?=
 =?us-ascii?Q?ReKqpkg/8MOV8LDwnBwbftr2kQASgTHdVmza8bXQ9F8aIDGejELD47CAQWRL?=
 =?us-ascii?Q?fOplE6iZ1kF7VJkAR70MuvH5mAXvx4iTv0ME3UxLb5aIee/NzzRA+I6PWFfI?=
 =?us-ascii?Q?MrfbENiuqsEq+b6swJuire0pbj8fEH0EvAYp6qu2S4BmMZ8Knvt5hQmNmUZH?=
 =?us-ascii?Q?e5E6GJhKdN/5Xx/pl1K2AK/j3qXkb+Npn8pbArsG9XiCOaIRfRTJFcolIkaq?=
 =?us-ascii?Q?7MRb1Ap38II=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?dn1sjCJMPdSLEuUv9NyBKnshj6ZIX6FfyUQGDmvWzHQ8MF2MEs+whowXBLel?=
 =?us-ascii?Q?e4jDgSoC/44aPk6I4siSkO8Xp4ljEQbVHkIkyMsqPVqoCdCK5Ladl3l4owvG?=
 =?us-ascii?Q?GlN/Qhk2bZE0Yf6WSuls7WOSypGxLfUAgmHYbrmbEDUuCFjIdpGpJ+/Pyy17?=
 =?us-ascii?Q?unTYiu5mRJ+BFmjM6dTYc5RdAtjZzmL3BDJm/vBpXcy/+/apgHKipoR/QB3E?=
 =?us-ascii?Q?1giLkgTFKXRhuokxPwKVbENpTLiEOOZgj0zPr+AiPm079t1ISOtKCnDKDvLR?=
 =?us-ascii?Q?AXQhj7vIwTSk/deRbHNOmxuhpfHEDZZedhbbJY2QcBGKYtMMIehy5d7r45pS?=
 =?us-ascii?Q?8LYuKgtkmHqNTGbAMnbJmmbJ9xp/EDj/k/0K8NuuNJ79xT2OE59zx8HQ8MMp?=
 =?us-ascii?Q?qiKSNo7hF7m5W2uUS+vTKcEzPJlupacuTadzaCKor/ueZPR5QbCDwb5QAg/C?=
 =?us-ascii?Q?+s+yLpxKCOV6r8IDTNKWlzrA0TC4HLR16wuDeEZAFhwE0HcrjvWqAdL0xE2A?=
 =?us-ascii?Q?/4FA7rnyKMbqMOCHwOqVqCUAbEhjGyg6I1HfiDx6iQN8XttrcEPW/xpCnNdD?=
 =?us-ascii?Q?7HQPHFKVtRsTf7b584XtCz8DQVo39BuQ8iYlOr5pqtO5nqS6sk8D4UxEtHGk?=
 =?us-ascii?Q?RramqcuAykFrJoBLs7QqSHK9LwE/avWuAcjm3az+cJe9pV+TdmqFKZVcjG+/?=
 =?us-ascii?Q?glgIB+JzN653RXKmF54r61A3XILdUXyC1znGpj+aMD7h2o70Jzjr4jG1IQF0?=
 =?us-ascii?Q?lDX2zD4yvgJv9DCXwGgrIiPmnWSP/KlxXKu77JN+BfobuWKgVcHj9kRdVeBG?=
 =?us-ascii?Q?TXdai0AIpKiyo3wQdiOZ0Cro5vDtJeSJXjZdtmGZ5+Z8u8922P/hpOOmkm7F?=
 =?us-ascii?Q?mERuNyM1bvlLUSjR0icWwkIXAHHCX1fJ7IGy72XvRNbQ6WbvUCLb+bGF/KpE?=
 =?us-ascii?Q?ioENytVisRBLF/rsFIGAhz62NEar4T70zUFp/ioeZe1I24C5+oXvhBtIsU1G?=
 =?us-ascii?Q?ECZnT5OvB/li0C/5h2qIv59hgHMwrap+z4S+ojbIoDOyDwQeCQ/HBsWalK5y?=
 =?us-ascii?Q?sy99GE/woSQp7PKHtktb+V4Ung9ZLwf9NEqFWYtc/EE6rM2eEAgPB4lirXPm?=
 =?us-ascii?Q?suwsmvO3+kbyQyKvg2f/lR2+YYlhIFbC/NW9Y/ebpItCXouzJrnWmzqXhhOI?=
 =?us-ascii?Q?l6xyDlsVpYQHoFg3zX07NHOuGhRj64mSFOh9Omkux4Nn6DtnPwrX0xn6PqIG?=
 =?us-ascii?Q?VitEb1ho7r7mLmHJZOzaOsCLSQvu7zXe29xced/nFQZvW6slheYzPjTV8igL?=
 =?us-ascii?Q?rxe9vc8/f+TXHzhH+yn8vAXch9As42XwnmSnaeqavdq2/gV1HrZ/6gX80FOC?=
 =?us-ascii?Q?z1XYNmLKghLT06zHtHl2ZvoktSQom5kl3BryQPqbzW598p75ld4wcT7pF332?=
 =?us-ascii?Q?gJPzvjDXRgFK/VdRQkQiXGy8Yrt7L7LV6N+aQ0rjQrJQTOvCtDk62zpjlG6i?=
 =?us-ascii?Q?MeAh8Y+ngd3OtxnVrqmlQSthNwU7ZOjaOP39/gKrTFecxmkNr6fxSFakUSFW?=
 =?us-ascii?Q?+b10awDECHtmgVHkWPnMTSWRfqttqqcGq+4uRDn8Y5/XK2W//A0RdvN4RrsY?=
 =?us-ascii?Q?kg=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: KwTXalOiyBFuGvPe25NWbeeRxsd8Jq09EnxPS77FyOwRtvJRh7et7GWD+PtJtKsGCjQBYmw8T/I6gops+EJ6e8wwnTLpqqkh2vlt4spdB2bd2ljdVMkMXRwwaFxErwnrBfTLcXfWN1Dxqms0hUT3JhU/Tp5G9Wza+ekjQpYJFQK1jY0kUAqAlc7NDJZ7fE5lqbpGDMlPqV4PLxVfJ/BYfyH5UkhBhsAQrHctf1raNLDIIXcvk+Ldy5qKx2DvmE8XsJPuCgoStJy8QMgwsUC1CNQD1OqQTl7DD6uO+RuM0SuaT17v/GXm7J30fAb0p0XelnTcRLrthdV3cBkYobAJ8lJlOkH50NezmVe+KYKR1q1czsDYuw7rkudZ5CRR+3tWKPDCLEVUy5J+qu50UtBbjzECirjeNh+RRbnCihEOfBiWYeDFBnHpvQ46Zgm1w4dPDG/F4qbr0KqxLk5vkvp5UKsMCL94H2pkgbKeNyynHDIInq9kRn+SkMoqpYayfJgl7ZaWrLOjb5t3Lu8v76lyLN+ZqU2ASLu2x09SEWvWV6QEQmzKeh10byoYXCH36PEioynW2VuOGxa165L7IL6u088cwiYx+PHzfGz7R1rcEUc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: ccb34583-8279-4f2e-6391-08dde692f306
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Aug 2025 00:28:17.5421
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: XsC5HrhkBAOCnpck6rZ/MaCaG/c25MTzjYvJCwJEB0BQT4RM0q/1lTtrRRVfw8v163AmAeA/Se5Ord60JzASug==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR10MB6481
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 bulkscore=0
 mlxlogscore=958 spamscore=0 suspectscore=0 malwarescore=0 mlxscore=0
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2508110000 definitions=main-2508290002
X-Proofpoint-ORIG-GUID: NZaMI1tGQ1DeIarhdpjXzRXYCNWODKZV
X-Proofpoint-GUID: NZaMI1tGQ1DeIarhdpjXzRXYCNWODKZV
X-Authority-Analysis: v=2.4 cv=EcXIQOmC c=1 sm=1 tr=0 ts=68b0f434 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=20KFwNOVAAAA:8 a=VwQbUJbxAAAA:8
 a=VnNF1IyMAAAA:8 a=yPCof4ZbAAAA:8 a=2LonWNWx6ZCzk-tnfBwA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzMCBTYWx0ZWRfX+x741LvJpXgx
 7QJrBcSjqjQXCu6pleOB2wrDKUmVF5fZXSoAMDGT/EfyQ71EHCHtyk7xaNSzXN6ltAkEj80+xIQ
 QT5t/q1z99ny7U8JFlJWHqVzxQ7Xr5sAAG9nTDvWwaglbk+L2J1Wb5RaZthMhRYvK3hV3fAAGuk
 v2du81zLc03mxmRmRoP3zOg5Jnjwz/7sUaIYstmmyHz19ZgllwXar6aSVzn+yqyVIW8h6Iwq8BY
 kAHHdQjcq+GG4Sc8QG/SRUVUD41NImS8C5Su6ylvKYiItxxjDCvMBakot6eJYkFPS5AZBTGJlAV
 GShx1Q/uJF+pdBUkQrMKzU4R4GnJyNSMTa0M7Qa9NH+VonrKjg4b8WMNCRs6hGzCS7LipMKQmd2
 /OkmsEXs
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Ti8JGuhs;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=DUR3gkoZ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Reply-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>
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

* David Hildenbrand <david@redhat.com> [250827 18:03]:
> Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
> is selected.
> 
> Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Cc: Heiko Carstens <hca@linux.ibm.com>
> Cc: Vasily Gorbik <gor@linux.ibm.com>
> Cc: Alexander Gordeev <agordeev@linux.ibm.com>
> Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
> Cc: Sven Schnelle <svens@linux.ibm.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

I have a little fear of the Cc's that may come with this one, but..

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  arch/s390/Kconfig | 1 -
>  1 file changed, 1 deletion(-)
> 
> diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
> index bf680c26a33cf..145ca23c2fff6 100644
> --- a/arch/s390/Kconfig
> +++ b/arch/s390/Kconfig
> @@ -710,7 +710,6 @@ menu "Memory setup"
>  config ARCH_SPARSEMEM_ENABLE
>  	def_bool y
>  	select SPARSEMEM_VMEMMAP_ENABLE
> -	select SPARSEMEM_VMEMMAP
>  
>  config ARCH_SPARSEMEM_DEFAULT
>  	def_bool y
> -- 
> 2.50.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/sulfte6cczeegb4lkmhflb2wp657ijsmyit3osicqmv43ypxmp%40pmmcxdi2l54p.
