Return-Path: <kasan-dev+bncBD6LBUWO5UMBBZVSYLCQMGQELT5QNFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 98B47B3A93D
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 20:01:13 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-3275d2cb1cbsf1963965a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 11:01:13 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756404072; cv=pass;
        d=google.com; s=arc-20240605;
        b=NxEko9m+UmRN1vQUbrvf66b8V0GLxX0NpIxUsDxBVpVVTKao2f/50payR64Q22tgSq
         x8kCCE1YbHtuaZcgpLScLaMhHmwT+wGphLixI/KA169we//T7EIALm5VizIYZeliSic3
         ijkJtN9NiI3kplggZ/5Ua82ZXzVVqC6yRSzbWEROKUX4raziEGwh/iBVQamoD2PCnkuc
         vamvc6Mkwi6xHjDWWR/2IXLeBpPoSeixDCDjTfAtZ+FpWPGjUmZmo+4C5Pj/Kq0ARSLd
         b+X9L0vzGLjWX4dITP9QcqveOJHanOnal6l+FLIuXFlDq+RoYpQPL0s/DfYBCnQ9fW3m
         h73Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bBRNp6SHoMq5fCnPmqoeRHmVzzai9NO5eo1G4KK5TP8=;
        fh=jE083aVef+eFdTiX+skKDvVtBtQL+kZwyf9ULdz/qNI=;
        b=bY8ZJG7hpOCA1QooGf1wwQcZi6GiC5VCLEh72qVAILlvj9pDQN/Om+piXU0/nq95tz
         DrBvIkSineVk2gAbb0lJ1Vu6YsGk+TTk9+ncLafPKjWduN6XyTYYTgkg/4l4nqm1JMVa
         jGjhIa3/2tLrv4lTkIbSVLYG61fnxI/U9YsFYe0bYZQfoStQE+nWBNtIt4YRTSClU2bJ
         M36oVC8UF+o7lsR978/pgpuLJPyyoqmRB3YnSMNupMpQaKOvqGqKLVzsVfdkFZhiHGjy
         WKHHDbg+A1C1SCrwdmKENpOC/pYbwDjlcuhsTGYn4QSb1euQyFkDcJbfn5YKHZOCumhW
         W4MA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=nXm4fcDh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=yAuHixpl;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756404072; x=1757008872; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bBRNp6SHoMq5fCnPmqoeRHmVzzai9NO5eo1G4KK5TP8=;
        b=hGzWUohBt71+2hevxRCjE0Tkowj237ugik8JIGgzT51D/n4a1DEuiKrL36OP+vOftT
         Kd+1Y7fb3Nc0bcayxjY5jtKDLQ2rWiVjpPWEDChH1eInFJstapnydKICTIuitcB8mE0M
         3oi5iGG+FfhTjBitWhDeyw8Nf0SWxwmGjkGQdcVvspcZvnCVtU1QDzgdIC/7ZjtuCP21
         RDK7tL2wttNe0LLrrRtjpRpJatLvL7AqejLAomK2yDx0SZWSVKren0LlKEIEZ8zAKwHT
         RA2PcTktBu/7eUIhdK1WE+KxOktggmpZ/Y2UwuSIAtpy5pEUcue1Ro98evhhgEzvmDq1
         CwoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756404072; x=1757008872;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bBRNp6SHoMq5fCnPmqoeRHmVzzai9NO5eo1G4KK5TP8=;
        b=gO7UVtHTHG+fmIF9iK2W9JOe5pCQbQgctGJmdWlDJ5dJu8veAJuIV/2AuDG7otYbQ8
         Lem4+FBNVzxzBn5LZwt8srU4rlku+KYSI7Ts3tbcNxrzX09RyVLBxA7NYbwdDuwuBk3g
         yBCXm1s5ZV/hhRpws8kGUdEwDfb+/prCUqfPNlFnGDB2ioesPgjpNYN/ZZ1+bvGQFY+e
         ym+6LDG1I21/D4hWRWt1r+66f5iJC275gJa1iIVbWcEJKJndZoMs/SAwEoqe36sZAk6M
         qB3dT5gWyQN8I3cOeQ/o55ojFtyXy2eTxWbSS3YaQ43UCQBlTMph1gb9GMMQBhuAbbgn
         vGyg==
X-Forwarded-Encrypted: i=3; AJvYcCXj53p2xJTS8TiJ0V2/Fz8MjYDkeZWNRzK9r0owCeFt2rJUmFqqTEwf95/9m2CDtuRORy403Q==@lfdr.de
X-Gm-Message-State: AOJu0YyMZJ6L1X/WLUb8c+5H6rS3e4FFqnxNDIf4ya2AvqHm9FrIYdSG
	EDP8xz8WON2Z5UEFHF0ow6gEWRg7rWnh3iPZlt2rxP3XzNCucD0REACN
X-Google-Smtp-Source: AGHT+IEnV4wQ4YZPQuOk7Z0E4q+tznE5tEc6nJyUG+vLrX07cShQw43Iaq0pc3zvR3dji3CN8sVn1g==
X-Received: by 2002:a17:90b:2d8a:b0:31f:6f8c:6c92 with SMTP id 98e67ed59e1d1-32515e412b2mr27067647a91.11.1756404070332;
        Thu, 28 Aug 2025 11:01:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZczkmC7y5HQ3L6Iqy7dpKWqF53kI7w8vyfsIDjHEAcUBg==
Received: by 2002:a17:90b:230c:b0:325:69d4:70a5 with SMTP id
 98e67ed59e1d1-327aacddb6als1122311a91.2.-pod-prod-03-us; Thu, 28 Aug 2025
 11:01:08 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCWTok5wlNUrz8P8sDYUCXRYn+7r1dZcme6WMK8VNpxrK4/dL00Lz0J+WGcvV1zOyeJIOt5L5ccTKos=@googlegroups.com
X-Received: by 2002:a17:90b:3e4c:b0:327:ac8c:10af with SMTP id 98e67ed59e1d1-327ac8c126dmr3205460a91.36.1756404068422;
        Thu, 28 Aug 2025 11:01:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756404068; cv=pass;
        d=google.com; s=arc-20240605;
        b=W+mcNqtMdEQqc2yelkNl9YuJ6BXjaFoB71po1yVm1tqb+RtLjS0dzPagupc5nY+sxZ
         SYwtQSM+n2uLP6FtmAlg1OzBB5UhJQhYFaWi3ZeKgs2OQle4VZj2lb3hjLkgPdoTX0BA
         jZfVEZttH/BXCKwGVMMMf6ETz0IP5PEWlDlxhArke/mVcWHop7iDPwcBFA4GCYThJNHk
         q0ztThDkFed8waSWD+JKWYdd882LOnrs3dZhkTifxuvzAF27yWhbO/3IBmsdjx4dPyUI
         i2XAwASnXzDii/jPQdQRkgx3bYy5jomIqF7XyLwwXAVGWgJuZi6LJzRvexU7VeCaTPNy
         XABQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=dVA6ZadjF7Xy/V/QU5yP7+94Igd8LWSIBpRHWPGKb1k=;
        fh=MLZZxRL4SFIT6jYbFuKp2h3ZqITnkbDpwlwS8cpEKu0=;
        b=YO3v7W+ox8+i/VsYelRTTOYNakMWvIkrVaxYTpAeUdVVj9ffXLo1Xv5AsIECitouR/
         HNz7xe46fq06FQ1HBu4fUdj5ydxWzAjsFPhHgMNq+qo/RD3rldrMKGd04cLeX7btbkcV
         DVB22GqFCvyHl2tf6i/Pz52SBrOCuByJQQXOUt4MG5tdJpMzeLcCFlPnMo/VGNyy4ltX
         WoVT+5oGeRXrNWsw/1UZp4NwE3x7AZQSJaTedgH8Q2/gkAlcGlIO0dWejOnPTAaE6OYV
         K9HKRwZQNh0Hv0YH9QRB5WmT0ZuyJz1u/PuWHigAyKh72Musu21dh4ei56VgfVX9SsdU
         nrhQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=nXm4fcDh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=yAuHixpl;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=lorenzo.stoakes@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f49394esi278981a91.0.2025.08.28.11.01.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Aug 2025 11:01:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of lorenzo.stoakes@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHMpwl023300;
	Thu, 28 Aug 2025 18:00:45 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48q5pt98n7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 18:00:45 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57SHm5EJ012336;
	Thu, 28 Aug 2025 18:00:45 GMT
Received: from nam11-co1-obe.outbound.protection.outlook.com (mail-co1nam11on2064.outbound.protection.outlook.com [40.107.220.64])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 48q43c6fv7-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 28 Aug 2025 18:00:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yd9HxnH/4OYIqiiHbuBfPoqZNA+5n7k9r49yuFaeAwgZNsv+4bPomEqGStlIHOaP+8mGUNskqrWIFIFDXdiqssEyr0x4tzwU2+/WE44GDMUpHyMgAI7nNo30JxjPF63SDCs0E5jgx7Q1vSsZ79aqlCCkoSOWkJb3RTnQIJGEdwexC5RhH2M+Bb/bNffQo/NGzkQa3nSrXeO2lHPFw/4eExGDjWoU6JXtdst3wwaWgZegd+4RzjpLUWgLjn2p1iWromqR8pvwwmRc86XgwcJb+7NBue3x1s+RWTm1FX+auELWJW/Pal/MSIHaX9hwz57ZddoeBtZHy6UC75/2GWxZNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dVA6ZadjF7Xy/V/QU5yP7+94Igd8LWSIBpRHWPGKb1k=;
 b=a1w6h+gPsBe7YEgnTGeoHMUtkm1rIepZBjfrjCw0Z6SlM9Wef2vb7+ig3YMvrL/wnAYKZu8IIfA7NoYIn03W5ZCb935T7rPb8k7h9gqRU26llfpmP/jr0gTcw9oPB/ktGgFNFYfPxij1fw5n8zNG4YJh0xKTDRCUCy3BTXImzQPxlu4ynz+Clh+A1RIgyZtFFIAC7YVFJEUa3T7Rft+1aX2XmQiCtJ22a7Kh7kbToDtDpV2ePdaZTq3Fx7u3+dqzClKUt1Q5oT9ipuaaGx/KQIweNVqAa3BPFo/as9CGsGeYUxM3BcjlGCTUwpVVT9HvRz2/lAJ/YeTryCXQPDMLLA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from DM4PR10MB8218.namprd10.prod.outlook.com (2603:10b6:8:1cc::16)
 by CH0PR10MB5147.namprd10.prod.outlook.com (2603:10b6:610:c2::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.13; Thu, 28 Aug
 2025 18:00:36 +0000
Received: from DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2]) by DM4PR10MB8218.namprd10.prod.outlook.com
 ([fe80::2650:55cf:2816:5f2%5]) with mapi id 15.20.9052.019; Thu, 28 Aug 2025
 18:00:35 +0000
Date: Thu, 28 Aug 2025 19:00:27 +0100
From: "'Lorenzo Stoakes' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Bart Van Assche <bvanassche@acm.org>,
        "James E.J. Bottomley" <James.Bottomley@hansenpartnership.com>,
        "Martin K. Petersen" <martin.petersen@oracle.com>,
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
Subject: Re: [PATCH v1 29/36] scsi: scsi_lib: drop nth_page() usage within SG
 entry
Message-ID: <c32d351a-00f2-4929-b0c1-91aa364e681d@lucifer.local>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-30-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-30-david@redhat.com>
X-ClientProxiedBy: LO4P302CA0010.GBRP302.PROD.OUTLOOK.COM
 (2603:10a6:600:2c2::18) To DM4PR10MB8218.namprd10.prod.outlook.com
 (2603:10b6:8:1cc::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: DM4PR10MB8218:EE_|CH0PR10MB5147:EE_
X-MS-Office365-Filtering-Correlation-Id: 85832de1-70b7-48c4-af12-08dde65cca1c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?hUHi8UIhQYmOrgMuoeQ8ur7MnLvqz/3cbvvY8bQec1QNRO8Olaztw0IL/yfH?=
 =?us-ascii?Q?Phm7XCn2ovs06tF3ztJVbFsh7zvmw+9FV86mugIT0yFdSikV73qsPpt7vJPV?=
 =?us-ascii?Q?S7r76KVD3kEA2gKMYWMtVBt/0t/5C4duIUKYofFvDMI89CpQsNiWOGwrUrE1?=
 =?us-ascii?Q?HdQwCsKtEJamq1v494oZ7BmrjL/fKtELRC/J4CS6xeQhMjJ5nAozXp8bWo/Y?=
 =?us-ascii?Q?zDBTaE5xP46aKryv8XQlI24mmeA8DLboafW6Y4bBzmB38Jwa610Y7cBa2R6/?=
 =?us-ascii?Q?Fn5aKkIHqoxoe2SaknCvWNDWg5dX11lyQj3aCeJffzfSgP6vm33L1tBRWjcP?=
 =?us-ascii?Q?XrxD2aO/CBENasPeyWX0oC4nt0VlngH0VL6H+w1eHlGaw9xNdG8vDI08rsm8?=
 =?us-ascii?Q?puOu0lwz+sjPKzpdpiNiNZ+qbh2UNTFzWF2FxGBUasj+jHo/uJkzjCVxqNAK?=
 =?us-ascii?Q?b8VeVvHxSPedzDF+5CAtQmkGHedMUKVr0P8SUFD8219ECqx1evgLDS11uZQ8?=
 =?us-ascii?Q?IOckFtjoMlIb1SzvKb43WQmGNo3B+pwk9SBHK/j8cKt1udZtR7aytUj333I3?=
 =?us-ascii?Q?8z68wYx6pLWbs4Bwl3dW6Czsa5J0ps4+hZvqXKeqqMvp9XCGPg5y0RmmmCvQ?=
 =?us-ascii?Q?nGQo3UJZmD4vOBozFSgwokC5ELKi6pTMAZOgyb1Evsl6L+Amq0xX2aa6UKeO?=
 =?us-ascii?Q?dr9ZYBNMN0iN8+5cvdAEKrZiN6NOLGOa0ytPH1xFgYRdPFa1OIt9o+Ry1+my?=
 =?us-ascii?Q?zbofOtZRAkFX1KDzu6nnW9hqbKJ4ABtzsJfHf4rJ+Hvc9nuaCGu0syRsObn3?=
 =?us-ascii?Q?WUQMUKcfMIu7Xp96VZDZWWrHnIytCPy/FoTRo/DiXELOZrlCxJLGl7pvN30G?=
 =?us-ascii?Q?U8Cl8bD2wgJ3cRbViZUXHz6vF7vvmnZ42uX1hFmQpF+am8WuB1DiOTxzQh7q?=
 =?us-ascii?Q?nhNpq+cLdN0WggMx4QAdgiOlD//vGDnbBeGf+3Xy6cY9GnkL8hL6NbdgZyOE?=
 =?us-ascii?Q?45Uj1GoU+uXdDuC1ugdKqmeG2Ez+HJrnDAKCTABBpiNRZOx8aks6irieWEHu?=
 =?us-ascii?Q?6P7zm4fsO87OAbB9Dszh03dMJGLHltBDdn++/2YC56jHe+r/JaRWzXsR2tgp?=
 =?us-ascii?Q?0Z9HfStB80sodT6KWGLgltrKK/g5oHTFwBWZjo0pMckGgobSZ5uVfmrpYbjv?=
 =?us-ascii?Q?9fnFrSsBi7DEjoUSAXKsIKh9dlGidx+GNyMRqrp3kvh6pVxpBFaPfC4w9geK?=
 =?us-ascii?Q?XhP0YcrZVPPoxqqv1f9DzBdsXK/+QisX/lxBSIqZk7cC0k3o92TOj2yftWtz?=
 =?us-ascii?Q?eV0VtUEz0ylGKxnZg4oZn63J/L4vX1Pgj5OjuUg4vZNEWqjOQgpBS/aHxH8r?=
 =?us-ascii?Q?qrKK5FsXmdA2e4+/owHXxgtGrpgkSo8CbAxfBblJQuy0rU3vjYPFlVnZcSbP?=
 =?us-ascii?Q?1p0nAmG6T6s=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM4PR10MB8218.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zcobeQFDJJCn7OxnAUVb2f6ktYODkxMgWxoSIdvHLDzBMXRo5LZLQs8XsgAy?=
 =?us-ascii?Q?Tbrf649SUoit9L+Zb/eFZ9skqNaT8NjNlWY7m+S+Hc/DkssLwBQYuIGSaICh?=
 =?us-ascii?Q?Dg2PtD7y4pruQ9ErRPVMVmTzTsoAfzMHdbmklzJJGPIzmQkuz67jBNUINleP?=
 =?us-ascii?Q?liNbVapmmD5rox33GhNjj0JMhNjfCwL/ZnWMZNy5y8XtXbiKftBzBpoC3dSY?=
 =?us-ascii?Q?ROh/RAb6Z5yUtJb405wqgo3g/JajOl5Tcp/RHYa8kpdhE8Ab6XL+yV7Jibxw?=
 =?us-ascii?Q?/BoZdyttNVa+mDK+jzQOsq0vG3a1BUQ2jv9k2ZJaRilMnvtlKlMcrtKi52qa?=
 =?us-ascii?Q?onhvCA/rDM/tyovSpw0aE4nIl1KNK5AuhdVYyFsScpZBJeMcqPy7ArCG/+5o?=
 =?us-ascii?Q?m9AGpfytyOH4+g4sturTMIaO2+6NLV1l4NOMXgDoeenEkT2mvqEoWTVci3OC?=
 =?us-ascii?Q?koXQASdWmWrMd9X+jQtWK4y1XW0WE2HwIujrq+II3VCSRmQUKQg3/Cgttm/O?=
 =?us-ascii?Q?rj9vS1sfO3CNNvR3DTOaZ4nHqSklKX9xx7wKUTxbcfVVvmhBdR+WwVw2+4HD?=
 =?us-ascii?Q?xkZXhQJe5glybZeNlIVJXFssEFda+CFzqBfoiUU9KnaakbAo3QD9FcxIsISd?=
 =?us-ascii?Q?Jw1M7JFfGf1KFYzMXi1qewMuIfzQyGfx9QPOugvrPZVAJfRE9vs1uGiCINMH?=
 =?us-ascii?Q?FidJJxy0FehF99VIVApMxwM+8nBl4ZrhBsUWPwh+TsJ7+aX6tM/gpQbTIZq7?=
 =?us-ascii?Q?3QB4oAdHD6KXp9BIcaRtCiqaOehoRVeiyVn7i/Lfs90deAyjpMD4HksGRp3H?=
 =?us-ascii?Q?BiMvx5mC8wRUrywEqgGX4v3xgskWCoUZ40ELWc1KYD8wOm5wipNBZrdYLBts?=
 =?us-ascii?Q?RSL+JwcXNRCCM4awaFNwNvqpa/GWa/lwcIpK1uTqnTwzb1yIos/5ECwv6Ms/?=
 =?us-ascii?Q?3uTkX4mv5PI2adW6Jen23nrAlABgtgrx1NKU/i8zpY1W9R0f+mro6sCTo11q?=
 =?us-ascii?Q?wK+U8gBJgtf4qY9gBvwslVC622DH23ad2yRi88+udJs7Rpdz8IH/oNpRVDd9?=
 =?us-ascii?Q?YPykvn1t/n0XXmRJDW8CI9JCvNIXMGwXMyoJsaXdjxOSmZudCNdX82MbRpp+?=
 =?us-ascii?Q?7YJD2IsgPy+UBa1fWT3v0ALqX9D8m5ZGPqtbxoDQEzEBLNubEIu2u2B5PEUy?=
 =?us-ascii?Q?DpJ6L6N08Mk3/D/6FMHyMRE75vV2dIaFRCxMBd3OBd3aZkAPIH/mwTCW7lhV?=
 =?us-ascii?Q?ZbmjG4w3hRBYSGD3p2Ka3mBD1HUuMOrxc96eisqFrCipT+Waq7yQ58/BlbJV?=
 =?us-ascii?Q?5fdcY15YdgWpM1bRhSQhQcYUD3DvTRkT2yu+kk6Y8wKgx4JPDOWiSYCdaz91?=
 =?us-ascii?Q?AuvVLzZ56S2HYBTkEVZtCvNvgDQ1kVrJRKLBcJNi6tXEXoTSNTAuarLsx6jU?=
 =?us-ascii?Q?jaE6+Lz9XuEiai+rWMuda9SUTxz9r86OjBJ0AInCCkhj6opgP8/M7NIRiGUt?=
 =?us-ascii?Q?YKHa201bR3BH06fxODhyDEizfLxMvdumh9E0EmctsGJH7RR5LzOQ441L/sy0?=
 =?us-ascii?Q?uoKUpmXS0pgC3wqNXcWr8Cmiu24SthiZ+KJvdfcTxTMp7eB5tMBUKEYEK4Um?=
 =?us-ascii?Q?KQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: xcE2Vinn4AEL7z1R+d3gvmryNCetXVOV0xAwSKYaI4TSTXC3Nf5UBYHV7ohokY/Axaz6s8162iSpIImflZnCziGDqoIM+NOPAdnYx9BzEj9EpMz46Pmm59B9M4fd9cs+tmBPYuVv10p9dy31Wu+enOA9eSb9oXQsxJaqYbVdcnxjAodfcpuV861BWfCgyMiVIK/7uXMXhKh9VpF3VGFHZGMPxlZFuK1N+8yOgZaxxdQTcd+MRM5NYgOfCRTDumvwzuthoUMFP8G3o4n0xvScQeUYO4qiY4f2pmC2cxNDib6e6WdxtHJ4BJk07zwUzN2QhRdpAi+JqOe3uKUni2Bl4NvC5iN/4XmrrFpjTIBdjNTO1byf+LEwYHr4F5YTxz31HNv328U/Qp3sU9j3lMElwAp6+H+2OTtsIHWvs2F2nLk3KIO3p7U0XBsNcsIJj8noXPUNHY6epmKvY8+m2g/O50TYCcZwDiSssIJcM8NaMp6zZfTfFzoIuEvUY/nBxPwE1RAABFLRVXGLF5J58ziZTQzPnQRmbzB9qECS+K/uPHzVANd8frxZ//tcEXvCy1uH7Yp9lXZjguTWeJ4nmxcFWypKNqSdgBsaAEQ98cCQiVs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 85832de1-70b7-48c4-af12-08dde65cca1c
X-MS-Exchange-CrossTenant-AuthSource: DM4PR10MB8218.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 28 Aug 2025 18:00:35.9428
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: gozdcvD3sk3JhZxINUR+T5JycbIO5sEGghy4zFqYseZOQTOjhjN/TODH7y/NJmEaBORaQSeXUKujeEFFbR6NxU1VehEPtDiChRUBXxZmSD8=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR10MB5147
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-28_04,2025-08-28_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 malwarescore=0 bulkscore=0
 adultscore=0 mlxlogscore=999 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2508110000
 definitions=main-2508280151
X-Proofpoint-ORIG-GUID: -O4MhCB-wzNYfdBNc9SpZMpyIF3oO1Jw
X-Proofpoint-GUID: -O4MhCB-wzNYfdBNc9SpZMpyIF3oO1Jw
X-Authority-Analysis: v=2.4 cv=EcXIQOmC c=1 sm=1 tr=0 ts=68b0994d b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=N54-gffFAAAA:8 a=bLk-5xynAAAA:8
 a=yPCof4ZbAAAA:8 a=20KFwNOVAAAA:8 a=ScamA3sR2JfJjcNNFWMA:9 a=CjuIK1q_8ugA:10
 a=zSyb8xVVt2t83sZkrLMb:22 cc=ntf awl=host:12069
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODIzMDAzMCBTYWx0ZWRfX99Sw52aVGPUf
 EAwqwGyP6bpndNkzqBCWrMwYG4NtwGUYZiAiSb526IB5DSS09hQo+Sf/IlyK8+/ezrzaU03PykD
 SF8fZ2a5iYRlTPKPsVUpYgiTCQXDmVBJQF27wSpF+wEzQfhw8gqFExztYATMrROIiQvOGgACUpO
 x7eeJ57d+7SwiKwwwjbb7vtJ2uew5aBNX6vSYR0HkY5CyK1gkHtQyp+uAPUlfrkym4b06uUpu5A
 n8tTswOJ/cIP8SorjzWaafdcN/zBaUbPfIFiHOYQdL7BUS8eZvvynhxvVuG9KrSzTTBlXCgRwjN
 YwGTigRaPDv1FKjTReTcDfYP1KWPgT3PViOMMTg4m7P4xqBBHYUWg1N/sG98lx/I0l7YeVUt8pr
 CKJ+HwLfRPqMSQbD467SCd40/ZTCzA==
X-Original-Sender: lorenzo.stoakes@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=nXm4fcDh;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=yAuHixpl;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Aug 28, 2025 at 12:01:33AM +0200, David Hildenbrand wrote:
> It's no longer required to use nth_page() when iterating pages within a
> single SG entry, so let's drop the nth_page() usage.
>
> Reviewed-by: Bart Van Assche <bvanassche@acm.org>
> Cc: "James E.J. Bottomley" <James.Bottomley@HansenPartnership.com>
> Cc: "Martin K. Petersen" <martin.petersen@oracle.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

LGTM, so:

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

> ---
>  drivers/scsi/scsi_lib.c | 3 +--
>  1 file changed, 1 insertion(+), 2 deletions(-)
>
> diff --git a/drivers/scsi/scsi_lib.c b/drivers/scsi/scsi_lib.c
> index 0c65ecfedfbd6..d7e42293b8645 100644
> --- a/drivers/scsi/scsi_lib.c
> +++ b/drivers/scsi/scsi_lib.c
> @@ -3148,8 +3148,7 @@ void *scsi_kmap_atomic_sg(struct scatterlist *sgl, int sg_count,
>  	/* Offset starting from the beginning of first page in this sg-entry */
>  	*offset = *offset - len_complete + sg->offset;
>
> -	/* Assumption: contiguous pages can be accessed as "page + i" */

Nice to drop this :)

> -	page = nth_page(sg_page(sg), (*offset >> PAGE_SHIFT));
> +	page = sg_page(sg) + (*offset >> PAGE_SHIFT);
>  	*offset &= ~PAGE_MASK;
>
>  	/* Bytes in this sg-entry from *offset to the end of the page */
> --
> 2.50.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c32d351a-00f2-4929-b0c1-91aa364e681d%40lucifer.local.
