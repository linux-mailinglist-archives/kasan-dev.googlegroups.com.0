Return-Path: <kasan-dev+bncBC37BC7E2QERB7OURPEAMGQEF7HEOZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 58074C1E5B8
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 05:33:03 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4eba247f3efsf11555181cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:33:03 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1761798782; cv=pass;
        d=google.com; s=arc-20240605;
        b=XGJIkI5IWmdMa7NzT6xlxPJotNAmSbPwBi7swwmdLCwWDbUnjKikAQCzlxFZliFIjG
         EfISRuGkwLvThxnIIz2eToPce45+XUKtMWPqiZtmwyDKvoZTosF0s3dTE5oIYcMlb5MK
         bXVk7EdSWNwb1+vagypfd6MgliVLjXeHwG0FywEgBdESTCpA7N042+o+UZ+SBc/yKjoK
         n47kiEW1aqtE9KcABkOM6H3M5UAkNa0DWYKjeoWm7XUkCHRh6XWi4566xT4HFkxXqR5S
         UbICpoZu+ZSlDelpDyQVbdDoL3hv7CKhyjaLy2z8R0n1wMIGQC8RZLQCLzTCF2yG4ZVX
         REFA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=J+WfUjvzqTEtQqDvvYE0eeW/CNJpF16GICriCzpMKeU=;
        fh=ssG3ctO1DhIEQvYMLF5pbFn63xHqrSrfCGo4SdqZ37o=;
        b=TRSQTFtvFntUVtFWEq2qWcQE154EWpiWiIEvlubrSRFXwAud5lMi+IcodtL+mMVEs+
         KnvYJKGU0EJg/Px1tVIUSU1shWLZk5xHz0Ib9qXHGWHjLeeOgVihg1dix2uFTQuN/+T5
         xu+p0wAC/38e4D9ObszgfFXYtpgnyLY4iHiVApcH7E9esOKBasDUw790GAaBem+2Jt8F
         rC8gFjvqrVs6UgRmaAdwzKh5sgPGRuqRNPfDKQOzNB7l+hPhdcLH+i9D6xLifQkn1vlw
         TFKWdBi0rRJ0AVtvCYGMM8f/WUU8YKFw9F10si6LSBJKDWGeR4IxJ1NEjnDn6dISCjrQ
         RVdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XXJ7Lj9Q;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="cvIWb/EQ";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761798782; x=1762403582; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=J+WfUjvzqTEtQqDvvYE0eeW/CNJpF16GICriCzpMKeU=;
        b=ICM3QlKhfsIwq437wEowWovHn1esCwQxEBpewEatgmeX+tXVwvywzecA1tE0XbEw7o
         PWeqnEphRXBbUON0IQEUL6R+eiurmg2q8n0p4CnZvVoh2iTt2T2X/v/I8mUr2it+5zUH
         KT1yWvHzqQo4YnqNfMcJsxVkL35gV+1ghZZfxe6xnY0Sm3bo3RrvWTQDoXnqWqwXuwmJ
         VAnGC/pNpo2RJXIIRoOmE2ST8/epFsf8g6UNEqa1uuYX7LW1TIEQPJAb5QE3On55P3xX
         5VE3cMcA/bvIFvbqPVniU17txT7w6VtMfTtWkDDhOrfpvTQaIG4mBvWbdIXjd4sAu2vd
         rceg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761798782; x=1762403582;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=J+WfUjvzqTEtQqDvvYE0eeW/CNJpF16GICriCzpMKeU=;
        b=kdbx+LW12u2RGi+3NsZgas29SN4eyZ6KAzHSzHqREBNoXOJL5JEQtlSppzRzipJSzl
         wSzTvPpSaehrRiVQIhgP31iXYnWE5Znk3jM8g1e8i1HeUr6ROwJsBGFGxtygAIN28fV4
         abgsrr9mRpu9rFvUv0S32JN0ZKfvd33eD0spCFNi/E82BiCL/q8R13OCqNg5CqKFkvqd
         mHE4P0qgpDV3HEE10oBbiw2nahgUKWlvvxf5O61kXc6bDiVeCnDmvrmfD2lZhkNXHX2S
         gQ8YkSUBEvvLniZTjxER/ZT8vg9WHUsF/DQ8Vgjy/ONWjiWRjjzJRlRHE2io7W4riNUe
         2WhA==
X-Forwarded-Encrypted: i=3; AJvYcCUCS19l/9N6c37yXn3iIn50GbtFK/1q8yexRSBgSt6P6AeMxrvtbyi8Awob6Bo8vaRowHy+7g==@lfdr.de
X-Gm-Message-State: AOJu0YzXlENZtzPeHtRO0tYmOqr955dRbNpCmrGkyz4pwlwHHSghdPV8
	PjcFaUnWJZK3uSaqJmjEBIDAjaWZSmzfv05vnWjn66mYTrhbtCxj8MVA
X-Google-Smtp-Source: AGHT+IHM1qAlotGyUZE2orCrX0aYEZyHlupS2QVZnhiHNodrSGjtczystli9pO1DC4tuzQdpbmSzjQ==
X-Received: by 2002:a05:622a:18a6:b0:4e8:b42c:e34e with SMTP id d75a77b69052e-4ed15b75c4cmr63239951cf.34.1761798781839;
        Wed, 29 Oct 2025 21:33:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zy8ovSRj/5vQF6fbhtCStsStw7HEOvuldt99pZKrDBNw=="
Received: by 2002:a05:622a:18a7:b0:4b0:8b27:4e49 with SMTP id
 d75a77b69052e-4ed232e8bdbls6818421cf.0.-pod-prod-02-us; Wed, 29 Oct 2025
 21:32:59 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXQNCZwsYyBGokeHEm0E/LpjOhE72P5XQTZTlOYMEmlw7CgI7+2xBUJOaGQV7q7u/wGPcH9ertapf0=@googlegroups.com
X-Received: by 2002:ac8:5814:0:b0:4e8:92ff:753 with SMTP id d75a77b69052e-4ed15b746e4mr73857181cf.24.1761798779157;
        Wed, 29 Oct 2025 21:32:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761798779; cv=pass;
        d=google.com; s=arc-20240605;
        b=QgexVEmYsb4rGAT5AO1NPJF/8tTRN0OpwRAduOozIp+Wb5af/dqtJIRhWc/I/NZXn/
         5W5dcuGOk6dJolmM9WoFsmECv4/5zOOyAJVzzokNaW0HnubZ3RsUby6n3dGhOS22WBFi
         hOH282ImP4ICUTKDesQJHlQAQ7lCvxlGNtDiFlGO090eXe3Yzj4BP5swxWHnaG+Quc/F
         isoZdReScCVpKRAp7OGRezCQbxxFDk3T1TYlxUQ+68ASuGsjWCTR0Ciue5Vqq4Xjj5Fj
         zB1IoFGuYrUK6Ke/HSXBY8ZB1d6VDHP+4WByEaaHjRAzWVp3uKYSJ5XRFAkVCYeByRbX
         2B4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=+ogI3lb+cW5fsfbaDEe0NNfBfsfXnLrxe7AVt9I75jc=;
        fh=ndziwN/lmeFpSDyV5btdRc0hszqvDB1uukrSsGeZypc=;
        b=cuJaehUvglXLqVPSc/yLKyb59AAJCSP67t7x3oJlfJ14h7wvXhRt5ajBAzJtK/mQho
         Jia0as386nlLhIyT49kZbhZ+1RKeku1e6ic2hvPQbqpQXHG7dSdBR+31Zc6bsYE1jWcu
         39/jJEGabhvVVPIzvSU42EBL29Obu90EDQSKbJKRKA9bcow6B0WrDH3NenEqLBvbe3UV
         n2Gj2uf01LgDXQojXeyQMnpnu6zkuLTmOHDxb1JMBHG61x93G+8fZ22HbjOcwXG4Qb5b
         ZtmxXf5U+hH46GtX2UEpfcjdrRW6dzWXp8yTpCcaxznDsuszLSetooMh8eEGDjSAqp/E
         EG8Q==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=XXJ7Lj9Q;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="cvIWb/EQ";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4eba518f66asi1585191cf.5.2025.10.29.21.32.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Oct 2025 21:32:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59U48bdi016648;
	Thu, 30 Oct 2025 04:32:55 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4a3y0304e2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 30 Oct 2025 04:32:55 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59U4046x031557;
	Thu, 30 Oct 2025 04:32:54 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012010.outbound.protection.outlook.com [52.101.48.10])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4a34ecte2p-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 30 Oct 2025 04:32:54 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=CYzC1TcjztWmT+y89ZDGp2Ic6ssKxBTryW7s2JIMcML9X9KDJwRHaUxkl1bN1o8y6S9HqED0TWSCUO2eo1riKThp1SPveUY9n0sS1jwdb5jEgQcbHo0qiAXdbMNZWwHMgwYGlhd4cxSTpoBugb/OSq0SUwqGWhe2lmh4n/Pit9erAEEegdRh0ei3jpqBndfM7FGA/GCcrCkiPGTjXpltePk1snkh7s4pitErhgXB3sgI6s/lkWbhX5+8X1eluW1IKP1CXGOVgSU+I7uTl/cLgk93nQKh9G1O44BHGjgnGE+NYf0LCBzYGv6y4zWxkFuiIFZtIt9b/vSBE1foRLp/Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=+ogI3lb+cW5fsfbaDEe0NNfBfsfXnLrxe7AVt9I75jc=;
 b=TAHY3M0G4mRtd9KYUOwxQc/z+6pBk9xdQ5yD867Z45M0ngdr3qUD5i29Ahq1JEh2BjT1VTMgI38+4f428KThp6hw8l2lzr55qLs/lYRoU8FWP7l4t1NGdWlA5/actowdN1yA5BNY52kqkYAO282Td/0far45Iur3PVpGhx01Y2A3x1Ku63Xe42+Ii3ybSxxMP1J4AW0HYsPB4s0QD+kxqHT8moAL74d0EDEUcOxA7QsnjhnyZSxIQgInalZgpIus2zoGj96Ac+0StSdC59RemeirOas+0278kRjdszoKalL7siy7mCx43BHusFOY3cZxqfwRquWAQHv5isSW4c/xZA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CY8PR10MB6562.namprd10.prod.outlook.com (2603:10b6:930:5a::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9253.18; Thu, 30 Oct
 2025 04:32:48 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9275.013; Thu, 30 Oct 2025
 04:32:48 +0000
Date: Thu, 30 Oct 2025 13:32:38 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
Message-ID: <aQLqZjjq1SPD3Fml@hyeyoo>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-10-6ffa2c9941c0@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251023-sheaves-for-all-v1-10-6ffa2c9941c0@suse.cz>
X-ClientProxiedBy: SE2P216CA0140.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c8::16) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CY8PR10MB6562:EE_
X-MS-Office365-Filtering-Correlation-Id: 148339f2-9708-4c31-60ff-08de176d6121
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?/U71V2qCgiKM41BkPa4DCaUphSz+Y7Gt//xEenqFnXMIubYlcr3bOGNQyeVI?=
 =?us-ascii?Q?BkiE9f4P0rLWxsstT7ixj+EpinJ/KTJAZdhvmiWzhrpCquVZNzuc/eVL3CCw?=
 =?us-ascii?Q?fsrl6HZTCWra8Nwa/m9k0z250qGSPJt0w0djeQ0Oqe6kY4rsVf350HHI5Hnn?=
 =?us-ascii?Q?JVc1RvF7IhpAcNw70hkRcG8F4UMGKn8d+2CjTgaLGBlPYR5soLzpl9aI4Mff?=
 =?us-ascii?Q?5ubVcYK1t6nQhzNrYFHNINHRVcN/9rny20zBLowHDWtrvP6TAWoPZRLpJkyM?=
 =?us-ascii?Q?wKgCnbDfbyD1vkdtN5l4Za7rM2v5g7fadVdZrsDDVKJy5Op8v2EjVglc9hwp?=
 =?us-ascii?Q?TOq96TLY4E1niJtXFYNHoVNf1Fl0SDDW5dT8LTWCzz7elrQ1Xv1o6bI1YZDd?=
 =?us-ascii?Q?nxFZ8/Txb7VlqtvuTcpOzxKVVTc/Up+jVffxoSxCYHnu3zanXQQ+m6RhJ+nS?=
 =?us-ascii?Q?jmIdvqSRKHgymoP5hCBcQZBL2mWGDTQBU51fBGk2JlYc/Av+KGwWROmAoBqQ?=
 =?us-ascii?Q?u6qP2nquLRfbKaxiepIrQp4aoWKh9HA9KQXk0D7bT0cyvVCwW6vXGwtJjl/4?=
 =?us-ascii?Q?j6Laj7vgv7tFPZl3pT3w383V9B3ZCWPKM67xa0H+FN1IvqkwZKMpDIKVrbe5?=
 =?us-ascii?Q?C99FfGSIunuygyji1PIU2wMCavaoqwhd6mP8zaQfgxK7PuIOIMqPe5h8tkgr?=
 =?us-ascii?Q?2hPIFzix0yoFt8DMTbQ4QdKSdwt3k3qVY3wWBaLbca6dJVfAA69h+4spH0rr?=
 =?us-ascii?Q?jmQbgZ7b+S5SLikrFr0WTA+vPVPFMroC1ydAHnend2mrNrGT9V6gEqbXy71m?=
 =?us-ascii?Q?oINmSWSfJJmbxEiHPVOmEFKqp+6VPQW36JvYLxAp/fSio0h//kiRB2pSU8Dh?=
 =?us-ascii?Q?r8XC5jDjbGuwR8h1vIyJuyxDawp8AHSvOEofcsSY58gLD81OeupR7DOdQR/Z?=
 =?us-ascii?Q?4zf5wQ8nQi4C+LaPcXqkXIAAkS5s3mB+P06QFqHGOXW0mBpORH+BPcSS3dBx?=
 =?us-ascii?Q?O4eORMPeTAxh7iHdX2JA8I/9HdTbTcL3QK/2IRfy3a8yimTH2Wb7PASxy47I?=
 =?us-ascii?Q?8EXyBheOqIDo6vXJrsx1mKAoJN9Az9WwnuSPqmD83tgL2QzcRKRmu/E2mE1G?=
 =?us-ascii?Q?NnnWDokDSegZ6yrDsH2B2tfhsKmjpOj8GrfCI3ekWEyHlLh/JcM9jmtqveZF?=
 =?us-ascii?Q?vX/mWrEX+dfZ9XTPv3x8ALFY3/n3T+kVvyKdq6NeOG9Ssx5W+DD2bnOSfxUQ?=
 =?us-ascii?Q?b+BCrMTPw7D6YJcaN92wq6+x+nZwQUlaGjWRB5mSuoo7F2v6EJVAW1BGYE1D?=
 =?us-ascii?Q?6Nc0fKgAZVqoe+3Y5ALGUEJz51SD78pSMD4Y1i/ZlMcanFkQsX0VZxca42YD?=
 =?us-ascii?Q?iWv9E11WS/AMMoX90+Xq2lnDKAPF4F1RucpF2GBkFbFhYQlIMDrQ8rXgEeMJ?=
 =?us-ascii?Q?ROfk+KebvS/dL2chiBDJtdavzvRAMH7X?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?GmppeAfYCMyLbVaJ1o/SKx3zrgZ5OyWuPh0y1PktAJm0Tp+wPUHGZ6vDgE7M?=
 =?us-ascii?Q?IvHfsc5sXdZTAgzkyLmsqjlU6qnjfUxGhgq5K2okynfU1L5xnwCeYE6CBAPE?=
 =?us-ascii?Q?BxfRcs2Ktge9Gi04TM9PfZtEzDnzUQvvYSle4d37cFQC+GlDXiSNjIdtyCsD?=
 =?us-ascii?Q?NLOI5NlYgzSE7bqkk0ukrAjCM1yiS/L3AAzzzo+RkKnmtN6CFVMRWHmY4TYq?=
 =?us-ascii?Q?feOq47qFj5igcDrA52Lgyqh1LoZhcMyMPxWeSvcJJhAOms8YxR7QXzSNaSZ7?=
 =?us-ascii?Q?OgCkF0bb/GiNhZXMZhydwmIcgVqRCyW0d2QtF6qqMZLE5uKYOad651zqmgBj?=
 =?us-ascii?Q?15/xM8tCRARgEpDFdpHVHqGwGYsSaAyWfvfbA1X/psMdVAMNYo8giT77zW24?=
 =?us-ascii?Q?Zt15w2BRiZPFgREZqiQ8mkpJ5KQn4Nci/kRsCYQI4j5GthOjNi1Qem7nk/ul?=
 =?us-ascii?Q?f0EAbReRl/2ufd5JY2hwUDIjcTbVidx1qOt2TS6q+yxAxKxwT0JIt/ffle9L?=
 =?us-ascii?Q?+AvtkrD0nKVFNNRBXOV9qkOs1vWe4rA9irgjuMzGKyVOHhmPugZxfEY8fhiF?=
 =?us-ascii?Q?WE6LFKDGjGpnDh/9TMxaM+/W+YoOc4Zp4Oj4UkvGOeZ6A2xDF3GXRT3fAvU3?=
 =?us-ascii?Q?3lr09PcHKbDsFBfRFcrVGGIkFWoUioJIouhRmbw8kudxChJ2Idr064cSrrBJ?=
 =?us-ascii?Q?vpo8QnbFc/vmPTZNqxxIUxDDENY3cWLxltpgFnGfLMnjyCgvJm0JRWvwnsAR?=
 =?us-ascii?Q?Z/WUVB95wbov+gBq8b0ydqbDhzhCRUXE4seQcPabA2exATa/BR2l8BW7pYz+?=
 =?us-ascii?Q?Uc/NJM5R9rePRWlSR9skW9rgyFfSeNij0w5OP5vYjZ5GtNcTxH2ku4TNx8EY?=
 =?us-ascii?Q?9yO8/A2hpolfpTX3P6GsfwHtbi6pm4PAYQwAsZ/2Z68Bx266E1B9Vt+OwCQV?=
 =?us-ascii?Q?gdokf88O4tmernEFf6mNxi1VrygKb3aA9RI1G8lYK/x4phViPYzHx3FFdgVT?=
 =?us-ascii?Q?WWX27UHcK/I2mou/oCWpV0BoEiDhQFEB07WMMELhEVjq3Zvt6FqxsCqpVQ+/?=
 =?us-ascii?Q?qjUXLjYiNaCgdKjhbfymcAaQagfCXVMzrctLy4Lgmq4yvREsRU4fNafUahrr?=
 =?us-ascii?Q?xbA+hWSQXoxLFPShDK5DLJSqTOSY89yCnXX3RJdgV4EMD6hCiU6s0VM+Bw2z?=
 =?us-ascii?Q?eEiUl4HSJnNsoG7WA6o0NxiJSRRCvBs5FXUP3kHxw9pXKYA/yhSJDd4ljN+h?=
 =?us-ascii?Q?xTDyJRbSeAsvezZhExj0ZqYfKacn7b0hz+eYcGye4x2v+A0VlwJ00/DEJ8oe?=
 =?us-ascii?Q?cagDT5Wpp5DFSgqtzqK1QLJPxW1n/j6eLjdXgZweo8ve9vszXBKaZIhMzEoL?=
 =?us-ascii?Q?IAyuqu9ZDugqfZAx4eO1lHze85AY4ksJpzGNv+gFwsMxNNlXVO51eRD6bY4q?=
 =?us-ascii?Q?CnUvynUh5DWSl6kKWHRR25tfJF353W+KqQ/7+6YNyr/WxEhxUnRPYa+jn6Az?=
 =?us-ascii?Q?gFdDEKNYZmWaRhtpSN9QVumSofX62+IEHpwVYT/SOSHLgGcLetMK0WpQ3hGP?=
 =?us-ascii?Q?K8WMTVsCLTcd7uwTDTDsSVvHMu/9qE4FmWkkI5M1?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: uQ2/dnlGbsSwZylXNZLGgeV4XpbvB7V/nUCt82LnicZsfxRr+YPVOih/JVIzl7RTEoIiPnXzfwAvcIIw5/8IN7QqCLhFFIbUrZz+LxP94IAQ96yFNJbtIWYopOpRBsJs4Fegg1zLQ/Y/ik0WbtwPpxkAz8sxKaA3KDYOmUyPK+QGarv5Oc11WFjpyATQ9JN8d3kVJMeIJwOa80/U2oiU92/M/hOs9WD3cO6YbEAD/UwNSltQEeV4Iwj8ilK9xG4JzeH5vu2UiGfM1O+3vYeTCUvchnlUl62B4Dh88Ae5y2eSUBYp8H5Q+q0wq1BxkCbSACu8DbpMpKx3cDzAm1p+V2VQ6nhWEswupok0VMNSPS/zb4iVEaaS/LL4F7Hp1O4xEXuAETsf1tRPTq9ydpLMZc6rY3oTq2JZsrUNOuq1LI9o8qp+t5A9I5xAg6HkAHg6SHs0G6/2hM147FeXfNoHsTZHCJ0d0N0d2NQuk8Zx6bWJ1OjxLiSu2gTzqkEO56gLTqcyzSvbHOOF92XgXw/IrhaXBoeufAR1bawlUcLtB1KMCa5Dzr2nyfz6bf+sjwZJ5Z+y+DcyAzMqfVDLnZ4fSwijfwgViaHoQ84JUsvYUVE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 148339f2-9708-4c31-60ff-08de176d6121
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Oct 2025 04:32:48.3809
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ZyTgAySSBq9ozoyGVYV/qzQsFPdcJuOVWgNK5dAr8xKrURewWAH559dQcs6j+CJsVqUoRU/CZpTri6kjokOgQA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6562
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-10-30_01,2025-10-29_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 adultscore=0 malwarescore=0
 mlxscore=0 phishscore=0 mlxlogscore=999 spamscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510240000
 definitions=main-2510300034
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDMwMDAxNSBTYWx0ZWRfX1VFrwFPBW4m8
 HjDmYExmGp3tT2EvsqRxDjgpTN0Bwt7saYVUAlf/EmMANJQIO0SSBLQHBCkSkYjUM8e0t2WwXc3
 dlGjVNg/OwoiJoX9Zm7UO+eN1PzPRxF/Ftu1auxfgTu4ou1b+6cZ1z4nT1vyXXr1CkU8tNf4a4B
 AnlQJHLikMMmyzsoAIyIYQadbpix05DZJSPDLEQQ4vS52Fap1v0XFhlV4bI6TV+/GwlWSZEUjfj
 KVBIJnmYuluywDU9RleIHgKbj6bafjy2YJ6+8xFMvyDg7ToyHJvo3zsqe7+NCvQ2PHbyM4hqwJC
 lTYXj2V0wVDzyEGtCQfF9xqXI6dbUG6jAvIolkXej3C4+n4kv7ROsBKe865Jc5RvUfkZStj2Cg9
 Kw83AqabUlKPPS5IYFediM7Ek9LtLZcBpfZ8r37KWcoRHYPtfs4=
X-Proofpoint-ORIG-GUID: L2Y2yzrG8SVbLKrnk1O1_OY3ZsPC0Eqs
X-Proofpoint-GUID: L2Y2yzrG8SVbLKrnk1O1_OY3ZsPC0Eqs
X-Authority-Analysis: v=2.4 cv=KaXfcAYD c=1 sm=1 tr=0 ts=6902ea77 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=0VcQ7Hxs89gHCWlLNQUA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13657
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=XXJ7Lj9Q;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="cvIWb/EQ";       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: Harry Yoo <harry.yoo@oracle.com>
Reply-To: Harry Yoo <harry.yoo@oracle.com>
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

On Thu, Oct 23, 2025 at 03:52:32PM +0200, Vlastimil Babka wrote:
> We now rely on sheaves as the percpu caching layer and can refill them
> directly from partial or newly allocated slabs. Start removing the cpu
> (partial) slabs code, first from allocation paths.
> 
> This means that any allocation not satisfied from percpu sheaves will
> end up in ___slab_alloc(), where we remove the usage of cpu (partial)
> slabs, so it will only perform get_partial() or new_slab().
> 
> In get_partial_node() we used to return a slab for freezing as the cpu
> slab and to refill the partial slab. Now we only want to return a single
> object and leave the slab on the list (unless it became full). We can't
> simply reuse alloc_single_from_partial() as that assumes freeing uses
> free_to_partial_list(). Instead we need to use __slab_update_freelist()
> to work properly against a racing __slab_free().
> 
> The rest of the changes is removing functions that no longer have any
> callers.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 614 ++++++++------------------------------------------------------
>  1 file changed, 71 insertions(+), 543 deletions(-)

> diff --git a/mm/slub.c b/mm/slub.c
> index e2b052657d11..bd67336e7c1f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4790,66 +4509,15 @@ static void *___slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
>  
>  	stat(s, ALLOC_SLAB);
>  
> -	if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> -		freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
> -
> -		if (unlikely(!freelist))
> -			goto new_objects;
> -
> -		if (s->flags & SLAB_STORE_USER)
> -			set_track(s, freelist, TRACK_ALLOC, addr,
> -				  gfpflags & ~(__GFP_DIRECT_RECLAIM));
> -
> -		return freelist;
> -	}
> -
> -	/*
> -	 * No other reference to the slab yet so we can
> -	 * muck around with it freely without cmpxchg
> -	 */
> -	freelist = slab->freelist;
> -	slab->freelist = NULL;
> -	slab->inuse = slab->objects;
> -	slab->frozen = 1;
> -
> -	inc_slabs_node(s, slab_nid(slab), slab->objects);
> +	freelist = alloc_single_from_new_slab(s, slab, orig_size, gfpflags);
>  
> -	if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin)) {
> -		/*
> -		 * For !pfmemalloc_match() case we don't load freelist so that
> -		 * we don't make further mismatched allocations easier.
> -		 */
> -		deactivate_slab(s, slab, get_freepointer(s, freelist));
> -		return freelist;
> -	}
> +	if (unlikely(!freelist))
> +		goto new_objects;

We may end up in an endless loop in !allow_spin case?
(e.g., kmalloc_nolock() is called in NMI context and n->list_lock is
held in the process context on the same CPU)

Allocate a new slab, but somebody is holding n->list_lock, so trylock fails,
free the slab, goto new_objects, and repeat.

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aQLqZjjq1SPD3Fml%40hyeyoo.
