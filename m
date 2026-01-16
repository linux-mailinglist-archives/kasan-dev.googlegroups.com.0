Return-Path: <kasan-dev+bncBC37BC7E2QERBW55U7FQMGQEP74OOIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D88C7D2CB4D
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 07:46:53 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-81f42368322sf1510674b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 22:46:53 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768546012; cv=pass;
        d=google.com; s=arc-20240605;
        b=bSZkTPIDg5y12Hizq8A4cNg3I4RgVxjiLgLNMzStjV9xJP7U5yeJ991HGOJzbgW2eG
         ofSMZYlrXxPx2bCqtSvh6yvwa+blmA1TGiyEzmL0UGw+BCcufu57UJJ84mDxVXm2i+kF
         Uhwu5BT1F7qJ9p6/SUkRYVonQAJUirrXhQL66bZ0ttTzY4bMqXK2nsDFMZMuJHhhexAo
         AZtHi/yNAmMqdNXHAOQjcPRKzOihSxxPc1/XYuq1TcgrP0Wccl+Jce4D8E7ppYJmIrmp
         rpNumjG5t1PYqKeQfF653VXiHoRZ0sLUqXw9RyjyakW6EmntIP0DfScXQIKW6v1cqSRU
         By6g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=G1S08iRHcr5YqkScAuOk1B3xnBZgVvN79YQiOLurcjA=;
        fh=u4vfDk+lRqRyRfvihx3caoumfGtYpXmDA/1Rjr/V3v4=;
        b=DCehPAEE5Uvly5PnfL1Jx3cfvao4Bim/gaQgOWVOwRvz2c7P7fTkqgu9BHwl3XJ9zB
         LiNaYGbhNEZIJBm/SyiLpKqxvf1i8hrb1iGNVwfGAQXVHHFU2LVbnK/MSggDcTvchwfX
         3lj6ZXzo+eiD/SQbldfaqo4BOC2ZlGGtelj1gdRjdZCeqfOFPTnqkSXzt9lF+vSyhtsC
         1+f6AdBn66V8LPKvQm8aR1aumZJzS/lqJM07LQEFIMd7CxclqlSrza91N5XNqk3wE2Y/
         rXFoAitsC7/in1/jaTCL5dwrI58EWmkG6oAkMRxEJAximtoRXjYU9lZQ+flL3X0p/7+A
         GdrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=U4k8atSb;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=M5q2GG8S;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768546012; x=1769150812; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=G1S08iRHcr5YqkScAuOk1B3xnBZgVvN79YQiOLurcjA=;
        b=ebdkjLKdNEtuHQ3Rl9t1PkkCFsM+3E439xkYF67zBN8ZARD65blkdwL5l9yAL/m9+/
         CloRZqjlKDhUJZgqFuZxevexw+XwkZZLKQ47ufoE0OhHDSqD/l5UoD7J/VwbGEDDxfrU
         GpYEC2jBzZB2OA/whK1r0AfpuSd8AymLY7Vd4RCYx3xMDlSNPeNnTcz18FMgTBMe+BU3
         e7xjhiOvQvdDZCBIMFGo2EdZxX5Br2mKyQyu/ZAmozyzbO+cBpYPkbI/7ri1Z2X8mZ2n
         Se+ljcvDlRh5lwlw3IaZVja6ET2QrKxJ1hkUb9SLVtl7xjhbJpBr5P/M8jSZ49lqa3dN
         HT5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768546012; x=1769150812;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G1S08iRHcr5YqkScAuOk1B3xnBZgVvN79YQiOLurcjA=;
        b=Ce6PF4dBHH9ualy0xfamputzZ0L+qwiXwwBOVtm0o8sU5mUtBGcSPkmlAvsMzIZ4O+
         qlNv52uaR8xm80zpWPmAyXIvVyGXn2QdZQyJvs7r5S23Xk/D/CXee93P8Y15g4F57PDh
         aCuuT7TSu2TZgIldN51yFLtiwegk9X3VQmXVGk+fw9HhfV0kZU4Fv6/XNXyNQKGSUele
         7OWDiV1p0lPMxoWjGUMDEx5ItvLISdL0vXuVIpP2Bg1Z7IZwzUZEUQvmnEZJ7xfN3cn1
         kIITAqB9vNlTouTGPthrIVgZknzMiTDTNe7hck6pTEOSd7GoTc248T5vDD4nF1LydmLU
         /I4Q==
X-Forwarded-Encrypted: i=3; AJvYcCWWnIC5cA0Sy3rxwupbu7TgsAVgP3Ilc67XhFUKjTl2W1oVIsNPCcADsEuyineb/ddpPH2jNg==@lfdr.de
X-Gm-Message-State: AOJu0Yx86RG9v2E1jzJ3g4WOm6tR8W2C9kAJStx5aGta00aMdr60rut9
	j0nOGBE3dg2Tc7rufzjkJM+DOrRwLWqQIAqXEySuJ4/XJ7iPmiuZ9vM9
X-Received: by 2002:a05:6a00:14d0:b0:81c:c98c:aeb7 with SMTP id d2e1a72fcca58-81fa177258emr1645877b3a.7.1768546011933;
        Thu, 15 Jan 2026 22:46:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GsKipHhol5HUb5LiMxWPewqgVF9NvOF2xukTnp+cO4Gw=="
Received: by 2002:a05:6a00:6d59:10b0:7b1:41b8:c173 with SMTP id
 d2e1a72fcca58-81f8ee42acals1020676b3a.0.-pod-prod-05-us; Thu, 15 Jan 2026
 22:46:50 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV4Fdgk5uklHUiXKXH8rxgOFjqAA8USkcjUcfmbrwXeNojSexJPqOU/ZFLgqkqBwT+UnHBMTfzqySw=@googlegroups.com
X-Received: by 2002:a05:6a00:330a:b0:81e:f1c3:89d5 with SMTP id d2e1a72fcca58-81fa17953femr1615838b3a.26.1768546010306;
        Thu, 15 Jan 2026 22:46:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768546010; cv=pass;
        d=google.com; s=arc-20240605;
        b=hY9c1KpUX+XAalEbrHMLuTOeqdIUT214h34D74ml9n/Y7/Dk84cYyBiUpMHVOSlmWc
         EurTZsYoFBlwC90yQDDx5+N9SzRtbvKBfIh78Y41KiJAY74TR2LNXQFP8pNJJG4pBJ28
         Z/Gc5W/TPJgT2WkBUc9FjfAyuIICh6daoXBuMZ6kV/56ISLj13V62d4xZwDlr0wortq0
         zB3aRwBMc4sxic/Q097aiNUITHuTjjxDLQiJBgW59gz/ddVIiCYBlt6hYs0QIqoz3QK+
         FXZa8xFdeV0LI6XW3Deb4JiUO3fJkjuEH5bw270BH0J/qphiO40WBZ4E9Lstw54FqXsp
         BCCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=GPnEgGmtlTiHHR0NAtUdgVKL6jQBK92oDBKyb/fUf3U=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=OBZFgDhBJEnfz2doIwm5rkJ/S61msrKjCVD8Swprb7nqpoSA4E01O2AJU0sAbEO0tU
         HtH7fvU5Dg5FVXI/Pv+rtDC/LzyIw/9sqiW1w4yV1ZXfxEog5BfTM2Nv59OJrsi4HLez
         4c46l+AZ/jdbPjc73ouRboqCIh0bnfix4bO5CqpOxiZRWRQ8TOALa17wkCChOjCH8k2n
         nRUMNCpwHqFQny6BWJvDLd/KGWU99bEmxZpqsBtlC5mei46iBktNG2nT61wYH0o8L5X/
         Bh11gIr4sB3eMjHKZXiAt6jSqQ4I8vqeCcJm8OLBp/UarO8NVeCIlZhtKJrvqeeIy+H5
         hUXw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=U4k8atSb;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=M5q2GG8S;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-81fa125de95si48772b3a.5.2026.01.15.22.46.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 22:46:50 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60FNNRd01430382;
	Fri, 16 Jan 2026 06:46:46 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bkre41h2y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 16 Jan 2026 06:46:45 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60G6LXRt004464;
	Fri, 16 Jan 2026 06:46:44 GMT
Received: from sn4pr0501cu005.outbound.protection.outlook.com (mail-southcentralusazon11011057.outbound.protection.outlook.com [40.93.194.57])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bkd7p8nyf-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Fri, 16 Jan 2026 06:46:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Iygy8I3e7abQbKzwgKBmPNTA5Z3vM1NF/kvrglmiYsoQgJrZtaJo8M2RYp9EwjXnVUw5QmH8i6ZMJ0HQ58vDudkCwOV0HETLVZMtW2V7vgPF6QDxjHksSnsYh9pi1+BbDHjR/AowMxj6xOftrBUlxcnHzA//9lzRKQpH4gUCz7Is2OSJQuZaBdOAH0d4rbZ2dnpzxa5w6q0OxV8mljekpXBzEBoi4lcm7m/DWOZmYRwhJQ95KXftvgumc1Lw1TJiQJwZttE7LsZICm/qK3woL+4KTPZYjWK8miWDbQZ9JqUqxIy+A77XRNuLfLcUzUgRyVyERGedAUmN/LOIaMGPsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=GPnEgGmtlTiHHR0NAtUdgVKL6jQBK92oDBKyb/fUf3U=;
 b=OvJve+Lhfr3YG/3YCXk2gxANjvIjsP8o2BamKvKq0U8nVvua/Yl2b3qMmrgbmcdav0p6ZlLhrmnVDA2RTn8h6p1yAXtMQ/Iwsszilc1g7zUXx2eHSWyKbnqAjiFVvW3ww+WYwHBnUTwNO8+mHSA/4NJS7AH64ToeorJPEtg/p5rFBsetzsg0WGVInmxGct/XJPFIZnk5n04lcuXXWx06XbJQMfEWY+osbw7KuJ36rPAfw1zi4dqd2hUoPiB+v4g7+UPnwuKaBM3y+2BO25aznxtJzMam8A3Z06NZR0smCSljAOz7IyTGxTL5ixw5ZjTdPsAmHHt8PkCoCXfA8JWh7g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DS4PPF80FDA9397.namprd10.prod.outlook.com (2603:10b6:f:fc00::d2f) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.5; Fri, 16 Jan
 2026 06:46:41 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.005; Fri, 16 Jan 2026
 06:46:41 +0000
Date: Fri, 16 Jan 2026 15:46:27 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC v2 04/20] slab: add sheaves to most caches
Message-ID: <aWnewyp0L0WRUPud@hyeyoo>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-4-98225cfb50cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260112-sheaves-for-all-v2-4-98225cfb50cf@suse.cz>
X-ClientProxiedBy: SEWP216CA0057.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2ba::18) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DS4PPF80FDA9397:EE_
X-MS-Office365-Filtering-Correlation-Id: c2edf117-9bfb-4162-749d-08de54cb017b
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?yiSFLAko8dJxUnBBLkrOs7JHesJw0+IFZKXQQu1QX0hVe4ODP8QAgRNkF/In?=
 =?us-ascii?Q?rpEmFQqlXzcIMCA7anFXhKuEg0YQ9snYeqKUh6q7kUKFxopL//URS3yCz90K?=
 =?us-ascii?Q?GY+zUxhPdB+If3Ko5RXaIjvH4wkaAFrZZpz/5x/NnvN1A2bBcF5k5ZctTqUK?=
 =?us-ascii?Q?oC1kHWpZ34UZFwgsmcqOCFXETci4vioUq6D1/+KX4eaRvu7LaOAxIBiUZxAJ?=
 =?us-ascii?Q?soK0URookA4cZatKnx5hFmNzjdNg4NCW/VgCSJbq/f7warlPdAuTJE6Bdm6g?=
 =?us-ascii?Q?OstaqmK4PPREjadtBCryP+NK8JF1BZl8V96yqqE3+C8njRoux93KhuRdoQg/?=
 =?us-ascii?Q?nNFUMWT6ftQZyLucgen3Mb9DvZFdutoHy29EBRPCe52jZNhizv9CwYJUZRtT?=
 =?us-ascii?Q?go5W6FS/SKGUHElRWtkl52syipcDPAVYcYAcCPWFlCVDwdT8CiE0ZHzATsul?=
 =?us-ascii?Q?6meGnSUaFj/0Ve2wQy0M9PVx4yDVfZzmr1WKfTmStHLXniXGou8SZ88EHsDz?=
 =?us-ascii?Q?t8pDTUIHnDod15kERUG0MG96qt0kIyZVLLQOjSkp3bY2DYQGfIRCZst09ix1?=
 =?us-ascii?Q?r6i9TRto9cmdOTm5X3mhI9va7kYuaSQkXl+5ZqmFywNxUd0H8wacVlTipylE?=
 =?us-ascii?Q?FqSZqDbVunoaA/vTkYMU2Z6EgOfPaXCPnbr21H00Kd0Y1CfYnnq4HSjz2pAc?=
 =?us-ascii?Q?Fcydq9D3HVyPkPEsR2HxI8G7YS9w17YRZ0C/uoPFPB4RnmrCOlILB40R3eeZ?=
 =?us-ascii?Q?2YRVUN8P2+fdXqkYh2CkumTXI7Oh09DIxIMbs0Z0jp29ehQ9m0KAZ+IFjFap?=
 =?us-ascii?Q?73fwgkjNSqcnyJrwDksygFcvBvmgws/kzSsH3aEjaqE3u7fT7HNPN8pNXoO4?=
 =?us-ascii?Q?OgArOvXm0Cx/fbTDRXAY+p+wCXXVEZDoaYcl/9kyg4bdnwQ4nVvjlCnMikX3?=
 =?us-ascii?Q?E80HWdWUj4pCzdhuda3ccnBJSRXkQq/DvovHA2nO3mYIa/btNVaTktyFw/hN?=
 =?us-ascii?Q?5U6MO8QvNmzZ8AX1NFrfoFQeSNNtwXt60xXlB+k0nacAGMlpKYz6zTYCDgSn?=
 =?us-ascii?Q?RDVFJhPyvkKxiEEZvu1bggFWWbbs0E6a42euQgIxepzD2qXYDi9AxzbZy11S?=
 =?us-ascii?Q?3vCu4IlKakYmABW0TkgkfagM6D5upGFh44B9B1uWy0ZTA8DYYeg9wrSxmklN?=
 =?us-ascii?Q?349aZVDQ/rxr5ka1129rkKcBKk1kblKgk1s7UKWLaWhHeFeWJqLdpGh5I+VF?=
 =?us-ascii?Q?nD/dsAwxP2h7XlbXn1jBfv2TuutO8SP8yCzJmpxnrHo37UnEvqnQKcva2V2Z?=
 =?us-ascii?Q?R6OYnBJdwgxu/h9/oY646jeueeb1LctZcbOEp60LBwEPKtIiHLm5gz66zPcf?=
 =?us-ascii?Q?p79aoyNoyn90OG+89/aOa/EXhY9V5TrFHoNUddEfxw3dFLgQlZplUhBZgqAO?=
 =?us-ascii?Q?q0Uh33C1drOKIigYqGbnQ4iBIovg6EmesbKNCIAVq2uQ6x9R7cpojVHKj1gN?=
 =?us-ascii?Q?qOfcteGuwwPZwx13Bn1DeHHU8kIvDPUIuWap26g3C1WUkegDorbflvWW/NXS?=
 =?us-ascii?Q?mIGLMCw+mnobxikX48k=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?KS+R/TU6ymvi+x4VPArYqNHq69yB/6D/sqpYj4FlI1cBzPS5rlBVeFwZinSy?=
 =?us-ascii?Q?N65FT7ZQgWjlz5qzxc7pOS23wZLDAERLdA7Smg6QHNGIQrLv7755MRUH2LbQ?=
 =?us-ascii?Q?g5M1WmCYLZYxvm71izIa3oEml2U59lzu1VmExaJyXRORIC7n0JdBl3+S0TWx?=
 =?us-ascii?Q?zlp3uKRUdyRXUPLFc0t5zHFQ8PGwsiB8ZwLkLHbqVcfMtmOMWCoL6OCIrio5?=
 =?us-ascii?Q?kYd4WERcJEsGPUbJRyMvJIXcNsC0eyjF4u3LuL8Or6LvQYSvC4nmot5Pi7f4?=
 =?us-ascii?Q?hIwYSVk2q/HewNKiNUjONA8NwZGrIov45HltHWPOFmmBF2H2zRDR5ixqY6wh?=
 =?us-ascii?Q?G3001RpqH+doZIeDrIJ+lZbN+5kacVi7DNh/FpdNsK6L6ZcY+5KYnrqiGMCY?=
 =?us-ascii?Q?cpFzynOkfFWG2Ynd0sUHhtBduIG9GPBVMQULngDlLesPu+j4wy3W3XSXl+e2?=
 =?us-ascii?Q?IKHCtw+Z+Mwm4a8NSKHm9vcSimmNy/f1CuIvEJvhMrVi+QfGHW9qZvlrpR/S?=
 =?us-ascii?Q?Y16VozWxPkqFpTgPY7SraTkRV6NmAs3YElmUfVuElmNEkOnV9V8HhNJUnREi?=
 =?us-ascii?Q?Wd7ZpjqamFMNBZc2V2IKG9DN2sdfAzjgHfe1gtW0SOMNkdhPjY/yza0ilnPB?=
 =?us-ascii?Q?CXPL7I6yTUSreV8LONMLpG77LPcztBDjzl4uqXjZ7V0m8OkgnMDW0DjpF8xa?=
 =?us-ascii?Q?N2ERxyN5pqZyVFe99A5zFIGdk9jzjKITf0c+JCuOwudoUBNY4HQ9EkCju2NB?=
 =?us-ascii?Q?YijJ9KIJd2kvto4K8osA8YYUFjYbRgIqu4ymkKWODtEbdQQzN+/mj44ZIyyS?=
 =?us-ascii?Q?TAV2Hmo39+5mLWq8Pq9HNTUKqtBew6p44Z1SM1NVERC50zn+TgCWse7Zfowu?=
 =?us-ascii?Q?UyPug6Bwfp4Nlhr7+E2YF3/T1IOL7HVSIi9IfEOcendtN7KUXs3dsr60oYpJ?=
 =?us-ascii?Q?RvNlkgi3OFkY0VcKaaZUze1Id67/abYhJy6L6lRtDt9YAF3U6Xu7FL0+5uCJ?=
 =?us-ascii?Q?+2+hQXSz4flIx4/z9Izd1aLvXkcb0YbxqgpRJyBhQDKbW4rR6nSUOawOa+cH?=
 =?us-ascii?Q?hIf1dqg19n1R8WinHGUfKsyXoDVgCgB/JomxMeLwwpf1aiuPn6YMzL+CPiCa?=
 =?us-ascii?Q?NttUxEDrDFnCTnOHa3WfZArZbL5UlP/x/CAv3UUXhiCJcMVgsTuVept3KiQ2?=
 =?us-ascii?Q?xGE09MkYV2qx0RxviVi6f1qoAK0/5s2c+ZT5ZYQfk5vleBcZUa7b89I6CFXc?=
 =?us-ascii?Q?QoiheS3epD0jEyvPUH6fD8xpo30Kv7WgpLGvo6eQd2Pq/mj3BF/lTEW2wucx?=
 =?us-ascii?Q?TVocw3W5oKCvuW/LIGpCFumKkNrRyKBgzvmu5L9yXkHuDp+u3NYT3//MDHKW?=
 =?us-ascii?Q?hBRcJSzOYeqydefeub7XsOnKmBwmJ3Ai6r/5g2oCCjcx6FFeErvG1XZgxF4S?=
 =?us-ascii?Q?o5DOIHh2CsqeFdQVH/s0sS6SZS27rqg+e0aUthe2uvtN5+d579y+EDRHW4jo?=
 =?us-ascii?Q?xbi9JpBmpUxoqzZfeGB2yfEBGUePkpK4UDjxNwQRsBGI6ZgkdIpxm34AGb8j?=
 =?us-ascii?Q?Llt02xlMb50jxERaWS4ZDnQCVyb28oP7whsb5myZg7NSKZLZzhiIkOTshfPw?=
 =?us-ascii?Q?Cvnxu4GHCAUCIh1PMKAkaKh8TYYoIAcj2zGR6HW0r/1Cx3Hl7TxTcPt5HB/W?=
 =?us-ascii?Q?u1xn70io3CPVew/ByA/6M6QfV1KgL0A8LxNSt+o2vsNOJo37u5zO9sV7X2JH?=
 =?us-ascii?Q?IwMe5g+XxA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: TQiuuD3GTVtgMnUMrI0565B5smaLvxgutqmpXzV2EABKeqoInpMc6CBm/KJqgV7llD84ybZfGTokjqqpFD67lkDVD01ERsqUAS+6Q5YUbKTAL8Dn6sfPs+xsagnBcYnSQYpl5lW6GW9Zx+rZk/rNwrHpt3WlmS6LSF7xDHMFHu6J4u2+q5K3LzDZrBpMabaDE/qq1Wc7OIJdaexyhBTjHVIo+1QrwrWwd3ZuymBvlqxz8CxPNCFzD/ybs0vWxIm9gzdu12QJbhVbijacTxa/Hx+UsJU3s3W2xZdinKAX8h8G3UUsEBoPhWjwPZVrjV7tIwZtNZZk34seHJMuyLajPcu84jFXLjSf2T0UYqaa7DC9GJt9n/SI+fS5D+DhvhtWtvld+N0EQMuzw/RrfKpq8mfRVoqVklD5N9vQCyDoDT1Si8UkWIG+Pr82QWdpjCfbsHWk/2wtRz5V94KVTTQ0RSUIGQ6XjDKFppuaWxyfFiySr43EWNHTYsBQPp1G6/aZnkciM5a54Sw1VS1gaI7sXKIJ+eriDDVhWUDCc2us0b9RhyoBQH8f+BcZhtHxDZTxtzcs3wvFw4vvjdJusMDXpnxhJBZbsf/Z4lO56J6xWmI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c2edf117-9bfb-4162-749d-08de54cb017b
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 16 Jan 2026 06:46:41.5109
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: NfGGSwSvsOHw69Td3gDfn9U+q1j8hY1YQ76ZHMQvD8M+E5hBNa9Fkxxa1VfQmuDjf1UEV1EeKyNcMIKzSeHkHA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPF80FDA9397
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-16_02,2026-01-15_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 suspectscore=0
 malwarescore=0 spamscore=0 adultscore=0 mlxscore=0 phishscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2512120000 definitions=main-2601160052
X-Proofpoint-ORIG-GUID: yG2FvNIvlbgfUps6m5ttWVrBd_R2zRXR
X-Authority-Analysis: v=2.4 cv=YKOSCBGx c=1 sm=1 tr=0 ts=6969ded5 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=QznUpgGXYvFiLFJPiAMA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12110
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE2MDA1MiBTYWx0ZWRfX5OhS04nPA08A
 OW1szInXMc+lLMuwCgF1k0uGSKE4aIIjc2SslIWi1A7k+TsOUQlk27vpDvUBYQ+izdbxL7MLNsD
 5VDJ3MziVCwoFM+qC31hCxlfXPHBZ/QEM4Ye9AwlvFeLb/k5HtrLCe1n8WvD8JPhhyn5J1CxEp7
 fBVqCBzEv5bYPY4o6qfq52rVNeT3UGX5VgY+BJeTtVlCjBXIc5s+bWHLWMOhxyph52aNGG4rdkO
 UQG5aQxamTnaPO/s04GWQXuw6oNBuJfZVRTVYZZ/NVjk+5YF9UcS83cKCVaVOjA7U7QYfiyCxkG
 0qA541KoXeBiSBsPjHqrUz3valC5ClXuLs/6AqUwjBGERPz84tCgq4rOZi19Qg7JxkipqzNQWFv
 YSqWCcMfEzUzc5okgzbsgZmvKiCMRpa3gBolmVLuGoaYMdjaBK9ScM31ZTmze9I4NXBVjFT7a7e
 cExyrBHkqnChwZBCBdBqwR+yIwiornsdNmX+diEE=
X-Proofpoint-GUID: yG2FvNIvlbgfUps6m5ttWVrBd_R2zRXR
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=U4k8atSb;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=M5q2GG8S;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Jan 12, 2026 at 04:16:58PM +0100, Vlastimil Babka wrote:
> In the first step to replace cpu (partial) slabs with sheaves, enable
> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
> and calculate sheaf capacity with a formula that roughly follows the
> formula for number of objects in cpu partial slabs in set_cpu_partial().
> 
> This should achieve roughly similar contention on the barn spin lock as
> there's currently for node list_lock without sheaves, to make
> benchmarking results comparable. It can be further tuned later.
> 
> Don't enable sheaves for bootstrap caches as that wouldn't work. In
> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
> even for !CONFIG_SLAB_OBJ_EXT.
> 
> This limitation will be lifted for kmalloc caches after the necessary
> bootstrapping changes.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aWnewyp0L0WRUPud%40hyeyoo.
