Return-Path: <kasan-dev+bncBC37BC7E2QERBRGYRLEAMGQE3N5XIXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 61D25C1DDAA
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 01:07:34 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-8801c2b9ea7sf9278146d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 17:07:34 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1761782853; cv=pass;
        d=google.com; s=arc-20240605;
        b=XRcHlwE3IHIEKyfYBAZOW54Mi2A1SWGg0rk6zf1RwtHMFTAEwwaEi61fPl4yT0IVNV
         5YBgfHsZN2RdqT6lt2ZihamPvuizC7MWJ1FKOs7nr6zDnG/SnJ3ezIRE5ZJ0tYoZeTKV
         f3TwX9lmOKAc9mIiEF3oYcpA1DCHNIQU4LgNJxZmDWu+37nBocww7TxEkaSmuih7GVGP
         ngBW9gf/LI2oI6/WExnC4TIL6FpMALEtT+fjoTgCl/tcRtGu2UQ9J7qbZ4HKP4Dy7aG3
         ku2dXJKQaCnW1Wud/9mviOnyzk7AC2cjfst3f+Mz1lDBmMlWs9Sp2LEM7VtUShhTFvTI
         QSPA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=swt9Sw72FKNUMCJbViFVB69sITKO+ZiRCejWp1dXLm8=;
        fh=JKnIh5/GezFjqqNnSy6Wyv1fD9ti+6xVjRufInjPluM=;
        b=K31RfqJdJmK7jTtr6640AkSkP90JapKXstSuT9HbWSX//h7E7BtEkFDhdBXZc3TuE+
         llMJLkNyEIvuBqT2o+EW1rVUUuEYncyd1JXwYXjLRYB99cvV2fSSYFn0G9tI8GKc/fyh
         SjL7azHL4qB4VFuwLUs8Ph56U38wHdTTVVSVDxlKnxxkCGbjhC+j7pOxjkrunYFHiZLP
         sllQ2jHI7noq1uJd3OhitUf7Qa9mJ/0+zt4LdQhZJobMpQ/US0hd5TP+nJgxrReXY4Gb
         +JYEBKenRI6DzuOYBjrSwepB8C++zf6bCkqU/F2h7Jjm3cnA0WPo10sZn/KC+5M7s8+E
         xB+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="LWfb/41F";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=OGJgrK23;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761782853; x=1762387653; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=swt9Sw72FKNUMCJbViFVB69sITKO+ZiRCejWp1dXLm8=;
        b=HQ1U8xWF1XA+uCr0c95yv1rHRkSe99BN7yPe6AqSoUls8xQBFlPJqgA5vE4RMWT56A
         TXo95pUZndbjw/8BYgJaGQ11IDH7gVMgIzfCuwDJW31Tc6J2cqddxq+RlBGiKt0SkD9s
         RKIa4BBFEn6eP5ORGc/D9VE8NxQmjgHh4mgxPPJr1ADJgVDAuDjCHjlcYorQPGPa6S7S
         832PFnCs+PkYr9PwYAW4UG+QQKjw4ESGwnAKVsYH643u+WeQbq4OWYWSwKN6YCq73y99
         v+NpKh5LkxATdggvZjLhJeEXQb2o78zFaO67X2uVfqnQTFfWJmL8+S1ugR7rvSitAoyQ
         uZgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761782853; x=1762387653;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=swt9Sw72FKNUMCJbViFVB69sITKO+ZiRCejWp1dXLm8=;
        b=hkmRfRzWbbA8CLkTY5DuZorWiY5MaDzIy5PduXVNLVPm3zjfcuBrjJro3a1ML4bfx9
         NbHsx0f5hOaPSGWjK8tVIBjB7z5PMGETzlms7DAyZveXv2SZ+7ZNmnPhQB95Zjb6ewjz
         Jtm7M4Vt/SMooAFve6iPd3RayY1JQABohgQBOab1BDZPNHmkG88ZDrtDWYJYTpJqXVHf
         bOm5g5ys12uPjdqHJyqtm7RJfODLvlddqONV+9nrKy72GwWebyfWqEM6dQc3lVdMvvls
         CIhWNnIhgvIm/iAlqryQg/21V0Q5inbAontonsnuv9K7Ky32b/WwOG8oB41isABr+fSx
         CuEA==
X-Forwarded-Encrypted: i=3; AJvYcCU5vi4u9pWkbnNZ3U8gGKXtwCZ7qdYq9rwzd344WnqeI7iaFoVoscdAl0fdDgFHSdJJHLXCog==@lfdr.de
X-Gm-Message-State: AOJu0YxlgSXXH0u/Gv3BP0XngyySSRz+fvrdYCgHwzRSJBG773HgcHXT
	OM4zgZRGIWSMkaHX/+iGNLVTEvlKXE6hRCfYKVMb1Zaj4zo3wIpiwLO4
X-Google-Smtp-Source: AGHT+IE8/F+cx+5rnqy4ZJ5dByjFUu178Gq/qZLC2FMXZvNdKZE0bDBpscTigKBcyoo07uHBdnwO0A==
X-Received: by 2002:a05:6214:20a3:b0:87b:e8c9:c484 with SMTP id 6a1803df08f44-8801b172f2amr20615606d6.20.1761782853163;
        Wed, 29 Oct 2025 17:07:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zjg5XQX7G58xtzVToDTmEXbJTVylI5PM8aIN7lOGb+BQ=="
Received: by 2002:a0c:e00d:0:b0:87c:2475:85e5 with SMTP id 6a1803df08f44-8801b34911bls4264036d6.1.-pod-prod-09-us;
 Wed, 29 Oct 2025 17:07:32 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCXBJKu4qQrrMam+iuBh/FECBGxNiN9mEHU4x48BT7Hhb9dUhFFO7IltoA6jdTGKjiivq27THiYytzk=@googlegroups.com
X-Received: by 2002:ad4:5c46:0:b0:87b:ab40:ed72 with SMTP id 6a1803df08f44-8801b12f0a3mr23752936d6.12.1761782852128;
        Wed, 29 Oct 2025 17:07:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761782852; cv=pass;
        d=google.com; s=arc-20240605;
        b=lm2cViOVnsrvSRkUIcCYO2hlDpxJbJFnEnQjcm1Qcju8G/uMTvr31L9bW3h0qyKz7c
         1eIqD+P8uJnwUBl14HLW7b+UIq/pvfkzGIDCrW/O+3zQW0+JyAhso5qYuoqpAjOS6U1P
         oX7mz0oIMrfpxLVr0AwlhxzgX19DgpzX/V/qbqmHEktmTaPiWDdsp7t1lLWTjp89SAWi
         VTMujHNPIQpj7x8T6ebMwLV6Zw9LlfgRHgpNSbZo+YPVvUDBJqH5I5dyJBQ6d1vHHREQ
         725NvuhGGIx7nWnAkY3lEztXav4rN+uPEufhSkDpjB7XSWCrYiEUQcLGDGI7DTmwcLxF
         kJaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=9xHUxtnOr3aoAl1mVpMiDba+KSMiMWNpBw1//xzoUJI=;
        fh=ndziwN/lmeFpSDyV5btdRc0hszqvDB1uukrSsGeZypc=;
        b=dbV3v5yDn1WJ0QxPMX5455BlD/DJe0WdZneBdfn8XLeT1mRZaGl542zzxlTuKnzayb
         mpZowxBhnC+JrnJ6KRqO9/JJkSNsTAnzre3mSPm6c4nYY91+EPEfxK4eLOj20PInJ31Z
         bKg7Jr9f1PdWSDHmhaO/NoKJJa0/8L1v9MaSKPRcVVmS8zc59apLBd1dPRp0UdQhzJD4
         mx4hDl0FrVVDbwODYfHcIxprdSrY9eOCUEkuk3UmdnyuIN76EPn0IX+2CZoenmL1QSNp
         5zAh0RlR5a3UByRYq+s6Jo8GDXovjRJzckVz0zzeHZgG0ytNjey7NC6WszQAIpLLDFcc
         e/qw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="LWfb/41F";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=OGJgrK23;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87fc65e864dsi6708716d6.2.2025.10.29.17.07.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Oct 2025 17:07:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59TKKIE6025166;
	Thu, 30 Oct 2025 00:07:29 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4a3c3b2jyt-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 30 Oct 2025 00:07:29 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59TNl75b023073;
	Thu, 30 Oct 2025 00:07:28 GMT
Received: from sn4pr2101cu001.outbound.protection.outlook.com (mail-southcentralusazon11012053.outbound.protection.outlook.com [40.93.195.53])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4a33xywgsn-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 30 Oct 2025 00:07:28 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ZkYSO14Q/z1cKe+7QBWWD1UcAQHa/XU+jAcsaws4//89q0tlX96N1vhAY38SW5xPtDsKs6lOTScTQKcvY6464WAoHb4UQDB0ptG4nEoChf+tYT3G9tNw7uhTVJOGW16w5sFgp6V2AF4Jl0WW8b4vzn7HULgPB263OEaceaE1ENDAGmIbZdR12cWPh1o0ermnlEvGL9QHWlyjB8A8P25pjdYgU8jd3+kz/JAPuF786T8XdbDLT1OlKcCu11oU39aaWv3MBfoSmYREcnUTfe2pwaGtbE9neLMWM2Uo1lye1sdr5Mz+4s6hQrjpOz8pcRQfzxYCoOBIpzSZKMn2l1x+XQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=9xHUxtnOr3aoAl1mVpMiDba+KSMiMWNpBw1//xzoUJI=;
 b=Gbuy874DjAPEqmNAKMdYU5utzQNpIUGghu7rEKtGqlWum2hcOsnxY53HjnApXNj/sGIw4X5b9hGylxQP5bDTBYzTX0ZyI643dTY57+tbzm7XvdFkXiZ8rv8Gct7MtWfQ1pNRpzB5Um3+KZfLUeitncMiM2SS/E6/yyK4So7C+MryDdXqG36ymEH2d5l4GLS5tcVjZ09Ycj2I5rnrTwgh9FQDmfdBEPTKDDACrb1dGyorF0edpg71T+low933ajcjxp2AFVUZsXooUxWN7Kuwyplm2Q5f2tPOScLdUKZ+4d7TlLLDHcTi/QtYtEQCuN8f/qBIb62m56w5ZeXA/JLecQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by PH7PR10MB6354.namprd10.prod.outlook.com (2603:10b6:510:1b5::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9275.14; Thu, 30 Oct
 2025 00:07:25 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9275.013; Thu, 30 Oct 2025
 00:07:25 +0000
Date: Thu, 30 Oct 2025 09:07:16 +0900
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
Subject: Re: [PATCH RFC 09/19] slab: add optimized sheaf refill from partial
 list
Message-ID: <aQKsNPQe--6QMOg0@hyeyoo>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-9-6ffa2c9941c0@suse.cz>
 <aP8dWDNiHVpAe7ak@hyeyoo>
 <113a75f7-6846-48e4-9709-880602d44229@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <113a75f7-6846-48e4-9709-880602d44229@suse.cz>
X-ClientProxiedBy: SL2PR01CA0013.apcprd01.prod.exchangelabs.com
 (2603:1096:100:41::25) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|PH7PR10MB6354:EE_
X-MS-Office365-Filtering-Correlation-Id: 8fb0c4c8-0632-4d1f-4b96-08de17484e25
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?qzaQpUmVTesHUspwSNV96s2A8/nJok0YjDGZj1h5pYAfP7rog34AdDmm59em?=
 =?us-ascii?Q?iJCjLainYtITDCwagnCsFfBaVKdMO41GDu9nNDV1+TK0SdxvU1TVfU7lSReV?=
 =?us-ascii?Q?9ziUXRIbj9asNVU9xkuvcNlRRBUKi38V0ELmMbnsLHRBGsuPw7dJAasPxoQ3?=
 =?us-ascii?Q?ThQ2q8998lZbwnLCj6lRTVMt65IFAveNDp/o6ut2oabQ89mwxjt/ieX4FFLK?=
 =?us-ascii?Q?c/ruM0/hEQAMiw4tX27dgieNz8GC5jJf2rFZIvMKOeLLBdV9erAb3Mt/Jv6f?=
 =?us-ascii?Q?c/c5xwNsxSREtrK2wGH1wT5AXhPr4t7bJoztMV3B+ZAkgdMBiaJXl/a5n0o8?=
 =?us-ascii?Q?ncG/KBv9fTgJWy+iawsnx48dGBzYNgT9XK4HRCPygksX8BN1fDmGujc0gdoL?=
 =?us-ascii?Q?Q6g+9jHjzFwhvh03NsxqhkNt+EfBLwjEoPwn2UmncnwS9hoJ1qRNOkP+zWdx?=
 =?us-ascii?Q?9R8se7XVXSjNA8ai8lMGZq/XCVYnrkjMaehcQhMiLCeUrpQU4GnZr6zeFXtW?=
 =?us-ascii?Q?a1CuDYu+n0ezRNhb+8m3KJJ8wohmO16u4MHlftbe585ZhFJHiIfVrjeZpe8H?=
 =?us-ascii?Q?2S2SysFn6gKsO4hqWZ53jP/pGSlt7nDgTsjTG55JqjIQri/VwiKv4LHHR3KN?=
 =?us-ascii?Q?mJeOvjtZFKFEycg6yZBBRV/N3doY7IJBzim+o69X3TlTWA/LPjHld0HurKjr?=
 =?us-ascii?Q?M30SP4UkxpCTZ7wYL6ebZGIRAOQhRKXVJO8QAZYFOJyGvVOykFoDd99jxBb3?=
 =?us-ascii?Q?1ay17u1TUgPW3e1obSoBMB/nlyqYLBXpOAZxk2XTEGIlN8BRE1ESVBfjmcKb?=
 =?us-ascii?Q?cLdRPbf7ttaAhE5EZ/cTCm7c/+qWByySroJwKRUAHXAeTsO6wFvQFjzTM62r?=
 =?us-ascii?Q?XrcgVwUQy3qbUrTctvy813hwaGvjd0o4+JV7KbXzM1JfGEnaSSF9lTm5N7eg?=
 =?us-ascii?Q?ZvXC7t5QRdAjbUztwsxB0UWowqSlBTDVV/bJ3yt7S+DhatrlTmfSTJrNVthd?=
 =?us-ascii?Q?oMGpLf7lScc9sKlnjzrH7vtg4PPoT9QiTCAfqxs0+UtGXc/PQcARpaquNv4E?=
 =?us-ascii?Q?kPSzIjBvctWe2DmO7mnFVPjoMfT+QcjhUU06kCYN1uEeZgYCVkjm0ZSjJ7wp?=
 =?us-ascii?Q?bWux2OC9bHppFn12W7sJBVASh4iNYbyMHAC8XkB5awIb3rcD+Mn8g524rFMZ?=
 =?us-ascii?Q?WGSG08gxMg4LjXQWcxbGRfmtHWoCkpJ9QOOVVKKfdCZVVGqJMomiRsnpl1l6?=
 =?us-ascii?Q?ZiZDDq8wjhsfA0TON94ysTlLrYoC5LNzQo9M8dLw2CK0X3lAIWaadu3UTVvT?=
 =?us-ascii?Q?5LHFNI0p6kXg6pYuUAgoxjUZcbtV+FJLJ3b48UCrrcB37R5fZxXY8GdUKJDR?=
 =?us-ascii?Q?YF4y7FDSfaVBYUzf/YgF7PVgjJY5WyT5gc/bxzRv1Eq9kmN1PAB2B9ZNt0dw?=
 =?us-ascii?Q?VGF8Kvk2VXmNPltSC0Pabd2g6Rg/2+Lo?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?Lwym6inxUFvkc4FgVXPpmkRD6BrENAgdDhbBrU2YbZVjNxMLYsKbcNMWf4a8?=
 =?us-ascii?Q?+9f89CEcR1arO/CStx5LzvNdjK8aZj9O0csx759sSGvuIU1WcrYNqCuqMVgb?=
 =?us-ascii?Q?cB1ognC2LjbI0o8d7/gM1VK+V0ZESjy23asvcp1xHyVrrNjOPujiBS8R9p6J?=
 =?us-ascii?Q?RBuiTRPTVVhieHGJST5qf0H1NhkvHCivilgGBmjg/aNtlsZg/rOeIcMY3JLa?=
 =?us-ascii?Q?oX9MR9cKEaRSuJ5SVAPx3y3JFndkoYX6yeaQMjLSc/fj2QxUrzCDhacWBr7i?=
 =?us-ascii?Q?Ab9Kno8jilnPhNIbnju7y3Tv3cJZNgsMxa/OSuZ+fVTFn9VNP5m0Z7kTA2B2?=
 =?us-ascii?Q?8ve2urivoho51HBokeT0ortW0FH2yce2rqWMEkCwv3CLlc2bqsVPQ3SD6S96?=
 =?us-ascii?Q?QCaOiahpY5OlRcXqohpFlmX/rC+XKo9/zKbiabtwaw/NLcVzKUOo4ng6EgG/?=
 =?us-ascii?Q?YEarhoPEly58KXPE7f7TkClJ7o5NgdWWqcyAfNPBruYgYXg2qRRegapbMxY4?=
 =?us-ascii?Q?9d6xVRAV+vhV/zYIgUEznsOFKUnxiabdT3LsYiyNbNeRoUKVvFAk1tdEH5Lo?=
 =?us-ascii?Q?FQrjK2fjpn62h9x6t0p9AiOGeKPX3lDzQxcIwkEqP44YX/ggvUQAsqXgo4O5?=
 =?us-ascii?Q?KWFCeoefoe3U06WNJq6QSi31SucWRiZuKihTuKieEyVb9RgSwLm45LiNtIDn?=
 =?us-ascii?Q?H1/Dl1N/AMCaqQ/oxlatgUG6CPCs2jlQ3S68IiD0OxE7PhO1JhJJlklzNPxL?=
 =?us-ascii?Q?WVhp5Zw1rzFRKJL/9+8wz8l1B7tNKD4e3RG2HDGhYiRBLJijItMTb8KJZ8+u?=
 =?us-ascii?Q?IAVB16XbA5IPDqaV9I7cZRdnQ1SAqX1YWkznIJfwTr/yEU2MGJEnKHRaeQFf?=
 =?us-ascii?Q?grzK/LdHuO+zSKpSSwc8WPB2r9A2Y8Sdxn7829atmRwPupAQIk5Nx02yAKYW?=
 =?us-ascii?Q?HyMd0wa5ZsxjtDx4xAca7n76s+BP/EJ8bXNTiA12iwzT+YH+DIZrRA2wwyZX?=
 =?us-ascii?Q?ZUXAdajNuq0ufOto2qU+xgy/XdkXlcsw9j8pv5ox9LOntm0XAdwMOUELEbl4?=
 =?us-ascii?Q?6BbUmo4/Jilk0Aa9wQPjOiObRaeQVq4A8EvDP46CscN2mx3i5tA2VJmQN3rO?=
 =?us-ascii?Q?T5RC8vJrfvKG4LyCHcnmmvIrXx3gkRrVlyaiToU9UQn0qksRXEQH80gWJtlK?=
 =?us-ascii?Q?As2CzG0nLhMchzSIxMm8b+RG+fCUFtfSh0UEuseoGGEfeBPuF0Qf9E8CrAHQ?=
 =?us-ascii?Q?mgiFezSubBxaFU0AY0TihMYcMuIIGIZO0HrkqCxOJHi1DhhF4QBp8Ou2v8vM?=
 =?us-ascii?Q?N1sDw/vy8HAX3BV+VD5Tx3zVUH4NAyjadACqnX6UOzvqul+lrEhnqB8tEBKI?=
 =?us-ascii?Q?+jmD+lLjpLYUMDInDMrZTSwKR8z/wwup+euzp+IrFcbYsxG4t+AA/LLTyFVs?=
 =?us-ascii?Q?fB7GzJH3Dqk+nnXNTfJOqjFGKzDJjT+akxxayrUul4D4Cfc5ClbdExqebUcN?=
 =?us-ascii?Q?3x1er3+xtRugDxgnFUPpvPBnEod0dfy16t+HLpOeHN/8w/jXiZtXBJPincmO?=
 =?us-ascii?Q?lE5YzI4NC3/U85dZ4vRATESho2mCapRu8UzQU8Gk?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: uYK6kIHIbVZi9TmT7OHBP7WkTlFrt7P+O95m7jyd6ZycribjK4O/9ZxA2EL2mBlZWY589u6lQYE9Zp55Q+jX+xeoe5O80appeK6SbckMdygm17/tOpzq3Xq2dFYeY58jaKHYelBVkFDOEb1AgHkGebHDyMpGwxpybhmWIzmyVux9LyDAmV6BFELdX9KxlJs1ENZ83Ef9BPdinlCGcL0dq5/lXa7rtuFYEWvV3HEQD/x7le3wZKyyFQdqa67bznq+CdHsXAnyNxZX/UoGC9p9gn63wxO+YX++Ad1uihXDYopgMOa+mTaM8PoqVgkFI9gnoMk9A11z9G986M7mviDvhH0LlC8RexUdF0RoMrzN0mIwRt4C8fK07XwHnj41XwWwX/STpOHWWisNh/5f1nlo/eQaeyxOU7cHctQG7FyfqvJlemFC9p3NnYNnUdhge4lru7nQz30TJdYKTQrWNSegJmwINXQDKu++eb1P29JqO3JNhdWKsxAPneE3R0koHu/O8CwPMRvuA0Znw+rnYHlemZgDrQZsGbSd6SvgjwbqDzXSg9Pt4tWx/lwyJy63vq9vkv5TI++9NJG1MPqLS//cYSa5+Ofck7+rva9yNjFuSUA=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 8fb0c4c8-0632-4d1f-4b96-08de17484e25
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 30 Oct 2025 00:07:25.3067
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /E/dJcqxvrw8OvtNM22OcFxGNqDDbrJiSy5Y/VaClr6K9sYJdvfAM1fvudWffMrS//bGWESAolCwpSmt2nc/XA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH7PR10MB6354
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-10-29_08,2025-10-29_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 malwarescore=0 mlxscore=0
 adultscore=0 mlxlogscore=999 suspectscore=0 spamscore=0 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510240000
 definitions=main-2510290194
X-Proofpoint-GUID: nrbYv1_cVP9dt3NacXsHC32Zzm2zap9U
X-Proofpoint-ORIG-GUID: nrbYv1_cVP9dt3NacXsHC32Zzm2zap9U
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI5MDAzNCBTYWx0ZWRfX/SSZBQ69IwUB
 rLOJUjfWasUYcD3kU6sORBrwKQw3A2awMUPBi3E1VbZcg8wlYcYH+L+qLI7svquXAJoGqH43ex8
 +xnYh55JV7psAOxVV4hbLdJOa2k6RRTF/dRsQhtHca3LdwJO7RARJmMm9EVqqxISLjLA54M2FHW
 MLBJMLgNU7Q4lo6m537BiqE/tdBsNXyg8Qb7wZSUAvfdUTocYXzi9cSsuDe63UrfKozd+HE1y+8
 v27gpPgMN7nCEQUSona6yelZ3qggkRN6AD7/XM0RTcbg269dlWNHCBCHKoXkJSVZI5NlWYdgdyf
 u15zuopIk8d4ApgFwYC0d8+YOKCu2r/O/H4ZttnHgjY0zSR7RSl//qteA7nMo0e8S4RLCF/sheG
 FwyFbWss0+20RsUAmFyzPOkvj16UHQ==
X-Authority-Analysis: v=2.4 cv=S4LUAYsP c=1 sm=1 tr=0 ts=6902ac41 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=ymNet4jE-Q9JvIermoIA:9 a=CjuIK1q_8ugA:10 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="LWfb/41F";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=OGJgrK23;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
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

On Wed, Oct 29, 2025 at 09:48:27PM +0100, Vlastimil Babka wrote:
> On 10/27/25 08:20, Harry Yoo wrote:
> > On Thu, Oct 23, 2025 at 03:52:31PM +0200, Vlastimil Babka wrote:
> >> At this point we have sheaves enabled for all caches, but their refill
> >> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> >> slabs - now a redundant caching layer that we are about to remove.
> >> 
> >> The refill will thus be done from slabs on the node partial list.
> >> Introduce new functions that can do that in an optimized way as it's
> >> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> >> 
> >> Extend struct partial_context so it can return a list of slabs from the
> >> partial list with the sum of free objects in them within the requested
> >> min and max.
> >> 
> >> Introduce get_partial_node_bulk() that removes the slabs from freelist
> >> and returns them in the list.
> >> 
> >> Introduce get_freelist_nofreeze() which grabs the freelist without
> >> freezing the slab.
> >> 
> >> Introduce __refill_objects() that uses the functions above to fill an
> >> array of objects. It has to handle the possibility that the slabs will
> >> contain more objects that were requested, due to concurrent freeing of
> >> objects to those slabs. When no more slabs on partial lists are
> >> available, it will allocate new slabs.
> >> 
> >> Finally, switch refill_sheaf() to use __refill_objects().
> >> 
> >> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >> ---
> >>  mm/slub.c | 235 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++--
> >>  1 file changed, 230 insertions(+), 5 deletions(-)
> >> 
> >> diff --git a/mm/slub.c b/mm/slub.c
> >> index a84027fbca78..e2b052657d11 100644
> >> --- a/mm/slub.c
> >> +++ b/mm/slub.c
> >> @@ -3508,6 +3511,69 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
> >>  #endif
> >>  static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
> >>  
> >> +static bool get_partial_node_bulk(struct kmem_cache *s,
> >> +				  struct kmem_cache_node *n,
> >> +				  struct partial_context *pc)
> >> +{
> >> +	struct slab *slab, *slab2;
> >> +	unsigned int total_free = 0;
> >> +	unsigned long flags;
> >> +
> >> +	/*
> >> +	 * Racy check. If we mistakenly see no partial slabs then we
> >> +	 * just allocate an empty slab. If we mistakenly try to get a
> >> +	 * partial slab and there is none available then get_partial()
> >> +	 * will return NULL.
> >> +	 */
> >> +	if (!n || !n->nr_partial)
> >> +		return false;
> >> +
> >> +	INIT_LIST_HEAD(&pc->slabs);
> >> +
> >> +	if (gfpflags_allow_spinning(pc->flags))
> >> +		spin_lock_irqsave(&n->list_lock, flags);
> >> +	else if (!spin_trylock_irqsave(&n->list_lock, flags))
> >> +		return false;
> >> +
> >> +	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> >> +		struct slab slab_counters;
> >> +		unsigned int slab_free;
> >> +
> >> +		if (!pfmemalloc_match(slab, pc->flags))
> >> +			continue;
> >> +
> >> +		/*
> >> +		 * due to atomic updates done by a racing free we should not
> >> +		 * read garbage here, but do a sanity check anyway
> >> +		 *
> >> +		 * slab_free is a lower bound due to subsequent concurrent
> >> +		 * freeing, the caller might get more objects than requested and
> >> +		 * must deal with it
> >> +		 */
> >> +		slab_counters.counters = data_race(READ_ONCE(slab->counters));
> >> +		slab_free = slab_counters.objects - slab_counters.inuse;
> >> +
> >> +		if (unlikely(slab_free > oo_objects(s->oo)))
> >> +			continue;
> >> +
> >> +		/* we have already min and this would get us over the max */
> >> +		if (total_free >= pc->min_objects
> >> +		    && total_free + slab_free > pc->max_objects)
> >> +			continue;
> 
> Hmm I think I meant to have break; here. Should deal with your concern below?

Yes!

> >> +		remove_partial(n, slab);
> >> +
> >> +		list_add(&slab->slab_list, &pc->slabs);
> >> +
> >> +		total_free += slab_free;
> >> +		if (total_free >= pc->max_objects)
> >> +			break;
> > 
> > It may end up iterating over all slabs in the n->partial list
> > when the sum of free objects isn't exactly equal to pc->max_objects?
> 
> Good catch, thanks.
> 
> >> +	}
> >> +
> >> +	spin_unlock_irqrestore(&n->list_lock, flags);
> >> +	return total_free > 0;
> >> +}
> >> +
> >>  /*
> >>   * Try to allocate a partial slab from a specific node.
> >>   */
> >> @@ -4436,6 +4502,38 @@ static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
> >>  	return freelist;
> >>  }
> >>  
> >>  /*
> >>   * Freeze the partial slab and return the pointer to the freelist.
> >>   */
> >> @@ -5373,6 +5471,9 @@ static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
> >>  	return ret;
> >>  }
> >>  
> >> +static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> >> +				   size_t size, void **p);
> >> +
> >>  /*
> >>   * returns a sheaf that has at least the requested size
> >>   * when prefilling is needed, do so with given gfp flags
> >> @@ -7409,6 +7510,130 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
> >>  }
> >>  EXPORT_SYMBOL(kmem_cache_free_bulk);
> >>  
> >> +static unsigned int
> >> +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> >> +		 unsigned int max)
> >> +{
> >> +	struct slab *slab, *slab2;
> >> +	struct partial_context pc;
> >> +	unsigned int refilled = 0;
> >> +	unsigned long flags;
> >> +	void *object;
> >> +	int node;
> >> +
> >> +	pc.flags = gfp;
> >> +	pc.min_objects = min;
> >> +	pc.max_objects = max;
> >> +
> >> +	node = numa_mem_id();
> >> +
> >> +	/* TODO: consider also other nodes? */
> >> +	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
> >> +		goto new_slab;
> >> +
> >> +	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> >> +
> >> +		list_del(&slab->slab_list);
> >> +
> >> +		object = get_freelist_nofreeze(s, slab);
> >> +
> >> +		while (object && refilled < max) {
> >> +			p[refilled] = object;
> >> +			object = get_freepointer(s, object);
> >> +			maybe_wipe_obj_freeptr(s, p[refilled]);
> >> +
> >> +			refilled++;
> >> +		}
> >> +
> >> +		/*
> >> +		 * Freelist had more objects than we can accomodate, we need to
> >> +		 * free them back. We can treat it like a detached freelist, just
> >> +		 * need to find the tail object.
> >> +		 */
> >> +		if (unlikely(object)) {
> >> +			void *head = object;
> >> +			void *tail;
> >> +			int cnt = 0;
> >> +
> >> +			do {
> >> +				tail = object;
> >> +				cnt++;
> >> +				object = get_freepointer(s, object);
> >> +			} while (object);
> >> +			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
> >> +		}
> > 
> > Maybe we don't have to do this if we put slabs into a singly linked list
> > and use the other word to record the number of objects in the slab.
> 
> You mean we wouldn't have to do the counting?

Yes.

> I think it wouldn't help as
> the number could become stale after we record it, due to concurrent freeing.
> Maybe get_freelist_nofreeze() could return it together with the freelist as
> it can get both atomically.
>
> However the main reason for the loop is is not to count, but to find the
> tail pointer, and I don't see a way around it?

Uh, right. Nevermind then! I don't see a way around either.

> >> +
> >> +		if (refilled >= max)
> >> +			break;
> >> +	}
> >> +
> >> +	if (unlikely(!list_empty(&pc.slabs))) {
> >> +		struct kmem_cache_node *n = get_node(s, node);
> >> +
> >> +		spin_lock_irqsave(&n->list_lock, flags);
> > 
> > Do we surely know that trylock will succeed when
> > we succeeded to acquire it in get_partial_node_bulk()?
> > 
> > I think the answer is yes, but just to double check :)
> 
> Yeah as you corrected, answer is no. However I missed that
> __pcs_replace_empty_main() will only let us reach here with
> gfpflags_allow_blocking() true in the first place.

Oh right, it's already done before it's called!

As you mentioned, __pcs_replace_empty_main() already knows
gfpflags_allow_blocking() == true when calling refill_sheaf().

And bulk allocation, sheaf prefill/return cannot be called from
kmalloc/kfree_nolock() path.

> So I didn't have to even
> deal with gfpflags_allow_spinning() in get_partial_node_bulk() then. I think
> it's the simplest solution.

Right.

> (side note: gfpflags_allow_blocking() might be too conservative now that
> sheafs will be the only caching layer, that condition could be perhaps
> changed to gfpflags_allow_spinning() to allow some cheap refill).

Sounds good to me.

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aQKsNPQe--6QMOg0%40hyeyoo.
