Return-Path: <kasan-dev+bncBC37BC7E2QERBWOWY3FQMGQEYCDU7KA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id u92dCVyrcWkJLQAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBWOWY3FQMGQEYCDU7KA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 05:45:16 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13e.google.com (mail-yx1-xb13e.google.com [IPv6:2607:f8b0:4864:20::b13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C65F61C5E
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 05:45:15 +0100 (CET)
Received: by mail-yx1-xb13e.google.com with SMTP id 956f58d0204a3-64939d0cd02sf903636d50.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 20:45:15 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769057114; cv=pass;
        d=google.com; s=arc-20240605;
        b=HfGGCinmePV3AYQZFB1wmRUSUZF1gh+mkOB9A/x6PMLCCTMXUtTiu6oY+bFrPBfj2X
         gxUQNf9LlOyGUeQS4nQ616cKgzdKX0U/c4viCttjA7NyUx+GAWvZI32Rfl9krzP4PHMg
         bksx/psqez1ySM8hssM/saPSRGp6HBkvVSMoSZIJpTjKH5YeQDMiFY1nGs74U+BDrByu
         31R8gx3JZzvIjZcDVkBeB1wAvLO2vNe4mntOfGUHoNS/KnJu0inAnqIYCAyFGro6by20
         WJOQwcN1qoCpUJPN+1Dyd7yXNrDWP+tsdIWe8Efy+7gp4RoGrKbeXk4k5sTzF3m8RSIg
         137g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=lnIgF0CX2QPXHdYiwJP0+O4hHdgUr0Wk04yUZaj8WBc=;
        fh=WbDUKb551+heQzFbvb2UVHLXIjlfURIZYjObkxRBW3k=;
        b=do4VT8HndleUX2nUy5LhfKFK3FGty1T3dG3RSIZ6DpSXjjiY+dUyXQu6RpjvL7W6Xb
         mI5kGpO8OH8W6+Lz2aCyWf3c190lbQjz2yZR97fpspLKdAbHly+oTuBmumgs6uIwqqWA
         qnn0UzOIB5h7buUk6I0+OJvB10UH+/X1+NGZW9FDaMWHsvA6g+AXPahbmEKexDfNNqVM
         crgcY4UPai7wCpXvxh9+4PXt5EJ/e6CiwhrmWpJuqKbj6c4XM3AqbJbwoQqj+4AdnNNu
         87wX6Oh6g6RuU/j2pwVnJM6SD7aRYKHSFXq6xXfloXiKiAf5FJwe6cFkwiloTWD8ABR0
         xaVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=kw51eDTy;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="eE/2gQ8k";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769057114; x=1769661914; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=lnIgF0CX2QPXHdYiwJP0+O4hHdgUr0Wk04yUZaj8WBc=;
        b=F23grxb8EG3zpDctKQbM4Eae9Kg+5C6QWgJHkYLQsBK2kHfbtA1gMxv7JY06DmnV6s
         NFc9/bokzGb1jRyJZaNmFxk+e5dm+BwB56mhsYNgk3nnwHqwbh0ItgFaOJeB02wnzRi3
         vb+TPYWyJby1JKe/pwKC3joh64+7t9f+pr8FEdZvmpJG/NpObZpSA7pRFsLdqIqvmO6t
         gTea86XHD0Is3+R8+lD6YefzxJhpkoM+6mEnSJe7xbeb0NXILFEWTr9Tlbu8tm0nrTOc
         QezvtcaEhX/PSS0x3S/Y/xqtWk6XwQ5K/zEpIRTR3fVbWJNibR1w0WlTndt++lZrdVy9
         7PnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769057114; x=1769661914;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lnIgF0CX2QPXHdYiwJP0+O4hHdgUr0Wk04yUZaj8WBc=;
        b=FJbtMfqIaI2pnoDyYfuD/JGIZWOXJ+KS3U9dqYh7tpreHCokIHkRZc0zGL4Ifrpxb3
         KvTcBFjfgV92TDr2peh0FCH6cOhHW/3Z8+zSKeL/DsEcMNxHDry4FYCr9f08C5NEy5hQ
         XWsdc/ECL7eSXvhO68ip7i4wgHLD0bPaAKNRJy3B+U8pfa34Cen7V1KwpdQpNuomgo7N
         0vR/pYuCNtILQCm19IR56bLzf9LvzbRBfWRj/1vV99O594pnUOx+aXHrLl2NkVHLLQd+
         IcIpQNmH/y14V9UcPc4Wcv4/dcbZV8kOtAABbHVZD7tvloOlc/FCCeEQDEp1NCRKlHP+
         yURw==
X-Forwarded-Encrypted: i=3; AJvYcCWg5CXvfxtJYnyme+v0978vf0KOA2a529OrnRK/7XeOtN+MhqgNsII9WsX3WGEreC81x9qGiQ==@lfdr.de
X-Gm-Message-State: AOJu0YzII6NLvns3iZW/sdo/W3+bNsTelYnoTgcDRlUDucCBJnfuAK9A
	ALOpyPijomsS4X4dn0VgVUeEg4V2zKjClF6yMJ81Y5HUeN389uQ3FXIe
X-Received: by 2002:a05:690e:16a0:b0:644:477a:92b7 with SMTP id 956f58d0204a3-64917750c13mr16091538d50.56.1769057114217;
        Wed, 21 Jan 2026 20:45:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fo2CNb6C+wTqJ1iY8evpRUE+sno0CBwVaFFyMHdy5vQg=="
Received: by 2002:a05:690e:4c7:b0:649:37ac:57c3 with SMTP id
 956f58d0204a3-649513fd3a5ls396618d50.0.-pod-prod-04-us; Wed, 21 Jan 2026
 20:45:12 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCW3JZcylQWtBhoudUkgdDOF0VJ6C69S0nPVJWEogBvwIakNSH9TBUFgmOJAIGSAP2+r7o0lk1FgRAg=@googlegroups.com
X-Received: by 2002:a05:690e:e81:b0:641:f5bc:698c with SMTP id 956f58d0204a3-6491776304amr17087567d50.72.1769057112720;
        Wed, 21 Jan 2026 20:45:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769057112; cv=pass;
        d=google.com; s=arc-20240605;
        b=ldK7fj/UKtPAsvU6501Od8Lo2PLCQFKmr6lT9cEzUGcvFGACCs0Rk0NQugF0/1oR/6
         3nERjVlvw5Ln+MarYKB4Fe+a6DCl/pODjEZD8sRZ+6S9HpuU0aDNCUxqy3uMrTm7HG4j
         ofTi8rX2FO4e38jd0o5OTfubFU6uwr8+cLsvcLizw8yXFvkQIVX4yUXs/ZKYx43lABYI
         0m+Xc53EAukOPme90RJ+k4Per7dyU0AlbH6kAt2ihkIwc7vOgzAZnES2D/hL3mWoFAEB
         zFm4Xht2eobhI7eSNCYUvO6P9E1jUruUN8gwyEApOLEbwy7L6sTNgSXwDqoE+v0wAwL7
         PJhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=Ncvg6/5fdjdIcGH0A4Nis3Q6egixoEx1JAfZ2dy6/9s=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=TVzRwaTainDvSas/DOAhWBfnQrK4HVPeWdyisjBsCijNEdx96zVYA4cdT3XG2mNC8Z
         x22wzT6PhMeJR4rHwybaqbgXvcOTiYLZbIQWfeZXlyGwkz56pOp5h3ML1kW1sXOJvTqm
         0ToLQeK/x1Wj3Q1FYvExt6J2SmaXQyDDasGQFQij3s6OR3nOyxkqrwy+9ltfJ1mQIJ7+
         YxFJzdC3x0PvcX1ElYRNdkdh5wKqfJTav6n0xSORJuApbCLrzzPBBxqqidricSKOlObh
         DGJqZD7ZSRn6hPLZwFqCTiAWC0KsNS+L/+5/9BK4sI7V2FzbtlnO9r8g8I1Y3cC+qrcl
         HQpQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=kw51eDTy;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="eE/2gQ8k";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-649170a0c2csi536605d50.5.2026.01.21.20.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 20:45:12 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60LJVKja3523415;
	Thu, 22 Jan 2026 04:45:10 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br21qfa6d-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 04:45:09 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60M2hkCF008417;
	Thu, 22 Jan 2026 04:45:09 GMT
Received: from mw6pr02cu001.outbound.protection.outlook.com (mail-westus2azon11012002.outbound.protection.outlook.com [52.101.48.2])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vcabm4-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 04:45:09 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=idkH4K852XYb0C5hbcO9lJgcaVFbUIBhCpIm+Y18u/S0QK0t86463NWO7hbji1RUaY4CL41s2MGVPk4Wr05nhq2kycdRSbhBFgIO0SPR3F1SEw9cIv1E9RpdOEM4NULIf/wViTPc2N+0ZiLDWoGHAsw5NexABtawVyGwxi7Bfv/yfiarLUt7rCA/VyWeBJ/zQcmaCzFwYUkhJkuUugVHmjenCi7uRTaJmVidVve/cJYnw374XnAirKA1tH2fZwn6e1hkcUjC+nab+hCZdhiY4DWtuVgkTytDLp9CdhcMzBXGvelpuKjRy8VzV+atS0fcMNVYVgphahN/ZB8nyJW0rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=Ncvg6/5fdjdIcGH0A4Nis3Q6egixoEx1JAfZ2dy6/9s=;
 b=g/f5wTtGwUcNtHjIL+wDVsNwZESq7TQzhV3TdNL0vyeqEBT0fZ0XqFrHBdFdPDvxvEOUSGR3ywFmn7oTzA388s5ZJ80qXq0NDDt6w9LhUmYpt3FqNl9eSj2oKf/VApCvR3xWPTACLb4z64QGx+wTNu3J4npKX3rhOEDKQEHeNuqRg251tG5OG9G45yPKWAXF37wk64guYKJTJoQTJn4bLwDikqks7A+4FP93ZfCr7S06re6cQHmUMtVqiVfeuHjje4cF0sysGsk+pVSJEWlvxGeUaQ/r/7TWboiEsVCWPg/wnIoRybTNaEf/lAAPFTv9gS4w6+LbowOTS532RxzKRg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by MW5PR10MB5690.namprd10.prod.outlook.com (2603:10b6:303:19b::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.9; Thu, 22 Jan
 2026 04:45:00 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9542.009; Thu, 22 Jan 2026
 04:44:59 +0000
Date: Thu, 22 Jan 2026 13:44:49 +0900
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
Subject: Re: [PATCH v3 17/21] slab: refill sheaves from all nodes
Message-ID: <aXGrQSOoG_6NdqNT@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
X-ClientProxiedBy: SE2P216CA0083.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c6::16) To DS0PR10MB7341.namprd10.prod.outlook.com
 (2603:10b6:8:f8::22)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|MW5PR10MB5690:EE_
X-MS-Office365-Filtering-Correlation-Id: 54bf9c57-ae81-42bd-0887-08de5970ff77
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Fvd0DLvDzNWow+vKO5jbOhrTb8Z4z6UEO9ShsUBgTUG+9FSCad7Bul6yoj+/?=
 =?us-ascii?Q?HP0ehGI2ke0MZPxoxZyS546pNjGIkcdTcl8Nco6gnnlc1vmble/i5++f8Mxr?=
 =?us-ascii?Q?GCysxvTMyGijSiGK4xzVEPWhASE6C7oMbufHIVrcSehCOM6yZfQ2LN+r4pa3?=
 =?us-ascii?Q?sq23v/FVYaFqOXOyyUND2dy3QnVeTA4MSoE8ouMV9P6SwL29LM8jYY8CqRlx?=
 =?us-ascii?Q?irzQp5EIJe3QNJ059AdN9TSU6x7xUaEgealO7y+reC8bRkNa4aocMBnNCn+5?=
 =?us-ascii?Q?ZbhoZUi4+Ela9R94XC0fzf1C3HOMxfCyTNA+Jxjqo12oLAs9/HL9mS3adckp?=
 =?us-ascii?Q?SkzHoHbPiDnz8eq+FSwLdiL488kehDZsDb3nbpfuAjFyoAEC1vswVXEzS8a+?=
 =?us-ascii?Q?YzYJhXw7YwthPnutfTf473EAOeiI0Nv4vcJ6jFjQ+lzHCbKujR3seYZGR+Ea?=
 =?us-ascii?Q?XH3ys/0E6ZSMoGQmzb+K0HtQVPObHpHtSR/ZVY+zavsIM+hls6vlFuDbOc6X?=
 =?us-ascii?Q?2kRzkQgNErTrprBeK28UAnfx/RYUvosxP/t+jxg1KpJ2ba21bsxx70aaqKfz?=
 =?us-ascii?Q?OZDt1ojVFtmuZz9vfiSEQJb/EMpKbK0rjnFuavNvOB/d4xGMjU5iv0cptT7m?=
 =?us-ascii?Q?wso4i+EsAbWkJT8/VU2RrUBu4eM/aomg4t6WJVJ7lLZWPQIrb4POUn7jre61?=
 =?us-ascii?Q?itR7ZbHiARGUlFh6bphzrYuwalAiU0K15UKMRyBHZkeaAdY6o70nf64rbVFt?=
 =?us-ascii?Q?8++UFAWWgfY9OXoEGR9ltQ2mUJeQoRgYWIzHYm4GqqqE8JVtCii0vQejLAA0?=
 =?us-ascii?Q?Uj34PkTH6mXK+KQsvjTH9Y+rOQBevRstiAikZcN3FapRcsab4awZYY/89Ha6?=
 =?us-ascii?Q?qBm2Zay6/pP1gZ3q6HVWeyub3wuhZdxCuBgFHyJhOAwWWtLW7XrZf8IbsHeG?=
 =?us-ascii?Q?Bozqzpmj6mdhgKxVWyfjZxTw9SscZLMGySLDAcZYVepQ0DOfdikpkVIK6KT1?=
 =?us-ascii?Q?uCB/cKDevmlpBnlBWet1NnrY8EfJ2rdK8n0YElxHYCeMrkYSTvsIMUu8CRoL?=
 =?us-ascii?Q?JlJKYJVGAIPIhU9lUm0o6p5n917JkTXOesIw/kGGNAA769ZJTCyTUsIBPqcP?=
 =?us-ascii?Q?Q01Boi8czYeoovVWcYVJEVaczIvhpnfjRfGq9KDnEHOXnsGZv1Kqhf+78YRf?=
 =?us-ascii?Q?daaK+r+GNIryTv+0jokVzuON6a64FUfF7Nwkt/eZQRkiIQMQjOVvDK21E/Yw?=
 =?us-ascii?Q?1rTVFZdn1EY8x135DALs2DX6JTRoUd/YvnsFfdciO1BuuV1hBX/op5paGUIL?=
 =?us-ascii?Q?2TxxjMZmrByZgIgibrGRAeB63dpxbVpFyf9Q5dlYBOKt6yVvWyGQy9mlH9yj?=
 =?us-ascii?Q?wG23hNW0L0TiSfj/R96dZkVCWsyXxhVn/ezFBj6SydGmOvEZ0tLZ3IUQEwkS?=
 =?us-ascii?Q?/nV+S91VQF8fIBIJN95V47+feCHS2kvjqXSWSqe8u/tWk3/pvGFGLsjpmm+w?=
 =?us-ascii?Q?gL1HQM5Bq6vGr3WwYKjdMqUZUSIrpJUPF5ov7YbV0ucKjBUGMTW8jqLOtDGM?=
 =?us-ascii?Q?8LhNNzxUsTiM79WOdm4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ftHZ6JZhtgeFk9RrapphdwbwcRVER2ZiJUvWtKcwAaAZyVfnj5sOvaIeX84R?=
 =?us-ascii?Q?sza5/P+W7xpfM/HUl7u80/Lhr9OYiL3HHIWFdj7rmAraKZE2CupdXAkGeABc?=
 =?us-ascii?Q?med/ZcezZCxlnskZ885r4cPhQdF531ADSkY4lh5QXlpBtabu0DP1TyDV27iC?=
 =?us-ascii?Q?G1SKiNqe+32CzC0+n7iI99LJMxIOLAfmDVfMowY11heh5zmKl8VgimEXj057?=
 =?us-ascii?Q?8LIVmUBi0LkbXlzRazc4p5yfycKvz5+0RTIBHfbgutOk+0Vt0cYedJ5rOVWe?=
 =?us-ascii?Q?Ef82FrkTdCSxz2dsXATMqwNAzdq5PoZiuF7/EI7BGfrl7IZaj2ZIaLxKzFid?=
 =?us-ascii?Q?JvetTtD6TWwPKVd2AmH9orgdcspJ/EpVVifQqPOOwhOJ80ZY00i9PyFNbDDk?=
 =?us-ascii?Q?td5ygDyIGE7rovh4Y5EjavxaoOm8hoW5luxpObVtpigOlGH6XJN+0cIFEryX?=
 =?us-ascii?Q?pudZ89GLAvcHtlb/uZa8+gyvzbbaoOLZDGV9Nyanv5sc8vbq/tnoIMq4qiz1?=
 =?us-ascii?Q?vTsa8K5VyU498kDfrfLpwKP0bLPQ9Th3kWm1j0jJk7hZBP1ULNclE1KYFump?=
 =?us-ascii?Q?4csNZdxhS2nZFVhnSj4p0HoHlUwxiPckbluN71Wus4wpjhD/gHrfO4otihNs?=
 =?us-ascii?Q?FJb1opWBQjKAyyFfuODVceiEIBmiJ47Fz2EH7CLNUznzN9FaK+CG0AlAHny5?=
 =?us-ascii?Q?CviRADPoKClFg4tFJwwNFQEp+pIp8icJS6Ubga4uhd2FMFFvSNKFj87jt7Dk?=
 =?us-ascii?Q?qMq34OcF20AoXAVg25Twf/E4twQpGBeETxvkcfxkRu1X9YyZxMLEJbDlKwuc?=
 =?us-ascii?Q?D98uyBMTmF5g6ARcQG7WX/dVs9DQC+40DJYG2blEmTTht6TYw/qbsL4FLLNc?=
 =?us-ascii?Q?fAtRwbyNklf6QFUCAQqMFujsIPIE8+cFvB8vIIdooxMbZX68pBvfWlrgHJOt?=
 =?us-ascii?Q?4YPGt/ONw6fiG58fpDy4bBFdSgd/Z35vBWtm1wDSOxqKglP+VXcdm4YftLg6?=
 =?us-ascii?Q?NCsRZRlQ4mYm5MffqQB0AjItECBC1iV9LRt5PRHNRgUFZvo710rg3aHDPtqq?=
 =?us-ascii?Q?8Mk5X1keosJe+m5+4T7RH/JXlQkwFLA1HR/ZGsFUpfxC58IUUFY8AooGWcgi?=
 =?us-ascii?Q?TsrVOd1v+TxJe3yQdXtOlBGoGz+Z6aYgEHBrvca75uFbFq2/cobW9HZE6K+y?=
 =?us-ascii?Q?yjvIm+odZRSJP+dcQh9nfjvnDhQU3mupAUGujR0RpIo8oV1bzINajDGIhqyx?=
 =?us-ascii?Q?KkrLBeMmFF+df5egZCSmfMtCLJcpFBGbKcNVuIVQCrqfX4K2yX24EB7psKFE?=
 =?us-ascii?Q?WaUByp0jYFoH58u6UIt7sjixkN5gizSKtrB4JhBqe5NfY1AEzYokVamxmGGs?=
 =?us-ascii?Q?yFOZswsnM4h+W1veh2T6/ljHZCm0p3OtcIDAG/ibfZy0omWfm4hGs6jrnYoA?=
 =?us-ascii?Q?UJCNKkb+N0eEugJ0tckswQcj2GXiuqm0R6FzCzTtP1UCar3+bIAsCLoXS7Pe?=
 =?us-ascii?Q?MXkIgqkPgcMgvzpmekSIiNecZVXkZldmCa1p+N1x8rXAf4+uG/YB/24Cotkq?=
 =?us-ascii?Q?6wZ7qbzNdYRQ1bh1HLnglsrrh7QQPxxKQjshpgUg9lgu8vKOWL/aB4419XsQ?=
 =?us-ascii?Q?Yh5KtpsIGzBWrTRABgrwoO8HxeWN8cXGWnHNjchilBMsImTEgQEWI5Zy7ZyO?=
 =?us-ascii?Q?nTKyrh8NSTf2+NfxeYn4TbAQDFQU2p4KWQ82Idut8ZUUAwpH5rt/AlPh2O0O?=
 =?us-ascii?Q?nYLApWHrsQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: +2G/FKdCteHwIRooy4HoEGNn54Y2GnQjHC+W5vF4sqFzV3/UNEJLUaf9u8pFT9M3rzNVULLWeC58D5uF4tsE2iigAjIoRbTYs9ZmkbsFGo9qHq9ElBk2BW2yE58sJATq90IAKeGeOn7luQLl+6k9teUt48H9/nQwaNliDBbkA3r2+MdAh95PMEBG2mp9b3jPMYBKD8PyH5XZScVsssmW60nMQjlJhWiRt5gU3r3UD/Fk2wDUDYT79ayORhEgZAbGbyXRt/EkGIy0R2OUJRUYWyWjYgnhJoOg39FFrTy8HZLaqy9CiCCpdv2gCC1ezJkvIcZR9CmcPn/bH65yoC4QJxTvC+xoszhcUdMFq7VHu9sgIInmmG2eiZMMT461zaxJRW9AQbUsUCvMyhkEmlk+NJjYGACOISYkZ4fQkUdP7Db0K8Rl0fKTKKoFxBGBxI8on7uLGjydF749iGAWfPCRrS6zhd9DYb1cfml9QBQaKT0Nv99TBLUFVd8GSWVkll578NgMnUwuJtnpHiFkFJVyxcGnpg7NkWdeBx6WFQAxIGDAZUoEs2lbFmzkq0XUot+aHSAAflR9BwoYhqnmkgMAi8JCGB5HVczHCfQxoBGNvsc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 54bf9c57-ae81-42bd-0887-08de5970ff77
X-MS-Exchange-CrossTenant-AuthSource: DS0PR10MB7341.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Jan 2026 04:44:59.5654
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: tqsyLh5mNnT93/sreV2kUjms9aK2J8i/uXnNlmMiJHoG8FHbsEVuANQv9PGyI1a5n64JuCFqv1E1rX762DlpfQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MW5PR10MB5690
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-21_04,2026-01-20_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=843 mlxscore=0 spamscore=0
 malwarescore=0 bulkscore=0 adultscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601220029
X-Proofpoint-GUID: pfqR5dtG5zn9GHfgPlYs2DH2Meii6YxT
X-Proofpoint-ORIG-GUID: pfqR5dtG5zn9GHfgPlYs2DH2Meii6YxT
X-Authority-Analysis: v=2.4 cv=QdJrf8bv c=1 sm=1 tr=0 ts=6971ab56 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=OFLp2U7DW1u7eWAI-QYA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIyMDAyOSBTYWx0ZWRfX9rc9vgYyA3iD
 EeJw/tPlWHUDcV/9HNYCinqWKajMEw/vpnD55lLYl6ZLgCgAQmxXXcRQtPc1qv8yx5frT3GHp0Y
 NZJ0ramAUNfATfmJNK2GcrADFI741qZRJTrkNiyWt72HZpijpkwo0B9fg37JuwLeXXUAdEIDBoj
 TmhvK5MXYHQT5MnwMHx62NPb1n3lH4qvOnU0V7wgDuAvDBUkRELs5FVOr7wwc7OreclB43F9lYF
 zga4cruVBkOX+cnwkIer3Z2z0rVu25KTKzdDqvXTRqnJwn2fZ3WBDqjNyDhD2wKdcFablu/5Gfm
 0E77D9AWHFFLnjV0iiy207RU3Z2HCF42RI47l9ywohpbkF1Qeeu3vtfmtTKjDJP28i8SK91F2X+
 8HDFGKdPAYRa3HW++jwoY0FXmT7Yu7l/uqW38p/D8FylRHz2jtrkWapsRQt0R+IG/kCOcACJ+Wc
 cLDjW2jRgUsulvgnvng==
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=kw51eDTy;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="eE/2gQ8k";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBWOWY3FQMGQEYCDU7KA];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-yx1-xb13e.google.com:helo,mail-yx1-xb13e.google.com:rdns,oracle.com:replyto];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: 9C65F61C5E
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:37PM +0100, Vlastimil Babka wrote:
> __refill_objects() currently only attempts to get partial slabs from the
> local node and then allocates new slab(s). Expand it to trying also
> other nodes while observing the remote node defrag ratio, similarly to
> get_any_partial().
> 
> This will prevent allocating new slabs on a node while other nodes have
> many free slabs. It does mean sheaves will contain non-local objects in
> that case. Allocations that care about specific node will still be
> served appropriately, but might get a slowpath allocation.
> 
> Like get_any_partial() we do observe cpuset_zone_allowed(), although we
> might be refilling a sheaf that will be then used from a different
> allocation context.
> 
> We can also use the resulting refill_objects() in
> __kmem_cache_alloc_bulk() for non-debug caches. This means
> kmem_cache_alloc_bulk() will get better performance when sheaves are
> exhausted. kmem_cache_alloc_bulk() cannot indicate a preferred node so
> it's compatible with sheaves refill in preferring the local node.
> Its users also have gfp flags that allow spinning, so document that
> as a requirement.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Could this cause strict_numa to not work as intended when
the policy is MPOL_BIND?

alloc_from_pcs() has:
> #ifdef CONFIG_NUMA
>         if (static_branch_unlikely(&strict_numa) &&
>                          node == NUMA_NO_NODE) {
>
>                 struct mempolicy *mpol = current->mempolicy;
>
>                 if (mpol) {
>                         /*
>                          * Special BIND rule support. If the local node
>                          * is in permitted set then do not redirect
>                          * to a particular node.
>                          * Otherwise we apply the memory policy to get
>                          * the node we need to allocate on.
>                          */
>                         if (mpol->mode != MPOL_BIND ||
>                                         !node_isset(numa_mem_id(), mpol->nodes))

This assumes the sheaves contain (mostly, although it wasn't strictly
guaranteed) objects from local node, and this change breaks that
assumption.

So... perhaps remove "Special BIND rule support"?

>
>                                 node = mempolicy_slab_node(); 
>                 }
>         }
> #endif

Otherwise LGTM.

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXGrQSOoG_6NdqNT%40hyeyoo.
