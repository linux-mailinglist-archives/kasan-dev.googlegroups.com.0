Return-Path: <kasan-dev+bncBC37BC7E2QERBLOPW3FQMGQELXC5XEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB361D39D28
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 04:40:31 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-5019f8a18cdsf115453301cf.2
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 19:40:31 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768794030; cv=pass;
        d=google.com; s=arc-20240605;
        b=DGe4dqODQKx9NpMLa5HNsS8NC9FwyDDitTpfCDON32fiYTRnCCHSI4gI8JcFTDidu1
         oBoqd745TDueR/JikTSBDpK6YPouftuZ3H782bsQpTgGwyEDORUqnWWqDceF1bTxRuQK
         EHJ0g7CG+c9MaMIzek4RW/cHKuIf92Cc5YtHU6Y08sHCUHa5d2SSa8gpmrQcgekViG1D
         RlSw001xZt7vh43OFPZrya+HCXzO5v8xLWDAFJaAvKZeB4x7ahiu+unyBOof/MpfKgs9
         Z5Ts7OIGqShSVRHU/Vxnr2NVavcVJN0GR6ABfy5JbDjhd0m6ICqij1du8+icnTDQyR2O
         vptw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=d5APJITP+5jGdaxWXiOaZcuyO2o9m9zGxFgDewAChOY=;
        fh=rCVsdXk3LE4n5+RJZZZkQxx6MFxlVG5ra/xB7LeUZ5Q=;
        b=S53gWLaRyf/+uY4tf996kfZX6jSFxkfwfRrVpNzT4PI/R1hHvm2J/XDNltaziFa5Vg
         970YmkvGhiEombeCbqVeay6tBegW93VHKc+Z6ipZo3uoK3XHJXs/uqLawsGe/R8OQwLX
         TsU2I2kAZdGtX0GE+6DdWAeSjzAx9ve+HuZHyulRDU3FMwMIcKNmsHrVXNj8eB5s7VUt
         3MFLC+p0MlaSbRQXabT9wlZv8KOAORYYW14AtPvRFpzNDz1dX/Dfna2+opLHJkpcKJNh
         1NYU+VcvAFHO7KF52cFRjoYPEekk+PBZ78J5Dan0QX5OQYRdBhmnmK485WPIwplqvSMl
         YwtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=JZUvd1pm;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DG0Eo96u;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768794030; x=1769398830; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=d5APJITP+5jGdaxWXiOaZcuyO2o9m9zGxFgDewAChOY=;
        b=DYCM8XPsx1oyaiz96KbFB3/SVD1XKfBEGNrwlblDQTqPn/D64K89EOIoXlo7vCOloi
         fs7j526xFKnm4av+K1YUiDgAn9ek7O4B6jo/d6SuCXCn/Dy3Oj9+yI2RpLGXbCOd0/ZV
         VsZAPEkd3KnjMb8DDJjdiFUu8bbNDRCXAdEXDwr6T8hVkeELmG/r60jw/yo0awbCZN6o
         MC81I0v75qBOPYyGqgMCGpOWUu22iQqq0/emOHczx9oWXY1FNWkqp/7KRE4QjBe/+T/E
         PX9eHw1uvIKTVwd1/haO1QnWPm8VEkGqLMbf8Xy6F7nu/1vlQTPVow5LwhWXe3CD6fxn
         0Rww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768794030; x=1769398830;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=d5APJITP+5jGdaxWXiOaZcuyO2o9m9zGxFgDewAChOY=;
        b=F2sn/ve+5n2A/9gP/SPPLDka2sRgVNthrRGxi5do9bbhi5SaLMzOZlyiGvC5nVjL5K
         kw+8hnoXTHZ/UJVTiwcuz0OW/W7Hle1dDkWDDmR1WggP4P6XdXcokfzBGSKidqGEQ2Eq
         ESrAxsJ1TPQpMK/VZwdtIxwd2lx2PxWepRzr0gzQQ8j08wnUmA+t869fmoQwp86T9UOD
         ld/L5ooSpluMYC2ebkOnwLtN8DlQn5/kGwE7FacseRx3z6MOSBRcuZddADwFAjxYnYmF
         GyGzzLlihP6eEvQ9oWqhvBoOXPxQq9XGJqUUjqXFZkvlIxN/Gfylb0PuALci0GiF90xc
         KgOA==
X-Forwarded-Encrypted: i=3; AJvYcCWabOkPc/DddgW5aF2mOlxcD61Oz/EOt86VVc+rD9XCLvch+K/U8xUPXLG3apJvRCAtARchaQ==@lfdr.de
X-Gm-Message-State: AOJu0YwYv0BjKIbu487OAiO1N/ssJA2f4vrxpnI1KO54XM7JxGuAEInB
	h+lsRRCi/yS7sg8xB5QS9Kn4og0DtB2Kd97HA7MbVc9NuT4w6Tg8lPHg
X-Received: by 2002:ac8:5952:0:b0:4ee:483:311f with SMTP id d75a77b69052e-502a16c2025mr154333421cf.54.1768794030053;
        Sun, 18 Jan 2026 19:40:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GP/kFO8Lt/Le/TaG8CQpzlDMkmM9/4QxKJGMYUQmIcFg=="
Received: by 2002:a05:622a:91:b0:501:5140:69d4 with SMTP id
 d75a77b69052e-50214a0ed11ls65103081cf.2.-pod-prod-07-us; Sun, 18 Jan 2026
 19:40:29 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWZ1QN4iSCA5OG7liuprQT/zOD6TOCEEWIEM6ZKoAd6drHho8z5ikGZpj3u35PfSP3/KdVF8xyehTQ=@googlegroups.com
X-Received: by 2002:a05:620a:3b11:b0:8c6:acca:4a27 with SMTP id af79cd13be357-8c6acca4caemr850115085a.15.1768794029071;
        Sun, 18 Jan 2026 19:40:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768794029; cv=pass;
        d=google.com; s=arc-20240605;
        b=CRMTCXOp+euzGkW2O1Euu8dPggK07prSeqYWxUS5ERkU9ayZsH0AjZphnvegHMCGMq
         MVpRl8fkJDETIyqwCiRjZ+8stcpUqE377oDkrRxtA1mHRP3CGByhyDFVu75VZJEevVkX
         wL4+LAjtdqGwLPydtzsQF5121w/hKO0s9jQZWmKEMqYyvG6KYXMwtJwX/DlKvvdMmGxe
         ZUee8kk6eJMAtISE3POQ7kIv9IJnjMuxyztaxFBorENawx7VZAiKbztp/PqWLBWMZ9mU
         6DfEMUqq9cYvgzqJo5af8YLamsM3SnOnqOn7l4OHuZjd7oeCCMbEEu5kqpt9EyOT0B0P
         wwXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=dXKVRZuQACHDrb4ujKq4CNnID40YHFMw0nSRLMWlim0=;
        fh=TNvnfp43dsY3aVEuJzrpi2qwrvkTwBLK5sCpt64Tj/k=;
        b=bQsv9/6ny6Bb3zniNHYBNtlb7AuLxC+Obz352nVbhtzvRShi26xKEKCq5caN1d1au5
         /7e/4hGjn4GQnX7kp+iherSjVNpnKveytNyNz1100HyKxuyCVNVPrkzNSHNcxaVMTF7V
         JYxSkCldmuxVDQgWgBVZzmt3stELJiYjRBheZ0gW5VWvckUkoeQeMJfNpJ4S9ukHnfBz
         JDuoDs4zwKO1uPfye0U+Mxn0Z4iTkeZI5to+LSA38hiQnI9ZvlWVdDf6zj2lcIrh2Uny
         SEGFW60cKHdDxzd7JB9pPzjuFlTlXgabPgVG2Rka0Y5/XZSnKKKYfebyobRIBfs63LMT
         gCew==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=JZUvd1pm;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=DG0Eo96u;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c6a72419b1si28194585a.7.2026.01.18.19.40.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Jan 2026 19:40:29 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60J1KlMK320417;
	Mon, 19 Jan 2026 03:40:24 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br1b89p2v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 03:40:24 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60J2AJZd022543;
	Mon, 19 Jan 2026 03:40:22 GMT
Received: from sn4pr2101cu001.outbound.protection.outlook.com (mail-southcentralusazon11012044.outbound.protection.outlook.com [40.93.195.44])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vbm62m-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 03:40:22 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=UENh6Due0Fb9OzkwPlCRIz3HCsi1tpT4bfBxb6/lWQhrgxMiOvOj/J9sZpzvDZ/cZMTkdGC9oNjKcT6beh8BnAm7xOyBK1zz76Y+hLfVHm/0Sa2AL8GQdasxf8/NQYgIfMMVZeFjdxca9n3a3UKuSugvys0lnnxirv+9agLjsyWUw8yPOrpBGVtkcRdoZPzt0OLeCSLaTlT7UlZOv+PHKHAciq9Md+VDItvSBa93oQS7MnXqnPLrk/jL2JiYFhIOD2S3WYrQVO6e529OIigtGIDhMSpWZ4YXevvEp/tMdACK+vdA8aNGUqj8OkLBmPtVev+C7KWxCfz1/rhXm9IfvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=dXKVRZuQACHDrb4ujKq4CNnID40YHFMw0nSRLMWlim0=;
 b=C1b2CpI6SVW8Bhg6iGo0xPHnECnF7Fbd6nlTSrl1CklapZ4w+kSa3h02UnPGT5+Hgv4CbfmRLtK1sQ3dre22xnw0+L74cE2l8YGqgesOPdBMWIx8ri38imFczxVsWSU+7SVhoJebOTe+TAouL+N5OVBY6k1AG/KJFPtm9FsqB25MJ/RBg76QYaZbu5tKSzWm41V1QLKxcYTQuHtm8V4dq60Nor8eYi7DWuw4REBeiCUr4yj1mbaxEmYgtsRflO/RpD18GWx9yXO3UK4Mk1mvR+CPWqT8Knm9ibEGARLWECQzfUsuadilMN9RlefufEnJyccKY6nBtVXddMGiY9mMXQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CY8PR10MB6635.namprd10.prod.outlook.com (2603:10b6:930:55::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.10; Mon, 19 Jan
 2026 03:40:14 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.010; Mon, 19 Jan 2026
 03:40:14 +0000
Date: Mon, 19 Jan 2026 12:40:04 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Petr Tesarik <ptesarik@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 06/21] slab: introduce percpu sheaves bootstrap
Message-ID: <aW2nlIlXFXGk4yx1@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
 <CAJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL+ycem1iR08gDmaQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL+ycem1iR08gDmaQ@mail.gmail.com>
X-ClientProxiedBy: SL2PR01CA0015.apcprd01.prod.exchangelabs.com
 (2603:1096:100:41::27) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CY8PR10MB6635:EE_
X-MS-Office365-Filtering-Correlation-Id: 349215c3-b048-464d-2327-08de570c748c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?V1M5WFlVUEdiWHlFZzZCbmpXSTJ4Qkh0YnE5NjhXOEM0cWFVcXdxaWlXdTBs?=
 =?utf-8?B?allRZVUvbGVRWnJzTzI4bFV1MTlEY1BjSGNaRXg5QTFBZXFSV1VTSkFxZkZG?=
 =?utf-8?B?ZzBLZy94NUJYY1JtWGxQRHFDTERUUHNPL3k4UmQrUVI1QWJ0WlZ4cGp6VW5Q?=
 =?utf-8?B?YlJWcHprZ2FydHNYUGE1TjlpV3lSSDJsblhrZTVPT05CODg5UU5KbktLRWFs?=
 =?utf-8?B?WTVVejRDaERGdUlUWXFDZkhyUDkydldvWE9PamkvOUZGUjY3ckQwb2IxOFRS?=
 =?utf-8?B?eVdxN0tlelgzNm5hbmEyZTM1UGN5c25LV0ppWmo4em9MeWI2NTh2bTdQc2ZD?=
 =?utf-8?B?VG42YUN5dWpIWmZHVFkyZUJRQnFDRmIrVVNqSVplcTRSUWxFTkE0ZXZPeDhh?=
 =?utf-8?B?VzhRcjQ5akc4bXUyZnRDQ0ppZUJBamZaOWswcE9EYmxjSzlZd0tBRFZGbW53?=
 =?utf-8?B?NlN3OExSUUVwK0w3N1VCZURGSDEzdU0rdHdCTjhrZnZYTGM2dGlkS0dHZGZn?=
 =?utf-8?B?ODFkSmtNb2FPaTExL0RDZmJLZGs4Mzd1cm1aVE9QQ3UrWjMwT2MxdmlqSEhD?=
 =?utf-8?B?akkwaktIdkhrN3dqYTcwVXlQVzZKSmpGS1R5MThKdkVvQjB0K2U2dmhGVjAy?=
 =?utf-8?B?dWZ0ZTBYYU9wanRJRDVzUnhJSGx6dVp0UlNLODl3QVJ2Z1Q0dTlZdGN2YlE0?=
 =?utf-8?B?MkN1Y2czMGxEVWx4UnlvczNZSEtvZitoaHZjTFRnSEZYazErOGVHK1lZaFRn?=
 =?utf-8?B?UG5LMHhtOUxQeHJlLytiMGlqYm1XVUFHTTNKTU9OdzEvb011Qy9Ud0pxaEZL?=
 =?utf-8?B?c0ErTTVBMzBGMHo5eUNTekVkeWtvTUVnaWd3VUlCNm5uUU56UDcva29xTkc3?=
 =?utf-8?B?V2xMNy9xN3A3OTl2bTlscmtyOHRvdXhDZmVUTkg1em9US2RnSVNmaXNEYlhx?=
 =?utf-8?B?ZWxTSmZXbmI2SlFQbzE5N09XbVA4N1hXcXFRdzMvbFVrOXg5ZVAzVkExT2FX?=
 =?utf-8?B?Mnc1My9qaUZ1WkJUZzFpY29hdG1hKzN6ZzZLQTNoUlJHcFNQMzdORjVkT2pQ?=
 =?utf-8?B?VXhYWXk4V3plQlplSGdTdmNOTU8zb0g4S2tkT2doRm1kL09BcUdaZWEzZDBO?=
 =?utf-8?B?Q3dNRVZ4TE94U1Y4VTdwbWIxNEkvZXN6K25mcEZFTjZzbDIzSWpvWE9vdUZt?=
 =?utf-8?B?OHdycXFlL1F6V3lhQUdERzRYa1RNZVNJNDBOWXBYdTdGVXcyL0Y3VlI1eFAz?=
 =?utf-8?B?MHJ1ZVh3SlNHb2dnNWh2SlNmNnBwS2xZdGZWdnBKRzVHbEpBS0tERGRwK1I1?=
 =?utf-8?B?ZVVjeVFkREFxSUpIVU5FZkNvNnB3YnBVSGJxVU5yNElORjduKy81WW5qV1p4?=
 =?utf-8?B?a1RTdGIrYXNrcnFuTS9BQ0s2SzdwN2ZMTEo5NlQ0cmpJVVB3eXMveXl3dWhF?=
 =?utf-8?B?RFJkcUkyZkpWeFh0YzF1b3hRU3NsdVk5ZkR5SUEvYlR1ODNPcUdGUWwydFYz?=
 =?utf-8?B?VFVjRFNtMTQvSHdhL2JEczJNeXFEZ1drMEF6aG5lY3FBU0hEWTU5dVJLYlo2?=
 =?utf-8?B?d20wdmFZMVZHZHh4QTg3VDRzZnhnczc2N2hidHF0M0pia1o5TFZhL3A1STRS?=
 =?utf-8?B?WllTRzFFdHdMcUQ4d1NRQXNiVXhoUGFXemd6dDc2a2RpRmN5bVhxODk5Z2ps?=
 =?utf-8?B?UTluR2hyc2lCT0JhSTVpQUI3RXFpakw2YlJYc2xyQlhVajF2b2xtVmd2a3lt?=
 =?utf-8?B?ZTRjQ1pQSWRCa2l2UkIrQ20yNkRuRTJ1VHBBU1daRUxJSjBxYkQ1OWpxSEVh?=
 =?utf-8?B?U0FIMC9jMXdxZUgzaWs2eGVmUU05WE9CWk5FZ1UrY2FQR2xOdStsV1hzeURV?=
 =?utf-8?B?b1pKVFp1MmJLVGRISXNNb0VUTDU0V1luc1dKYkFvUTBBMHpCSEhyaFBPSDJB?=
 =?utf-8?B?SEZOb1plbHl0Zk5YeWo1a3ZrMkpTbEhJQmFPQVMxQUJGZkZDcW43bHRYQk5k?=
 =?utf-8?B?VU16RVNlYjRuRE40dWVRVlAyd0JOd1AwZlM5MDZiWnlZd21EQ2U3bDdpci9V?=
 =?utf-8?B?WlRnNklSY1pjU3pFN3pyVnI4QXYxQ2N3QmhGRkJRaVhYMTYzK2JyVkl0V05D?=
 =?utf-8?Q?9/p4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Q2ZXREF0ZmEyU1ZQMDJCTktYUVZxNHpxZ250WFUwZTFqWnJaU3FJQXJGZ2lp?=
 =?utf-8?B?elB3dS9Pb285a3E5QjlHSHVqWEk4WWFEWXlqZDdtc1hveHEzVC92L1gwZ3ZV?=
 =?utf-8?B?VFMvMjEwSzZTQ010RmNaWCtaZlJseGEvMWpuWGpZRkdCTGdRTE5KY2R3M0ky?=
 =?utf-8?B?c1czNDNQeTVhQThuOEttcitHODFieTNweHNwWU13RldHbm1vcUpGSEJHQXhW?=
 =?utf-8?B?ZENzalJQaFlZc24yYnJhYzA2VjR0YzIxNUI1aEF1akIxWEFzYUx2MkFwaWZk?=
 =?utf-8?B?b2JKRjlQbEhWcUdrZVRZMUJVZWdrUE9Yek9nck52N3NJUVlRTmlzVGlJUFVM?=
 =?utf-8?B?dS9qMFJtVmdMWmxsY3FDcExqUzUwVDRDMWZ5N29ackxXeUM1YStHUDFlQTdT?=
 =?utf-8?B?MGxtKytMZUNZRFRadU1PK0ErTmMzV3Z2ZHFMeHRiYXlVdG0vZG5odkpTWmNw?=
 =?utf-8?B?ZGp5K1ZSOVViczl4ODNNTkxFeEliTTdyeEdnN1U3UXBSOTNaT1N3YjE0a204?=
 =?utf-8?B?ZWYvT09tZDAxeURrZjlpSFBoMmg2WlBDK0gxTk85YkFBa1VUU2wwYVorK0M0?=
 =?utf-8?B?MGUzQzBQK2NyaFdrMCswU3ZSVGh4d3BvODdLTTFtSDBDTjFXQndERnZrd0pN?=
 =?utf-8?B?SU5LQUoyWGhNUG1tdHM1cTZ4UDQzYWRLVUUrcTY1NTlVUGo3WjJBcGsrL09F?=
 =?utf-8?B?K05vRUw3aEFWZ3BLRWR3WHVPb3dDMXhvcXdabFM1NHBjaGhEeWJQa3MvMEtZ?=
 =?utf-8?B?Rmx1Y2VLVXFOYmU2R2d0Z256bm5qSHpzemtNNSsvSktUeUt4VWZVdzlMNTRa?=
 =?utf-8?B?bmMrcG52Mi9lSkd5OTJYY1M5Y0ZEbjkwWldmanRBKzdpTUh3ZGxLbmNNRDJP?=
 =?utf-8?B?eWJEdVNuRkJFM0F1NklvdDlwcnpLZmw5eXZVd2hRSzV2L0h2YXUwb0wvbkVO?=
 =?utf-8?B?ZDBld0JVN1BndlVCM0E3aDd4blNMRjFDM2lOeHR0U3JWc2QzQ253N2g1Rndm?=
 =?utf-8?B?ZHYzSmEwZHZaUXo0NG5YSFN3b1hOMnMzR0FYd1dIeTUyQWtBcEduVjNnbmtT?=
 =?utf-8?B?WkNJSkJ4SHZ5REJFNGJzNExDZkkrRDdodkFMMlg5bVlVKzFFNXd3NzRRSllo?=
 =?utf-8?B?S0U4WTl5UkQwZHZBc1hYZFBOeFZHWGtqbWRVeFFGNEdlRjE4MitEQnBmdWtm?=
 =?utf-8?B?Wit5Uy9WUkRKMTlRUCtPSjhMNkZvdnpWc1BDUkFIdTVTekhqS214dzl4OURT?=
 =?utf-8?B?OWdFZnJacklsbDdTbGpOU3VpQ3FZM1dyTnFTOVJPMU9KRDJzVFJ6Zjd3b2s4?=
 =?utf-8?B?dFpreG5uaTJVajd1UU5CT3hOZlpLcGplWWNLWFBGU2JNekFzeG10UW10MDhr?=
 =?utf-8?B?ODZRdkU4eENYOVVCSHZGcFRHQnRzbHU4eUp1R1BpMDBKUkRvUmlPN0lxVWQv?=
 =?utf-8?B?bWNUM2lzWDFHSHB5ak9OVk9DdkpZK25leThFYTNQNm5qV2dKSmlxMElQdThU?=
 =?utf-8?B?TDRDVTNTUWJYMFJxZ3VDVjBuZnQzQzlCYW55Rk5IWFVFNkV3SmpSem1NMUxJ?=
 =?utf-8?B?UVhQSHlqc2Z5MFlFSWxBaStnMWFHTGdQYU9EQW1jUi9XTEFDMWFFQlFKSGxq?=
 =?utf-8?B?Q2loZ0x6WVV4eVk5bllkOElydi9DLzQxNGM4TXZPT1NDOFA1cVlQV0RRS1Bh?=
 =?utf-8?B?NlZkemg4cHRIQWdUMGFHanJrUnVpQks2cWRhWU01SUdseHk2b05BU0llTDNu?=
 =?utf-8?B?UFlHWUxTOFcwbTJVazFuSFZRVGhtbGZEV21STzJ0cDFqUUd2ak1RYTBxdFM1?=
 =?utf-8?B?aG16TTBTTSt3WTZJL2VhakROZmMxb25jSDhrSlJXQmNaRWozVkpUMEpWbXZm?=
 =?utf-8?B?a0pXbUdEeUV2amRiMzlBbDJFVkRDTzZKVkE5cmNiVFc4OHVoaHQwNXhhZE9k?=
 =?utf-8?B?K0RaYmptYWQ4aDNVb1daYnBFWm1CNjBQOVNlR3AxbC9XdGlDL1AxVUNCcUFs?=
 =?utf-8?B?d0o0MFVSUDFHczUwZDhyQVVydk9acmJuOWJ4VVFSbnRmVExZai9NQkhnb0Er?=
 =?utf-8?B?MkFyTlhxMm9IVjR5bTlvV1VFdUgweDM0UG5uWmRBK3pDcmx3MlREYUVBSE4w?=
 =?utf-8?B?dHRlYUhlVVYxZ0ZjRUdBUm9IWGpNaWtIZXZ5TkFkOE9XVW9SZzNDZmNRZUts?=
 =?utf-8?B?a25xVmdycHgxR1FzeXY5YVV5OGdMVnRFZDVjVFZ2eGNpK3BuWmUrMFhUek1U?=
 =?utf-8?B?SFJQTEZkcENEb2I1ZlhwM3owa2FlYWxwT05CazFVNXFUSEx5bXp3cmlUYUlp?=
 =?utf-8?B?NnovRzZpVTV0Y1Z5cGEreVdOSXNzUC84bFJKV2ZDemowMDJnWTFPUT09?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: k+abDA2Z8QMLHAb3qyhCPEgWiPB4Z3Q4e1DBA6tmZYntC07zTqukfsEHB8zaOg7xPjX4LP+XbwySOZkGCkPAd9DZYhoHU18pvKt4vcx5i86/w9K+IBfqKthU7i6qXKMQsJ3/jUkBX/QfrQU/sxLw15DZnxc4Fq6yvJb4r9qjnS8SQLW/mw5XL3B3KiNSwYNvQjkeao2bySQQnXyB3r6Rs/umacSBD7xFCDLAQ1KPvVsNF6zaehFIyDpEVpHmnU1g2y9vAfZtLppdxX8m3/AD5bM0YH/I20P7qr4WVB1IqNdfRi6lEkepZPgDME/ffgDoCYlJELh8nZIsceEuK2C1YTrbN+qovgiIb9/Yw42CWAJcgXxg4YP4rH56kZau+BoPYT9UGooSb6s3H7pWgJXZXe03upXAawuqXhuMzJW15TmrQ2cJ82/n/3Oiz9hqs2YvrMr+Lfqgv8uXPmu1wjG5bAAUE75yndlQ/bSRca4W4UeRzBa8gkL7Nf6G9JcuhmJR7vXVtrEljZ5proOSjWiuA+pcyOPPescBzonpPSiryqw0D4PpPUPSIZA0IGcenDs8MZZ00s/9Bz1oWrAHUApizoRSv2FUOWVznDz7EJBTdJs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 349215c3-b048-464d-2327-08de570c748c
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Jan 2026 03:40:14.2966
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Qp6tvdZPLZr2lK8xH/DxMto8Fy5U+FbZBVZF8Ow2JMJrlJv4GGyUjD2/0TRDzr9eSIWjACd5/B9sJkt4DPwvjg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6635
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-17_03,2026-01-18_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 phishscore=0 mlxlogscore=999 mlxscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601190028
X-Authority-Analysis: v=2.4 cv=WbcBqkhX c=1 sm=1 tr=0 ts=696da7a8 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=IkcTkHD0fZMA:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=vNGDkrUGIHPNHXQ7m_QA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10 cc=ntf
 awl=host:12109
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE5MDAyOCBTYWx0ZWRfXyHdkO//mkT2E
 AmOhKOh/sRM8LVjF2+ZDHz/LVLqItPebWWMIZGd/76+4AilWy1tBeaFBPlf6qxe9JuYOGIvnhR6
 2IJ6mUtXi+3FBhxNjW+2Wm+3j6xSXXFcPAKU3kiOp1Ifxlqj5t68IJMW37AJhEpLOpsKCCeVPwl
 SxWBq5BWppIbh6dpclVxtFWHLx6YfYNI/b8vMWoYeNIRxWr4hKdbx7KRgBK39TdEOp7wGNiNfLW
 A+S2VY1gMoqrrHtFvCvOaJXk9uMahm1nSbINzndOticaUXB7Yhn35zTzatGiCyMOqD+w/5HXAA2
 l7HBduGxdi4Riv7cA0T2wIjpGvu9wGk1XvLBf9g3n/FizYESyX8Fjsig7l6j2gcv4y9PNHmuWnj
 XfWx5SLo21gCbYhVRjD8cSmMNIdlDYLW4BSYu8OuOMlyYTxkYC8D+ALRD3DIb+7HES2wF3/77NS
 9Lb9K29Pc65pz3/hJZ30KFS/0Per+3hWPsyRoQZ0=
X-Proofpoint-ORIG-GUID: gxkvvMAMRBf2cA0XcQ4NOddJGjJx-7_j
X-Proofpoint-GUID: gxkvvMAMRBf2cA0XcQ4NOddJGjJx-7_j
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=JZUvd1pm;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=DG0Eo96u;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Sat, Jan 17, 2026 at 02:11:02AM +0000, Suren Baghdasaryan wrote:
> On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
> >
> > Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
> > sheaves enabled. Since we want to enable them for almost all caches,
> > it's suboptimal to test the pointer in the fast paths, so instead
> > allocate it for all caches in do_kmem_cache_create(). Instead of testin=
g
> > the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
> > kmem_cache->sheaf_capacity for being 0, where needed, using a new
> > cache_has_sheaves() helper.
> >
> > However, for the fast paths sake we also assume that the main sheaf
> > always exists (pcs->main is !NULL), and during bootstrap we cannot
> > allocate sheaves yet.
> >
> > Solve this by introducing a single static bootstrap_sheaf that's
> > assigned as pcs->main during bootstrap. It has a size of 0, so during
> > allocations, the fast path will find it's empty. Since the size of 0
> > matches sheaf_capacity of 0, the freeing fast paths will find it's
> > "full". In the slow path handlers, we use cache_has_sheaves() to
> > recognize that the cache doesn't (yet) have real sheaves, and fall back=
.
>=20
> I don't think kmem_cache_prefill_sheaf() handles this case, does it?
> Or do you rely on the caller to never try prefilling a bootstrapped
> sheaf?

If a cache doesn't have sheaves, s->sheaf_capacity should be 0,
so the sheaf returned by kmem_cache_prefill_sheaf() should be
"oversized" one... unless the user tries to prefill a sheaf with
size =3D=3D 0?

> kmem_cache_refill_sheaf() and kmem_cache_return_sheaf() operate on a
> sheaf obtained by calling kmem_cache_prefill_sheaf(), so if
> kmem_cache_prefill_sheaf() never returns a bootstrapped sheaf we don't
> need special handling there.

Right.

> > Thus sharing the single bootstrap sheaf like this for multiple caches
> > and cpus is safe.
> >
> > Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> > ---
> >  mm/slub.c | 119 ++++++++++++++++++++++++++++++++++++++++++------------=
--------
> >  1 file changed, 81 insertions(+), 38 deletions(-)
> >
> > diff --git a/mm/slub.c b/mm/slub.c
> > index edf341c87e20..706cb6398f05 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -501,6 +501,18 @@ struct kmem_cache_node {
> >         struct node_barn *barn;
> >  };
> >
> > +/*
> > + * Every cache has !NULL s->cpu_sheaves but they may point to the
> > + * bootstrap_sheaf temporarily during init, or permanently for the boo=
t caches
> > + * and caches with debugging enabled, or all caches with CONFIG_SLUB_T=
INY. This
> > + * helper distinguishes whether cache has real non-bootstrap sheaves.
> > + */
> > +static inline bool cache_has_sheaves(struct kmem_cache *s)
> > +{
> > +       /* Test CONFIG_SLUB_TINY for code elimination purposes */
> > +       return !IS_ENABLED(CONFIG_SLUB_TINY) && s->sheaf_capacity;
> > +}
> > +
> >  static inline struct kmem_cache_node *get_node(struct kmem_cache *s, i=
nt node)
> >  {
> >         return s->node[node];
> > @@ -2855,6 +2867,10 @@ static void pcs_destroy(struct kmem_cache *s)
> >                 if (!pcs->main)
> >                         continue;
> >
> > +               /* bootstrap or debug caches, it's the bootstrap_sheaf =
*/
> > +               if (!pcs->main->cache)
> > +                       continue;
>=20
> BTW, I see one last check for s->cpu_sheaves that you didn't replace
> with cache_has_sheaves() inside __kmem_cache_release(). I think that's
> because it's also in the failure path of do_kmem_cache_create() and
> it's possible that s->sheaf_capacity > 0 while s->cpu_sheaves =3D=3D NULL
> (if alloc_percpu(struct slub_percpu_sheaves) fails). It might be
> helpful to add a comment inside __kmem_cache_release() to explain why
> cache_has_sheaves() can't be used there.

I was thinking it cannot be replaced because s->cpu_sheaves is not NULL
even when s->sheaf_capacity =3D=3D 0.

Agree that a comment would be worth it!

--=20
Cheers,
Harry / Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
W2nlIlXFXGk4yx1%40hyeyoo.
