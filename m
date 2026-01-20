Return-Path: <kasan-dev+bncBC37BC7E2QERBR5IXTFQMGQEEATPBII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 957BDD3BED2
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 06:36:09 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-79269803c05sf57233727b3.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 21:36:09 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768887368; cv=pass;
        d=google.com; s=arc-20240605;
        b=GVbGFSyQSJA50zPto8WiC+LUhiG/3ZHzSz85DuhaimhmKVkaK+tI7TYGkQevrY9tGo
         7aqNu3vuaszSaFXl9sYBiN8Tmh7m1jN5ER4QWaznhPCRLdTyUoqOQ9jPE/TZ5MTieUwx
         JFu+hgAUixa0jb3OgXJmooM56yM47rT0CszGY9sz2JZnh5aXnRbdtKWn6EEnUN2ExbXm
         Qn5Y7lZNFlK2WUQ8AIgRkUsQ0QtBr0MyXV0jbwIeuVwqcigUsq4gwB7MWlvMud8bQ0jF
         2nUplpRQ6L/QzVzxvdafAAorMkA5sOOVe24H1jGsBPGk0KxjXbHk4EUjmJNWIsB0gi0v
         gGiA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=rT+5mQw7arKFjLfcCUt73biNTlm44X6o5GAPptP+yQ0=;
        fh=iATQl/Mkj22pEyGva/eEnAXd3lE3wGf+eLS0GngkFR4=;
        b=lTvbVW6v4cXZIAxi1m1qvIHEMJTxdfxbOi+Y3RsCktDjJ0UGDmm5RuWWu+AOdeq8dE
         +8qBAO1+6ytEHRCPGVR+qs+b3R/jgRue65UAZMASgQIB9yKAupBA2Wn7RnrTopABrZXJ
         R/gEm8YSX4bNK7u6jDSMrineeGeDtajT2I41CpmVD6q/eFHVmKak28ItCbSUaeNpxR5f
         MddR3yiznBu9l/KDDV2/jVb6XFQG2DRACePMpXWVmhGew6HMHA/v50NeQg1jLGuZMIAP
         Bj22h2nWrETLsxVLnUYep70y9OdStSCYr/I9uJeRqTE0IKplqpAza4gUHeKtVEZcUCwQ
         voog==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=AzIyA6+e;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=N5+bAiHF;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768887368; x=1769492168; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=rT+5mQw7arKFjLfcCUt73biNTlm44X6o5GAPptP+yQ0=;
        b=JCEbsGXfli64b6bGqw+R8RRLGSKFc2fOXnxLkmedgQy80HPxo07SQByKoRV6sDZE8o
         AGVhW3KV2d7RtntTDoZG5n/5pgWKCB2mFgXHVv9Un2t8RTPgP3vqqMdcD/CC8L2a0URH
         DD/UiAAZ3+H62pcgjll5vTF4JS42KjPZuxP7vVYbb8l9FWmWAdZH7zmIjAAL7YG7/q9T
         RnNAERfcC8hJDeC+NksI/fwiP0wHZIUOleOuKLpzRyc1SX8I++fz862NnrCDZrIEoWR2
         d1vfnfmnYEFJVmsB02YryaJ1ZWmTDZaq0NXoeZVJVi3+aMYORGNfdVLqC3t4oRu82aKG
         JxKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768887368; x=1769492168;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rT+5mQw7arKFjLfcCUt73biNTlm44X6o5GAPptP+yQ0=;
        b=BPJ9kBs3rG/Cfi52CrDBV6b0WQ+2qxVUBS2bxpaF26UgPzAyNDk6Qgn5X7DJ9MSAGu
         T6n74QvdEs0fXiaYqJxGKdLb9yPOXX4iVlz+lfDxWTmVFvhp3Y5zznCUEtgjhB1B+fZG
         dSltUtZcRChR1DWCAthK2P2a6KFMwPO3RtZ30TcpMLFWW8JIGZuZPsCHjPxpaKQdew5/
         HwECrJ4JjgtbzP2ICA8Zx97okPYzxhcu262Kr6eC+faF47bNM0ZamPQPTk0zISQT2+Ur
         vBea8qMEtXMcgUJ0dMAqLlsRcL2nJVASs6M8ocG72K8P4NzB/LTPVtgHGrA9xZIvV03P
         bw4A==
X-Forwarded-Encrypted: i=3; AJvYcCW96gH3lnM0IWzWftJ3dJeMNuy1A0wsmWqT01CZBeaRBUlTWH1/VOk6eWgn6XP7ojIkty8TBw==@lfdr.de
X-Gm-Message-State: AOJu0Yze/tWy8GabcCWW68BXCxy0nH0Y0e89BgWmXTVJWOwhlaWwnvxw
	sXjqna0eqalctbFP2XM6RCCaoKfBxW9TAo22ZcsUgCoN5yFniMEq1/Ju
X-Received: by 2002:a05:690e:1504:b0:649:3297:6394 with SMTP id 956f58d0204a3-649329763a3mr3084428d50.13.1768887367871;
        Mon, 19 Jan 2026 21:36:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GHLDhZN5j8mYo/grJ6iwdiycW54hQyy2gF3f4ujuID0w=="
Received: by 2002:a53:da01:0:b0:646:7a94:ce27 with SMTP id 956f58d0204a3-6490b91e2b1ls3658070d50.3.-pod-prod-05-us;
 Mon, 19 Jan 2026 21:36:07 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXuuo33IeSq3i34plaSyodPIb2KkxDjTy/ISRP8S0qCzQctGW+UktZBTbdMVah51FbQ1JlqSoRvgn0=@googlegroups.com
X-Received: by 2002:a05:690e:b46:b0:649:4be:2071 with SMTP id 956f58d0204a3-649176e3096mr10266284d50.24.1768887366799;
        Mon, 19 Jan 2026 21:36:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768887366; cv=pass;
        d=google.com; s=arc-20240605;
        b=c3h9q+AAhvUEUXMDR/MR8fg43OhMikP5d1V4VPTabCDxei4JSJNQD+spjDv0FghUQX
         hgRgNHDUsUKRQBvbZGGomBaf3Zjh8qOldDFo9eoEk/MlT6HDWRTjhvpYisX5Ob71+XyZ
         8R6vr9Y031tpbtaHG88cttkM+FodkeR73B/ADpjsyfijC46fvi7metgfNx9SDjO0jpea
         mqEpS6IuJ3Lm3Xo9g/OQr58IFMB8eGMRvu0jyHuHdXKe6oBo8WEELOyQBtrE/5SmLlMp
         3KxoTcrbfR7QPT6IPed6I68X7hPzgkAQdo6id+SHROB7neFGu2vu1P4spA/J6P06U2im
         Ld8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=6Lw1vMCUBFMzP98hEOhbgZ6QP29q0BLC35G4exCG0tg=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=BRSRyBQaYom474nnS8npIg08ZcLQ5pXT016tq9AFNroBZoYQFfc84zhDtpIEaskB0m
         XLHm7e9yqRhPges9MehngGHesz7yAqeWtuKwdq7dxn7fbXc30PEzTEvUwS6X/aPqhiQK
         i2a5iNxZLd7WWN1dglnyTpXSACsfyuGLJIpS5MxJiyR8wcHtNXWwXVt6ECf3Xf8LK98Z
         W/kLgLfDUDDg3sluh43Bm1sVylPGdZpa3Hv0XLC/TAh+e5XamQP84Ned1juuD1szg0Es
         1VioUCGEMJ+PE4RA/ktnc8qnrHPaInoWBnnCJfVjITfHHa6T273gt5Y/oVG7I2S7MVa+
         p2og==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=AzIyA6+e;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=N5+bAiHF;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-64917006683si393847d50.2.2026.01.19.21.36.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 21:36:06 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60K3mY5u3021113;
	Tue, 20 Jan 2026 05:36:04 GMT
Received: from iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta03.appoci.oracle.com [130.35.103.27])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br0u9k55v-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 20 Jan 2026 05:36:04 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60K4ApD3018914;
	Tue, 20 Jan 2026 05:36:03 GMT
Received: from dm1pr04cu001.outbound.protection.outlook.com (mail-centralusazon11010020.outbound.protection.outlook.com [52.101.61.20])
	by iadpaimrmta03.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bsyrpxhq6-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 20 Jan 2026 05:36:03 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=AwwQVbWSNcFsgJFaeUwHmWtxksdFJrrLU2U5++dg0ma8Tw/vTBqToSXdB1BFvGWjkWE9hdWKe+ZUv2G+1zUagkDEeWp6TcLuXDu6S3lmNobiJgIxLozLSeZZCoLruJypuJ4vgmDuesY+PNUbvPDeLkzT7H5LBDIw8oCL2mLOlICk4ByXewEoZprTNgo6YZZAxooM0xkUBs7PY0i0PN9nsgTEhQmI4sUkEPGJVajppr2+h0BI4BfjTKB2Ikhj/lg7St7/C55iFGZTbaPQZ5E/IBVx+bKOU4sm7MpVm7N8JjoaqZtrzvnD6jgufIAFj+2VnZZznc3CAulXNEdoJFYCFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6Lw1vMCUBFMzP98hEOhbgZ6QP29q0BLC35G4exCG0tg=;
 b=PtXkWCS2M1gUT8Xh18sVX+3RsdyHQ/P5VVTDECSoNFvZzYOwt501ssJfJoW17lDeaowUs3w8p4xVv26SrG/w3cs8trjjzW24ev6+hv8c2KRDDi+FrspCaBHCkXCpr6uHfbSmmmjUuc/ewmw3HySLrBeXSQ0C9b3wDSCW6Skimve17NCV3fmXVncG5m55qwMs1lhBZ31dH/nZs9B16Wlyom3/3aI3KHKPnJjqirJsfxWCqTKJW471ttKBHTBrfH7DPTu5f809eBvlZ0Ld2WreaASL7Rz66paiFf8bD0rhusn+njQRySgAiJOD08cF8PdQS/vfuBqQmdtKX9ShWQeUIA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by LV3PR10MB7769.namprd10.prod.outlook.com (2603:10b6:408:1b7::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.9; Tue, 20 Jan
 2026 05:36:01 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.011; Tue, 20 Jan 2026
 05:36:01 +0000
Date: Tue, 20 Jan 2026 14:35:50 +0900
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
Subject: Re: [PATCH v3 12/21] slab: remove the do_slab_free() fastpath
Message-ID: <aW8UNjNBXf651a_1@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-12-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-12-5595cb000772@suse.cz>
X-ClientProxiedBy: SL2P216CA0170.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:1b::12) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|LV3PR10MB7769:EE_
X-MS-Office365-Filtering-Correlation-Id: e7a16174-3a8d-4575-9acd-08de57e5cbcc
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?1fwlUfBpu5t9XR9fv4TC9CMyYwkGT6eQAGm4OEg87WWiixti6ZSawgd4uiOF?=
 =?us-ascii?Q?UmA2AbjGKEdWYF0xcPXrxgOJ0DjtJG7Me7VVTrUeKKtY8Rg5yjtOo/qLOzF2?=
 =?us-ascii?Q?jqjjtPkqh8YyiBXFm8DTrNe8B9sGpirH1dRVUhej+jCWQ5dGKogjwmzzNsqn?=
 =?us-ascii?Q?bhmqweX85mshtFfOXty/kZPcKyOxgF86O/66t9QeUqs9n5zvijRYrisacbw/?=
 =?us-ascii?Q?v1CDe3O6q4ZPoRGRKSMLmltXYPgLiplzA4Ld0iCJLl1ojDy4vCsxpGa0PGcY?=
 =?us-ascii?Q?wfdg4myE8ZCyRyl67+o/I1Tra2pSdPi2XHscaxbmv6VPfBC95Jt5+npKpqF5?=
 =?us-ascii?Q?l/a/pzDt3VBjB0pMO1RQyQikZDlWEuDcGkVvTUhy0KLi3ukNTHfDMdKSFn2d?=
 =?us-ascii?Q?uVCayVd5rWIfGPmDUZIIMn55Hu1zUYU22DR7q0uDXxKoiGSCAjZdE27qE3Pf?=
 =?us-ascii?Q?ADDuRxHdwcOOMJz6FO5+y9YM9ji3CUSrvR0l6xhCKlYr925jOeRZVhfaYwqw?=
 =?us-ascii?Q?NlhNKlHzeKoCXZuz02bprnsBZP6qUTrbbRXpCeMOt5eh7kbMyR8ULEmVECEp?=
 =?us-ascii?Q?9M3QbBLVkpbe+JMGgIGgXY5DYVkvUQlXDuajS4o9ZEZ0wiy+r6AvuiSTfdkT?=
 =?us-ascii?Q?raDW7r5WPOen1lJL2wAgnJ9GBMPMRo/iriRf1f50Z604gPmf21ZSPODcW9BM?=
 =?us-ascii?Q?kSjTrswaLVuLKSds612G4ZdhUo0k/BJiYkoaZ22YyEcAZWQg82VgV+FLPYLs?=
 =?us-ascii?Q?dFxn+sxbHYKIMcfglwXCtsBPOU+HgJc1QPyWdhDUDKGphyuHd74OlHy+Xyyq?=
 =?us-ascii?Q?D6UiJTmjlk3I6FTDZGy3poLfLsLI+1HrcyjgofVgSUmbCEKFiMClHI3Hvc5k?=
 =?us-ascii?Q?rVRz4iozKP5+0+XFTHHYvUBsv7IVZCrDjit37lJEhd25mCEAA0GDvDkYdfXP?=
 =?us-ascii?Q?aKq5QXTujfcsBf58ggtxtKm+VIoULoV6Ul8UxjAtQs/oqeVGdNDUJpQQlLD7?=
 =?us-ascii?Q?EoeZaPrBfTyKDG7Jw3URnt5l+WQWaptLGN46SFIQN7Ms9NNptuAxZwJAb5Gh?=
 =?us-ascii?Q?ncVx8SvYWBvLATJse8ePl1hB13sEngdtQCSoj++AP2NO7b3IeLiYlDthmX5E?=
 =?us-ascii?Q?SQHAzf1EIgcyrUi3fthwMWa53RM9XA9ma4cMqBXE67uUQoLJSm6x41jouXVi?=
 =?us-ascii?Q?543fEygpmS+uav2w10rJnKjpH6Dn/pJrb8J3sZnxMgnC9yhbGdRQICJzfBt9?=
 =?us-ascii?Q?dUOjVDRBX5iBpS1cA4yB9/d8Nmz9qfYs6Xc05dQvR2gzGcFKPyAlDc77XtAF?=
 =?us-ascii?Q?lAjc/7AqEaDi6bGqaBEnB4Pyfb8rJcppEc7O68Ad1y1uGP+XgvNO/mnriyr9?=
 =?us-ascii?Q?6IJDva0Sgw78V3kO0b5dU9Ha7UeoZcggPWJIlmMf6acDzC7kOEaZ8efKIOXo?=
 =?us-ascii?Q?J7dOMCqZKPoFs89Z5b2v3u3igmtAFoVoIZlCXQe77IY/AFPmuqkWTyJlm67N?=
 =?us-ascii?Q?AA2uIea1PsGSTL9uzZdhRGllf2R91jRXZjAylbWRpJvwW14I0gbm2S1eID1/?=
 =?us-ascii?Q?xldVMZ39/k9I27j7vF0=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zeRZ42z7l2nQWCy/y12BLUss1xb+a8JOHgO+kRUZNrLEmkudHXdVQG0YX6/W?=
 =?us-ascii?Q?6Utv/V+8aWGeiBR9Ay3rNJF3xy5AJMUIybN3g7bvASqESZdQkUYXPmt3Iti5?=
 =?us-ascii?Q?d00sdwZIrssxViiVB6+wD/pEVFyh1YZCuw9y0x3ohsxE3CNlyKtAUsIJgTte?=
 =?us-ascii?Q?Jh/RaBaE6myoZ4JDCWyGLbQn7gJS7eKyNSEsy25idOnZavggjWKMVzZtcYUk?=
 =?us-ascii?Q?i4p2psUf+2iw3swMItPDEHJsFb63uIkMCY9xbAQmuUdfW30q6jR7V159Xpma?=
 =?us-ascii?Q?Cwpnre/t83KjLtfxNQNHCeYzdYUqAgeP8edk4oj5f6WD5g3aeRWBmEzJ/Opc?=
 =?us-ascii?Q?iPnm95TN6MyZ56K0JFwxzdXlC/viduV3/ccR2C2V5gvqbHSfxeFz2cEuizqg?=
 =?us-ascii?Q?CLndN2MkLlDJTjaO05p1SkoqjWjrjc75A2Qtn0ZJHz+v/Vx1R4fQXEjdgjqJ?=
 =?us-ascii?Q?EifaOCYhLaMRT9qr0RhDkmmkL39feY50jhhjv8DBoKPYzmLLyILpEqxeADwJ?=
 =?us-ascii?Q?46p2UHfbODUilPZ2vOpUif3TjpuW4e4Re+TMhVBrfegAjtxsckzS7x9DcQKJ?=
 =?us-ascii?Q?7BhDYI4dxVKhQsELUJBEv84RvMJN67NX/+MAAeAF+n2lMnQR7QN/HmJC5FRg?=
 =?us-ascii?Q?3zLiqRPgZ45pnaV3EmIZ5UuwkP1zWPsjM2rNYhiPEHrY0CMbrfk9NN4hfiEp?=
 =?us-ascii?Q?yQAT1E41OHDYi0ZpRegDPvKLFhWOWFxgjL38+mFKG/CPHgVFdPm4P31ASJDu?=
 =?us-ascii?Q?gBdN4wq1q0XwQOj4/EeM96yKotlZ2IxqtnHRGPcuDhQm5ogNXeOvRlWQjL0P?=
 =?us-ascii?Q?D+/Kdd1k0OCkY82IN5xwBFEiQ+zu/4oD+DLkT3etIr8y5EnXdi+LZM0Ksvr4?=
 =?us-ascii?Q?Y/3rWnhhnt0DR625PYPWW8JEcQBBQYAuNi55m7aQHwpTnGqC3ieo3W69bVT6?=
 =?us-ascii?Q?jQ7P2c6cKLvlZ+3z/HPcgoQdJ/q/6WwIxdfq0g0q+Wr510wO0AHJSP2TjVC9?=
 =?us-ascii?Q?7K50tYgc4Mk+7ZsM6q15wwX1weh8PfnO0upxqHKhkynAnMlKbThLkldCO2de?=
 =?us-ascii?Q?ebC70Gk+GPQYDF3K2jjvYRaPZTEeeHvnpSNXulZARZCC9PBmoB2yiee94EcR?=
 =?us-ascii?Q?1sofWkrIspu320HYlItQWfgRgDQ2sGeiwZe4WhsyI1uaNDNT2XtSCeXJyYA5?=
 =?us-ascii?Q?yJb6bPv5I7r3gfRIe+jPjTsHXRntqWc6WPzswxa+9w6FZE2o51G856BsHXuA?=
 =?us-ascii?Q?57ExYsPXUJHLZo8VnyKSzstAn3AN7+LIp1FAJ6YnOWhW0BklIbB23dJ3EXMU?=
 =?us-ascii?Q?7///YEg1/OaMiFO6U2TO32tKqvvYKfcykW+zeuw94nBuJ9tin8ZqxjMH0JXX?=
 =?us-ascii?Q?Z9sci9pC5flssNeeU8EVl7tXmEk+YzNXAbVgYMlj+4zxRDpf3+jscx9k0Nal?=
 =?us-ascii?Q?nOs6A8lRJwSFTqiJmp1hIX4oi3nV1jBepYdDnI9jhM6L9Gs12P5LzORAgZKy?=
 =?us-ascii?Q?h0rMEJEXiKn01lMnEKoNgLDNCUPdCq33fsYLcX9YEZoXZVyRrFSPXCuZaq7U?=
 =?us-ascii?Q?/AjpJdSL+LzteIa0AoEj2phMnX+p6ikskKYevlJHy5h3cTCo/a94r+dzBcwX?=
 =?us-ascii?Q?LWsH2S4sxC89YJZn5VLJDElrxFQZ4eMdFa1lBz4sx8IgcEYyFuDQcl01JCeT?=
 =?us-ascii?Q?HacwxcHi+aOVoUvmPWjUENTNt1kljCQbKV9qJ3xA3bUObap3+gaR3xMClpWl?=
 =?us-ascii?Q?secavgtz4w=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: FIpIQ716WtdOjjy0lJ7oTucmnLvC1bnqF+K618zW/7Ezoa063CY0hVPmiI91epecG37QwxnSsk+0nO71UL8jyEFZdbNx2pyANSu1kfTS5LdtOmEHl5YEQuDFUhau5d66vOiroaF4+tOvI8R4wS0aRledoLwJzgLC9CN9t3X9S8bSqlg9bly9UyStPPEvXujsBaXrDP9F3d/EeOMTpBs9TKFBJ4L/tYAno6D1arJ/K3ryZFVBN+yjNqucaMhisE+fbYk9KcnzZeb5w/5fjx46LaTKr5SSCsanui95NBQxwoza99pJviH1SEn9/5uO0HaQw8YJDKBd1VzRDEunm1jAFVQc9zOva7WhqKSGLEI3Mp/yCJbWI7eKkbFo4cVU6OprPaci/cPbgJnJ6YkSw/V+O+uIHA6LP6VHxue9VHMx1qwR2Md9wNrujUTfbaf52SGdEZ8CeX9ekFbPSrbUXYiRr3QdkCIzziPy2+Ea88DVJDesCLXVQheGCAU7/BCLbFUIC8CdV3B8VU8icIwqj4mbyxTx63T1XgIat51C6Xcqqxqje720SIKQsqlzlZ3jZBDnPPIZamO13AsLpkPnkkfCUldfdiYV16pwR+l+bUA1tD4=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: e7a16174-3a8d-4575-9acd-08de57e5cbcc
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 20 Jan 2026 05:36:01.2834
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: FMSdnCJBi6wvhbRDPdoVZuTUE9hKCYRaczE26AE+KKT7sgbCWGUTFGLqBnuzAuTN3GPYzWf2H+2GYDMlFpCVCA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LV3PR10MB7769
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-20_01,2026-01-19_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 phishscore=0
 adultscore=0 malwarescore=0 bulkscore=0 suspectscore=0 mlxscore=0
 spamscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2601150000 definitions=main-2601200044
X-Authority-Analysis: v=2.4 cv=OJUqHCaB c=1 sm=1 tr=0 ts=696f1444 b=1 cx=c_pps
 a=qoll8+KPOyaMroiJ2sR5sw==:117 a=qoll8+KPOyaMroiJ2sR5sw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=mmuLHaXanjJjNhj-MCMA:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:12110
X-Proofpoint-GUID: 6J4yZcSZub-Rux7FAgESBNxrWEBbPlkx
X-Proofpoint-ORIG-GUID: 6J4yZcSZub-Rux7FAgESBNxrWEBbPlkx
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIwMDA0NCBTYWx0ZWRfX7nBrOs6DOxW0
 dCv1DnaKHj7vrJCqZQjgk/LB7xkJ3Sjck4BBwVNzEzkuktmenxHXy/3/ldveLYh8eCq2bq8beNi
 Ej9M+Wka6W4b2DjBfY6NibNU6FCaxHwQLAUcHv4MhVzBO5uGTQSvia9E6zkUfYj4R+3vS4h9Bl2
 b+SU3Vad7+kBab6PVfZo+lsmhHUJnktzrw063x2z+nLvtulCVW6m1H5MVjrfGCZn794g4rXW59l
 +Yyufk6cJ8IUa9r2/CtI4u/h4bTK7fLE5gbj2pixHJVzqTa6vWZ7oSxIjqRkFJsr6sJs0KeVSHv
 uKC5g4b+xFILsWTTXzJl8OnHg4PWaaECLRqfKOeSEf08JfMxjV0x7Yn7+uO8w56xpuWB5ViFh/4
 V76h3a9vl5xdneLjHFNfLUn9jwqoc5EFI8FJNgwMNY9TGkB5Ca7ln544fDCVnDLoT1IWbhnGzq4
 cf9o0y4alQhKZ+sooHTYCufB22ywL4i5Wu/fjWhM=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=AzIyA6+e;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=N5+bAiHF;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Jan 16, 2026 at 03:40:32PM +0100, Vlastimil Babka wrote:
> We have removed cpu slab usage from allocation paths. Now remove
> do_slab_free() which was freeing objects to the cpu slab when
> the object belonged to it. Instead call __slab_free() directly,
> which was previously the fallback.
> 
> This simplifies kfree_nolock() - when freeing to percpu sheaf
> fails, we can call defer_free() directly.
> 
> Also remove functions that became unused.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

The alloc/free path is now a lot simpler!

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW8UNjNBXf651a_1%40hyeyoo.
