Return-Path: <kasan-dev+bncBC37BC7E2QERBQ427TDQMGQEW3J26DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E38FC0BEA3
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Oct 2025 07:12:21 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-78495d5ab26sf113662047b3.1
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Oct 2025 23:12:21 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1761545540; cv=pass;
        d=google.com; s=arc-20240605;
        b=jzO6b8ZLhiODqXEdUrlQaf58USLOvSDlcNmz3AGbUPuInMn5KU9XIsd1ncByjGlp5A
         qEn+p4J48JHAQkXXtVZ5Y7XJQL+rl5gwIN9WqsN0r8i+x7p/jS+EQoUml6IFQUFBq2hP
         OjKiPN1EQT3joPiA/ka/0Eue1CCgwBPTUoxHz6h8QM5hfDcQn/GtflOwatMl7LRSJvfa
         AnGU9olbTVzGWPm6K/e1X2pzNqDB+xa/yr3cRJL6jIxeOCXSn7AZuiXDgz6FjhKo4+Yi
         nbscyX/fGWGHWW+Fx8f1ymoE+ZKBnGEthRYhtZpNEht/ShR+FhbekzCFc9xAtpXAVQ0v
         GCHw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=SGwLT73P+T+e7//h/ecwWix3EefAlfZMh1mm08r/e2M=;
        fh=sInnurwK6wBffHAAvj7ZGpbq/LNa7TjoGhm56+Z17Dk=;
        b=eaPQU5TQbjFHlvkOGFxEB5nmbDWJGr//DNqEQj/jkuOkQb9wk0NPVeNjEvqpsnHSxb
         s6P5Xk8J4HXfAL0gT9+WDmv34VJ8bF6dtEz3W2/p5P7LB7hPJkGTiA2+czGXTXklaGqu
         AibsxVKvdWZOxpKPadTxLV2diDWnTyWYGGlV9YGbV4dYzHDEZv/RwBPeGK+rwceNYmAb
         XsLzd9KQIRoF4IK2xpiquOgjuYZa0otNHwTjRhSFNAag9isVS4oGW5L1oOejqczo2Y2n
         q3ZY2oR3sBky16BrH7BERlzqB+xTVIS974GXm9NfPlgAcC9HPiBTA3yEwZgZsA1hzmS5
         1KnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Rwmb/aJ3";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=LpTBg0y5;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761545540; x=1762150340; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=SGwLT73P+T+e7//h/ecwWix3EefAlfZMh1mm08r/e2M=;
        b=n3fO82QRFTxCGUCAQgilom65RgT1QL9RQ1fy6kNto24R3JJRUa73eSEJMvxJWgsOVc
         2Zp966avryW3w8E0WIZ3ZuI0v++3hqGmOenlD7TQ/DOM6avRm1a5SdZRzPoG2miquIWu
         JAerXSCxccpdVjlnVclxEU8Whu5wfZD8xSJttbUNYt3KtZlJO01O9jt6Sokjw0grMi0Z
         34nIY2GaYszxqxEA2LoUfnOOeM8r3hpWZO+E2WS3wZLuryfW2cvcCzJSFR93uQLghnfh
         vFK68A51fLCZlNGLJVnvfy62HCYrVkLmSY0N/etjiKA++idWKij+9JnW9uDfKZ+kAVrL
         F3lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761545540; x=1762150340;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SGwLT73P+T+e7//h/ecwWix3EefAlfZMh1mm08r/e2M=;
        b=mgKe1vU4uqRikZ1SmEVKWvKBLV2zLb1ZpgcLhZjdxd+6cU+zGNHCT7qmN6R91sEs7t
         yIP2lo2bWwVyyW/NW2G+zBZetJ027/8swDuzhNRnPgXhuZUiMAaz5wq5YOnLt4qWtwQl
         D1a+VMKcB4efG494doi+lLvDJfKGRUYurZ0ZNdSZ15b89xrqJ8jcNWbwdLSNsgYO8wtp
         f2tlOUtrHAd+muzznRfges27lNe7YeDLiOHXJwOBacOaaAjs+6dx7qeBDRnBZkLxJ9Cf
         0q2HS+UV9y9y1EBvs9ALbAB1E3rO5Bz/N5Hm9Dslq68bC9VPHAxTZ4jSBw1/AYLXDCsR
         4J7w==
X-Forwarded-Encrypted: i=3; AJvYcCW9ZhOteVeu+bl6iffVsvlMBOFdZStMexZU7um7msiOengoi4wszkpd9NRgF5o8wqY9vVHGUw==@lfdr.de
X-Gm-Message-State: AOJu0Ywk3OeWy8rTB/EDqLFsGr+zmw2tWVYG108Gnlg1I83ayrwFitzg
	tih3wpGTMRpl5x0ECtuWrHhkQe/MtqsKQupHJ7B0RnT5ogvh6QfuKdd0
X-Google-Smtp-Source: AGHT+IFV4z4P9Nj+kbXdENLLGdU8kWHafCELsZ+dGuadTN9tlS0g+VrIxnLG5HRt4zsUFjEiH2vUAQ==
X-Received: by 2002:a05:690e:190e:b0:63e:2059:cb7e with SMTP id 956f58d0204a3-63f42b7cb08mr9295366d50.18.1761545540089;
        Sun, 26 Oct 2025 23:12:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZFnpR6mzaNb+BrHv8bhQICrr/d81EiIhvjTVXXAJzvIA=="
Received: by 2002:a05:690e:1a20:b0:63e:1de4:7fb6 with SMTP id
 956f58d0204a3-63f28b15657ls2663220d50.1.-pod-prod-00-us-canary; Sun, 26 Oct
 2025 23:12:19 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVDwL8zy1U1dh7RQ2ePP6ElVli42S7ZM5hF7lkjD0RwvOrkWUlvoPCLPd1iHD/AghXbKKG6GdZIShs=@googlegroups.com
X-Received: by 2002:a05:690c:d82:b0:784:886e:7c4a with SMTP id 00721157ae682-785dd5cd652mr85856587b3.24.1761545539129;
        Sun, 26 Oct 2025 23:12:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761545539; cv=pass;
        d=google.com; s=arc-20240605;
        b=KPJAQBmxWeC9x8J1Brf6sQkjpOE+9l+1YLoqoY4jtZV7EmJsFxOhR8sS27cE+lH25g
         fFly4E5AVzfDW5L4+C4BCAUiPjY0arKnEOAt2e7Ny13e9WCkWMZ/jWs84ZcxWCTtkJcm
         KrJzBVat1zcQb17l36dS9phj0KT7nXUSzA4zCqTu1GcDnpkeXfLl18Skb/lPA4Ecokoi
         Ut9gyH9sVh6laNHXBPlWhuMkGT0UpDKsOHijemnwpnS7R0DU5rso1B9G/psdC9oSwE5e
         okCRYk24Bn5Kaz5R9R5wwvG98qB1zUVBqvzxKtvuxfX6KEap3EV3bA4pIq62Fv66QsvV
         mBtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=8XD/BfLVB+bksvs0RJckIAUGGENJtjEeo8NR9p82cZM=;
        fh=ndziwN/lmeFpSDyV5btdRc0hszqvDB1uukrSsGeZypc=;
        b=b/TeKcGjSGx1+lcN3LXLy3ODEUKCOGVHS0WOgexIQI6Jxgedmw/r03B5x0PjUESF/K
         wQSna/TUFmnuPau3j6/h/anSHouMEIRGkg3jlkf4N7/AZL5pTLDgCwahQVRKC1u57f04
         0uvrg7wLlVWYEuwnWmWaCshzYiW7CHDgpQifXufxqmlhOa9iDXnTsDVoTy/CVwESXBLP
         pXRoiLdyyBcRznJfywFEgnq5AIfzLlYH5WWtS79uNnIPRQvS+86xEdFLVJHfh2nPIFoB
         eSNawm8Uke+gi+7rtLwqc1+GKwq43Zl6/YYsr6Pmz76Wmk/OEL4605R677XREcnokxf2
         xcow==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Rwmb/aJ3";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=LpTBg0y5;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-785ee57b09dsi2432577b3.5.2025.10.26.23.12.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 26 Oct 2025 23:12:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 59R5x4G5019735;
	Mon, 27 Oct 2025 06:12:15 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4a0q3s2gkp-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 27 Oct 2025 06:12:15 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 59R5TWnl009090;
	Mon, 27 Oct 2025 06:12:14 GMT
Received: from ph7pr06cu001.outbound.protection.outlook.com (mail-westus3azon11010066.outbound.protection.outlook.com [52.101.201.66])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4a0n0dmat2-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 27 Oct 2025 06:12:14 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=anOELCfZKyPNM4pqi2Go/s9jJAIsYsN8m+jGfgGP8MIRnT/StuUN+bCm3aIkxqkZCTxTCxCLdz7WKELZ3+maRG8ytabEj3I/SzsKBl8sMo2wrXf1tBRRdMof33CNKrbBsca/+gF5km/EYGM1MoNRxSUGm/QAIatUxnHm16I2qzDkCpfHJjsevTGcIn3T9IurEb/x9LGgU26NCVqlcIEKdY2Ic1X89FPH2L4pEMSAAP0LrsOqhl6KvlfR/4v/Pr/SJi5AQROLzSiioRJCSoFcWOqf3I4NuBNvTuc9k2L2kcHRidL30eiLWi7+zXRvjj36rUkF8ZEjqG7J+qD2XvFuPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=8XD/BfLVB+bksvs0RJckIAUGGENJtjEeo8NR9p82cZM=;
 b=usBc0InZVIU6iFsrfhn3v/IO19Ei8CVbqUehNpNOASDcB6sDfCd+Od3A3q9TbKKEsqS8HmesZ5I+itbSG8kg91yeIKuA7jizlJrtkAffscN8cxRa27afGTThmD4WatFU1tjL9Pk9h6G0K9eEpRYU34SGo45SW8YDEfQlsoi3f6qFj0/PGNR1Mk79fjfRRtkR6YEClvVz1f+gm/cA5Mjk3Wf7TjiWX40OTpyH66CjRV3asU1AIqXpoGTs25j3wUxwTqCeweP2lhsBT+3UdXXBpNNGdi6CXXWTEiIvc/2zU4R5lhVQcPe1OD/Sbbf4yNE+r+34NbOms2GEcsAK2ubH7w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CY8PR10MB7218.namprd10.prod.outlook.com (2603:10b6:930:76::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9253.18; Mon, 27 Oct
 2025 06:12:11 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9253.017; Mon, 27 Oct 2025
 06:12:11 +0000
Date: Mon, 27 Oct 2025 15:12:01 +0900
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
Subject: Re: [PATCH RFC 08/19] slab: handle kmalloc sheaves bootstrap
Message-ID: <aP8NMX48FLn8FPZD@hyeyoo>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-8-6ffa2c9941c0@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251023-sheaves-for-all-v1-8-6ffa2c9941c0@suse.cz>
X-ClientProxiedBy: SE2P216CA0104.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c4::8) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CY8PR10MB7218:EE_
X-MS-Office365-Filtering-Correlation-Id: c8eccede-307d-48d5-0161-08de151fc3b8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?S8fyOdAipSPp8Vjl8wOmdfQP1Ay86lRuVe/navipv/e0aZF8xl6AsIlE60Jr?=
 =?us-ascii?Q?J9ysS2BFGj9Mdbh1Voae7EYCIoKyS7+nBMpam7krPsdOtLjUXYu4G4ueKoYM?=
 =?us-ascii?Q?WADhqeUsjR2+XYxSh9D6VvpjmDtxc7SgLHoLLwcDijJerxQilPMNqGZ2tTQY?=
 =?us-ascii?Q?Mmi00hKsyeA/qgJN8H/ZqCZj2WnAwCwJg1m7rutPikK2bMFZKajm7LOFsJTB?=
 =?us-ascii?Q?fjhc4Ra0DsLWqXXZdIQyJ6sz60KKVNfW7iQVMBnrjdUVXFN5tMsSW6xDLJtR?=
 =?us-ascii?Q?CumWkNLZeJgGjaQqRUzc8QhlP7audnPclZMBv5pfByMWqD9JhEcpo6uAZy5r?=
 =?us-ascii?Q?RXFktxdoFbGXoMlwGgUhhRep/gX2sthlM21T3vYa0SG5H2DmBCLHyOJB3hlw?=
 =?us-ascii?Q?BaAHOVkJXghvNpW463PVDJz8JXY5oTGvm/UH++sfme2Qlp9t6AkarZpQkDDE?=
 =?us-ascii?Q?ypRPQKD98HnvU/gmPv2ZQEenvYR8aiq+TjxxT7LVRHYp6PTXs/xho4MWDMmL?=
 =?us-ascii?Q?jfVJUB6TqA/+5YZYA+GviYULBA91m6cZNdJNOlTy4g9oo8qZFUZdF9yxjz32?=
 =?us-ascii?Q?2NO52GqN7h+Soe+vm3ceJzPXsFy3vCBv1E1mkERc9GG+htL9ykqAHfybgaBQ?=
 =?us-ascii?Q?1RnT7fek6l2cmsQDNh9eeOW5jXeRIpUUq+dgd1yKJ6RlhUqfTUmVJWDrCt84?=
 =?us-ascii?Q?t/8+h2qVQoLZ41ac/U7+1WoMyz4u65Dq9sOk9RMHy0+XAzAeJIjacjOCcYGg?=
 =?us-ascii?Q?D095cw0AE56KEd0CBUUe1PeohoboZLQ1WQSOYoqMAlmtELNHFBIsvAWqfz29?=
 =?us-ascii?Q?bDC1apyMYy1XFWNHrbXbg/nb9uv3LQ4QexApW34a18MbmhQRogIlnKNsWfeN?=
 =?us-ascii?Q?hLStcnuHaBF0LoWPnWm3N8OVRndML90mW4E0XVlJMJASHDuAAwcXfrLhmrwY?=
 =?us-ascii?Q?MWq0RzhQRsSs2ixqm9nNXbcfnUDKDjSGPua/qYIbxhlK2kPwkfKVU6tpoD/H?=
 =?us-ascii?Q?doZXaDBnKwQnxJ3FhaxQbamRx/V/dEOoWcz23T5rylnKCtuw+Am3XKW9jRod?=
 =?us-ascii?Q?IEDbiCeXLNS4svFdzzyGn0sjHbsjLY9K6BL47IiCp7pWE6ol4Lx+UyNj9M1a?=
 =?us-ascii?Q?NHrhtlvF3GqDWpyyERDpt7RqHSfssUc1I+lfpK25zWhsiW26excbtXMZN44P?=
 =?us-ascii?Q?qpwgpAh86ygNZspPeoPHAWQQ0gF89zZ067sKdkP0w4di0dIg5U+W9b5dZ0Ud?=
 =?us-ascii?Q?J+h7E7/QeZjCKKByNT2h+6nvMZsH7dTvUWAncgETFnQT1SFgM8w2zFJlQOSD?=
 =?us-ascii?Q?A4+HW4HtI5p/aJDKnPQEOReqitd0glN1Xac4/zLgbpGGL+20HblqFfTbFlJt?=
 =?us-ascii?Q?pW6g5MNBydX9hxQncxqsA3R+GPFqv4NkTHl+SC7WjhjYnpV1hYfh3vNQ7Ays?=
 =?us-ascii?Q?4Oi8hlelrH7INhqo09o4kPuMiBlPQb7C?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?d4SR9787mUqLIotxWZyKJbaparfMpEdlXU7D8t6oCWkd5bIcJ6zOdVGJMsEQ?=
 =?us-ascii?Q?uKAUSXigD4BuWDRsCR2xX3gBDxvLhT2HEjdP6PCNVbVbAW8oJzuTkzKOMYUe?=
 =?us-ascii?Q?iOdrKxiwdIzlQKU3Ib+Z4eMDl81E+8GywwD3XJkL270nbCuJvoZGtnuTGfvi?=
 =?us-ascii?Q?X/alpNTKhNkN5fArHqjXNwzfXxZpR5VG/UbWokLXUMHg+qlFZvZh/aq7T8/U?=
 =?us-ascii?Q?mqpLzidVS7WwXVbQpHJSn07HVERxgUPRJdkFCB4RpD8W3cDN1jcGGKdPAG25?=
 =?us-ascii?Q?UhsXGZTku3X14KXRCF+jb83RYCIo0Ijjil7+NQPdSo4YVB8GhNaIg2DVVi60?=
 =?us-ascii?Q?5dqCikEDOmMr9BI45CHySCvD3GWtusYCFxIvx3ZjlbM9h/AfENGrG+FGWP2f?=
 =?us-ascii?Q?UQxQD2vSFp/VgR6GXqH+lORuQDLEocFk6UOJKnzMLDnBYsvGLngj6w2zTGzQ?=
 =?us-ascii?Q?UcArqaS3HFemBkl5F6ErPIUsI3xzCD993bVwfuzkmrzIM7ubCCM939AL81/y?=
 =?us-ascii?Q?C75OxTI/4FT19aP6AEGf3dmJFup0ct0S1VlbkRPLZoamm8nW+5fgi8uzJciA?=
 =?us-ascii?Q?Do9JOonlfvL2/tOpcEJsaYyUijR8AbWV+uxkAYRwulsyawzOeRSHnCcpsok+?=
 =?us-ascii?Q?HrYh9xfU7mPaBn3gZhUt6UT8Kd9lt53yU2T/vi8VhzB8wiXFvlcY1NcLwCXl?=
 =?us-ascii?Q?rb67EuocricEqc7j0Y2Kn1kJ6nt8yUbfRnVwtoK5N0Z16WxH/QcdzgrW6oQy?=
 =?us-ascii?Q?nhATtinxfT5gfQrgTuJzjGbNRAPuY/0CYwxW+sQeGufP9+cPp6QQA/e4ChX6?=
 =?us-ascii?Q?+p0nGExzb+JHxjf564LC29i3r7pN7hdCQXy0yWvlEQe33M0z+V3Q8L+g13kn?=
 =?us-ascii?Q?u3+OtmPD7dt5XQwibyVa0wWX96NSS2fnFaVMimTkN4CqfJSfGJkh0phcP/9V?=
 =?us-ascii?Q?RIy+EndUbntyGFeHVgM67hPjjQtmE7vYKn12k5iAj4MG3MoY97lubuQ04ETq?=
 =?us-ascii?Q?jhYNfFyqX1mIbVq+VZ04OJe0V6d1EOHcmKlPpqiszFsF2Nb3fN5Q92N5F6mM?=
 =?us-ascii?Q?PlQ4B0VGlBbC1pyHcRQJ5zH3UrGHv5zh52EO7op4/mHnVycWNWqdeSccxILQ?=
 =?us-ascii?Q?ITb00ZwWCbJWkH+0kZTNpA3fglYT6zbV8LA5+eKfvFealAzdyADIx21+mfr2?=
 =?us-ascii?Q?2FFSWXs7sDq+jQrfj34TlmAccsIL4Fa1g4SqcZH+APmUnpJmxvl1IQAJxE0a?=
 =?us-ascii?Q?PXrFW3Tm//7rSA/uh8hY6rFjW/nEcSObstIR+JYb5MdOcv9+TaCwWuK2599D?=
 =?us-ascii?Q?pNKSzI+nVwymxZfhsS4/K92thfgnRhj/6uu4yfjNpBi3AT92vDdGuzEhSgyS?=
 =?us-ascii?Q?GIOueLHae2MUV4YmlFJoLT46pGXoCZxPxassEOogCSxJDaJa2N6FEZxImlpG?=
 =?us-ascii?Q?1kheAmNueeFVJ/mCSWuv3AdzZQazm+yqAoqzi9vlSxkHMKgom5ex4GV6thI0?=
 =?us-ascii?Q?rWD2g4GEaMUj13YF5TrhWboHlTdNKXW+VeSKgimZ+ORPumJ+kSjqKIHvDx3l?=
 =?us-ascii?Q?mvX1ftKuMtYFXE/f5T/sNfnz+iKE1FqSxX2Emi+K?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: lg0ABBLgpTCUDg8r386l4jBgKqfdCdcIkIT9BbI+YfQVHESruaaMGt38RbHVOBLA1vIIkT1TyMI8mRofywFkq95xWmG33zPeNqdGEWkissWqOC1aSbyWkikQCgdfAa7nZMV7wqoO6zBJIUdHIGENFt5n6Eq83Csxrc7LH4krzZ9vg8Ka/PcVv+SzyfD85Hwr6hqIMaNbISLpJDIqOJu2JnO9JdC3ZegfZFgY/6lfqa/xUgRFhPcWFLi+GeEsB7EgXvezt4zmuvzVZltpfkw7BkwJTw0Qf+xiTcscdcMT7UdNUxCxFHvthPqKdbyAmGmesWCm7HYlGHiGKp7aV9QDX4HoJ8FmOnn8gUne+on+Aghyp9Hspa+te7WxJYNR8GVFclFbJViRpgCOiBDUQ83GPeKRVuLDNVYY+0PLnZUJmRmGMiu/d1oH3h4odGRZmE4Dnk+wSDRipK/OpFq8GjBltXxrrrg7WvubElFj4Xm6eH11A9vg9Z9DlkM5109gNziojoGnVrnGBEhFooyM7wpUtqOe0oRyFSybbCuZ9qyEqNWIunmwKkRGObr1gDCSFSvwACRYaTO85P2EfPitVE2ssiBR7chVy4k/lBMaCEG7EWs=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: c8eccede-307d-48d5-0161-08de151fc3b8
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Oct 2025 06:12:10.9515
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: rAjiCmzlRjSgUSSgSbm/rSN0gB+y5p/Bje17IYDoaRL9vu6+jGPewPthyIXC+VlACuzVqAxz3KEhszl+bpL0GQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB7218
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-10-27_03,2025-10-22_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 mlxlogscore=999
 adultscore=0 phishscore=0 suspectscore=0 bulkscore=0 malwarescore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510020000 definitions=main-2510270055
X-Proofpoint-ORIG-GUID: s_LTlO5HJxIcOB2j1z5imqvwrRr1hEyl
X-Proofpoint-GUID: s_LTlO5HJxIcOB2j1z5imqvwrRr1hEyl
X-Authority-Analysis: v=2.4 cv=Q57fIo2a c=1 sm=1 tr=0 ts=68ff0d3f b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=x6icFKpwvdMA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=-85A0CBtFnTczM3EjpIA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12091
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMDI1MDAzMSBTYWx0ZWRfX37n7yvrn0UtU
 sE0c1tJeC75pkuVzzr2lL1Hh1ItGfGo2EkRcBEVLwm2BktT4h30PNk1Rx1LXqF+qPGCCOCVU/Gs
 dZlrYBb8/VhsoZJswwXlhzVy0HSHWZ/fUZzs3kJSgeYh8Eyu3MP9K/tPslzEd5kbg1gb3Vo6Ze9
 H9Oi9YyXmLhn5QmvKHA95lDR+vjLc3z0nUvQxIYtY0tlMFCL1CcxchK8l/TexZBq6O1Haa5foMB
 5Z8ObDTisLo9s06t9jLjZ+zAC11LOvjC4jVQGe+Ln0gNTKJgszcjoe/X8u5hpBjVVnVkrYWLBPe
 ATqxR6eNhFR75iewZkWbnfAJLTi8ZHt3cCka9Z3Zoo41B/Te6QYc2pu0WrLxX2ucRY5Ezss+Eop
 VChdRL2F+f2NwxBU+Ancmy/ag5iwvk5S/mF6mLHvyGZqaoIi750=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="Rwmb/aJ3";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=LpTBg0y5;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Thu, Oct 23, 2025 at 03:52:30PM +0200, Vlastimil Babka wrote:
> Enable sheaves for kmalloc caches. For other types than KMALLOC_NORMAL,
> we can simply allow them in calculate_sizes() as they are created later
> than KMALLOC_NORMAL caches and can allocate sheaves and barns from
> those.
> 
> For KMALLOC_NORMAL caches we perform additional step after first
> creating them without sheaves. Then bootstrap_cache_sheaves() simply
> allocates and initializes barns and sheaves and finally sets
> s->sheaf_capacity to make them actually used.
> 
> Afterwards the only caches left without sheaves (unless SLUB_TINY or
> debugging is enabled) are kmem_cache and kmem_cache_node. These are only
> used when creating or destroying other kmem_caches. Thus they are not
> performance critical and we can simply leave it that way.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 88 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++---
>  1 file changed, 84 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 5d0b2cf66520..a84027fbca78 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
>
>  static void free_empty_sheaf(struct kmem_cache *s, struct slab_sheaf *sheaf)
>  {
>  	kfree(sheaf);
> @@ -8064,8 +8071,11 @@ static int calculate_sizes(struct kmem_cache_args *args, struct kmem_cache *s)
>  	if (s->flags & SLAB_RECLAIM_ACCOUNT)
>  		s->allocflags |= __GFP_RECLAIMABLE;
>  
> -	/* kmalloc caches need extra care to support sheaves */
> -	if (!is_kmalloc_cache(s))
> +	/*
> +	 * For KMALLOC_NORMAL caches we enable sheaves later by
> +	 * bootstrap_kmalloc_sheaves() to avoid recursion
> +	 */
> +	if (!is_kmalloc_normal(s))
>  		s->sheaf_capacity = calculate_sheaf_capacity(s, args);

I was going to say we should differentiate KMALLOC_NORMAL caches that
are created for kmalloc buckets.... but no, they don't have the SLAB_KMALLOC
flag.

>  	/*
> @@ -8549,6 +8559,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
>  	return s;
>  }
>  
> +/*
> + * Finish the sheaves initialization done normally by init_percpu_sheaves() and
> + * init_kmem_cache_nodes(). For normal kmalloc caches we have to bootstrap it
> + * since sheaves and barns are allocated by kmalloc.
> + */
> +static void __init bootstrap_cache_sheaves(struct kmem_cache *s)
> +{
> +	struct kmem_cache_args empty_args = {};
> +	unsigned int capacity;
> +	bool failed = false;
> +	int node, cpu;
> +
> +	capacity = calculate_sheaf_capacity(s, &empty_args);
> +
> +	/* capacity can be 0 due to debugging or SLUB_TINY */
> +	if (!capacity)
> +		return;

I think pcs->main should still be !NULL in this case?

-- 
Cheers,
Harry / Hyeonggon

> +
> +	for_each_node_mask(node, slab_nodes) {
> +		struct node_barn *barn;
> +
> +		barn = kmalloc_node(sizeof(*barn), GFP_KERNEL, node);
> +
> +		if (!barn) {
> +			failed = true;
> +			goto out;
> +		}
> +
> +		barn_init(barn);
> +		get_node(s, node)->barn = barn;
> +	}
> +
> +	for_each_possible_cpu(cpu) {
> +		struct slub_percpu_sheaves *pcs;
> +
> +		pcs = per_cpu_ptr(s->cpu_sheaves, cpu);
> +
> +		pcs->main = __alloc_empty_sheaf(s, GFP_KERNEL, capacity);
> +
> +		if (!pcs->main) {
> +			failed = true;
> +			break;
> +		}
> +	}
> +
> +out:
> +	/*
> +	 * It's still early in boot so treat this like same as a failure to
> +	 * create the kmalloc cache in the first place
> +	 */
> +	if (failed)
> +		panic("Out of memory when creating kmem_cache %s\n", s->name);
> +
> +	s->sheaf_capacity = capacity;
> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aP8NMX48FLn8FPZD%40hyeyoo.
