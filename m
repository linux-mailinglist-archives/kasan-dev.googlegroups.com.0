Return-Path: <kasan-dev+bncBC37BC7E2QERBDMNY7FQMGQEKDXK5TY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GBNPH4/GcWknMAAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBDMNY7FQMGQEKDXK5TY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 07:41:19 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id EC2B562501
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 07:41:18 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-7cfcdc4a093sf266173a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 22:41:18 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769064077; cv=pass;
        d=google.com; s=arc-20240605;
        b=einkpg1FKMVglncUp7YvLCBVS/xLoigTgR+63umUUdxY5WwsSw+lNWMS3lGncAHoyi
         +fESGI0sPcuKOTUR1JVJH98AWqaIS1R/ehN+EsCEI3HzWn5HxtitxpLusjvjjtyGmJiN
         FrlTG5/US1OJXWanh8xJgh+itcrKp+H0TLThIyhYb9VR9YoVF+DthrQMiv1SjEjvWnqm
         zf7X2qHNoUJl+Y3omXIUPe88OSV2qQ1GEFOU+Vxt6llFzzg1MeoMI9UmRr7N/K1zCzev
         74WvVh6gC/9N+66e0f5+WFBFMxXLgOhRkg1f4VrSu7Sl4+RbU1MWSyLw0HEbOQTKlngu
         s7xQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=nP/zF9ngyEuTlACuUs2iEqzkyLEHVGSjTGld2UXCGWw=;
        fh=/sNx7TC7zVYfBCkLJs7zOQdIxmMowvZPvlrVA2va+sM=;
        b=f2wl28XN1AjR/GIWnQcOpl2OdE8i+cilPHhg/ozGaVQu+WswnCmJgxwTmAujqU5ji3
         5aMEsw/rDed9R1vMuIYnmm+k19mvO9L3fs6l7Yen4gLm2beNzmHWdIa8nYsoK5qq3Oou
         o76128c5CQ6Ylq0qJWIFL8yJra5TxUsvNJTp1Zzq9mv0mD9sl2jSyoo9iMoy6SWPjnKT
         VZIPOLNsnmRS8Jbn5iT9YlNUFNOt/1HdOv64oNPdP9D42J+8g98etcx2WitBHCCWFsHS
         7qufVjN6Wu/Hkcr+ILTpKyRtnVE0q41hd/vDwd8JrniEtppC/sfF7g9wxKkoCbpZ4uZS
         yloQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="DA/glrpy";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=k6Zg4h8K;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769064077; x=1769668877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=nP/zF9ngyEuTlACuUs2iEqzkyLEHVGSjTGld2UXCGWw=;
        b=qZnlM5sfxNEuURH75tDYhdYY6deXDGQgmlhVsgKjnLvQWCCpH1foPhKflLsiMB+dUO
         vDAv5zprxlYTl4ccYEGdRHXfXnCL/l3FXZG/Dg1l9tyEVaEhWET4Fko6P6alA9Us9Jlc
         tOfbXvvCf31u5Kc/QAW1pPSl6KrLkn7lMnfXJA4E+tPsRZ2nk8Tj2AV/7NrL/Qz81uiT
         jVL++kV5cTGmQwIXML/+/G3xO/V0YbGz0PknnVoTPVupsLnd9iZJkiok03CWbEVZNbCx
         Ygv044ApF/IYsxEu9RIKAlHJsEj/S8y35fNRnOSTGUE3ml+Xk4vERrNcI+70bdkrCCh7
         7nww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769064077; x=1769668877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nP/zF9ngyEuTlACuUs2iEqzkyLEHVGSjTGld2UXCGWw=;
        b=Pe4miUNtELkp+KA2aAMmBCaUThClOYOWkSWVzJ+kQlPgKciFhdDYoxiQ9bYKcXxMxX
         2mwVT7wPFlHe/EVkQ+/yuusrkscZMcgZ2cRPDA9TbNAC3MWp+VCsgYYB+FnDvjH3KM5w
         y5Ov/rxylGAkEFJF/qREAg33EmMfAgbi7uBrA5uK7PWAXXEdpvTPaYWEpKVqN7fGJxqX
         ITSe6nca1fEFLBgFf53qu+67kuhKlE2u7gWmDHag0PE4NDZdM5TT7JGLwIgeRXCtSLnY
         MV4j5Udv8wuCG+BzI6s42E3BdQxikHBCaK+LEa7Lvjy0zIm8FXhcSp947PQBmI29yXTO
         uy4Q==
X-Forwarded-Encrypted: i=3; AJvYcCU+8x1bgf8v6YmzRqkXTi8nlIGliArBomyeIXOD7OLeFWBPTDurWzYE2/yprg3qkBQ56myyeg==@lfdr.de
X-Gm-Message-State: AOJu0YxNWpR1wacOIkfbA+xhpl+OFuFzDCskCoCqsQu16AkwZD28h7MC
	oQ4L9QSjCI+uV10KGzEjMXEVkIEPJZJ1qwzcrgFhKv6zSfYrqtXGqXgz
X-Received: by 2002:a05:6830:3113:b0:7cb:13e6:f674 with SMTP id 46e09a7af769-7cfdee8bc9cmr9001718a34.7.1769064077394;
        Wed, 21 Jan 2026 22:41:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GOZ+WFDL4Gmua6CtCVf7TWfke4E33fPzfGF7RYz5HMWQ=="
Received: by 2002:a05:6870:176f:b0:3e8:2785:9a19 with SMTP id
 586e51a60fabf-408825b1060ls304793fac.1.-pod-prod-08-us; Wed, 21 Jan 2026
 22:41:16 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWUh2rDDhPnMx9eVjN/FsT010s3pzuB4y/8bL7vBmlxvoxz3+59F3i2lMKczPM7/5UVc3XGk/omfkM=@googlegroups.com
X-Received: by 2002:a05:6808:ec9:b0:45c:832a:cf43 with SMTP id 5614622812f47-45e8a8f508bmr3590243b6e.14.1769064076342;
        Wed, 21 Jan 2026 22:41:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769064076; cv=pass;
        d=google.com; s=arc-20240605;
        b=avCi3LEfIcrpElTUerZixXuEYZdsHF5lfdNLYfEYPPxAnG1mPQUccGCRZXN0OOQ0YG
         EplfLOUQGZo6psIPMCgSuQOE5rkgjBK5LZ/27gu/Y1tTId3Im1UFsIb+J7HtPSE9lBut
         X1dzz7zx2J+TR2aBJOXWa+1AaNLNJl23DiGXp3j2aRk3ZRqYpT15d7SOSn00N7FKCPwO
         s43wfOr8FYuuvI+YyBeCnCQz5CX2NFXooYTasqmp+YEHyEHLVZMB1hKpzrvAB+6jqsSe
         Mxq6dMDY3yvks6J44aUjJChMXJQbHugFWj1h/TuzHdCwSoKRlHFelV+UwoNrCkrnBNnA
         kImQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=G6YhzHmG4XIOaQKFZgk0Dwtr6Ce9szCA6LpNvKQZsR4=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=BgA0I57iD8zytpmyXJ3tYmZt3kHN6ysM4t9dYd0/tqkcA4Qt6OnQyvgGdBHxCWoyn5
         xTLOk3p9QkkD+JDjJui/yMnWp5doztzm1CaLg+aWIF9u3+H9rGv8iVnZ+7AChiWISPqy
         n//pI3t4ER48CuzshBPRgnruaCn2fKHtSVwNhRZDWEv2iETJBAmhaLV5a4n2pCNOASxS
         1ULsrP7voChJcwtaEemOKUNEZuEwGazTVD7xJ2Mlat5YPcV+J+ENvu2GKw50gxU2/qOR
         hexbvNqEURdX0HTaLiKipsQ5wO28NuAS6gmRwVtysULHxLjAUfX436ez61CSVxGMy7kD
         K/qw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="DA/glrpy";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=k6Zg4h8K;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45c9e024593si634760b6e.6.2026.01.21.22.41.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 22:41:16 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0333521.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60M1IqOt3264903;
	Thu, 22 Jan 2026 06:41:12 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br1b8f8mr-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 06:41:11 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60M5HYKi018032;
	Thu, 22 Jan 2026 06:41:11 GMT
Received: from ch4pr04cu002.outbound.protection.outlook.com (mail-northcentralusazon11013039.outbound.protection.outlook.com [40.107.201.39])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vcdug1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 22 Jan 2026 06:41:11 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=KQJgjVdORGYIrRFSz8Y49+IL2cZX4eWxuFY4+Ls+Rk2GpMQyn7Al9MbEZxjfTnGgnp/wzX5zbIbDREI1NpV3XO8b5gXm24xpUjlZhW6c3xCd3EIxdJxRnjrxmLOkyq3fBcioV5vp1hnknSB7vZfOY2JVs2cpKpL3kEdHpJjrb6dor5OC/8EpW+V2FZ+UxUzGeTSaUJ/Kbbvhp+S0PImysEy8aZeIs4C2k4gC1Ucg/+TYjcTprWKd5qpp7UKqLcfQ3uMYshSmjeTJKXKbCFak3cwosf9imlhqj1IZzzVpTMxyf31ajf+MYxq+qU91p/CZ+S4alSz8i93r5/nMgUdoTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=G6YhzHmG4XIOaQKFZgk0Dwtr6Ce9szCA6LpNvKQZsR4=;
 b=qk/1pdtBbEV1xQt8tpnmmIlcGzNdjezxKn9GjrmnDMldiVjJYYIazouxb1Bq1eP2e3Qz91FllhCCedd9euhvMFyj4/To73TM+by/6mjArDgnaeP1b2EDBu22ICm9d+BtCAkfrsf0TDoMUw5rrOna6o1Jrq7UFQGs4kbpyISbcqEh+GTnpOFAx1zQIWOOdY2bUZ9ZP8GX0VCyyQNEBVsu/uS40Ydv/sK8OsUY/HnFQBj1OZXbrWvV/QPXXsD3Cl2izwPahmLbQudZQauoXKcbx4Jm5Z/m1MtRFmX2Y6Ez3oGXdIHja37tkpdZyseIEYM5BVgsaNJpLFI4kb0Espt3rw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DM3PPF5F5663669.namprd10.prod.outlook.com (2603:10b6:f:fc00::c2b) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.9; Thu, 22 Jan
 2026 06:41:08 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9542.009; Thu, 22 Jan 2026
 06:41:08 +0000
Date: Thu, 22 Jan 2026 15:41:00 +0900
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
Subject: Re: [PATCH v3 18/21] slab: update overview comments
Message-ID: <aXHGfLV6FdlNPc14@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-18-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-18-5595cb000772@suse.cz>
X-ClientProxiedBy: SEWP216CA0080.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2bc::16) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DM3PPF5F5663669:EE_
X-MS-Office365-Filtering-Correlation-Id: 5cb20472-b010-4f70-db9f-08de5981390f
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?AX31u6ZG5tCpSD//PW3RBG6gwavAAzPYmLDiqg/aoXB4hAc7CgMMz54N2Ttd?=
 =?us-ascii?Q?nUHF/1tlabc36YlqVDPoYlZbaGqHGPrWMUL20m0jJX3gT7cI3tU2CQJugffx?=
 =?us-ascii?Q?1noVzjZDpSEYL5dZ/WqX+AHBOhms7FVHeL9q8ETZhMtOErmcEuw5NuiqKCZ+?=
 =?us-ascii?Q?YkPdkSrReRBoEsMrOqED0IJlWuIh8xO6Itg0jUZ3eXEdD7LbdIFmSQkXwzmJ?=
 =?us-ascii?Q?9MlEpatOv+P0YqjG5dAQg+wFeOaE/K2P7W6KdF1PjENjbKX3xkQwS4urC0U6?=
 =?us-ascii?Q?n7GHi0bEMOxNdr1wvpL9sKHoLmX1D/Z7UtV/Gpmefdzb1hzvs8OzlBlGofut?=
 =?us-ascii?Q?EYLx0YeIgKIzMnWzInC8nUT96S58/Z1RFPvscOnem/bZoknExQa9Ub+bH9lw?=
 =?us-ascii?Q?suiKPO7X+BiajK4pPiAKRnoVxr46s9hTpoKPlbtMDLG7GXiYuJweYzh4SkF6?=
 =?us-ascii?Q?yUoNEafQDAvGi1AlCvmh23x6I8uLpj6mrOSkCzEVrMNd7d2JhsUVCiotYJlr?=
 =?us-ascii?Q?1Jz6YDAjSD5JdqDbtHfTHHGCOZypWg1dRp0/3YyqID87t8z+ELeHtDVkzSzO?=
 =?us-ascii?Q?EvkukBmM/fGitR6g1cAX7yODPd4ARMq/LZdqxjWoE3AqG4YbbjXJb/oEsfIa?=
 =?us-ascii?Q?T9cN0iU5jkGIWEGbITLlm5oJ0ykzMUfUTzyMd5X/QcaLhLuoG1w1n2IRCiU2?=
 =?us-ascii?Q?vLdHnjE7MzRpx+DUMKxKsW6g+LXkwcJc8CeXHS3TTxAlgHHG1FCTgHCY0IQl?=
 =?us-ascii?Q?dI0zku0q5A1rEevV9M5P14Zi8xqjNp9e4e1hL8JQG7nZwNoN3kqn0meEVFZv?=
 =?us-ascii?Q?26QLYPR793tDk2e4HFdNnw/xZNzmqpYx23t3G/hfANpVk6oZynigmx1AMoAN?=
 =?us-ascii?Q?pDUcKCTBAn7GTprfFcTSmCWHfmdsHndwqWuiAUq+5Vs0R8lnPPLcEHSk09Ot?=
 =?us-ascii?Q?11C5EfaH+tq0aN77SbtQukvKIkGIb0gcBnEya6bnfar787efIM0jpZlsq4RZ?=
 =?us-ascii?Q?KYyJENqIi0QepDQb9Z4U15zeJP5TImz0Z4TIUYXNoT9inxULng17L2+66Sxu?=
 =?us-ascii?Q?HVL6vxWugGCempbtRaRH4q6YJ/MUhI/ERFUOvB9zhNJMiBLT5+/KV6SHH9yG?=
 =?us-ascii?Q?URzjJrx7ywM5Mwvp8vSx86wtApCN8UNOR6g8kvQ8QCevR+CP4AURMja0CddK?=
 =?us-ascii?Q?v4P+ZSygg0oTEzdkCLDO8y2rtsl3HlDxQ8dBWDmXv/SS+Acif9Kem7JZM9P0?=
 =?us-ascii?Q?kL+NkjH6S9O/Sb7DfFpVyMZfzf9ve3z6vMx3WlslgShp93483dF2jfi2Cw0F?=
 =?us-ascii?Q?A8kvcIwicxHvxjftojuGSVqgFE0spXpH1e3zUWHAoIdtxtNoxu0ODPODtU1W?=
 =?us-ascii?Q?5cF95xWCRLTUXpgwnMlxcI1cC4Z2r2DqUFIjXNewwMho/bSfnJZt3THpztUN?=
 =?us-ascii?Q?oZVlWXbY5j4aLFNBJQGnzoL+emo8f53bv4RpOG+82Ga/Bq6HOn5H2a96IKdm?=
 =?us-ascii?Q?yVqfHWUv3+bjYIke0Pa32uYkV80Zbvzv64XWdmkK17OtGx/2mJv3gq/VZI5y?=
 =?us-ascii?Q?EbbvtinuQZYQ/eyiR0k=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?3ZY3yuaT4KFHjZ6SQ69oxW53gz5np0HMDbpPXyztbhYgiDGQUETmqsTQkf+j?=
 =?us-ascii?Q?sWXS3DJ9uxV8O5ZoAiyeWlZ8SeeEif8Ic2Skopbxyee6+oQHYccjklW4sd4A?=
 =?us-ascii?Q?rdU1Dl1PrRNjKqFg77bmkihTt/Zf1qAbnlj+Rn8HD6mzNstR4rso2vl9Garj?=
 =?us-ascii?Q?qqoSQPTvG4F7k+cTVTp+K9XIiL4bzeA4U/aPAS5Mb/7V2aPiapqNFF+6zH6t?=
 =?us-ascii?Q?hmHr+FnMmb7s14dRmFa92t0m1f8nJik3rEmuPg+mFYVqYVvm4HPvHiKuADWf?=
 =?us-ascii?Q?/AKHk+ktc4H6F9n3YlF486nvOMAxQjbQQZKrAFbjHigRGqJcGm2iixfDPN+0?=
 =?us-ascii?Q?bM2QgxKD1433OWlG4FoxpNcq/0nxlyOWzKZp1M8XCwf1oQ69dZk7sKUlVK9c?=
 =?us-ascii?Q?1WYNlMEY8CKXR+sJMZBdJqLlFzk85fgC62Hb33J0brsWoa6WxvQpc8aqxeFf?=
 =?us-ascii?Q?TzYBxJPpsGVZlJDbkjEybRGiTmSU1GE1HTJZ0zSOaibKpNDwFj+Y+s4WTFkr?=
 =?us-ascii?Q?T2jZu+9Apt3C8h1hDKZH2iXDS3FJwQjs/RE44AwTHLQWyCWZsF9cvP9kFma5?=
 =?us-ascii?Q?kfsL+0/h/3i+Gy2oOt4OargsWKcUngU/j5S+cqsheynw5zdmoe1SwwVHJ6g/?=
 =?us-ascii?Q?/Mc3Mm64OmOlW0ewvIZEBtw2hVTgPdPJBzSPYXvkQlq7F1/QFLryTBAhW4rV?=
 =?us-ascii?Q?02TfFtlGiJ84UH+cOpOL/V/+tnV13sckn1T/yxLa534KyUto+mv6IQ4Iv48P?=
 =?us-ascii?Q?HXU1JlPjq1lBd+ZRI6k9+jqqqn5ykon/K4d4aO0sIitVZKuywSHLFfkZkHUf?=
 =?us-ascii?Q?gBiMd7dNQfdibV17vu4prAaqwoRV5lh/el7/ff6mVuyGBz3nBqwiaC/R8OtV?=
 =?us-ascii?Q?5E+kj1r2gong9aeIsXb9jrccB42jS09d59CoBHiFiq5g4XqFO0uwyyxO3VZl?=
 =?us-ascii?Q?ujWqvouJUZcDvu1Rd7as84oAx99h8waFzpqqWrmzslUOt0J2MiiGFRa9aVf/?=
 =?us-ascii?Q?9660IgVtcCFvECn/OlpIEcVKQ2Gvehe/i0a+e5Byj7gR/hqdCnRhWhJtvL9b?=
 =?us-ascii?Q?qNgkkve3osqLiUFML80ZDV1dgm/AA4jhYyEo6k0g6c7K/Ne4oEaklF9Rv5vk?=
 =?us-ascii?Q?Qtq/lVz9sRjErmEtEQ/Xn5vRe9VQeHN1dPiB8dkV3gP6mpYYiZx0BUOA7BUj?=
 =?us-ascii?Q?caicvtpgpK/rib6RdHe3enB925w1K9xXqLT29dVnkBMDSO3+jDgXRvmncNH1?=
 =?us-ascii?Q?5oxOBxrpaXdJRctjUKbbdrjX0/GqhkE5ZHHFbdo4OudhVjP+yZ67nup1UMhS?=
 =?us-ascii?Q?EdekdDdJdEVrB2hjqCWNt82wVpPt8x3J7YsxW7Nd25o/uF6GsKF5BwrZfLbU?=
 =?us-ascii?Q?7J54ghXNXIrdEu4QqpSBjrCZiEWC1IdV0JTdd+WlICxrvMdOPwh4JYIQlCco?=
 =?us-ascii?Q?C/zMjpgQeDdfeKCDTREZuQNt2AzjENgiHzTe40kqHVZb/6XLIVhiQYlc25GV?=
 =?us-ascii?Q?81zfjH0tqV27kedqUYvZIrfhFL423x1PW6W3ffPUMG9w+Q9qZNhOs2ZnalpJ?=
 =?us-ascii?Q?Ty+isrLPOeggahXbkVUL0aP3rFLrjSroSUeTGqH2//oa6tezVhyomxtF7vb6?=
 =?us-ascii?Q?cRFziSIB7mEYSSyj80pRZPDbufa38e9Y8IhPE6ybibrNwfwTewzgD2aPYOfd?=
 =?us-ascii?Q?s+vAx+ejxVSVeFgONRiuNpLIE1DJrK680VYaFyhUct6sU+UVC9hYcV6FEcVL?=
 =?us-ascii?Q?uU7LBwBbWA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: AzEJWQSfcU7WuRvzaJGmSib1DVCSWhzJEBEqFg9OoR7K5uvI/jrYS9x2qSzCwUQFgIDmT9gjKKtfo+cfBXdmZiVOAdq9GM9f5hgHqrifYABxviW9jjxwNvZbhOsVqCWhWrZLSRgl+4a4FOjBpkTENh+aRSoP2rL/uKwtO6co+aFZmQ8HGqihUIEP21VDccav4Z4OCEcDQXzG6rXik+TgTack0OrAwQ0X4Upo6vXUKFYQQGWw26HyB+79Y6Ud2hDRTD2rT8XE+W7XpaqqurD7b9k/ndokv5ihlYFKYuOLwAT3x0EuyukpR0EsY5LrAyIQlxLj0mhiHFFJbTIoPbVXFr+4zz6mcBER5W8zdXqSlyfFLpaGf8bOunvte6AGhmPAaSjInt38qDrHMbTtD19hq1Hwmd6uNoCWJJ6NH3c8qZHRZnHlTeVM7BegAJ5nKwg4wWXPhzz/6eiFpDnENQ+zTge3Xq2vF4Lb9SIgSWRayRMXVu8XFJY0dctjZMrCYnfkBbvdvB6FA44ZnUkUUoIclGCNmAluwU442oXi+LGmVUeC7QYkVCUgo0maG8FDTv4KW/S5X4N2vsM1q4jzQb+1+pN6XUohJqGJTxDoeA730wA=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 5cb20472-b010-4f70-db9f-08de5981390f
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Jan 2026 06:41:07.9641
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: Ad1GbZI1ADeFXWABZfcL5bzlyTYhR7dKC/Iq2UOM3+WpaSQkwpPo+SZgFnuhUSlArsMBBacuuYO91OEL7q2OZA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPF5F5663669
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-21_04,2026-01-20_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 mlxscore=0 adultscore=0
 phishscore=0 suspectscore=0 spamscore=0 mlxlogscore=999 bulkscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601220041
X-Authority-Analysis: v=2.4 cv=WbcBqkhX c=1 sm=1 tr=0 ts=6971c688 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=inOo-CydEO0l5Do93jIA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTIyMDA0MiBTYWx0ZWRfX5rOnEMmpzUcF
 uFITeOL3f6mceVCSoFBuF0TUD6/jIfaSLxP/ugiq+EfTm+Aj0WckTcnYaVghxH9lT10lQHS6lP6
 GIz0188bFUTPxkffQyXYcLmxARJxI3+fO5w3YgseAM47bDoiLrAgwi+T/bBxo+MHdZHqCZex0QV
 55qbLngB6cQhgdVvdyPw1NSbFvUezFKM1E8fScPRXljbB4Z0MTDSEVjgBggORnxRsG28grwvkhr
 VavlP0PJ65Z/B2oOp+uYRbKIj5GrcvblhKZfrfbqqd1P2FdRhUn1vtG3sopc8c0Ne16SGAD+j6W
 /dgaD/t9MRxMAXw+FxuHA5cq0ucIuPLlVIHJm753nHZjmm8n9TrWw1/QXEySDdeOj9l9n6E57sp
 LxWJZHTeNt7W93Wv/mkft0YGC21K7xE5yUO1NTuhSl7rsOBNhyQLiL+5KXOEPNgJa8A7Jzksw7l
 eX+ScJSAOOWwnOjaGvw==
X-Proofpoint-ORIG-GUID: 9pLVWzg9bTltSnoja2dfmhO8iVkdB279
X-Proofpoint-GUID: 9pLVWzg9bTltSnoja2dfmhO8iVkdB279
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="DA/glrpy";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=k6Zg4h8K;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBDMNY7FQMGQEKDXK5TY];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,googlegroups.com:email,googlegroups.com:dkim];
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
X-Rspamd-Queue-Id: EC2B562501
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:38PM +0100, Vlastimil Babka wrote:
> The changes related to sheaves made the description of locking and other
> details outdated. Update it to reflect current state.
> 
> Also add a new copyright line due to major changes.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
> @@ -112,47 +123,46 @@
> + *   node->barn->lock (spinlock)
>   *
> - *   lockless fastpaths
> + *   Lockless freeing
> + *
> + *   Objects may have to be freed to their slabs when they are from a remote
> + *   node (where we want to avoid filling local sheaves with remote objects)
> + *   or when there are too many full sheaves. On architectures supporting
> + *   cmpxchg_double this is done by a lockless update of slab's freelist and
> + *   counters, otherwise slab_lock is taken. This only needs to take the
> + *   list_lock if it's a first free to a full slab, or when there are too many
> + *   fully free slabs and some need to be discarded.

nit: "or when a slab becomes empty after the free"?
because we don't check nr_partial before acquiring list_lock.

With that addressed,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXHGfLV6FdlNPc14%40hyeyoo.
