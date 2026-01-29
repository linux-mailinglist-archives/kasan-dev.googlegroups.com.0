Return-Path: <kasan-dev+bncBC37BC7E2QERB7MS5TFQMGQE5RY5KWI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uEt9Gn8Je2k6AwIAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERB7MS5TFQMGQE5RY5KWI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:17:19 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E0D11AC86C
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:17:18 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-8946b186018sf24667406d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jan 2026 23:17:18 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769671037; cv=pass;
        d=google.com; s=arc-20240605;
        b=LbmtED4QNB4GYeEGLWUrjqlpMOB2WcP15FnFBozFRnfUM1jX6yIrom/yV5Yr5lYZH1
         FcTFdiFivj9tzyNXECQ9a4rG9jT7JY044KcVbCKhRD1I2N35Nlot4rt8RvAV9FKlGpCu
         iubukeTIgU0Ui3hCXwOu+XbDNR5KDpm+38t1XtiEqZiS3fjF4C2KZdwPUuiiInHlz3zC
         mFmfiBPqt1BGSCuV+thcDBLjM02UlbHynXp6qLrmuG6DLjdAuLwAmQ/9ylYvfY9DicFn
         9obxBvwRVfGEb/nKx1IQsNJNZiauCnXyZHd5Zj1Y/15MpfcUE0/UqrPDFiU9eQKp1s5G
         5xiQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=qo4IVtT/zBQuyONgNe/Di/+3wB3mW38bptazItm1rvs=;
        fh=TktK1jGFbf9nEQKPpGg7U6b8BJ68+J0rlnT4rF2Ft+0=;
        b=jdyCjlT8xLlPc8jweJXzUyScN8Y4FldAYGUEX9DXfD/6jH0DWkY2RsDA3ugXBACuFO
         V6tpOGQZ3sKTosJzYA0nI+tzu6E2guQtwTKUi1tSY8Y+/yul2bKMjQ5GNj44THA68VyI
         8U7uyyeAay32LtESFj27XeS/+FqzcVJDsx2adz2dl67NeyymfRsMwmxc0BHkgQIA02hG
         2/1uel+e/t5Nok/Gp7BJk+TzSTKk01MsQRIPstvHRDofU1dAlc0zndjyYo5EumVi7w4d
         kdFDI8uxaGhaENNJAhyyeYQqCJmJH8cRfIyPuxOzYyFt8o71qSKACKh1TVZ+1kWs9rig
         Q2EA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=mSRrCj9f;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=nlm+jlOf;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769671037; x=1770275837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=qo4IVtT/zBQuyONgNe/Di/+3wB3mW38bptazItm1rvs=;
        b=VIk4wRRu6N8BTdo+sLoOZYFeDp4hzeFbzMiGgNTjbS3UOigW0FIoNlDlwMD5aCQ1w1
         L2U9F7DiFvuSyDt/rQ/ywQdJ0ELD2aMCgsRALT4GjVu0LXgWL79aGmcoidt3238OjV0f
         1t8G2hw6k/mhEfI4gyKaV4IlWTW5OWkTfNXUV/CQvFCMgCYpSMrukxvLsCbOIuctVArE
         b0l/ZY4FymqHKT80aB27aR0f9WWrAIP8ddCITwpZgqpbVzvxY53kI21ddKl0zCx7s+w2
         tIAfi6R1f5c3HlGH4ZuuLz2UyN+mx1Mt/lXBHLlbED5ViMaszKXC0D4s7P5N+Oo0YVDb
         PJdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769671037; x=1770275837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qo4IVtT/zBQuyONgNe/Di/+3wB3mW38bptazItm1rvs=;
        b=pWyC9V66eelE0zEZUlNzp6D/1sPVhBwPcwQIBketo2z3PifbJ7Vg5dP4OJ+zWccmaA
         jZB3N8RT2JmN3ap/kgXklCotuRennZ3Remb3Ul7flzGtpzJREUuB8sxh3ASgR32BZ0Hi
         KcjnHUTML1xvkrYBii2OkdWPvTf5f7nVBpkLx/1V7pCsyzkAcN31XwWK4885A2O9DOD9
         hgdqGUXrhdOsOxMWrIpk1HQN/XoO4ufH2l/kh7kXHflxeK9x+6vFayEqicG+Ws2dYU+S
         jGplFHPXusx/VNXP2VJbmDQ66i7msMVrlOZf7Wgg0UAifzSsFOaJgbwjJQdXdCFpqbM5
         k4QA==
X-Forwarded-Encrypted: i=3; AJvYcCVnN86/tNbAcl+SUe+rQXNh+nA0j1DjEoAjGL75ybBuYq8R0+kbMUv3gx7oUp43RaKpbENLXw==@lfdr.de
X-Gm-Message-State: AOJu0YzvXBFz9WFs25lyghau9Gpnme9G963JVCAA9ooBoQKeyqOudDpJ
	07q8e0WDJFom4T/KOQzIhXIBNXtMQUVKO+NxlLnE7RudvexGo0dA6tkw
X-Received: by 2002:a05:6214:c2f:b0:892:6ec7:b2a4 with SMTP id 6a1803df08f44-894cc949c31mr122176086d6.49.1769671037291;
        Wed, 28 Jan 2026 23:17:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H93jHmGIk8uSQv/PULGgw31R0gPe0rShqt9vxykxOywA=="
Received: by 2002:a05:6214:528a:b0:882:3acc:d7a with SMTP id
 6a1803df08f44-894e0b2c14fls7069746d6.0.-pod-prod-07-us; Wed, 28 Jan 2026
 23:17:16 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCU9y1lGGg5xVkNVK5D7n4GKJajVF1kp/lTfCOSLh3///DQuG0FrXn3BLBKDbDzFJhMzkJOzxCFjDm0=@googlegroups.com
X-Received: by 2002:a05:620a:44c1:b0:89e:b0bd:ced9 with SMTP id af79cd13be357-8c70b8ebf6amr1016784785a.43.1769671036129;
        Wed, 28 Jan 2026 23:17:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769671036; cv=pass;
        d=google.com; s=arc-20240605;
        b=IyYZUfKDg56/SCLw1GBzy5ZmFY8KmgNlPUUKxz6a6qVPENvh8LOjIOhL20NSd4XbK5
         eZA2K77F+xsMVuOSW7PTrCdmE/rZismmm2gtNmVYdTHqGf0zcGd+8Fuqoxto27ToD0gA
         hKCg+a69Gbkqf3UnWn5aH5z18ZK5ayQDE3sfAwTKoetJH1XDZPjpi0cFFDAPUAW47+U6
         DsqXXHFBlCAHawoEkwJnXbTjf2HElgzp3erezQsjRhpctWz2Oaz+IzdcMVeILgZmMyuI
         mjg1CqG1w5sonhvm7YOgtwCHEpF9WTQzhOatuAakR+l+X/0DoiNi8fOwfSSdZuw7cCt7
         iscQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=NpIB2r4Jyad5bLbMjVh9gkV77hL33TY4MUV9hoXQfUc=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=RxVuyqsWzbJ0H985nOS68cY4+7hbfv56NcpZDy2eVVA+t51YITwNnYaNnlkeN3Ser1
         VtqWuS7qs7cKVd3/i1BQ7HjaBol6AAQIzQ3kjzAV0ILH9ua5AIHyzd7NzVDvuvacFeup
         hh8C72bU1gn8D24mQvDlpJDrK8St14cOAizBFhXsAP+iG7uQOumK/JMgfTNDXqW73ff4
         uATI4OlJ+rN4UjWfEnq+HLxGnz6DOzAyBnNBWCmS7wew4fnp/7PmtHJYlBCChRkgWqSe
         J/+RoksmUp34VJ3vuRzpJN0I4nGGQUSwpqWcPfWg/f4uyD08ux5yB1CwistRQ52Gatyq
         2AiQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=mSRrCj9f;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=nlm+jlOf;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c711d272c8si18239585a.7.2026.01.28.23.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Jan 2026 23:17:16 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60T3YUaV3744719;
	Thu, 29 Jan 2026 07:17:13 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4by5dj2dqj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 07:17:13 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60T6pKT1032720;
	Thu, 29 Jan 2026 07:17:12 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010033.outbound.protection.outlook.com [52.101.56.33])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhbxs1q-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 29 Jan 2026 07:17:12 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=ASny3/KLS6qCnjk6tEVSYqjKLmPXNV8W9+tdMRcT41K+lSrZfwy6elGlcmX6MCb2ltCwFzOihng12v6cxrpfyLP0aaJBWmlC6h/R926HG7LuYpCV4mt5cmlzxPLZsWWLUiQGmpA29/i20Vi3L2fAb0wQu1BCfiRdp5NabL4GZALJTuFQWsMnOIWxHltFq3rZ68jg3FU9mucVbf4pAud6v7LPYvCJ9gGTd9bwKLvPhJnbiKlusj/nTYKUIxNo+s4gibVQ8ZiO3/0wLoXy8EZCqUaybDcdkV+Q51hopLXEZwVnIc6YlhbJdlEI7UB1juYICZUey8y3eoKoCg0pqRpqrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=NpIB2r4Jyad5bLbMjVh9gkV77hL33TY4MUV9hoXQfUc=;
 b=mFZTorrNLrRxjjsONVn2mxPFzNLV9Nh90yaY3xhHhXzhyyfRO7inRYher6I7uFr4FZl9mbPEzgM9YzrajWANDyHw31OabaVofkrxM7pBHHY4m8+Q8tJNHUKba0tizRUNnap9HI77Fe9ucEM6KuCbkbLZ0NoFs/nv3aNATzEkRE6i5juusJIGJcDhaw+G82HM5/s5kVQnFcCasN1u26w4cv5wRBanWP3WEosPEkyN6yqlnzr/zpVhQHr0bGmXUxFRPvUwohncOC+Jh1IBsQfZKdyI5FP6F7PToOGSNE4UpJp24ena2s1ynyUvo2tROGAsj8x6eEqsgApaaGDmysGCcg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DM3PPFEACE3F2B7.namprd10.prod.outlook.com (2603:10b6:f:fc00::c54) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.12; Thu, 29 Jan
 2026 07:17:08 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9564.006; Thu, 29 Jan 2026
 07:17:08 +0000
Date: Thu, 29 Jan 2026 16:16:58 +0900
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
Subject: Re: [PATCH v4 20/22] slab: remove frozen slab checks from
 __slab_free()
Message-ID: <aXsJalZN4qdFze2f@hyeyoo>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-20-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-20-041323d506f7@suse.cz>
X-ClientProxiedBy: SL2P216CA0123.KORP216.PROD.OUTLOOK.COM (2603:1096:101::20)
 To CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DM3PPFEACE3F2B7:EE_
X-MS-Office365-Filtering-Correlation-Id: b80a278c-71b6-4d8a-29ee-08de5f0669cf
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|376014|7416014|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?1csfLsWPBDv2ZtMio0nWElVqocna8crfyH4v5ldXbN1NwVEaHG2yEGGFt5JJ?=
 =?us-ascii?Q?rKAKwzy3hQ6HJYWtf7Z4OeUr5bg69lVVV+7L0CZXJatH7ANwr6EPgS7DeFkq?=
 =?us-ascii?Q?21V8yUqUk3dZ5VzuSVFSowOJuuDPcU8qlAtfiJlu0kxj/gGheJLE6U18CB/9?=
 =?us-ascii?Q?a9/59SzEaJP1vFLpKAwDbVdo42w/C/67/VxYdjXE+g/ef1dTtdpRf5GefGZ1?=
 =?us-ascii?Q?wzSxXWaqoGDYi2ab9ambeBNbvPVTms6vfEu3knJlitrp0/pKKOeVyO4LqjOO?=
 =?us-ascii?Q?pz88i0LTrWqCka99eYo2FHSrakcLSofNPk3RpgX0KEkLLdk6E3IqYlyYIKwd?=
 =?us-ascii?Q?4f6S/ktioMng+3TZ26P9y3fvj+CVMkrel+1Ewqqh8uf1ZEmDBmLfbHWFx6bi?=
 =?us-ascii?Q?uqUmrpCNMqAkt3ZWhKCBo4ikew7rcQ2zow4R2ZRDEAsi+p5rHOfOgAaDCjeW?=
 =?us-ascii?Q?LnMLWA6zAVcfwo82M10NbKlqVI4Q4eNch34nylOIXbPQ8+1PT1yOc6HOjPd6?=
 =?us-ascii?Q?IdMqJ6HLKJMcTBtYiv5eWZUXaMUvNBnNGxPgc0HFqcTdiOSvy5df1hBY1qWA?=
 =?us-ascii?Q?4HDrg7+Il3JwGP1PbDTfa4/l24NtH4aeno3IRSn9n5gThdpjnnDDOEZHwsp1?=
 =?us-ascii?Q?fZbpBUB8uYzhm9yPvjTEw5XV+kZsCerEoxXY7kpaczEcxSAITIH3/lu2Hgnr?=
 =?us-ascii?Q?ZRXz14wzL7NjHooJo77jMWHlPuHRNrGCyu1hGtWOAlUPwMcnZasNwrY52n4E?=
 =?us-ascii?Q?jh342bomAhIoEIbWme4h70+V2EqgZaOIFIzBVHxzn8SalMiw28fpc/OYKyup?=
 =?us-ascii?Q?Blaf0bYhMOKUMRe9ArdnMihNu6kkRIhiqG6Yd4kb/fm4AjagV6S0g88Iqh7V?=
 =?us-ascii?Q?GaVkU7IzzKiiuvX5UkH9+Xi2LWyBKT/O/YMDNSCFoJkuaum4mqr/CRs6bDkC?=
 =?us-ascii?Q?fb7yaD0V26Vt5y4JsLZdcBHWfVes6cFeUS0EpV7mNVMPuW2F6ca2jIVDkm2n?=
 =?us-ascii?Q?LC0CFbOlNNU1Zd3O+6XX+amaz2tOf3ENWc3fCWBvlDhASuwews5XAMS1lUuR?=
 =?us-ascii?Q?85KP1Zd+TaCh3J7cM3cARGn5ql7JJDPoVLvn/OrjA/lbAhiIdPS4WU6MvTAt?=
 =?us-ascii?Q?ifd8W1SfyLAwpQNIOsG6MwtNnNntD4mBUJCQhHNEUe4desBmjYiUOqjPjvIp?=
 =?us-ascii?Q?MoluSdkspdhIzzycoKFyf0kCrq1YzSaWUTt5x0SL12Msx13wVpGQnP+kuDDp?=
 =?us-ascii?Q?oegmQC2rBnzHKZRdaW1JH8iN4oY+uJraCo/8dfTTT4jaWI1tTvf8bhWLPROm?=
 =?us-ascii?Q?fRmVin14flSRk6c328S1t6JO4j9dEKoAnnQEQ+p5VNsjZaTxoyp7Rren+3lM?=
 =?us-ascii?Q?EM5d6QBOwJlGxJVK5g3W+kr1/p3s5L5fZlBmPlY7xvf3W8VKVB+2+Vz10PNt?=
 =?us-ascii?Q?rbGBcu8ve2ZT7GXMx0ZPdW0kX1zezCvPMw41bPaIJrGzSaWwfwapT95aP8pK?=
 =?us-ascii?Q?LmWJRJ2My5MSOrKbpQPoPwZxNE9qdY+aFAaff5OYZlWpN5OjZtg7KzXzyFut?=
 =?us-ascii?Q?AA5YYgctdWoSqwOyvS8=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(376014)(7416014)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?pV1TtgOuy44fB9LiJ5zrEm9DZ2C4L/KECUTdS3ucyAXh9V8CHzHT2LtU5Yqy?=
 =?us-ascii?Q?CZfg5Vg1NrcrH0Y/+VKepDG5mxUmj0I2sVUZjoQtTIyZSxttIjSzUUsWdx1+?=
 =?us-ascii?Q?ng/v3TpBNvyRjWpBCTm3WtAd020ae7VJ0aljhpNf9o2OvSTl2OYVCEohi2Ru?=
 =?us-ascii?Q?tl947L4ExozKTcmAbrU0NMozx+atVxYQsFlRMPGZgJLKDJgavjGE2B32YgrP?=
 =?us-ascii?Q?c6EwzS2ki7EJENq+Z47x+u0AHAm1vmfcfZd7zEk34s5GPsVvJ1wcW2cVZ5dF?=
 =?us-ascii?Q?f5CekZWbZMy78X6BMxmHuXhqgr9nwZc13oGCAjQO8RbtnoKTUaJc34v/NrLI?=
 =?us-ascii?Q?urg0apqk4mlxJ7oQhVIh8nN0SaATil8BwHSTH61lAibqZzdpiCbtnhWJ8rod?=
 =?us-ascii?Q?qTpyj91EBHom7Uyzbld8RJUsQC2dL/k7bVuhSyXxeoCkzR8nLyvyd+7gt9p/?=
 =?us-ascii?Q?Tq+4JZhZwC7V3FDeFQadLgcmsaGDnK+Z7RZorMC02m5plO1zYdsaSlcSuVRB?=
 =?us-ascii?Q?e/y8dtyFlBiZX9egbXXUQ/L9URzEho66XjtqsixtJRHqvULLbhEj5d37puhn?=
 =?us-ascii?Q?UvLq2WNs2TJj/R7vmJWBwu77snqM2d1A3zPuJ/8H1//Wm5XvrdtTKXaHYBya?=
 =?us-ascii?Q?UUbURH/EDF9VNLB684vqTpySOW27r179ChIscux09eUWvAgDN/H9QFkUn87p?=
 =?us-ascii?Q?di2NZ+MueFaGN4V9E6c1tN8pEF529LDtkPlVSZstEFMkkGwE1pQVQ58cOepn?=
 =?us-ascii?Q?fPE2ejLHf59aY+tm2zMPGLDUP9HIWTIoh6I5LIQErQXii+1KHUEaoWHypxGc?=
 =?us-ascii?Q?v3yLIUG30Vkh/6xyI34Yl5SvWohZ1+p00z7VGye3pl4nVpyKjO7H+CpJIhcb?=
 =?us-ascii?Q?IdczAH5vAwCXAuAUFS3B46+TQgIVRPThdj4vJvPKh/sxEAE7u7kQ+/IEZ7Vs?=
 =?us-ascii?Q?rXElP8FLNosMgWqIlMViMMDhZgI0F0XtDYIUSTHMil9hqcqEFUa0JzJdRf4X?=
 =?us-ascii?Q?zbyD5SG1U0+deDDVnW8b1yzfXsWApzkrLw+8wuPwKcrhC92Gvx0TqCEItQK+?=
 =?us-ascii?Q?eADx7yH4fnfrgihQ+9etj6L3RbeZDqXQqPkXwffDjR0BrmQXIjt9CMDe9N6M?=
 =?us-ascii?Q?UPyTmfD4xP0rCPCddq8oV4CDoRghudv2jw6kEjnw3WqvhWhj+hTUZ+axjB4U?=
 =?us-ascii?Q?T+VxTHnqoW8z4KX8GGjR6WrYVZkhKQRA736NSysitj1/I2HhtKGlWhQwqnjN?=
 =?us-ascii?Q?fZr9GKTqZNyKVcblHqQaufB68oN3UVGshStwEJbkGWWe3X/lS34CjkexKRfg?=
 =?us-ascii?Q?+XSpYXvr/OVA7NuUg3LwQ2r7lX5l0vH+sXVLDl/zZt5oFEug2VYE5t752bY9?=
 =?us-ascii?Q?f7uLHKoBojTgFOiyEhWfGp5TQcy/rIGhR85GBQT/lX+xYLvap8ZOY7M6zGX+?=
 =?us-ascii?Q?WPZxs9wUM30AvSQZnH5owwq7C2CJlZn///2dMyZPgTE/2gAfBg0b/+aKID7q?=
 =?us-ascii?Q?t4CcY/fBG9HZJOuJrAj0dAA/h1Bwp4cmhCLuAeo3M4u8GTPEBquIwN/3Edw3?=
 =?us-ascii?Q?xTjh3p+Nvom8DyscuJdoOWAIoHuDg1z5OypTWQdw2LPpPkMznQQI/i9M/58H?=
 =?us-ascii?Q?j2/eW+jYrtAVeXgvRlmUSbhvn5Wguq9QKgvW3C2oXUCCwdixhvvA6L9qSHFZ?=
 =?us-ascii?Q?BSwHAdd+1HahP3AIeYC+R7WML5xeRi38oAzo6LB8aRiq7lVeJWfu4606D8LW?=
 =?us-ascii?Q?HfkF1LzeGQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: u0LFikNkSGzHN3BOxVhYA8gUj0ht0Y3Eg4bxeKp/EeMVlvVRhhODd65XLWhR+J6KIcZEB5rmnQ+PkE7X4a0G+ng+y7y4A/+ml+pkt3gz9QjWl8TMF4v1IFmuVWH6MerXICx2IjRcoxNELcErpDys9DRzcXNE+dcEOBs0jlNENsqG/heVLfaRZSl+C8XQ/o+X3vyJBJlsh9dN6q0f31C2aiCVcrmUc4oMp+e8hXpe4I1vytQt2mB73uo4sGYPT8NKj9pLmIXWNPsIIqfbN7asw6N9u1mS7z8eV0pyOWXM0G3ZMu5N2n3TuOrSvr1xiPpFuDGlH/WTwrkYusZzH50b0v2rrUICuORKl8t5YYXUQ0B6i5ZlhNjFs61RpiMl5xz75HTZ9P8hOEcijU7gFZ38zpDEk+Cm6c9WNH7xN2IhDh5VJZGM4BI+0EmZ8La9Fu6kNIEE2GXoiPRhk01AO3jVpXyjDLAUKAL/iywZr5q0BTw/wj5Fiv1CxbV+PdrUwZiZ3vdI2H5iOSOmT4rHYelI4Ch9jK55K7AtXoPphkI35qbODj3/PbBZKAz6eNpbah6LmRnWTRmZZpKJ/0D0A84ITCy8aO/ZMzneRGpjrMJHErI=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b80a278c-71b6-4d8a-29ee-08de5f0669cf
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Jan 2026 07:17:08.6529
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: mH1rJsHrpjXhaqtB7ZZaxL0EhxqK4bSRLh/h0iy4aaxUsdZsPQUH3p8I+1bOFFT1bK+SagNgIVKxj9aimHMtYA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM3PPFEACE3F2B7
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-29_01,2026-01-28_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 mlxlogscore=999
 adultscore=0 malwarescore=0 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601290042
X-Proofpoint-ORIG-GUID: X3lGaFsQ1he15CSpMhL3V2zNTNuwfFXB
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI5MDA0MSBTYWx0ZWRfX+QWYmNTH/4uZ
 TP6gcYwwAmEP46nn0Tjfwa/KQiND6s6R9B6rOuIURpMqMFiXoiT6wCPdXssc+gCEq91vBbb/O77
 8ol8GTZr3a1E/Zg71DWb94MJN1QbVl34J2d+4ZmlVeIL/+Cgv3MGqtMKSfgWzXmso7BhA7LJrGm
 T0ltqehxg6mCpByfJKzEe6ckejqpb7SEuSr9Z8QtSh49Mwuyyr3ZHN8O3r2H1tWSEI/AX6IZIus
 1chKhKH3IZpcD30GtREIAiDPcBok3qKrLLOwgtGd2Idni1dwGlWdLGUfozNu+g0HqPtmJQQqErV
 ivDanoTuWK5CjDeniOehFiydWpnDaDiOZeT7QCF4kENVp5OlvLAfohreyqpLCOStevydpOXfmJR
 lFBQzRVnpm1hZP8+/CLKpFP2n1XBzM4ocGk+tKmqjtUXC3ggR3hJKOTWNnW2406Sg9hKGyf3LJy
 dqnIPPGM47jdm4vmuPg==
X-Authority-Analysis: v=2.4 cv=IrsTsb/g c=1 sm=1 tr=0 ts=697b0979 b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=LwiVl9ns5TU31JiSBR4A:9 a=CjuIK1q_8ugA:10
X-Proofpoint-GUID: X3lGaFsQ1he15CSpMhL3V2zNTNuwfFXB
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=mSRrCj9f;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=nlm+jlOf;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERB7MS5TFQMGQE5RY5KWI];
	RCVD_TLS_LAST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,linux.dev:email,suse.cz:email,oracle.com:replyto,oracle.com:email,mail-qv1-xf3b.google.com:helo,mail-qv1-xf3b.google.com:rdns];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: E0D11AC86C
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:58AM +0100, Vlastimil Babka wrote:
> Currently slabs are only frozen after consistency checks failed. This
> can happen only in caches with debugging enabled, and those use
> free_to_partial_list() for freeing. The non-debug operation of
> __slab_free() can thus stop considering the frozen field, and we can
> remove the FREE_FROZEN stat.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

>  mm/slub.c | 22 ++++------------------
>  1 file changed, 4 insertions(+), 18 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index d9fc56122975..3009eb7bd8d2 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5145,7 +5143,7 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
>  		 * to (due to not being full anymore) the partial list.
>  		 * Unless it's frozen.

nit: "Unless it's frozen" part in the comment could be removed.


-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aXsJalZN4qdFze2f%40hyeyoo.
