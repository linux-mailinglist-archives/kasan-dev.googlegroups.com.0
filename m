Return-Path: <kasan-dev+bncBCYIJU5JTINRBAOG4PFQMGQEGNJUOLA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CPVRKQTjeGkztwEAu9opvQ
	(envelope-from <kasan-dev+bncBCYIJU5JTINRBAOG4PFQMGQEGNJUOLA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:08:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 26833976CE
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:08:36 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-81f5381d17dsf3993640b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 08:08:36 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769530114; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nj30MZNhvI2encF88oDHPXYOMnTxh67s5WOoXH1DP19XX3Qr4hDELk1pUSvMciD/tm
         SKp9nu+b8+s+NyMW/HPqwGOENSh8iQ48OpFy7wQZMrCBJMUSwVl/SrPulbSLzpSjeRIv
         qok1K9Ei06ZiKlQ0PcOCiHRr5/gMe0mLisRDwKSqCXDBFdWnZONDYjDkNueEkJISYJg9
         XXVqonDK7Ek7FTL+rz6HsA7vloAzUjegkt8+7VFuGk9ioxlnzZ9DxEE6LN2s77HXSAcF
         N/DMxCTBeA4w5025BXjBTWZl6AA0jgsaO2YilQBrkdySzxmCXP3E9ojvOE1M8CzTNDqd
         F73A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ujWnCAJSZJ8naKRVdtnd60+1C8uYRP9z7SQ3ncl1Kjw=;
        fh=RBnAtXdiiefk34J0uc/OU4GjyD5tyOtMT9teVKdhp4w=;
        b=Dyw4FLGbPC/O6LR4UilN4Mw3IC8ykN5Rr3uiBVU9X93xtvKZsmINLhWHdtgjnfWfO4
         +lXvn6vh8HHBd+lRshGdMGX/GyAOL/j8k9flV1qGaWZJUSNO4OZ4aiG4Qm70muv52oxn
         r/JEUkAOBdokbxFE47U3bWNs2r4HhjzoAM6lQKCHh36opTUl7uB62PuWsIrHOJn+qs8M
         XuB+lNxNXuC7RFp3qQbPysPbBTwZMVVWJ/TGEXPgNvoaNYNB79uxX1xW7jFFNEsKUF3v
         GWrC4pFQlvse4YkboGYRdjIbk/Igyx8ju8zPKxgst4DrajenzMgCshwESTmZ04TATRr3
         cqXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=RQtiyeLF;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=IlZbBnp7;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769530114; x=1770134914; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ujWnCAJSZJ8naKRVdtnd60+1C8uYRP9z7SQ3ncl1Kjw=;
        b=IQsMIykFw5ZqJqYEXyf1fTJ7ceXHGnMYh6eT6ibB9HUqEPyOvE3ZbeeoDKm1wgXmZg
         W0fb3EsJn3xf0jIiSgRfH4dVMX6Zc/JbU22JXlfOkZaVKxfr6EfquQzkv/iuHXBT9/lW
         crCXN+TA8YXcf0B1BGOkvWHxsLr4kZ2mIa1i/9oZz69mlrw6+vQwZw/rFO09/WDPACln
         dCY7Yhe0fNjfFdYpIyqVPLDeY3yT+0u/fmpdQgm/9avHNHC6AQIzxRlUXBt5ZP//0vDW
         z6qSrAcEdA2G9RpaIetsdOGiVOLgURfW+4/MAMGla6gGBEsYkmXjcXm4NDaQok+gUpTN
         cHwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769530114; x=1770134914;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ujWnCAJSZJ8naKRVdtnd60+1C8uYRP9z7SQ3ncl1Kjw=;
        b=j8eNZWSMciyyQFrFVVAylqtvw5LnJghZm2lMQyEvHF65bpl8KnGpTDp4BsUjFIL1UT
         AWMXE3WlBiW6E1hCNp4/+YbMsK1yf8Sf7eMd6VjfYIP0cBx/gHZQ7uGoP31PXOdy8BAC
         jJI6mFT/Y4lrgORUpnp4Fo9wmO4P1iLZzsKMYO4KghJ2NmYMUBOo8NEE9ZSK3YvhkrP8
         jQoA4ftBI5hAQPLLkc4Tzm26GTYJ8t0N6DhblQfbh9HdJBQX/ePXn9Uwtbygj+YeEoRN
         Aa9RCXXnM3rlcXS3xjnd8JaYUIUKZrVRa/vcsw7MnYHr+oKB5Bs62Lag9xq543IvlL11
         INPg==
X-Forwarded-Encrypted: i=3; AJvYcCX1cr6jFAy8oIluWRLj5MT4rp3n39vTmKPC7BnCjrnH1UTOP41gpCNVEhFs8P7VsVNmuBPkRQ==@lfdr.de
X-Gm-Message-State: AOJu0YxbT3f2b5cRJBTThyiN2NhnpG7HolEEAKCB0eVCxJ8fIwlPLo4T
	WnIMdUC1b6O4x7mPpmf1LG/Uaiojvh70OKbU26ECTgLIcN+O/gEO4ejm
X-Received: by 2002:a05:6a00:9295:b0:81d:70d9:2e96 with SMTP id d2e1a72fcca58-823692c4b64mr2586990b3a.54.1769530114298;
        Tue, 27 Jan 2026 08:08:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EexHBy8fy4E1WeurjiE7v9ywYgtgJGP0jEtexWkHMb5g=="
Received: by 2002:a05:6a00:2ea6:b0:81f:6638:28d0 with SMTP id
 d2e1a72fcca58-821d69a41c1ls6910579b3a.1.-pod-prod-04-us; Tue, 27 Jan 2026
 08:08:32 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXEMHDNalvufs07Mdd2z1fStLviIwJ/t5XziiZtJy1fQ3RqnVKYMS0yzzVUCrXkpHrvSYMOkOrT8lk=@googlegroups.com
X-Received: by 2002:a05:6a20:9c9b:b0:38d:ebdc:3555 with SMTP id adf61e73a8af0-38ec654e764mr1919801637.66.1769530112254;
        Tue, 27 Jan 2026 08:08:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769530112; cv=pass;
        d=google.com; s=arc-20240605;
        b=hWHSiEAEkvNSG1cxf6OLQJgTbjEXhmsav/4s4yyMkb8k0yHQ+dtuZWOMHl20KuDHt2
         Du7eRVHt9U4Gv6Tc3EAlx24tuCcXNPjkkug4bDcTJ03tjmNkeKpyhM2Cf77vJPx3byxy
         8Mbb53yf4fYKKpDXCJfHvrWb34+wlHNQT493RVCD7g2QEfyddB6ZBhIbNJ2k+sbk3Pta
         p1lU1k3rSke0R+ucNxCWIGRoMEXqdjEndxyGTF4u/4BxpHdlR0RIUoiTHt2m9CAgTNpm
         oEgwb6ybb2f9JdKaWMR0aqyVyQumNefGVXPDvenC/rHPhf6Wd5wVUaKD4NAR6d61G+Jc
         lwng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=5t582QGrC14pIhgsFn6X9e59v4k90P8OL0Ro01myA9k=;
        fh=Ow62FcfbLm8VQ69X9vk1UxeWlVQw6eApzAyhL8gQ3rY=;
        b=SQvwYfq5OxQUlJgke614aVUPUnlE1ZtIhPwInhPpaauOKQyoF1PIsLPDO3zidYs9/p
         iQ028hCUiCXIjj+fz98zChvqUGPBituImLaH5d/rjCm/38gVHFjICGdjf193w8r5RTYT
         xSf8HvZdHW2k+GAT0MYISAZd2mM3rp0gSM9o5OLHndRZNh4cRC/Ee4ldGd7XdQDrGlo0
         Un7tHrCSkYmgT4EzZiuahTeSGYvy4aYMr9/084RjnJe632lLblwELvTSYMniG4maaWIX
         bzScMQoUUNAnYKgwStSjgKh6xzJbY2CvtnsbH/6z5TZuAOt/VqnS1QI5iQcOJZEIbQ9L
         CUWw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=RQtiyeLF;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=IlZbBnp7;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c635a1b35c8si309033a12.4.2026.01.27.08.08.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 08:08:32 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60RBEJ1M3280362;
	Tue, 27 Jan 2026 16:08:28 GMT
Received: from phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta03.appoci.oracle.com [138.1.37.129])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bvpmrc97g-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 16:08:28 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60RFWDvl035109;
	Tue, 27 Jan 2026 16:08:27 GMT
Received: from bn1pr04cu002.outbound.protection.outlook.com (mail-eastus2azon11010040.outbound.protection.outlook.com [52.101.56.40])
	by phxpaimrmta03.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmh9m297-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 16:08:27 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=PQ8ktfVj/joHNCRRE8fnc5pCIHvnhaWgrqmnKwZyYF7TgqpS9y5HHU1cpDgvt3kQuTXbQmVDz8FYrM4XPGGSIQ2hYsSJBTfxyG3I3tcvt8u6OSLpiEHlekoh/4RUjAaLpI2+J80OWDcLpjx8YPtdaeioTmaOEvrGfS+RWZGDUKMpqo2q5UwsJD+IeuhRicc7GME1DlfGFWe+GDtdwS4IwIvtOSFgMlIEwfs/O7RRty/QfUHsimSteFv8L374A+SzTvHw0EjS69ghew4xt1D5qm0njrEq/2N7ZCVar3WW5J5z7Z5ceMhbXuChcDyeXGEJiPYYzzAvtkJUOdq8RKT31g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=5t582QGrC14pIhgsFn6X9e59v4k90P8OL0Ro01myA9k=;
 b=QSqVuTVQ5TXHcC4gUQ1HZgh418rbiRODlfpjkZa/tSFZfXHF9D/dBFqSO1Xd+N+UrTrKURPOrZE07HDE+rulcyvPVm4qCjsX4X55+BynEchhZ9FtMZPz/pLGBYIYf5awWuDUCX5o/px29u1DREt72xJICNW4UH/dSdxchsVfrucn241Z2O7+Xq8eZMk4INdRrvDP8YeDX2BDPcdhloqNaVf5VDpcpo1wqhEU5qhkqkQe5cZiElog6qxUcqEMTh6RhCjEYMsYHjj1w7NVaclUem87VPahVuoKgH1VQdWGzKeBd9/c4owYsFp9i/jGWn8lLhzLOj2VkTNn/RnkbRV+eA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by IA1PR10MB6268.namprd10.prod.outlook.com (2603:10b6:208:3a0::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9564.7; Tue, 27 Jan
 2026 16:08:11 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce%4]) with mapi id 15.20.9542.015; Tue, 27 Jan 2026
 16:08:11 +0000
Date: Tue, 27 Jan 2026 11:08:07 -0500
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com,
        kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH v4 01/22] mm/slab: add rcu_barrier() to
 kvfree_rcu_barrier_on_cache()
Message-ID: <cgkr4xc5oczrjiox2utksbvecbke2kpniacaog36njcdmvkdxx@6hnvksdzrwja>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com, kernel test robot <oliver.sang@intel.com>, 
	stable@vger.kernel.org
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-1-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-1-041323d506f7@suse.cz>
User-Agent: NeoMutt/20250905
X-ClientProxiedBy: YT4PR01CA0011.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:d1::24) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|IA1PR10MB6268:EE_
X-MS-Office365-Filtering-Correlation-Id: 89ac915b-0e64-4ec6-dafe-08de5dbe44b0
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|366016|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?S7Y7jc+QoSDwT+6/jVfAMEs8oJSbmbJ6DKTaE9dN7t2sMx1EgNjdHe4Og211?=
 =?us-ascii?Q?aA5wp6Vrf2aXQSJVcK5kdnmHze7UYiIa6yMbT0pzLWP3/JuDPKXyGpGUqE20?=
 =?us-ascii?Q?RCS5yaYeLx15mKfZ/EPR9a1583HfUdgor3Gcp2G3DDxV5amTxARI60eX0vJp?=
 =?us-ascii?Q?1PCQ7ixk9yOw4zsTbTEyOEvteT3XpkOKLGp64dvVctHOme+gnLv2GkbXj9Op?=
 =?us-ascii?Q?8E238xZ9kpeibasgyjV9juITBgbJLHQ+LRn0+vq9KZ30NUQvOv5q8ayXGgkg?=
 =?us-ascii?Q?TX4M6eOMwMgdG46SztdNW13PNLTIeZWjkh6b2VRgBS59QiCV1rzfgSjhk6KS?=
 =?us-ascii?Q?OYrUGPcMEjuPikwtF8jeNSpEDtsZP0PraH8q0EvHKlu4PW41qiHmv01ShZzC?=
 =?us-ascii?Q?1whT7ju55We4om0hg3fm75rRvGkbKzGu/TmTGkjM/aMSGl7jqlnNuXEUgt9P?=
 =?us-ascii?Q?dEUl6dtBUOzyVH0kzro1dncTQcXlyKjiqsdVN8Owh2fD+YFOEH6572Pvaq3d?=
 =?us-ascii?Q?tPNPCtMyuSEKDo3f7xW0TWHktlzht21NINWeBtdT5Mh7s/v5baPC1epvPb4R?=
 =?us-ascii?Q?VgfXFXJ5tkgt2vw683SNC5/yKgk5A6FcqJH/nDsJ35LDMCFYQq8/xOA5Ldiq?=
 =?us-ascii?Q?feF9ybYZJfG+i8UAvpbAhp+/cu5g7bLoVJp2UrxXQMzoF8eWL1EAL45/4rdL?=
 =?us-ascii?Q?XoSEHl7/C1Dxji3Wq8CtCez+AbV0d5J46XnY82F0yF1LSqKzsSuT3GEAfUQi?=
 =?us-ascii?Q?rDl+mia6wXwoiJlg8PVAGXwJ5+Tte5ERa1oKU8/UO66R9jrx5ZLnjuQefgNH?=
 =?us-ascii?Q?dulZ5ZkViYRPsA6QLfKnO8YXuY2rCxJRsLRi3GdmgSnIW9UtD1Khr7KDby9+?=
 =?us-ascii?Q?7B4YswrILJWrmmcw6Aknb9WzgNftMuaoXeXXJkNGt7nq05aw+2Rko/FLlLk8?=
 =?us-ascii?Q?FmROo6k1tDwJZV/crptk7ZdXQaVYEqOMMSP9WIap3F+QhkleihyCx7n3Fdzi?=
 =?us-ascii?Q?dzlbW2fXw44ZUFJ4cvmyjTdcnwUROFAAbkPxTwuUcV0on6r31F/lEwxm+11s?=
 =?us-ascii?Q?QN9wb+jfd+iJYNETOpW/sVs9wdu72lqT012Vt4jdTJLWhnJvQXfk5p2enB4F?=
 =?us-ascii?Q?4ZofSxdNfxG4fvtkPoywNALDdLw/Uz1TeUh58sFg+oqwBcUQH2qcQKvc/8KF?=
 =?us-ascii?Q?3O1CQf18xTFtQmS11uZJCaF9pJfz8qAw/+OYFgrv23Yzfe+Db1qOMiE5DEJ3?=
 =?us-ascii?Q?HE/XN95N7BKewFj4I9cuI3tkkzB+PLS8R2YUwuEeB085yfwcuIMd/aCpJfOh?=
 =?us-ascii?Q?rstNbuXPgOSHNGESlr2zW6t15L6U0mT48tX4qNf+/KCUCjFoi2NdGXmWknHb?=
 =?us-ascii?Q?vLKKmpU3U/HtT4GADSF2ukRZyRSTuvGm9QEZUXi2PxXa2p7IER1CkLfT4N3B?=
 =?us-ascii?Q?fAQy8YZTu13ByVxbasgl2KSxOEVvxhdhBMDHSSXsvIriQpdWHtDaP27O11rz?=
 =?us-ascii?Q?SvVegRSDj91VfXKSot+9LU+OEkl1x7JGVlLa8xaXmMmjWFqy0YxGDT/dX920?=
 =?us-ascii?Q?NkU5OAUcEstgiFz0GG1+BWs1hhZHKGrI+i/iF5v8?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(366016)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?K79AyAYEOGEcsUr1iGiES6mnqPSLTEhoLrjNfWTDXzWiSgGHhtUDBmQlOE/r?=
 =?us-ascii?Q?Z8PmNtqgjaxsTxhB+lJc4hQ+HOUJ04JIP6udrgduJFpEp4mxesnnQVVNnmiH?=
 =?us-ascii?Q?4EkiXyTksD3dVz4xHA8s9nTaj+mwzD1zQdz3d5E5HuUQa6Ltt3a3b6bDbzrs?=
 =?us-ascii?Q?mv6/MLD4NuRMi3eG6M9Cj4roeHPbs98Agdi3B7GG9YTGr3GNl0ABxZDIPsiB?=
 =?us-ascii?Q?0nrxXQ1BJjzoLpvZpochwv6wxnObaCaAkYPgvPhAw57iDQcA6bgmqG+chMfo?=
 =?us-ascii?Q?YxyAbePVM1pXUN3CdkvuQcsDEmTjLaywF4XeRkFZmZ4AJ7boZmgXQk4tXXT1?=
 =?us-ascii?Q?CSH7oSc5vWWNwPUIVT3V3toicgWwYPoVehYCcdR+9re6RQAg+1mVCFCkOG7+?=
 =?us-ascii?Q?21mBt5WTnIX7ojZi8EnvwrJ442BoGU3kic3heA1pzbYd0tsyy2y30Hv7TTuX?=
 =?us-ascii?Q?+KqiqNRpDRG3VQCK6BSmQ8iAorAUf7/AUqkX1Pav29NRGNGcjI45twTKIoDS?=
 =?us-ascii?Q?L0sTVQKAVQWJKDgBNx9bpIKnmrvvaYgQPhhIu6eH1CCz48GBn2LA6pQuMmR3?=
 =?us-ascii?Q?0RSUI0fwapLxsUxQE9iT0lRQ8t7NJfW7OZAYgI4eC7hwSZeGe6uQrNupPBXK?=
 =?us-ascii?Q?Wnigs4uZKlRB68ju+evneHKmNGEwE1Lh+VMkbINLFcSve5kZq58e6k3rL0/Q?=
 =?us-ascii?Q?lBl8iwWbvczIHVtyZKKf9pxEK8zU9qCw3F0xkRTrHmgDBDcTKjn+4Ek84Biw?=
 =?us-ascii?Q?ashiWVs1sKp4hj52CltKUKNxJb+8rXAKpkWQSRgaBnxw6AEQsTysTrpwOKph?=
 =?us-ascii?Q?2m1EKZAeYORBfKncGpTT/2gFW1wUkprfUlDuVQKkmxKh1412m7Hgw4y75Vna?=
 =?us-ascii?Q?GyALfPtm3PJxj29nsPSTdyVGryRPhot9qLMcX+DXqPuHzjgEt5ZnO1k/IaNJ?=
 =?us-ascii?Q?4NPPNum6+4tQO9gRaeoii7BiDp5gliBkR30f5RiDJMPg0roIP1k+1CZXqYlM?=
 =?us-ascii?Q?S/0zHB7bgZKuii1EE/oRgQIc+PHxi5DAZm0otcsrD600ybVO+DwUwneUPvzO?=
 =?us-ascii?Q?5cl+3e8os6OZxDAu1f9OZir3jzfNAdlmtF0LBhi1XAZFx/0FnVkMdhBOqqRl?=
 =?us-ascii?Q?6gA8Va7ERHpL2BnBNmf0L0bjJig1ddEwg6TurE7SXCRI4JwyXUjPGLWLMR3t?=
 =?us-ascii?Q?VDDZwSqIoEDusI02kxf8gOCSQFxIZOLcffQZBt3KOBuoL7yPt0eXRjB52otU?=
 =?us-ascii?Q?Zo6lyOREWfUyXtH42XHKl0O5CGV5IaUE0L3TkKF6f5wF26lskt4kd1dw+atV?=
 =?us-ascii?Q?aQBoxw4yyVMYXwcDoptzBtF5L9/m481/Nhq04EvkbGuj0qea6Sx046YkaNec?=
 =?us-ascii?Q?GvgBRYJlgW3G/aCPFEU0aexWMmUHIZLkP6n3IXLd/Y7fG8OLpssCkfi1h2iO?=
 =?us-ascii?Q?hHEaLQ94EQUPBSBHywJ6HteTs4lZGmoK1Wg8+0XuRe09VfJVdh8bC5lrqvl9?=
 =?us-ascii?Q?VvKddY52rfreDN7On86CtCJIV8JppY6n6Im0GXmAuS40XCjcaDQ2aJj2cS7x?=
 =?us-ascii?Q?xSeaZpSI70OTQ8IkJOO7h1qhW5MpxAWYCElEGCMWvVCxkTo/DsXR7+7agGkr?=
 =?us-ascii?Q?xfjNdvrdsKrL4qmi79EvuRMpgcT+sIQGF1jzgD6r/AWUFWW9h0eirujlErms?=
 =?us-ascii?Q?U3UQfwgpY7OAxOrhoOFdGCmZHieXjPq6NKvddoCx1Kb/O1wM5YJE+0/XOBY7?=
 =?us-ascii?Q?0TJjfc5+wA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: rKSIfAXRSLUHi/DfHcOoFxMlirK6BGEX0fPQE/LXdXN3SMc8H7XQND5TB/ahCFKKp7LlbZF+tTlhajqsiwLrAJ+tKpemArDO33ogfzeEUwPY8TR/rsJevSEVNr8UJn1wIIq6axMxOuCLwjoyQrsHvCyfmrQQho65t2IxQwIBIobG13U/oedPHCsrPO0x5oAQSKHDtLCO8fNRowdVZ8yoRwZoC5Yg/6iNtT4HZllm1EXEguD1WyrBm6CGt3gkCGb0wgJRcF8UvK10EUISwTS4sFiKw6bZEkoGTZzf4mgaI7m8+2jV6PDDtkgPkMP4TgRGOSMxmcso9KsS7FlFq3+S5gtr/TBuoouwQiTYs+bpWJCCcvArhNx2tyqgiDdFwJeGmKflZdMqqnndSV9l2vREDHIaMHmlgZEDZIOx7iZWS3jGazOpa9Iy131fiJktwOpNXOjCX5eb99bShjLZ4dsqp/QY+JQ/V6ek1Pq+v2HLoWthKz60EtWT0UUplcFHorFJZBXFvr4kJkVhdJZpw7JoDFFZDGtu5ciIRkDX+fSfCRaaQJPWlM1adaTS6I1H70HbV6iFgppbAbgo8P3H2WXOoWZ+xR0B9rIUQIuzDvJ1SYc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 89ac915b-0e64-4ec6-dafe-08de5dbe44b0
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2026 16:08:11.2029
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: zfNvPTb/1g9mO3yA3EnojbjVgDWRzb+swG4UUBVJQHrl0mcST/Bt1KmcFn9YuYzdOV14KlUuPtDJtMZGxsQAXQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA1PR10MB6268
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-27_03,2026-01-27_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxscore=0 bulkscore=0 mlxlogscore=999
 adultscore=0 malwarescore=0 spamscore=0 phishscore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601270132
X-Authority-Analysis: v=2.4 cv=Q//fIo2a c=1 sm=1 tr=0 ts=6978e2fc b=1 cx=c_pps
 a=WeWmnZmh0fydH62SvGsd2A==:117 a=WeWmnZmh0fydH62SvGsd2A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8 a=yPCof4ZbAAAA:8 a=1XWaLZrsAAAA:8
 a=Imt2tuDpn1oFvdueNcEA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: zcPj0zP4SY8-6L_lPDvlm2109hnV2G-A
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI3MDEzMSBTYWx0ZWRfX7aG3eKTrLddV
 x8cuo31/UDRsAaLMfDzhRSNTjssSm1GpUXjOtGzFsAp0F/vQwRb/AXGZafn0XzDhHY9wWzwOLUV
 Isy2P31hzb7q7VXKOxWoTrLH3vvY1lYRMVpVTMMrki8KnJyvr7OQwax+wLb9NQPBn8/mI3C8ssm
 oiK2WNOqXQncckLamBTQat2fBwKmDOi7yogkvltaqdlmi7CgRLvbciJY1pdy4se3Wn0eZMDT5fJ
 h4wrRCAwnyA9igYvyUmt8Tz6GjhVf6xStwkOi4tx+rChPhv401LvdWxjy4PP9wnggh7aZsnvnu4
 uOGnAYr9vEOjaab9tcUuJT6k9OlVhGGnl8EUKPfNBilIP2LDXub98ga7cgRf952oHZk+Ua+7k/w
 54w7B+PwgKqvUaDoNhOSlJVUrslsRn6Lb/ML9Fbs1tEFw0RbF/67pR+slwnvYbqaQE4LxlLqp9o
 9fxAhU5C2zlcPlzvIbA==
X-Proofpoint-GUID: zcPj0zP4SY8-6L_lPDvlm2109hnV2G-A
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=RQtiyeLF;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=IlZbBnp7;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
X-Original-From: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Reply-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>
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
	TAGGED_FROM(0.00)[bncBCYIJU5JTINRBAOG4PFQMGQEGNJUOLA];
	RCVD_TLS_LAST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:replyto,oracle.com:email,intel.com:email,googlegroups.com:email,googlegroups.com:dkim,mail-pf1-x43a.google.com:helo,mail-pf1-x43a.google.com:rdns,suse.cz:email];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[Liam.Howlett@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-0.997];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: 26833976CE
X-Rspamd-Action: no action

* Vlastimil Babka <vbabka@suse.cz> [260123 01:53]:
> After we submit the rcu_free sheaves to call_rcu() we need to make sure
> the rcu callbacks complete. kvfree_rcu_barrier() does that via
> flush_all_rcu_sheaves() but kvfree_rcu_barrier_on_cache() doesn't. Fix
> that.
> 
> This currently causes no issues because the caches with sheaves we have
> are never destroyed. The problem flagged by kernel test robot was
> reported for a patch that enables sheaves for (almost) all caches, and
> occurred only with CONFIG_KASAN. Harry Yoo found the root cause [1]:
> 
>   It turns out the object freed by sheaf_flush_unused() was in KASAN
>   percpu quarantine list (confirmed by dumping the list) by the time
>   __kmem_cache_shutdown() returns an error.
> 
>   Quarantined objects are supposed to be flushed by kasan_cache_shutdown(),
>   but things go wrong if the rcu callback (rcu_free_sheaf_nobarn()) is
>   processed after kasan_cache_shutdown() finishes.
> 
>   That's why rcu_barrier() in __kmem_cache_shutdown() didn't help,
>   because it's called after kasan_cache_shutdown().
> 
>   Calling rcu_barrier() in kvfree_rcu_barrier_on_cache() guarantees
>   that it'll be added to the quarantine list before kasan_cache_shutdown()
>   is called. So it's a valid fix!
> 
> [1] https://lore.kernel.org/all/aWd6f3jERlrB5yeF@hyeyoo/
> 
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Closes: https://lore.kernel.org/oe-lkp/202601121442.c530bed3-lkp@intel.com
> Fixes: 0f35040de593 ("mm/slab: introduce kvfree_rcu_barrier_on_cache() for cache destruction")
> Cc: stable@vger.kernel.org
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Tested-by: Harry Yoo <harry.yoo@oracle.com>
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  mm/slab_common.c | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index eed7ea556cb1..ee994ec7f251 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -2133,8 +2133,11 @@ EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
>   */
>  void kvfree_rcu_barrier_on_cache(struct kmem_cache *s)
>  {
> -	if (s->cpu_sheaves)
> +	if (s->cpu_sheaves) {
>  		flush_rcu_sheaves_on_cache(s);
> +		rcu_barrier();
> +	}
> +
>  	/*
>  	 * TODO: Introduce a version of __kvfree_rcu_barrier() that works
>  	 * on a specific slab cache.
> 
> -- 
> 2.52.0
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cgkr4xc5oczrjiox2utksbvecbke2kpniacaog36njcdmvkdxx%406hnvksdzrwja.
