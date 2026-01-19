Return-Path: <kasan-dev+bncBC37BC7E2QERBO5EW7FQMGQEH7QHVSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x1240.google.com (mail-dl1-x1240.google.com [IPv6:2607:f8b0:4864:20::1240])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BD5FD39ECE
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 07:42:05 +0100 (CET)
Received: by mail-dl1-x1240.google.com with SMTP id a92af1059eb24-1233893db9fsf9404620c88.0
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 22:42:05 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768804923; cv=pass;
        d=google.com; s=arc-20240605;
        b=eYzCRAT86PaEFTz6DgmQT7QRrILLq357aA40/PCzL7r34uIY/0JjbJBFKZNO9GwRtk
         VuCp9IK1zpoEs1WrBd5ABGmR5tZ2EVETck9f34m15Tyk0sySf+gKYW0cZX6JWIN5XWzh
         gbTW5di252hCrvlyjcX/loxuMhE0UqIFCCQMpBHIc1HI5FT/KdTbHGb/tdBgEtq29SFX
         f/RUEOEWaoJQbxqAddZCN9XJpiPdnYpbIjPet9fxNHRLBh97u2kXvsQNRm1RXXGK1xVs
         Z9fB2VGwYQ8spMaGGNBWnjKu4CMEh/W62dHXumRxE3DKDaOytTNBA2O0mmo2g6y7jvPd
         MzdA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bM3T1BK3BvkQhiZfkMTtBBju0VXlAL/zuUxMEIG+v/0=;
        fh=zNi/2z6AjrfHKe4A4ZnB4Nx9funLFwIwCbI4sGJI1yw=;
        b=NHtYigRkJz66i49zx9jG5Ki23VSIBZ8UpzmE8IxAbKJrqsVndxQJVIyxwqxDuV7r4O
         GJp9QQRXsWyCwisGqzDu84K75MhQf+p7skOrAeXjUnhuYCGCDu3SMX17DWlkWUXFH9H4
         EJzXOAPpLn3rfTknXtEbjlv01P0of+jtL0Guu9zREMa7UPPRg1TZtVq8iWc41KEAP8di
         zSEwvCd3bA2VyRnBs0Fi5G8OZ3m5TatrwcUxXDMy3QpkQT7VO/t+9az1jfYUHTGI2g5h
         b1E/lRsMLXDmpg0XIAAKCVtMX2+C9fw1NWuoNKUZeVS+SmIrGsX8xg4kbyb2K3g5Dr9D
         GkOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lr8OcrMX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=XPUvWeSn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768804923; x=1769409723; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bM3T1BK3BvkQhiZfkMTtBBju0VXlAL/zuUxMEIG+v/0=;
        b=AJs7tW0inH/z9BIIEIqmlPBM9npIvi+kQVx8TN9tHEMIeS6QURP8GtVHY6OgpDQ3cm
         O0SsKJHQR31BySr0sOTfV8l7ercTmIRbB/KXoOgtUG/gclVWWetEfLBBcesM709gE2hR
         p/Uj4NGD0iddXY/NCkjbf6N0U2HhkUBylXedZGsxU2Fs/puOVfnlXTtPsKgNKIBUMzbh
         P4eFCK8/VarkQqcIqu+JAHPiWxYGIL2YD4IXvAmx1yawnqccISEW/+/1Oga+Kxs8iHev
         gJwlMT2jsKnl65/1VjQ6wJdkqe9KtKi6c7lc93nFc5VX1IJRRBM8DfhUdMQM4QYmWAxa
         s3CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768804923; x=1769409723;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bM3T1BK3BvkQhiZfkMTtBBju0VXlAL/zuUxMEIG+v/0=;
        b=qxpqtUFxQTvJkqqlNp8c6WMTSSnPyDFmnWbHO2w45ll1aKfQ+oqH9Im4W/jHAIKG7U
         sl6/x+V/raXkuddY0IGKHu0RZIjd+A5uS9aMA3fJShKFW5MQ27fhnGbU/P/B8R47/PuO
         4Bf17tSw1DzkhPhSALvPKZBgjPRK3ihPU+4KB0rHXMY/Lrt3LW9fFkyBuA3szejjLoiW
         fv+KYcBYGSHBA4mvKuhRGMg9ehiiVJweqDSSVllkFOAP4IFj2cJT4nWOn19IrwkdC1nZ
         ve4QzY0mXW58+tVwEVkABwrSEL/7XZ2ylLRaK7U0A5a6xgzFDwQHwTWdqOOMo2k7Z3Y3
         ywug==
X-Forwarded-Encrypted: i=3; AJvYcCUWoGCwGpzscXFkUYNIWdx6cuRRl0IM0V4aGPNvRjY87dAr7JEtt1WRDfmzKkS4bbAYP+ukjg==@lfdr.de
X-Gm-Message-State: AOJu0YzNTphRNt5cEQReJjbFIcLSjPfghsGDApKVvLqORjj9+M+Yd9DS
	lKvQoAH+NNo+HgtxPIzaOByZyOqEwP9JYMxeXwagtFPK3WRaBa5kE/eX
X-Received: by 2002:a05:7022:225:b0:121:dea2:d54d with SMTP id a92af1059eb24-1244a71687amr8712430c88.20.1768804923418;
        Sun, 18 Jan 2026 22:42:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fwhb+wZ6biNQdsw7JLdzJQyxxgPtRU5ZgwU4FrOmNU3w=="
Received: by 2002:a05:7022:380c:b0:11b:519:db62 with SMTP id
 a92af1059eb24-1233e2aea99ls3005840c88.2.-pod-prod-01-us; Sun, 18 Jan 2026
 22:42:02 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCW4NXUP/5I46wZHdjgfMlN5wSJvQn/9XDlQkHxQB91WnX7UnXTXZaqeY8OADDGl02WqiI+1NVtyK24=@googlegroups.com
X-Received: by 2002:a05:7300:6ca1:b0:2b0:5079:d3c8 with SMTP id 5a478bee46e88-2b6b3f139f5mr6492104eec.4.1768804921681;
        Sun, 18 Jan 2026 22:42:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768804921; cv=pass;
        d=google.com; s=arc-20240605;
        b=DbzMAHqOcevgsQm1+IiyZomAsWDkty1vISD/rElneMV1qIVylOG7bZ/zH6erBPTp70
         W+3rtJAKeQcdAPbGJw2Ru3XZQBoUe992y/UUYu0KYPGE+Mf9dxvc90PlyadQ5Wy8Z087
         Y8ryzNs+aziG4BL2Iqd1KkLZiz4RKivhqjOlAIsCSohMkeDjV8ndVNaYBKRShfzx8cVx
         mEAgVYF3Q4pvMbkr+D4UkCBlJ85Py37w6oNWAWgEXtKZPxndjxXNp86KWIa24NOdXmDt
         dQ/O6DNRbRtbn3oVll3takE1UFtY0cE2QcMRimQ4mlj1Dq4v041X3BtmmR+u/j9pSQRC
         eItA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=qys+lJv7r3+INwG3kLysHL4NNjlai0WEYBKn2KeAYAc=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=R5i16I+6Xvn9PGdZ2IKazq66mLwI6L6eg469xfhgx5YLLXb1QYhC2EciN2USPyoIlg
         0TyevegTDS+/KBxGkgEBMvYYTIDQ98t9wnsCkx89Bo7gXUnUwaLKq7UMZFpr43KUHITA
         pAzSLzQqaZpHg4N7dvLt8+UowqB10HOvXQrquDj0Cy7y5fVv8ZRMk5DdynojDzRaHcHH
         knnb3NxyFPUqhFbwA4Q/U9R/ZDhgaAH6NrfVelDV/LlvKLZQeeSfkVjOBPypceZGtqFT
         O1tCnIOh9YS2o9SxIZpkeEFXLsJdHPDdXZLgkoJxJAcdIZXyVqGwoi+/G135zUoDn/r3
         JOEg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lr8OcrMX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=XPUvWeSn;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2b6b336b868si341210eec.0.2026.01.18.22.42.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Jan 2026 22:42:01 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60J1cHr2116105;
	Mon, 19 Jan 2026 06:41:57 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br2ypsq1y-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 06:41:57 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60J51fto032836;
	Mon, 19 Jan 2026 06:41:56 GMT
Received: from byapr05cu005.outbound.protection.outlook.com (mail-westusazon11010066.outbound.protection.outlook.com [52.101.85.66])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vbrmyw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 06:41:55 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=X8uhl/U9MawagiGmG9JDhJ0/EE98ges6y9TSXxZIf+5+PfvyhrEUC2b1MHkJVgh5cQOULrhnTcAc3qCDvyMQgdaorsvoGGph5gSuWkAURLqozcH2LWkAyUqzf5OMR4m6XWTwRm/0QFzaNUVrbJwasW7gmUGbwYNiXpmgvfBNiI6h5xTXRNHYgoEibnk2AR+BYKZtS56XrRMf7NIoPoa98QSZVVEPY0wN7ymzccUsAGD2W032ybkMpnGzZw6LXb8QUOlDbCdPS7OiDhbygD/m5b6D1Y9yDisZQMIbt9EB/ijl6kw+XOad+frGiWem1gNmK+zPaXgiwXoTGu7pEuzFLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qys+lJv7r3+INwG3kLysHL4NNjlai0WEYBKn2KeAYAc=;
 b=aYlw5mHEysRmj1WzSdMpQULdx0LOfGa2Orw+WoC0Vf34+xVUWvPCpEhou2dgFJsC4E78CICayHxL6y5COtGMlqc8RtC7LHrUqfSa9HRlhtoglljtHbfgquHHrf78oXbRcIDDwIk1lv/n71LUWva68PVg1b5bI4TQ/whR7UHqd7ozdAZHoa+6KanpvdSWfZgS+w6FvdJW5HPnJw+3Ky+N9jDVK/nKcF6V/YEIjOXva1O9LI/39agTX2uTAzcK7Er2ze3fcTcqqZQcwULO5/uY60nCB2qqq7+5wkdwYHq6w/ezdd2zCUOA5QS3RrIFimsBGmSPQDuPk+GeniQ2/Ngm1A==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by PH0PR10MB5580.namprd10.prod.outlook.com (2603:10b6:510:ff::7) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.11; Mon, 19 Jan
 2026 06:41:50 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.010; Mon, 19 Jan 2026
 06:41:50 +0000
Date: Mon, 19 Jan 2026 15:41:40 +0900
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
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
Message-ID: <aW3SJBR1BcDor-ya@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
X-ClientProxiedBy: SL2PR01CA0006.apcprd01.prod.exchangelabs.com
 (2603:1096:100:41::18) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|PH0PR10MB5580:EE_
X-MS-Office365-Filtering-Correlation-Id: b3f6581b-48e9-4c8c-2dad-08de5725d327
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?aCGvQgb6EpmbsvoDD63Chf4WIc22XHGH6Wcl5IG55lA1YpZf0q3MJ4Hz1Kp2?=
 =?us-ascii?Q?FbzHpvzTGW0P2DIVUmRj94wTPdSWxaUmDEJMokTtQbBmeD182oUlBwVaNeVX?=
 =?us-ascii?Q?KXwdK5nO6/D8oLnMqLXiRk+6n2QYgO0/KafzSptIqL+Cs9YZI9YCCy3RAtsx?=
 =?us-ascii?Q?L8i9tQE5LyFIP7IRZ3ox8CgSmGDrtcXjMx4zp7yNiNI79LjU6oZXLKWPksbf?=
 =?us-ascii?Q?jyP+myvsi+M1GFrnkBuET34lGr5C23b5FvNR8TohSMWMV5e08Fe7gAfL1zEI?=
 =?us-ascii?Q?lPco+XmPuA6sNxlSNQXPoeMS2kxApHxqxhviLsMLO0PeI7vxdGxPRbrhH7Ul?=
 =?us-ascii?Q?yNyer8CiCJSNrnD8cRTlD913qtYgdw9cmzjM8AKczbm+/ANQ/0LAMgLnD7vj?=
 =?us-ascii?Q?c71NpLZXoTRweuAcvk4ZR2JgZhwhVAL8X1F3bJKIdBzPOefLZ0gCq/vu829n?=
 =?us-ascii?Q?NI5ps4tEvhpJ4c2ksYt5b71FxXf1ML3ozXRnBvQKVoY2/WGL0PhFMTJX6fyE?=
 =?us-ascii?Q?3lURkwx41/Hyio52T7bKNxgbFX3+eTeAfQ7pJGFsAMJKYkKI4METC62aw77n?=
 =?us-ascii?Q?A77taBtEc8J2mo0AyEq0ddaoIzVt4028N/yf6GEVPe1aL9ZPOnNAUN5lDeC6?=
 =?us-ascii?Q?PKZBY2UK0WSgS5aRVA3ub2X9AiH33JXaasnIwcG5ngj6lE03xX0dBXcosz1m?=
 =?us-ascii?Q?rgFUytxR4X6eA7i31hv2DgvZl/D153BojEaR/yuXiSAxn/AueYS74AvwJVii?=
 =?us-ascii?Q?lX9JYlcmGMYmJcL/1OmDz5FfjZjTlMAbrW6L9EoE4j5FThj37z7UdP5GiWRp?=
 =?us-ascii?Q?t7aGOpwxMg/KvG1DrmLovK3ooq7Rt36RQIds8OEoM9cn6hiJzXM7lgNNWwqL?=
 =?us-ascii?Q?8/bOgkwcuoKRA+Tn90orzNx0pEWbZz7LoyHqUZ0HwG4J56VrcA1EmNgmYq6H?=
 =?us-ascii?Q?KBnfdIKs44cIDNTYaCcpI1x2ndxN3gZtaUGGG3yQx3ZROLyq2TDSRp2T2XPL?=
 =?us-ascii?Q?T2sU4qX4UvqGrR0Wm5NEEiaLifkemG41WwxuzVHyERJqwqvl+jcKDG7GpAEK?=
 =?us-ascii?Q?KH/QQ0/QmUFsRjBTNwWXPLeniLDdXeOL0qCfzJvHSTFogvnrgGz+KpUvj0IO?=
 =?us-ascii?Q?OiRiirh9rx12YH0pM3OQYlgFWfV0VJn8lGPRTWOjdgD6WmCkjxncexG3Rpid?=
 =?us-ascii?Q?rxYgFzpv8oJUaQmHVzWuGshrLatGaZQgYuX/qAvoRVUGgdYv69QN/rx++2ud?=
 =?us-ascii?Q?//xMXmZ0DJBbonzMchtWBuE0MoqOHpIzyO/g7Xe7SyZtQSS2LvOxnhg3BZiN?=
 =?us-ascii?Q?ELV/YTvSLvyO1DTuRDQ3P4AnDRxScSIBaAPQUhEzseHouBwTQiJtETmTKJZf?=
 =?us-ascii?Q?IgBh038WzrAvUzjizxCk3Y6LXy+rqjEWUJI0OnVPQx0Lzq72Z8Oq98xTh4PU?=
 =?us-ascii?Q?Qpq9magpFVtVfv0j4YwOfTLxSJzzfKlDAkk6ShDPDgQAdFjC4Sw+CbK/vStp?=
 =?us-ascii?Q?f/LVTabpfMcR9CX7u/Ye9mjWvjhxB0fPV79HJm0OTk9EP/JSKJl06pTb1SU3?=
 =?us-ascii?Q?uNxwoh2w0f7kFw0YyN4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?m6UCOBNRkq7/8Tt3pXD51+qzpEOm8lXc4N8eZw497nTjJfJaU1jgUDWWS3We?=
 =?us-ascii?Q?4LoquWMna44il4U1mzOAHuGD2aP1zmqzR9bs2639/4Oa1BIndRsA0eHV4gyp?=
 =?us-ascii?Q?VZohrXJG5g5RtAWogW1dNgXohXJ8cQpfeHoNwLyl8CzN/2X4SK37lGziXWVW?=
 =?us-ascii?Q?Kc0QNMX4xpm1KurZDOe31BnH10Q0nUuE0AzlGHOVej2gXbOouDijbOOgMyn+?=
 =?us-ascii?Q?Yt3KbMlKpScaqgev1+/QAK6aXm6vxphOcs5genydXRFPy7siyVZQvvcyIsIa?=
 =?us-ascii?Q?Wc7rmmC8gcFF2mKNc1kSY0BoMfVK9i/QOJN2z4+6PGkan/7QIOuUdm9AxZVi?=
 =?us-ascii?Q?KPM75ggaobmVJZ8ulAe31C00qIJc0X3lYnTWVZhewAFeJ1P3Mmo3liHhhvLv?=
 =?us-ascii?Q?38mN11PJk6F/FL0y+EXfQLMDlgq9w7Pzb6rt4bE917H1CLYknZWgMl7nM1qG?=
 =?us-ascii?Q?TV3ptvsoK9U2k1kS6W/hKV4IFmAyPiegQIbaAlBqjHATl5tA9CHs+vPxejiB?=
 =?us-ascii?Q?VvO/6u7nezbwe5gq73uYQcpmbTxneTB6K8c/AeSuQWveP/FPz2eQRfcPRgH7?=
 =?us-ascii?Q?zkFn+2KkQQpLSLw1OR2ZB8Rv6msQsP/lKV9WQy1aYho/wVcrYKPGTxYhFZ5a?=
 =?us-ascii?Q?460pLbHxLGVfViW/gfu/QiZ6dDPWC3nvkjj716FC2Cc5L4CQ6wCxop7TckLn?=
 =?us-ascii?Q?X/iaQpMFdGxSUjiX1m7Hd5swjBopQcvWgE8MhoH5iHQO690MCJK59yM6mzBD?=
 =?us-ascii?Q?+RLSgDqxk4G/p4B6xPmR+EwhzaquSha4SFDgLOw4vVmxFRTCBPGtDyyTihnF?=
 =?us-ascii?Q?vf72CoLZ0fIVB7d6XQ1dOvymTitD4Y5Ycu6H8LmVcc93B7SXpg8eWjO0degD?=
 =?us-ascii?Q?MH9nIGrDGlf93Xj+qwtcsl/LTPhs0cDPJAd9IgTJ6/zlRwM9jreosI7Y1fvq?=
 =?us-ascii?Q?wysqeV84tcXu5DcFoFVRhfu/lY9I+izXDQvXDU0KIYcpdYRyA6OvjJ9r2xbB?=
 =?us-ascii?Q?wiwHg4k688Cp9ENIE9ywPz8WNXfpNFGFnip/HPBKyAnwRGnABxfnr+lVJ0AT?=
 =?us-ascii?Q?d+2S3NnT0uPXicfvEqZ90AaX86icPWS+jG/53iLnhLiiGRcQC/W90Z/HGWsT?=
 =?us-ascii?Q?5t7XKSiErnzkMNp2EIlK5ukI5yJ/N21YQhlLZt2exMvqW3zQsNG+CArlSRYq?=
 =?us-ascii?Q?92hA/5zzWBZocolXqJyNO2E2+99tpxZKClSlvnNJlSxUrPM9vxNEqVn1h1uV?=
 =?us-ascii?Q?TWMu5Bp/FgVXEmKNiynp5iBEaempln+4TPPuX9MKiNph6BTlGGf6Bbsp3Xzk?=
 =?us-ascii?Q?sEBXBw3mhsb4CTe7hV4uKY/aRvMXrCcecX/LBu6EffztgD+MNmV4fvxWwfr8?=
 =?us-ascii?Q?ZiSNkYbTtRwb6NKTw7qy39bNXjW9FBYw7tJRW+aaR1mqrUKHfTobPD6/v3bJ?=
 =?us-ascii?Q?U9Fw2hL/yII1QNqrdAZwsA3VT89SsLJWiHXENiNMrxbMqhJSbsjzdCcAqWT8?=
 =?us-ascii?Q?76k/vj9CqixKBVvcySxBk8BaHBfIqfyblacM6zUvHP9PoxljbapWIy9KEXy8?=
 =?us-ascii?Q?TWb/WoxX35EJf3CVGx2UZFB2/KQLsjDM66RD9fWYehsaL2t3vHKDafbdAekx?=
 =?us-ascii?Q?zHmYNDvQ5e9pjIhfekO9AVgRbBllXq2PWx6LRmnXCmjL/cIVXRefPxlzobdc?=
 =?us-ascii?Q?G8jIkLPWE2zooUGdOzNOcUckzCIhWMvBQnTb43+eKSVDEYTuMbKWpGVr7OFb?=
 =?us-ascii?Q?mVd/307lzQ=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: V2oKc6UW0ucQBaNkVSQT1o7JZlXCnzaypa8z+xgVL0cweP1UJBRirCA2rtkppaS9k9dF5Dz9EHsqC9/oVVf3oLYnqZHAHCEkR20g+y86eH/Icqz3TG8HVzo6IMlU5jA4Z35KOEK7/IRlSNqAtmj00vHGFlIHWOFL5RXpe8BuCoVr1UsasSQkSbMmllQI8DOKrud8CM3eF+afpgpGGKboflc9RQXt4nJKC8iA6CK5UZypR/luj0gpBLZd9uayaC2XUqfG3VrldArzDNMcyzuxKFH1WT1I+Ju0lbtKYh2i6/Oja0OMV1UaEgmWnysvuj5bERY67/bUdTGej/Ifsb4PlxbI+m9hoVeDEX5KQWuyYTZ6pHMrxV8rFHE7mYl+VEwq2IDmDptR6Y99pQC4nyTHOXPKiuEWeGIXxCLoCtVNJq6QfL34opJpNfZhLiM3YGhRozjKJ8ClR4L30fAuqNx79HlJ6EOTPiLN89MjKITtmgH94aa8hL5fc3dhAOycA5Essd+od+qpqLQ2KNPQsZFU6fsEx+8eQWMPyP7bn67cAj80bGRLHlAr0I7Zb59sa8lVEAUX5XgO5L/F0aO2LylVNI1QW42GklfvWtEVjo+fCZ0=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b3f6581b-48e9-4c8c-2dad-08de5725d327
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Jan 2026 06:41:50.4389
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: EO7d+9Gbfy5CJ3E1e2JTOT1NQuLyphLywjcudPPXuJwnnPx+Kd7x5JxnHhhwY8s2ON44d0qutSJLPZ/O79jGPw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PH0PR10MB5580
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-19_01,2026-01-19_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 bulkscore=0 adultscore=0
 spamscore=0 phishscore=0 mlxscore=0 mlxlogscore=999 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601190053
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE5MDA1NCBTYWx0ZWRfXxBB8U81HQHRK
 tu8jP6y1MoVygYcD6mujwsybAacV9d+n59x7yny0SsCDFnMDC/XZmNq+fLcKRC1rdgZ4u44aXRn
 bytN3f/vghIQiKP3/Nq20jp85KurFMrTC3t5m0mHgoWkycSzNB5MzUPYigpGn6c/hybBqRzJPrY
 adIh+PDpzlOw8pagjAGBWnpt01G1w4mwUb+GP1AS7l4z2rkoCpVqyHUBR0UrXUX8DSdUP/6AEhp
 vIdVAnyWwuawP3HV1vMMYp+GWLMgNIH3E4Pmx8uoaVwUuSt73qhq5gZJINR+YpY8zFKawVYOnqV
 DumPYUvo4gNcmbvQlSoRvm+vUOCXjFDfpJhIDx5TxQZ39rA4bEt128L4R1tX0fGsxDjGdHbP4cu
 QoH+S0NleqqtuZTDSvmBPVqhjM5yMccK4ZYIRqxBUBO4GtngmfUs/uRKQ5njc4n9+FscFQAoSEJ
 GJjGsSpjFdufMgFRYCNgnGORLOplphg4XQ+VTCS8=
X-Authority-Analysis: v=2.4 cv=de6NHHXe c=1 sm=1 tr=0 ts=696dd235 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=rNssqR8MEun7ibg-cOIA:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:13654
X-Proofpoint-ORIG-GUID: ioUXTpB2R86zeJ_kpBU3H3-7bp6yiiM3
X-Proofpoint-GUID: ioUXTpB2R86zeJ_kpBU3H3-7bp6yiiM3
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Lr8OcrMX;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=XPUvWeSn;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Jan 16, 2026 at 03:40:29PM +0100, Vlastimil Babka wrote:
> At this point we have sheaves enabled for all caches, but their refill
> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
> slabs - now a redundant caching layer that we are about to remove.
> 
> The refill will thus be done from slabs on the node partial list.
> Introduce new functions that can do that in an optimized way as it's
> easier than modifying the __kmem_cache_alloc_bulk() call chain.
> 
> Extend struct partial_context so it can return a list of slabs from the
> partial list with the sum of free objects in them within the requested
> min and max.
> 
> Introduce get_partial_node_bulk() that removes the slabs from freelist
> and returns them in the list.
> 
> Introduce get_freelist_nofreeze() which grabs the freelist without
> freezing the slab.
> 
> Introduce alloc_from_new_slab() which can allocate multiple objects from
> a newly allocated slab where we don't need to synchronize with freeing.
> In some aspects it's similar to alloc_single_from_new_slab() but assumes
> the cache is a non-debug one so it can avoid some actions.
> 
> Introduce __refill_objects() that uses the functions above to fill an
> array of objects. It has to handle the possibility that the slabs will
> contain more objects that were requested, due to concurrent freeing of
> objects to those slabs. When no more slabs on partial lists are
> available, it will allocate new slabs. It is intended to be only used
> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
> 
> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
> only refilled from contexts that allow spinning, or even blocking.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 284 +++++++++++++++++++++++++++++++++++++++++++++++++++++++++-----
>  1 file changed, 264 insertions(+), 20 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 9bea8a65e510..dce80463f92c 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3522,6 +3525,63 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
>  #endif
>  static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
>  
> +static bool get_partial_node_bulk(struct kmem_cache *s,
> +				  struct kmem_cache_node *n,
> +				  struct partial_context *pc)
> +{
> +	struct slab *slab, *slab2;
> +	unsigned int total_free = 0;
> +	unsigned long flags;
> +
> +	/* Racy check to avoid taking the lock unnecessarily. */
> +	if (!n || data_race(!n->nr_partial))
> +		return false;
> +
> +	INIT_LIST_HEAD(&pc->slabs);
> +
> +	spin_lock_irqsave(&n->list_lock, flags);
> +
> +	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
> +		struct freelist_counters flc;
> +		unsigned int slab_free;
> +
> +		if (!pfmemalloc_match(slab, pc->flags))
> +			continue;
> +		/*
> +		 * determine the number of free objects in the slab racily
> +		 *
> +		 * due to atomic updates done by a racing free we should not
> +		 * read an inconsistent value here, but do a sanity check anyway
> +		 *
> +		 * slab_free is a lower bound due to subsequent concurrent
> +		 * freeing, the caller might get more objects than requested and
> +		 * must deal with it
> +		 */
> +		flc.counters = data_race(READ_ONCE(slab->counters));
> +		slab_free = flc.objects - flc.inuse;
> +
> +		if (unlikely(slab_free > oo_objects(s->oo)))
> +			continue;

When is this condition supposed to be true?

I guess it's when __update_freelist_slow() doesn't update
slab->counters atomically?

> +
> +		/* we have already min and this would get us over the max */
> +		if (total_free >= pc->min_objects
> +		    && total_free + slab_free > pc->max_objects)
> +			break;
> +
> +		remove_partial(n, slab);
> +
> +		list_add(&slab->slab_list, &pc->slabs);
> +
> +		total_free += slab_free;
> +		if (total_free >= pc->max_objects)
> +			break;
> +	}
> +
> +	spin_unlock_irqrestore(&n->list_lock, flags);
> +	return total_free > 0;
> +}
> +
>  /*
>   * Try to allocate a partial slab from a specific node.
>   */
> +static unsigned int alloc_from_new_slab(struct kmem_cache *s, struct slab *slab,
> +		void **p, unsigned int count, bool allow_spin)
> +{
> +	unsigned int allocated = 0;
> +	struct kmem_cache_node *n;
> +	unsigned long flags;
> +	void *object;
> +
> +	if (!allow_spin && (slab->objects - slab->inuse) > count) {
> +
> +		n = get_node(s, slab_nid(slab));
> +
> +		if (!spin_trylock_irqsave(&n->list_lock, flags)) {
> +			/* Unlucky, discard newly allocated slab */
> +			defer_deactivate_slab(slab, NULL);
> +			return 0;
> +		}
> +	}
> +
> +	object = slab->freelist;
> +	while (object && allocated < count) {
> +		p[allocated] = object;
> +		object = get_freepointer(s, object);
> +		maybe_wipe_obj_freeptr(s, p[allocated]);
> +
> +		slab->inuse++;
> +		allocated++;
> +	}
> +	slab->freelist = object;
> +
> +	if (slab->freelist) {
> +
> +		if (allow_spin) {
> +			n = get_node(s, slab_nid(slab));
> +			spin_lock_irqsave(&n->list_lock, flags);
> +		}
> +		add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +		spin_unlock_irqrestore(&n->list_lock, flags);
> +	}
> +
> +	inc_slabs_node(s, slab_nid(slab), slab->objects);

Maybe add a comment explaining why inc_slabs_node() doesn't need to be
called under n->list_lock?

> +	return allocated;
> +}
> +
>  /*
>   * Slow path. The lockless freelist is empty or we need to perform
>   * debugging duties.
> @@ -5388,6 +5519,9 @@ static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
>  	return ret;
>  }
>  
> +static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
> +				   size_t size, void **p);
> +
>  /*
>   * returns a sheaf that has at least the requested size
>   * when prefilling is needed, do so with given gfp flags
> @@ -7463,6 +7597,116 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>  }
>  EXPORT_SYMBOL(kmem_cache_free_bulk);
>  
> +static unsigned int
> +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
> +		 unsigned int max)
> +{
> +	struct slab *slab, *slab2;
> +	struct partial_context pc;
> +	unsigned int refilled = 0;
> +	unsigned long flags;
> +	void *object;
> +	int node;
> +
> +	pc.flags = gfp;
> +	pc.min_objects = min;
> +	pc.max_objects = max;
> +
> +	node = numa_mem_id();
> +
> +	if (WARN_ON_ONCE(!gfpflags_allow_spinning(gfp)))
> +		return 0;
> +
> +	/* TODO: consider also other nodes? */
> +	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
> +		goto new_slab;
> +
> +	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +		list_del(&slab->slab_list);

When a slab is removed from the list,

> +		object = get_freelist_nofreeze(s, slab);
> +
> +		while (object && refilled < max) {
> +			p[refilled] = object;
> +			object = get_freepointer(s, object);
> +			maybe_wipe_obj_freeptr(s, p[refilled]);
> +
> +			refilled++;
> +		}
> +
> +		/*
> +		 * Freelist had more objects than we can accommodate, we need to
> +		 * free them back. We can treat it like a detached freelist, just
> +		 * need to find the tail object.
> +		 */
> +		if (unlikely(object)) {

And the freelist had more objects than requested,

> +			void *head = object;
> +			void *tail;
> +			int cnt = 0;
> +
> +			do {
> +				tail = object;
> +				cnt++;
> +				object = get_freepointer(s, object);
> +			} while (object);
> +			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);

objects are freed to the slab but the slab may or may not be added back to
n->partial?

> +		}
> +
> +		if (refilled >= max)
> +			break;
> +	}
> +
> +	if (unlikely(!list_empty(&pc.slabs))) {
> +		struct kmem_cache_node *n = get_node(s, node);
> +
> +		spin_lock_irqsave(&n->list_lock, flags);
> +
> +		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +			if (unlikely(!slab->inuse && n->nr_partial >= s->min_partial))
> +				continue;
> +
> +			list_del(&slab->slab_list);
> +			add_partial(n, slab, DEACTIVATE_TO_HEAD);
> +		}
> +
> +		spin_unlock_irqrestore(&n->list_lock, flags);
> +
> +		/* any slabs left are completely free and for discard */
> +		list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
> +
> +			list_del(&slab->slab_list);
> +			discard_slab(s, slab);
> +		}
> +	}
> +
> +
> +	if (likely(refilled >= min))
> +		goto out;
> +
> +new_slab:
> +
> +	slab = new_slab(s, pc.flags, node);
> +	if (!slab)
> +		goto out;
> +
> +	stat(s, ALLOC_SLAB);
> +
> +	/*
> +	 * TODO: possible optimization - if we know we will consume the whole
> +	 * slab we might skip creating the freelist?
> +	 */
> +	refilled += alloc_from_new_slab(s, slab, p + refilled, max - refilled,
> +					/* allow_spin = */ true);
> +
> +	if (refilled < min)
> +		goto new_slab;

It should jump to out: label when alloc_from_new_slab() returns zero
(trylock failed).

...Oh wait, no. I was confused.

Why does alloc_from_new_slab() handle !allow_spin case when it cannot be
called if allow_spin is false?

> +out:
> +
> +	return refilled;
> +}

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW3SJBR1BcDor-ya%40hyeyoo.
