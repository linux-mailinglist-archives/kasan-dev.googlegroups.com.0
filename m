Return-Path: <kasan-dev+bncBCYIJU5JTINRBLHP4PFQMGQELAM4UGA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6J2qEK/3eGnYuAEAu9opvQ
	(envelope-from <kasan-dev+bncBCYIJU5JTINRBLHP4PFQMGQELAM4UGA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 18:36:47 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dl1-x123d.google.com (mail-dl1-x123d.google.com [IPv6:2607:f8b0:4864:20::123d])
	by mail.lfdr.de (Postfix) with ESMTPS id A9F5C98829
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 18:36:46 +0100 (CET)
Received: by mail-dl1-x123d.google.com with SMTP id a92af1059eb24-11b94abc09dsf8799969c88.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 09:36:46 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769535404; cv=pass;
        d=google.com; s=arc-20240605;
        b=lL6hQi7BIL7Tpe5ZJF/oU1R4mBkL9vC2ji3WYAMrSVOIAncfnzzjYELgBLo6PwjcSf
         clSxRnQCxJpDxG5zndtMS/5c8J7msEwJbPargPJLySKvUQjhntav+w94t57xUtVQE6sx
         9Lc+TMjJtOM7ZvVSueCw9j3CM9YC7euUF2dxAdNk6sDfvXTRyHY8NG2kL1UFW9y4lft6
         hvqrTIysim9qp3W2DFy9/UnzkE+rc+X4TBB22yyO0wP5ix5LGIywzsKoZ9OrT5Cex+uo
         Cl8wkPBb7DHIJsrguaIPGyQvt5NW+q2SlJUfh7KsQ59Wy5XPJcpJCErsw0yvmFdgwiWz
         cS6A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uI7kwuCXZNCP0IFbBn/YUCrG5RwzrmzQ1wp0e3NnzFE=;
        fh=ZTjAZoPBfwov6d9SYiZhxTvBoMIV17eOtka9UzZifUo=;
        b=EaYfGWtxQB5clor04ChBydXtMIohECtPpeB6yzXxRGzkX4rownDnVagkGNXWXPoBp8
         V8Qicmbo+6O+54BH9UfhP5VTXzXh9r7/hAuc/npGfu+AHVjSaPuVhT67BzLWk6jPhbiu
         lV2YEN6IogT/D+5f5Ql3SwgTWNBF8YYtKHmLvxAsuv8QEcNZMf4Ma04gDiZD+/JeQhN9
         fjqoEfl9S2BR/iIZ4N4uldnU1JueIpCYz0AH56duAFC32dndepXIQnXWAx68oSejHT4n
         JGbGBZpD7JmAFBJnCCDH5VDmwGSGHOsIdNK5dcbU4LNulfBfXvk7CYSmMiy5wweZbS3d
         PU3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gLcb6f7Y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=fn+HKgow;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769535404; x=1770140204; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uI7kwuCXZNCP0IFbBn/YUCrG5RwzrmzQ1wp0e3NnzFE=;
        b=eed0sJWfMaoHp8J1G76txAnQW7iUo7RvnlnBVMaYG8/TtDSlANFtTFde8L8QOqnIyg
         kEou+fKhcC5VHbWvH8mj/L+FH5MgrKc24zBSzE/01Obr/kxt1EcVmbjdSTE06wV9CLaz
         /mfy28SynGGlj8POKuF6ymkGjX76lHaXeINsrzoyjJXd4kkPm/ky0Hbfzh31cEdqzy0f
         34ZH8mZtOP5BMyX5FyNbldSTzJHzS6T0DjatBTAY1WIGeCcWUi0hwNpaSd5tf4PkE3pS
         8uDhJIbSS5tfV9NecT3RLU063KaYS6Do3tj5VgMLONpp7F2ZAt2MeiCkqXYa5Blz8fHi
         pUog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769535404; x=1770140204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=uI7kwuCXZNCP0IFbBn/YUCrG5RwzrmzQ1wp0e3NnzFE=;
        b=mGgLpuC8DTcavf7CQnq1zY+ExNLVoIYMclEc8utK2ZuE0VQ3/K83nQ+DmbnE0OJOUp
         R4PKutkZj4Xo+c4aDOwTIk/zcQoYRl8s2WAiWDrO8tlBAB79Jl2ZaNcBWbRtCWcYboJy
         fpY3bhtELnFFXXzAKBu/WcuVHBXTMfXjyaTgkiqW5GeqPQa68KES7iqpKl6TbpV0Cedq
         AXytaO5pJ9p7FUdjGckAFJTRQMs9UHcIs8HzFwmgh9+HSiRBrVrBG3W+sSe3YjDWw0tS
         PdBUKfOVdZkQxIT9DK+MmOeNPz1/UbjCDh07m4TcHTQeSLzyYIOL/k9NGxze6fgUqrFE
         LXGw==
X-Forwarded-Encrypted: i=3; AJvYcCXPNfOrhWVRXQki2Vgt4lkM6AOOj1my9Kkg+k+tEWuqY9uWVKs2JvqVmwRuCaXfEEsnSzn8sA==@lfdr.de
X-Gm-Message-State: AOJu0Yx38VwMnk4nhdsaMyv+RS/EIlsgsBXkmleGzNcWijy+DDYxonwR
	SbIOWbXFCH4/As7qs4e3krPf1NgZZZU/e79UywJM+IBMBmNF+YSytiRk
X-Received: by 2002:a05:7022:51f:b0:11b:d561:bc10 with SMTP id a92af1059eb24-124a00d5cf6mr1557052c88.41.1769535404512;
        Tue, 27 Jan 2026 09:36:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HeoTp53TRN8WTsWzNHdZ7wsSuBzDmAScblLRWgCFW3rA=="
Received: by 2002:a05:701b:4188:20b0:123:3985:df67 with SMTP id
 a92af1059eb24-12476d1bf33ls2570590c88.2.-pod-prod-03-us; Tue, 27 Jan 2026
 09:36:43 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWs2wJskqtgcpvtBApmbDduM6cWrm5pO34uNVrrrbfWUZ4m6pLEhuORa92XPEyfbfciYqUarSfbsqU=@googlegroups.com
X-Received: by 2002:a05:7022:1099:b0:123:3488:89a3 with SMTP id a92af1059eb24-124a00bd734mr1179482c88.24.1769535402783;
        Tue, 27 Jan 2026 09:36:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769535402; cv=pass;
        d=google.com; s=arc-20240605;
        b=hN4SfDLRftqG2FLI42JkuPVX24FAgxMueefe5m0z4cgg5pNa7eExAoq39OuyABd7PW
         EH6LAyAyW4M4A4HTcmtt+ZJhAVEbEkR2F280nxE8FgbLiRMaaGUUYxMgcuNu8whzRFA/
         N8WpLCtzD/XqaoRxJswPZkWgTm8BvWbgtaPSsXr+acnC6NPiwfNapHaeTDAII4zwfDzR
         PLvsPXqZMc+4tWo/ETSIa36wb6v2G182drhJj55MN1oGR4dc1RCjPKknOXSwtpi8Lbq2
         P1EySnB1V4l7rNZX9iBBndnwYZ+7TusFVD/rNYvIVQAFbNHWKUjD3mJnP1kZvb0Dx3bR
         dcQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=QXir7zTRJqvrWYhRE8iA37qejfvxY08rtLYP5bXEggg=;
        fh=EGMhLkV3udorsQux7n/+Xk9u7IyRbMe92LwjbXHNLfE=;
        b=kTVhr8/7MrU9biUNMY+Fiz/aMdsliEtc/SFFm/B2pQGmRb3f+QzvoZfCyGMeGiORHC
         fi99EcGCMQtcQpApLeylc5h3YzGGgfZs297IydDrTVwovs/dBiMBIAwYe6BH7vysQm3k
         y2qv+Ls0l0zfZSWIeJQGXEHQRdYw8fYgBlYcU0gd43DGqNN9XyjGLIRuRrIDyEvsWAeM
         j0h+j7VNZQMM00cmleIDGMzjPlFEG1bX3ueTzpskyfQeCPR2vnzsgIpY/T/E2TCrUzjM
         goCp4BDaAzFuCtc/GP8ErDC4QHN0AooWlMT0HeKXSG1TwuX+PDFf/26PyumEaAgxiU2v
         vLyA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=gLcb6f7Y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=fn+HKgow;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id a92af1059eb24-124a7caab6esi8160c88.3.2026.01.27.09.36.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 09:36:42 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60RBEI2N3713709;
	Tue, 27 Jan 2026 17:36:38 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bvny6vep5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 17:36:38 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60RGgSfL001851;
	Tue, 27 Jan 2026 17:36:37 GMT
Received: from dm5pr21cu001.outbound.protection.outlook.com (mail-centralusazon11011039.outbound.protection.outlook.com [52.101.62.39])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhe9gk5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 17:36:37 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=S77agDwp+DRoGC8l9wT7sX0fx8PmF4W/MHgURvfiQIyIep+Uq16/4AZlNAxfIg7Ihfol9lJ7GZZBSY/RFeHJFgZunwK5PqMI6WYkr/hMW3zuyTg83B/dlrxbWoji3Ss1of2Lsr3gKOmMWErNavcNTzWqYDaxMGt6WRZn3ftKmwHJumwz32kz6PBQYvwlw0g3ii7WsWZioHnzJWJ8hJ3nDRxIP7u7WcW6x60/g6tHfU0mtLo5vwYliQBTx6/mDjmbe9VzyOA7FEXi8ZPsNqZFP7HduentnM1PxzorpZS/p9Gr2fwaeafP9KBJJD8cmKBnvqkUiKjQiiqdFWdYN6l/Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=QXir7zTRJqvrWYhRE8iA37qejfvxY08rtLYP5bXEggg=;
 b=NS07vV3pp/4nfYj6//sNzx5kr/V/uk/8P7TrpuSpdkRuy+oRvo2VCPEt9w5Hn7y7uM5Ykej+9D/q5P9arspN2LGRTYwlBJdkp8Cs4/J/VJW5rpVj1tKvZ+aDSgSLUv2wusTy4SiWqKafetwwe2FlbdwLNzHUaINH3vXNI1xP1O1sa8P381q/G3tSSRWCkK8i2j1RS+LMPb9XNWk3i9pt9rsq+LDvlIgwoQR1KaPmipmc4f1WXfJknNkGEtZRSgxHKbVx8DJ0DyKFbDyyQQV8d06bN3hccK19HRzXB2ciVZPNKEZc7R2pDikPncKKO8Q0QdLXdDsVwfYzyozmS0mUzA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by DM6PR10MB4219.namprd10.prod.outlook.com (2603:10b6:5:216::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.15; Tue, 27 Jan
 2026 17:36:34 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce%4]) with mapi id 15.20.9542.015; Tue, 27 Jan 2026
 17:36:34 +0000
Date: Tue, 27 Jan 2026 12:36:21 -0500
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
        bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 08/22] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Message-ID: <7dk5q3mbusqlklpk3ja57upbhkhhg3bpueh4nemuthesmwpgnk@zkk4fqug3cwx>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Harry Yoo <harry.yoo@oracle.com>, 
	Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-8-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-8-041323d506f7@suse.cz>
User-Agent: NeoMutt/20250905
X-ClientProxiedBy: YT4P288CA0090.CANP288.PROD.OUTLOOK.COM
 (2603:10b6:b01:d0::23) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|DM6PR10MB4219:EE_
X-MS-Office365-Filtering-Correlation-Id: dd2acba0-0ea2-47de-7ae6-08de5dca9d71
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?SQOADRwydAMTzY5/SBq0dpXRIXHvE1Rx1erGe8RqDWFttNZtiazSXHzc1lHU?=
 =?us-ascii?Q?AZYJmJY/c+oiMei4ErZ6Se0eGZk0Xwi64AbMEREkQEm8QoQkG7Zu8ONvABRK?=
 =?us-ascii?Q?LTHbIhn4+zSVI17erEpOolnJW8he2oOQrKIK7jfTNMOqIu4s16De64/e+BMV?=
 =?us-ascii?Q?xrWHdCB1mRkF+ZbWIrRiSZZ4XfaCV0J/KyqYamlacQZB8TIdF9BFaz8/V+R7?=
 =?us-ascii?Q?HM3LNMqMK5voQnQtus9I/7INEawJUy3TZf8qyYdJgibrCyXvY9f188FxiHH1?=
 =?us-ascii?Q?wLzAeucPbELUnpOxhcbI4iMSUjJveSYBGwlQ6mQYCdFCt0LgPgUmIYtjCwBd?=
 =?us-ascii?Q?H2z8tBblZeHHvHVoSlUXoY/sGRCvIXOYnTJ82FSszMKaipWeXPaKjRFj2Ecv?=
 =?us-ascii?Q?TfWtfg0N6tz1T02SAkzc76QNrhtRnGGrW6nDiuG5CvuCMYEsx/NS6+Bcf6C9?=
 =?us-ascii?Q?6OwlDEQ3nQ3ftZJzdXKYvfyjKWLG7fLCxCm+75dBittkSb0jb0QrRbs1J203?=
 =?us-ascii?Q?3mcMFnQjFMIjxZNbncmMEL9XAOzTLPDNUNuCHvIkuhz6OkHWiTdbI+ovf/W7?=
 =?us-ascii?Q?VLabtyaEURt6knvRrTtxbi2BZJWuuNR13u5+V7EvgkCAGmgCkvceV3mHv6pn?=
 =?us-ascii?Q?6MuUZLKT92y9BpvC726No6yTQ5Y367N9VehgIMyT7Y+X1CvliZKqoB0S9Bk5?=
 =?us-ascii?Q?skhVf+EAoRXDBp41z4C5LipdgfVkxfTj6ytEYvZ/M5064yVvyeLRZSt+/46o?=
 =?us-ascii?Q?mdDWmRfkgSdYwluXeClmOcKCGp8OIGMPzZH/Hy6JH9Bm0zsMwK8p0zX7SNF2?=
 =?us-ascii?Q?1tUTAHFZ3fV96NbbDnO0aL++MFBHtUSsd5rtQz135ZTMXX6NaJVl/PpJ7p67?=
 =?us-ascii?Q?GXpYf+S2eKxeQRgERaConfRJL3kgKpu0Q1GT0SUh6AB8gz1RIgkKzeNk4GpL?=
 =?us-ascii?Q?Z9pE/xtjhe4zttRqGlPAuJ4L2Bo5FWNgKAkDN77I+dpeFAqPPB89AIumuoZr?=
 =?us-ascii?Q?UMGAtTpAT6Ojb4aQb3qsEgOHOCdpHY3zOmH5cuMIz9GCPCfGH2BD6mW2O6bb?=
 =?us-ascii?Q?KtCZmvXwLhpb7xcLhnnvtTiCjUciApB/jSZtFM3vEZ5CycTVcpmfRtgEL3OQ?=
 =?us-ascii?Q?oz34Km+suozWC5VEiwSC6nnWNktSe/1shOUzJ1C5D6+9GuyMXPvzZiHdy1iF?=
 =?us-ascii?Q?eyLxNPX7/mbIUz9pgamjN6WvQ8Q1jwpVnYZx80OszfwSD5Avayo2Fcp3pveS?=
 =?us-ascii?Q?TealU+otEL0TBcz/AywTRnXVBzLzSc+EiznfvgnhAKbIs/tQwocZe/UWo8Nm?=
 =?us-ascii?Q?z9OTed+jt5cAjdjPwSwe9nk6uIFAdZ+XpCfr1MXgrO5jI10LYbpWlQp9G5ug?=
 =?us-ascii?Q?qqYFbGSVz3rNCGBK0ncvEvljUFRRoVPZZgUMIYGM4wC56Falk36zMjdV6QyH?=
 =?us-ascii?Q?qjspvuKWrYk1P7xnOpZfxe3VUq4zVJ48henPE1I/GrnVeSOrOGmngMOfQ1yM?=
 =?us-ascii?Q?HTzK/LSuqWmhbN4rr+Si7Qt2Lrj26EgzKRWfj1GkGGszw6tUJ9OWdL6uVhhr?=
 =?us-ascii?Q?UftW4hXTCGZEY/AnuyE=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?WKmBRSFZCBRpEDWIwSB0maBfjpOctulNN5X4/5xPfKsiZkBl2c4Upl3h+sn4?=
 =?us-ascii?Q?rhj0d5hwF5MVzQEybUgKEX30YdVaZLAGh53n7UjuDfA1QXanMjwtO7NbWWTd?=
 =?us-ascii?Q?tavXcxtde+LmowUnYvgIx2llKLi7TTWfwbipJS7zeqgE8Mc1awe9+kmjH+7i?=
 =?us-ascii?Q?oXXqWrYAOGtQcMmqt0/6g2QcqER9p3UREZW0qN7ZcpFNJ9fM05u1qKSdrwiM?=
 =?us-ascii?Q?lK2/3NlOo6AEdNNZz6CyCp8kE/Nxw3JIbacaVwGoXNXeqXW/eHBORf8IH6My?=
 =?us-ascii?Q?V+8m0UtnoKzM2jDDwV92xOhztnVvaVa2j9VfAqEhJwR/DUxjs/A0IWYqYoLF?=
 =?us-ascii?Q?37CH/qly4pgoUobW6pcPptuKmUkxLyA2/tVAwXSZWxXw4xBW/g/NpYLGomMi?=
 =?us-ascii?Q?+qs839gmICYf5s+jnjXpRKHT9Pqky5lBL3HoexiKvu9qb60v3igw3dPLyKMq?=
 =?us-ascii?Q?jWvoPWsPAlCS/sXqSAzQn/Nmjd56ag44LvokQcL1Sl4Vzo++kMK+c2+V9BY9?=
 =?us-ascii?Q?p5Q/TEitWJRYYcADFEkGW3l39lzP5VopGYqmjdl9EMmg7g7gpcK3okShGR1u?=
 =?us-ascii?Q?0u+VL57CAFtwRPynN9so9VSNh8LQ/B3CbnSCml1PMrGeQA84Qf4Rk3doQY/k?=
 =?us-ascii?Q?xCICqhfclzoHWgn+1qxwVXBGZL3SAkgZ/kaq4EvuHlzTVZCGOpuLrKQ3pFty?=
 =?us-ascii?Q?NQ7brSJCInk01/nlkdquZx68Ki6No5feFZDVNjG+DEmqA1uJcF0zv34Ykw1T?=
 =?us-ascii?Q?JZ5sNeIuv4jAZpdwBhDo7H96OR9g4DWuRCQ5YWucrdnHLy58QgHerRYRVIB9?=
 =?us-ascii?Q?tvAmtHWT93IObY5h2DuVpWzXt+SSAL5Dzt8oyOwXEsTSIp2I1klP6EOKoGJA?=
 =?us-ascii?Q?KZKtH6nKgeqJy2gJFGKjrwCkkb7iPxRgXB/HtlUdSmkyH1xhprNRGRcFe1u7?=
 =?us-ascii?Q?JX6O4jYPD9qsEXYCfvIavtxB48ntm+F0apoZbvjXamJidlAC+a0Eqz+b30RP?=
 =?us-ascii?Q?nv0EArh6nwtp1mxmBt1F5V9Mmie9MYYsckE/qxE8x/03VNjbHJZeX6rRq73h?=
 =?us-ascii?Q?f9M69hYGKJDHh1EgCuOHmHiEbH2H20+5MJ5eVtaRmsfOE7rXWtsmICKFEyM1?=
 =?us-ascii?Q?Z4wOCnCX7sYTjOtVtptCWB9ftsex08UZCXHhM/2ALpuP5i91mJCpTo7zp4yu?=
 =?us-ascii?Q?+TpsKdx7zZSRJxvn4S7SzQVhoNfVVe61xGY1TvHQ6yVE2xuAiXf8DsDSrJEg?=
 =?us-ascii?Q?PRtgK+lEZM1TB+ZefAVU2wSsjV2dW4WZK80VtM62fDYHxJVigwzpG6KUixVV?=
 =?us-ascii?Q?2GXYgQLNNuEFJnIoaXWS49vlkHhX6M4FgcI2Rc0I1bgLZ/FH9+r3pr/CTl6s?=
 =?us-ascii?Q?LtwBBieLOr9BYfhkIJ8UZivkCDDsPACj4lIBHFetB+0D3faqA1dhcg2RZjb2?=
 =?us-ascii?Q?df99LJcWGk7duD3Zau7P/B6jEARkw6q6/GqgU67jKq2nXAuB/xxentC3SCc2?=
 =?us-ascii?Q?+lECnHAGu0L6OcWfVhF2Vnr4t1T1Pl4NyXzCbbawXZq86dFn6g5tBflc1D8R?=
 =?us-ascii?Q?5ikWHkNX0Jv8DlWwS58rXoiVKKBS5KQvHtSWMiwP5ztu8TcetmsKHlgj/gMU?=
 =?us-ascii?Q?eQVC4NtiGQ405zdYDUoDBIwBNDEPD8JfMARJsig/Rfbupovvi7aql3posSnh?=
 =?us-ascii?Q?bXvMvrTN173ab9Z5Rwxk6gNnTWanQ8qdb5tI1thGcslTcJb/h8KDddjElmBU?=
 =?us-ascii?Q?iEkatb+9VA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: rnp0+af3Uf/9XywPsbEajsAHGjInA+jyGdd3Ib3i7eje+NMoKS2Nb/vODxwCg68tATI9w3TCjlKAF3mvWFY4od+cVqAsTaRdWpjdWeEPa/5B/hl0s3DNo/i9e5g+jx83UqiylLJ1xQQn0zfzyT9R4Bz2LRILkOVG0ZeQhcIOVY0Ca4q0jsoRvQhJErYAmRmtPyFEnuCDuztP3cc6WcihVDrZVNMEn/gnxcn1+ekX8JTAD6Z0+pQXt2hRUAC2lg/Mkop+5jP2C84cRy7LRWBYNnqn1GaFXdzOm42z7Iffym7N/SWqybh69E4b/eC6EGB/hvmXcfAzvEzdAmuDDOFL7B1TcSfUzhpm4XPGOpmlE+1V6KxU6lokxR/giaE5xEBvZSA/20VgNxktpTpo75khwfDJPz0FXvHBBbu7nngWQb/S4DzclDQeWznCMT7LKD2pSKf0Se+PvyYzokQCp6quT24sPZpQa+j0Itg5pQuhKT+l8xX/AiEPcEZfJ9gYZ9dCYju0NCw2vHbGN7p33zSbPu8cU3HuW8uT0n6QfbHXiXwWz5qdjCv9Tbm95dh7HyJWNX9d7WqIPFg4f5HkDv7CgiuBnwEvZCcxemP1QMZA22o=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: dd2acba0-0ea2-47de-7ae6-08de5dca9d71
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2026 17:36:34.0945
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: GUbf038Y07g+PmbZctmamU9wbRIcENkO4CdEoXIQGF9vJx5c5HlFCgznkcqIPfplOlHzc09EhDaJSWErnnUMVA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR10MB4219
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-27_04,2026-01-27_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 malwarescore=0
 suspectscore=0 mlxscore=0 spamscore=0 bulkscore=0 mlxlogscore=999
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2601150000 definitions=main-2601270143
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI3MDE0MyBTYWx0ZWRfX+JSTySiuqFwn
 loLnLTLmnDy+QPF5xOXTajxN07v6idgGAMbKRSOXwu5um9FO7Ysr3/A97i7ILSiwLH1jccWpvE1
 9GSSMfTXaH0jpbtQ2WbPGxXvmSBgDWBVitG7z/DXW+/x5ZcK7d1iRTaVnjU2mLo52qiHq/LzqnB
 Bjq6Q70iuEC65AHnMowBxpckPA8UC1KT92XSbqevLd11qh5mE70vD7u75CM1ZfI9iHiCRAAK0oE
 XUI8a/seNpZoH735HdKTYdHIJRXqUNEUuLJ0DKJxfIjyr6+glbTrWRxtJCu1Eixv4ASo6VPuajB
 bJLLv8JvtaxbedHP6KoQt00FazIw2LbxXeFKUoxoG6dAaKVjKPDaK3Uv5G+faL5BBQkX/jrEBTZ
 n1IkoXoKBqwdPAXyqUOcGc7eqd3l8+H4RiUoQpn2i+J8km8UhrC7tSJYj9DGKozPSfrPq+u/xiK
 KhZ878AYqnn9QY+L73AwT5p5zzP5Nv60EZYANl6U=
X-Authority-Analysis: v=2.4 cv=C+XkCAP+ c=1 sm=1 tr=0 ts=6978f7a6 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=1XWaLZrsAAAA:8 a=yPCof4ZbAAAA:8 a=0_aX6oQtOsjAA9Aozg0A:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:13644
X-Proofpoint-GUID: xowf7Bek0qxwotQE6-UfXlfvdobAY6JV
X-Proofpoint-ORIG-GUID: xowf7Bek0qxwotQE6-UfXlfvdobAY6JV
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=gLcb6f7Y;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=fn+HKgow;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBCYIJU5JTINRBLHP4PFQMGQELAM4UGA];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,linux.dev:email,mail-dl1-x123d.google.com:helo,mail-dl1-x123d.google.com:rdns,oracle.com:replyto,oracle.com:email];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[Liam.Howlett@oracle.com];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-0.999];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: A9F5C98829
X-Rspamd-Action: no action

* Vlastimil Babka <vbabka@suse.cz> [260123 01:54]:
> Before we enable percpu sheaves for kmalloc caches, we need to make sure
> kmalloc_nolock() and kfree_nolock() will continue working properly and
> not spin when not allowed to.
> 
> Percpu sheaves themselves use local_trylock() so they are already
> compatible. We just need to be careful with the barn->lock spin_lock.
> Pass a new allow_spin parameter where necessary to use
> spin_trylock_irqsave().
> 
> In kmalloc_nolock_noprof() we can now attempt alloc_from_pcs() safely,
> for now it will always fail until we enable sheaves for kmalloc caches
> next. Similarly in kfree_nolock() we can attempt free_to_pcs().
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Reviewed-by: Hao Li <hao.li@linux.dev>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

I'd rather have a helper that _mayspin() or something.  That way, when
we know we need to or don't want to, we avoid extra instructions.  We
can also avoid passing true/false and complicating the interface when
it's not necessary.

The way it is written works as well, though.

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>



> ---
>  mm/slub.c | 82 ++++++++++++++++++++++++++++++++++++++++++++++-----------------
>  1 file changed, 60 insertions(+), 22 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 41e1bf35707c..4ca6bd944854 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2889,7 +2889,8 @@ static void pcs_destroy(struct kmem_cache *s)
>  	s->cpu_sheaves = NULL;
>  }
>  
> -static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
> +static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn,
> +					       bool allow_spin)
>  {
>  	struct slab_sheaf *empty = NULL;
>  	unsigned long flags;
> @@ -2897,7 +2898,10 @@ static struct slab_sheaf *barn_get_empty_sheaf(struct node_barn *barn)
>  	if (!data_race(barn->nr_empty))
>  		return NULL;
>  
> -	spin_lock_irqsave(&barn->lock, flags);
> +	if (likely(allow_spin))
> +		spin_lock_irqsave(&barn->lock, flags);
> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
> +		return NULL;
>  
>  	if (likely(barn->nr_empty)) {
>  		empty = list_first_entry(&barn->sheaves_empty,
> @@ -2974,7 +2978,8 @@ static struct slab_sheaf *barn_get_full_or_empty_sheaf(struct node_barn *barn)
>   * change.
>   */
>  static struct slab_sheaf *
> -barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
> +barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty,
> +			 bool allow_spin)
>  {
>  	struct slab_sheaf *full = NULL;
>  	unsigned long flags;
> @@ -2982,7 +2987,10 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>  	if (!data_race(barn->nr_full))
>  		return NULL;
>  
> -	spin_lock_irqsave(&barn->lock, flags);
> +	if (likely(allow_spin))
> +		spin_lock_irqsave(&barn->lock, flags);
> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
> +		return NULL;
>  
>  	if (likely(barn->nr_full)) {
>  		full = list_first_entry(&barn->sheaves_full, struct slab_sheaf,
> @@ -3003,7 +3011,8 @@ barn_replace_empty_sheaf(struct node_barn *barn, struct slab_sheaf *empty)
>   * barn. But if there are too many full sheaves, reject this with -E2BIG.
>   */
>  static struct slab_sheaf *
> -barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
> +barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full,
> +			bool allow_spin)
>  {
>  	struct slab_sheaf *empty;
>  	unsigned long flags;
> @@ -3014,7 +3023,10 @@ barn_replace_full_sheaf(struct node_barn *barn, struct slab_sheaf *full)
>  	if (!data_race(barn->nr_empty))
>  		return ERR_PTR(-ENOMEM);
>  
> -	spin_lock_irqsave(&barn->lock, flags);
> +	if (likely(allow_spin))
> +		spin_lock_irqsave(&barn->lock, flags);
> +	else if (!spin_trylock_irqsave(&barn->lock, flags))
> +		return ERR_PTR(-EBUSY);
>  
>  	if (likely(barn->nr_empty)) {
>  		empty = list_first_entry(&barn->sheaves_empty, struct slab_sheaf,
> @@ -5008,7 +5020,8 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>  		return NULL;
>  	}
>  
> -	full = barn_replace_empty_sheaf(barn, pcs->main);
> +	full = barn_replace_empty_sheaf(barn, pcs->main,
> +					gfpflags_allow_spinning(gfp));
>  
>  	if (full) {
>  		stat(s, BARN_GET);
> @@ -5025,7 +5038,7 @@ __pcs_replace_empty_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
>  			empty = pcs->spare;
>  			pcs->spare = NULL;
>  		} else {
> -			empty = barn_get_empty_sheaf(barn);
> +			empty = barn_get_empty_sheaf(barn, true);
>  		}
>  	}
>  
> @@ -5165,7 +5178,8 @@ void *alloc_from_pcs(struct kmem_cache *s, gfp_t gfp, int node)
>  }
>  
>  static __fastpath_inline
> -unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
> +unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, gfp_t gfp, size_t size,
> +				 void **p)
>  {
>  	struct slub_percpu_sheaves *pcs;
>  	struct slab_sheaf *main;
> @@ -5199,7 +5213,8 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  			return allocated;
>  		}
>  
> -		full = barn_replace_empty_sheaf(barn, pcs->main);
> +		full = barn_replace_empty_sheaf(barn, pcs->main,
> +						gfpflags_allow_spinning(gfp));
>  
>  		if (full) {
>  			stat(s, BARN_GET);
> @@ -5700,7 +5715,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  	gfp_t alloc_gfp = __GFP_NOWARN | __GFP_NOMEMALLOC | gfp_flags;
>  	struct kmem_cache *s;
>  	bool can_retry = true;
> -	void *ret = ERR_PTR(-EBUSY);
> +	void *ret;
>  
>  	VM_WARN_ON_ONCE(gfp_flags & ~(__GFP_ACCOUNT | __GFP_ZERO |
>  				      __GFP_NO_OBJ_EXT));
> @@ -5731,6 +5746,12 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  		 */
>  		return NULL;
>  
> +	ret = alloc_from_pcs(s, alloc_gfp, node);
> +	if (ret)
> +		goto success;
> +
> +	ret = ERR_PTR(-EBUSY);
> +
>  	/*
>  	 * Do not call slab_alloc_node(), since trylock mode isn't
>  	 * compatible with slab_pre_alloc_hook/should_failslab and
> @@ -5767,6 +5788,7 @@ void *kmalloc_nolock_noprof(size_t size, gfp_t gfp_flags, int node)
>  		ret = NULL;
>  	}
>  
> +success:
>  	maybe_wipe_obj_freeptr(s, ret);
>  	slab_post_alloc_hook(s, NULL, alloc_gfp, 1, &ret,
>  			     slab_want_init_on_alloc(alloc_gfp, s), size);
> @@ -6087,7 +6109,8 @@ static void __pcs_install_empty_sheaf(struct kmem_cache *s,
>   * unlocked.
>   */
>  static struct slub_percpu_sheaves *
> -__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
> +__pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs,
> +			bool allow_spin)
>  {
>  	struct slab_sheaf *empty;
>  	struct node_barn *barn;
> @@ -6111,7 +6134,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  	put_fail = false;
>  
>  	if (!pcs->spare) {
> -		empty = barn_get_empty_sheaf(barn);
> +		empty = barn_get_empty_sheaf(barn, allow_spin);
>  		if (empty) {
>  			pcs->spare = pcs->main;
>  			pcs->main = empty;
> @@ -6125,7 +6148,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  		return pcs;
>  	}
>  
> -	empty = barn_replace_full_sheaf(barn, pcs->main);
> +	empty = barn_replace_full_sheaf(barn, pcs->main, allow_spin);
>  
>  	if (!IS_ERR(empty)) {
>  		stat(s, BARN_PUT);
> @@ -6133,7 +6156,8 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  		return pcs;
>  	}
>  
> -	if (PTR_ERR(empty) == -E2BIG) {
> +	/* sheaf_flush_unused() doesn't support !allow_spin */
> +	if (PTR_ERR(empty) == -E2BIG && allow_spin) {
>  		/* Since we got here, spare exists and is full */
>  		struct slab_sheaf *to_flush = pcs->spare;
>  
> @@ -6158,6 +6182,14 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>  alloc_empty:
>  	local_unlock(&s->cpu_sheaves->lock);
>  
> +	/*
> +	 * alloc_empty_sheaf() doesn't support !allow_spin and it's
> +	 * easier to fall back to freeing directly without sheaves
> +	 * than add the support (and to sheaf_flush_unused() above)
> +	 */
> +	if (!allow_spin)
> +		return NULL;
> +
>  	empty = alloc_empty_sheaf(s, GFP_NOWAIT);
>  	if (empty)
>  		goto got_empty;
> @@ -6200,7 +6232,7 @@ __pcs_replace_full_main(struct kmem_cache *s, struct slub_percpu_sheaves *pcs)
>   * The object is expected to have passed slab_free_hook() already.
>   */
>  static __fastpath_inline
> -bool free_to_pcs(struct kmem_cache *s, void *object)
> +bool free_to_pcs(struct kmem_cache *s, void *object, bool allow_spin)
>  {
>  	struct slub_percpu_sheaves *pcs;
>  
> @@ -6211,7 +6243,7 @@ bool free_to_pcs(struct kmem_cache *s, void *object)
>  
>  	if (unlikely(pcs->main->size == s->sheaf_capacity)) {
>  
> -		pcs = __pcs_replace_full_main(s, pcs);
> +		pcs = __pcs_replace_full_main(s, pcs, allow_spin);
>  		if (unlikely(!pcs))
>  			return false;
>  	}
> @@ -6333,7 +6365,7 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
>  			goto fail;
>  		}
>  
> -		empty = barn_get_empty_sheaf(barn);
> +		empty = barn_get_empty_sheaf(barn, true);
>  
>  		if (empty) {
>  			pcs->rcu_free = empty;
> @@ -6453,7 +6485,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  		goto no_empty;
>  
>  	if (!pcs->spare) {
> -		empty = barn_get_empty_sheaf(barn);
> +		empty = barn_get_empty_sheaf(barn, true);
>  		if (!empty)
>  			goto no_empty;
>  
> @@ -6467,7 +6499,7 @@ static void free_to_pcs_bulk(struct kmem_cache *s, size_t size, void **p)
>  		goto do_free;
>  	}
>  
> -	empty = barn_replace_full_sheaf(barn, pcs->main);
> +	empty = barn_replace_full_sheaf(barn, pcs->main, true);
>  	if (IS_ERR(empty)) {
>  		stat(s, BARN_PUT_FAIL);
>  		goto no_empty;
> @@ -6719,7 +6751,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  
>  	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
>  	    && likely(!slab_test_pfmemalloc(slab))) {
> -		if (likely(free_to_pcs(s, object)))
> +		if (likely(free_to_pcs(s, object, true)))
>  			return;
>  	}
>  
> @@ -6980,6 +7012,12 @@ void kfree_nolock(const void *object)
>  	 * since kasan quarantine takes locks and not supported from NMI.
>  	 */
>  	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
> +
> +	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())) {
> +		if (likely(free_to_pcs(s, x, false)))
> +			return;
> +	}
> +
>  	do_slab_free(s, slab, x, x, 0, _RET_IP_);
>  }
>  EXPORT_SYMBOL_GPL(kfree_nolock);
> @@ -7532,7 +7570,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>  		size--;
>  	}
>  
> -	i = alloc_from_pcs_bulk(s, size, p);
> +	i = alloc_from_pcs_bulk(s, flags, size, p);
>  
>  	if (i < size) {
>  		/*
> 
> -- 
> 2.52.0
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7dk5q3mbusqlklpk3ja57upbhkhhg3bpueh4nemuthesmwpgnk%40zkk4fqug3cwx.
