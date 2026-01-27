Return-Path: <kasan-dev+bncBCYIJU5JTINRBCGN4PFQMGQEZJOKB5A@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eFDDN4rmeGmHtwEAu9opvQ
	(envelope-from <kasan-dev+bncBCYIJU5JTINRBCGN4PFQMGQEZJOKB5A@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:23:38 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13f.google.com (mail-yx1-xb13f.google.com [IPv6:2607:f8b0:4864:20::b13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 75A1497B49
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 17:23:38 +0100 (CET)
Received: by mail-yx1-xb13f.google.com with SMTP id 956f58d0204a3-64956cfd789sf5538208d50.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 08:23:38 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769531017; cv=pass;
        d=google.com; s=arc-20240605;
        b=TVOrx2xjTwnGAiOxwQOEu0QCRWJW/bd93yZy6LpDTICbF+1XSnnimp9hlLy0+1yTM1
         k/SK9jmq8kkQFMMZ6eRadhLOgsx4bg58gr8jmDX4q7lxMQjBQSpEFeL3TDRC1cISJ9Wi
         z6VGCqTLeSVsRiSuFGtFYbiLCPjo76hEiHA/CfCs9OQuOhiaFjzZvRnM5Sicl9ua48KF
         1+6uhwn1rpz1IQyuy9TqVhOcOAeUPq0UEZdm6u5xd/LQgvjGSGdt2YrblWt7JeGZ3cBP
         bglepE0PgsQfOWPnzdGsFIgOP8iYzj18o9s5BomDaaQ1+zy/du3Kwb6nspd7v9QWBLpv
         vN3A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=biTzjL4KR4JqV33loloZKQGFLKKvjLykzDc3hmT51LM=;
        fh=ao5UHkjxJzxDu3XICMQtBH95TvL4LzQ4HUxQrXC5Dbw=;
        b=KIOMxU4hWoQyTrZglns8JvIoQjVApYAzyoPOvJAZU2J1XxmeT+WYt6fHm1wt9sVlpu
         RGL5Io8iUw/AdEuc8I7mdLZHiBp98R/kxnv9ARRtEZveg/z8N1Pe6KvOKW2Wuj2h6l/S
         9wjqLiSBRztHCi1uL6Ypvin+v3U3euAMOk3j9XYGd7zEnHRZw2emu1JBYKS/Yd3U/RfL
         UElgB7s9J3WxtBrQYrhTOzbu/rT2gTa+2J7Bv8opKntHDZ/hL7x94KzkcDSPoUyIW+Uk
         6Ocp6pTNAghhMdj/J8f7HlqWsOQisK9jI9WaV0bO7TtSUxkKhdUjEz9bKbHP5bNFzudJ
         2how==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ecxy9GQY;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=l7oKcr7z;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769531017; x=1770135817; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=biTzjL4KR4JqV33loloZKQGFLKKvjLykzDc3hmT51LM=;
        b=T9sX3uggYrMD+kUH5LgNiSnTnxQLsUTU6D3XlCf58/0K1b/Ob2w4O7LAtjGWObisnS
         w11JVHv8WaS9l11CHY1sIq9+nYhONZF5Sk60ndNw5ajXPytAoMX0V8QjiML6ii+zkp9+
         rZ9Ip7y8UMtHUPTccpLv5TI8jbwwM0OZSCZZbIfqT8D/UC09NyfBy0ShkGP52+9iW3U+
         imZghxq6Q8ljE+avf56YVEjd9/XW88OgJxd8nydgqbY8SzuCrwFmrcoQ7Q3VzbCVFY0R
         wEYXp/X1QbTu2Qh5/kKBenARGe5nKKK3hqxxau4PJmWwV4Mpb2FIU4uq18fBryrRkt2m
         M8pQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769531017; x=1770135817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=biTzjL4KR4JqV33loloZKQGFLKKvjLykzDc3hmT51LM=;
        b=UPK8hfeGKPkzu26v5WhwFQuMS5dsWj6Iiprv2CENJWRYVgVLcWuPY6ViBru1n1OPxr
         sW6cu4RBWkeoJgY6KQAd3Mmxs+1M7rA07I+kHfSLr6HCepBdL08paGGqYFRRROp5xgip
         depecMg2UiEEsMOTRZOXb6DWSMyGFQJGe3+uo0Zl/eZQ4LqWk2aERF+kZ7o1XLeg2ICd
         rn94y0QnSg36d3pwwFa+IlWisfjEL2B7biovqPtQuVS3MUTBIz/nR6V3jG2240liiIMh
         7eiki0rDWPByLpbmqZDlJZuNL3RLXIze8ErVtGyw+TfzNTpbjYgnPXSaeM+3TDBilIHx
         +73w==
X-Forwarded-Encrypted: i=3; AJvYcCViLDdz3Qp3oInNYyqDz2e6y83w98nk1UoFWPaTGNBJb0j/tFWlYECHk1R/3Li/g/JaiqWqig==@lfdr.de
X-Gm-Message-State: AOJu0YyXPcnNJZ7sMQqM6i+rrQnRT607OLzkUZ1ceLGNabLU+LrCntB8
	UooeKBT6IjO+EBRB2hQkwe5XGF3MB1cUG7afKG49Qg7pkxK8+vuUK5Ec
X-Received: by 2002:a05:690e:4009:b0:649:5efd:5ef with SMTP id 956f58d0204a3-6498fc596abmr1452195d50.70.1769531016879;
        Tue, 27 Jan 2026 08:23:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FtARdajeMEgMfIXOvH3ngdrECPUEswozR9U/zc0/0Iag=="
Received: by 2002:a05:690e:d56:b0:649:6421:82b0 with SMTP id
 956f58d0204a3-6496421954bls3051264d50.0.-pod-prod-06-us; Tue, 27 Jan 2026
 08:23:35 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVfdP4Yg15yE+fP6ytHBWpqBrT3nk1OV9Cx+ZwJaGx944oD7gKctq2+60Entufke8rwzp4QsxapC2E=@googlegroups.com
X-Received: by 2002:a05:690e:d03:b0:63f:b4d8:1f3c with SMTP id 956f58d0204a3-6498fbf7194mr1488333d50.35.1769531015825;
        Tue, 27 Jan 2026 08:23:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769531015; cv=pass;
        d=google.com; s=arc-20240605;
        b=gZedm4In9r2byl+zDE6Fr56pa+jfyNqjcsf8788wPehMKqesq6UpyECLfDEMEW6uLE
         xsEkdSNic4zuVURRn0C8KiV2MKnARfLkFaYicm+x6DGwIL5MpOueRRtPh+rpQAef+e/7
         DfbkichUDQMtOwmmbTZJvjPug2mS6Wdj+LcucDvsm1yGeQ0+4XF39v5WLuvz5+AVFhqj
         nMSAyufA6Wc4X4lvg/biOadsVkR/lgZhyZJpU5FIP3vFQ0Rj9Jvte9/Ynm6hg3rQdqs+
         UWbXc7RbwH3Y8yX46ezAzrfJkl6ExOTpDjYbYy87+5XeXtcs1jZHuqrkWqh+AZ2rN8AH
         x1xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=K1Drd+vR1JZNiY0xvX/P+1Ka86l1Nw7bFsy8Cb1KjLk=;
        fh=EGMhLkV3udorsQux7n/+Xk9u7IyRbMe92LwjbXHNLfE=;
        b=iCzvcb5oiYQptFRxiV9I9Rc5lEICW8/FMYrRisTz6t6X4OsKrTdOSK5x56BSVpnwoY
         kTDBkJourAoBsDZhsmws0RnugrlE8Fga1FnFZ/N4BZ7lGknYwRa8li0S8JWA0zJNkAjw
         a6oTv70JjnPHW/eN6RoZA7Cs9347abGKpSCUGIzXhTPabIiC9pDDJb2cVA58ET8nUxjK
         /uQdSmToklo3mXprKYnaJL0i4k01vil3WwVxem896ky08HJ5iEoBuZOsAFV0hzTSSUrj
         UZZgcFBVWQBlrID+dli/XlKUjGAo+vjJOsiI1zPCZlrYaI9KY024KY8ltWPfkxNJnVmI
         M35g==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ecxy9GQY;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=l7oKcr7z;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7943ae2a548si4789507b3.0.2026.01.27.08.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Jan 2026 08:23:35 -0800 (PST)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0333520.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60RBF4c4456433;
	Tue, 27 Jan 2026 16:23:33 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bvp4bvbxw-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 16:23:33 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60RFhOX8019784;
	Tue, 27 Jan 2026 16:23:32 GMT
Received: from bl0pr03cu003.outbound.protection.outlook.com (mail-eastusazon11012006.outbound.protection.outlook.com [52.101.53.6])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhexa8f-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 27 Jan 2026 16:23:32 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=F7IIyc887Kwnm1hEZOAAODEShgXLaArlVfNITAwDpxiKI9Xvv38FmgoRXHKItGz3HxaAZx8A0jiFPO4DJLcjuZAj1EQqp7cWgDoAPpgMtHpbCTgzW3dLjcSctB9JS2Giac7lKW49gKZ4lIK1rQYBTD/VIwSrKME+xUq9PFuA1xLYAjUzNMvd8Hro/b1EdzWBRpn/s0chFZdlh4xXQw3YWF7c2P/8+f3gNBS1VFAG1fuhz4FQJXCIpNJxYRSQT2QRe+/qfJdyCRf5yiAR8AHHnEvA6pnSoba8CfqKZ/GHsQQlLxm78z7G4qhdQaupPJtVo2n6R5mSV+Gp7TnDI2pzpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=K1Drd+vR1JZNiY0xvX/P+1Ka86l1Nw7bFsy8Cb1KjLk=;
 b=MUZEXz5F3PI/v1LwmAfji1qRote0g4t6Ld6snMBkswcUpcyuw+Z8aPcI/i9CT4OeB+3xU3zSPBwj8Ymg+8uA++38NPQVrHmDzvYVLAWK3JsCddLKbqkaoA3XoTTzDD4vEOAthWB3qPJCaiINaeUbo1+uGOvH6gWMaot8RzZzHQ6MT848Bo7osDmbSHwIR1V23Ak3hPSBe18XNvnMWJJmLwVKIX6rhutFJbHTryNAWvVlmq63CjUxUcP3mRh5k4WIF6gwCFaPR1UXhahjbGn9J+D+gsLv6NtOR2htRPbaNE6gh0dktvomU2IA3cjjkVtUE6BOUo82BukWcShK52h0pA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by MN2PR10MB4287.namprd10.prod.outlook.com (2603:10b6:208:1da::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9564.7; Tue, 27 Jan
 2026 16:23:29 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::4b84:e58d:c708:c8ce%4]) with mapi id 15.20.9542.015; Tue, 27 Jan 2026
 16:23:29 +0000
Date: Tue, 27 Jan 2026 11:23:26 -0500
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
Subject: Re: [PATCH v4 05/22] mm/slab: make caches with sheaves mergeable
Message-ID: <iumqtb6shmu7q2dgd4pdcl5n52qhawdjv4p3h26moqnxfrq7q3@54lzpzd767yp>
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
 <20260123-sheaves-for-all-v4-5-041323d506f7@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-5-041323d506f7@suse.cz>
User-Agent: NeoMutt/20250905
X-ClientProxiedBy: YT4PR01CA0363.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:fd::12) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|MN2PR10MB4287:EE_
X-MS-Office365-Filtering-Correlation-Id: 48dfc7f9-a950-46a3-011e-08de5dc06812
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?JdcijE3hk8Jt6x79aQK3fAFFL3VUORXvl9j8HeWu0TpJ3vnGCccaV61aOtXP?=
 =?us-ascii?Q?WgtNtadqL2lg95L0Wuuu79WZOdGvb54xgDOqAYj3swKxqfcckRNnNyqK+Lvg?=
 =?us-ascii?Q?8NoR2Kyvejcza+E31XtsaJ4FuTdDwv5IeSW6hx9crfL7HTAfgq2HuSbQUnhn?=
 =?us-ascii?Q?zUUIn8RBXrIfcivNxzbKc4ywNtcBNPC2sfQJL6HzKezKlidXX6wfgirR52gK?=
 =?us-ascii?Q?4CwJFGgrlXyKCBSM4hx5lmUMdDv6aG6bt6GYKrnWFoMbVYvxqH/veoTcrpX3?=
 =?us-ascii?Q?MHX5eXVRvPuxXKOWAbSPSttt9tlnaiFap/q7xqwS977qPiD6+pZFSuLKXt3F?=
 =?us-ascii?Q?Loac6q53zyxNoKs27+oxGSKaTZZpcsQPSiyvPceUw91hTWiw5sGmTJk7xXhe?=
 =?us-ascii?Q?RCG+QM9c/v3D5sn99phlx8019td6wr4fISC3gFDkgQiUKnABz8qh+b5K50Cn?=
 =?us-ascii?Q?q74FCIKyeKx5JBKwFrK7NK4Vbp++/wlKlVvHzcOt1kvpC0AK2pG6vrAVd9mZ?=
 =?us-ascii?Q?GruPAhC427TuJFjo3uEhziOub3kpA/7s5t5wYn5VPAXgdRDm64ab7oEyyrgJ?=
 =?us-ascii?Q?PxzWdEchXtFr/QgnxpZo35eRZX0OH8lMdYl9mkoo/xY+oLz/fJcphQihHv6o?=
 =?us-ascii?Q?5M4ObHF9Ho3R5RU2JguOwPbw4cGadX1wA3ljMJL54miR3hKRs/WDCj4aNWq/?=
 =?us-ascii?Q?115Cfbr6Cmo2dkPyXFQBGFc3rhADSkoFHOOw1UQcK5zmkGXkiIqak9zbsPyT?=
 =?us-ascii?Q?6kMnwdO6S2qKwQHIcRhpejtNiOI2t9mcv+W8rzYCZNcUj7UeC3JyZw0T/9ef?=
 =?us-ascii?Q?Y8tHE1Ivz/a6lAUE3g0qOlVkVOU+9k5FP0yL//Tb7UsBCvgDyXA+IPFJ8UBg?=
 =?us-ascii?Q?Rbdv1RSQAJgmcmtOLKvsBB/RxCUmPQAYpkslm0sJTosibJ9GuRs0zF3Ql2Ql?=
 =?us-ascii?Q?VImHRRQYkhoV8aEWoKKssg3qRKWYjxAhFhd7xihQrQnqN7x4MdfF4dv1I1Pg?=
 =?us-ascii?Q?C9rC6+9iwGa1e8R1gY7Gnr5JHGTRPYoBhr+xDFxoUapPSRmAxujrtXy03oRc?=
 =?us-ascii?Q?81qr2RNKmpxnZn6YS9vx//pNe69hgtXTJk+2Ypw75hwnh8dx9ZYuiwsAWyqY?=
 =?us-ascii?Q?tb2zVkEIw4199xb5DUxtj22rqcCck8GQ2ROQrG9PJ8hJuX3Upt+QR2vwCvyB?=
 =?us-ascii?Q?kiUixDBNmHgaUi/qsuWw250QVPSegBUS8q4/BiigxqB5zYgHqHdBnH/OuqiA?=
 =?us-ascii?Q?YydHDuzA/IlEK8cG/qW5v7isQZus10+yzBclg64ntk4QeuGzCu/qkTNqRJUz?=
 =?us-ascii?Q?2yD9oUZTVGnDa8Z1sSCoLvf7HiNtJGn6XHxzAygyuHGc2P9Z6KM3L0uxl0AD?=
 =?us-ascii?Q?lZ4Ku6k/VjbJBzXhx/zEccdJSithgULvo9HQo3PCnwJFL17S8iyo9kavjRa7?=
 =?us-ascii?Q?3JvJhBOX8ZApgee4IiaBKz8Sk/+WixXdYoUK4rSCpUQLJcnycIpS0t9V5RbD?=
 =?us-ascii?Q?2ruM0Y6AscIve+2KSH/KUtXyKy0XNzSuFtBZOl0iJSCMpRxOLnsZnx7WveDP?=
 =?us-ascii?Q?AaOj7Sx0/CQA2kFEtW4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zZ3ET06ebIdS0BAuO8XcL7fGbZJgw+2Nc9rhmFmnrT96vru9Vg0oC829IvPv?=
 =?us-ascii?Q?w4zLQqNaF9wgcWW3iQa2y5JK31k6NQbzasRaUXXpwiGlrwylK/Gio5W9+Lh5?=
 =?us-ascii?Q?mL9cKBfkAnQsB/ykpETaHUPw1jUszrH4rhvHIEqIxDLzkEHfYg6Pct0wYKVO?=
 =?us-ascii?Q?lcdrtVWI6EOhPSEbkyvCu+ztCJ9DnsxCKfaqZ+Wx3TpII9yW5bcCove9suUc?=
 =?us-ascii?Q?Siy4ap5cFdYoDmw7ez3MFQH865iLRvvi4lp6hGN/7vlCn4IlpQ0/RwaTfQHt?=
 =?us-ascii?Q?N1Kr6VhRIszne+kdMONVTt+EgSaK3hQZgYxJR7YD9HTCIFZtxFfm6hDZCskU?=
 =?us-ascii?Q?2QFkA7r3aNDgP3dxrb1lNP5UJtNeCec9tRG/biGPYT03vmJlYqRJeNVnrWMd?=
 =?us-ascii?Q?2F6xI8XVQ69Ytj3iLgr9nv9c4tvCPluHIsDvf3rljw3diSPCZRcWrsXjJwmk?=
 =?us-ascii?Q?cSaoDiFJVLfMA++/1+UTXvLBeQanTR82qQx/U0DjzkajbELRVGCh6HvgqHBz?=
 =?us-ascii?Q?IDo0RDI5suR9uoUwLn5kCx4JKqPz4eniUisWD19FDL42tWFnUI6M3eIJC3WK?=
 =?us-ascii?Q?FO64+JfzDG7FH/YV1KAj//ZfWEzBfD65feIQQ6dFA+aTXYi/LR4WrBQRlxib?=
 =?us-ascii?Q?7gqEiJxVdlz59lwtGmjN1FWatxnyXEm7yLv9aTT527zulV8yNkV0T4+IZukH?=
 =?us-ascii?Q?SsWh0nrTrt+rECQ+zRfwXoIwTNB6xLzT9Es/PZC91v46SLui8SvisM6F9BN6?=
 =?us-ascii?Q?PWxsz5FpMEx0KlmAkAn8JXGVu+Ib6YiOlIoRJm71nnWi1OkJKb6Jlfs/qKu4?=
 =?us-ascii?Q?/s99ou1pHHAielij9bxGjegKlFJjDsUSpsPblrTzh7her/YOztC9rIkF1SaD?=
 =?us-ascii?Q?lknirYE/bwPknE/8Yez8OHbFuVK5utyxlExFCU8jEzUPz6zk47a2zTQn3itQ?=
 =?us-ascii?Q?QMzdi5cNqb5JNIhWAo3cI2W2rJcSPrpjoYjB88DjzQhofXQtZYYp3abMcA39?=
 =?us-ascii?Q?BjG8ITA8sMoozyGRj2RzFI7v0nBhjbhFYGl3KJPzuWo78sdFtXVMIxWr1rJ3?=
 =?us-ascii?Q?1jYhhmME11/7EIIV+cQgsbOr2Ke46NTbdM826HC9QEl+Vd1u/ZBzgiNsfcUK?=
 =?us-ascii?Q?Zx8y0L44aDRw6vjKkaPpnB1D5GPrsrt/py8g+edJWqs8FdS1dHF2BCGObXGA?=
 =?us-ascii?Q?viG0W6caRY7KZ4F3XLR38mYATI2zC6SbEd8iNNwuy2/T+vaFAbg1FF9DdlA4?=
 =?us-ascii?Q?9861q0d+f6MhzLZIkRMlZkbXBfHIUFeLV9dpO71e0+2K1IdPHee3x4jeZu6b?=
 =?us-ascii?Q?BqaK6KOMM4/DpjigzTJ2+7dtSI28daAsiapvu9wpCWkNEp15A/eIWA1sxjSc?=
 =?us-ascii?Q?xDD9jpGvcfe/ru809Z77SFmuxSpM47yzlks1ozXjlw4iwz8GfCFQ0mUP5S0J?=
 =?us-ascii?Q?WZhrEZ4cGS+PP+J03bA5+gIXzbKAK5RTuBS3kKhI2BroYh3j+ezcZSJaGIp+?=
 =?us-ascii?Q?YHOqii+6WhsUXz6ZoPKk5oRd5Ysf0KsK51JGr9RVB2U3j93Ni/FEfVZ2njtZ?=
 =?us-ascii?Q?fa8G4cdgOYfdzngj7OAqKCJSXizHamgrf6bCsR+WDnM6gHYdd34NBdAIBlKM?=
 =?us-ascii?Q?aZheVFSTBGSnJUHAxmRKtWlG0/zGNXE7T/iemMwjAQ4gdTr85scH0Ip9tU2x?=
 =?us-ascii?Q?ij6dpigTlEQCyVerx1rgKAVtvGpYgRfQeUTsJE0uM8DDGRayaDlBTPjlVLZw?=
 =?us-ascii?Q?PmgvkY7JoA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: L/HEJ6IeozZfI90TVX+mzdtGyjpPKTHBln2ZJxM9c8cosi2Bo1z2jkvA2j9frfQUrEbJnPGo6kBNXigcJ9Vn3khCljdxsI8/WD20kwh4iSwAFnNaVATVOIN1RmMZfcYvgwhcc3JXeDPUdtg5dASIyL9HOjqbUJWWa5FPWki8RGS4A8MHJMoyauXL8ERmPXXS0gDqqHBXaw93cgopXAw87M76/Tl42X7+VIZdVMLPZV3Xsmqw2626uBeSOzw4fWM46T+VPkReMp+Ik7anNM7ry0AMhLtr8vn8+Ib2aX/AFmpQSfqHEdWKvIPagTgQkeAQdg496NEMFTHxqoAW242OUhjY84FKCHokjD3R3AACqJErhEXeEd4Pm17IrP5/XwKSiMg/mh0ywY4gSbxexfvHkdOnL4xAtc4q4xRZazzsLtZ3cByI68amB801SrVCN9+4CviylmprglxU2WTQIDiS7aqodmiqoaDPJaBMvH5ZSk7ByymRBuSJ4oH7IQgBx3vOPd8kLBNYOtzhmc/nJ/lCosV+jfbalxhlOSBYP76NJ+kyiv7fT5xnuzcE1okeeHBXYrWnzObCSMql8NVTinb4PiyZqHIYKlTAWFTlLghMeZQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 48dfc7f9-a950-46a3-011e-08de5dc06812
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 27 Jan 2026 16:23:29.5801
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: ZnK0BzgPjIbq/2N4dmXPU2OkuCwYB/HsjaCNjkijcHWvWDechpu4c03KRzLNeIBeJDE4BYanzWg9BgqsSb4Y6g==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: MN2PR10MB4287
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.51,FMLib:17.12.100.49
 definitions=2026-01-27_03,2026-01-27_03,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0 phishscore=0
 mlxlogscore=999 mlxscore=0 spamscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601270134
X-Proofpoint-ORIG-GUID: xChBaeXn8tsw3rVTfYs97MeilS0KJFeJ
X-Authority-Analysis: v=2.4 cv=StidKfO0 c=1 sm=1 tr=0 ts=6978e685 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=Oy7RBdJ_-iLdDo7p6TgA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12103
X-Proofpoint-GUID: xChBaeXn8tsw3rVTfYs97MeilS0KJFeJ
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI3MDEzMyBTYWx0ZWRfXynAK/4HdwvhG
 jgw0FJ0dLvnVp9U1xV1ZIPVJqOxicy5gvrG+NgaQMJniUO6HpRiCsmWfTeIkS6F6Y69JUZRPBpc
 06KikkO3ATSV4tLDhpFWHuI6ScrFtnvjc7a4sv7rihkqWWk4QHU9IfZzzSug+EtKn6RIiXw4g9O
 qnfgNk4qUYSG/93mu+jgq0flxaKoMpJCV6g5wQdxJiUl4aKhHWkmgjhzIjqzpQIZ2nqQdZ7Ouyu
 aKdCTj4apaj/8orqDg/02GHJVJbw91C9vw5+P4LV8WcguBTtq0+fmPAazCYT08SA2NV0Xf+bLoT
 dPVkZn+jfVxF53eR0x6GvPjdTNQWjvAnlLYuaYH03nmgJAftWCuveKvziz19OP52WNxx64b3jMu
 tBRqv6rjAOHBXELJh7verl8Zy9Y/pSxzJ/CLf/OZ2HvxbizbkBVSp8FPULjTuy15rUgG2GkzJVq
 v9SKsg1nd6NwsCqM/9Y9ejRYN+RpirJErZ205M5Q=
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=ecxy9GQY;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=l7oKcr7z;       arc=pass (i=1 spf=pass spfdomain=oracle.com
 dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates
 205.220.177.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
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
	TAGGED_FROM(0.00)[bncBCYIJU5JTINRBCGN4PFQMGQEZJOKB5A];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,googlegroups.com:email,googlegroups.com:dkim,oracle.com:replyto,oracle.com:email];
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
X-Rspamd-Queue-Id: 75A1497B49
X-Rspamd-Action: no action

* Vlastimil Babka <vbabka@suse.cz> [260123 01:53]:
> Before enabling sheaves for all caches (with automatically determined
> capacity), their enablement should no longer prevent merging of caches.
> Limit this merge prevention only to caches that were created with a
> specific sheaf capacity, by adding the SLAB_NO_MERGE flag to them.
> 
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  mm/slab_common.c | 13 +++++++------
>  1 file changed, 7 insertions(+), 6 deletions(-)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index ee245a880603..5c15a4ce5743 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -162,9 +162,6 @@ int slab_unmergeable(struct kmem_cache *s)
>  		return 1;
>  #endif
>  
> -	if (s->cpu_sheaves)
> -		return 1;
> -
>  	/*
>  	 * We may have set a slab to be unmergeable during bootstrap.
>  	 */
> @@ -189,9 +186,6 @@ static struct kmem_cache *find_mergeable(unsigned int size, slab_flags_t flags,
>  	if (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && args->usersize)
>  		return NULL;
>  
> -	if (args->sheaf_capacity)
> -		return NULL;
> -
>  	flags = kmem_cache_flags(flags, name);
>  
>  	if (flags & SLAB_NEVER_MERGE)
> @@ -336,6 +330,13 @@ struct kmem_cache *__kmem_cache_create_args(const char *name,
>  	flags &= ~SLAB_DEBUG_FLAGS;
>  #endif
>  
> +	/*
> +	 * Caches with specific capacity are special enough. It's simpler to
> +	 * make them unmergeable.
> +	 */
> +	if (args->sheaf_capacity)
> +		flags |= SLAB_NO_MERGE;
> +
>  	mutex_lock(&slab_mutex);
>  
>  	err = kmem_cache_sanity_check(name, object_size);
> 
> -- 
> 2.52.0
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/iumqtb6shmu7q2dgd4pdcl5n52qhawdjv4p3h26moqnxfrq7q3%4054lzpzd767yp.
