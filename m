Return-Path: <kasan-dev+bncBC37BC7E2QERBLXHW3FQMGQEGMTKNBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 28809D39D7C
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 05:31:44 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-502a35b12cesf80992651cf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Jan 2026 20:31:44 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768797103; cv=pass;
        d=google.com; s=arc-20240605;
        b=AU8D3C9vpcNv+HMHUNfUn/95VGB/ykLR3NZ6fIMCJVk+cURIyMFZ1e9Zag4zcxIIB+
         lwMZj9V5Bjl9Gnkw4cta0EVhZrabxzRUiw2dNmFe/imbFMogvP3SAgtFznkUUDXavovj
         Ues+/fMPE8UMWsL7vpAtl3bF4VtBA6R746oCuISaEN8W4ISXW7PdhhUSQWBNNKltS0kP
         ICnbLpcmefCR5kR0ioP+76O1JCWMGXk0mP48qHgobXQXa61e2onpg173SJFLR1KHYJ+o
         BaSy4S8jmVjxYtybEJmZpI9j0X1V41Tfxj3RZbHIz7Grd/aLK5fRPnK6Qo/WUx0zUuCX
         NV6g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=3uTUNgVTJxE9McSY0kvsZQvqgz5GWMf4gfJGDDWz/nU=;
        fh=na75gJ2QBcouu1/o/xyZVGuWK9QeTj7YGkubD7Ey7pk=;
        b=d2+XCNqvuUBjwFZBvrl6BRxovk+F+aWuWqHgO06HdT/RZMrB+OxWvX0dzjdWpaTGpM
         Kx5bC8RvCeuRy/KwQ3ld6W9ahY+LAFhzRwPFEUwgQij5jqowCJPu9fd6BdTX6XI+AleN
         pnGdTzDUGCzi2KfqpaPAGJkz/dEqRbNjYQs03sWJkn8nSEqzwNlvayCixeIJF7+a222Z
         zQgAyq+NUEWMDM9c+fMrYGQGV+4eRkIbDiBVsbb7ArjzOzDgpiPkRUi4U5JY57LqVNzY
         GOz/xRfOdlNoArb6+e1PVGJmdriRhl3XIUZuypE77rmTaLG9yk0OvR0PRNSJ5ClUwVT0
         8Hxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=BPpzRAPt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=lr71RseJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768797103; x=1769401903; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3uTUNgVTJxE9McSY0kvsZQvqgz5GWMf4gfJGDDWz/nU=;
        b=EofiaaTg1GR4HhqY3i8IckA3PDTJZB3UVHxRnU2t9H71We6mx3FHpM6MsPn7idByM2
         L67zAj40qG2aWFZ3fr15Lgr0QHXfpGbMJdqkcQaviFp6WhqKeoja1AXPz3pKqX8yZ2uy
         mQljdDn3g8P9uMSjBdlb5BoBxNTWyfeyo6zewlTOkOUod0kFrtOwYBNbQYX58wCZreCV
         Mu+iSDGO9qzxFlvTYdYS/kICxmlcwNN/fWtdrIa0ZkWZvqylCGc7dq+KVWcS6Gvfc3nj
         higPjSWSt0ELBKrPGMRiIqKPUKvP8YN4vmOiBeb2xxKwLQTtI8L9vvCGvEpic9/09HFQ
         Xc1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768797103; x=1769401903;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3uTUNgVTJxE9McSY0kvsZQvqgz5GWMf4gfJGDDWz/nU=;
        b=rjPcx2XMz3JQquoijtwrG+tYr8dLCywrX6wYOtsycrtI42Od4PUlfO/eDmPrzvC2RP
         vV59TDAothrfAExe7kWUzrh1oO5UW2lOq3UihUjlYjnT6mOM1eM+WD0h1iUBu4bBMYp8
         TnICXRiuYUQMczAcydTWU1aTbfLzJsKTP4ew4C8Us6BEVXxWJv2XAfup9hNMQZTgifPR
         zvcUDmBKgFuZ1/F+R0YzvYrHATFHF8MnmcuCjb5ugpuusV4iN/pHG6Kf0GUXLNF/NhKd
         mg85+OTyhH2clcTIsMIMxxURlkW3Q/2xnm7a2YNKwF5pTJHICOPrcnE1cdfAgR+6Qm2V
         eFdQ==
X-Forwarded-Encrypted: i=3; AJvYcCVsUniu9+JiEcHoCWhPnAzRqmqRyRSTJuUxckp+vmRQriAxDcnDjjWpnMOkNQxdFj69Y3yIRQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw8XDbbbnqoG9AzPcYbKreHAIVPSZW1XDryKxFt7XD4vdnLbNdR
	+ki86oOUO/2QG9xqtYaOGFoU5ii5P4VaCpsnYqeQOstrDTUS9JMaxxNS
X-Received: by 2002:a05:622a:546:b0:4ff:b3d5:4f6b with SMTP id d75a77b69052e-502a179d019mr122933681cf.69.1768797102531;
        Sun, 18 Jan 2026 20:31:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HucaOF9i2XrUV8bnKnMjQSXUe2l06CKGHHO8xuzpJmwA=="
Received: by 2002:a05:622a:91:b0:4eb:a15e:a083 with SMTP id
 d75a77b69052e-502149f1679ls69186331cf.1.-pod-prod-03-us; Sun, 18 Jan 2026
 20:31:41 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV/R4hCY44BSC1nZy0Y8NSx/ML1mXXoJo/FvotLmuV7grVcRLr4bfLdh8OxFIu8Y3qaTteo07Pl+e0=@googlegroups.com
X-Received: by 2002:ac8:7f56:0:b0:4ff:c884:31ad with SMTP id d75a77b69052e-502a175713dmr159269331cf.53.1768797101517;
        Sun, 18 Jan 2026 20:31:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768797101; cv=pass;
        d=google.com; s=arc-20240605;
        b=JMr4vN3rALRC3e6SCNiUI/vFhmOuTQuTTbivz7c0HPhsA9Cg9qKziEQcebj8yJnmlR
         v2dmUe1bhXWVyma+LIeoJ3g4ThLGbSKXDmQ+bJ+NwforelhgXG9qHHCMCu1VOzFMtiFZ
         Cu5Rqtqe/yTUeD2pKLsxWQETe1rgg8S1anlVbP4e0RhuhycW+JnwHHcgLfudsulCXwJE
         W4R7vWhrXXHCDxxmJ9socNlCpIAOajpEkAejbwcOSLzoWZzXw7OadAKLbaOYfI0VvItQ
         YeTv78mClN2nXpMLUK1+t49Kz7iVytu7FEUUWATdR4y0fxHPMzCAzmbXacYhQ3hSvBDd
         6eRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=0uClx6JzrXV3kBJxbOk9VAjb43kVsE69AVGuAdTul6E=;
        fh=cD8mJcoQfFkTlzKzCvOe8LoFw/w0zXxii+7038wtU+M=;
        b=RgguELCDqzu0lokaHiC+TEAlPTpaRjGKTFPBuXEoTlKXhKG/5J1vfsfRfRv0IjezVa
         9uatKY202FYJ23vGRLrq6s0wM9BYErpIbWij8xum1RCbtYJ6BJSbskDt0r3WgoDU7zAO
         sl/1xn8ezuMgOCFHY6Fj1GXzXlYK78RYjWcItS5TWkESro1EjtI8C1j7ie7sv9/jYgD8
         1BXnqjQKU+8z/lbc3SM8CtaQMZZ4RvDcVT5x5iB6a31/i3rIjt8llohbgPXqjEupoHLq
         3T8+fP7rreZTdB8bkBBsEkjVjRfnyQz+BrSoLWQTeWrvTEn+6Cnek7O4CPlqsHQ8AQZL
         M+dQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=BPpzRAPt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=lr71RseJ;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502a4ceb215si2403701cf.4.2026.01.18.20.31.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Jan 2026 20:31:41 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60J20wBB148825;
	Mon, 19 Jan 2026 04:31:37 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4br10vsppy-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 04:31:36 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60J1PRtO021910;
	Mon, 19 Jan 2026 04:31:35 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazon11010014.outbound.protection.outlook.com [52.101.193.14])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4br0vbn4yx-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 19 Jan 2026 04:31:35 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=nzXYcJFouyMdhoj7HOZM21oijGCQGwOB8FVJNMwoXZvRFssYb0Sx5zTVkHnh6q+U+vVVvmaybxQfddoIaplGxeHSrOfB7A1wdqZw1NlQ/25GWjFDZiU0ETR5LgV9PlwzMi6tBiErw3CsnPvxrVIFEgRs7WCc8TabSpf2PHfAFMWKPdY2F5j1Bc8nc5YvLPIT07NqzpOrkHbgoK/lEf2JJD3ibv/igWgtMEm3hQegwQi//MXidobWB9xU86SuOHE2m6OgTISDdu6rRGWiuvzsB1tlCvpsSZi/Iz4i3+Hmz6szun5qJLkzKGFMRL77aN+zOukAVO6cREkcChRmcKKxeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=0uClx6JzrXV3kBJxbOk9VAjb43kVsE69AVGuAdTul6E=;
 b=GXIBwwh5H3vxdq9Av+oL3sZOYsnXwGvW8BUpWjSiEmpmUfYvREDOfaLhurloQcQ3VRm3MQiP+K4U3ukjvJh/QJ3nLHVc0BGr0VrDsmcwurL4uy68/0df8NrmFNSUv0pOnYkqn+MAeLwFkPFG4F7LmWGE+3IvAiZTUko8ka2L8E2cFOHtQYn1E+2Y76pjWsXgTep22CI9+eXqW8dwaXjZWdglQZso2OVIfe0wUfD53IbKyvH2HgFw+r6/riTUZz+I7Y1ELYzykoJQBdCowg1a44guNjr+hLomNOs7I+2IuHPHcLFjsvG9sHaWNdVaITOu6ZRgmti2CzpQqaNo9uh0iA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by IA3PR10MB8348.namprd10.prod.outlook.com (2603:10b6:208:581::8) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9520.11; Mon, 19 Jan
 2026 04:31:31 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9520.010; Mon, 19 Jan 2026
 04:31:31 +0000
Date: Mon, 19 Jan 2026 13:31:21 +0900
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
Subject: Re: [PATCH v3 07/21] slab: make percpu sheaves compatible with
 kmalloc_nolock()/kfree_nolock()
Message-ID: <aW2zmf4dXL5C_Iu2@hyeyoo>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-7-5595cb000772@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-7-5595cb000772@suse.cz>
X-ClientProxiedBy: SE2P216CA0165.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2cb::14) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|IA3PR10MB8348:EE_
X-MS-Office365-Filtering-Correlation-Id: 09d91e98-9d0f-435f-b7bf-08de57139edf
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|7416014|366016|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?IYShfeIHf4n+3Cu0oyBscxxRUlhpeZpmjkuyN6OVeiWWMuDCupwIPq4LbNuT?=
 =?us-ascii?Q?UTG7x3dg/4epnnMQXxtJzrX8TUVnLe2ugFl1YZVP9vLCrGlInzXRk0ojudim?=
 =?us-ascii?Q?IkpnrbluJv6TDcGA62zXykoVOWgriCapVRxWZK2n0s3V+Ii+5fPOjlFwtR1p?=
 =?us-ascii?Q?ymG9H/zWUwefzBo011zMRHnbjcbMfCnOfapAqrM5ls4Tht1LT+7806YNZsjY?=
 =?us-ascii?Q?pXBwXFH6QqR7yvedP3sqN7URBFif+UxVvqqEnIsXsnUIEyi1dkqXm742ZpUI?=
 =?us-ascii?Q?6ikjatme0f+F7zHvoTwv7kBsUQxSJgDTfZFJbuLWd+ogs5Lb33hxHcsLVorL?=
 =?us-ascii?Q?BAui59xuGs3ZSWCEB8HRANNbH5W8kQf5OTkmnWRDLUpd65jQwBpk7CDz2Xf5?=
 =?us-ascii?Q?NSHwzEhuAy76ELBOK056tPxplHDg7mhyHJlmUISvJRrLuCeikOT5fz2CdI9t?=
 =?us-ascii?Q?oEB4GTJ3ObQbXbP7ELLa8o7ygoHBHyXDz3XKtys46NBwYmTt71cBoM1KO9n+?=
 =?us-ascii?Q?lgcE6GSeRsvGzOiVVzF0ZUbTlf8zi1Dzs5sDZEAT6jHJAaDHQTNKg5rymQQl?=
 =?us-ascii?Q?bTl0WWno/c1KTyJxL9NN6v5oyMnbJR/uwq3V6ZkAjkYjcoZMBM5JDwqNdeNY?=
 =?us-ascii?Q?Tmm9AnONPbokdClB78njD+N5cQXKAbzknXkU6fcEofWHb1ZRhfK8x0WZMyCB?=
 =?us-ascii?Q?u40mjFLKXuhvqrrfhPQGct1jN39SR9WSuwqFZrWKl7RgTyEJc6n5CunAIGhh?=
 =?us-ascii?Q?5zZ/DuIUbJ2iO6bcOy4nddeLXHe3yJ5BQ2304mnYVKUJ5rKoplDqOuJ9mbat?=
 =?us-ascii?Q?RfzjfngDydoNB1dGN9Hog+CsLe2u9L73YjvlAe8AWMTXCiG2IB6CUFrFkcI2?=
 =?us-ascii?Q?vC0haU82YRK+Tv4k3CNq4hE2e4VJy/2WiUayshACi+rYrJHEvNoSt01YzrIa?=
 =?us-ascii?Q?0pl/8Dah/q1aIhl6WAEXkr7WBJ5pEN4qiPM+ed8hz7anwCrbXgAMgQWhGszq?=
 =?us-ascii?Q?Yp/ysRJe4wFRgWglZ8LnQeUOrmqA7Qv36QxfyFITREA2PbSBJZfMZmqnnAua?=
 =?us-ascii?Q?GOi+UvzkzcTESXJ5hMQxvWD6fHsCu6zjjFBmjEAvm+FDAjjWXRjQObodOH2Y?=
 =?us-ascii?Q?DQ3GIB9iN+Trknmm2xYPMZhElKdSEwoihtOWlyCKMZUM5GONZnwvZKh4yc7O?=
 =?us-ascii?Q?XRNodJevVL7oVLVdBzypHqbwVedyzZCxq9M2yXqIDmkkUqQPJXn1TPOpdu8f?=
 =?us-ascii?Q?v0CNVZhBrHaLM9fVanXtJxWLXDmYPhcZBSUmOTDPGo7uMC1ivJPtxI+ADLP3?=
 =?us-ascii?Q?iLSvUe6Vv4PPCjm8s4ukU4CyTffxGY5FRLl+ZyP9egdeQZXIJtAv+3Sx6pBk?=
 =?us-ascii?Q?3qX5k3CpsuPjHNHPNI57Ps/97Z093ml4UZwN8l0FhgUPgCTmYWAp9/ZEs4TT?=
 =?us-ascii?Q?ie9JjF2rsCCgwPV7Y9tl3KlfNYISq/haxpzgv5308N0CSWP+ysgmTph6eXvR?=
 =?us-ascii?Q?9jNd8SK2W8YZSa4FlZV2C0eJxKa5C/5k1MN78JJJ2zgHDcFOJ1SxiPyyyyJU?=
 =?us-ascii?Q?/5jdXg9uZpJBBAkCQT4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(7416014)(366016)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?W3ChPyPCQBm7UtmhYA07yuaMuhq4NY8wwFBjzA9ULQlCP848XbKR23NBBF1C?=
 =?us-ascii?Q?2GO80fcqncWSumsw4DRt02qPzjeKBXPjJA3TVVvrvvJxQOGjDrOoLB282lwA?=
 =?us-ascii?Q?QiwTFB+s9XCvKJ7SfWUs36fwEXjjDkZQw0CU+Nc57gz+njuKExrEDRyoOhmL?=
 =?us-ascii?Q?MQbQBwTFgnQcSrSj65haW4nSMKZrPS5/frCM9+dT2DkA6Jo62e4zLrOgTgf+?=
 =?us-ascii?Q?zMPxEOwE162zVimSScy0Cv67bkHN76JN/9EL0yl/VmHFsCiIbMNeaXQOi2+i?=
 =?us-ascii?Q?8EUxL7VCjqTaPooRBVmRNBTW18wFtS1eiefpXp+nw31aKWFUuCrJR6ZZNztD?=
 =?us-ascii?Q?F7YJtTGac6OV+LBW2AE9XqEZtAYU9YDqq8pCR1mYXPQ0+dkIpjWhBoQFatYc?=
 =?us-ascii?Q?//C9IYcJo5EGWnvUBxnRs52iPyChMHHeNj/fschUNnOIqSJM+EWplfOAv0H5?=
 =?us-ascii?Q?O3lAXnP04Xh/I2HCxJJSWvnFtKMBpp/aMeZSv/qoxWoxHlESCZqFomAJpcxI?=
 =?us-ascii?Q?kGXnxNSdoWOg6sgxyQDCJqoRU4Vhf9L2HfuWZd/RHW8Fmw1slJ5I1OzIWPSe?=
 =?us-ascii?Q?da16fTWvQ0TM6F0KnVvGciYvhg53E9A8TS6awXnORCATfg3vZ72V4D/NhvT6?=
 =?us-ascii?Q?tPpMULVvd3DYB0otCnpIlfBfLgB7GFf+rTEAubSPhe+meT2alvqJbgHKdYcd?=
 =?us-ascii?Q?eqSzbE9/Fpq70VFb3tiXLEWYs77AuRdryuIF/ywSekyta5vieM5XTv0+YcHF?=
 =?us-ascii?Q?rZd/lDB8BIStouMAtpQqJMKISmvxaNd466Mhj+zQFF/pXAmtrdKt0+vhnfaw?=
 =?us-ascii?Q?Wp9+ehIxK/F8ecSXtHKt8btSpPM9by0rPKOzYtTu1bM3xmNJ/NA3GnT5Ab0R?=
 =?us-ascii?Q?HG+ZAmVrgLoJAICY0deov91djl8Zyz+Vi8TPjkEYeI2kPR4RIC22fEsCiAB/?=
 =?us-ascii?Q?v+OOqLizM5hjd+9iAgt+gz0RZx1QATZA4B4vU9qyjnkrdCJ/LbEcySrHnZ8B?=
 =?us-ascii?Q?/qS0gORkA9uX1y7PiPLJFQhxNDSVHtKDoiON8ydkPBdpJvMdK0thYLGa6Ko/?=
 =?us-ascii?Q?psMgBUWGpTEskVki8v29kl1E0JeFlYj+kKpcms6jMyjc/WHRMKkwIpQsJLVm?=
 =?us-ascii?Q?UTPex769skEM2GOqdhVQ4/KtW0Wy2xNbYO8YhRvQh+MrvS0IwTS3cFexVkdj?=
 =?us-ascii?Q?FAQ5fOX3JeJU1ZMpGanoyzTT1TcYifFGZQiT9xY1a6ObmGzMj8njFJy2ajUB?=
 =?us-ascii?Q?vbfThoJ8aFKBDqGTTaYVBjC/IqGYPO0Ok30EoCt3VWzyOD2mLhl9a9WqH6jw?=
 =?us-ascii?Q?rugZprAufizEhJm//hhiYvwkTcxy3dtDHUGwLJdj21HV3k2LeJuKBzY6sZr3?=
 =?us-ascii?Q?eI/24NYF/rWxNTqety9PZ0cHwkewHylwARoDOIi8JcEnXaKWOHZ9N5xDCume?=
 =?us-ascii?Q?zqeN07mTJv8NatihmSkly09bT0cirawPhduM3VHiR7+F+VPU6poiKLh9He8m?=
 =?us-ascii?Q?fJj0TJeu1XssmQUrHuaj+TwU65JjJ0aD9+nJwoOo82kkywVCg5NUypDZhpWp?=
 =?us-ascii?Q?xlGkUH4cECujo0fJLJwiepxVGFa1eV0/3tdXryFclML6CAYLPLy5+qXKxafe?=
 =?us-ascii?Q?bNW1pYd6ixYjCUsLqYp7Dqb2B0H1hZ8dp/l7WfmhPA/tUsJ1L2Jh40CQLh0G?=
 =?us-ascii?Q?/o2DV48/BMYqjGXWQ8U6weKOpEslkPrHbqjYoNfIJYb4SdSvAN7VZ4f4uB9b?=
 =?us-ascii?Q?dmwwCVe+BA=3D=3D?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: G5LaMUn+hiMwa99KVPWnRbeDmi8RdO1Jlw694ahvGmLl2bxMVWc1I8+ha7Pecm40WgRXqBgEj5j9a/zuiExXUUt86ACeh/M9fjR9RWVauvl9DUhXZ2YZmpV30YwCXmRnC3Gz7VW5ssocyxom+1rCo2yHVo2f9gK25CCu/U4leQzIqP85HQFnMlNU9A8UjlVLJGmfefGZsBoBeEVIPL6Fu9nYHgETdjzXrU2Us/rzZJf8ibOdIGJJd7A9ch7HFK9bvWzpN3/IcfwJtUcu98M7q/ebf0eAC6A86mcjvitUim5BIC+OaqyEA8ZOD3bm0mCgYi0scB+2LOqPC4GnNi8jjii+LP3ktjliYfSF29rFJvxTzLKRFlDOv/KYIFH4HWQtrWGheJRf9+g8UBepIi1IjGb4ONSHFxXjqpTxHxCphLmAq2Y92iFj6ry9S1AsOh6qtQkKm4fEAQrsc3DecWcnQrArwNUbsUSCmRohpU58sPfHmfBZu3ABpSQqimldhQUk0PLjYb/uvphmXCWELDhbtdveGLBqHLF95QpRD24USsc1BGaj2L0OZAsviawlrmbLHQoisC7w8un7np1jNf1/SwQT/KS8n+r6/4lHDeA9xAQ=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 09d91e98-9d0f-435f-b7bf-08de57139edf
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 19 Jan 2026 04:31:31.7133
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 1doQKURQkzAptJ1cnMUortydehsWXZzuM/cEAkqOx/SGuei220PV3wyKjeqC2tNQPDomiRBL3XA1Cz1PRijPoQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: IA3PR10MB8348
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2026-01-17_03,2026-01-18_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 adultscore=0 bulkscore=0
 phishscore=0 mlxlogscore=999 mlxscore=0 malwarescore=0 suspectscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601190034
X-Authority-Analysis: v=2.4 cv=H4nWAuYi c=1 sm=1 tr=0 ts=696db3a8 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=okt8U8eJDhC6h_ZcaKcA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:12109
X-Proofpoint-GUID: _fbIus-m9KxC4kP19uxdwhspLofg_9iq
X-Proofpoint-ORIG-GUID: _fbIus-m9KxC4kP19uxdwhspLofg_9iq
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTE5MDAzNSBTYWx0ZWRfX10zX+MiK6c49
 UGSrVIcCkjnLqX24U81r9OGmhzXjOWyaTZArGKamMVd3rATiCFwMRnDh26j3qur3pj4y1ksAbcV
 w6qy9b5AR2agxIXDLPC4VD5vwJZ9DE4TQ8H03dqT6bs5B+O/ok6Y9cLK55Qwp0qvrOfDcbNEuDa
 qVVU0Z5JJW1UKNLDG9ui1y+nZ4BST5fcvizia1vvje+yDqGjgcaHY6P1kkzku3qElXrc8NSI7vB
 bZ/dz5ABZzh0ZPISjjgYtzbItBykbuz9qh7RK+ZXZe+a3bnDXmZjlaiUo9w11UzYKw7nfbveyai
 cnqycMd675RVbBYVpcw+O7h48Aih3bH7/DMz73hsTN33DJRyCr80fjYjo1HRmGCpdlLjatQXT2J
 7lVIfsBwsCRwjKYwkXG7wLslamQ3aRzUItjXrb6jtwi6cBvDlDtPi7/If5zzEu1XqiKKbzIO09q
 DzHphhQlYSUL8uxK38swJ+jm3XZWwBD1TlN75Kcs=
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=BPpzRAPt;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=lr71RseJ;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Fri, Jan 16, 2026 at 03:40:27PM +0100, Vlastimil Babka wrote:
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
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

with a nit below.

>  mm/slub.c | 79 ++++++++++++++++++++++++++++++++++++++++++++-------------------
>  1 file changed, 56 insertions(+), 23 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 706cb6398f05..b385247c219f 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -6703,7 +6735,7 @@ void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>  
>  	if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) == numa_mem_id())
>  	    && likely(!slab_test_pfmemalloc(slab))) {
> -		if (likely(free_to_pcs(s, object)))
> +		if (likely(free_to_pcs(s, object, true)))
>  			return;
>  	}
>  
> @@ -6964,7 +6996,8 @@ void kfree_nolock(const void *object)
>  	 * since kasan quarantine takes locks and not supported from NMI.
>  	 */
>  	kasan_slab_free(s, x, false, false, /* skip quarantine */true);
> -	do_slab_free(s, slab, x, x, 0, _RET_IP_);
> +	if (!free_to_pcs(s, x, false))
> +		do_slab_free(s, slab, x, x, 0, _RET_IP_);
>  }

nit: Maybe it's not that common but should we bypass sheaves if
it's from remote NUMA node just like slab_free()?

>  EXPORT_SYMBOL_GPL(kfree_nolock);
>  
> @@ -7516,7 +7549,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>  		size--;
>  	}
>  
> -	i = alloc_from_pcs_bulk(s, size, p);
> +	i = alloc_from_pcs_bulk(s, flags, size, p);
>  
>  	if (i < size) { >  		/*
> 

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aW2zmf4dXL5C_Iu2%40hyeyoo.
