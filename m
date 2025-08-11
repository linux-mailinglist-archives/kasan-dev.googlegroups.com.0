Return-Path: <kasan-dev+bncBC37BC7E2QERBEEC43CAMGQEUS4SIKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 2396BB1FEA1
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 07:35:14 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4aedcff08fdsf76919491cf.2
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 22:35:14 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754890513; cv=pass;
        d=google.com; s=arc-20240605;
        b=PA/E8EYnGwF2p3Gn7nqx7+g5ApKyKjUprK7WAIcD4CLsH0GAxbPlHVMpJAvGFNeUyr
         WDRaz/cMSNbt7Hrqm3mgkAMDr3yxi2reQmcpZZqzY0YX6BGIgVCLHXv8ChvoBuOKFgkK
         7FIjNURhLeFt9X4UHc3+cv2y6DIz0OFDPBzul9ykL8LeF8uwGG5RtDpoGs6RGoOgJf2C
         0zwmtcOz+9ZzkQNr2JoGmCJtyRO3J2IKXHfNfwxhndU2dxLvfDNXCu9HtnKyS2ZeUNU6
         zB+8WnhEwunhg2TP7s6haO1oVjLSavfVv3zh0v/whA+2W8/i8g5tfkotCJD+eQr7uzrZ
         dDRA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=JfqeNEHbplFhfLbb6ox7OzTzNtRpn9Uk6aeXvPgy+G4=;
        fh=Aj6y8EeWMD9pUWKqCMP0hYALTU+PEvtYvo/ejzhor9A=;
        b=Oq9Q7BUMoyZYtag8CFbW1VzD7N2tFFDNfApKiVU2RWq4SxfEojfNXtd8/axSvaOi1E
         hrYLghYEsQBNrIFQ296FdjQSCo2NnA7NYgM47P6vTZxsVY8tlBrjsEh22fJGsW7nmfBc
         ttYugrmZnriQajZUbX6nxqDF/znmf645sGnIjcPQGsR9FdjVEe/RhxBdDpBoFeVoeDqa
         cPimlw35m9pHX+60Od5HsapL0D/2S3Wc7ccieAB/NSGL0Cu4cH4TM5yBIQZtDWF25uG3
         THGfttuP73dKVfEjSDdNzNmiOnmeY2mjQsm8FVys68t86CqZItr0/loMhcpf54dvesXx
         4aCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ot41yEhp;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=APDc4ElL;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754890513; x=1755495313; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JfqeNEHbplFhfLbb6ox7OzTzNtRpn9Uk6aeXvPgy+G4=;
        b=ZWWIA7qV9/KcfzkSUMdO6Dqt8HSVciB7+VdRvud9ZyuIJZq6EemA1trSI3uhp6JgLb
         QVDT9B6V8j1oVUP2kFG8NK3LSOm4sMHrWl5AudX5T74aKjEXV46ZiE4vmRmAuXFKM+05
         lvw1W2TV/0+sWGoCjG78EJvrc2U9dGBg+6+3uXJptncrZeBvZq/BXhI+rinUDnaZqvF4
         7ZaepIRSYJgfEMPqGbLcW6HuoOiZq84E3Bu2T83sT7SaaQ9MNjrmccRRq0kfGw6BOfBu
         baq6tWA07Hthhv5UBEDVxXstaXN1aLHO3g1lhHTsSbCqc9/mejd3eronsm5xFhGxldOH
         YZZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754890513; x=1755495313;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JfqeNEHbplFhfLbb6ox7OzTzNtRpn9Uk6aeXvPgy+G4=;
        b=HCntbXRfBO1dfuL50bL5rb3QMoMwRWw4K+MucWO9MpMewow+Wh2NMQo7UmG80JvZjW
         N7PGP77TbmvamCPkIyPGTe+2kyjM0wCouLztKsEI6b2CctlWqZbOCo5UxbqMqb9qIdRH
         R3D4hwE/94v6t+Yok2f8W6qehoTXSATyRUoE2issTaC0wejedY5sUmMVDtGSvuYx3nvo
         yk1piJXdOQAFzZPm7LuqsmBhcGLVnNANkzaUwqt1iQ9CIc2Rfwe2DWFr3vONIoJ7uLwS
         fLvOsUh4gvJ6KxZb/SKHuLGSWjO/oP3hUJIdwdOOgP7+ZVgzP40/pixLu+okhh7FOOSF
         3NsA==
X-Forwarded-Encrypted: i=3; AJvYcCWqhNDSbzyhRLrXINRipNlJNhXC+OZ42EWLbvBu2SLZU00o8PIJWDB5+t7rUxFrbQyk8hnr9A==@lfdr.de
X-Gm-Message-State: AOJu0YwFtcTlqJvGYHRGUy9Ie1KABIW99MS1LeJ7uf0+GZUPUAhPlFam
	g+C+I0ehrwLTJzanyv9pBqeIXAZS1yBrL5COoHGTP+rZvlXLoldi1D6i
X-Google-Smtp-Source: AGHT+IHWOBdz/4KfwNwRC5ggOnsojod71a4/5YB/sdTy4V0I8ENUPAkSzDE43/efM/kLJst/OKwxqg==
X-Received: by 2002:a05:622a:5a0f:b0:4af:4bac:e523 with SMTP id d75a77b69052e-4b0aed0f0e9mr142988151cf.8.1754890512690;
        Sun, 10 Aug 2025 22:35:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZevADqzOwIIj6nhiZ8plSy8nAZhi8DIxz7zFYenpOurqQ==
Received: by 2002:a05:6214:528d:b0:707:2629:964c with SMTP id
 6a1803df08f44-7098809df7dls49783396d6.0.-pod-prod-03-us; Sun, 10 Aug 2025
 22:35:11 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVz3L352baB+bUWil7gPjvtisFsr3a00NNjZT2iCJQvxKQyMDuRgRoe8l5EDkNrnRGUGAxaJoPuL8M=@googlegroups.com
X-Received: by 2002:a05:6122:a23:b0:534:7f57:8e25 with SMTP id 71dfb90a1353d-53a52d7133emr3641013e0c.1.1754890511649;
        Sun, 10 Aug 2025 22:35:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754890511; cv=pass;
        d=google.com; s=arc-20240605;
        b=CBioJXZ4iET1U663OWHx/QjH6qYsTg5iWbv2eCihS4bZf8qv3lo33YIFQKN4xFe1W6
         dluVoCeJvNW2/ANie653UfBrrO2TsW7QiM//Tuv420P1lmn9ZjaRappiflkye18VI6zv
         ahk4EoSftMafFteYmglmQVcPYl7mtjyDoB6nlMengyM/8vxpjo5wmMOCE02ZpK5RkKAu
         N4+V59Z1yGFMZRPM26qU43oftmUKehrwmFfsbOlynONWLQotUgscTcjkh9cL2AnIs3Gc
         0GhDmbhJKpETIS9SUm0knDEcbfHsKY/RaZ3vURfCE97DgU2pIRLorYyuFyQfrKNbCxLM
         KDYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=1lRXnSNyEfXMe4ZNzvaA414iZaKLsJsXe2dxeRySSpI=;
        fh=ibbQO9U02cHhAxvOEUY9mWPo6+5ye4eWHkymspSm9Ck=;
        b=jBtOHB6yEel1JMa6aSN0P0XVBhxTZK32yE3KIL4vNPoF/f6cUs1slL3rPjwtMjH6UB
         GVDWk9WB4EYasie3tsdS05GE9hng4Om3kEkm90Mgy0RR50SBMimuvi2rVps6FDzjBKEe
         ASGYsdyNf1Jrm2A5BP5JcJUpI33DDXjBY6ls+1Lx9O2W7fqm76mwEU+gZoSFvJkplOAk
         /aDUC/OP640dycKIEuDX8GqbLFAA2KZRhrJm14xk9CxcxAXc0Prir/567xEa0LZG3VNi
         7KLWm1qoImw8T/qZxskhdF1JcemBcjTnEXvfptAZJCnC3QCWJo1oKrOtRX9qYKjcOzkf
         IgGQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=ot41yEhp;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=APDc4ElL;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b0258660si511029e0c.3.2025.08.10.22.35.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 10 Aug 2025 22:35:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57B3NB2c001771;
	Mon, 11 Aug 2025 05:34:57 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dwxv1qvk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 05:34:56 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57B35JfB030234;
	Mon, 11 Aug 2025 05:34:55 GMT
Received: from nam11-dm6-obe.outbound.protection.outlook.com (mail-dm6nam11on2063.outbound.protection.outlook.com [40.107.223.63])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48dvs86v4k-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 11 Aug 2025 05:34:55 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=V3zWnxcXSI6ZOYqDz4w/f86LZZ7LXg/5Nwp5akTm/Q2AyJKzkE/b7Cl39EB52DLUCQfM44q2jt4qM9ta8NI9Xwl9YvcMOHDwF+YFLPyV2ZBqPlCP0N+RJDzwPLw+O+9grOhdv/bboe+Z9SAP29NhxT9mi243YttlSfhQgyQSJzmAZpYuzEBHC5HYHYX9pU+TgiahxWB1WP2cy7QH7WOX1xWaW3HM9d6HT6LMWcqY6J/be3heFccto2xefkVL9BDlrWYyNmc4/Ffz76MgLkDo9uIsup77E1Xvi7ekmDFK0Kt668VdkZ0kmq2Kuxu5gWrUWT+95gv233HhBKGg2QYrTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=1lRXnSNyEfXMe4ZNzvaA414iZaKLsJsXe2dxeRySSpI=;
 b=wj2Z7pmlhvEyjUtCH4WvcM20aX7aB8GLupGmQYdiBzy5n4lqHEw7L03d3fXyVQQcQFGrZloo3Rb1mQs+057N3U9S5zf+74uZ34IJWhURNRVvPGFkGaaOnXWyH7o99ZANYtZNXr1Nf47MhzI5xEYvKyhIa5a5fm5kBAhUwoXCzkUslavBSXzwTAruHcQT1YH/ZKQuFEVO944H8Bk8H8JsgZ6+AUMuIxWDXBiavSXg+B4bP+Fi2p94fxVQJDtFCYTE6tkdtCbjhPR4x3JupYhchmjsYwAQbIZmTPTZ92As3R8MtjOFfLcN6D+uqs27ShE1Tfsg3hYIbO/zpahyhqLzLw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DS4PPFA0AD88203.namprd10.prod.outlook.com (2603:10b6:f:fc00::d3a) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9009.21; Mon, 11 Aug
 2025 05:34:51 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%7]) with mapi id 15.20.9009.018; Mon, 11 Aug 2025
 05:34:51 +0000
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dennis Zhou <dennis@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
        Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
        Andy Lutomirski <luto@kernel.org>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Tejun Heo <tj@kernel.org>, Uladzislau Rezki <urezki@gmail.com>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Hildenbrand <david@redhat.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        "H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
        Mike Rapoport <rppt@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
        linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Suren Baghdasaryan <surenb@google.com>,
        Harry Yoo <harry.yoo@oracle.com>, Thomas Huth <thuth@redhat.com>,
        John Hubbard <jhubbard@nvidia.com>,
        Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
        Michal Hocko <mhocko@suse.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-mm@kvack.org,
        "Kirill A. Shutemov" <kas@kernel.org>,
        Oscar Salvador <osalvador@suse.de>, Jane Chu <jane.chu@oracle.com>,
        Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
        "Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
        Joerg Roedel <joro@8bytes.org>, Alistair Popple <apopple@nvidia.com>,
        Joao Martins <joao.m.martins@oracle.com>, linux-arch@vger.kernel.org,
        stable@vger.kernel.org
Subject: [PATCH V4 mm-hotfixes 2/3] mm: introduce and use {pgd,p4d}_populate_kernel()
Date: Mon, 11 Aug 2025 14:34:19 +0900
Message-ID: <20250811053420.10721-3-harry.yoo@oracle.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250811053420.10721-1-harry.yoo@oracle.com>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: SE2P216CA0186.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2c5::14) To DS0PR10MB7341.namprd10.prod.outlook.com
 (2603:10b6:8:f8::22)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DS4PPFA0AD88203:EE_
X-MS-Office365-Filtering-Correlation-Id: 505dc15b-5bad-4137-2cf2-08ddd898cae9
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014|921020;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?8CcdPYzh4cYZ3sJ1T4QXLkRQQr991TN0noekBJ3tSdu50sQuqApTxs672sDG?=
 =?us-ascii?Q?3ryp/Cqi7LL35h6ruo6l1nQLrRfri+Mf8lh7eJrM0Vn+3626c9pc9aYRI+nU?=
 =?us-ascii?Q?wn7nwsRcfhNCIdywostBUjmiYrcdObEpPxT9MDQpI/y0ehS+xsrrhsKG3RJD?=
 =?us-ascii?Q?AKnPmOWrSGYoMKGBsoqqoyqEG5RA7y0lfVjm0HBs94MoXTfuLrpvQ942ajsZ?=
 =?us-ascii?Q?Ztax1DJHudIhyE/KsQDfmEIx6HJNXoIcWMgCrriSGw3Gj6LX610Ceb5zve+4?=
 =?us-ascii?Q?r0F8hLSG9mBlq8/8wN4ozBNSf3M7puLkpin9Xx0ZgUyz8cFME3kOp8AMkv1N?=
 =?us-ascii?Q?IRBs0zHtHOtfAzWugnxW9/cryYxax5JLELSxsHhsYAU9jdnkszIabkiZFryz?=
 =?us-ascii?Q?mWfC7JnKZpd5jjKjsCRvkQ/O3oGoSzdIwVQkFHTjjvEienItuICiUhcLv0W7?=
 =?us-ascii?Q?fx3lxat7PLdGCIg8UknPWDHQiZ+45y1dX1DgNcZ+0qLOy0avBTQC/CYvWwPk?=
 =?us-ascii?Q?FkdnzYjMyUOgrwUK9AVbM2DKbdnArCD/p8VaUXUzacgaaE1Q9mO3fo0oEP5q?=
 =?us-ascii?Q?MnJcpF+0n9NHtaAFumIRAtoiLdRZU7O3yNM/4QMSZ+WLN2j4NvZnqwkXAqVe?=
 =?us-ascii?Q?fqJuO5Wqx9p00ykosJjqXSqF2knn0F8AO/CZMggabHNC6B+9zZ3b8qYU2V1N?=
 =?us-ascii?Q?n952W8k6KJRC+iUWS9wimS6aZa/LOtC0bbbpAlCwKQ7ceuJ3jLP0FNXCSKY9?=
 =?us-ascii?Q?C/EaOTa1vjT8OySu9/rSjEODhB1r/FUF988oo2x7fPX69s/najRqFkgzREux?=
 =?us-ascii?Q?pnkjxIdrR8++pXefC6/6jW6SxVUVSYdsZeT1b7clNrVDJYvoQxfjAc3Uj1Oi?=
 =?us-ascii?Q?PW4UJcjjbR/uGpcV/CAZOgfly+v+1LKr+3z9muij1Phh4kaJ3bMbpC9RjjKp?=
 =?us-ascii?Q?q8D1e1iTHkGpdZ2cR6/CTmSuNHaa3YbCWe6lqtrSxtlEUfmzSyZUoKZuq9Vy?=
 =?us-ascii?Q?Q2D/jcIxdciR9zY4Sz71fDgIbDwUoWj7TYtkaGFkYD8FW4VNjEBwDxPeKjNw?=
 =?us-ascii?Q?0SXMgjB3JlHPP+LNij1agc4COUpA6uJ4LeVUEInEVWLDxB1bV/hUef7c0ze/?=
 =?us-ascii?Q?A3Y4KIcf37SKHSunrqdY7RIoJjBuYT4/+xO6tO8M0mSiyanPNDH+O7/FPmsy?=
 =?us-ascii?Q?Tz1+3aHEel+wqAfPv3jQ9t16FxPhjbR30xuo7TXFd9jlc/wORFgQZrCVRjiI?=
 =?us-ascii?Q?qIW/OM1v3kxkEZH3TK3Y0lXjekUZ9rpiTQ5IrkgqZ9Xbxtdkrr7dhyPFzvns?=
 =?us-ascii?Q?YC6fDshXQe4E60H1JCz5rZGlw+TBikzHKJRmUqhJRaUwkH4FFPaowwl9UzCd?=
 =?us-ascii?Q?7AdU/BfyJQxisygFjdpGn5OdDNMl8xOLaciMkO6JtqU+Ys9idgyQo7r0p04w?=
 =?us-ascii?Q?K3jymk+8h9GLy1JptuvXQb8o2H+newcegNUOC4u4GUJM+c5GB+1DMg=3D=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014)(921020);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?dpxRVB4h12+wuzs0Mqp2lnqEkxV1JWU1dDP830hOi+EigiBtgme3OuYDdltj?=
 =?us-ascii?Q?3ny0EW1+u4QFcn7OaaIoVOyvCTuW4RUloWF51ta5q9Hm901PgVW1K3C1BKJ2?=
 =?us-ascii?Q?VmABAoOWBYVJkymXMVKWxeoXyxIJWdmB4zml5cdQBvkNgUECHsw5nCy3HjtW?=
 =?us-ascii?Q?+Lm6i4OlJhxWsGMtWiEoDMkidoUCeXESxWWFWhq6MBtLBumSkOD6KStFP8bV?=
 =?us-ascii?Q?oQnJn0MG7SGy/ajxKarBhLvkw1KncWXUhWpkH8yaNGAK1ZbdKlavvdN5bTsM?=
 =?us-ascii?Q?Bs3LaVP3SHxxYAJAnC8Lubu/CKu9nf7rlYukbAPwbE4URr2Eq9Jv0S3VXrUG?=
 =?us-ascii?Q?K+TVhXVP/EzmpSuITVRMRprsZRh9oxZyhiJQAkZFElp5C/wunKd3ivkLdrDZ?=
 =?us-ascii?Q?+rT4TLlSWxHYKFYbsTji+GXtFvMJ1jka7B859oE1yutxkHyzkqrY2H5L4SNm?=
 =?us-ascii?Q?lrnxKbd8ibSA3xOnLREGOzY/Yvn9PBfQMMxzKpJpAI1W4jpzVkD/9mdULalC?=
 =?us-ascii?Q?7e/gHQlr5y2ffnzwLBi3bt1gDi6b7B/UB1eR+1DjOeLSfF9whT0KxGKglbU1?=
 =?us-ascii?Q?lwUCPOQoipqrXlOdQOk6jAUVuytiihMQLF3ZLZpjBmoAuBnBjPhi34QMVdvR?=
 =?us-ascii?Q?FxWE/9efuT+HwkHmrnBUuxkg1xzBnWmV4GgeZ6r+rTRzF4cCsvWl2C+kmDZ4?=
 =?us-ascii?Q?+7CfvieIrWFUMfGmXxondeEZxkB/EUBTQnKP3o6nNlIfzCvg2joZph+7eDNy?=
 =?us-ascii?Q?XOsgK6WkCMXuk4GUUovXo+beJtilFI9ImaoiOiQFwDpEL3qU/W+MwaDXUlTj?=
 =?us-ascii?Q?tiUcVVyMcgE/uRVXEYtusu8/l3m9iGNy1PtuplE5iqLuA+GEwVITHwQhXJaO?=
 =?us-ascii?Q?ymC1jFP5kTTe/VXYPRpiQZmvtFqXQ1gcYJw5Md7jBUpGyyrIjtzjwQgpV+Ht?=
 =?us-ascii?Q?op6TvRGSYq7Drz7Z6QtZEVTlSlk0aN21B3ZeTS3wTGKn9fdqb0zARddR/GFv?=
 =?us-ascii?Q?OxBBzjR0LM9ICLM2kcqqU7oTCo0rQNeuE0+p1jZrebjLBPCCzllTb4YwDtDI?=
 =?us-ascii?Q?/YNBoGd8L6cu/QMEC24jpqZRpiWhzq+hVpRpUIEGwmPGdwMWIpcB7+sPrq8L?=
 =?us-ascii?Q?r/tRtijnVioYY+iQpBAtUGoLWWxb926+fO1/N2BAkc5pLEDxzabl/H2INz/K?=
 =?us-ascii?Q?0T0e8cZA6FdiemM8O1f+6tZbhQVyNO2mWmw/yE5qi6kxFb5tuvLMCM9k2UvI?=
 =?us-ascii?Q?1/XYS/Wxuv9Eke6o6/DOU4C3D9mfRiYXtDXseJUJkjxvgd+pMu5aP7e5b9tk?=
 =?us-ascii?Q?ctRPYoCt97BH0QfxxTV1xgRckYMiKeu/JNKJUQtESkrAejyAGOyNzPD7mEUi?=
 =?us-ascii?Q?v54RndgMs+6NNBeKOdbnrrOw8lNtI8oxoOtXFuUXeh6fqS6DPQVYWLeISeXB?=
 =?us-ascii?Q?sURG8Qba2hmHYqFqJUV1CypU7L5TBeLfYJyrJq4HJU4pSUxlfWyWkihzhaAy?=
 =?us-ascii?Q?Azs1w2F8XaJlb9Ho7cc16JmDWHMN3m7uoaLjtlAP8oZfw49GOBYe8j2m3hVT?=
 =?us-ascii?Q?zAIi8QaPPkhRTzw3RzYrRVWaVZ7CF4n13QaOroC8?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: JUywtE5Ea6IGkQOw6l40FuRNeSQzNkL93+7GEqWQ3gsUjRAQG5PleEwOdGsDGS0jjZUmNSMpTPD19fvMJ7TCe3Wvgr3H/lD6Pjq3LIpv3mNSYEZSFcFeX+jMNl4F7So9x8KZVMxLnFtOSDWZdNnZjVSTP6dqZMPU7MnW7BpFGsXlZrkon1Zng0ttmY1Tu2984FiVgXnrb4FKi7DC7FvAlkxnKUhBSl8/KJCmGAccWa6V23f0woeaaE/VknQPi3fa3Gc30zxeovRneAMXHwE5lll6Vpg+5eGnhUFL8w/lGHywMsFm19DlmBIOW6i7O0L+2/ZDdjmnjkIaqX7a8xMyJ8d80rVBALpXk/Cm5hS3oEua03FlV60skTGAPb+4D/1iQraB2xm6SRvYm3shjXljRfET0GomkQv56Hz3bx3c2CBqQXES8Au2X+reZ1soEkLfa3kwTDgZHK5AI3/zLbB2UklTatZCiQ2FUnCnS+RWe6Ec5ouAw9eGkc4WNeSx6aMC0DG7doLnoyaEmvx7lIR9s+6ot1v1Nvq5xMrk2e61r7wvYZTHIDC5ZacrMZZxjPLLQuAQNQ/AOtFovnH60JkNYLjxa7wdv6JW+4ZCWZvyRgE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 505dc15b-5bad-4137-2cf2-08ddd898cae9
X-MS-Exchange-CrossTenant-AuthSource: DS0PR10MB7341.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 11 Aug 2025 05:34:51.1065
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: qaJduwqU4wMZz6jS/8AapQx2HNRZIg4NTlzRSRiev5KdH3UfpYYtM6C9tZvLMQ1e5K6CzKBVbleOUvR50j6A1Q==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPFA0AD88203
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-10_06,2025-08-06_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 adultscore=0 mlxscore=0 bulkscore=0 spamscore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2507300000 definitions=main-2508110035
X-Proofpoint-GUID: 1LN2ldAisvf4yv0dUp9Sq6W5KZCjZ-zJ
X-Proofpoint-ORIG-GUID: 1LN2ldAisvf4yv0dUp9Sq6W5KZCjZ-zJ
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODExMDAzNSBTYWx0ZWRfXyaLbvAiokImk
 vuFFUNMIMYo/RJjAziWqLxV6gQfeqo/YjgVFIMCkcWMkG/1Pa74tp/qBFR6yVY/NLx1Ff8zilmU
 RvPydGkItQ9SYMl9iz5heUpqZr+7HZt7xApV8jcnMYeDxt/wqsquemHvuUn3h026n+z66mIdnXi
 6Gh1wJYLp7AvWMyaqTB+wnAs3i3v51SahqisJ6RICLUe9v+A2C8Cq4t/h22uzypEcSZu7uHwhd4
 lL0TlSjbdlFy76qhjG598XUPYB3vCyHQUEviQhTwtA/JY1h/zYQ/4LcnPli7hTOI34vPKocovxM
 6jaBZmmkWhyCJ72G5QrAVqYjOjuB+d6iCkufBktDwFjQXtkuDTXNkTNcf6h6S6RgMCK2R8Vlg6X
 fA5IVVZkhjcwZH5IaXF0sTKxYurJBTRFIOTepEpdFxGUT1MvE3xEVWPLLmnPjj7QIQdt0JfR
X-Authority-Analysis: v=2.4 cv=KJZaDEFo c=1 sm=1 tr=0 ts=68998100 cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=2OwXVqhp2XgA:10
 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8 a=yPCof4ZbAAAA:8
 a=vuXxwHPmmX0stN9n5g0A:9
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=ot41yEhp;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=APDc4ElL;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

Introduce and use {pgd,p4d}_populate_kernel() in core MM code when
populating PGD and P4D entries for the kernel address space.
These helpers ensure proper synchronization of page tables when
updating the kernel portion of top-level page tables.

Until now, the kernel has relied on each architecture to handle
synchronization of top-level page tables in an ad-hoc manner.
For example, see commit 9b861528a801 ("x86-64, mem: Update all PGDs for
direct mapping and vmemmap mapping changes").

However, this approach has proven fragile for following reasons:

  1) It is easy to forget to perform the necessary page table
     synchronization when introducing new changes.
     For instance, commit 4917f55b4ef9 ("mm/sparse-vmemmap: improve memory
     savings for compound devmaps") overlooked the need to synchronize
     page tables for the vmemmap area.

  2) It is also easy to overlook that the vmemmap and direct mapping areas
     must not be accessed before explicit page table synchronization.
     For example, commit 8d400913c231 ("x86/vmemmap: handle unpopulated
     sub-pmd ranges")) caused crashes by accessing the vmemmap area
     before calling sync_global_pgds().

To address this, as suggested by Dave Hansen, introduce _kernel() variants
of the page table population helpers, which invoke architecture-specific
hooks to properly synchronize page tables. These are introduced in a new
header file, include/linux/pgalloc.h, so they can be called from common code.

They reuse existing infrastructure for vmalloc and ioremap.
Synchronization requirements are determined by ARCH_PAGE_TABLE_SYNC_MASK,
and the actual synchronization is performed by arch_sync_kernel_mappings().

This change currently targets only x86_64, so only PGD and P4D level
helpers are introduced. In theory, PUD and PMD level helpers can be added
later if needed by other architectures.

Currently this is a no-op, since no architecture sets
PGTBL_{PGD,P4D}_MODIFIED in ARCH_PAGE_TABLE_SYNC_MASK.

Cc: <stable@vger.kernel.org>
Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
Suggested-by: Dave Hansen <dave.hansen@linux.intel.com>
Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
---
 include/linux/pgalloc.h | 24 ++++++++++++++++++++++++
 include/linux/pgtable.h |  4 ++--
 mm/kasan/init.c         | 12 ++++++------
 mm/percpu.c             |  6 +++---
 mm/sparse-vmemmap.c     |  6 +++---
 5 files changed, 38 insertions(+), 14 deletions(-)
 create mode 100644 include/linux/pgalloc.h

diff --git a/include/linux/pgalloc.h b/include/linux/pgalloc.h
new file mode 100644
index 000000000000..290ab864320f
--- /dev/null
+++ b/include/linux/pgalloc.h
@@ -0,0 +1,24 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_PGALLOC_H
+#define _LINUX_PGALLOC_H
+
+#include <linux/pgtable.h>
+#include <asm/pgalloc.h>
+
+static inline void pgd_populate_kernel(unsigned long addr, pgd_t *pgd,
+				       p4d_t *p4d)
+{
+	pgd_populate(&init_mm, pgd, p4d);
+	if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_PGD_MODIFIED)
+		arch_sync_kernel_mappings(addr, addr);
+}
+
+static inline void p4d_populate_kernel(unsigned long addr, p4d_t *p4d,
+				       pud_t *pud)
+{
+	p4d_populate(&init_mm, p4d, pud);
+	if (ARCH_PAGE_TABLE_SYNC_MASK & PGTBL_P4D_MODIFIED)
+		arch_sync_kernel_mappings(addr, addr);
+}
+
+#endif /* _LINUX_PGALLOC_H */
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index ba699df6ef69..0cf5c6c3e483 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1469,8 +1469,8 @@ static inline void modify_prot_commit_ptes(struct vm_area_struct *vma, unsigned
 
 /*
  * Architectures can set this mask to a combination of PGTBL_P?D_MODIFIED values
- * and let generic vmalloc and ioremap code know when arch_sync_kernel_mappings()
- * needs to be called.
+ * and let generic vmalloc, ioremap and page table update code know when
+ * arch_sync_kernel_mappings() needs to be called.
  */
 #ifndef ARCH_PAGE_TABLE_SYNC_MASK
 #define ARCH_PAGE_TABLE_SYNC_MASK 0
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ced6b29fcf76..8fce3370c84e 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -13,9 +13,9 @@
 #include <linux/mm.h>
 #include <linux/pfn.h>
 #include <linux/slab.h>
+#include <linux/pgalloc.h>
 
 #include <asm/page.h>
-#include <asm/pgalloc.h>
 
 #include "kasan.h"
 
@@ -191,7 +191,7 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 			pud_t *pud;
 			pmd_t *pmd;
 
-			p4d_populate(&init_mm, p4d,
+			p4d_populate_kernel(addr, p4d,
 					lm_alias(kasan_early_shadow_pud));
 			pud = pud_offset(p4d, addr);
 			pud_populate(&init_mm, pud,
@@ -212,7 +212,7 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 			} else {
 				p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
 				pud_init(p);
-				p4d_populate(&init_mm, p4d, p);
+				p4d_populate_kernel(addr, p4d, p);
 			}
 		}
 		zero_pud_populate(p4d, addr, next);
@@ -251,10 +251,10 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 			 * puds,pmds, so pgd_populate(), pud_populate()
 			 * is noops.
 			 */
-			pgd_populate(&init_mm, pgd,
+			pgd_populate_kernel(addr, pgd,
 					lm_alias(kasan_early_shadow_p4d));
 			p4d = p4d_offset(pgd, addr);
-			p4d_populate(&init_mm, p4d,
+			p4d_populate_kernel(addr, p4d,
 					lm_alias(kasan_early_shadow_pud));
 			pud = pud_offset(p4d, addr);
 			pud_populate(&init_mm, pud,
@@ -273,7 +273,7 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 				if (!p)
 					return -ENOMEM;
 			} else {
-				pgd_populate(&init_mm, pgd,
+				pgd_populate_kernel(addr, pgd,
 					early_alloc(PAGE_SIZE, NUMA_NO_NODE));
 			}
 		}
diff --git a/mm/percpu.c b/mm/percpu.c
index d9cbaee92b60..a56f35dcc417 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3108,7 +3108,7 @@ int __init pcpu_embed_first_chunk(size_t reserved_size, size_t dyn_size,
 #endif /* BUILD_EMBED_FIRST_CHUNK */
 
 #ifdef BUILD_PAGE_FIRST_CHUNK
-#include <asm/pgalloc.h>
+#include <linux/pgalloc.h>
 
 #ifndef P4D_TABLE_SIZE
 #define P4D_TABLE_SIZE PAGE_SIZE
@@ -3134,13 +3134,13 @@ void __init __weak pcpu_populate_pte(unsigned long addr)
 
 	if (pgd_none(*pgd)) {
 		p4d = memblock_alloc_or_panic(P4D_TABLE_SIZE, P4D_TABLE_SIZE);
-		pgd_populate(&init_mm, pgd, p4d);
+		pgd_populate_kernel(addr, pgd, p4d);
 	}
 
 	p4d = p4d_offset(pgd, addr);
 	if (p4d_none(*p4d)) {
 		pud = memblock_alloc_or_panic(PUD_TABLE_SIZE, PUD_TABLE_SIZE);
-		p4d_populate(&init_mm, p4d, pud);
+		p4d_populate_kernel(addr, p4d, pud);
 	}
 
 	pud = pud_offset(p4d, addr);
diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
index 41aa0493eb03..dbd8daccade2 100644
--- a/mm/sparse-vmemmap.c
+++ b/mm/sparse-vmemmap.c
@@ -27,9 +27,9 @@
 #include <linux/spinlock.h>
 #include <linux/vmalloc.h>
 #include <linux/sched.h>
+#include <linux/pgalloc.h>
 
 #include <asm/dma.h>
-#include <asm/pgalloc.h>
 #include <asm/tlbflush.h>
 
 #include "hugetlb_vmemmap.h"
@@ -229,7 +229,7 @@ p4d_t * __meminit vmemmap_p4d_populate(pgd_t *pgd, unsigned long addr, int node)
 		if (!p)
 			return NULL;
 		pud_init(p);
-		p4d_populate(&init_mm, p4d, p);
+		p4d_populate_kernel(addr, p4d, p);
 	}
 	return p4d;
 }
@@ -241,7 +241,7 @@ pgd_t * __meminit vmemmap_pgd_populate(unsigned long addr, int node)
 		void *p = vmemmap_alloc_block_zero(PAGE_SIZE, node);
 		if (!p)
 			return NULL;
-		pgd_populate(&init_mm, pgd, p);
+		pgd_populate_kernel(addr, pgd, p);
 	}
 	return pgd;
 }
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811053420.10721-3-harry.yoo%40oracle.com.
