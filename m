Return-Path: <kasan-dev+bncBC37BC7E2QERBAGM2LFQMGQEO43PH7Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 9/zkCwOmdGls8QAAu9opvQ
	(envelope-from <kasan-dev+bncBC37BC7E2QERBAGM2LFQMGQEO43PH7Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Jan 2026 11:59:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 806817D539
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Jan 2026 11:59:14 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-502a13e3e55sf113037521cf.3
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Jan 2026 02:59:14 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769252352; cv=pass;
        d=google.com; s=arc-20240605;
        b=UGftriXlIg4lkQ2bj62bhdJEo8lt8tpt05V00hK97v/Sjcqli4B4YbgUHWFlwiaiFx
         dsKCp8SQIkORAgYge3WXmDIFTMbc+NbMKUfck9i6Ewf10W2yoLxskjsz69ofFZKiMTCk
         WW/99NSf+yIp7uLvfcI1GNkklpyWIvIbpx0KOGMgJ0WO3tc7q1ACKHs6xQaz32zhAIgA
         OpmUE4eHDWjd9S4vxyfdozszaCmAMwQsyFPkKvcfopdg2JdQtjBQi5FLL8WFaIL3EpCS
         XHhpH8hoch2P/OqU2UD/N9r2TNBk2FB2+mEntrlq4nFoBpj0ZB/Y/r77Pm+HO4fc8zCM
         bIsA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iKcmfpVinzATZb66/2EQKgGVWnJnXDnT8bS8ZGTjRlc=;
        fh=eG+z42CkVXMM0f0BykvNYUhtrXxDyPLi5VkeGcJiInU=;
        b=E4U4C5bXm3Ns4CX1zYWgKs/2lKpzsLsYR5bzZVTIHCA821H8omXuPqMfgax9gofJMs
         f9jczph1LXroLW2b4ewgCF0icvws1nIRs4cBh9s3Ru0F0+DNRfmyeQPQ5SIhOxfscfkh
         +3NPQ+M49f8WOx7KtAtFex31iUCCc6LvXQNxT1f1ZKg4WsNjF41p5QBEIif1OYsedVES
         L2231DFiNaErlJvxmMymP1rZb8JmD/rvroLV5ccqc3NIsCg8/pVpvinwb378VUKklW3n
         mPafoCM+5AqlqIB2HJD1xnHi8Qc1JUYuPFYHH1EeI+OaIthWwCXYGTaDN89WP8w8iOVH
         PGbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=FgxvEChg;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=pxX1YsVb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769252352; x=1769857152; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=iKcmfpVinzATZb66/2EQKgGVWnJnXDnT8bS8ZGTjRlc=;
        b=HuepYezm0cpQ7KdAmqDyieXdrssmcrh5vpHwEaJa3nEO/u0KXpQ02q0AzyGFWAfYaf
         f2QOgQEJvOh7rP8armu1XzBM+24Snbdcmz0IsadDy3n13/CgYQ++bpvp75Uu77aSCqCR
         hrHgaTBmjaiYdLM5+tD2nzJsSO3rG81thIeRTn9z8MYUNBn1CtUJPtDJaAZOlbEZG11B
         HtayR3knBB0h1Dyb2sf4vO55aKPSNbJJEn7smY9zxdJ/Rfkd0iNz+BzDsOGJ2z1zDQtN
         qI6BzGzZUmvE0Ws42u+YFiQMDq9HiRt3sz0+UK7J/9W62u1lWP66oUIkqJxNqLXWNU3V
         RiTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769252352; x=1769857152;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=iKcmfpVinzATZb66/2EQKgGVWnJnXDnT8bS8ZGTjRlc=;
        b=kMcDpgvO4l4yprHxEs26nkFCQz7wLuzfEd4VW7tnwq1uxPGJaXjfjRPR2DRbHpgRbd
         KMvo2QyPTDnZtR8NtIilnP1xldg4O8mzg1rdp+9pT5UDTbqmcvIZ5CULHtMam94Mmnij
         KrSaH8Tg7mo5jZi1Jo8o+XWDZEu1mV86xOvYS24d0+n8MQ3TBo9I0ScKkfOw78PUenW7
         OMOTLSdKlSHunnUKIsQhNzZ0xSbiTuUl7QiFQXAxZi7jvN7TdcCdMDrm4u6wZTFSpimL
         ZfRqWhJ1KtSOUfDPdOmWmv0MsGWC/kkq3iA7eIwPYthssrfUHdK4oXrqRaiUdsbj7KHs
         H6Sw==
X-Forwarded-Encrypted: i=3; AJvYcCXeg7hvBLdTj46L6soaObp7lgwSaqURSfpRMlOo+efqnLImcHuRWu85wKplSjy/a6lZSTlS4Q==@lfdr.de
X-Gm-Message-State: AOJu0YzNIr5X2ITXWZNCkoBP5vNxRzdlk4U1F3ELpTEoU2rAQYZXWC0q
	zkm+T3Lh/qLHaID59dxAzyw3pKWZ6SXXz9tgiZQn6MmWpPc4VVWBiUTL
X-Received: by 2002:a05:622a:243:b0:4ee:4a3a:bd07 with SMTP id d75a77b69052e-502f77d3657mr80298921cf.75.1769252352278;
        Sat, 24 Jan 2026 02:59:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ETRI87v88Qt+wtUqHMdgxZd+PCjrFsJHaKQu+ehakMtA=="
Received: by 2002:ac8:7dd0:0:b0:4ec:f039:2eda with SMTP id d75a77b69052e-502eb895f4cls48384981cf.2.-pod-prod-09-us;
 Sat, 24 Jan 2026 02:59:11 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUQGaKvIwVRtNrEKfaPsc28C16HcB2bKnUIWNIABRDJSs/VBbmJiMhLR87Mr7JxyavTFKEaMF+dNoI=@googlegroups.com
X-Received: by 2002:a05:622a:1a9b:b0:502:a2d8:453d with SMTP id d75a77b69052e-502f77c8fedmr80538961cf.66.1769252351262;
        Sat, 24 Jan 2026 02:59:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769252351; cv=pass;
        d=google.com; s=arc-20240605;
        b=eH2d7UIvGlYzX8H+HOtWA37P6MvD+z9tubqCkzKy/tKrrD9epUZHyg9kinvXTbO7e+
         BGdtKK+P56spCIiO1FjScB6pscvakuAsvJwHt/GPeEiSc+ZApqLkOtDR2B0K26jtAuEg
         kilhQB7/tPisJUcyain7j9jb8av3rk2qVUOfhZ9Re2NMKfb1MJts0n21rKniGub8++q6
         +1oyDPwBIT+quzmAaiLMZlqj+V8lAEkd+EkZE5P10NGMB5YPZLUY/wZ7t5FoeruNE9+V
         56cSwPgSMStJgn/m0RhlN0FMeCuZ2MRYVopjyZxseM7orAiJ5fELkuRv7m4PVm60nlFP
         jubA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=VX7f81QyBjum/NVUeIyMq3FxYMdh+OvZbCxF0gmR1pI=;
        fh=BD7xwyIiwoFSsOvXaztGWwMtQqD4/7Cn5hgx/2eq2L0=;
        b=WohnYiKL7EbTpFN3biKhNEJAwU0zpsbF2Ysd0KIuAp3b86cygTXv/bT3OgdEszr80Z
         DdzMNfBK9vA4+8dIEDrH8nfCKt7JSl/JdOonRH4u++lmY1Zg0uybbEydowPMYAMmRh6M
         65kIkHqsG77awXhFhjFH+kvicDRw6OmPRK+FZ+yXQTIRbsbkM7B6XI9z8itl431SAh1n
         HdB+oQ4dzEaLfG/UQDtLdePqSMK2+3LmlEgfYhU4P3FVay+Mdl8NnfvmU7H08UJdS+5U
         8yYhGh0GPdOXo69gulZ6XXdLOBpaQ1dOuZ7UKCWOZxPWTN4zO2t2vzyhe2ve9f7cNh77
         dr1w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=FgxvEChg;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=pxX1YsVb;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-502f7f77cdesi1707531cf.7.2026.01.24.02.59.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 24 Jan 2026 02:59:11 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246627.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 60OAkusK560979;
	Sat, 24 Jan 2026 10:59:07 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4bvmny06u3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sat, 24 Jan 2026 10:59:06 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 60O8AHPP019814;
	Sat, 24 Jan 2026 10:59:05 GMT
Received: from cy7pr03cu001.outbound.protection.outlook.com (mail-westcentralusazon11010039.outbound.protection.outlook.com [40.93.198.39])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4bvmhbkx20-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Sat, 24 Jan 2026 10:59:05 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=QfgSebBi0pVukO5sordencwtVzs+vE9Veayzkg/jzL2OvV5AWustj6f3khTjMcYWYku2vRfcvA22Xl+DXpV92THGMcDMbA+I4I+tk1EcrKc7MHWbtLutBel3QutXJfavlklEwar/9QmEU37RIe8/mVB9QVk0OZ1GbS7P1/3eoGvc4XhnMIeK9fzuTp8P165LFRNVj2AXMnIivLDzgMreUyp1S9T0d1/UNNhX6GfrTZSOqpINyF8V+42PB+6WRvYVSqX6ZTU1mWTou8y/JJpV8I+whgbOE1rkVXYu9lrpemR7SOTnE4Lfw02pCTRVw8R4FbupmCiu9/zM8hHSQPnM4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=VX7f81QyBjum/NVUeIyMq3FxYMdh+OvZbCxF0gmR1pI=;
 b=EYteh+5SjEqn/m7FPjQFaH2KqIx3Nprexk3y2lYmVOIYXMpi1qqIVjW6LslQOmg2go2I8LVkYiWbk7jhjbbtaC/Jpqprronfa161afymPqn42W2ebs+bp4uuUmQueYGfTppqejt5JlEJfZ+xbr7XEiUOeGcTpj2/abzF4P8Ie4I6zX+dr+pu5soW5R6M97SJR2BrFWbY2+OpioCDuFtiBjVxIOMu7pFtNKRIqXXOElDQFuGGPP46dFqNOmiit+Qp6K/ielaGl9IQtAVhkzSNAwcMyCVFfT7TEJQgWbgCKLqbtQrZC3nSoEfiFH+fhmXO8nefYqi3+mRCelgXSnVjZQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by BLAPR10MB4916.namprd10.prod.outlook.com (2603:10b6:208:326::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9542.14; Sat, 24 Jan
 2026 10:59:01 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9542.010; Sat, 24 Jan 2026
 10:59:00 +0000
Date: Sat, 24 Jan 2026 19:58:53 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Vlastimil Babka <vbabka@suse.cz>, Petr Tesarik <ptesarik@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
        bpf@vger.kernel.org, kasan-dev@googlegroups.com,
        "Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH v4 02/22] mm/slab: fix false lockdep warning in
 __kfree_rcu_sheaf()
Message-ID: <aXSl7V7wyiqP5dPB@hyeyoo>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-2-041323d506f7@suse.cz>
 <20260123120302.TsiVMAQb@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20260123120302.TsiVMAQb@linutronix.de>
X-ClientProxiedBy: SL2P216CA0118.KORP216.PROD.OUTLOOK.COM (2603:1096:101::15)
 To CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|BLAPR10MB4916:EE_
X-MS-Office365-Filtering-Correlation-Id: 5f63c679-762f-4c6c-9c84-08de5b379450
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|376014|7416014|366016|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?bFo3ZVkzTm8yRjcya2NmUzMvVE80N3haM21rSEYxYkRueTVicFFGdzNlbnN1?=
 =?utf-8?B?czBqRjZ5Zjlwck5WblBudlNJWUVqeWlRSEVOa1V4M1duRHE0Z1FMdVQ1aGpn?=
 =?utf-8?B?cmRyS1RLVUJBTEFtMkRBQjBrMVo3MzcvMWxwQ3d3bVFrbFFTVzBGbU5IRHhJ?=
 =?utf-8?B?bGlMNUQwU3ZMa29lc0JuUk95Z1JLRkt0ZDI5Q0t0aDZ6MkRIV2dYc1ZxTWFV?=
 =?utf-8?B?RS9GL1phRFV3R3E3bm50dGIvTVZlK2E3K2dudzdROTY3VGcyV3FxSVVOT3RR?=
 =?utf-8?B?Y083a3FNck1UTnlQNGVETWdQMEJOWnZvekxTdmVsTE9BaXM4aVc5bVBTaHJD?=
 =?utf-8?B?dkJDMjEwdW1LWi9LWDdGZHk0d3RxWHM5cGo3b2xmRERJb0VydE96UXNSK084?=
 =?utf-8?B?b0RScW5oUFNxQ0tHYlh5VVhJTDIyUkdlRTVOTWdUZzVKSVk0eVNIbENlbDdw?=
 =?utf-8?B?T3M0MDRnYTQvajN6Zkx2bnZWY0dkbHNITFlUUVpHell0cjBhYVdlSWlCTTVL?=
 =?utf-8?B?WlUwSk12dmhqaVgwVG82M1VQMVJrTmlBbW5HRldhTlZMK3gvOTZCcTE5eFl3?=
 =?utf-8?B?WWVNMzVZQXAxSUhuNTF5ZmNXSmhUZ2s2VjFwSjlMVmVmb2lHeEVLUk5lRlVE?=
 =?utf-8?B?dkR6SW9aSy9rRHhuUmlmeC85Y0gzN3dBN01qT3RLTE93MVZYVjl0UE1BbEd3?=
 =?utf-8?B?ZmlkWkR4bDhyajBtaTNvdnVQNGQyMHFaZnhJbmFQQ21HeWZWQzFjWDVXZnpF?=
 =?utf-8?B?bTBMLzdORzhoS0h6ZzBtejVteXJKZWZyRElFVVJRK3dzNjJrZ3hjRmpQVU9D?=
 =?utf-8?B?NDVxVVFjN1RvMURyWmd4MEwxRzZScFljVVFONGViQU51RGJzcXFtZFRpbGhL?=
 =?utf-8?B?UVJ2MzF2UzhZM28xSjJqWEtWK1JBNnZ0cFBBcDJwU0hRMGE2aXZXNitxYjNI?=
 =?utf-8?B?L2hnc2xPMUVGb0sxd01YR2l2WmJreDEzS0lsUkx6WnU1aERkRUdMclFmdndV?=
 =?utf-8?B?Sk41OHFJd3pKUWlpYmZUNTlLTDRqOEs0NllrMmg5YkNZRkRsWlBYaXBOMEYv?=
 =?utf-8?B?WWZjODZMcWJVM2lXaDNOektMbzVkWm1uUXNDb1lPcHpwVzJLb3FBL1U4Mk53?=
 =?utf-8?B?UUNLSjk3R1l1ZzFCSFE1MGhHNkxsT0l6U21jdVI4bUswOGNHeHZjMVRlV2dk?=
 =?utf-8?B?a0ErZE16R3p2NXBENFcvWUdSMGdXeU91ZHI5NFN0VE55OWNNSlZFSmY2L3Mw?=
 =?utf-8?B?TVhRS3RvZUpMUnNqdXBpc0pXM3JRTzk2cUtkM0JlcnBoaXlEREUwbzFLdmdl?=
 =?utf-8?B?OGxLNE5jWjJUMUFwdmJGQzdwRGErc3RCbHV3dENZUkg5b0RXU2dYY0pWeE1y?=
 =?utf-8?B?SU9vOGpGZ1RTODhNdmlNOFBKVDczWkxmZHJPK1c5SnZEdGR0c2VscmdwU2FU?=
 =?utf-8?B?R3F2SzhHMWVnTWxHQW4rb2JZOGM2OVJiVGoybkplVEp4MDhYNDZ0UlhJYlIy?=
 =?utf-8?B?bkpZby9rTVNSVEhrRTdEb0dTRXFscWNnTi9QSGpVRFRjc05WMmdZYW01bmxF?=
 =?utf-8?B?MlFOR09JR1NzNlViQWoxTXJrUzV0a1NvVXd3Z3RwcVdEQ3NsQk9XRy9MWVNy?=
 =?utf-8?B?aTJxODFGSXRyMWpVWDBkSUdXTEIrMlFuTFBtUHQyMmpNQlR3NXkzWHJlRTFs?=
 =?utf-8?B?eVBEYUQrMm95c2pXV2E3RDRicGE5OGJMSC95REwwRzYxZm81SlNnRldUWXVB?=
 =?utf-8?B?T2twODh1bzZzQkxKREgzL2ZoVGZDdVUvTk1RdGZheHNVdk9ydk5ObGVhV1U3?=
 =?utf-8?B?ZnVPaXQ1MnFxRk1HQzh2TjV6ZDd5MkxFV3BIZldONEFrSGJndHBzWFJKdXQ5?=
 =?utf-8?B?UTJKS05RN2JTYXRwQUpZUllKSlY3WWFINHlwNGFtZU9JanE2UU9paVVoV1Vq?=
 =?utf-8?B?ZGdGSjJGN3lOYzRmZC96U0NIcEM3cjY1dmswMmFMUHFBbzZsSk1xWHphVG54?=
 =?utf-8?B?ZmxDSk92T3YrTi8yWDdJbFk0cjBic1Z1bEt5bUh5aEg4M2NWcjg0WjVrSjVC?=
 =?utf-8?B?eCtrQXZia081NmdsQnhLK3htQ2VxMTNIZG5tdFpUTEhCdVVIUW5zOHlLbmVC?=
 =?utf-8?Q?BZgo=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(366016)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Z2wwY09wd05EaWljRjJrZHpmd2p0bWJvS0tBUDdSVGVPWm9JSys0Q1VldXpK?=
 =?utf-8?B?Mnk3TmJwV2I4RGhmbVdHVkNYNGVLODFpYzMyMUxzODVvbnkyZktreVFPYWlV?=
 =?utf-8?B?T3hnOWhPZmlOaTRPMnUvdWFSYUYzNFJiL0dmczdvazJmZ2tSdkN4djV6S2oz?=
 =?utf-8?B?M0hEKzFndVRiUk9Ea0NYd0FDRFFaZVFBNTkrVGdEcUNSUWg5M0RnZUQ2aDBE?=
 =?utf-8?B?TVdtWXc3WU41MGQ0N3kvMWd0UG1pZUZkaXkwWVl1N3dpdzBZeEdzRVlLWUZZ?=
 =?utf-8?B?TkxmcTZuYUJwVkIxb1pFSk5aSFJ6QkRMMFIrRnV4ZHlranBzS2FkZVJ2UGtv?=
 =?utf-8?B?Y3ZRRnVtNkJtZU5wREdDeUZxWitTMzdlV1Z5S3U3UjVadEwyb0Q0M1IyTVJU?=
 =?utf-8?B?c2tTdDhGTkpQQzZLWmJVT1NVUUdwdWUwNHdLUnAxcS9UUXFGMlNoSm1RS1d1?=
 =?utf-8?B?dmNPWDh6dUFZenRVQ0ZtdmcveHlQaktNOFRKQ3Z5Q1lOQURHbDhJN245dXZo?=
 =?utf-8?B?a2NxWUNYa2ZhaCtEQlBNRWgvWit1QnlSYWJMTEdNem1LcU03Umt2Qlh3NEdQ?=
 =?utf-8?B?ZEQ2bUFkR21yL1NkZGc4MmJ1VGlTYjc3cXhJZC94bUNBZXcyc3c3TStEVk0v?=
 =?utf-8?B?dFdnNm5kSG55Wnd5UlhoZ0JaK2w4UEhsRHpGTVB4TGY2bFBpbGhCMC9iUVE1?=
 =?utf-8?B?aTMrRHdRaDhrQzdMSU5VQXRpWkxmRGFYRUt2bHRIUC81cWsvZDI3ZG42RUtB?=
 =?utf-8?B?eEpORGJIZlloOUR2RnQvQXpxblFDYVlPSXNiRXJYVGRPREkzNTlvT3FMbHlq?=
 =?utf-8?B?Vk1TT1VXeFIwZElvR0dtejFtakNnSUVBcjNZc1lqQlF4ZVJwQzAwTmYxV2Zl?=
 =?utf-8?B?SDVLaWRQeVpjaS9TeTRCcUZNcFM3dmNmaWhwOW5wNUFuRVZPZStXbXBEZS9Q?=
 =?utf-8?B?U2I4ZlRYZmIveFNXa0JEWW1ieUFvVnJyZjhldGt3cnhlaUpBTVpPdjVzNlBH?=
 =?utf-8?B?UWQvdEZSOWl5d1pwRjdrV2lwaS96dzJ0TTlhaWY0Sy9zN3FkU2tZQzB0cnoy?=
 =?utf-8?B?ZklFV2I1RzdkNTIyYzF3RGY2dUxodjByaUZQMWpqV1dPTTFMZEFqQ2dyRGQy?=
 =?utf-8?B?djYwdERKYkZMYlp4R3d2WU9nVVZtMkZnNk9ucEpOUjdQaTRSTlMzVkxOOEZ2?=
 =?utf-8?B?K2w2UnZUb3VmT1JkK3lrazJYMWZxQThHRVpHUDdkWDdsZW13bG5uV2pRcnZ4?=
 =?utf-8?B?bWhPcWlNZTUrdkZ5ZWNOOXpkV2EycW9HQnlkZ3NuM1VRdURXNW9MTmxPVVNQ?=
 =?utf-8?B?WER6L3RUQm0xbjZoTTJpTEtVc0JQMkpPNVZ6OG9NcFUxZDJ1V2pSMnFkMGFn?=
 =?utf-8?B?VHF1UjB5YlNma1JjZExydGFQWThSS3drN1hIV2ZJNG9jT0lrVllTQ2tjSGtX?=
 =?utf-8?B?d3doR0JLak92VlNGVlkxekh1NkhmcEhrb2prQ2xiVGZOU1NQZFdFTWVUWHhp?=
 =?utf-8?B?T3B0MzNndmttb3RQMXJoV2IrSFpraDk1YUViRGF0RlI2YkxnazNud0dQM1Fw?=
 =?utf-8?B?cFd1UGcrU2pnakV2Y2diNHJPZlVwbzllM3JaN09EUVZ0eGUwMUlaMzBTVXRN?=
 =?utf-8?B?NEhZbmJUeFBwd1Y3YzlMbHRzbWRza1lMTzhsV1FaMnEzRzF6VDdrMWIvV0hZ?=
 =?utf-8?B?TFA2OFFFaVh3QlNpcURUTStRQWxYWDU5bHlxckZnMEtEdG9UWVBzeEhoSng1?=
 =?utf-8?B?R0xWWDZNYkZJd0xweG93UUQyQnpDekxwV01XRzdmT0JHaVJUcjd2K3c1aEJp?=
 =?utf-8?B?YlJuaVdxQjJJMThPVWpkdUlGNFdOb3hpa0lNTUhQOEdoUDM4SFpGdU1UV1VB?=
 =?utf-8?B?c3lILzA5TEFZaHRlZ3k3bHBLZGs3SVRSTU5iempSeldrVmw4NCsya0E5NEFj?=
 =?utf-8?B?cDROU3FTcHVPTmJHaFlGMHF1NXdsOHU2UzdHbWttYTkrY3FGRlNxTmo2ZFJW?=
 =?utf-8?B?aFUwZndKZWlvZTRwTG16Y3U4NWFabnF2cDZnOXhMU2x5d3ZDQUdIeTVPc2xv?=
 =?utf-8?B?NXFQSklWMWVoeGtVdndEdzJkS0w5eXVQeWc5OHdXbzkrRDljWHRHL1R5T1NL?=
 =?utf-8?B?YStaWnFyanEzQnN4Q1lEeFNCbGZiSjZwS3JYVzk1Y1B2dldBY0plVm5PRTZR?=
 =?utf-8?B?dnh1NXQ5cyt1TEtHNlAzTm9hR1hhSlpBMWN2SkhUSHNra2pzSDhWbjJHaXl4?=
 =?utf-8?B?cGNZbEJFa2pSb0h1bjNBS0hERkZxYWIwVkczT2p0YndpU3JHZThlOGMxMnhZ?=
 =?utf-8?B?Q1hNeDhodzM1QlFWRnptNE4xemR3MlJPRXdWMUQ1RmJWYzBNblk0Zz09?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: u9MscleD1DGi6TYRgEDQC5suZVcxpeMENjqmzQTDTtQLGJwKLoqT2DODrL5ojCdyVb0GTk2+XqrQalRwIld+HdEf/l/ZE90mn9tp71TGCykgqUknZq9qCcjz29GNwZUy2vNWp97SkyhUQnLziJpNLTgl6LJuUvE3QGPzMF+qLzHu3JHRQdQSp9F6I2GBqXxKhCUBBPrOw4euLsCQT6uKr1gglpTe908kXBplfCYK0pUoC1/l6iLJVsHdfLmrAbh1iy9BUgqO7CCLjx8uHYhzomQYEiPSH5L71wnzcIaYUhvMZ1gv0RD4q7eWoW7xTEK6N0yIg6zTfbjEYxRWL1OcVe8Rl6JCCz8aTkG0mSn/pQ7C5yivANptkFCYT7p9/CylgavA/cUpHpc2AX7n76RWHeTaNciBQ3KakxwnkZFNAAYn7i+drTpx1roBuEalIJaLf5bDrtrNz2QADMZiF+ld3RfiXedsgJEQkZPSNutx9DxYc8SlVz1d/03XMvZhcvMXoYX9aArL9vD6L6karQ3xQ5mjcFlHG4AWA96qvYdLsKjsFiFBmw6zwJx99HkegMRTau86WOBEZ942/TDwpCejzKflhDARsDmt0xA3q2j5jAM=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 5f63c679-762f-4c6c-9c84-08de5b379450
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 Jan 2026 10:59:00.5872
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: UIkcPCy4b1HdZSDF9RF5vOATGrl1RRBydiXll4Lf3iSKWPRX2yidzQolH8vwI1+ttL3F1PEX/RWPTDLNHH139Q==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BLAPR10MB4916
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.20,FMLib:17.12.100.49
 definitions=2026-01-24_02,2026-01-22_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 bulkscore=0 phishscore=0
 mlxlogscore=999 mlxscore=0 spamscore=0 suspectscore=0 malwarescore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2601150000
 definitions=main-2601240087
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjYwMTI0MDA4NyBTYWx0ZWRfX0Pyu0ahOv250
 oScvGS/nY+FKJa4bCDIp+dwwSMcWFKzBOP8PSxZ6+FAutdZ/UeO+sLHEcBGU8q5MyAlnx5tT8I4
 5EmZIxX1b88T/APPIkuR7RwefN4767/XI3mz2PpqgU/7Oa49uUK3ufyFBOHyw8oSRV4LlYJEuf2
 +NvownC0pLAjTrT6UTt+cdUyKF1WDpKLRdMI8DRNAWyfkey+/neq9Dpi/knwo+OBqYF9wrq4ApX
 sd7jg1D/wHRc607XEckRIog+6vG3ld1SMu5MhCbz9Sa50ev5x/Z0uNTbDCOQMX44k7CoQFX17ai
 rrItTJ2B9aStkBpmlrUtOxijHBc8uPdLz+/AabFwh+me7ZKK6d687G3iSV0WWr4/X5iz+rqTDbL
 RFXxAz6JTYMuPCoACJ5hPksYmA5fq1/+oApg5+4/vdinyWOfqsBs+DmV6r5tUqFp0ozTRJ4av7K
 5NyVlyIhUn4EFkyvaTNJB0qN6HnvznlA22rw+tQM=
X-Proofpoint-GUID: 66La2Wgd1IDhRhVGVC5DvHVmP01-JzoH
X-Authority-Analysis: v=2.4 cv=cZrfb3DM c=1 sm=1 tr=0 ts=6974a5fa b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=IkcTkHD0fZMA:10
 a=vUbySO9Y5rIA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=NvNhq0AuJz3OI-n_XeAA:9 a=3ZKOabzyN94A:10 a=QEXdDO2ut3YA:10 cc=ntf
 awl=host:12103
X-Proofpoint-ORIG-GUID: 66La2Wgd1IDhRhVGVC5DvHVmP01-JzoH
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=FgxvEChg;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=pxX1YsVb;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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
	MID_RHS_NOT_FQDN(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC37BC7E2QERBAGM2LFQMGQEO43PH7Q];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.cz,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[harry.yoo@oracle.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_SEVEN(0.00)[9]
X-Rspamd-Queue-Id: 806817D539
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 01:03:02PM +0100, Sebastian Andrzej Siewior wrote:
> On 2026-01-23 07:52:40 [+0100], Vlastimil Babka wrote:
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -6268,11 +6268,26 @@ static void rcu_free_sheaf(struct rcu_head *hea=
d)
> =E2=80=A6
> > +static DEFINE_WAIT_OVERRIDE_MAP(kfree_rcu_sheaf_map, LD_WAIT_CONFIG);
> > +
> >  bool __kfree_rcu_sheaf(struct kmem_cache *s, void *obj)
> >  {
> >  	struct slub_percpu_sheaves *pcs;
> >  	struct slab_sheaf *rcu_sheaf;
>=20
> Would it work to have here something like
> 	BUG_ON(IS_ENABLED(CONFIG_PREEMPT_RT));
>=20
> or WARN_ON+return?

I think adding WARN_ON_ONCE() + return would be good enough.
Could you please adjust it, Vlastimil?

> The way the code is now it relies on the check in
> kvfree_call_rcu() and tells lockdep to be quiet. And since it gets
> optimized away=E2=80=A6

Yeah, it makes sense to add a warning to avoid future mistake.

> > +	lock_map_acquire_try(&kfree_rcu_sheaf_map);
> > +
>=20
> Reviewed-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Thanks a lot!

--=20
Cheers,
Harry / Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
XSl7V7wyiqP5dPB%40hyeyoo.
