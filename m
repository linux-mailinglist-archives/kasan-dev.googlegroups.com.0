Return-Path: <kasan-dev+bncBC37BC7E2QERBCPU2TEAMGQEGMY5QTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F749C55586
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 02:53:15 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-8824d5b11easf8961896d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Nov 2025 17:53:15 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1762998793; cv=pass;
        d=google.com; s=arc-20240605;
        b=KOA0Gt6fDpUfRli1KJh7rFKysL5NLvlMTqQRYvvOTakYoIIRbrXBDsmDkk/SzDlKH1
         ms9T8EtG8cME7z+W7E4Z10EvDEH4BCANVP28jrf61/cA+RI7cXTNTxo8qOrVFkPWPRwb
         DDDhUsbopeaxXjygPyvCBqH5By2R0G3nLTEcl51xAxp8UcrDrO8OUMDZ05/rYlIwdSam
         x5PYZqHoh65aO+QWa5FyU2beVpbLx6lEnCkwmB23mXgeTZfaoK9XaHB4nH5B+ro47gSv
         XksucUysnhZSviwz7rrRbXeF1b2A6QbNt8y1IYVbLWvD5YNd0xCOCbkmW657mNBzs1RU
         qX9g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=kmeU7RkJ4HOG+5Ae9wsHY4sfXePCSJaICoa5YIO4+TE=;
        fh=3f9mzyF451HCjbRIMn3YJ0TfwY8gW9P53D5ZNULQdgg=;
        b=DiedQ91zrOqS1P+Y4Q5mhIVieeTdEWSZmsRk4hFIZdgZDQCsK/VA8bZALR2PQ2Dnew
         joEIsPmAleAR7wxIGnS2JIGnCzk8cfXs/QLRZb3TkJh1jWCfsYzHY2aiONBY12BhoBA1
         vLHFBFY62yNWTM99Id2pYK54ySQQfhkBEHVbTBR6dze+mhR9JTmIcUuLxOz4rKvV1nZn
         0Rk8kefjvBcLPbEPmf/NmJMYRnPy1BxElsx2v6+HJErsiqXUTEVpMF2MtA5IjzB2J6AJ
         BFYOHB37apKGdD6ZCJSW1Up+4Lp5GSax60K4aC1Wf7+hxiIfzsCdN+canyMiqev436yp
         x37g==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=I5abqi5J;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=0QC7Kxbk;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762998793; x=1763603593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=kmeU7RkJ4HOG+5Ae9wsHY4sfXePCSJaICoa5YIO4+TE=;
        b=q0tyjpeA1o6nl26xops0vE/EkgwuwUFEZ+fd8ucTHQNeBUU+OInyTOTzYwckW4anf8
         GqqB4pSe5C4fiOxwxZjr/Op7mGNQKUE5C+rSeWrR/9kXUzJyr7Oad8BCySUsmgRiSQim
         nxrk4nVlbSVqr8liY8VVfTqz0Gz8o97O1gsEr7lv1+eZRjZaXekEIkxkfRiK7783lpKs
         uM+mRazwhzKiOwSH5eVz/guyKd/6t21c+M//uzMNu8xiY4whDjBgL2ztNK5yWGbJEzj2
         BpCl6iWNFDBIwL4/25OQjzVIhfoxitGnTl6/AXxn/BdRWay94FRzA2EgPg0qSuyy0EZ8
         bDMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762998793; x=1763603593;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kmeU7RkJ4HOG+5Ae9wsHY4sfXePCSJaICoa5YIO4+TE=;
        b=fzKcCLBFZvAW9RES8Fqx3ZIbr7RpHKQ1OsZRPTlJYFT7paukJv2EKcRCJ22yYxpHyn
         qM0Acd31EDKM5g+lI67wPPllVpfoD0sspwbXGwqM0b4vNIUMcINpnsEWwUQKAmh4pE2U
         wl/fNDQo1TdD8y27chTOsGSHzEKsdlQ425q+C9Qnit13iKX97JURj9bfNkkI8boHkHK8
         98Mu9bVwMdTouKigtTZnyMlotOTZxGSqUMj5yvmStgDR6owx8QRHNYkW5urpLaPjJP4Y
         FbhQRxjbvbAq6zQp/4edB8/V04hxJ3+jmYCvGrVUkF67L8/wfZuPk2Ga9V6wI/kXg4eE
         7EiA==
X-Forwarded-Encrypted: i=3; AJvYcCUdV3QrjrEOiIguaBKv8wEiT4KwgrDPBH7NYR2e+iNVWQr1yjMvcP7Vv6mO32VnNXSD7VM/sQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyts3OoO9B2ph5nnQs8+ZTHWdkNa6xVEWTRNvKfq9PDnpAg340/
	lu1K8LSVl1vgGqhIWsQwr0Xi6pUugEp8ROlXDyl8574PGEzQbkTAb71o
X-Google-Smtp-Source: AGHT+IGkdhymasyIR1n2BstEj1E3v2LnXJy6gNK9/u40MNNal6yFhuehauqud94VczASfuNLJ3pBOQ==
X-Received: by 2002:a05:6214:8016:b0:882:7571:c023 with SMTP id 6a1803df08f44-8827571ccf4mr50941616d6.47.1762998793671;
        Wed, 12 Nov 2025 17:53:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YAuXLrTujlEbun1x/VtnVZ9Ra8bi8zhHo0ALfJjHug7g=="
Received: by 2002:a05:6214:2601:b0:882:4a63:63ab with SMTP id
 6a1803df08f44-88281b263a7ls7949306d6.2.-pod-prod-05-us; Wed, 12 Nov 2025
 17:53:12 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUDcz9kt/u2imSnQThAvqliEcULY71XdYos5Ymoc6yFc6H+knXPfnTipwdQdb/IUpTLej8rh8vAsOc=@googlegroups.com
X-Received: by 2002:a05:6122:318e:b0:558:251:f0e8 with SMTP id 71dfb90a1353d-559e7cdd4f4mr2192981e0c.11.1762998792792;
        Wed, 12 Nov 2025 17:53:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762998792; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zv7mU6VigAoDzTc4iq0GJnA98FRWhlGExL1iQtjiFnCfdO6f6/PBE4pbkNlM7rzMNY
         s70vg55SSI0TsScbG/q7+o1VZDVbDm1SRMAUimMMkOCbrlMZp/pzhhXOYsvqE+GA7TRZ
         pwk7MV94kPBFwYlJHMbfbu8/6FPHYhh3rO9P2r8OreVwxTAsw+bKYNjEwATovl9RbY5o
         19FPm1U9VQzmCjvZ0HhB/g9d8PNvm+y+WoWa7AaK7105sBVVhz9g/jJbGwaGiEEA52Kx
         GdbXGQMHCViAk78+iLFBn7QZLdhu/Bzy/4NPhsW40367I+Ru5VBatEddrTrAlPV/hSaE
         CdSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=3AiENayf1udk3Xzjkgesxjjv6rBUH6zUzqjaLghkc7o=;
        fh=z9FBhjMbkZ+0JHvms5X5JUwpeTV3lUJTZoU17s0577A=;
        b=gzYqmfkpn7P67HP05pLE+ZBFlpz7Op7MdTnPzh5ucjnI2QPwsESaQt4x+6t/7hwnE7
         6Yj+8zNY385xCb6s6IDG7AdUVjGS7PdVUaQr2buP3E2F3lukm7aFwtDxhjdJODbXyQLv
         6Oe1u1Sz6Vs6xUFk3dfyQvY9PndLu3JFylRq9YsArEdSXEP5aYIuM0nk5a4FjMBF/ceB
         Yfu2nN9w1cHxNkQytgSgDMtZzFPGB8A511EgYvkGkWXuvFos3VX6LJgBgdn8FxGIRcXF
         6N1y046qD+a+fVyG8hYvS8Baje7E+qa4c2cAbj53+sWPe5POFpdL0vMl8Vtplz1ch4ge
         d1Ew==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=I5abqi5J;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=0QC7Kxbk;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55b0f7ba1e8si56016e0c.2.2025.11.12.17.53.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Nov 2025 17:53:12 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5AD1gEhK015601;
	Thu, 13 Nov 2025 01:53:10 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4acxfvgvey-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Nov 2025 01:53:10 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5AD0SYic029360;
	Thu, 13 Nov 2025 01:53:09 GMT
Received: from co1pr03cu002.outbound.protection.outlook.com (mail-westus2azon11010038.outbound.protection.outlook.com [52.101.46.38])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4a9vafhqsk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 13 Nov 2025 01:53:09 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=yM6eA7lgV87uhON/H/Di9Wi/ZHcO9W+fw2iQNOcadSFp7BclyMPes5T9/uZ38TwE/Sw6Jzw1PYqJBPiN7M0ucfifAFEGxe0xkiGbdiLLvvmkKXu4ZLTPcEtE7AidaGB1+x3pptFKTdEI61qQ5G2AdpG69mjIZpzKgLhhfF8voKw/bZjcaywWT3BOvvkwtTQpErsTXLjKgmLCiXNj9Y3nkWIbXKiREyQ1wjm0o1XeCL5GAc+E7VA2gVOec+pq3u+Bf1MqnYZQ31JEpXEqwlIanwTsK3PFNMhOAa1NDlbMZzhe+yKLrLbWQqw6kuGyVf4e76JmiaZeTcT+gk3np+57gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=3AiENayf1udk3Xzjkgesxjjv6rBUH6zUzqjaLghkc7o=;
 b=wFse1hGXxwpCUfOkvdUn35P2J+36ZUT2szvPCLsJMXZANQPAeQczinXSLPDNORDZwi8WlIL3PxsyUFMEMqpTjDOejQLUk8MqwRp5+O7+43N+EwLArcTkGTlnORbpdCPQYVR3KrqkhEX8rvhClN9oIHMs9U9I3MyED3mkflY5hj6Zj6KRIb8ky6IDHTAbEMJispMa3azlU3xDgeOtPk7teY52q4D5ElWbwlqG4K4xyRsdrAf1jzzrVAd5O/40BUfMSZtPub/t5raK446ToWLu7ZlIkuXPqr8k6qUkbtTb6hqAYI2Z0maoHugbN7kix35JOewGXr3HNecIBTraHJKYSw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by SJ2PR10MB7081.namprd10.prod.outlook.com (2603:10b6:a03:4d2::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9320.16; Thu, 13 Nov
 2025 01:53:04 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9320.013; Thu, 13 Nov 2025
 01:53:04 +0000
Date: Thu, 13 Nov 2025 10:52:55 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>,
        Suren Baghdasaryan <surenb@google.com>,
        Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
        linux-kernel@vger.kernel.org, bpf@vger.kernel.org,
        kasan-dev@googlegroups.com
Subject: Re: [PATCH 4/5] slub: remove CONFIG_SLUB_TINY specific code paths
Message-ID: <aRU59y8i7fICC29T@hyeyoo>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
 <20251105-sheaves-cleanups-v1-4-b8218e1ac7ef@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251105-sheaves-cleanups-v1-4-b8218e1ac7ef@suse.cz>
X-ClientProxiedBy: SL2P216CA0154.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:35::18) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|SJ2PR10MB7081:EE_
X-MS-Office365-Filtering-Correlation-Id: 44b08bb1-5b49-43e7-210a-08de2257621c
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|1800799024|376014|7416014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?QwXF4dFSirJocmEFgq75iCk8jACCk+1g+RN0jjSE+wiGUzo6hXlVyUz6hMpD?=
 =?us-ascii?Q?wYqEdtB8kP6d0EeocdQw0UosBqm9uWz9tbiZaDyZ4qnqV7slwh/O99QWuCEa?=
 =?us-ascii?Q?kdUCyIBGMHd0lhV05mLPEnwbrIk9SnTtraerpvuBexyteIGN87e5ZV6KQYAw?=
 =?us-ascii?Q?Kf23yWMVho3q5IOWV17EcWg0kd1YFEs2LLTXsd7CVbisqa3gS1KpTzCnF5sD?=
 =?us-ascii?Q?wJaGRx2qUQteIB7bb5hjfvTwOEhtkcdpfgabc7ZaYFaLZFDafztxPVLGHgzm?=
 =?us-ascii?Q?D7sAqArHssYsIyNdV0bic3ejRWG5cRGzlgZ+IW7vjbXGo8pwS8DKvJ6qKma8?=
 =?us-ascii?Q?/cghXTHwYLZ0INrNO5oLLXVJGeecSgZJoqN0nPGBPaq6knCPt3deIX7UmQ0L?=
 =?us-ascii?Q?zEhoXlefDcYhrc949xDNa2lsNmXXv0abCbA8uQDqLr3PnEXWpvj9npOUBKMG?=
 =?us-ascii?Q?OL4Smh0D0G83Ls+sNRXnXTmMNqanoenf3UBKT8xmJXs64Y6k5jq91NS59r6S?=
 =?us-ascii?Q?dtjB+xyOvxS/PSOHELLL0q1pUKBC7f2jb//8QQr2EN2/Q3NLaE8VWz6+jzgJ?=
 =?us-ascii?Q?zaB+6Qsm/j1IX8pr34XMyWMe9VFzNsC4KTykcJDuZGRAvcbiGbqV6OReOK80?=
 =?us-ascii?Q?rqRQWM03+HNtJFpYcxSyLEjTylTv7XmxT4iFQN32rN74QLWO8S9sIgfsTGXo?=
 =?us-ascii?Q?aZm0OmUWKq3fIlbL9JVvcskl59Tam9j0AX3CUyWm+qj2IAKDA06DNUWKat0p?=
 =?us-ascii?Q?BzM5UIImfDCyTor+cu5RO0JagpluFvupYnxHhAgjs5bYCh9UIAgw4IW6A87e?=
 =?us-ascii?Q?k+SfkAaYhIZps5c0cPjQTIwnw9G+vaTyTRIn7vweL53+QlBRgiNzmtMvwCXj?=
 =?us-ascii?Q?XTbzo0xl4mtFlEfj/U00J/sSZYxWsfyseSueHDDw/nAxLs9/wEodLppdT7Ik?=
 =?us-ascii?Q?4w4uvlSdGiN5+oHzcMrjuSBVrz8xxZRc7GlRjJEfrTX4Ui1hfzKiJl4/hA/X?=
 =?us-ascii?Q?V7c5b2mnCrbK6FIFThQ388kDQWq7jPWKhp/7ThfjNtmIGl99OaCIakLrRmNm?=
 =?us-ascii?Q?c2WJxszJEgKjyJstkIJlPCw4RlPmHGMjfov/JZYKZxWGAK5YPugNwd3Pe5C8?=
 =?us-ascii?Q?kX5ln2z3816h4eDQwyC6gB0eMwbtcqI8rgbnR8pwkxv9CyYIpGHAMqR3W8es?=
 =?us-ascii?Q?mjvKtiy04AuTNYAU5jvmXUiFc3XuxXOOHnzZwNC33uP5zUOFFP8bgQbOF9SE?=
 =?us-ascii?Q?jEZKcBSuceDrzPZwhnP4jrEhVTua8VWkIF+H1sfDD2OpEGIo+fOHUSAUsIRf?=
 =?us-ascii?Q?9f3hsMHEg+Bg+VM/1c39Z9nyXqKc+vwcGo0JwZ7v/4fnLV0snHn9es3s4JGE?=
 =?us-ascii?Q?jJNcyXMAGXACyy+sbXHaBYSKK1EED3ijJIXvjgGddSXn8AL+00lJ6TCA8nbn?=
 =?us-ascii?Q?ihIkLBLnVgVOwq3m6LwmCfxKvRkaU26B?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(1800799024)(376014)(7416014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?I2BLNr2I9hX4ESlij7VvkXqzJ6yACJyNnVFVmVHfMlogGYW4EeTHXxgKrzjT?=
 =?us-ascii?Q?ZlprUpJbYlkHJlsTZXT5XVgMYYMe1gendf22HEOTWCen32egV4hD9iDwkNt6?=
 =?us-ascii?Q?kQB2qSg+q1lsYIpSKcBTfA9BqfZ+Oy6LXKFaySz+yuvUhtp3JsCa7SFSsAh9?=
 =?us-ascii?Q?/NLksFIMIv4im58e5iOvXulbYmn68+Tj3JXeC886A0zubhpe+B8f12F0sHSr?=
 =?us-ascii?Q?+W+T75YtKP7kJ64IsobUspVAW1BJTaEYWGn1Sfo/k5rxcq9RNg6CH4IriOgQ?=
 =?us-ascii?Q?ZutUGd4ONiIuYiJ8QLcwViUWjelMb8otdFn2OsNrrSI8Rm7vMXHJAXoXTJGK?=
 =?us-ascii?Q?P7UcbOFkkFG53k8pMU5GUs5CJjSVyC8ixgLCPXIeUC7MonK6WFlzOUsAJ0M4?=
 =?us-ascii?Q?Umhh2hfzfn9lBLfUNRJcVZ0dVbSEERxREZnhSIhv642k5UHmQKkIgDvm7R7F?=
 =?us-ascii?Q?gJmXukUV0e5Ww03v7XFj9ZIsL7HUVSrbZOVGQKckkRnqtmbZTq/pZaH+HZ23?=
 =?us-ascii?Q?VMOONecyx3xit5TGL1jWXj7p1lPoRoEqJ+SKyOKAEKQ9TD82zyrkvNIbJGng?=
 =?us-ascii?Q?Tl45fwtkUVw1IC9ZonRFnSg3GR0WxA5I0BL8MgFng+mfbKpvSWFD5YgvwXqe?=
 =?us-ascii?Q?/0QlTrgbiMoMcQXE1HXVqEHSztnDEQpZ+pq15szbcZoShs/Vehye7P5usJhN?=
 =?us-ascii?Q?nNYTQ/iwhHgwHpzaWHG9/rAff2rNobls0Nv4Z/iXxSnKFpt+g/mJrU5bKOjA?=
 =?us-ascii?Q?gFm2Tc2vn21rjhdrzQmUk0NXSqBfp+IOxiovccpL9tT7ehoL+K3w57riy65Q?=
 =?us-ascii?Q?o3LM7r3KgjwaH20QVv7kZSz1aEEushJz84l0fVorfirwefzDf5JECcG+SEtX?=
 =?us-ascii?Q?fs1F4vwJR8tmA1BEFSy+B8CEURLZrTEgAcDXbPci7/10HqT6qbA5KMPIedpO?=
 =?us-ascii?Q?SpQqcNj5UwRL2SiI9DPxypQ8F0BWRA64SLNJcLnmHruZlLXdJN/JH6ORAthh?=
 =?us-ascii?Q?+6Gn6DHYz/YJQwmaVh9poi8vxz2Q4+Zuuu9HsmvLThc5Av1tiqinUIrbdukO?=
 =?us-ascii?Q?JaQ/Cm6lVuzgVd225i14r1b6pHAbv2v91JnjD9Q6MyJdYkWf9amHehqmWL4+?=
 =?us-ascii?Q?Q6TulZyg4lTTXuVUFOUIdiCMSBjeLN2yXpoxRbi3z6fQ4AwFXuXNEo1omoHC?=
 =?us-ascii?Q?zSOFNjnm/OBZDiCBJzCkoiro+GhQTEL/1mhkXLjFShLipLBbEgoeamjNxa96?=
 =?us-ascii?Q?CmmOIOQ9cFVB7rmdxC4vCAPD226vB8X26oZsUPniTqCnntulr+yhqH5h1m1i?=
 =?us-ascii?Q?ZsS0N7/9QtSCu7rn2Dv/9m7UUAW5ONu8YnSwDCAifOeMU/b2c8/zk0W7bu0h?=
 =?us-ascii?Q?DWu6DEq/avWryDIWuNKTpt5Z9YRbU/C6qpihApT/a2G1OGeaxvEiYmVL3mxW?=
 =?us-ascii?Q?RwJmrsj2ripvLcX4IlJiXOXqCV5naoA8vf3hyZwZLyiQDhhFhF84ZOM3yBps?=
 =?us-ascii?Q?Avfgvt6NliYnjzaHghfRQEaElXYgLtIaoUGkotpVWGxM0OQnODRix5cRsoCZ?=
 =?us-ascii?Q?7yUfgAfEcXCdmNKXQDQQnH0rJMh21Kny7ygbZYzL?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: WLljFfQzqejpbqaiIAEsFR6U7+Q1OqI8orLhv2dbTysfIUVZo1tS/LBtDN3Vuxscu0gxL6kMj5UNW9a4+XDezqgOFXVtxwHz7if9xFL2YdhoZWWV/edxUWwdmkr6XD43tHOuLT5C+doLbW4cxiPna4JbFfB+AEPrsvnpueSOz1CBH0VkMgEw1qN68e0rxNwiFxPthOWNy0kca5dpc85tp+iVciwud1vE03utIsqE41Z1EpdzPIvUBWNhrO6nd/3gIluO4NY40bblxncZYgxS2Fwn1VqkoxmUg0Py4t0paBJt1QUNYg/+6NlMmNqptF80HULaHUo+9hAZ6gtp1V2cV+Y6hEtQpkzuPOLxYPWGiO7MaoDinFNrpyuUIzuYAZpITqrzjTxg7Kj4l6dEdI0mK/FmZXd8CwhSogz2bKjq7carGHAlcMCH7V93ZVzCVTpHpRJhEA1TAAz0tbpkjpZvmoZH+rPFAtrlN3uEX0nPTRzW0Q4SMIud9dNBMUREhzRFto+ckLlG2fbEMWGoxGExZFT37HaygNNlQOz+qr0ZCz4aNF+IO3XUPhnnikI2oCaQxevactVMUtxcBTfe5cfKsay9dA9UeYYaMQIWv8kn7pc=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 44b08bb1-5b49-43e7-210a-08de2257621c
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Nov 2025 01:53:03.9367
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7ix60AzQFMSk8Iq3yUgYfdiqKu8yQQstj6+R0nhGa+JLvK9C3QTocoAVkfkGkqL3+uhEC0LVLnDIS3jxQUTSnQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR10MB7081
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-12_06,2025-11-12_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 phishscore=0 adultscore=0
 malwarescore=0 spamscore=0 suspectscore=0 bulkscore=0 mlxscore=0
 mlxlogscore=824 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2510240000 definitions=main-2511130010
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTEyMDEzOSBTYWx0ZWRfX2wln66Y6uJIp
 r+cL8ixMrqVzdVrG2iqaneOTz8bF7eaiClcXVY2t62awAS5FWPBKTftHQYmMxoTZ+usPFGvfeRt
 gXA9Rm3ecyqWamkS3VN0rYqjd505uqPVbUXhP4gCC06sxIbGjIjFK4Ie7n4AbuDhtE9trfbHlVs
 T7kVixqibelISTO1iUK6/eIiOOd+SdN9L5N6CmO8vueMYoUFUMWUfZPSphRmo7hynaTsbhTamHf
 dAKxyuJiL7+cwX9XzRk19oypBLBiYeMUugm3LId4aJWZ1o1CB4Jji6JycCMqtHZQcZKNFeHU2/B
 817HteACFNK3KxJ4FvIPeaq/DiZzykf4vp2ss+JBVsSeF/3qCPhiavvQcPFao0G6CjRWqMM5w5d
 ZP1Iiy5hRKl3wtodvz98ToBi4Lh1rKtT1GA4uOOihR2Ze5fWBpc=
X-Proofpoint-ORIG-GUID: tBRMFoVuGmSDXM_nv4EAIBk_A_UddLh5
X-Proofpoint-GUID: tBRMFoVuGmSDXM_nv4EAIBk_A_UddLh5
X-Authority-Analysis: v=2.4 cv=FKYWBuos c=1 sm=1 tr=0 ts=69153a06 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=6UeiqGixMTsA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=8ol0XHITZdbz7p4FxSsA:9 a=CjuIK1q_8ugA:10 cc=ntf
 awl=host:13634
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=I5abqi5J;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=0QC7Kxbk;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Nov 05, 2025 at 10:05:32AM +0100, Vlastimil Babka wrote:
> CONFIG_SLUB_TINY minimizes the SLUB's memory overhead in multiple ways,
> mainly by avoiding percpu caching of slabs and objects. It also reduces
> code size by replacing some code paths with simplified ones through
> ifdefs, but the benefits of that are smaller and would complicate the
> upcoming changes.
> 
> Thus remove these code paths and associated ifdefs and simplify the code
> base.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Looks good to me,
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aRU59y8i7fICC29T%40hyeyoo.
