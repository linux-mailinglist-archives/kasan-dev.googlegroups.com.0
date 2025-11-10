Return-Path: <kasan-dev+bncBC37BC7E2QERBQ7MY3EAMGQENWZ7SDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 50F1AC45C04
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 10:54:14 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7a267606fe8sf2520011b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 01:54:14 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1762768452; cv=pass;
        d=google.com; s=arc-20240605;
        b=Bl+g19Xo8JV15xHxRCV/SQ6yM/h/3y+trvD3Kvx/Zwz5bwYHK+d+bAuhQv8cNb7N1E
         p+XTmXsfkb/pGQxKQcWsoa+FE8LCwo2gpXfSGHUDQyCJnsd5iTbv3PQzuTUS9ApDkgtA
         src+czkXKXHZTjAP7RXVq6V/V+jd0SGSWtUAdF2IRnmtawdLlO6KhZjB5X1w2Zl9j8Xc
         rFpET4wbG+8c8GVHq6NrfLV8GO5vrhAE7z5GxJLNVYgazbZqYLOA0HozqBREBHDPExQs
         9KzGxzJ7i4FNC0z6F4SxQvan10q7z+oCIsqrDcgqra24Lr7WUqlowi94qUd4bzHopHRm
         xxGA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=bBlK+g8Mz0oN74/GftruxnZ7h4jsdmG7isX+jL+tDx4=;
        fh=BChbBlDlH3aAsey7t7YIzyk5iIoLxaIiZFyHWzSlHZY=;
        b=WkR+vfvOVXEjSyFi8X+YT7IS8/XVza9nAXmwUrUx0pxgD+mLHBSFqVWafBa6EAzLwE
         TW9VU8qwCBdvSFv8JxbhW1If9CMC8g+Yt8FCkvqdiTvlmnKzaNpnANRKfArfKWUZInk9
         5Ltg42c23gTriSlHVErN0huHOl0UskPkOMut+hDYiuCCPd9RPg6aZyERGiV/6YFFP4Z/
         rKHjuCdiCocqoQuOFYQ8aYjnjjrNX+eB5FjtwW3SpwRI6CDe1IdY+HnFDYwaRcnwPcmu
         SU5fCHzvp11xIqGuxrfZbBmwbEpLzLtNt2jxkbcm4i6FKyU1neH+OU5fwLcP6aS7Y8Tj
         PDAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=oydbHTQP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=eGDmh4jw;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762768452; x=1763373252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=bBlK+g8Mz0oN74/GftruxnZ7h4jsdmG7isX+jL+tDx4=;
        b=xZ4lk0JBWsg8QZ8/KPIVBAaReeApx7bxdAg/+IdyoCd6Z4/fiYN+0gOCuoawsGgOzW
         +1+nA6KiVTGJmcfPJAWi+1uoIbetOdkvsfZ6BrLlYGuaCQkNoSib1ZOR5DYYazxWK6JZ
         hOxVw0tkv3VzE0x/+UwRrgmU3fePF2J7dBZGrB5r2dKhFuniIwJZ4rRkQLrI0oUP6e4N
         4wU+uz3CeqNplFKPuY72ZW7VA6Ab53kawk/BT662XBOfgciuPyhIQPimwpQ6MfTwq5Kl
         dXWZyp0K/BAm+uWLhn6EgYVjd3iFCG5wl5Hp6UrNoLtK4tik0kZwzVVlq6sjCn+pP3k5
         ZrbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762768452; x=1763373252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bBlK+g8Mz0oN74/GftruxnZ7h4jsdmG7isX+jL+tDx4=;
        b=i+i9IW1RaFaky7/rZNLbOvcZl5wmZhYLk3ng2Bne9OBeSy4gFfnoqCR3rXYXgMUvi2
         Xse15FsFH6trZUooENKnvfCyYqywQKWeHg67vARBRMSKvpyjeoFogrPGhK5lpslnPPoy
         8ewNwDCVaalov6BI9AaU7YhJlGzh67aHlyUc2HBPyJR+INiNYptCnpytnv80B96GK4Yt
         5qLjHD1xRxO720YyQevbTu5HWccyTU7ZPXZ1YvyP1QQhG5l3AWIipayWW7D1z57kzAAe
         IhBCC1sIhaRmY3eQK2AtUbeUbCL+kckK8rj1dXQ/HGg9A1BqUIy9zdT6Qi2Ssvq9MyRf
         plWA==
X-Forwarded-Encrypted: i=3; AJvYcCWAwdfQJ+aa+VKmREYcv8ormmF5OCglhwxFfpQ+uaeATHvRM30flnGOTKxy/cz4BUeEpvk5pg==@lfdr.de
X-Gm-Message-State: AOJu0YxnXtH0H9WuCQISePlkJUE4F5HZNSWiVAUZkYOGekEeitcIOd+y
	z40vjsdQ4FRURmblkMNtC0dtgBdcAsNOiqnC688mRv8/oYmdVhsPjU8n
X-Google-Smtp-Source: AGHT+IGeGFNTdun4kRSSJskzkZD1T852SJqvkl/oz3r+vYZxAWea+VjQsGhXLff2Dny9ifzD/+xO6A==
X-Received: by 2002:a05:6a00:660c:b0:7a2:6eb3:71ee with SMTP id d2e1a72fcca58-7b225b57e12mr6479153b3a.9.1762768452239;
        Mon, 10 Nov 2025 01:54:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZpmJywPAIzdG6UhSjUt5QfDoA9fGawiGr/bVzeg+cRGg=="
Received: by 2002:aa7:9a05:0:b0:7ae:d5f8:b7cc with SMTP id d2e1a72fcca58-7b0c8f4690els2888626b3a.2.-pod-prod-09-us;
 Mon, 10 Nov 2025 01:54:11 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWr3D6ng/7Qc5Ic6gW9+VU4BgvW71gueEprIbc+RyQ6VJuS/YEz68ovBQ6BTg50LDnEVpTAJohI/y0=@googlegroups.com
X-Received: by 2002:a05:6a20:9f88:b0:353:b488:d50e with SMTP id adf61e73a8af0-353b488d815mr11101752637.26.1762768450780;
        Mon, 10 Nov 2025 01:54:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762768450; cv=pass;
        d=google.com; s=arc-20240605;
        b=O/1BBG2rpjTL5vGJOyHP4YDmgYnz5zowl1zW0xcO5APAipLJmb7cGcRfaJmIsnVyEa
         o52u+bNoHRs0GmZM3VbDTRHX4HSf/USWSyOQrcXaxCJeaJ9aJkn1RoPw572R0smywkzN
         8wkQy/Twa5k33tSPZADy+NIYAOsSyxqAI1akd81ii04v0O7sMz8fAKbAv6wyUIin2IGH
         3OJgimbsKW0IxEtSTFk/JJqlEnFz862pmjln2TRv/qxAP884creNr67AQTwNopVx8Db3
         5UHCNIxaKKsLcj5JTDhG/2MDtkWGHpwBV2XyxyWvYu9SeoPZd9V9gg8zmrA1ZqxyJgpJ
         KUBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=IfGibePj8O7QTRpwz0RBLnLO32n7MD+f0y5RLmU7uzM=;
        fh=z9FBhjMbkZ+0JHvms5X5JUwpeTV3lUJTZoU17s0577A=;
        b=XpL8tF1Kx65Vn2bIPCJNpRDUSaBGSGdfmN4Vxb5W3YqEPq5Opu0+jFS3Lx3RwEV/E+
         sObt/BJyhXiLCURPPC+JtjJYn0on1FREs4eMGoGzoziTsQ4LzK1+Xq8HHR/n866JTkD6
         YDfhp45xsSHynrSXjAJThjxefwapL1V6fu8GVoFMzFeWk2xVmgI642pOzypm3Kk9Plhi
         dPsYxeDl3G6QQ9ZttvxM3Saaeac41UwUlhd+xYRGbS+IDhCmmosrke64+48p+lsnib0I
         aOHOqHCCYuRSt1WDYOcJ3+eQvW0pptcGejqPSKP7Rma8fzECjnGDK0N4+fC2fCZUqvm3
         EP+w==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=oydbHTQP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=eGDmh4jw;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7b0cb49dca9si357388b3a.4.2025.11.10.01.54.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 10 Nov 2025 01:54:10 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246630.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 5AA9NbuL010590;
	Mon, 10 Nov 2025 09:54:08 GMT
Received: from phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta01.appoci.oracle.com [138.1.114.2])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4abbss09gh-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 10 Nov 2025 09:54:08 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5AA7eVhq007388;
	Mon, 10 Nov 2025 09:54:07 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011042.outbound.protection.outlook.com [40.107.208.42])
	by phxpaimrmta01.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4a9va8eshm-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 10 Nov 2025 09:54:06 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=mmFa4y4jJ/UjzH6Rpb1ooF35gwm0041+DpWGqfpetNcLMoR0ajKo+Ikfgj7GMzqa1sXH1Ylvo6dkjAaINcffKgh/mlVDjjKQgzDt+KKJUBXt5O2WcVH91l87vyVxyFI3hc0aJ3FM/NW1gqFGiJJZ6nkMTfzNdEVpj6MoauiOWTaGCLyG2S6Oxan8LzUSO1KfrRUDxdqWFUwJoM5hSFUJP8HuPOCdYmTIoF5FTtbapAGGsMNqSQ7lM6oOBDCxO0EK1zUHY2BOnJfTcnrxrSx7l/resGZWi/zphQE2DjwG0thV4xu/DTXGcTRatK+USvHmu3iTk4hgUhnMu170L0WSOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IfGibePj8O7QTRpwz0RBLnLO32n7MD+f0y5RLmU7uzM=;
 b=cypoiJQ2tFiSKhgVAjQg8DLbw01V0GyNd7CJ1LKBZGfgX95nzN+FQqWiqrrXzkglK7A5gGyV3DurPuHMThgfqj88JO/Me+gSc78IYQ8LfGK8q1tQCG6dbzTXVFF34Tm3cfjxtgW8obWI/MOxmmli8UZhUofn3sWviIBh29kNP73PJ6DmphLxQ30VDg5OLZlsXUEpZUVdXI/MRM0Q7J8theJZ1xST2Bearjv/okc17flcbURUruXqtp14rZopVoKnKLzrYGn4FSlMZA0Uldx5xI/0EVGm/QVBbe7+fIj+A9Y/HgGIFYsZ4VXL7HxsB7vo3YMD7Os6uk7kFdCHkIz31Q==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CH3PR10MB6903.namprd10.prod.outlook.com (2603:10b6:610:151::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9298.16; Mon, 10 Nov
 2025 09:53:54 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%5]) with mapi id 15.20.9298.015; Mon, 10 Nov 2025
 09:53:54 +0000
Date: Mon, 10 Nov 2025 18:53:47 +0900
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
Subject: Re: [PATCH 3/5] slab: handle pfmemalloc slabs properly with sheaves
Message-ID: <aRG2K8YCqCZa2Yfx@hyeyoo>
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz>
 <20251105-sheaves-cleanups-v1-3-b8218e1ac7ef@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251105-sheaves-cleanups-v1-3-b8218e1ac7ef@suse.cz>
X-ClientProxiedBy: SE2P216CA0036.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:116::18) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CH3PR10MB6903:EE_
X-MS-Office365-Filtering-Correlation-Id: b265e0b0-ad35-413f-1fc6-08de203f0ec9
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|7416014|376014|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ecfb9c3SQGSsVXENOeU7fk/wzFGX7UKlebO9d0wo/bCigB8kb1PluWoSKOHG?=
 =?us-ascii?Q?DnKB5M91CHNnFBPyYH7oWTlgnU+ZabVsIAfZYGDT9EvVUU+OL0VhFI+FMrwy?=
 =?us-ascii?Q?PPdEVIk00G8qfVkI2sQLX8Ug7fH6ztli2XQMnjmxszsbNuYl+TIM6/3ERyds?=
 =?us-ascii?Q?c/bEvTuhq3kDfKSyflMBCfqFSTzVb4zyuFo7wLQ3Bcsro9ubKyFtnhalnhQm?=
 =?us-ascii?Q?68gxHxRF8yq0oUPxbYmlazX8UNwBzbG3Ev4D+J9HDs4p/OJOABEXfxX4vKxk?=
 =?us-ascii?Q?2mrY30VcIORxKQ5eeP1Q3geNiYYeCoV4T3ZJ7s4zikdzuzmsB87O+IWR0DE8?=
 =?us-ascii?Q?+XXIKoWS0iZGNJxUXqohQUOY52hUnSNMZgBRpznW8kiLsG3sPaGhGSKg2vmD?=
 =?us-ascii?Q?1v9tBcQ0xF7LFxgLuJ8nXY8i/joyH58+wCx8QIpn4ZyCwrdYV8Pawmx8OGYP?=
 =?us-ascii?Q?z52DLOpJ6xirHt1wY/8Ugdc/grPG4+FXa1rf2DqyttAE2HdbuNrDmtakf9Jz?=
 =?us-ascii?Q?BrubDseHaUCzCMQbyzE9hMz8BKi4+ctmnnsY3B5FVm7gwaHGMhfRc/5NWbqS?=
 =?us-ascii?Q?ZtLxNt8qbDpMdybQu0FVjPxBZw6Kx3d//3uYyNp/geos53owOQvThZGPYdv6?=
 =?us-ascii?Q?amPFBD/WMO6NIwCIeqJq1C70RHSfDLXfvM7U3KF+v4cSEmeiqlv/0EJYAs0E?=
 =?us-ascii?Q?28TBfIa072WQ46FgpHPRGn0H+09HB1XJYdX+EAR0ThwJcP6r2I+X7nLe44zN?=
 =?us-ascii?Q?3JOYPAlXGN9cGJMON3RXc17Z83bc1kKhTT837uzwpTauXyKx6C/kAjVTz3z3?=
 =?us-ascii?Q?EULiDgmpZ1jKj98dF/PoF0kuSYzIDJTp0kSYMxPze/I23F/Hwywjn2B9Huo+?=
 =?us-ascii?Q?cmm9DTzS+dPLE0EZ8ql83iBrjAsCYCnWldKjGxaG7+UyHyTne8dHcycAibum?=
 =?us-ascii?Q?g2s5DmoSOYKuvnJaDFw9MKEalpQNinRVnAPP94oIysWQL/oaZMRAxpF4ePsy?=
 =?us-ascii?Q?J61H2zN1JvddpBhl/QTDme8C3DGFj/jyzru4YTiME11dH7tQEjtICLp6AYCj?=
 =?us-ascii?Q?WfUx87gqIH2m2/MWEMYswqmAtrv8aEvAlYxEisF+hRmnsf5zDnCvF9IJh8td?=
 =?us-ascii?Q?C/o3D/gnq1PjqSwJetF7J9nNQEyj5piAi+fom1HID9Kkwb9tdHR1jSAw1okr?=
 =?us-ascii?Q?dpkWzI0skaBs15a2nDvweu1xnWuIl5STWskW/NL0lj1oMJSIJTxvsxcnYd+C?=
 =?us-ascii?Q?Gpyaf2cXd9/DjvHMtor4DVVNJJJZ/viiSO75B0T8tqiJUlSkDWwjIdRoc72z?=
 =?us-ascii?Q?uo6csHGPHXPa0EKXNsTu9/jryqyetQoTmnUzLNZeY9uvtV08dKhNxypD97g+?=
 =?us-ascii?Q?0AoaQ/t0tHf1bVWP0dblkRaFKCkPNuuracHKsRabjCNO51O3QZPOJHCSE3g3?=
 =?us-ascii?Q?tDv3Z1zJNOwujAMOHOk7oo8NsoLa/eDO?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(7416014)(376014)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?QJgi0468xbEVaUw9gyAjOsr2Zh8ZcbN5aQPmTfp+G5Rwf+G/VUnxQEowr5XU?=
 =?us-ascii?Q?HElPVeaA2Cf4hB96spGirs5GZOJ/0dlJJuRPAmKwPtwgyM7Q+08B40rF6sg0?=
 =?us-ascii?Q?FzhGX3JK9YELSlEIT7IxseClXvFr8nzYf+aXwSeOzD4+YDY0M9kBsV0AGaY/?=
 =?us-ascii?Q?F0ZpQqmX2zHTgGS5lSmviHljmBghIT1PEezLgfIjAK4ItHvWIOTdQjGDFTvE?=
 =?us-ascii?Q?PhtifQYvoT22XAMV776ZFokHck7nt1xi1mlf5mllxc9Cjo6kK1zWueybrJBp?=
 =?us-ascii?Q?y5/3mHogthZC/DDIBh66Li9ADr9wV5ev1ngRsfIx3rdxWlHtnexicslP44c2?=
 =?us-ascii?Q?VE81GInmXjOsj5vyAMa7fogqhp+NEoZW9A+7DRQUx1KItRoVuemWVMwaHlDQ?=
 =?us-ascii?Q?f78dP1vcH/quXhEkHAv2FQ9kugFeuPAzVPhFZnEenuwM8yfXddV8qsf6qqHp?=
 =?us-ascii?Q?tjwTnN63c47N7Z26fQhyOR18xmTcrQAiRqMRt5NofXItJgTK3ma8ODG46RIw?=
 =?us-ascii?Q?fTbsBxQZaOHikpfvwyZoeVcyvZYkkg7f9vvoMxuaa8Fx3OBTQB2hhCAKhm9/?=
 =?us-ascii?Q?hCYpZ2QVwra/SeGquuuVvjCNc0GcEmPq7K22lklR6glVz8rNWg1/JKu6shBL?=
 =?us-ascii?Q?CtXWSP2oNb9glcObP62Io7LLNIheH9LbT4LM8S0DDTqRa61mQy9rna5q0KSw?=
 =?us-ascii?Q?CTlxGvtU5W3ze3Rc8zRcnkq+GZvh5AlmjtffQZ5UXqnQOr+5no01vE9W928F?=
 =?us-ascii?Q?70WOjsgNmQLWshAdF+yYeXzwPnTSch1eiPNx/TrHZzSUd0YwT9c5rlraF3lr?=
 =?us-ascii?Q?BykvDcu36Os+CI6V09fzx7av97kQ419txKFL92n5Xda0BIVE71iduwFFHMbV?=
 =?us-ascii?Q?GA1fmbB4TDHs8hqZG4OfEIGGtqgaXeeQEmSFCYElZ3O7SObPJq5cvxzFMfPN?=
 =?us-ascii?Q?54wTPHvsVx/LBTr/+Fhimdl+v/xPGxsfXXdS2yLqG/I4dZF7+tS13lxm4iw1?=
 =?us-ascii?Q?pHp+xCuiTteIsU4YAKfS2m/5FUtqTGCn94HC1Da55+oXwJY3MomBUsHCkMQP?=
 =?us-ascii?Q?71ejIDGZqsZS5gJP3WDnMQfYl5UDfr8vXjabmvOr6c4+1S9dQUZ/SGMRJrud?=
 =?us-ascii?Q?WB0taRtPyRG/vZ9v9Z/L5PFeejbXrA335yn0RbrUyKQaQY3sX8AcVEPzv1v4?=
 =?us-ascii?Q?TwOnsCrpjmQyWbSvDfnCv+0RKd53G08v6eUsJdVp6wCaBLG0VDz+q2SeAn+R?=
 =?us-ascii?Q?x6O0PaEYw8WC/9UwxZGCtAftMuozYt4ybZcnnXqcyisqICjQUFGhfoAzElVd?=
 =?us-ascii?Q?NVbjNklu9UbyK/BWOFqVzIBoZCpPeRUskdRj6GrDDht6yP0TJrIEZ+ztVRjA?=
 =?us-ascii?Q?2zDm9muFC7P+f6qJycBeVIY/QltRe68u+TcOAMaCHRS6mrM7NcrPsN2yTvzy?=
 =?us-ascii?Q?smc3MuMTqMU7jiTtzbGQ7XSDmn4NNQGtBeQNO9L2uVpJ34GmFF68hr1r4CXJ?=
 =?us-ascii?Q?9W0ysp7LHfUUZ/4zucR2IU8fmkWL5FS/jOeDN42sgNg6Bm1WBFubYJuAIWdM?=
 =?us-ascii?Q?csDot+XCK8PydcGJlfQ3KDj1GmO5lW7YJWu2+1tt?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: f8vZ/ZFLd+qI+S5W+c8UVxXT69foYD2JC5yHcf5mBdVMRrnsSzQRBKYPf6ZMWqH4ixGY1RfbuYNEUPxQBUhG4igRBIoM/SKQDVed6U0f/scF1jPn99AidKdNVVkHuLy5E/0nyQUxRa5G4IXbr5CmzXWAfNvJkOyzZ/XgIajDNyC78QDs1HyJI7sBNHMcvmSGeuXEMT0umDrKJGuvFvUstyapwweR4keadZvIOcjvaOCzjEyqOqzDbhm/Dq6cW2+gplGPU+jfq6b6GHrPSkbuwaY2jN+AdbqPLb84Br65H1HxMNLiHoDwAElfTuRAZvpb6eeGLv1QYnVsT/+T4NUmjeyZJiXXCti0fdMeLZPDAUS4F1E5SNOI2KsT/CUwF+gBqVUyAHAliV36GpH4/C13S3lXKsnFI6qW9TvchjSSqMlaROcUGy0v8V6pX2UiHMrNHBJssClYE6YgZ3se2n4cW3QSloUTA2isy3nk0/ASTev+cU01psgq/7IbOYkFW04MWVPPEMgKVdAGxUgNoemza+qBScyXvSUmCOWNojHR6c4cYGyOC0i6ZFIuzCzn4M+CmUGV0IVwmv67V1cgdoW/it+VxE2gdZjIuwYPblTW+og=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b265e0b0-ad35-413f-1fc6-08de203f0ec9
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 10 Nov 2025 09:53:54.1554
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: vwopuvu71u01svUlGSoD1Dx6oNBUTIieLlHsKPp6zOrP7R1OMHV/+E6gjD0qZ9pnUZu5x/iKk9hfa1VxiYk9lw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB6903
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-11-10_04,2025-11-06_01,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 adultscore=0 malwarescore=0 spamscore=0
 mlxscore=0 bulkscore=0 suspectscore=0 mlxlogscore=924 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510240000
 definitions=main-2511100086
X-Proofpoint-ORIG-GUID: avIVK6MeXggzdI4ey0PDGhG7gOfsgRgK
X-Proofpoint-GUID: avIVK6MeXggzdI4ey0PDGhG7gOfsgRgK
X-Authority-Analysis: v=2.4 cv=f+tFxeyM c=1 sm=1 tr=0 ts=6911b640 cx=c_pps
 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:117 a=XiAAW1AwiKB2Y8Wsi+sD2Q==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=6UeiqGixMTsA:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=yPCof4ZbAAAA:8 a=HqxLjavZxCgagS_tWHYA:9 a=CjuIK1q_8ugA:10
 a=cPQSjfK2_nFv0Q5t_7PE:22
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMTEwMDA2NSBTYWx0ZWRfX2tB7iniY8jMw
 zinHLodhV9OyNhQlKrlHX2PfKsmS0Kqk9xRUIN13cO1ixaXx5wuA3xriN1EvJamCcLpwjSrA97v
 12iDoMgAwwNeFDIzi9oscOJbaB9jiExYrEDCEjeDBEhjgLyWVshA1Z4KiXoGGlnztIemf5vg6X9
 ikD1wlzP9JAu146CgH6bHv73wDSNEW0E6fToy10nR+yijZYsDR4hsQaDHtoaOVQewDXIsaeRDuS
 RqtZ5HM1MObIRXyMetAQE/exirWvSP+3TJaYaM7/d2/rwWd9I02x7aoJANRcUn+7aStgKcydJJM
 AaMjlTRwdHPcJjXcm8F7ZzlP/t/BTHByfxQoVuB+VfKQtOzSC1BEs9WOyHCP9n3er96X8ZdVdK/
 Bhix79bwnm2ZKkZ2b7lvPWbpunUVDQ==
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=oydbHTQP;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=eGDmh4jw;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Wed, Nov 05, 2025 at 10:05:31AM +0100, Vlastimil Babka wrote:
> When a pfmemalloc allocation actually dips into reserves, the slab is
> marked accordingly and non-pfmemalloc allocations should not be allowed
> to allocate from it. The sheaves percpu caching currently doesn't follow
> this rule, so implement it before we expand sheaves usage to all caches.
> 
> Make sure objects from pfmemalloc slabs don't end up in percpu sheaves.
> When freeing, skip sheaves when freeing an object from pfmemalloc slab.
> When refilling sheaves, use __GFP_NOMEMALLOC to override any pfmemalloc
> context - the allocation will fallback to regular slab allocations when
> sheaves are depleted and can't be refilled because of the override.
> 
> For kfree_rcu(), detect pfmemalloc slabs after processing the rcu_sheaf
> after the grace period in __rcu_free_sheaf_prepare() and simply flush
> it if any object is from pfmemalloc slabs.
>
> For prefilled sheaves, try to refill them first with __GFP_NOMEMALLOC
> and if it fails, retry without __GFP_NOMEMALLOC but then mark the sheaf
> pfmemalloc, which makes it flushed back to slabs when returned.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aRG2K8YCqCZa2Yfx%40hyeyoo.
