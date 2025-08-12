Return-Path: <kasan-dev+bncBC37BC7E2QERBUU65TCAMGQEHVHX2AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 091EFB223C3
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 11:54:29 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-b46ed24bc6bsf1086299a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 02:54:28 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754992467; cv=pass;
        d=google.com; s=arc-20240605;
        b=bx3DBc6d7syEKDRmIKD677G99G0DbVriokYzO3+lo4+IAOdmby86bPA2FxXRGDl8MI
         xu+UxuGEVaS111newvb5tPDJ5aLT/+UbuhDEjCcdJYl6i/ZNTaueWQ8en3o+Ba41pbEo
         BNmpn/LNHpbzZZE06m2CqYSvGIJN1L7zSgX+jIki4OXANEDR5dFEM7IpH9YaFZtVzOjs
         V+ZqrRWin62nBm97bdV0YQ+J/WZiJPxqaqvH4QDAzwnsyX491+JXqAX7rj4+EJ7fqm8r
         dMD1hAczRFl8tO7yW6Y86NfUz0jtT6U8rcvj0q3u2ScwWSZO577bzCJJeolxbAAkFir0
         fm7Q==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=38SGmkywlIYE9v3oMDznE7EO3DRBYegIG4Lscm6etWA=;
        fh=ypslJp/d9xRcLVJ3Bp0IrOv13Wejdbz8W4Sh3s270do=;
        b=SlPKluOf/Xryi/PhJAgGLH14mj1+h6FyPtpBZWF1oIoUjKRmoEPkntBZgJWqtmzQqS
         Cwjy56yAG6aitX32K4rRO2ebP5CbkrHN5WzDh0HQuxA+5cn4vplvrZ24UWIS12Klg2/n
         8C7yW/Ykz4BWlbIjuUbY+1Z3FETtwbMVt9O9u1/OMmQwZtcm/kOWlmhsBhL5MFaCGK5x
         DyJEWGQvdH2rNpkoTFm+oGhaVojLYe39aFy1D4TJvn3TicmNmo08VSP758cW+bFAhT3x
         noIudMft9Jo1JCU5LlCN/q4E4eh4ywNLUYTB3kz4pn0RPMsEXiitfleXaS4OuMEde0N6
         e4eA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fU1K2o9K;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Sx3PlI4X;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754992467; x=1755597267; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=38SGmkywlIYE9v3oMDznE7EO3DRBYegIG4Lscm6etWA=;
        b=xNpH4X1Hh0LMCUsMPiKMAAICCMoUIsXO8CNX/szT8dxONNNjcxHXSKQfrBpuFccL6K
         KJp287A7hg39jEKvgjVayonmiVUjjBJ8hZJ4dAG/qHI3i2KRIken9N8h4W4n/Z/iCVe3
         0dBZEfTzZT7nOL4d0PQ3rVakp+nYlwLpC+fVifouhtjFGL3+vVbKF8eOzcTfdOindEDw
         48yhcXneie4YtXJoyjIG048vlViOCXuK1ZVLjAK6btQ2+FxTLTYSguKXGWkv5MZ28UwB
         cPmBCcb72e2L4ekaTcsgIT75GTHwAs07CG2mPQL1MvrsctgMtjdWGfpYgd31DyjAfdbS
         TS4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754992467; x=1755597267;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=38SGmkywlIYE9v3oMDznE7EO3DRBYegIG4Lscm6etWA=;
        b=FEV0euYlMnjTgXuHfZAUuSppx1kXHwfycIo8y6ChZn3AXKFqoXLyYYrbXViAb5GXnu
         BVhRBUcpuKPa/y7ioNE057JJvAcUmVCeM/CJTQmqiu2BbuJO5G6QH5BgjKIT3blj4MHy
         eUOOtcOPvf+mMdKT0Q/csIY1v69cMiXwOxuGw8NbeVOrYMrAyM235LMaxfNVoaNFWp5/
         ivbvcReF059aRw8CQVtQ0G+OPTmqo87Cmx+hWzFHU7Dh1UkD3BtHghsmqnzyA+/s5RZ9
         C3Id2Tbv7keTt9/PMFB/GJ9cioBEloBXFALD9+V8Km8eOR+V9HGX/sqx06x+Qkum8hve
         /e8w==
X-Forwarded-Encrypted: i=3; AJvYcCUDeqecDK0FQ6hFXLi3+2ACeaDpa8QxD4iCieLqisWYsdZZOKrGu/hz9iSaBimK3A0RJtukeQ==@lfdr.de
X-Gm-Message-State: AOJu0YwXZn51R+UtbY2CUWViB52b7NTcoCAvbsQFe+LEbRcPddwEvrPG
	gXXaOlVRGTGJPS9R50Wl3O/aZURw+w6Q6Bfgzws8pb3Ot/abQF282uKL
X-Google-Smtp-Source: AGHT+IHh764xZH15EreaupZ8uJmIrxQTo0+ZJPBbTCQd7WT9OGiJW5YNbRBPgsjYVdFZ+zBIs1+Lyw==
X-Received: by 2002:a17:902:ea11:b0:240:3239:21c7 with SMTP id d9443c01a7336-242c21dcd0bmr234829785ad.37.1754992466589;
        Tue, 12 Aug 2025 02:54:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfJBdCchVNJ9+vnlWGKza2zpStt+wHZ0eap9NjHQi2QDQ==
Received: by 2002:a17:90a:a82:b0:311:df4b:4b8d with SMTP id
 98e67ed59e1d1-3217508d928ls5264058a91.1.-pod-prod-07-us; Tue, 12 Aug 2025
 02:54:25 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVDSTF+gqRE4u+VICtjmviOvvDF/UyQ9FIGNeBPUv8FW8lbHjc+K/FEZkKiAMh3bwAjzm90VUP6Dnw=@googlegroups.com
X-Received: by 2002:a17:90b:2ccc:b0:321:79a5:835 with SMTP id 98e67ed59e1d1-32183e62a3bmr23270940a91.24.1754992465145;
        Tue, 12 Aug 2025 02:54:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754992465; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z40xg+DG9PmeJUQYdlotaan/CmQviz4iBBs+Pwj3tcujLH59qd5xzylWOwmGAoJNT5
         egoR6De30iqYXFQ+T41e5O0dnn0+EVlfQeS5+Ybv7AzHf5lalrQTviVzrXP6NSGxGFQ2
         yhLsljFcQC56SkIkC876UY7awT1dC+gTwTg7KCHGXXrmgMDAwZEaYWSd3E3Tm2wCFiC9
         311cmBPn3ygDhpp5RFIYQBDYS7yT6W2RJBc4SFhvQFKvgjKWO2SvBnYauaA62hdK8uon
         ONPkGb6uTxszrd7+2GQ0dX4jFW/bFRz9GFugtOL/KKixIcxccgE8qXFtOCPobjhVodBC
         3Oog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=L26V0d/sZNb++Teh0H1uU7SXswzzF7qQwdArp0v4v1o=;
        fh=arBNNMzXNRcqE5wdMSiM4awR/ukSz85ag6ow9K19PbI=;
        b=L8T4yjAThlgLgYSjnrc8hY7/e6F7b37ecSw9z/bggDZofuchGybnCPKGJp7S30vyhW
         WvWxVEdQUxdBOeVwSR50HbRe8H2qnFTsbHsmM1l4MbwxK4yobNeuWkPuqzSqDVyvLPdW
         byK10vh5Z1DlsD9vUazwvOZs5gT9yYw7LyQykNHYp4XgA4W5iFHBzZXgYxyfTn7wyc+d
         rNqKcY/aQKiudZuhPvS7l2slo2MokFPpgMJiV3GSsgn/KizuTZSAJnnjESEJOIJEQ0Cl
         5e3qlj0EvPp7SJRyrwWd5lMGFfpUzsy+ehQCheXAejg2b6npP1psmO2ZXLRN+2VQOGlI
         ikPg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=fU1K2o9K;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=Sx3PlI4X;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0b-00069f02.pphosted.com (mx0b-00069f02.pphosted.com. [205.220.177.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3207eba0cedsi1246756a91.1.2025.08.12.02.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Aug 2025 02:54:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.177.32 as permitted sender) client-ip=205.220.177.32;
Received: from pps.filterd (m0246632.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 57C7blj2006657;
	Tue, 12 Aug 2025 09:54:07 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 48dwxv4afv-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 12 Aug 2025 09:54:07 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 57C8rUWL030191;
	Tue, 12 Aug 2025 09:54:06 GMT
Received: from nam04-dm6-obe.outbound.protection.outlook.com (mail-dm6nam04on2072.outbound.protection.outlook.com [40.107.102.72])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 48dvs9rna1-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 12 Aug 2025 09:54:06 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=me9T+u+lQhxwLBl/eKZrzAqntkRHDpKTOedZ4jjjZD5cOFljC3dfcg+QLZaB0zdeLFo+C6JcFa41u0MXGELRdeeNbwAk8NMFQtA79tRcNJfLSe6IHPZh9fe/Xt8lS8iP7clLa8sTvH1kAzVNMM8FWJ7FybIiWw5uKz57p5OooGf17/y/82Zm70BD2vVrsIaeLkLPAMXLmlaxW8cPt3oqq+HFUa92Lui5MQt1onXV+i2iGb66ogceaNBWi3NjWuTi1DdKyaPrwAj3rpUqpUao+9FmOTAZY3N+u+uorAYrlXEyFZP3X0Cwst/uEZidMaHJIej8ycFKsvUGK9W4U/1t/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=L26V0d/sZNb++Teh0H1uU7SXswzzF7qQwdArp0v4v1o=;
 b=Ykr+yBDNWSEnF0dz4RD7AEiyjE5yLtwC5D/Y7ZVTrVxu0KUJTf6nypHBJ6b0fojr3RDTKIhnJtuyOo5gVtIYmkVICnfKvTwTYz+pf4KgkEzSvjnQX0CxpYvw2nIE/FjZl9M2ybCfZL58w4MYo3Ty89mCZvSN5Wd30gSuLr97oooKAu8X20WIbh3G8J3C/4aYoALRdQwnW3UjjbcPp919944dGoXt+vMEma2Cy87Z2QQN26UeiA8RRG89TlvqW9Pxq3wFlit2u/aQabSRnehz3hTiU5gWMcX4JwpIb6grR6BzfxSGsWlYQlBPVXv+Re4QmyUfpeb0LeHhB/m1FXOZ1g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DS4PPF6D651AD93.namprd10.prod.outlook.com (2603:10b6:f:fc00::d27) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.13; Tue, 12 Aug
 2025 09:54:03 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::f238:6143:104c:da23%7]) with mapi id 15.20.9009.021; Tue, 12 Aug 2025
 09:54:03 +0000
Date: Tue, 12 Aug 2025 18:53:49 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Dennis Zhou <dennis@kernel.org>, Andrew Morton <akpm@linux-foundation.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>, x86@kernel.org,
        Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>,
        Andy Lutomirski <luto@kernel.org>,
        Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
        Tejun Heo <tj@kernel.org>, Uladzislau Rezki <urezki@gmail.com>,
        Dave Hansen <dave.hansen@linux.intel.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Hildenbrand <david@redhat.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        "H. Peter Anvin" <hpa@zytor.com>, kasan-dev@googlegroups.com,
        Mike Rapoport <rppt@kernel.org>, Ard Biesheuvel <ardb@kernel.org>,
        linux-kernel@vger.kernel.org, Dmitry Vyukov <dvyukov@google.com>,
        Alexander Potapenko <glider@google.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Suren Baghdasaryan <surenb@google.com>, Thomas Huth <thuth@redhat.com>,
        John Hubbard <jhubbard@nvidia.com>, Michal Hocko <mhocko@suse.com>,
        "Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-mm@kvack.org,
        "Kirill A. Shutemov" <kas@kernel.org>,
        Oscar Salvador <osalvador@suse.de>, Jane Chu <jane.chu@oracle.com>,
        Gwan-gyeong Mun <gwan-gyeong.mun@intel.com>,
        "Aneesh Kumar K . V" <aneesh.kumar@linux.ibm.com>,
        Joerg Roedel <joro@8bytes.org>, Alistair Popple <apopple@nvidia.com>,
        Joao Martins <joao.m.martins@oracle.com>, linux-arch@vger.kernel.org,
        stable@vger.kernel.org
Subject: Re: [PATCH V4 mm-hotfixes 2/3] mm: introduce and use
 {pgd,p4d}_populate_kernel()
Message-ID: <aJsPLRDhan9KvPmW@hyeyoo>
References: <20250811053420.10721-1-harry.yoo@oracle.com>
 <20250811053420.10721-3-harry.yoo@oracle.com>
 <8c8c6895-53fa-4762-98a4-886a53903341@lucifer.local>
 <aJneGJSJcltEIT41@hyeyoo>
 <c3ec3012-4ba0-4b7b-bf0a-88f39ef029d8@lucifer.local>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c3ec3012-4ba0-4b7b-bf0a-88f39ef029d8@lucifer.local>
X-ClientProxiedBy: SL2P216CA0149.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:35::9) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DS4PPF6D651AD93:EE_
X-MS-Office365-Filtering-Correlation-Id: 0d769e98-78fb-4486-ba56-08ddd9862b0e
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?EB1DuavtX56t0QsPUCDuiOZtsV6aoZ29A/tWabOj20Jp082bkqLtj7DPuNxN?=
 =?us-ascii?Q?FX7Ye70QZyt0FNgu8lHNpZNpStipPtbpe8gfmAMJFo4m2LlhCzmKWm5vLs2c?=
 =?us-ascii?Q?mzqqenYkQj+99J7YvclcxHVgjy10GqFqJwq0v8U3PC+b7mWMqYBa/xemDS7y?=
 =?us-ascii?Q?Wv+8Hx+a2iEv08MARiHJettJHg3UDxdx5aFlJMt6BHaKXjyyala7+OriXy6x?=
 =?us-ascii?Q?t2tx33eQRYvRMEvJmTQzVN3DNxiqQPN9rYULwGSxDQ6FD3rbvwCQDN2YUIhy?=
 =?us-ascii?Q?3cjrYMlkHdOViRuQBbt9TPPxDE6B3K+p2Lzz9Xy2dd2i7oNaTHwJUhmCbcX4?=
 =?us-ascii?Q?KYaA4hHdNfA2//d7VAgoT7vUkvypQrTEvU4vEdQa3E3/DQw+oAB4zdv2sYOP?=
 =?us-ascii?Q?gOziQILv8BoIBlqCQS3rRlG6/jmG0LiXiP3eXnxUnH++4P9QCEWR7ccQNq2/?=
 =?us-ascii?Q?qNh10PnA2NjTwd1rwHh0ESRNRhYVX7x4AB7I61g0jnq4Au4J8i+4p6GWTyDa?=
 =?us-ascii?Q?nDUGN9AzB2F1T5OqLuF2M7YH4PB0/Jd9mZpjN1SGvYqIKWMF+alkwzoHGTYS?=
 =?us-ascii?Q?YtPrI7nl0sLwqZpEzf7UmN8KoVxUP9osCUcFhlR29uhX8DFrnqVV2fYK0M3j?=
 =?us-ascii?Q?7NpQ18QEBfZhl6OMLdVMF/RsyQuKX/2fhfY3c41CaVInmpnjFGs4gUbObKGr?=
 =?us-ascii?Q?WXgmXjPB2W+gUoVK9SsMMg15dmyikTx/ydj4G1dMKbTbv9JUvOjq6E4yWnWt?=
 =?us-ascii?Q?bB01Vnn1fqdtUKoHAetEee6pw0uaD00dj36Myrwhfnsiy8Am4MiGFJhfWSay?=
 =?us-ascii?Q?VIQOsfWCGAgYrZvo32T1bKIlqH3T1q+hS2DWqEIhUJ76+NjE0YRUW4RQluOf?=
 =?us-ascii?Q?NTdszp113VNHoYLYHLiR0Q/IsO/2f1OujxMhDuyY6olUmsBSBGK8beoXXvUu?=
 =?us-ascii?Q?WzA2b8YykiKQwuKpSu7PJj31r4u7FbaTtBtZOjl74uB7d8oLHqByo/K11ZRZ?=
 =?us-ascii?Q?nNzbbiT5tKw5F4/Cz5TKfxMFuU9qEuRf8LAq4v6Gkfl0VyE0U48+Qpf4Oku9?=
 =?us-ascii?Q?Ra1nYmYl855sizHOQK3RPKp1zrghPJQw64cHet16lb98+eV0fEFD+U+0YDXW?=
 =?us-ascii?Q?t2GWeaAF/f2hK0DbpBtjMKizMQYJhczJpaW0Mm2tA3+xdAKE9sF5ImeaWaoN?=
 =?us-ascii?Q?Y1wY7kUeGb2l0wsQ8bhCFpn2Vz3WN8cmeO4iVFcjXL9/i6QkAWPQcHsAUj9S?=
 =?us-ascii?Q?7n5AUiQ24InnTHNIzSpjLExpSgOcYP9gEX4RLlxcRZ22z0Zp6cDDcBL+safp?=
 =?us-ascii?Q?ls7dUTd0sKLYiMU/snQQ1ZsBZDad1pnKpVfpGAs7j0hcCxFsE44nEP/73d1D?=
 =?us-ascii?Q?10m35c2+q1nqN7GKoEJkptsK+2ESGaIrMcDoErFOitQCFY+P9PhmWiRdgk0J?=
 =?us-ascii?Q?zVtn5s8DvZc=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?zuwwsIlzm91kXSx7vWU7IDoa+PV878egqJRBeDBunQSnZKsVJtleslqFwpDA?=
 =?us-ascii?Q?TjF1XrWqRBkdW0bUZKa/R2MA9shzAVA++tKvm7PXrRtFNqZRmbP7d1KSKAZD?=
 =?us-ascii?Q?lJy1WYrzlOfAkpkPsR8wT/hts47bDiAe/wnrLaEB7+QuFfO7KyAWerKDizSG?=
 =?us-ascii?Q?ntSuwX6KTXRCmp0vGhdUvnM9dkbxMG+vIV9eH4PBsrOWskltfU2Pm1rXtyz2?=
 =?us-ascii?Q?LpB9ZZu/ibgBecfSZnJZyFFXoYBLOh/JPJ5Jdk2krO+/l4mXxcUM5+kDfbUx?=
 =?us-ascii?Q?0UQlKBsPNVyxqwVT4O2P+x2Y9KERvuLNmInX2mn1x+/JW9+YPYgnZ/s0+hW1?=
 =?us-ascii?Q?/BGsG8bHBzaTGP2/OYZOXuMM2opG4CC+VqTffu0jYopIK/3uoG9PH5ObySAn?=
 =?us-ascii?Q?MiFZ0MSTM7OtP+8xbyyXsEclovCltttcUb84bfp+iqJE8lTKxy8bbcBKOQIj?=
 =?us-ascii?Q?npKFAKzpC5rRf5991RWQKIN7E/UzvQwH8doggj8/nNbhCnqeCxqbM0bupy8w?=
 =?us-ascii?Q?p3A7tJyLt5CqoplxuY+9XZx+bZJxLw0wGG81oQTJUuOAedMG03UnAQLy5m8d?=
 =?us-ascii?Q?Yo7Mvl9qF1FQxAkbfG8EPJkaEiiMnknRx68weaPYpVmhKp3jfb7/4n95KS8D?=
 =?us-ascii?Q?8ceRwKXuORtNobTgJH/0F1yYj/Iq+5Ksm5aDgNf4caZ0E9fVvhPPI/jfGDB9?=
 =?us-ascii?Q?PgTTrbJdg2jHENJncQLBCRmdjL/zTWTmaAnAJGOmrFle1AeZy2uXVxifvDjF?=
 =?us-ascii?Q?GtsbCGRV/M4Ulj1CImnl61OpsIkhqJ5GYodAgzP/kab4s5CNs58VxUYSLKlK?=
 =?us-ascii?Q?cEY/+/vhiaTda0usVVLXF8S1QVzLbVLSnevgHJAv6sTZmccdpbaXSAjG7TFr?=
 =?us-ascii?Q?1GkR/v+ofkDSIg/co/Oujc0AeipfTXPPjpTTVulpShkdcbOgLk9qVlWQaedm?=
 =?us-ascii?Q?tJQ7DY6LFEnjUCNm4WwrehBSmgWAkGkpjIfb5nuRVVvV9LANiuFxOV23e8Tz?=
 =?us-ascii?Q?JFm9+l7pXvhUlujU4jyjYYAwk4P+CW93IxXBuBo8xx0LPmnFQ38OTAKfar+m?=
 =?us-ascii?Q?dYlOu8b+j3qzQfHUUKXSQljA6BigygkflcTI1uGi3VPLEUEzNNHOpn9ynS8+?=
 =?us-ascii?Q?3RVjlXLHZcys6Zr4U8mt0MOqd4iB1xwKBdKWSpbdqSVVHYyXkpwkoPzlgEId?=
 =?us-ascii?Q?69X32vVkSjS32car0yHt9+vj0TFDZ/PwlOWKgQ1xdrbXerif2r5s7BslgtvX?=
 =?us-ascii?Q?H92wYgLTP6/s5IcRRxcv9lUiC2DkcgOkcXyPbSb5WlYj/KDxKdQWBtwnaqMC?=
 =?us-ascii?Q?gXaP04vtWE1xwlxBbgHefKZSp1xg0jBbvDUDV9tDGT/oxQbOHAGjMjK0kxUN?=
 =?us-ascii?Q?dQo1BZy5B27ZWC3vpf9FicvxnoQ2+aAPC5F/uRtvQKqPmkC/pva+SpZKBQ1s?=
 =?us-ascii?Q?9ptBQu+yvLbfXeRzd1D7l51HI0cP9RJb9kOLpvi6O+9h4r4+cRYZropWZhb4?=
 =?us-ascii?Q?17CTU92HBSh3lTDnI0XU1br+zeZcdbTniLc7YkdOGXwmel/hprrLX1WKDXAO?=
 =?us-ascii?Q?Nsc4Hzfs9DQeH5h2/RCF5M8MpG0o9N4bhMMFikHb?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: Su87cfW/Xe/W7W/RqwhfkSyghFerZdGh8NsIoVy0eOteTZQ8jFZK/euQ5oMflQDttYFQ7hdlQnZyGR3XD/iNn0oWkKFa9Ll45QnHgwPefNybtR9yPZtjegCNHU09sjZ+p5CMTx4QsrH6S4KjbEmAoRqSGjFOd665W21fIuQ5bV1JHPpkDqYlFGMftYlfyqFFdOhBh0RFibM86TgbpNWD+lwl4Fge/Y4Hx3fcGmTsi0qM5uqsEH3LQ8dt/8Vs+u3EU5W4lQIM+54Mt8W68EWHZi1gQrWvdcl7TOpMwmbQ9O6ca4kfM1h1A0/sMoYWUnKTMzQXwXUnbzNZ47wlNCo/ugFVy+paDFdwhsqYIzCnYwsBRJ49IUQerp3P8jt1N+Yyw66MbxSGWVsupT+YyuAAeg0pt46aEkjOeAgY0gfLff4N9xOTpRNUtkAeRNfRfAOCFI/DBiJXVA60dfIQ3+WQgNn3qT+1ixEamsVgyszWg7JUyaDo+WmkHw0zli8Y3WgcRmZNJ8pJa5FWwGjAXX+7bmy4zAabbalrp7HxjVXmft+pVSjOaRGpW51H959Fgba8B/PLvBfII3rzcGqc+gqVkoDBo9A3YWtf0QUXm8hLPV8=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 0d769e98-78fb-4486-ba56-08ddd9862b0e
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Aug 2025 09:54:02.9641
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 4wo1kWv9NbZ3ObJnvTHm4mIwF3HSwG7g99OR3BV+h5jfi8EiKzzNgToj+vVh3mdmKogbphjq+U1+jE7OSnSthA==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS4PPF6D651AD93
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1099,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-08-12_04,2025-08-11_01,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 phishscore=0
 adultscore=0 mlxscore=0 bulkscore=0 spamscore=0 mlxlogscore=999
 suspectscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2507300000 definitions=main-2508120094
X-Proofpoint-GUID: LxESXiUBpnGUxuugotJgOF_aTPD2J5KC
X-Proofpoint-ORIG-GUID: LxESXiUBpnGUxuugotJgOF_aTPD2J5KC
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwODEyMDA5NCBTYWx0ZWRfX5hhnxsWWEQOy
 JYNnw/EzEzFvKmTlM3iQ/0yR+7C3UYe5m21iu/JAj919T2MRt5P84NeFwkQB3821rN3OhfeCgpS
 losi74xH0EKxNN96F5JEUPelK6ekkquTeb+v4TiFc3r7GmXOZMstLoC014n1nl6orD1JWr2qb3z
 cCYr3m2GYXQgbIVRFuY7A7r1nJZVyRDiV57pPHy1eI4x9MfJRJFBrDQCMZ8yBcG4dlV0FMxKIG7
 h8aN+nw8MSlnU+qb8pkjP1ulplmf9/2xVQQv3AD9Y16YLinXTZiEgQi6RMwGHMG+o8WpK6n/B1x
 RRXu1cHjFJ2soMKbf+H7oHernYr+31Vz8rvvXpBdfOeDE/LPMHGnizlRTsxjolF4ZuKos5MEPBV
 R3jOEN+p27XONjoRjN5qKxQOd/GFh4tGuj5j0xmse/CFFfDQnnCH7kNXcoqbr8q8n3zLbwfH
X-Authority-Analysis: v=2.4 cv=KJZaDEFo c=1 sm=1 tr=0 ts=689b0f3f cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=2OwXVqhp2XgA:10 a=GoEa3M9JfhUA:10 a=VwQbUJbxAAAA:8 a=QyXUC8HyAAAA:8
 a=yPCof4ZbAAAA:8 a=xvrkwoS1mEYJalSrI2oA:9 a=CjuIK1q_8ugA:10
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=fU1K2o9K;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=Sx3PlI4X;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Aug 11, 2025 at 01:18:12PM +0100, Lorenzo Stoakes wrote:
> On Mon, Aug 11, 2025 at 09:12:08PM +0900, Harry Yoo wrote:
> > On Mon, Aug 11, 2025 at 12:38:37PM +0100, Lorenzo Stoakes wrote:
> > > On Mon, Aug 11, 2025 at 02:34:19PM +0900, Harry Yoo wrote:
> > > > Introduce and use {pgd,p4d}_populate_kernel() in core MM code when
> > > > populating PGD and P4D entries for the kernel address space.
> > > > These helpers ensure proper synchronization of page tables when
> > > > updating the kernel portion of top-level page tables.
> > > >
> > > > Until now, the kernel has relied on each architecture to handle
> > > > synchronization of top-level page tables in an ad-hoc manner.
> > > > For example, see commit 9b861528a801 ("x86-64, mem: Update all PGDs for
> > > > direct mapping and vmemmap mapping changes").
> > > >
> > > > However, this approach has proven fragile for following reasons:
> > > >
> > > >   1) It is easy to forget to perform the necessary page table
> > > >      synchronization when introducing new changes.
> > > >      For instance, commit 4917f55b4ef9 ("mm/sparse-vmemmap: improve memory
> > > >      savings for compound devmaps") overlooked the need to synchronize
> > > >      page tables for the vmemmap area.
> > > >
> > > >   2) It is also easy to overlook that the vmemmap and direct mapping areas
> > > >      must not be accessed before explicit page table synchronization.
> > > >      For example, commit 8d400913c231 ("x86/vmemmap: handle unpopulated
> > > >      sub-pmd ranges")) caused crashes by accessing the vmemmap area
> > > >      before calling sync_global_pgds().
> > > >
> > > > To address this, as suggested by Dave Hansen, introduce _kernel() variants
> > > > of the page table population helpers, which invoke architecture-specific
> > > > hooks to properly synchronize page tables. These are introduced in a new
> > > > header file, include/linux/pgalloc.h, so they can be called from common code.
> > > >
> > > > They reuse existing infrastructure for vmalloc and ioremap.
> > > > Synchronization requirements are determined by ARCH_PAGE_TABLE_SYNC_MASK,
> > > > and the actual synchronization is performed by arch_sync_kernel_mappings().
> > > >
> > > > This change currently targets only x86_64, so only PGD and P4D level
> >
> > Hi Lorenzo, thanks for looking at this!
> >
> > > Well, arm defines ARCH_PAGE_TABLE_SYNC_MASK in arch/arm/include/asm/page.h. But
> > > it aliases this to PGTBL_PMD_MODIFIED so will remain unaffected :)
> >
> > Oh, here I just intended to explain why I didn't implement
> > {pud,pmd}_populate_kernel().
> 
> I'd add that arm handles PGTBL_PMD_MODIFIED and therefore remains unaffected
> just to be super clear.

Will do:

This change currently targets only x86_64, so only PGD and P4D level
helpers are introduced. Currently, these helpers are no-ops since no
architecture sets PGTBL_{PGD,P4D}_MODIFIED in ARCH_PAGE_TABLE_SYNC_MASK.

In theory, PUD and PMD level helpers can be added later if needed by
other architectures. For now, 32-bit architectures (x86-32 and arm)
only handle PGTBL_PMD_MODIFIED, so p*d_populate_kernel() will never
affect them unless we introduce a PMD level helper.

> > > > helpers are introduced. In theory, PUD and PMD level helpers can be added
> > > > later if needed by other architectures.
> > > >
> > > > Currently this is a no-op, since no architecture sets
> > > > PGTBL_{PGD,P4D}_MODIFIED in ARCH_PAGE_TABLE_SYNC_MASK.
> > > >
> > > > Cc: <stable@vger.kernel.org>
> > > > Fixes: 8d400913c231 ("x86/vmemmap: handle unpopulated sub-pmd ranges")
> > > > Suggested-by: Dave Hansen <dave.hansen@linux.intel.com>
> > > > Signed-off-by: Harry Yoo <harry.yoo@oracle.com>
> 
> Given that I missed you fixed the vmalloc.h thing, this LGTM so:
> 
> Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

Thanks!

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJsPLRDhan9KvPmW%40hyeyoo.
