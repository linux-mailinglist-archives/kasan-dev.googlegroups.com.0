Return-Path: <kasan-dev+bncBCYIJU5JTINRBHVW5LDAMGQES75GGFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id E262ABA9A70
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 16:43:44 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-b56ae0c8226sf3298310a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 07:43:44 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1759157023; cv=pass;
        d=google.com; s=arc-20240605;
        b=cQ88r2qIBesUJ4iij4FRBlh3fZjqiYXHuXQVP7NRISu9VYTmZirSi5aAaGSZVOKzNL
         19Exugup6mt7d3PgDzElOQPFHi/DQkeUpNlTW+jdSKCZvLox8FVZrcLFWrUmxwrt+/bD
         QQU6vBBnn0mvuWMrJoh8uW3jFUDsthR4MyxhQRtnVQeUevh5BcBBfgyrwdXbM/C6chCa
         0m0LF+OZg6ToS/JXfWVttcCSNoS9HCH9cmD3DB33fUcSp31pxfsocW+M5cqseBemCIfG
         AECGWRV3yPGDu8n0Ye6BIt6c2UAf25t93lS5wxBRGZ6ZFcQAaMNAtCM8vNm0k6Tvus85
         vKCA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :in-reply-to:content-disposition:references:mail-followup-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=8VuIGFz4falkJAZRyNvaaV24C3wn96eKVoCT1bvx5PI=;
        fh=pWMudHYIPnIz/3k2KOIzKfemkamLi27TTPIqT1G/1hs=;
        b=T+wlmK5AkepFQ3+4Yn/8FvDoB58coS+eyf6OzE3eLwdGpl0BXnmEJpIbOZlwd9c/4p
         m1OK2k/EQgCKHbG2xB8g5VpLLm4LDdT6felUoz5KUCGoa6Nj4SYVYDqv2ZVS68H8qQM/
         vbkW56sgTK5dfLu4o8MEpR2IAJvlWoqYosWogHAF4owy+4VzJmvQOkrvwqSC/vuhX1Vf
         ckMmaQuVNx208VUrUmntcufmxDbDWkJZyGeEwW5kxYlN46wKvNBFtAn+LmxAr0x+R8Pd
         ApBqd0XEjyMCBQicPum8qPhccWldgQYtsZhqfdzssKwgMdzmBD/mQa5uO/nq7PnCooxo
         FHcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Y+IkF/2V";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=OJlLdv0h;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759157023; x=1759761823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8VuIGFz4falkJAZRyNvaaV24C3wn96eKVoCT1bvx5PI=;
        b=oCYC4xVbwc/0Y7pflSTAaNzQBeMVGExnS8vGwZjoy6+pFmK3TLQ6PwBW2+ZCuDFXmP
         LT9py9Se04MxWjHnFsaIthkdoe+KpEqOFYv46CXvkuC5W840orQlnYwPr4MApgyDVd2F
         1tv99HFkMdMKye55UCHg+0hRIvbdo0R2vtsxGcPJfNyM3j1+9wl6UTOJBdkE+ABlhqqW
         55ewNfR62IlNK/LgFTcilhPV/qE9iheFcOdJNaXCIdxorFumjs4W5fhAiTl6V6FCkLkh
         gZyQOtnR9VnDWCtqwJlPfGEZNK/b0NEtkPI1LepCIiklNjXecVdcj6nFAKZVjvLw08G9
         FF0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759157023; x=1759761823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=8VuIGFz4falkJAZRyNvaaV24C3wn96eKVoCT1bvx5PI=;
        b=qg3b8SZ1cArduEvjDcPAYxGYr7m1GRHRj4qDv3b7um2mytlISheg8pkW8FRHiroD1t
         NAK+iSrGiekPfs76s6BDx9mPHPF9qyrjOX7SPLITT4r0FBrm5Rxts1iMecqnRotvmtnM
         Fub4jQxrFXh53YhMZq0l2t0SSzE6oai2I81QR8GGu9MhKWYHB6sTUGzi70/VtOZopjAn
         6EQ1FFEJ3fTSokcKmx5DzjsPE8tXr6V4vNuyO6jgcGmby2bffD3aG/ZGgv2js8p3wbsx
         /CizaanBJYfDy18o9jcqRQsMv4vaMY5aO0ZTSfAF7vbH+c9YIzoRpiACBt/rc7bDh2bC
         neBA==
X-Forwarded-Encrypted: i=3; AJvYcCWbTkbT57c+wiG19Tfpa0ymq24eBIDiKligEbrqPC+NkFYMjsgqehcKczyiUj3S1WjnR5RirQ==@lfdr.de
X-Gm-Message-State: AOJu0YwYQcyjgYOI2LmADama+syZ7A2G11ptwpzn007yF8K2TabvOOeO
	xRiy6zOPW+81FfPJvTQ4i9ZF1axxwY8aCRac9Cu1sfWO87ZU/Sm0b2MH
X-Google-Smtp-Source: AGHT+IHPfeSp8uObM6n+b/jr6zALvX1Pj34HCjTRAPs4qBrPa60zNOi8gXU7yAE+ZTz5VcWbOnqOVQ==
X-Received: by 2002:a17:90b:4a81:b0:32e:87fa:d96a with SMTP id 98e67ed59e1d1-3342a2df10fmr19460500a91.26.1759157022382;
        Mon, 29 Sep 2025 07:43:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7sYxzDHnpPxbu7fp18YhkKyB0DOHwfFxY5az+6KGy2mA=="
Received: by 2002:a17:90b:2512:b0:32d:f96b:10e5 with SMTP id
 98e67ed59e1d1-3342a5c548als3056090a91.1.-pod-prod-02-us; Mon, 29 Sep 2025
 07:43:40 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCX3ZG+qsqQ6QHna08p0c0BOU/lKaeFI4bijlODHSx9jrOCIBrM8kNqS2pEvdSyqHkhy0eVeK7C8rCE=@googlegroups.com
X-Received: by 2002:a17:90b:3a8c:b0:32e:4924:6902 with SMTP id 98e67ed59e1d1-3342a241270mr18542719a91.3.1759157020237;
        Mon, 29 Sep 2025 07:43:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759157020; cv=pass;
        d=google.com; s=arc-20240605;
        b=T/xQzJ20ACWbc39bUiF7Lm2gbpdbq+OMgiVXZaa9iD3QMIPbK0Dc6Mns7RAe0NGMwZ
         eTCCe4Qo9v5uF3aigx7Pnlz8l5uhaL4ybE/UIVol2TU+yigvEQVJkNuoNW3b5JO1aosQ
         GO+M2zoE6jGm12OW9aKiXP4c80ct3O1CDMGyDfXsPfo9IE0chAiLVXb7xly/tSBw0z6l
         H8o9kAlWdl8esy6yKd8Pp/Fw5hEH03Laf/90J9v1AuPWOOxz3Qb4UcJNxmbcD2Gkeg6f
         R/jUNgK+8hwYjnKCK6ZDXJcEysrEs56fb69UNa5YcS5I5FCEpAntUrzoO5GyuizmBZXt
         boIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:in-reply-to:content-disposition:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature
         :dkim-signature;
        bh=i9ZAayJo/qb6vZT/Nf5FZrbPUuq7bxT4zySoXnZaa7I=;
        fh=hdZS8zsco6dH1+gCeylKndd/jSgIwWVEoBecLvzmulg=;
        b=O3RRqklpH/u34itLVYtndA11k9FcK0/2oSF3BFcUQWN9UNlJd9VS54nLeOYpkwK70a
         FTKGAOWLnCXqaibZdBZy6PPpujt+bdOyToJyJNq/sbSyOdRbI09r/cugr3eZ+kERZmsF
         ZCl6+wlrIS1wHG7Ers/WRU0mHuKlXkNy2UDfyGc110Fx/MtkuWRpatdaUO1JuNOng/dj
         gErb9VII2Le2v2F6W5QZ2UbSA94AufRF4qREdZveCU8ddz2hBGtaVGRy12J3yCgbyAen
         YBTCpm70OPWTgW+5TfF6RQJHQAntQZER+lE8KWowHYdP50lKvVPMuM4wyWiIK0sLnw+f
         p/XQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b="Y+IkF/2V";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=OJlLdv0h;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=liam.howlett@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3341bde8647si664798a91.3.2025.09.29.07.43.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Sep 2025 07:43:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of liam.howlett@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246617.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 58TCR4PS027221;
	Mon, 29 Sep 2025 14:43:35 GMT
Received: from iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta01.appoci.oracle.com [130.35.100.223])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 49fse70dep-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 29 Sep 2025 14:43:35 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 58TE5BFl001952;
	Mon, 29 Sep 2025 14:43:33 GMT
Received: from sa9pr02cu001.outbound.protection.outlook.com (mail-southcentralusazon11013004.outbound.protection.outlook.com [40.93.196.4])
	by iadpaimrmta01.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 49e6cd2e8x-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Mon, 29 Sep 2025 14:43:33 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=C68UOIu+z1r6fA3FjhDORzCeRKOt2tc1wyDDe3swjVkEvQ4D3CSykCZkFiEixXuUJyuvtdUG4Qd438KmKBXImQb+vNkS5ZEszZ8QNyqiUquZIKlXeCIDrRPP+0hcVtiyPLw57HkCgSsNmsSDxnofOnnbk6xLFRzHE4zXkTmU7yk17NNnyYHsvJaVUXynIe88pQtSP6OW6mk9dbf65/wZotMbWR/16Hb62+APwNYVH16mK0W2isFOHTflVbSbzme4egbHUYz5ZoF/u4xjHdR3cxAVv9akAPh/XPF/0MguDVJ9ef0Hv4j7oebDmn5MCc0EeLoLYX/cRkY8EE+mo7QkSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=i9ZAayJo/qb6vZT/Nf5FZrbPUuq7bxT4zySoXnZaa7I=;
 b=ihndpDB7YWvTcx+b6V3rpKzVJKV2O6RDtIMu5u+INDANJvRWIsVPW+3Gy5RuM0bX2kRYqp8DYuNJNgH/+EZGFJneLQDElO5VgPbTpHCa0J9jp2QWInCZgPuCR5NqLJ5n/sy2NQbA4kzgh+G+Nf8vis9wacFYAm0BEd5yCo76GZui582zMNjiVHpRjpXJvVdJ8+GhivktfY4T3QQ4I4E8EeI19pmDp1Nicg7vKRqwXEPfjNN/03daNZF+L66cgZnevFyndR8X+gpJNf5nlzcUqdPdInu+WxBTxh1dWb3JXIl/JU0haFH4havX7feWhdG07O2w+KbGsT4rTTpO0TXlLg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from PH0PR10MB5777.namprd10.prod.outlook.com (2603:10b6:510:128::16)
 by CH3PR10MB7632.namprd10.prod.outlook.com (2603:10b6:610:17f::19) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9160.16; Mon, 29 Sep
 2025 14:43:01 +0000
Received: from PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c]) by PH0PR10MB5777.namprd10.prod.outlook.com
 ([fe80::75a8:21cc:f343:f68c%7]) with mapi id 15.20.9160.015; Mon, 29 Sep 2025
 14:43:00 +0000
Date: Mon, 29 Sep 2025 10:42:55 -0400
From: "'Liam R. Howlett' via kasan-dev" <kasan-dev@googlegroups.com>
To: "jianyun.gao" <jianyungao89@gmail.com>
Cc: linux-mm@kvack.org, SeongJae Park <sj@kernel.org>,
        Andrew Morton <akpm@linux-foundation.org>,
        David Hildenbrand <david@redhat.com>, Jason Gunthorpe <jgg@ziepe.ca>,
        John Hubbard <jhubbard@nvidia.com>, Peter Xu <peterx@redhat.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        Xu Xin <xu.xin16@zte.com.cn>,
        Chengming Zhou <chengming.zhou@linux.dev>,
        Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>,
        Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
        Christoph Lameter <cl@gentwo.org>,
        David Rientjes <rientjes@google.com>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Harry Yoo <harry.yoo@oracle.com>,
        Kemeng Shi <shikemeng@huaweicloud.com>,
        Kairui Song <kasong@tencent.com>, Nhat Pham <nphamcs@gmail.com>,
        Baoquan He <bhe@redhat.com>, Barry Song <baohua@kernel.org>,
        Chris Li <chrisl@kernel.org>, Jann Horn <jannh@google.com>,
        Pedro Falcato <pfalcato@suse.de>,
        "open list:DATA ACCESS MONITOR" <damon@lists.linux.dev>,
        open list <linux-kernel@vger.kernel.org>,
        "open list:KMSAN" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] mm: Fix some typos in mm module
Message-ID: <gqrtcqx6yggzox5ze3eodz6vgzdatjyiuadigptvguamon4p2b@znmbdpruwqil>
Mail-Followup-To: "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	"jianyun.gao" <jianyungao89@gmail.com>, linux-mm@kvack.org, SeongJae Park <sj@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, John Hubbard <jhubbard@nvidia.com>, Peter Xu <peterx@redhat.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Xu Xin <xu.xin16@zte.com.cn>, 
	Chengming Zhou <chengming.zhou@linux.dev>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, 
	Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Kemeng Shi <shikemeng@huaweicloud.com>, Kairui Song <kasong@tencent.com>, Nhat Pham <nphamcs@gmail.com>, 
	Baoquan He <bhe@redhat.com>, Barry Song <baohua@kernel.org>, Chris Li <chrisl@kernel.org>, 
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>, 
	"open list:DATA ACCESS MONITOR" <damon@lists.linux.dev>, open list <linux-kernel@vger.kernel.org>, 
	"open list:KMSAN" <kasan-dev@googlegroups.com>
References: <20250927080635.1502997-1-jianyungao89@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250927080635.1502997-1-jianyungao89@gmail.com>
User-Agent: NeoMutt/20250510
X-ClientProxiedBy: YT4PR01CA0095.CANPRD01.PROD.OUTLOOK.COM
 (2603:10b6:b01:ff::18) To PH0PR10MB5777.namprd10.prod.outlook.com
 (2603:10b6:510:128::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH0PR10MB5777:EE_|CH3PR10MB7632:EE_
X-MS-Office365-Filtering-Correlation-Id: 13e4309d-f39c-410d-e6ad-08ddff667cd3
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|7416014|376014|366016|1800799024|7053199007|27256017;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?ox0l7OkLxTpz368vcd01mJae9in+HlZwGqzjhEgWwTCS0eXbjVQ4EolCX5Qf?=
 =?us-ascii?Q?TnJQGds4JYLUxGHley0XelvEOuGOCxnacUooPLr4f65T0SG1vgkMPzwnjXe+?=
 =?us-ascii?Q?284iWtpqmH6gLNQRAL9Q6Aa7JyNWKONaCeqpfaBcy1GEQb6JHuD0NuvujKCJ?=
 =?us-ascii?Q?wPtcteA+lgC5esGChLjta+jwWlx9rVUb3xlXLk/s980WLsHZvZkp1u89EL3b?=
 =?us-ascii?Q?EpirVi26a8Eja824jJFPJhucV7iMqrA83QSfwrgzw1Y7GTS0/dN9yKV4Sz1o?=
 =?us-ascii?Q?wOaluDMCXsE5K7nZ/5iRZJvAd7d1n4eytdCydg7DBNzJHEvz2Xi0+CQVi8d9?=
 =?us-ascii?Q?usF/d6OFqufp68rESU/6RT+q8OaM6AVs4OUDbmAzL2wJ2GmJZlEoI49yLSsO?=
 =?us-ascii?Q?R+D0Iklm8XuYZXtx7tMlrFS3REuHALDvF98g43QoB+/fpdquqdOuutRhQfus?=
 =?us-ascii?Q?mbFEZnWAD1WZc4x5KVIiPtxWS7vWBtrJSi0JXUmfAm7lr8YXLrr/oAWZK3FL?=
 =?us-ascii?Q?QM8jF1Gs8J4qvf2WDAMD8gqd0sl9dVWG4dkdxjbamvzilvW6Ju4HlXpQrPlZ?=
 =?us-ascii?Q?Bdm2aWCTulIqWL/AZM2jA3Ria/quZZDec6GNKcOf5rEZgRZkyJTn8ZFlYFN9?=
 =?us-ascii?Q?bphUIB2z0CB7SD/8nhYKL23QTcwKNOEtX6KQBxGCAnZtZgPFE8xoof9Mwvpj?=
 =?us-ascii?Q?qKG5eT/kNcn91arWT/9OaZnCTpoIfaQlBa80NyAcwQ+Idsywj8y3CS5Fw7LU?=
 =?us-ascii?Q?kr0erWPOh8GZknQRoG3bD/Ne/02g36N74cBfAAi7M/RaJyhZ6l0RHfGl2jDZ?=
 =?us-ascii?Q?cxxV3yK2IPf0r1idwUdSMKntWMpOdYKtdZPTApN0KtL8qc+hDwx7DqhhoAnK?=
 =?us-ascii?Q?oiOxu4zBAU+8lph9wwRhmBOla6OQDeJf4UCEUtXG++mwY3NZfHskDE3RS7QM?=
 =?us-ascii?Q?K8brvDOkVfiHD4uJSn0dIFU1zQRAE27NkIK8xCIwHjFs3lhGhWmPoZmo2qYK?=
 =?us-ascii?Q?pB8Zt/aojZ0BAbXS57RyPULpZ4GxFv2HsxWAxM05eZJnoFLbPz2PYbNYP45m?=
 =?us-ascii?Q?HiXrW0I6CSSbevyH5QduI2GvGp7RBMA1z9zEhZaDKm8InnRajOZ0PWOZXEC7?=
 =?us-ascii?Q?mI13izlenoaq0Ja9X6T520AHhfJxLf3cywEKzwQzal/eiI1vh3iP80LgstOg?=
 =?us-ascii?Q?cuY4vxxyFK+lBdXarRzNuhC0r9LiNhSNwwQhYKjeNZqwTM3SG4CCDPRvcXfP?=
 =?us-ascii?Q?j1dypWVeISh+m3DVDiM22Elj8QUkCMSWNEl3oKIOeHXze838xRooDKw1A8xs?=
 =?us-ascii?Q?o2q1j0jvaJcHw6hZ7MSVI2yxgJfZ0uFqE31ZPcNx+jXF5QRT0CgKFwRw+9Vx?=
 =?us-ascii?Q?U2Qm8smw1TpNToDfifXXCEzumKVrBdm0blm5CS+G2DwmN8bkNQPQDFW0YbVf?=
 =?us-ascii?Q?T2IZHLg6MGkjG6W3YD6I9qDofl27ZHxhCcc9OOC4V7HqN+vQ8/ft/3YnjLYV?=
 =?us-ascii?Q?Bjt6YX4PNduX/EtJKUbVTLEYuJ674lKJk+wT?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR10MB5777.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(366016)(1800799024)(7053199007)(27256017);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?EV2OnYzLOIXQ//1GO5AT+LPPyJ6HjxhQv8P8Sul68qPd2h6g1VBPJhWU3tQL?=
 =?us-ascii?Q?8c525QTgKJPT0PYhwZ2aj3yh66vqZ8ClphmmXCPipgI8p0hCG2E4VarKsbQK?=
 =?us-ascii?Q?raM9+Q+YCNDRZdwDiRUR6EDKoKcykhu3cp5p0pT9VbH/azBVswXLryCG2T3j?=
 =?us-ascii?Q?/FusIC1YWFyzlqFGcRaUndp69CNTkzlDk7RShkBnCrawx9up4ZQrjezWI2F2?=
 =?us-ascii?Q?sHjltbZkkjBNuCutNIdwc+QmGNbFWrjx3pYre7Pj5LKTXSZAEnLQo9jrgVGR?=
 =?us-ascii?Q?ImLWoqiMM6eTi0HuwO5QYJRzI8DBAVpdrWCq4TMozsrPglLdJIBTAriwmXXn?=
 =?us-ascii?Q?64ZAP7ZZOyz9ow1UBqZO2Bs9XXVKuKqnYcMlBL9+nOPCMQEccDMUvY2n2J/0?=
 =?us-ascii?Q?5Q5xhA+PIt32zQhLiPK3eMwwPcvLlvNnLEDve0WRWEtXN0PHqyvY4bZZDmg7?=
 =?us-ascii?Q?JLPUQdpsrszn64737gyJ6Tz4xAXr/BPxNzU4W//gBoittGO71pbuKO/srMNz?=
 =?us-ascii?Q?IDoKMgXN88ljIpNUtoqr4HSYL4no5nygJZYeBW+D5KDngZ4Q3c8zQZHlu+PY?=
 =?us-ascii?Q?3SOR6zHx81IFGMRsHAF08Gp7e8arb8G2Q7y0gl3sMa5KCkqDTdLldJYMcj5m?=
 =?us-ascii?Q?y5aZy4QCJmsvlotlaETbGsei8ZwsHbKhxlRrcJrVQW/QqKNi2YqSEtOy+x7G?=
 =?us-ascii?Q?Eja2nssWxw+9Nfq7s+8thehmvmT8SYABcYqfVyEc4R59n/P3gTrr4/EPc9uv?=
 =?us-ascii?Q?UmcYRcWaQWUSjN6jEsS2hSohwkzV3HHGKgJDgk2iIS1D4oD224pQPmvEParU?=
 =?us-ascii?Q?eoRra4gCj8SjL2yVVFqk0b5D8Vr2VTABVLfjt1+3tz9JzENCEUPww/a3f/20?=
 =?us-ascii?Q?Sd5lY//W/Jhg7Gup1+1BGKu5x1bJx3QzAVLEKFDQnXMXOsDqh+QLl5T5vY/E?=
 =?us-ascii?Q?PG0Fimf4XyJ92gx2HEZuIpAkFr++Ouw7mZthAjlJy+xINSL9gWUzL+6+M1MJ?=
 =?us-ascii?Q?UEFmUsOalM04RrSkMOFqafIRCPjZjPT9IF+uZ7x3iKCmkvCDd4xnwgD5Hn5o?=
 =?us-ascii?Q?M1z40YiumqC5HiKuSfUra7/5QOlihawswHN+kGgzoV5C7G6ob4+MZHt76gr3?=
 =?us-ascii?Q?H8nZWjYsukT+f/b/Tdwqf8JxS8CSlV9GdTH4dbPsqnvO9KzX2uG9QEUIv17G?=
 =?us-ascii?Q?63YZbIy+rHsam7+9doRIDYp7gW6UtLvUKzKB1ZlYCiRhoRBoP6KTkwoypomc?=
 =?us-ascii?Q?v1iyEy+CzQ+S8Udo5ZsGQBGcbVFHQHoHNLko1p9TfFsmf6tNoDFNyZz1nCKD?=
 =?us-ascii?Q?HYPD2JsfbgFWhH3SL9m5pkCO0zdntnMzfO5ErUSy+0Hklf+4nY8/IYHA7OqO?=
 =?us-ascii?Q?OksUG6cDhNMM+CjOgRvHVYM5K8pp/rCZvhem57iTx+1lfa+GSVV23de20D4i?=
 =?us-ascii?Q?ySsH3WrhXBA1zkq9jpo8lwryyklwF5z/fxJUEGWVtGXbPLRbzZhVYELQYgU2?=
 =?us-ascii?Q?urnjmBeAdRvJBg0Z0Z05GdCbCSF/Nkmn3YfbdKyObDCV94fHaY4wspVW77pX?=
 =?us-ascii?Q?hxFn9Os7QhPe4/Wx22a+vZBzFurgVu6NN8k6TK5K?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: fpV8d4M5ncemueQpzfoKKr+aPJayvJfwNio6ixTuDW1pGfkzIEZFe4f3s+q2CheohaL/o6hgVjdzUPOzLHigQvDZQLQFSrFJ7utLSyrAJ8rBHWgv1EsUwtIe9rds03Y2HfMNUOe7cPV7R/Soo0eUGHfFWAM7bXqlOGGVURXKVz0sHlbpB3HkfttmHEYB0FFyxGOEeN1hUzBLdTtKN89kcVp2EhzrKAYa6BHPSFYVkLcwDnKdyafbMUKoW+ESm8cR2PDQlJv6Awb3fIctj20rvDWuOoQQ47HZ9D/Sdk61bGqCnqf46c7nm90vDhDEzuIFzkaGGxg4S3FDNDkVGXB4ZsqzsEN0LV4lZStxwSjeygMKxbJTkdIOmlVJ6PrDKvarGqrKUk8t5gmWxw8LyVo2Hv+RxatWirRcMROciaSMPfoZYq3Q1odKkzi5sqyHaM/b9kecehDvB89EMUTf/5iqhkyPRSGLu5zkH28mCxtHYhJsI5B1/mYbrP/B2b0zT5dOl6RQ+iIsQDuqQQcar9RLZpr3W2DzoIAJWitfFcOfJxiXSvQ1aKgyQ1HPQtAk43IIGus4qBghaWSunAxSGstYgZmoLVh2zoveDb/Gl/aU/kk=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 13e4309d-f39c-410d-e6ad-08ddff667cd3
X-MS-Exchange-CrossTenant-AuthSource: PH0PR10MB5777.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 29 Sep 2025 14:43:00.5939
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 8iBWCBOHFYa0TfI8OlM2VTDRciy/tUpuNG7iaB1H7TB41buuppqUCgFxWS0I4VCzq3p6nQt5/ae8Mpp6aOM2wQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH3PR10MB7632
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1117,Hydra:6.1.9,FMLib:17.12.80.40
 definitions=2025-09-29_05,2025-09-29_03,2025-03-28_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 malwarescore=0 mlxlogscore=999
 phishscore=0 mlxscore=0 suspectscore=0 adultscore=0 spamscore=0
 bulkscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.12.0-2509150000 definitions=main-2509290136
X-Proofpoint-GUID: ZBOhEuLwnx1QkYOPgPmkJEo5rkuKufjj
X-Proofpoint-ORIG-GUID: ZBOhEuLwnx1QkYOPgPmkJEo5rkuKufjj
X-Authority-Analysis: v=2.4 cv=fs3RpV4f c=1 sm=1 tr=0 ts=68da9b17 b=1 cx=c_pps
 a=zPCbziy225d3KhSqZt3L1A==:117 a=zPCbziy225d3KhSqZt3L1A==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=wKuvFiaSGQ0qltdbU6+NXLB8nM8=:19
 a=Ol13hO9ccFRV9qXi2t6ftBPywas=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=yJojWOMRYYMA:10 a=GoEa3M9JfhUA:10 a=pGLkceISAAAA:8 a=yPCof4ZbAAAA:8
 a=qNUx3bLqDGtHolEI0M4A:9 a=CjuIK1q_8ugA:10 cc=ntf awl=host:12089
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUwOTI5MDExNCBTYWx0ZWRfX8l/DkqFS5qCw
 7bZmtKpuRvBeULKgufwxdtvn8q0M17w2sPaWnam/icrYqCisWlnM9ASRH4kZjxJLibVO+fE7K/a
 3tQixyvbZLBmtpK4Tz6mo7vB9EKaAgVDGSB0RDUvP6DFbyel3KPMDkCVBU79PeLARwZbq/qU8AP
 G5z/4sF9lZ9sYkc5WTZdoOuhV4EMAM1ihRf8ITrhVbtWWCnfH4ExxjlwlESAOOJymiK6k4UhY9h
 b1AVbgVMr+zOZXYHfk8Cq31o0KCwW3SgbVRosQCfOw5JbzIoYfBKBiwviYb8LfuFLBldf+Y4iPP
 rnN5xn5HU1sEwQgAds7Lq5yqHe72wTLqYGQheX3EiRzPfk+47+eb6GlqRIYiM7YIW0kNkGJ/mfT
 8dH4wRZj8VGHIUdmTMraivacd6QQT6lS32ujlqgd6J7hhx8a5cc=
X-Original-Sender: liam.howlett@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b="Y+IkF/2V";
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=OJlLdv0h;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

* jianyun.gao <jianyungao89@gmail.com> [250927 04:08]:
> Below are some typos in the code comments:
> 
>   intevals ==> intervals
>   addesses ==> addresses
>   unavaliable ==> unavailable
>   facor ==> factor
>   droping ==> dropping
>   exlusive ==> exclusive
>   decription ==> description
>   confict ==> conflict
>   desriptions ==> descriptions
>   otherwize ==> otherwise
>   vlaue ==> value
>   cheching ==> checking
>   exisitng ==> existing
>   modifed ==> modified
> 
> Just fix it.
> 
> Signed-off-by: jianyun.gao <jianyungao89@gmail.com>

Reviewed-by: Liam R. Howlett <Liam.Howlett@oracle.com>

> ---
>  mm/damon/sysfs.c  | 2 +-
>  mm/gup.c          | 2 +-
>  mm/kmsan/core.c   | 2 +-
>  mm/ksm.c          | 2 +-
>  mm/memory-tiers.c | 2 +-
>  mm/memory.c       | 4 ++--
>  mm/secretmem.c    | 2 +-
>  mm/slab_common.c  | 2 +-
>  mm/slub.c         | 2 +-
>  mm/swapfile.c     | 2 +-
>  mm/userfaultfd.c  | 2 +-
>  mm/vma.c          | 4 ++--
>  12 files changed, 14 insertions(+), 14 deletions(-)
> 
> diff --git a/mm/damon/sysfs.c b/mm/damon/sysfs.c
> index c96c2154128f..25ff8bd17e9c 100644
> --- a/mm/damon/sysfs.c
> +++ b/mm/damon/sysfs.c
> @@ -1232,7 +1232,7 @@ enum damon_sysfs_cmd {
>  	DAMON_SYSFS_CMD_UPDATE_SCHEMES_EFFECTIVE_QUOTAS,
>  	/*
>  	 * @DAMON_SYSFS_CMD_UPDATE_TUNED_INTERVALS: Update the tuned monitoring
> -	 * intevals.
> +	 * intervals.
>  	 */
>  	DAMON_SYSFS_CMD_UPDATE_TUNED_INTERVALS,
>  	/*
> diff --git a/mm/gup.c b/mm/gup.c
> index 0bc4d140fc07..6ed50811da8f 100644
> --- a/mm/gup.c
> +++ b/mm/gup.c
> @@ -2730,7 +2730,7 @@ EXPORT_SYMBOL(get_user_pages_unlocked);
>   *
>   *  *) ptes can be read atomically by the architecture.
>   *
> - *  *) valid user addesses are below TASK_MAX_SIZE
> + *  *) valid user addresses are below TASK_MAX_SIZE
>   *
>   * The last two assumptions can be relaxed by the addition of helper functions.
>   *
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index 1ea711786c52..1bb0e741936b 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -33,7 +33,7 @@ bool kmsan_enabled __read_mostly;
>  
>  /*
>   * Per-CPU KMSAN context to be used in interrupts, where current->kmsan is
> - * unavaliable.
> + * unavailable.
>   */
>  DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
>  
> diff --git a/mm/ksm.c b/mm/ksm.c
> index 160787bb121c..edd6484577d7 100644
> --- a/mm/ksm.c
> +++ b/mm/ksm.c
> @@ -389,7 +389,7 @@ static unsigned long ewma(unsigned long prev, unsigned long curr)
>   * exponentially weighted moving average. The new pages_to_scan value is
>   * multiplied with that change factor:
>   *
> - *      new_pages_to_scan *= change facor
> + *      new_pages_to_scan *= change factor
>   *
>   * The new_pages_to_scan value is limited by the cpu min and max values. It
>   * calculates the cpu percent for the last scan and calculates the new
> diff --git a/mm/memory-tiers.c b/mm/memory-tiers.c
> index 0382b6942b8b..f97aa5497040 100644
> --- a/mm/memory-tiers.c
> +++ b/mm/memory-tiers.c
> @@ -519,7 +519,7 @@ static inline void __init_node_memory_type(int node, struct memory_dev_type *mem
>  	 * for each device getting added in the same NUMA node
>  	 * with this specific memtype, bump the map count. We
>  	 * Only take memtype device reference once, so that
> -	 * changing a node memtype can be done by droping the
> +	 * changing a node memtype can be done by dropping the
>  	 * only reference count taken here.
>  	 */
>  
> diff --git a/mm/memory.c b/mm/memory.c
> index 0ba4f6b71847..d6b0318df951 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -4200,7 +4200,7 @@ static inline bool should_try_to_free_swap(struct folio *folio,
>  	 * If we want to map a page that's in the swapcache writable, we
>  	 * have to detect via the refcount if we're really the exclusive
>  	 * user. Try freeing the swapcache to get rid of the swapcache
> -	 * reference only in case it's likely that we'll be the exlusive user.
> +	 * reference only in case it's likely that we'll be the exclusive user.
>  	 */
>  	return (fault_flags & FAULT_FLAG_WRITE) && !folio_test_ksm(folio) &&
>  		folio_ref_count(folio) == (1 + folio_nr_pages(folio));
> @@ -5274,7 +5274,7 @@ vm_fault_t do_set_pmd(struct vm_fault *vmf, struct folio *folio, struct page *pa
>  
>  /**
>   * set_pte_range - Set a range of PTEs to point to pages in a folio.
> - * @vmf: Fault decription.
> + * @vmf: Fault description.
>   * @folio: The folio that contains @page.
>   * @page: The first page to create a PTE for.
>   * @nr: The number of PTEs to create.
> diff --git a/mm/secretmem.c b/mm/secretmem.c
> index 60137305bc20..a350ca20ca56 100644
> --- a/mm/secretmem.c
> +++ b/mm/secretmem.c
> @@ -227,7 +227,7 @@ SYSCALL_DEFINE1(memfd_secret, unsigned int, flags)
>  	struct file *file;
>  	int fd, err;
>  
> -	/* make sure local flags do not confict with global fcntl.h */
> +	/* make sure local flags do not conflict with global fcntl.h */
>  	BUILD_BUG_ON(SECRETMEM_FLAGS_MASK & O_CLOEXEC);
>  
>  	if (!secretmem_enable || !can_set_direct_map())
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index bfe7c40eeee1..9ab116156444 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -256,7 +256,7 @@ static struct kmem_cache *create_cache(const char *name,
>   * @object_size: The size of objects to be created in this cache.
>   * @args: Additional arguments for the cache creation (see
>   *        &struct kmem_cache_args).
> - * @flags: See the desriptions of individual flags. The common ones are listed
> + * @flags: See the descriptions of individual flags. The common ones are listed
>   *         in the description below.
>   *
>   * Not to be called directly, use the kmem_cache_create() wrapper with the same
> diff --git a/mm/slub.c b/mm/slub.c
> index d257141896c9..5f2622c370cc 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2412,7 +2412,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
>  		memset((char *)kasan_reset_tag(x) + inuse, 0,
>  		       s->size - inuse - rsize);
>  		/*
> -		 * Restore orig_size, otherwize kmalloc redzone overwritten
> +		 * Restore orig_size, otherwise kmalloc redzone overwritten
>  		 * would be reported
>  		 */
>  		set_orig_size(s, x, orig_size);
> diff --git a/mm/swapfile.c b/mm/swapfile.c
> index b4f3cc712580..b55f10ec1f3f 100644
> --- a/mm/swapfile.c
> +++ b/mm/swapfile.c
> @@ -1545,7 +1545,7 @@ static bool swap_entries_put_map_nr(struct swap_info_struct *si,
>  
>  /*
>   * Check if it's the last ref of swap entry in the freeing path.
> - * Qualified vlaue includes 1, SWAP_HAS_CACHE or SWAP_MAP_SHMEM.
> + * Qualified value includes 1, SWAP_HAS_CACHE or SWAP_MAP_SHMEM.
>   */
>  static inline bool __maybe_unused swap_is_last_ref(unsigned char count)
>  {
> diff --git a/mm/userfaultfd.c b/mm/userfaultfd.c
> index aefdf3a812a1..333f4b8bc810 100644
> --- a/mm/userfaultfd.c
> +++ b/mm/userfaultfd.c
> @@ -1508,7 +1508,7 @@ static int validate_move_areas(struct userfaultfd_ctx *ctx,
>  
>  	/*
>  	 * For now, we keep it simple and only move between writable VMAs.
> -	 * Access flags are equal, therefore cheching only the source is enough.
> +	 * Access flags are equal, therefore checking only the source is enough.
>  	 */
>  	if (!(src_vma->vm_flags & VM_WRITE))
>  		return -EINVAL;
> diff --git a/mm/vma.c b/mm/vma.c
> index 3b12c7579831..2e127fa97475 100644
> --- a/mm/vma.c
> +++ b/mm/vma.c
> @@ -109,7 +109,7 @@ static inline bool is_mergeable_vma(struct vma_merge_struct *vmg, bool merge_nex
>  static bool is_mergeable_anon_vma(struct vma_merge_struct *vmg, bool merge_next)
>  {
>  	struct vm_area_struct *tgt = merge_next ? vmg->next : vmg->prev;
> -	struct vm_area_struct *src = vmg->middle; /* exisitng merge case. */
> +	struct vm_area_struct *src = vmg->middle; /* existing merge case. */
>  	struct anon_vma *tgt_anon = tgt->anon_vma;
>  	struct anon_vma *src_anon = vmg->anon_vma;
>  
> @@ -798,7 +798,7 @@ static bool can_merge_remove_vma(struct vm_area_struct *vma)
>   * Returns: The merged VMA if merge succeeds, or NULL otherwise.
>   *
>   * ASSUMPTIONS:
> - * - The caller must assign the VMA to be modifed to @vmg->middle.
> + * - The caller must assign the VMA to be modified to @vmg->middle.
>   * - The caller must have set @vmg->prev to the previous VMA, if there is one.
>   * - The caller must not set @vmg->next, as we determine this.
>   * - The caller must hold a WRITE lock on the mm_struct->mmap_lock.
> -- 
> 2.34.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/gqrtcqx6yggzox5ze3eodz6vgzdatjyiuadigptvguamon4p2b%40znmbdpruwqil.
