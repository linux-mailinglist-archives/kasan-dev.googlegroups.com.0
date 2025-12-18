Return-Path: <kasan-dev+bncBC37BC7E2QERBHFBR3FAMGQEMOLFXHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id C29E7CCA526
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 06:26:54 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-34c6cda4a92sf557417a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 21:26:54 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1766035613; cv=pass;
        d=google.com; s=arc-20240605;
        b=j4D3JDLJpoyx6Nbx8vRcyi4hIbRH4GfKTJZn3QxOsowi35Tz8bJobs45WDEYVE5TfO
         W3UVtpkMtYb6Mz846Xey6+dLhPzrTyd0v+Q3s77OH2EvQaxkkUA3L7IbQO/AKY9dpj4z
         puJwpRBiB4m1+9f4GCPQy2Y2kgsBPkAUh0HZ6GPAwoRuZko22T9VTvKolsswKHhCuOaj
         b/V517nRUo/h3cqtOv03flifdgz6Xm7N8Gcu4+rBUL+nET2el2HiFU6Na9sjLJWf0C9R
         CgmvBOExlnF/Fr1qJI4FwMLLfh7GhFiFTyc0Gla+5c0D84s/yXKHa4fA0cI7x0uO/dIm
         SupA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=tOy8o6FUOXPsg0TMlKA+vR55936CJRa7ntteaTOpF/s=;
        fh=jqdj67qmqZz+ZTgiO1ahrrvji2cba1o7bmg9exobFVo=;
        b=LUI5oTq7MEha118ZJVDtiRJSFHvKsyQzIsb5ttFAt6RVj9cJvwQ2sdNOKGqd0/wi02
         d4AB6bJ1EkDrwcUOU7MnhCx6M68/OyLmvPifIkKklxCrjeu0OjBafHYAXmpeO85GxsM4
         +jpwMEG3iNMvyl8erZemm32TPQWDxoP6KDavJF4q/WgvOGeSPpEIf5+C53HqStXpBOtO
         dPxlFYAJ+Ik/8ZkO+Q483QbwZc4ekASVM965ZNJMnY8aHTKUO27cbhLh+eF1rkx33QzC
         XJhQtcpRvpiH4DORFJ3q89OWAErzQqCtS5yHamvy+wtoQv+O+QevSis7igpol74F6NP9
         EwMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=V9zORFD2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="Crr/fe4M";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766035613; x=1766640413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=tOy8o6FUOXPsg0TMlKA+vR55936CJRa7ntteaTOpF/s=;
        b=XoBEJmP5VQAhozHfg0FP3diJjwG4GZTrbbo92UzZoW16c+Rj/ingZH6Da75pgbv+w0
         tjkE2pPsDous1nIqa+T7BZ8/aCABT/4OOA1Cd4duv86HX0C38WxeyM0OL2vbndcesVKx
         NnoC9ehkYpx/NpsbT2P/0AkN5WTUGj6oSRsPQVOvskgXi7qZE39sOkC4OoPi6HmYwC36
         ilLOoncmp7Gf1wJE7cxMAdEmpVPZCOX8dZt0BubZbsQl+tG45b92q/GOiNOshlHy6E4d
         4iaGzehOnY/MLqlxdVYlM9SjEauppo1uvekJy8zEO2VpyVEWc9D68HQHxKbxcfQG+k5e
         zxCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766035613; x=1766640413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tOy8o6FUOXPsg0TMlKA+vR55936CJRa7ntteaTOpF/s=;
        b=XEbr9LLU6KF8mmdr2er1ktw0zj7JaB9u7sDTnQ0PblHJs6ZATSgqNfSdNPrTqIDOWR
         2w1UGUjadr6PW6E8J23/lz5bqVQHQACLo+xzt1+DVTM3lZRKBZ450kgLkcPFHRd3k0zL
         GjVz8maIuBenwLwe/OZpGny7AIA2+9/8/4IBb3tjxEUbPnR/2Pqnh9pdz8x1WcZ7RBZp
         S7/VFA6Rbu8AIKsVSPnwn/CCkQqKs9kQp0/iMg2kxaNakjMFo6qU/3PdjwQkdWVCtY6u
         eGl/LJVBjaRjC41lMA0xdhO/XLr6rm7d6kcDtiSWUbkMC/qchlsMpZ3ObEZQoJbJ9SKp
         f3cQ==
X-Forwarded-Encrypted: i=3; AJvYcCX7MwMNJJoo7rGppomQ5oqD79a7Upmsx7KpS6y9qhHyx8DvuUOX4qFQuCHpuVwN9wGrBjdWqw==@lfdr.de
X-Gm-Message-State: AOJu0YwkEUEBCiiCaeWjwe5Ptad/+IdtIxDg2qciEYes4UEWuOfSVBlE
	lMEGuL4/cmbf69eyBmK6sPTWhKv1D/MHb29nL26LKPB7Cmqy6na2J9UK
X-Google-Smtp-Source: AGHT+IHG8jqyKbUbgCESoBQvpMfqxuo79j5xOWfGxsOSdg+hJcxJWgf72xOGXoig2LzaH5sxgKwZyQ==
X-Received: by 2002:a17:90b:17d0:b0:34c:7183:e290 with SMTP id 98e67ed59e1d1-34c7183e3dfmr11400072a91.31.1766035612967;
        Wed, 17 Dec 2025 21:26:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY+gVTbhcD1pnKFEfxgKnLWJ86BQGJlPNtP3ZE48/tMdg=="
Received: by 2002:a17:90a:c243:b0:343:ca22:84f7 with SMTP id
 98e67ed59e1d1-34abccc7894ls5708694a91.2.-pod-prod-01-us; Wed, 17 Dec 2025
 21:26:51 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVEB4rNRFOhQu57mWGa/M6P3oCjvoriJLWjlDOuBQuXxummkYG3VZK7USAznXNoET1WHtw+Y0FZ7ko=@googlegroups.com
X-Received: by 2002:a17:90b:2d83:b0:34a:aa7b:1af8 with SMTP id 98e67ed59e1d1-34abe4a2b9emr14792497a91.32.1766035611254;
        Wed, 17 Dec 2025 21:26:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766035611; cv=pass;
        d=google.com; s=arc-20240605;
        b=iIGo6c6Z7r6t6ny4BePs83laf3VdEWqqUjGw8/rCzQMKdhRai5bb0NGs0zn7mktDGM
         VuTBF/7mildGT2cpI05d7rKQoC/lDbFIjy2hnKRYU5bZPNryO9s1Rin9pqXqi534mKkz
         2c1qUeC1MaYV+dAIiBb0UmZBl68SqY6oCM8xwwBH5gMCuCYcNnmD955ykscfxRpfPffs
         /+YQ25aoUpeuyEWLg5fDyJfCeKHneFKBo0YH6580zFg32NJkUHU0of7r/uwRCh9W57V2
         FnsqHexfnnC0UpIWju62k2tKA1hC0l6n5Q+5pmtjtvludud0Grm7TtUYhT8AYckQqfsk
         1G4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=cMlhR45QeBoQbuO/vA15+h0KMVa2pxs0X4cI7g93v+g=;
        fh=jg3V89NBVc5pOS1nRySjjiqaN6oZdJM+d7+VIkOzF4U=;
        b=DQrQw9GA6lNi0TW2+2/rf231HYxBHjgKcFbXr4YB6M5f9b/I1JLD7lJBqEGDpKF2sQ
         CdYfoo+DahSBJugO+2ACO3KEqqnb1eWKXn+GSGqFqoaUR3sM+b+S6uOdXKxdWvnZRaUl
         vG3atpWLq8a7cQQlTGpEidG/zJgrdTBd7Oer3WA8JZTyfOyhp0oUYHs6++ZRvFTM4aId
         +Jsmg9oRJCXj5yCwZvmb6T3XpSEpzbhgU7tyjJ18EjAjINWYi0rDqFJbWq3YzS3Eax/K
         gmFE9vhQ8xpIUZ9cS7HF3TmnDGqyQLT3jeWou4BC8J0TVhXT2aX6ODbD4uSdcTZEjebO
         44aQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=V9zORFD2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b="Crr/fe4M";
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34e76be92c2si12981a91.1.2025.12.17.21.26.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 21:26:51 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 5BI1gpfV412467;
	Thu, 18 Dec 2025 05:26:43 GMT
Received: from iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (iadpaimrmta02.appoci.oracle.com [147.154.18.20])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4b1015y7bj-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Dec 2025 05:26:43 +0000 (GMT)
Received: from pps.filterd (iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com [127.0.0.1])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5BI3hPVI022456;
	Thu, 18 Dec 2025 05:26:42 GMT
Received: from ch1pr05cu001.outbound.protection.outlook.com (mail-northcentralusazon11010020.outbound.protection.outlook.com [52.101.193.20])
	by iadpaimrmta02.imrmtpd1.prodappiadaev1.oraclevcn.com (PPS) with ESMTPS id 4b0xknfjet-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Dec 2025 05:26:42 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=uvZXCPCu9vsJnJHkwZtY9RO9LoQ97plw6IMTQyryL2YfrZ7PYD/wAzKZRhqmhJTCUeBY9lHCOnWGc2XcjfMJR+gaWo/bk+SyuT7F2lg0kFU6nITSNeAFx+cAzzbh2fLqAQZfwRDJZgtJlknbGSCZ2adOX233N/IWoknVwJ9jnJKXB9f6dHZiGbB3gexaqCdVh6iwuXhulxT3wx2g5hpJcpairxVGXGurSo5kTz3s/J/HTtLL5uNXbUIRC9GWBp6sYumj3ViARgVbrB1zgG957XPOvxTAojcQgQetyq1Z6Hl60zXN14wtjlDrdZqofHVu3axfJTo9P1cG/A07BcJTdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=cMlhR45QeBoQbuO/vA15+h0KMVa2pxs0X4cI7g93v+g=;
 b=JMC937Y/auE8z0ETrdgRE2uOebjANwRStsjssuCeeDedNEKHciY4Mj3bLKAHBVHS2i525grjw8OPWdx4I4S8jxJ/vwWMHl5jMdlfrccfn1me7oSIlD7hR/1gXkawtxghpL7laCgE7H6kPKRErhMOrghR5C/Icgb7MllVl/Nb8rVipogGLtL+DsHcHLfDMm8KBlteJ/MZ9AfZJXt50rZJgh5wMQjMCG3mxF43kw7LCMbRHrPvCPrdbzv8LtBkF1jWuuF1+jwW1XwP6eF39VTIj1zE4avbACh1wWf8fWYF+heTM7cJTfTgUmaTB0+MciptQHszrCDE8luzLpMh6/xF5w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by CY8PR10MB6468.namprd10.prod.outlook.com (2603:10b6:930:60::5) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9434.7; Thu, 18 Dec
 2025 05:26:37 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9434.001; Thu, 18 Dec 2025
 05:26:37 +0000
Date: Thu, 18 Dec 2025 14:26:18 +0900
From: "'Harry Yoo' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
        Linux DRI Development <dri-devel@lists.freedesktop.org>,
        Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
        Linux Media <linux-media@vger.kernel.org>,
        linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com,
        Linux Virtualization <virtualization@lists.linux.dev>,
        Linux Memory Management List <linux-mm@kvack.org>,
        Linux Network Bridge <bridge@lists.linux.dev>,
        Linux Networking <netdev@vger.kernel.org>,
        Harry Wentland <harry.wentland@amd.com>, Leo Li <sunpeng.li@amd.com>,
        Rodrigo Siqueira <siqueira@igalia.com>,
        Alex Deucher <alexander.deucher@amd.com>,
        Christian =?iso-8859-1?Q?K=F6nig?= <christian.koenig@amd.com>,
        David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
        Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
        Maxime Ripard <mripard@kernel.org>,
        Thomas Zimmermann <tzimmermann@suse.de>,
        Matthew Brost <matthew.brost@intel.com>,
        Danilo Krummrich <dakr@kernel.org>,
        Philipp Stanner <phasta@kernel.org>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
        Sumit Semwal <sumit.semwal@linaro.org>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        "Michael S. Tsirkin" <mst@redhat.com>,
        Jason Wang <jasowang@redhat.com>,
        Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
        Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Uladzislau Rezki <urezki@gmail.com>,
        Nikolay Aleksandrov <razor@blackwall.org>,
        Ido Schimmel <idosch@nvidia.com>,
        "David S. Miller" <davem@davemloft.net>,
        Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>,
        Paolo Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>,
        Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>,
        Alex Hung <alex.hung@amd.com>,
        Aurabindo Pillai <aurabindo.pillai@amd.com>,
        Dillon Varone <Dillon.Varone@amd.com>,
        George Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>,
        Cruise Hung <Cruise.Hung@amd.com>,
        Mario Limonciello <mario.limonciello@amd.com>,
        Sunil Khatri <sunil.khatri@amd.com>,
        Dominik Kaszewski <dominik.kaszewski@amd.com>,
        David Hildenbrand <david@kernel.org>,
        Peter Zijlstra <peterz@infradead.org>,
        Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
        Max Kellermann <max.kellermann@ionos.com>,
        "Nysal Jan K.A." <nysal@linux.ibm.com>,
        Ryan Roberts <ryan.roberts@arm.com>,
        Alexey Skidanov <alexey.skidanov@intel.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        Kent Overstreet <kent.overstreet@linux.dev>,
        Vitaly Wool <vitaly.wool@konsulko.se>,
        Mateusz Guzik <mjguzik@gmail.com>, NeilBrown <neil@brown.name>,
        Amir Goldstein <amir73il@gmail.com>, Jeff Layton <jlayton@kernel.org>,
        Ivan Lipski <ivan.lipski@amd.com>, Tao Zhou <tao.zhou1@amd.com>,
        YiPeng Chai <YiPeng.Chai@amd.com>,
        Hawking Zhang <Hawking.Zhang@amd.com>, Lyude Paul <lyude@redhat.com>,
        Daniel Almeida <daniel.almeida@collabora.com>,
        Luben Tuikov <luben.tuikov@amd.com>,
        Matthew Auld <matthew.auld@intel.com>,
        Roopa Prabhu <roopa@cumulusnetworks.com>,
        Mao Zhu <zhumao001@208suo.com>, Shaomin Deng <dengshaomin@cdjrlc.com>,
        Charles Han <hanchunchao@inspur.com>,
        Jilin Yuan <yuanjilin@cdjrlc.com>,
        Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
        George Anthony Vernon <contact@gvernon.com>
Subject: Re: [PATCH 02/14] mm: Describe @flags parameter in
 memalloc_flags_save()
Message-ID: <aUOQehpfZsgGrb36@hyeyoo>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251215113903.46555-3-bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251215113903.46555-3-bagasdotme@gmail.com>
X-ClientProxiedBy: SL2P216CA0119.KORP216.PROD.OUTLOOK.COM (2603:1096:101::16)
 To CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|CY8PR10MB6468:EE_
X-MS-Office365-Filtering-Correlation-Id: 977d5c1c-3cb8-441a-71df-08de3df60433
X-LD-Processed: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?mtwrq6WwqPy4zabYRSQ3a25VDb7Cn6p80yheWxo05/7HNCHfsm179rJR/JBx?=
 =?us-ascii?Q?5arnCEYIGJRxIMmvKCAmWUpHP4NI7qkNx0ug+WIwLEIS1K5fKCoI1rQIFL64?=
 =?us-ascii?Q?3plBUA5Cgd0i6XNZfvP0CvVXjVX0NQetFcXq+Ego2lWOXtux0u1N4DroMbyN?=
 =?us-ascii?Q?oA3UoOMtW9CghlndOydcYjLVhn6nFgUtC3mHX3HzmWkYtjIltuHeAdUuMjFH?=
 =?us-ascii?Q?1EURgj0wPWQAKJzjhxdCizXAyKBqQVjjyEbNrQ7cMiucSQV3F2zIwClp6gty?=
 =?us-ascii?Q?UOujJRXEPNlau13De/MFQW9Xa/rYvEt2DAZAN1dDkCE39uTKnmaG0stDlUh/?=
 =?us-ascii?Q?D1f6neE8dYjQ7lNUWQGeyWcaGk0e+NrYHGViUK7ZbhxFw84/gWcNE7vMBAnH?=
 =?us-ascii?Q?Nb579HosuovsB94hlNm52eVqjJYr2HrmmlcqsKeblW/XyAwEcCV7cIX73teN?=
 =?us-ascii?Q?d7S7/NaQlncsmt7RcAZ1AkZefCKc7puJqroQj9hC/BcqD3QQAJQ2F5yj/2HV?=
 =?us-ascii?Q?PMhtS8vfWQgnUHMC3U+PWhsEjZANc/oFy40mNIaUDqC9AGpRuzycA44EQSKZ?=
 =?us-ascii?Q?0i7wXbpYkWu8dxuO9ilWCOB/anWtqcEQ6GW3E1Ofq1uu/5tEgePAIk3sFfj2?=
 =?us-ascii?Q?8vnoqywPUmo2GUbv96NLTKqlRqcVjRIzvT6bOkZ2l9rbezjPfPUOI+rPwWV+?=
 =?us-ascii?Q?f2IbPCYtVUIgHpF/KZ0lqUyHQp6AVQ7ZtAOpu7MBUuj0jrcnYyoUJJlcmdNK?=
 =?us-ascii?Q?TuyKR2T0VA6TIiSo0xzwlGBNzExRv+tLUVHnpdBpgPxJpbM/wIGOOTqeLEqh?=
 =?us-ascii?Q?a0GgN+2rE1Ggj2OA+hB6YjGPYO3W2K53WRumLyAMr2C09btRwae1m/soFQt7?=
 =?us-ascii?Q?uRQslTabqKK/STOOcJ3ZB0f8F279jRPuI4pGdSOO+2P5ACCqYfu4UTQmfRfG?=
 =?us-ascii?Q?f73mu4jQ/0PPN1iOSp0WXSIQcEPotWI0aO43opa87ITm83CE6MxjH73tmRkl?=
 =?us-ascii?Q?Kp2CxX/u2Gp1P3pYdk1IMjivPETdYo4Xz3GJpa74EW+bZQAXkc13HvHN7z0C?=
 =?us-ascii?Q?qBVjiZv66/kB256W8/HaaT02LFr/4PNYM5/N7QNjx2CXZdcg5fMIw1P2vb+b?=
 =?us-ascii?Q?boYU5ijgMj5f5JCi+nU7qN1hnfDLHyitVhLrnfpJjE5H5Amm34ybnZyxPL1m?=
 =?us-ascii?Q?c+X96FjPeXJlQCzNQIKs3ULwrPyJa+q70+zaJ+LO6YDM4EUFCO+BT7qrU5Wb?=
 =?us-ascii?Q?KRPFQ+zNO2v5UH/95lZb0RF/mnDJnMfyvYHPBMC2plSbNFr7y1ZIZsJ9FfTM?=
 =?us-ascii?Q?ULwUjvx8in76g038AIrey2VMpfHD+1lsO8K7h+2pF5foNtdOii3ENPjKmnxW?=
 =?us-ascii?Q?e/5RtN/GBlN2mBmLQn8GIda1XnYHXcm3FuhxuAj5dgZYYvNEWHfwatZvnGDe?=
 =?us-ascii?Q?Y9RAeHBZXeNeoc0UISujjGZ5ay3uEph+?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?ANhtgV9ZS8R6UE3Np9rAs+NOrA8zYaFw8Eo5JKhPRLn3GdqCpXCzAQG19ORM?=
 =?us-ascii?Q?3XHo4HiYeuDRjurjZqqPk5MjOarwqxS5tvCpmZaHtYs+hX7mgE1b4t88N6D/?=
 =?us-ascii?Q?jj3m70BNCLpjClohKdDWnLV+STaGYxp/obxLy0g+mC7zaQZrdrfI1Zm7Esfg?=
 =?us-ascii?Q?gsSc+lGgRx/oHlxDECEmprfamK8h9ddN0qy67poyYevN7+5uhORcf/D2QJdk?=
 =?us-ascii?Q?6lmzX/BjBIQet1+pXRB9Km1HsaNwNIbtJD5lOUnlgMdYqm5k2Y+F+bg+USzo?=
 =?us-ascii?Q?UV0jhJHDuwGO4tesFUrvvjP8uRy6XOL6U9Blw5Y8vpsqTi0FAu9vAv9W5hKi?=
 =?us-ascii?Q?42KKn7xbJbp/URxLkKtxkdaVxP4DOeWSJ606snEnWTEX1FIZax9ELucDiBcY?=
 =?us-ascii?Q?KADN9zrJyDoYCG48UGhtGHn/23kgPD9jUiNbFcT9L5DsOFuAlVkzieZDDZeN?=
 =?us-ascii?Q?xHZ7N+O5wZMQjdEJF/662NIq4bYXucmkTKAQ4tiLXUVKHy1J+lTNOhD+/8Sz?=
 =?us-ascii?Q?B8tmvwWLC6K+TPAZmdnGXVXAH+UKQoy3LiCOwnUWd7NBsbfOu8HdTxZJclZd?=
 =?us-ascii?Q?NcV/1FEa0oYTDzr5XwM2dNku1g2w2Ss/BSgVSiSAUPxkjBycBT29Ed1HnQjC?=
 =?us-ascii?Q?j7JUgVoxmYZrsHjUWbsFBIC9nmJCpn72hYuqrHhpTQ+4GZIxSRVP8iDUjZLC?=
 =?us-ascii?Q?KwZ2jZOZAhQKXh15cN4eLci/Ha1JHxP5Kv0LCzxcXlXnZvi/ebtB9PzpWBZp?=
 =?us-ascii?Q?OZvz3D+BVMYyWKIaiCPMkaZ+v8+VwzmfqOiDe+lMU4Ho8z7AYz7WCFYqq6/i?=
 =?us-ascii?Q?ezqoiTVTQWwhD9YdwJB3pEww6T8WA+81gkwbLDHsiR0zd7XJQfdyUPbxeKzC?=
 =?us-ascii?Q?AJ8qeCLJ5NIEhZHECuRByU+O/kWFDnhsiI6YhmnlJpr6knu7waeo0ZxHnznd?=
 =?us-ascii?Q?IfpEp0ROjQPNjEPVazlubMs2SJp4dGyocS0VljABnCrdU5AocuKgQ0BEYctm?=
 =?us-ascii?Q?ZaOMQngQuHKAxktGqcNgAV5Umq0L+JgxgHQdtLQm54gJlz5GnXYF1bcwKUkg?=
 =?us-ascii?Q?H+1yQ2hawCphWsdR7NJW6FMMnmhy8ueVQh1R/RZ/D3mFOUPW9fYjVDUpPzbH?=
 =?us-ascii?Q?fFnr1hW6whjOcLPJXeil72NWrmxNxbx/DioWQoexs70r4ugiDr7WjLz4Lgj1?=
 =?us-ascii?Q?loP20BGVojfTmAkcius/9FjxH4JpsrUKDhOVh+YTtaEqn3K+66vWrJ5ECQ6Y?=
 =?us-ascii?Q?7qrRwcfA7bl0DvcC927nujtxJEqoiMa2Fkb9bbSFD6ppWDhPxL/VEPqtmQq3?=
 =?us-ascii?Q?tScb/AK3eQbKm5rfPT9TygWWy8A/fYYcz9M3L8UvbqrRwrfyMrKQaC8mOIBc?=
 =?us-ascii?Q?YPaMlFECr5azApmdEaEyuVEZ/u70SaLtu4fWNocdPg5NsRJLUdMBys9BDwYu?=
 =?us-ascii?Q?SMyxgX/2vpKp7/IXtjVrwo9V12K4QhmtkRv4ZYke4tOMZ3WE8hpyNlKhlHpu?=
 =?us-ascii?Q?0phtAzQHIQNVFLw8ZRBXmHpDkJ0EpRt5/ZLM5+YcHoqHN71EWROjWOiVzgbU?=
 =?us-ascii?Q?McJX9xXlbAqWzYBgi+DG7HcrlrW+JhXPhZnMR5Y5?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: xkh5YRXzxBuiiqAMbJlqNQVfRPyNKZx03QP1ukKdSZX7aiF39+sRgEE9crLwcinFu/BrkW2ShMUBCAorcpJrq+ds36CrpMYLCCOKfbgklEQlsGl2+oNC0rrlsO/PbLp4DZy89Ou9Vmia6IMDn6GJQo3/9wn7Ckntx2SMbo3SHLAb8BZ1Uj+Wo2/1mBqX4gZdyM5g0mCfFFbTqvUxtXQRrdB+uC3y/dGxCO7mU57BmWeCRLAO03F6FKYosrY3Y/a3MMQykAMU6oqiOSQw0r8N65gT/gThUBTvmBZeVXpuf7YfyUhwhStTc5cVGGH5mLsES3UYs04F2PpNKS+Ekn4hEtyHCd2IyaQwvUpoxePYnJCeQsZPKIYwk0/U+6rFhg0Fyn2olU/q8EPxTeTIBzbyzr0hSSUwFPNB91WxnOi760+IvGJjChc1pOx0t1En6TEleRDxdvw34Yp47jdH3xh6aK/Fburb4WSJXYD1KMXAAx92ZqfL160pq0Sp1EgyRDd/SjKNxxUz9s5g4pl2YyoUbMYJB0NhxLPakprN+MWXJXGL9pPWoVp8KjKy9cgvipiz7wLuGjbWpPvjiJzO6MVbZz4IxhWVfmPvi9vfl26Op0o=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 977d5c1c-3cb8-441a-71df-08de3df60433
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Dec 2025 05:26:37.6560
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 3rzdVCYi6u7LDxqLMEnt2Nqex6N3+UcaXUlhRJTUKh/6GfCm/zYz29/aA7/5ifhIEjkTk4ONNkcm+9xjOpKhIQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CY8PR10MB6468
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-12-18_01,2025-12-17_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 bulkscore=0 suspectscore=0 adultscore=0
 mlxscore=0 malwarescore=0 mlxlogscore=999 phishscore=0 spamscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510240000
 definitions=main-2512180042
X-Proofpoint-GUID: BsTvM-f7QqL7auGcK7EFSmM8iqDzKyGz
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMjE4MDA0MiBTYWx0ZWRfXxCNFXNXUPXWt
 Xory2CPVxZ6QUYTd9K7aFXVRW/frcaWXw8XaWC5E1rvYM2K7tlKLOBcFJCRHsZt5H1KXjplfVPf
 XB9shodHj/DByCh6VNo/JGeFulc3F+EH20zHP2wtwnE976cnz/y/yCLApPyqCvEW5o4reD+gHjY
 I1VUR8szKghn/3AFIJend4ltmMLoFl2ZekOhEpiXaQ3tISMS1TfOb2UCw1VFwL+QDfe3ZFMDOMA
 twqoH5hNIBJTweWxl2VTbQB73otdcWvV9+y3nuS01EjtE/u8DhTDdtpELZ+Vvxc5T/DT9McSwXu
 ENo1GFYBgdGzK5AgC4HupxHcxEWGGBZ9v9hK10s1EHYxOHMWxiFIRTOmYogvfgdYtrR523eT4MD
 v0p/6YKtGF6h7c2eRxfYyI1FBm9Vc+Mw4IPtr4lY2vO9TgWLYTM=
X-Authority-Analysis: v=2.4 cv=GbUaXAXL c=1 sm=1 tr=0 ts=69439093 b=1 cx=c_pps
 a=e1sVV491RgrpLwSTMOnk8w==:117 a=e1sVV491RgrpLwSTMOnk8w==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=wP3pNCr1ah4A:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=pGLkceISAAAA:8 a=yPCof4ZbAAAA:8 a=Z-cONpKXGyXygPhPFqMA:9 a=CjuIK1q_8ugA:10
 cc=ntf awl=host:13654
X-Proofpoint-ORIG-GUID: BsTvM-f7QqL7auGcK7EFSmM8iqDzKyGz
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=V9zORFD2;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b="Crr/fe4M";       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Dec 15, 2025 at 06:38:50PM +0700, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warning:
> 
> WARNING: ./include/linux/sched/mm.h:332 function parameter 'flags' not described in 'memalloc_flags_save'
> 
> Describe @flags to fix it.
> 
> Fixes: 3f6d5e6a468d02 ("mm: introduce memalloc_flags_{save,restore}")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---

Acked-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUOQehpfZsgGrb36%40hyeyoo.
