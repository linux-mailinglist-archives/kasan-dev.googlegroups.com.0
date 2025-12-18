Return-Path: <kasan-dev+bncBC37BC7E2QERBZFBR3FAMGQERXZDR4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 23AD5CCA548
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 06:28:06 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-88a360b8086sf7137316d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 21:28:06 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1766035685; cv=pass;
        d=google.com; s=arc-20240605;
        b=IwrB4CZeeneeYSJE3At3IP4uF+LS4hTXAEDmU7kLmf9G4UEefjen47qXIBH7AB05Hy
         2ZWUPwBSl7GKK97uDNYZAUBbn5/W4DDgUXOgFNt29U3P7zkiQm57KXSOYaMOjBwtGgJq
         SfEsi+LkR7P36fi8SdASeFqyAbkjM9P1QPSqEi1NTBQVETUBQwxi/W3FARvF+kztT2a8
         KIT7cfnOy3VHiZtZTx7DPExC4dXngRrEZR5MT6AyPELL7049Nr8a5WoB7RvSTNLkF+RP
         QtzXVN15oUC6PKjfStxbaPJ6XJbumU6+IDDiU5w3jsr0igkB8j5NaAxhMrGCs2teHig0
         Or8g==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=2bKmsIw4eqy+NeRg4vlavMfH4MosBmckrDqEgyofKgY=;
        fh=BV288hwVH8Grq/yekt2tfDBjY2c3lRpqSfH72GAqqn8=;
        b=cKw6nM+AGZXzz8G3paZGY15N+jGLqxnDtplENQFQQV3Fc2TH+LfJc/nqNo6X7Y1tGx
         8R3pFRl9GRSQpf0YHSeacwqkv3MHRFtre7OROm9iYyoUuL2O10WTYpkCGG30U7SdITre
         94T/hTkmdIWRuwEnY3MIAFUZGG7/n2RtHt42Dqz2XUzmcwzqLItC9HkoFxUpOnUlgCMA
         JYu0OZpuYupRF2LFmC0TNdQrkfHF3dyIYRnZnizHPM6n7SKfZrU6lMvE9G+SseNkNQu4
         0cpNHIWqigDMnOlzRYolViw2upz/Y5NCn1GKliJ2FTRBQ3ixJ2ADdmByWtsljvEYj48/
         VOcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Nrb63J32;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=GMwJVUTl;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766035685; x=1766640485; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=2bKmsIw4eqy+NeRg4vlavMfH4MosBmckrDqEgyofKgY=;
        b=U63i4FV4D9SeaxYMite8F5s3ex/Tt6V65TsFDW4JlElyU0T1JSSvJN+6iZt8XXWKSA
         A8HCwtChEAJ3wrt7TthXKO05E0B8CzvPZPV69ODcyguqDAu+cLw74Supho/f3F1J+Rpa
         nsSBkZWrxWKeXtrRqutfxAYqruSP3KR+v4jilNO12BBRuBJ6orp/pR4T8kxg0TTravE1
         kvT0fDxxIXBgAIbvH1xxBGY3y97QXuO9aLcYULap1B50DUFSCMyHAUNaDDpDSYZdqOgr
         yTYt2Ij+/WKfjX/u1FLVA7A0rWaaAqm6uuN8kA/T7gT/tuKfNXx1KcLQ4RkV6MWzVv6a
         QHTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766035685; x=1766640485;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2bKmsIw4eqy+NeRg4vlavMfH4MosBmckrDqEgyofKgY=;
        b=deTLb0YGc/H0aTiA1CcDktK7UHhccpIivqveFAEJkzRJYcjtplx50zbnzqEyw9uvN1
         5fybWpujfNoa3qcWJqE4EUBlGaVAWTp2K4ZPy1TFnfoZP1UUakoXPsRc54WrprBnlboU
         vP9WXQNu16P/VnkZPvMP1zduYM/FIOaGCXptob0OHpN6lbp+wkV/cvClicXw7ABwpEev
         DR7bdrGOXK889140QqRCSUNs42g2ewtjCK477DxB6VovUnxBAH2Aj+s9FIZBypzRFK9N
         1/Hiw4D28WnMlroueMABGm0iPho0Z2hGBVFq983daxa6gI4qbiUcRB+vr+uApNW9N8Sr
         rbFA==
X-Forwarded-Encrypted: i=3; AJvYcCUjXbAZgL9EmXuJsAV/YFdbgHH+WaPhi4VLz2YsuBxU0MEadWmEd98qw0fXv8aNaOrwiSQSuQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz9ZEFniEch+tZml2OAbODFA3h8NgJKOB3R76ti1K77Hf4rQWLT
	FCvrBYnOp+XeyxEjXb73aN2O/J8NzHes+IMc8Rw5iL3m7zc6G0cv+83o
X-Google-Smtp-Source: AGHT+IF3FZL3ddKH+aFHPlTicHHkJGGo/zGJnFmYcmSe7bwW36xLwHMoRHasWNYkTyEqWB4vL1Woqw==
X-Received: by 2002:a05:6214:3f89:b0:882:8746:b047 with SMTP id 6a1803df08f44-8887e01a418mr297436906d6.10.1766035684869;
        Wed, 17 Dec 2025 21:28:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaHK7dzQM/nZZibjylIin0TUR9QY3qJvcbBbZ4hCMNNXQ=="
Received: by 2002:a0c:d806:0:b0:88a:577b:fa53 with SMTP id 6a1803df08f44-88a577bfc16ls19196696d6.2.-pod-prod-02-us;
 Wed, 17 Dec 2025 21:28:04 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCV+WkTe7Ch0iB2qRS1GECcMF+QHK3rJO7DS8fHKedsiiZyf7HTO1UM6HeI/X87aHGxqOZDq3Xqz8ww=@googlegroups.com
X-Received: by 2002:a05:6122:2888:b0:54b:bea5:87ee with SMTP id 71dfb90a1353d-55fed5887a6mr6589014e0c.7.1766035683885;
        Wed, 17 Dec 2025 21:28:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766035683; cv=pass;
        d=google.com; s=arc-20240605;
        b=j5AHkIJlHNdFzymS9vw8PfjD7hpDdv/KuPGdDGBYUSFgqNYrDI8Qxv6ZCdaPC7+zWV
         l4sBlx0FQAi1VPVjWvoCjKbUYjgjLB+hkRvMCptEL4iOubbjaNMfB7KdGl/iS6vFXQts
         PyeZaz6xS7WcYqxhGxPU0Co5yJzpod8qQvNuyACQwlYqbhNQt+/WWEkYNXcFL0P+qzRO
         KB1gbDRlBANyX6GB3Kb+5evuzKkUWobWV+2zb8lAzqT26s0JfENNBxBwH+ZvSWqTHlTZ
         dXLNxTamojgFcFp3w3VC4gPrupyNPEktyiCSBD58vXmv2opaJCFMNtH6jQJrl4Nwjayp
         aFRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=6TseSqFcdNa1hh8Hfu4bZy1acZmVqLPp00IfQJb25UI=;
        fh=jg3V89NBVc5pOS1nRySjjiqaN6oZdJM+d7+VIkOzF4U=;
        b=S/cAGC3MSrbmJOL7Aar9jtSZ6GULTFVXTwFZcrsb5mIVuCT61La6c5o5/8Dn2V3+In
         DwY/yw6hgnNkf9NmW8dhx2M0gkNCdCiqr+VF8XG8xnbR5hiLFHTpQQO8zygPPswe5N6c
         iwhcriF9kcViCPMKw7WFFs/M57FYXyCcXvLuefxEUpepa4uSsVqFLwgrYCINNE+3TAN2
         i/Cm8nfW7qwCfyJCOE32XmAU5b2rKMb/17VDwjDUB4zpwjfAdJI8AJr0tphXhFWzrTr5
         MOuktbAFGvfB+kna6gPuReAnynZP/cdIdMnSLnuTwYCeAcVEUOpP108M4Px7V+bnUSjm
         tiLw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2025-04-25 header.b=Nrb63J32;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com header.b=GMwJVUTl;
       arc=pass (i=1 spf=pass spfdomain=oracle.com dkim=pass dkdomain=oracle.com dmarc=pass fromdomain=oracle.com);
       spf=pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) smtp.mailfrom=harry.yoo@oracle.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=oracle.com
Received: from mx0a-00069f02.pphosted.com (mx0a-00069f02.pphosted.com. [205.220.165.32])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-561510232c0si63841e0c.3.2025.12.17.21.28.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 21:28:03 -0800 (PST)
Received-SPF: pass (google.com: domain of harry.yoo@oracle.com designates 205.220.165.32 as permitted sender) client-ip=205.220.165.32;
Received: from pps.filterd (m0246629.ppops.net [127.0.0.1])
	by mx0b-00069f02.pphosted.com (8.18.1.11/8.18.1.11) with ESMTP id 5BI1h9Cv412899;
	Thu, 18 Dec 2025 05:27:58 GMT
Received: from phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (phxpaimrmta02.appoci.oracle.com [147.154.114.232])
	by mx0b-00069f02.pphosted.com (PPS) with ESMTPS id 4b1015y7ch-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Dec 2025 05:27:58 +0000 (GMT)
Received: from pps.filterd (phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com [127.0.0.1])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (8.18.1.2/8.18.1.2) with ESMTP id 5BI4j6j4025249;
	Thu, 18 Dec 2025 05:27:57 GMT
Received: from ph0pr06cu001.outbound.protection.outlook.com (mail-westus3azon11011061.outbound.protection.outlook.com [40.107.208.61])
	by phxpaimrmta02.imrmtpd1.prodappphxaev1.oraclevcn.com (PPS) with ESMTPS id 4b0xkcpa5f-2
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Thu, 18 Dec 2025 05:27:57 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=IjupQn02JQX3Op8Eod1FNcukym0YlGSObwAaa71NEzoBH/tMXS/kmdW3jL1w6BLUJVN7mdg2xVCHnW2dF1NL/r16whiC9chUZhSQuLC9fv9tf1rzwfBD4VSnLvPjDbpm1o2n9XJWCnkjGucqFzIKaTNIn+pss5nm7zP6cZZ7vrWrqkqdlyWhRFhwD+DR1dvdk7h4gYaDlAyMVVtSLaLqBTpc13Z7OumMiX/HArDKPtxtFfa55hQgecnukMfKLK/dT78ORt33GnM/e9OH4prHyY6rOEibyzZ+EC2WI2B0Gl2Y2wRL4IcHB5P5pDF6LveMmV6ZyvJqAZifZzfBAPmm1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=6TseSqFcdNa1hh8Hfu4bZy1acZmVqLPp00IfQJb25UI=;
 b=nFDQ7GfHti/6+zAI/nF1ccIXGZ+XvulMANzz1GlSvsKmftgUfL1bmZl4+OUg8CcchpatGoIi3zd0vbIiCq6IzQlsgADMDWSAG7EkROqJrQOx9Na8WdDEAyfuXkXREnxo6kYTeiSQpVMfbQOmU2k+45PTV4HMVwdDLUj/qKykL/llFkWnYZsodMrYbDk2f3IypE1YLJNnX+uvsqlX7tTYQGPNEhKCqE8JtW0UEGifaq0KMI0a7rdeP7N/+IUj1Y82DrTVx3AlwxcsXqjtYehRAj8cEFQBLK1aHRTZ0uc0UPyTkjrsIFmMZnI0ITVq6z7NJjIUjhp5GtFGD/YZWAPXtA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=oracle.com; dmarc=pass action=none header.from=oracle.com;
 dkim=pass header.d=oracle.com; arc=none
Received: from CH3PR10MB7329.namprd10.prod.outlook.com (2603:10b6:610:12c::16)
 by DM4PR10MB5967.namprd10.prod.outlook.com (2603:10b6:8:b1::17) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9434.6; Thu, 18 Dec
 2025 05:27:51 +0000
Received: from CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71]) by CH3PR10MB7329.namprd10.prod.outlook.com
 ([fe80::c2a4:fdda:f0c2:6f71%7]) with mapi id 15.20.9434.001; Thu, 18 Dec 2025
 05:27:51 +0000
Date: Thu, 18 Dec 2025 14:27:32 +0900
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
Subject: Re: [PATCH 05/14] mm, kfence: Describe @slab parameter in
 __kfence_obj_info()
Message-ID: <aUOQxLXtVLVSe58U@hyeyoo>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251215113903.46555-6-bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251215113903.46555-6-bagasdotme@gmail.com>
X-ClientProxiedBy: SEWP216CA0119.KORP216.PROD.OUTLOOK.COM
 (2603:1096:101:2b9::9) To CH3PR10MB7329.namprd10.prod.outlook.com
 (2603:10b6:610:12c::16)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: CH3PR10MB7329:EE_|DM4PR10MB5967:EE_
X-MS-Office365-Filtering-Correlation-Id: a3253b09-987b-4467-2f9c-08de3df63001
X-LD-Processed: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b,ExtAddr
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|366016|7416014|376014|1800799024|7053199007;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?Uy1j4e2QALjdO7VPqWWp0bf45gm5id56kKuXrs4Ds+kceST2lEMA5UMUmFiD?=
 =?us-ascii?Q?sJP0tKKz6VQoPZJR77uNyVv0YC+CbNhSxGE83rO3IGQdji9ihZoHJu4iM8+w?=
 =?us-ascii?Q?jBWH0OyA0UNvJVyeke2ooB2albuJtiIYXmu3ePjcvKsy/nMlAhFaaTlo5Oiz?=
 =?us-ascii?Q?c3tp9ocQztI4sJRFLL6ykKPMMc1YD72ihzk9AguYRSxS091nu7MhdH9XXLPC?=
 =?us-ascii?Q?Disbg1PUPc9y8+AvERTLyC3SsZ8Y/q4orfgKSUhnczMvvEIpo0SvI3kz3fNm?=
 =?us-ascii?Q?8hUruDa6vPAIjTW83eYqdi2n78FA5LI816DfHa5aCzDwxpbYQu0I9l/w3ycI?=
 =?us-ascii?Q?3y2HE5hFAH6Wn3d7KVjY6JPACpvpC4JaqXQORbSmLgjye4EKrhOZDgdtIzwc?=
 =?us-ascii?Q?LZDeKTevvsCVNJVCUZuST/a03utQG8J4HpwS8m8eU7th1VrPy/UP/RFkElaS?=
 =?us-ascii?Q?ivphqmXTKRTShdQ/ul19PKQxmk20KnvOHeGlXHxYUaBKvpfChxaSL63m2bgj?=
 =?us-ascii?Q?l+A91Ua58uVUpnKcxebqOYHx4DjNzz9fJEjjxhMbtUiuxEfUoYQj/wLRyVcN?=
 =?us-ascii?Q?Al/ppV2IkIdr6CZV4XFFPLYyJONkeMZumu/uJ9KTkZVt4QGi9WpMZfNPePkv?=
 =?us-ascii?Q?lwTCxv7BPuvWqIIoxkirblSZM4mK/3O9RisV4QzQ5cFhei3ClwWQF4ZakE4O?=
 =?us-ascii?Q?L2VxdzPvOcdnXlmu7BuW7gjHmxVG07y/OZHqnjF7kbKeVaYxeIGgmNwNixrz?=
 =?us-ascii?Q?KYieY67YphpC5d4MuruHSTfq9k4mPep8NmJw/J4wwwGFQviZPX+Z45vTtlVJ?=
 =?us-ascii?Q?lem4x/p9NTL9fxjoJWddrKjuTapRJhjHs09NZYuymMQ1rKfDRZyEaPPWI9lX?=
 =?us-ascii?Q?WjJsA9XSFx/krC79FiaD+fR5HiyLD/yRKeJyWEhNx7cxiNonZZ9UP+cguiPS?=
 =?us-ascii?Q?9TjaNDKFAs1uYGxl0NhiCPzi5h6lNsLbWCj1y8Xl+5cZxpmZ/6wjHw5MduTA?=
 =?us-ascii?Q?DwpYFK+BfHI7QrWnAKSN7NlpfXgU3Ev9PtZ5RXXcTjRjfAey/5V+GbFz44nN?=
 =?us-ascii?Q?2iNU3j77G86Kny4VdRWd8ngB+1sgaudE/4F84GE/DczYE4XUU5J8CTsD51EH?=
 =?us-ascii?Q?XumPP0d+JDHcqbnGjsFQpGnMDPU6GmsO2FSb/Ac4c6UNuKXYEFGkcBPE5Wuw?=
 =?us-ascii?Q?Dv6ZDm1QeZEVxoNSs9MfQiStpoACE7/6BuWE0yDFHuf4+amqefSTr7rHcL8m?=
 =?us-ascii?Q?IVTiSOvkGLxG0KHGtyPJfhUsoPXR6LVRksMyjT8m176ro0KoDFrb0ru/ORtA?=
 =?us-ascii?Q?hN9dsTFPJK5SrCN6NoGeAPyb3hTo4ciCnYfmYFru064U3uXBZYJUBIlqp5Px?=
 =?us-ascii?Q?oDCv+dS+sw8Cq5Au6LW3XhSHgUhwJ0AxjeBMIOF+0Ez0mmC3czSQH/sdoJAZ?=
 =?us-ascii?Q?XE5ceHh0pKwXMgNJIgEvuD/S0zfsMzC0?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:CH3PR10MB7329.namprd10.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(7416014)(376014)(1800799024)(7053199007);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?QqvMoFkGzdBL4cCFiEeYTnkxlzm7NJb4V3OF0NsUAN/4qHQFdeh4oZTaQgVR?=
 =?us-ascii?Q?Vj/AMIAP1A3yqV0DtoDXmngUmjz9VtpG5/5J42KqrA9R12LtLMntH7iMOoiu?=
 =?us-ascii?Q?y3ux/E6ZOpSTlFWdLYA/fEtdHAI0KT0hX1+eUV3UPIMomyj/YuVndtF43y0x?=
 =?us-ascii?Q?Hvc2/KVFC7Pq+9qcqNz8+/8IvJbcoNkCgl6vFuU9fwuNWFT4ZnZsWxIVMo3R?=
 =?us-ascii?Q?mm05TexaBF4b07ILTpEUSmnlF1lS7ps3A9afotDWfU8vika61mxVV7AHClX4?=
 =?us-ascii?Q?TuYhbMzvKJhPak2HjDz/BRXeXRjq3vhUAgbvj8UiEORwyzDonYdR6Hx/izWU?=
 =?us-ascii?Q?oIDKfeXc2tFjMpe5TrKv/0kR+FnOKXOrVSVeE/imVxMQIOn/IRkRJ9uopUgc?=
 =?us-ascii?Q?Puo3OR/HndhBn9bIR9DVff6Wndkr17AcAGXpXbd9rYhCyhllP//arPoi/MKK?=
 =?us-ascii?Q?cnb85X8G5QN+M929UzflEP2PhWKulC2tVylSTYmELxRBtcbwXSAhDVAaX6Mc?=
 =?us-ascii?Q?elD9ced5wKuPV+HGGL1DjhH5PSmj4TTOSxtGTj9TAm25VyYLPlivu53rUjfO?=
 =?us-ascii?Q?QgHAT7lAsnjxGhVhwMzhrz8JzdxnChXvp5e5Swyy+8mBf4PRDpyOjnYSsUlf?=
 =?us-ascii?Q?o6+oiPxUu5DWqdPCTrppBFMGWHrBCmJh6q1SbFTXslO3bjgd4649C5AtHq9X?=
 =?us-ascii?Q?Wexmj7Vokhct7J/mbWhir5SRxChZIZZ5Oune2+AJUKOqKJZoyxEujTkpjjFr?=
 =?us-ascii?Q?h3bWg2ScTuVqRZ2XpJercoilsxJTHQ8OkVF40w2pyvM13uVqYtwV6YJslUKW?=
 =?us-ascii?Q?zGHWb2UjbRBotZ0/lGtwLABdLt1B/7be0xf80l0mWTD9YuYamAMEeun+adqO?=
 =?us-ascii?Q?+jX8k1BQBz0hIjbbwCD8Nv3h+iQo6Fjc1qEMrAZKsopb/t9oNQI0tMNEospr?=
 =?us-ascii?Q?EL+9LyAzjViwWcLFx4tnoyEnof+QKNpJYob6VuOL4liO1S7UiIszINAwDqeZ?=
 =?us-ascii?Q?XKqlVy/buSXGXWjJElvcaY9CZoAJfERXW3JngP3THHWy4Q/GoJuNFYguqqb6?=
 =?us-ascii?Q?r86WS1378kflifFZzOVP4gpDD4BNuZv6GvatWJDk8ak+tGKlJTOE1iH/DQVw?=
 =?us-ascii?Q?RqJP9sd8tqkkUd6ihowKuR/J+7zMu8IxBi/K+P6QlX1EoIWIbmWDVc05xwUO?=
 =?us-ascii?Q?NP2ZXxO/X55gp6cUH1b7LNUenpMKfbSF5ujCvB+VwnxjJCUEclLomUEEE1mc?=
 =?us-ascii?Q?DQ4537lZcKf8qCckERqOGTkzy7AfMYb8hYldgA9dGOxChVCOy8xVXaPY2pIw?=
 =?us-ascii?Q?1gwOE2f33/6KvHrmJDoRecVsxNpMg8O9XCeoI6Xu6YC+ZB9+EeDepcK46p5K?=
 =?us-ascii?Q?eESpjf0JvwJZrn1QoPEeV/33gSXlIFRurccFrib/R7E+f3fx5dOU3fxLzPjn?=
 =?us-ascii?Q?4WfiFseuMeKrxA0YH3B8lK04d9HnhP4FkFsfitDG8qK6ls3lCHfKMh7Y9yap?=
 =?us-ascii?Q?vpzgLng3XAIICnCZAxptkOG5CoOVI1vWQDQUNZ2yVYZhyOyP0fXyPMV2XLMo?=
 =?us-ascii?Q?VNO2vH6dKm3WYiyhtJ+YuM7LMd1t4XVIOFqS+rFn?=
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: tE4lWbknYszrdnRNvubZH8dODjSMpX7aSmgm9L6zEVr/ABf2/V/A6TH7tQucszqQsuHYcUWwY1KlI3z2HDuAwWdUw6+SlngiqPOfNiWh5itnz2/Ibp+uPFAS+GttLdEWd8vVkpiirNJ0gK0r0yJ0E5lMZsXksanj03JEXY1o1ocgx67FxSbPbJT6f9//9HaFlfRSifqLAi+1jJYdLeAuKfKu+9DW1VWqtBscMYeK6g1LX8pJgod7YN4Bq+Iz0W8qKJB0rzbqzHzBJPo3blgNq84pC1Hehi5FCrRooH1U8KHmZKBghTKejmrAiwhg6GXz2gXeAvz27gIpfPRwemCROIX2JDAb5fc0bwlb2kUZaqXL6+tYXA4UW7d2FLPxCnhH/hz533WZwmRO6XBYKbNgkyI7YsRRHxG6bV+PsC+9tKqc7tnPYurUKetpx8Cfx9Xf8LFrScu/WiRppD+WmIPp8H0prE4O8UcXT9XsawOOGUfikjAbeRsSfAYWbqsNun6K6Eo+cDb7D88L+RvhJliGHcMvxM3XJ3IGVJEY89uPbdq1j/YWVAvkDjLkHhO8uIDvsqB+VFih9FaEZnt83r+k+UmUtZ8YqZ9wzOTgkJqzXiE=
X-OriginatorOrg: oracle.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a3253b09-987b-4467-2f9c-08de3df63001
X-MS-Exchange-CrossTenant-AuthSource: CH3PR10MB7329.namprd10.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 18 Dec 2025 05:27:51.1123
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4e2c6054-71cb-48f1-bd6c-3a9705aca71b
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: /GVMj5IT+Cia90fnQ5qQ4yzTII8NvSQ+zxJDXSTUSySX8H3tloSQrTrKkdZ9P9e6yAINoSxJBUP7qAuYHNZKkw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR10MB5967
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1121,Hydra:6.1.9,FMLib:17.12.100.49
 definitions=2025-12-18_01,2025-12-17_02,2025-10-01_01
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 mlxlogscore=999 spamscore=0 bulkscore=0
 suspectscore=0 malwarescore=0 mlxscore=0 adultscore=0 phishscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.12.0-2510240000
 definitions=main-2512180042
X-Proofpoint-GUID: XGoSxf8dfUdMI4QvpZOV2PKSpOzr2eEZ
X-Proofpoint-Spam-Details-Enc: AW1haW4tMjUxMjE4MDA0MiBTYWx0ZWRfX/lB64Ksbkz2u
 S28x6MDv255ywv4qahLJL4PUCj5sbelSC41muY7W7ClsMxr5IE5nkRUJ1E3XZQR0rJ1ERXDJDjg
 WckyWqQZYIPOjrljRjvitKdSUfazMK9cSfPGcZ20QLdK/tSEGVBp2H2NEEBZ/2pqDoiGqcHewGn
 slFGYs3eIThlAoufZ++9TrjruXN38EYA4u80m2n8l0FU481+VBtURLmTNdy9sXht1O2OtiaJC7l
 CrDP0ERrXAPhH51sP3kuggT5CitkoMLOS7V5tKYzALVU1m4MVEd1BdPzXTpaNbDCvD+XT+/ZYms
 m2IHWJAgH9Q3XUOz2TgU0nFW/sMd8eTd1uZh0moOu9sLUxfqN4IQEy5rMXKh/EYl0/z7IdMKnL3
 YKblzjGWkPvjuL32wphfj5bY9li7tw==
X-Authority-Analysis: v=2.4 cv=GbUaXAXL c=1 sm=1 tr=0 ts=694390de cx=c_pps
 a=OOZaFjgC48PWsiFpTAqLcw==:117 a=OOZaFjgC48PWsiFpTAqLcw==:17
 a=6eWqkTHjU83fiwn7nKZWdM+Sl24=:19 a=z/mQ4Ysz8XfWz/Q5cLBRGdckG28=:19
 a=lCpzRmAYbLLaTzLvsPZ7Mbvzbb8=:19 a=xqWC_Br6kY4A:10 a=kj9zAlcOel0A:10
 a=wP3pNCr1ah4A:10 a=GoEa3M9JfhUA:10 a=VkNPw1HP01LnGYTKEx00:22
 a=pGLkceISAAAA:8 a=yPCof4ZbAAAA:8 a=tOzzCTW8nSJqF8abkYwA:9 a=CjuIK1q_8ugA:10
X-Proofpoint-ORIG-GUID: XGoSxf8dfUdMI4QvpZOV2PKSpOzr2eEZ
X-Original-Sender: harry.yoo@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2025-04-25 header.b=Nrb63J32;
       dkim=pass header.i=@oracle.onmicrosoft.com header.s=selector2-oracle-onmicrosoft-com
 header.b=GMwJVUTl;       arc=pass (i=1 spf=pass spfdomain=oracle.com
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

On Mon, Dec 15, 2025 at 06:38:53PM +0700, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warning:
> 
> WARNING: ./include/linux/kfence.h:220 function parameter 'slab' not described in '__kfence_obj_info'
> 
> Fix it by describing @slab parameter.
> 
> Fixes: 2dfe63e61cc31e ("mm, kfence: support kmem_dump_obj() for KFENCE objects")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---

Acked-by: Harry Yoo <harry.yoo@oracle.com>

-- 
Cheers,
Harry / Hyeonggon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUOQxLXtVLVSe58U%40hyeyoo.
