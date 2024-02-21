Return-Path: <kasan-dev+bncBAABBQF62WXAMGQE2GU775I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C95A85CDF8
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 03:26:10 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf596645ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 18:26:10 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1708482369; cv=pass;
        d=google.com; s=arc-20160816;
        b=sWSnJqAb6xoAHJWnRZmK6evf14aYYrJzoyHci9THFvQC9xs1RoLOEH5H/qjIo3nFDX
         bx9ocTLW1cISCjd+CpG3DDLpiMyQbX4h1JvfEt5JbCw92mmYhnpA0ihsnrMMOT8R8w3v
         3dsceWeR9Cefnjagd7iIfSCPcgsxPj6Q/BLrMD5YPr1SKC7tcGb0q+dJwdWZRHe6XBAM
         WIsfA7OtbReWVeZUQyi/2WG1DD0tpzZfanXSIvy/GNyALGm+B8r4Kl94AlJbr0hD8/G6
         29r5yM6j9sKOqk8RYjpbZP5mt8xZ7ojcW5vdpKR7foKDPYFbrsmxwaluwzxTv0YFtoRC
         15uQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=OkByfFAc+itD7ouLN0nGh5Nf4aQQSJQR2yfaVCK7vAo=;
        fh=/YU0bLMXavyhNQN/wI4vfcrKpGrbw7n2E7o+uPZxGYs=;
        b=HAoDIVxV4zklKx0/lcWjFqGxmJMPUORKqlW94jNETJFsn41PyramRtNWIxSYtS7UCt
         6lZEtof35CueDybdySxVloJBDS8W6dddtfkn4ztiOzKJtSwid/6ASiF+YCS1WOvzR1bs
         rfAs9pULEDrYo1kfLjxZHCPzt9R93dtHxUEsJJUTb6HN3Ub2HSsUAgeqLkclYIa3wrGF
         shqpyMtx1TYdjTVAYxUCTuJspbecWTAGNPXgSNnQZUvBVfVEqdnjMmeeb/updoCO8xJ+
         hNEr6atY/qm6B/5/uQVCFCVx1rRz/hzZfgg893B2MNa4dxIKu8RAUj60n0wIQfjE7A5D
         YrcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b=IZKtgutL;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708482369; x=1709087169; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OkByfFAc+itD7ouLN0nGh5Nf4aQQSJQR2yfaVCK7vAo=;
        b=b6gWQSOhBD+1d/mHOez8aXrIuAabnFBcZ9CPFv79ZbTunpF9LCX5NDrDa/K2tI6Wwm
         3DO2mCPeelqCJHp2PPwi4ROWjq3JQ2VvHdHh7jBeYPlZLM88oyvlTAwwQlrRPS3IF7Eq
         D86JAhtN6LMbXtuypvqZZeJ+GnsbH7Ihux9TJDaMjwLAfUBYXG6vm/U/acwP0aKWvYsV
         epeqSWCgGFFycpYknjTg3z7wxcfwiNH09vBT/lgA/Kv2KYyP3HYOsT/QOC4O22ZLMjTe
         C6eXoyqyAGdfpwG4yHIQ9e5m8HYh42EpDNO41gmtIwSFzPQi82z/rT09lLr+FLYX+ua/
         H8BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708482369; x=1709087169;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=OkByfFAc+itD7ouLN0nGh5Nf4aQQSJQR2yfaVCK7vAo=;
        b=T2nLI14NmX08/i+5KzxWBqIs1DNbiwfyRW6rPCzPLh80BL5RJCynZwlNBzLbbHJx/D
         F4xlX3QfaprPRDETTyuelaXUbO/kw3wVbCoeDzh5T9eEbnXFQX4UA4HfYn081CeBmpTn
         WirLm3pyHl/e2ZGU/wMNOeMil1c39I7Rp3+qNQZFrTzwNpUCLegcDMpg7uU1iEikn42/
         PkiErrOiITbbWJTw6UyRCrwz/pbaH7Vw1mygD2NfjqWzCPjCSnsMuIZ0pl69TUKhXvM6
         F+RVXpCF7tAB5BSzs1PRcb/EDr7deKZJ6t6h/OOts75G0vmK9wbhRkrNOwUuFvwAZtiP
         s4Ww==
X-Forwarded-Encrypted: i=3; AJvYcCV2d+CpzJmeVfF+up0kvbescCznb8fuU8wIAo+BTtpGfvUDS6xCceWE6+LyU43Ik34gJbdE5RtCtQeK4APNNHWp1eDc+yTrog==
X-Gm-Message-State: AOJu0Yw07/bbdTacyiXeE5Gi6d5CV2nMLy6F7j1Vn1NreStohNVa8WDJ
	rNEwRqaxWpsaGmSeelZOKHUtQ1V00iZkpT+UiO40GKWY9kq/6nBN
X-Google-Smtp-Source: AGHT+IHICcwkYhiznzcYhlBmSDdAdiom37LOiVpEV8vauRg+/pQwd6ASpuotHySVTDQz53zof3a6Qw==
X-Received: by 2002:a17:902:e184:b0:1dc:7b9:196d with SMTP id y4-20020a170902e18400b001dc07b9196dmr120610pla.18.1708482368929;
        Tue, 20 Feb 2024 18:26:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2e8f:b0:298:e10d:b61a with SMTP id
 sn15-20020a17090b2e8f00b00298e10db61als3407561pjb.1.-pod-prod-03-us; Tue, 20
 Feb 2024 18:26:08 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCU6iG3ORjzkrDBTmrB5kTcabayifhy6gJV9JycoYq1YKrSP0LdDaKyjPACTM9uCzko4GegG6j0zuTKwnPFrLqpmNlFVbR+MTIXKTg==
X-Received: by 2002:a17:90a:7e18:b0:299:e9ca:c497 with SMTP id i24-20020a17090a7e1800b00299e9cac497mr2660971pjl.4.1708482367766;
        Tue, 20 Feb 2024 18:26:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708482367; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kz1a80ZNCTkm/QzE7xqvikjw2KJnnVR0GUsHia1q/cMkBUDNe2wag2UqgQsOpSYmQI
         U3D1pKVRxlW9DynTn0lXifgvYonoM6MDxFoFKLm3LhUZrNLQrJklbmDIuiSP+gJzDAlO
         MyEgX6mPgz8ijR69zcuDC4xnKOJkzuX+E0Cz7PJ2Z0thyUqOIafy+b1fOLranwCBrXoP
         bJjR9f2mAtR7E9xik4yU6x/MS6Z6+Vnn61iBqp6kvOXvpv8drqEdBz+ZGrmy3omFoYgP
         lIJu76xSqYdfOpw9hGD3Og549niGQpnEswFBZ7VNgkycLwVHMyFpohjXr/W+SPuNE+FH
         SB9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=4fU47u97qBavmDdSa8bhVb0l0GHt9YAkuld4S8s+2TI=;
        fh=Ah6r3UfbxXHVSN69qhRhgXePou4OMOfcO152A0MToiA=;
        b=rdxk7uRMMc7RCS0UZi9joG/EXJkUPKTWBcCP4m5g64p2HCH7mRzwx0eM7vMXZPUh0k
         MH5DApjyskwfu0j9t0Pwuuw3YGX8cmICMPLV7+UTOJS5t0ujdRHklXRXNFZ1jShRyDrC
         Zd2zep3Bi+42CRW9ImzkrMeDZEswKmYvACynID6L/j4jmGYoPYAfBKwNoB70uN+yZoaB
         K9N1IjbE0OfC2lazcx5z7/ub1IqZoSrBR8hzFgxLD6txZ+LDCMvYAuQj/5MWBL+MPfeo
         H/F2pvnFhobcPtc+iKnakmZ5DTMpa02bggzkY6sMsNI82hAe5sePtO/UD5l2Lvv5nihO
         Q3rw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriver.com header.s=PPS06212021 header.b=IZKtgutL;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
Received: from mx0b-0064b401.pphosted.com (mx0b-0064b401.pphosted.com. [205.220.178.238])
        by gmr-mx.google.com with ESMTPS id ob9-20020a17090b390900b00299277feec9si38081pjb.1.2024.02.20.18.26.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Feb 2024 18:26:07 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates 205.220.178.238 as permitted sender) client-ip=205.220.178.238;
Received: from pps.filterd (m0250812.ppops.net [127.0.0.1])
	by mx0a-0064b401.pphosted.com (8.17.1.24/8.17.1.24) with ESMTP id 41L0alrR022271;
	Wed, 21 Feb 2024 02:26:00 GMT
Received: from nam11-bn8-obe.outbound.protection.outlook.com (mail-bn8nam11lp2169.outbound.protection.outlook.com [104.47.58.169])
	by mx0a-0064b401.pphosted.com (PPS) with ESMTPS id 3wd218gagd-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 21 Feb 2024 02:26:00 +0000 (GMT)
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=LR9T4aCxJoPe79K5X8cOb9vI5uK3FDpb6fZcXZr62PnrfIQmR6IzNp1PPb9wVGWoxNG8JSjp+MGaXECMlpAaFQU0a263t2WqWjTmZHqP+S9QnyWdaHInBGDlbmapx6VncVMZy2hGwRq2y9q6NcfECioccV25r8tyNuA4OEHKkLc/bMyhB2MWa6nec0U4QYJSArmUNrCQXBJO/Ma/o9X66jbRTnBBBUjb1bA1q9W1CZQHSHUT6TH52WlBdLabcG4zyPaCKXUTkYjh3VSqscYCA9ZCdVH24IXUpoZx+TXnZbUTZtZv7p8ADHJgOGbs0SQaOkEGvWVyojoKfTFFIif8kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=4fU47u97qBavmDdSa8bhVb0l0GHt9YAkuld4S8s+2TI=;
 b=JAdL1ypUBbsmoKAjujIpUXidjXAngSSK9fSiGBvRjAxcxPMY+zAEsSgbszoqD9TJiJ5FIJ+CAUPWYJu56SRjoyMveldqbBVbev3/AaH82t0UOp1Jw47sSZDIuBFo1yqP3wEJ5qrWugy1F67SPHbx3/OAQSiWNroJegr3bxSTdWaURWNec4B8airKsbG0EXzR+6Me7KAL1WagJmQqfw3hH9WWnwVJspevsicGJYidZDhJc2j9HywAROvWkLlC2xNb3vmDoKLChvGGmoezVigQzDwXE3OXeKIRT3kVCCaC/9DnW+ocL1tiFg7xjz6mDPpVkgIgqLVuz827eXOYaGjOIA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from PH0PR11MB5192.namprd11.prod.outlook.com (2603:10b6:510:3b::9)
 by SJ2PR11MB8538.namprd11.prod.outlook.com (2603:10b6:a03:578::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7292.39; Wed, 21 Feb
 2024 02:25:58 +0000
Received: from PH0PR11MB5192.namprd11.prod.outlook.com
 ([fe80::230c:58c0:c3f9:b5f3]) by PH0PR11MB5192.namprd11.prod.outlook.com
 ([fe80::230c:58c0:c3f9:b5f3%3]) with mapi id 15.20.7292.036; Wed, 21 Feb 2024
 02:25:58 +0000
From: "'Song, Xiongwei' via kasan-dev" <kasan-dev@googlegroups.com>
To: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
        Pekka
 Enberg <penberg@kernel.org>,
        David Rientjes <rientjes@google.com>,
        Joonsoo
 Kim <iamjoonsoo.kim@lge.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Roman Gushchin <roman.gushchin@linux.dev>,
        Hyeonggon Yoo
	<42.hyeyoo@gmail.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander
 Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino
	<vincenzo.frascino@arm.com>
CC: Zheng Yejian <zhengyejian1@huawei.com>,
        Chengming Zhou
	<chengming.zhou@linux.dev>,
        "linux-mm@kvack.org" <linux-mm@kvack.org>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
        "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: RE: [PATCH 3/3] mm, slab, kasan: replace kasan_never_merge() with
 SLAB_NO_MERGE
Thread-Topic: [PATCH 3/3] mm, slab, kasan: replace kasan_never_merge() with
 SLAB_NO_MERGE
Thread-Index: AQHaZB4W8cdfqy83J0yGhys5aQz/a7EUEbtQ
Date: Wed, 21 Feb 2024 02:25:58 +0000
Message-ID: <PH0PR11MB51929A162277950399731E35EC572@PH0PR11MB5192.namprd11.prod.outlook.com>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-3-e657e373944a@suse.cz>
In-Reply-To: <20240220-slab-cleanup-flags-v1-3-e657e373944a@suse.cz>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: PH0PR11MB5192:EE_|SJ2PR11MB8538:EE_
x-ms-office365-filtering-correlation-id: 1157e4e4-bc73-4f7e-59db-08dc32847099
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: aRE0AidQDAM/DubXWQxw7jyln8XiEx8p/XA/OCiz6i/9oi5YDV1LTswBo4TSRU0WyuPSIYvtDGPg9ab+V4fYfLqo6QjXM0S8qLHeor8EGkHNT+mjp7Ij4lH3x0C1CigjGgl/kT89l4UE8c3XMrkuyqkiKlpe+kAt0PVh7r3qVOD2Libe7jY93VIO6B5r1pAB64TjNLn/QKf6ki1GWAy2Ba47XKDMwHjEmfTyEOUqWMErXJfJQ0blEjK8oNd5x93AvqRWk/qGc9SX1QBYsPh/KHm8rtEBzK8+Scj+ibRL0gUFQ9GtEoYS8jje6OjQ58KpQegjG/xcM86+Q6WADO+R1fuNKrAipwsZ6NtoIGkPHxpwmp3DoQXw/LLh3DLlZtTGBkMQybAeOw7FJDdlT83cEH9ceYzkNJIHNoXsoCaHd5qo2Tbf5vL3P+FswML5TXRIOXG9nlm0ggHuhGyx8vVkXsv/yw13b0vWjxKZW/HvlY1YaRSWuNu0S5i/CTQORev1jjhuQSj5uuy3HX4D4PtFu3Is9teRE41JqSjUzHscpziAzJ21pxLlOM2hFdStqjnZE7CQag1ixfsFfEUqu8FaZuSYJ5K+URTbocXvhWdVqw81psNSfvqcGF04RsfuK6sB
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH0PR11MB5192.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230031)(921011)(38070700009);DIR:OUT;SFP:1102;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?K3VKNUw2KzIvSExFaVF0S3FqN1FjK05TNHNHUzZod0JiT2JMeC9WWmVselY4?=
 =?utf-8?B?dkFVKzFnMGNYVzkxK2NqdWJtMDRrYWlwcUZyRGJCQm1jOEtOWC9aNFFQaDMx?=
 =?utf-8?B?NlJ6UHlFcEtNRWZ0YzBQekEzV3hVUk9IUnlBcGxUa1pRY2ZJdzNNR3dlc3JJ?=
 =?utf-8?B?UTFGemRHUGlLSjRSblNSN093WEM2SmNSRlpGRlhrRGJJQ0xwaFFRMlBnUStC?=
 =?utf-8?B?QWZQSVQwTlRnZTRvMnpqT2kyK0FBSVlnWThzNkxSMEJadDFJOFZzUno0Q21w?=
 =?utf-8?B?MGhKODY4K3BWZ2I1N21HOW0vaGIzRDhuWVljNVhBcGxNWStXcmo0MktoZDY3?=
 =?utf-8?B?Z3RHdGdNNnVHczVQL1NmVlBMZjRxOCtSb0ljZTc2d2hJaktrOXVjYm9sZlhB?=
 =?utf-8?B?NGpkYW40Q20rOUw5TEc4ZWRDVzhyMjVtaWpqVWREa2hQSnN1eGFENEt0emww?=
 =?utf-8?B?TExxanlOSGZsWDBka1ZVVXlkckJyTE84Zkx6RUozbFN2Ly8rYjRoTFYycG9n?=
 =?utf-8?B?UmJEK2EzaWFHaVlvdUdXVm9Ba3JXSDFlTHlHdnZ2Z1ZVVFdBYURLeHN6VkRU?=
 =?utf-8?B?Ykc2clh0QTNKSVdqODB0WTB5TnZXdTFDZFZUWDRzd0dKN0lEKy9KZis5TmtS?=
 =?utf-8?B?YkdNbjFRenRTMllhM2taN3RJVjVLV0oyV016aXorekR5eTFWa3lxTEx3cXVN?=
 =?utf-8?B?YUNYTlJEWnRkZExETlp0cWI5dldJSStWeEU1bTdQWXlXcHU2Ukk5UCs3T0NR?=
 =?utf-8?B?Qitoa01KcGpXM2FZdVpjQzdwRGNsZnFJOWd5NzBNWllod3B5bUUxYnBEblpu?=
 =?utf-8?B?ZzBtVmp6Sm5NQXd4VFFGa254WHh1M0hzZWJraW4xRDFNYmpvOGsvbU9NZkJk?=
 =?utf-8?B?Wm0vWlEvYjZDWVZNcnFpOGhCM0JLaEtYbzlmUXlkZVFFdlg0N3RnUzIvaTQx?=
 =?utf-8?B?QU9SMTZPdWZkQjFVWUhodWlGd045bXUrQnVGN1F2YmJ1ODNNdjNIT29iTy8x?=
 =?utf-8?B?NVBlc3N6bmgwK1VjeDFFT3N1cExYdk1LR0JlMUtmTzhZb01UL280VTRySHE1?=
 =?utf-8?B?WEVRRDdWdU1GdUMxTGpwcWRuSklWaDNhM0dXa3VLZWQzREIveWFPS2IyQnZP?=
 =?utf-8?B?M2JSdGszMFNxUzJMUFFXcTQxVHZtbThNeDlBSWlxRVhOOWJuTTNyOENRTGNl?=
 =?utf-8?B?V0xmMVBNTW4vbmZuWXgvNSttT3hOU29OM3lXSVhQdjN3ZWVodlFoMGFJZXBT?=
 =?utf-8?B?WEk4Y3V1NEhIMkdSZXhTb3hrOGdvK0ZIb0JxNWZqUWF1L0NWWlBoSmJWU3E2?=
 =?utf-8?B?SjB1RFk2OHhqQVhEM0VTT3U3UXo0eXJ1NHAydFJtUlQxK3dIWlZ4K0MyZW8r?=
 =?utf-8?B?dEdKUnBhN20yMmp3THZ6dzlnZit2bE1XOGE5VkxrL1EzcGNnWThJclhzdnVK?=
 =?utf-8?B?TTlZOVhqd1ZFT1Qxajk5WnplR29wYnd6a084QnB2WTIvcjNRcElEMFY3S0RW?=
 =?utf-8?B?N0VDTGdBM0djRkVVUm81cmFUU3FmWGRYUmRuUUhSNkxpeWJNaFJJdVU2cjEv?=
 =?utf-8?B?Rmd1dXZMSndQMHRqekdKZU5ZMEh0TTlvRlVWOWJyRGVkYnQ0dHJHdEJmWlFJ?=
 =?utf-8?B?bDRVOG1ITVlqMGdhbW9GTXdwVG1FaHBPQ0N2OUFNeXltMEJReTdubEh6bGht?=
 =?utf-8?B?VEdWVTB1OGF4Yi9RK3luanJyb0lveTNTVDJGVGdsVlI5UjIrcGg0K0JGUVRw?=
 =?utf-8?B?U2xUV1llb2FJUy9NNlptam1lbm04d2FaaTVIUlN2YUZ1NmxOaWxiKzRQUy96?=
 =?utf-8?B?OUMrNHpCUDZLY0JmTlpESXpwVi80WThrQ0JlSVR0V3BaTXRsT001SG5udTNF?=
 =?utf-8?B?WkE3RHJzQ2ZPZHVYb3VpYjhwNllBQkVOU1NhWTB0NDlldzhwNERtVGxSZjhO?=
 =?utf-8?B?NEtUUGtmSFIyRDJGcGgwVTl3Yis1VnZjSENxMWE4R0Z5eUY2clVObUFKRzNm?=
 =?utf-8?B?K2xuWDZBK0Rnc1cvb2RNUUl4UUd5d2pGRmVRRHVsVnYzaUE3MjJiRFNsd3g5?=
 =?utf-8?B?L1hmVmtaUy9HdnlhVFFYa3BiMnY0MFJlMWtvRjlJWWIrZVNsMlNNMEdVcEZP?=
 =?utf-8?B?ZHhhMlNsdDRvYlRvZlk2Y0oxUUZSTGhDL1JKTWVvbk5pL0FtM2tLZVJwVUhL?=
 =?utf-8?B?Z1E9PQ==?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: PH0PR11MB5192.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 1157e4e4-bc73-4f7e-59db-08dc32847099
X-MS-Exchange-CrossTenant-originalarrivaltime: 21 Feb 2024 02:25:58.5503
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: niaNkxNUiEcHvmGrB5h9YLUmAIwvBNc8ecBAW2bt+5hH0055joOUmvligXZVEuyDSDAE54wz6PJEVZnCCjAqQicQ5KEFk1FMSqCyEV58vNA=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: SJ2PR11MB8538
X-Proofpoint-GUID: ZzzndM9eSNgGo8ksyQQwqEBmRwqAIHDU
X-Proofpoint-ORIG-GUID: ZzzndM9eSNgGo8ksyQQwqEBmRwqAIHDU
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.272,Aquarius:18.0.1011,Hydra:6.0.619,FMLib:17.11.176.26
 definitions=2024-02-20_06,2024-02-20_01,2023-05-22_02
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 mlxlogscore=859 mlxscore=0
 priorityscore=1501 suspectscore=0 impostorscore=0 clxscore=1015
 bulkscore=0 malwarescore=0 adultscore=0 spamscore=0 lowpriorityscore=0
 phishscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2402120000 definitions=main-2402210015
X-Original-Sender: xiongwei.song@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriver.com header.s=PPS06212021 header.b=IZKtgutL;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass
 dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);       spf=pass
 (google.com: domain of prvs=27813ddd7c=xiongwei.song@windriver.com designates
 205.220.178.238 as permitted sender) smtp.mailfrom="prvs=27813ddd7c=xiongwei.song@windriver.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=windriver.com
X-Original-From: "Song, Xiongwei" <Xiongwei.Song@windriver.com>
Reply-To: "Song, Xiongwei" <Xiongwei.Song@windriver.com>
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


> The SLAB_KASAN flag prevents merging of caches in some configurations,
> which is handled in a rather complicated way via kasan_never_merge().
> Since we now have a generic SLAB_NO_MERGE flag, we can instead use it
> for KASAN caches in addition to SLAB_KASAN in those configurations,
> and simplify the SLAB_NEVER_MERGE handling.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Ran a rough test with build and bootup with CONFIG_KASAN_GENERIC enabled,
feel free to add

Tested-by: Xiongwei Song <xiongwei.song@windriver.com>

Thanks,
Xiongwei

> ---
>  include/linux/kasan.h |  6 ------
>  mm/kasan/generic.c    | 16 ++++------------
>  mm/slab_common.c      |  2 +-
>  3 files changed, 5 insertions(+), 19 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dbb06d789e74..70d6a8f6e25d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -429,7 +429,6 @@ struct kasan_cache {
>  };
> 
>  size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object);
> -slab_flags_t kasan_never_merge(void);
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                         slab_flags_t *flags);
> 
> @@ -446,11 +445,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache
> *cache,
>  {
>         return 0;
>  }
> -/* And thus nothing prevents cache merging. */
> -static inline slab_flags_t kasan_never_merge(void)
> -{
> -       return 0;
> -}
>  /* And no cache-related metadata initialization is required. */
>  static inline void kasan_cache_create(struct kmem_cache *cache,
>                                       unsigned int *size,
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index df6627f62402..d8b78d273b9f 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -334,14 +334,6 @@ DEFINE_ASAN_SET_SHADOW(f3);
>  DEFINE_ASAN_SET_SHADOW(f5);
>  DEFINE_ASAN_SET_SHADOW(f8);
> 
> -/* Only allow cache merging when no per-object metadata is present. */
> -slab_flags_t kasan_never_merge(void)
> -{
> -       if (!kasan_requires_meta())
> -               return 0;
> -       return SLAB_KASAN;
> -}
> -
>  /*
>   * Adaptive redzone policy taken from the userspace AddressSanitizer runtime.
>   * For larger allocations larger redzones are used.
> @@ -372,13 +364,13 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned
> int *size,
>         /*
>          * SLAB_KASAN is used to mark caches that are sanitized by KASAN
>          * and that thus have per-object metadata.
> -        * Currently this flag is used in two places:
> +        * Currently this flag is used in one place:
>          * 1. In slab_ksize() to account for per-object metadata when
>          *    calculating the size of the accessible memory within the object.
> -        * 2. In slab_common.c via kasan_never_merge() to prevent merging of
> -        *    caches with per-object metadata.
> +        * Additionally, we use SLAB_NO_MERGE to prevent merging of caches
> +        * with per-object metadata.
>          */
> -       *flags |= SLAB_KASAN;
> +       *flags |= SLAB_KASAN | SLAB_NO_MERGE;
> 
>         ok_size = *size;
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 238293b1dbe1..7cfa2f1ce655 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -50,7 +50,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>   */
>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
>                 SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> -               SLAB_FAILSLAB | SLAB_NO_MERGE | kasan_never_merge())
> +               SLAB_FAILSLAB | SLAB_NO_MERGE)
> 
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>                          SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
> 
> --
> 2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/PH0PR11MB51929A162277950399731E35EC572%40PH0PR11MB5192.namprd11.prod.outlook.com.
