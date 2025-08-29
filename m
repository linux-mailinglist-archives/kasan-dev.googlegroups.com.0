Return-Path: <kasan-dev+bncBDX6BAWC34IBBC5LY7CQMGQEWZS3QWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id A7DF2B3C0AF
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 18:30:04 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4b10ab0062asf49813811cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Aug 2025 09:30:04 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756485003; x=1757089803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :deferred-delivery:date:thread-index:cc:to:from:thread-topic:subject
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NDv/WcZDMG7czxi3nnFfBW6T3ukWSV3RoNBBSrBqwHk=;
        b=sefMCsCnr9Reju+94tnRskTgaBk44cFc9fc3vi+ZnITjWBVwHlIuMJzTWVDYDHA5Bv
         OLb3/u9pVW4nQ3kUnhzS+dA7g8JO22yHU/oQVAMjh6/x3i+B/tIOXzRh8GQcLMBgHhIe
         YhzBUUjWXMuJA6wsNSpl5p0laXScbq7odCvsRWPPWlLJ0jvBLFc2tpvvoY5GPL3WeBTr
         i9BYhNpJDeHL3abmH4xSjQN6lxF0Xq/kOwKfrDuRsfk41RJfNq5nblnWZLjeep2pfQmL
         ppmJ+0IY0NOul9EI/V6orjdXRoeen1k3sCcb4D7Tpi9aTKBqBrUdY0CMClE9NGPpmKAc
         b8GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756485003; x=1757089803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :deferred-delivery:date:thread-index:cc:to:from:thread-topic:subject
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NDv/WcZDMG7czxi3nnFfBW6T3ukWSV3RoNBBSrBqwHk=;
        b=dzmO6xBO2ODh3C9OCdVU/0aGzJccc26512F6Nu7MHD5458ppjvKd9pBe4rQtx1o3s/
         RWzaif+t5qFQAHQqO5YeAcmXJNyx1vZw3id1zvjCf9+7b/IlC1BZZA45QQxZsl9g+uJW
         7LvPL2aNRH0c7MQPTgTPNP0rvKA4bfR/bF9j2yx/4hYJfC6OnXldcuRVUubQQJwJDbz/
         9wZdGkUEnQ1ztiHzXPoggHCMhvZJLWf1pj//0vjzNG5i9W8cxHakKhkrELniKSfSQaXa
         f/gdUWd54lWfhXdC6BSLr9d7SEoPn9DDwzeliwydxP1p5+RLbwRTflOaU0Yq5qsJAxLe
         Yidg==
X-Forwarded-Encrypted: i=3; AJvYcCVuIpMfqWq1FYxyzlM5lP4USv9uqH15y2d4MfFAzvpMeFFV6dBS9cL8td1Z/MBRc52/sjdfnA==@lfdr.de
X-Gm-Message-State: AOJu0YzvkIkQAa9Ily3WmPM4H+QPE6PiuhI8cfPUw0+8M8Y6ThFXjhCv
	un87yx75kYdG7sRMnrz4z8rbeyAUCnCEmtEOEe4h5dTbFv2bPf24H/u0
X-Google-Smtp-Source: AGHT+IFrdpJeJ8SrfQrgM1iBUZJ4q2RsHlHxbDoRQWhhCBfxxU+nJiU4Dpj0K3eUG0b8ID7/JG7HTA==
X-Received: by 2002:a05:622a:5443:b0:4b3:140c:ef9e with SMTP id d75a77b69052e-4b3140cf52cmr14772051cf.14.1756485003578;
        Fri, 29 Aug 2025 09:30:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf/j/El573xm3ZhyK/IUbs4I0T4/EGb8tWQ4P2+vF0XGg==
Received: by 2002:ac8:7c41:0:b0:4b0:774e:d50c with SMTP id d75a77b69052e-4b2fe873d75ls31927741cf.2.-pod-prod-09-us;
 Fri, 29 Aug 2025 09:30:02 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCVXa01elxvYpW5XMPLcmBGhyxpP5I8Iq2l9ponuin//yjrMqTvINoSeeHqb4f/V94s9GPNthAXRz64=@googlegroups.com
X-Received: by 2002:a05:620a:390d:b0:7e9:e67e:d068 with SMTP id af79cd13be357-7ea10f94beamr3277506585a.25.1756485002401;
        Fri, 29 Aug 2025 09:30:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756485002; cv=fail;
        d=google.com; s=arc-20240605;
        b=YKIAfKnvbWvQoYD6xOg4pBw5iQNaHu2LrvFU+HW26fRzVf/oAK6nkIV7kTS2p/oEsz
         JkMR6Tz4Z5g4nThbMDsYOpHAyaNLNl8anQMbjzvISaGcSGBnSQ0HctRUzu2LUq1LH7hM
         ZOqk4RsrAytCmbYs7V/5KUSEmiJ3Ftn+VEYdi4d68QDeyAllU2aYPXsxU5rm4EHYfwEu
         lRwdFkQtB7O8PXtQEwm+u5ErItQVt7wmQ0FXlRoJhOijvLUO3Hy2WhrYCLTtVe/iciad
         b813C1ykZx0tb7/4DUmHu7gF6DZMBz9Ob+0E35RsnOo3zCmsZDdLaX/rH7md+v539I8u
         3BwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:deferred-delivery
         :date:thread-index:cc:to:from:thread-topic:subject:dkim-signature;
        bh=IUKH7q64B4AZKyl6BHgnsCPbmL/bBGjfZAM2AuF142M=;
        fh=rsX3qcsfDhi93MpG1D9mfzX1/mDyM6WVCqG6Cg7lFZs=;
        b=TSPIx2kJyUUNTYHUChnXEGhMXPHUcT/KRtjUjxISUphjbESrG+iJSH3dODqZUrdhGI
         oKT3oMWD+928gmaxhQUHmMRCJ6CoiO115MUQ2CUb1GMrtg++eAxvWQj2FJdohGvBTbk7
         1FlQ/n40J51Xtbf2nMiCDkk7AcOJe9d/JPdtADy8ybDTNGANkFIXbNtwDXI8W0bEm3kn
         79n8tqP5emcZJFEXtzsmrfEyf/dSBfdP0JP70gIXkGfQr9PVhZovdLjDkOa9D80LXPIV
         ot4tTmwFnjxuMuBMKrl6IFE1S3uFIyW46hOMJs06dJ3D3g+AdcVKXY8eY5aOxFi3EYhs
         QFdQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amazon.com header.s=amazoncorp2 header.b=aizTPejD;
       arc=fail (signature failed);
       spf=pass (google.com: domain of prvs=32944d1dd=akiyano@amazon.com designates 3.221.209.22 as permitted sender) smtp.mailfrom="prvs=32944d1dd=akiyano@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
Received: from iad-out-007.esa.us-east-1.outbound.mail-perimeter.amazon.com (iad-out-007.esa.us-east-1.outbound.mail-perimeter.amazon.com. [3.221.209.22])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fc0cbe82a9si13750685a.1.2025.08.29.09.30.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 29 Aug 2025 09:30:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=32944d1dd=akiyano@amazon.com designates 3.221.209.22 as permitted sender) client-ip=3.221.209.22;
X-CSE-ConnectionGUID: OvK25TeeSeK03kBznH2NIw==
X-CSE-MsgGUID: 1jG78zBmSY+y1d4F/Fqq7g==
X-IronPort-AV: E=Sophos;i="6.14,267,1736812800"; 
   d="scan'208";a="1617061"
Subject: RE: [PATCH 11/14] Documentation: net: Convert external kernel networking docs
Thread-Topic: [PATCH 11/14] Documentation: net: Convert external kernel networking docs
Received: from ip-10-4-10-75.ec2.internal (HELO smtpout.naws.us-east-1.prod.farcaster.email.amazon.dev) ([10.4.10.75])
  by internal-iad-out-007.esa.us-east-1.outbound.mail-perimeter.amazon.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Aug 2025 16:30:00 +0000
Received: from EX19MTAUEA001.ant.amazon.com [10.0.29.78:6180]
 by smtpin.naws.us-east-1.prod.farcaster.email.amazon.dev [10.0.50.39:2525] with esmtp (Farcaster)
 id 59b93efc-7ead-4e12-a773-4e7cd5d1b3cd; Fri, 29 Aug 2025 16:29:59 +0000 (UTC)
X-Farcaster-Flow-ID: 59b93efc-7ead-4e12-a773-4e7cd5d1b3cd
Received: from EX19EXOUEB002.ant.amazon.com (10.252.135.74) by
 EX19MTAUEA001.ant.amazon.com (10.252.134.203) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) id 15.2.2562.17;
 Fri, 29 Aug 2025 16:29:56 +0000
Received: from NAM11-DM6-obe.outbound.protection.outlook.com (10.252.135.199)
 by EX19EXOUEB002.ant.amazon.com (10.252.135.74) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) id 15.2.2562.17
 via Frontend Transport; Fri, 29 Aug 2025 16:29:56 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=xtENIYqvRtgX8aDglaxuSt+48zVaccnoEXpnVDszWlXifGkf0SwNKXmgc1yy5/PDep8yBC0SyGMMALlOsRKtmoWNxGtRbGNxCYFUXuHlCDrC4BEl07iMnuNPqM1VjGVoAQoeCn9DnJyyPfGcIUJlDo5KeMPVTQuXoNcXpa3lkr0EEUp0DdwMmsVGIFNtnWDkLs5ktjv5pk6U6YATlNECApWH/N/vJUg9yV3914ukC4nTYXRJ0O+4dsPkiqaV7VaFB//bqNSVVg3Hp3HsSdLo0AkXQYhzvTQeES6VmogVwFJZF1eUFJTA+7dTtqz9pmaLq9nPdVHrMQLzOqM0kJvsNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=IUKH7q64B4AZKyl6BHgnsCPbmL/bBGjfZAM2AuF142M=;
 b=wq6IsXOecUvJu1WfbChOLnHQv98h+xssqAVbZOEJcjBa20XhC2GM4tQOcAq5ciF/d/qZTaKYAdgBFch9XXFVPnEdGYue7ANs96dbmV3V7vs1LfeCGkPtKPAHNv5wn6pPzT2cuwgEOev53shUmUiGH+jmIIqkTOx+30xonWlmzmZOVz6+ZzBiCjnWl71nZ1ZcFa6ysWA/FgxDVipZm0CPd5ZpmRC39ondeoU6qcSDVbz8tCIxo63nv8wFEuMUmWseQSrEH0kqUa+TafLCLZJEq1RlWkWgT2kZCtFngTjEkEdin9CGIu5Vr/tvFhMNEHV5KzdijkRH/qI7yKN4SUGCPg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=amazon.com; dmarc=pass action=none header.from=amazon.com;
 dkim=pass header.d=amazon.com; arc=none
Received: from SA1PR18MB4664.namprd18.prod.outlook.com (2603:10b6:806:1d7::5)
 by CH0PR18MB4145.namprd18.prod.outlook.com (2603:10b6:610:e0::22) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.24; Fri, 29 Aug
 2025 16:29:46 +0000
Received: from SA1PR18MB4664.namprd18.prod.outlook.com
 ([fe80::55d3:142d:553d:9b9]) by SA1PR18MB4664.namprd18.prod.outlook.com
 ([fe80::55d3:142d:553d:9b9%4]) with mapi id 15.20.9052.019; Fri, 29 Aug 2025
 16:29:46 +0000
From: "'Kiyanovski, Arthur' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>, Linux Kernel Mailing List
	<linux-kernel@vger.kernel.org>, Linux Documentation
	<linux-doc@vger.kernel.org>, Linux DAMON <damon@lists.linux.dev>, "Linux
 Memory Management List" <linux-mm@kvack.org>, Linux Power Management
	<linux-pm@vger.kernel.org>, Linux Block Devices
	<linux-block@vger.kernel.org>, Linux BPF <bpf@vger.kernel.org>, "Linux Kernel
 Workflows" <workflows@vger.kernel.org>, Linux KASAN
	<kasan-dev@googlegroups.com>, Linux Devicetree <devicetree@vger.kernel.org>,
	Linux fsverity <fsverity@lists.linux.dev>, Linux MTD
	<linux-mtd@lists.infradead.org>, Linux DRI Development
	<dri-devel@lists.freedesktop.org>, Linux Kernel Build System
	<linux-lbuild@vger.kernel.org>, Linux Networking <netdev@vger.kernel.org>,
	Linux Sound <linux-sound@vger.kernel.org>
CC: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>,
	Peter Zijlstra <peterz@infradead.org>, Josh Poimboeuf <jpoimboe@kernel.org>,
	Pawan Gupta <pawan.kumar.gupta@linux.intel.com>, Jonathan Corbet
	<corbet@lwn.net>, SeongJae Park <sj@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, "Lorenzo
 Stoakes" <lorenzo.stoakes@oracle.com>, "Liam R. Howlett"
	<Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport
	<rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko
	<mhocko@suse.com>, Huang Rui <ray.huang@amd.com>, "Gautham R. Shenoy"
	<gautham.shenoy@amd.com>, Mario Limonciello <mario.limonciello@amd.com>,
	Perry Yuan <perry.yuan@amd.com>, Jens Axboe <axboe@kernel.dk>, "Alexei
 Starovoitov" <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>,
	"Andrii Nakryiko" <andrii@kernel.org>, Martin KaFai Lau
	<martin.lau@linux.dev>, "Eduard Zingerman" <eddyz87@gmail.com>, Song Liu
	<song@kernel.org>, Yonghong Song <yonghong.song@linux.dev>, John Fastabend
	<john.fastabend@gmail.com>, "KP Singh" <kpsingh@kernel.org>, Stanislav
 Fomichev <sdf@fomichev.me>, Hao Luo <haoluo@google.com>, Jiri Olsa
	<jolsa@kernel.org>, Dwaipayan Ray <dwaipayanray1@gmail.com>, Lukas Bulwahn
	<lukas.bulwahn@gmail.com>, "Joe Perches" <joe@perches.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Rob Herring <robh@kernel.org>,
	"Krzysztof Kozlowski" <krzk+dt@kernel.org>, Conor Dooley
	<conor+dt@kernel.org>, "Eric Biggers" <ebiggers@kernel.org>, "tytso@mit.edu"
	<tytso@mit.edu>, "Richard Weinberger" <richard@nod.at>, Zhihao Cheng
	<chengzhihao1@huawei.com>, "David Airlie" <airlied@gmail.com>, Simona Vetter
	<simona@ffwll.ch>, "Maarten Lankhorst" <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>,
	"Nathan Chancellor" <nathan@kernel.org>, Nicolas Schier
	<nicolas.schier@linux.dev>, Ingo Molnar <mingo@redhat.com>, Will Deacon
	<will@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, Waiman Long
	<longman@redhat.com>, "David S. Miller" <davem@davemloft.net>, Eric Dumazet
	<edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, Paolo Abeni
	<pabeni@redhat.com>, Simon Horman <horms@kernel.org>, "Allen, Neil"
	<shayagr@amazon.com>, "Arinzon, David" <darinzon@amazon.com>, "Bshara, Saeed"
	<saeedb@amazon.com>, Andrew Lunn <andrew@lunn.ch>, Liam Girdwood
	<lgirdwood@gmail.com>, Mark Brown <broonie@kernel.org>, Jaroslav Kysela
	<perex@perex.cz>, Takashi Iwai <tiwai@suse.com>, Alexandru Ciobotaru
	<alcioa@amazon.com>, "The AWS Nitro Enclaves Team"
	<aws-nitro-enclaves-devel@amazon.com>, Jesper Dangaard Brouer
	<hawk@kernel.org>, Laurent Pinchart <laurent.pinchart@ideasonboard.com>,
	Steve French <stfrench@microsoft.com>, Meetakshi Setiya
	<msetiya@microsoft.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"Martin K. Petersen" <martin.petersen@oracle.com>, Bart Van Assche
	<bvanassche@acm.org>, =?iso-8859-1?Q?Thomas_Wei=DFschuh?=
	<linux@weissschuh.net>, Masahiro Yamada <masahiroy@kernel.org>
Thread-Index: AQHcGLuTBzGQJ2HjQUKWAGuAiYwph7R5z5Qw
Date: Fri, 29 Aug 2025 16:29:45 +0000
Deferred-Delivery: Fri, 29 Aug 2025 16:29:36 +0000
Message-ID: <SA1PR18MB46647E011B94C5CC701F7104D93AA@SA1PR18MB4664.namprd18.prod.outlook.com>
References: <20250829075524.45635-1-bagasdotme@gmail.com>
 <20250829075524.45635-12-bagasdotme@gmail.com>
In-Reply-To: <20250829075524.45635-12-bagasdotme@gmail.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: SA1PR18MB4664:EE_|CH0PR18MB4145:EE_
x-ms-office365-filtering-correlation-id: 2351047a-1357-4c69-30c7-08dde719445b
x-ld-processed: 5280104a-472d-4538-9ccf-1e1d0efe8b1b,ExtAddr
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230040|366016|376014|7416014|1800799024|38070700018|921020;
x-microsoft-antispam-message-info: =?iso-8859-1?Q?Y9Ys02gnEJbWPt+eT+U/MY71EKPRYTyZT2JzkuTz1xe2f2N8P8bGN4znEb?=
 =?iso-8859-1?Q?CYv36gAwTgpCldhxYlTRS77nGlIMePC8jpWdyaKHKs4/QaWxAnFknquQgv?=
 =?iso-8859-1?Q?6QhkT+DWIl7xt0KUeC4z1rV6EmvjAoVborymKzgstHU112TqUthTP3sR9z?=
 =?iso-8859-1?Q?IOmJS/XTxwSNYRUw38i9wPSDVvDjmOZInb4LHsCSFxH3boRYnjbQ0rYOrH?=
 =?iso-8859-1?Q?8aosECfMdk9EUrl1mP5RNitferT8DRyNsa5qAv1MHqpEvLwiX2/14ep6iB?=
 =?iso-8859-1?Q?obUbfDm62MIyRCI+vIBtoaGzt372h0uknTTcoTcs6peXVRtCmKbDjg6IBr?=
 =?iso-8859-1?Q?02mvhzFARUM2MuttCHUMKqqEyW7MzepFKW2AKYV5jKr4Y7j4kRv7M/87Um?=
 =?iso-8859-1?Q?GWuzGmVLtuvpPOVtqnuEeXa0/4Xod0iXvBMBJvcpyxSSSr106aMFwCNp0Z?=
 =?iso-8859-1?Q?1Y2/08y/u2QuD4oS9Sf7QUS9DC0crB1rATOUFVZ/QpO3Xgyzfm0RyOOSCr?=
 =?iso-8859-1?Q?NVYe4uyrDU3ufVxFduB8LRVwIDxEnfhjKvIqFPtgQ1ny+DffCeLrESQcxE?=
 =?iso-8859-1?Q?4N7UNDYLC8iKUJzfggWCJOtagow0pmbDMjbPlwHl7f0983pZDtxRWmkCiR?=
 =?iso-8859-1?Q?NK0F2JzSK1k5v/dkboceaIktU5T3Iv+G1X6AV1LRVAnvNr6UpU0v2achsU?=
 =?iso-8859-1?Q?MmUH+djEYxb8TwAYI7B7iOfZXO2P8a5cdspxb43dvxJvgLvM37V9tQlbNZ?=
 =?iso-8859-1?Q?lFAJ09LRoEFuEyi0UrrLUIjL6yoJqZRcq0hcmPotF7Hm18i/pHILaxURjo?=
 =?iso-8859-1?Q?kDAutEIq83FsT7yQ0b2vSTLPZwyqQP/nmUBW6FNPi7ENXys22npsyVXh8D?=
 =?iso-8859-1?Q?tGx+/S4/Gi6JPoBEXYTXuRpZvGuDFuHBN8SrUCI+mjUixpEP/q5D3k2IUu?=
 =?iso-8859-1?Q?HtuR+J9wpVsTOTx4JKPZweAZo2rJAu6rEvdrLDoq9n39JTj0fOaB84aM32?=
 =?iso-8859-1?Q?dMTA4qx7/vcvqJijNlw4QdisW8IhQhvxhslHnaGqy4RcfGGATWcKcTbgW8?=
 =?iso-8859-1?Q?56+6PDrKTPE+6n/E7MwyhHBA/28CkFdAKUik4bb9hKLSCuHgNQI43gcVh8?=
 =?iso-8859-1?Q?NhcEJODpE4P9v56aj43xh1hcWZ9NHFNlQWOvzsvJKCyyW1CPsvpi2V6voE?=
 =?iso-8859-1?Q?ksLmhpiyB/wB6YCdhUnFHrmqgVvGg9jcDzaVPYDrcYyLvQL8iuz3PSBQVF?=
 =?iso-8859-1?Q?jPPm/zGCWLxEa28wjWrya8OdmTbViOo7eD43nHhdZb59VLm1X5m43BHrkI?=
 =?iso-8859-1?Q?GdPegWDi8jYOgPWQFUrPfn9eBVeKj/Pxc05z357yk9g8hfNtXxHH5MepQt?=
 =?iso-8859-1?Q?dZ6gixYudDjTDpsGmdilN3V5yr5eN2zftqyrSY52CkxapTOk3ChqOk5HR4?=
 =?iso-8859-1?Q?wOLU31QA1eTy0ha5nOeamOxoA5dN9xHQAyT2kFGcVtA3gVV+TZk825/8/i?=
 =?iso-8859-1?Q?QmQmyxmEK6P+GDFJI/At23PG8tGAN407c6QECO9/ce6jh0PLXUJW9rHexm?=
 =?iso-8859-1?Q?CTw6zVeVY4zRfhhVbpLXAOvZ+z/n?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SA1PR18MB4664.namprd18.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(7416014)(1800799024)(38070700018)(921020);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?iso-8859-1?Q?FxkdxsX4Ybdn+q9ZpwXflRzDTr62JDlnYm3D42LaQVEm3V+vLWxj3gF3q1?=
 =?iso-8859-1?Q?rOGS4Wu8vkkfrN+RelS9TCYjLq6ZHm7U0TKovMIGd6ovmetjaRGO9EEC8v?=
 =?iso-8859-1?Q?MjVvF/Y30865iWklmOwSLSZ17y/j+W1zVRp6mfCLvdH3xEy+gx6LTwROzZ?=
 =?iso-8859-1?Q?iKhYTy0+ekwMwpkmioArTqE4RUZUTIuMkj8xBs7vdZAB1WwxfQXn4n/Rut?=
 =?iso-8859-1?Q?/lwaLv7+4dkqpF2qZeYNs/5KcloADG7IqRTXGtIUb0C7XjeQ3AKmu10I6k?=
 =?iso-8859-1?Q?zCdMrbzpV+QQysdEM6PMIIM3k9Ky1fNyPKhZYr+uvsD6pcFQ6u1lvSGE2i?=
 =?iso-8859-1?Q?niipjghj05d0+d3cP8pv1FvTNCY0C1pbST1aGR2CdYzwE4Q7PPX+sbto2T?=
 =?iso-8859-1?Q?abH1lci5iYl2udP7bdsrMTA5hJaxGUCAcQk5ko2bTUUIoa6glqRzgODSIC?=
 =?iso-8859-1?Q?GNCo9EjoeMSQsJlK6b1eOlrdIeXPNO1doUaaTssGNZLCCWwTKKOruhav69?=
 =?iso-8859-1?Q?g8d6MRvviA/Q+1SiTcERMfkUnmY+vF+8E9G71vcBg8O4pmZ8LJVL1Xi+N2?=
 =?iso-8859-1?Q?vk2meoPoTPK5CKG4DIo7Cpk8Ld0GkrB3qvLWJETsUwbVL1s6/xkzG9u9Yo?=
 =?iso-8859-1?Q?VlTExGdeYcnwL/BF4vKwB2nIAZIMDm/YJdOWZsx6seL2jlqWqrx1rk1GAh?=
 =?iso-8859-1?Q?fV8O8wNr5ahRxm65cF/l0v+cm7TvZPbd5jbEKlgNPfQd7KS4uV5JjdjF/q?=
 =?iso-8859-1?Q?qcFnR5BYpfNnKU1afhOzlNe/LYGmE43A2gH04+j0FGv+9rKK3PROOof4D2?=
 =?iso-8859-1?Q?qePL0CbYM6PiWFEdTN6zxWx2K+K6x4KC6xu9hOy5lLiIv5wE/ln/J8GKky?=
 =?iso-8859-1?Q?M+XJiDloFrCBR04DPcq6pQvaBP1E8DHn5a+aPDF8Sbi3PeSg22pLIh9Mqy?=
 =?iso-8859-1?Q?xue1RkxaHhWFgZFlSsSV7r42PvNvpGGn6WcsqmJDzrMrHLNArdR9a2Duy6?=
 =?iso-8859-1?Q?vBk0U/2vvkKBDpOFIH90NzO2xBSAsl+uQqGybysJHNs/tnwgGDI2Z0WiUq?=
 =?iso-8859-1?Q?qyzfWTgbVu8W4Xn2q3+D+m8ZpEpCM+euu9rMX/ROxvfi9rw6+tsw4kUz3A?=
 =?iso-8859-1?Q?tKLBHrqqQs3pC5RZbqiGmN6E9n0VsRRrV7BKhOERWjFDx5P29NMdxZ4V4P?=
 =?iso-8859-1?Q?zyzK/9woYmfizLHFCLFYIzS7y8OfhdUL4fhzC/5DihYZ4XU13hnHPGIwAM?=
 =?iso-8859-1?Q?Je+Pwn7rVWtOs73OJQgxUISrD52xDJo3l4nTLpEL2IIt1o5+bTGLhdwpD9?=
 =?iso-8859-1?Q?IG7s7kjSmiEGFsY7lJIO0h0oT2cMA9vxHldypzS8MXLmwDnQUkd/bY//6x?=
 =?iso-8859-1?Q?jcc0aD/4jT1gWr1gUQAG/DPdyrLKsJAbZR/i7khJaq/YAxkfHzRB8Gv6rm?=
 =?iso-8859-1?Q?u1h+G/T3gnu3YARUvpu81+WkM7dzmB+uyxIP+dTi5caF1VdxkkawN2fBuj?=
 =?iso-8859-1?Q?UkQJZHmPcRMmIbdqcUA5w67QLGJv4nNUUsJyD5JSIoKjx3DS22tZ7o3kQ1?=
 =?iso-8859-1?Q?CpBROfMCmldWvuSYTlAZXzHmx4kSy0DHooIk8i9oPbeZFY5vBUVB8mCwrT?=
 =?iso-8859-1?Q?B1xISVEUAeMeJS5BZ08J2DfFYZifnT4ayw?=
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SA1PR18MB4664.namprd18.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 2351047a-1357-4c69-30c7-08dde719445b
X-MS-Exchange-CrossTenant-originalarrivaltime: 29 Aug 2025 16:29:46.3033
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 5280104a-472d-4538-9ccf-1e1d0efe8b1b
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: tVgFsZAGNaAA9eeS15tivTDWmK1XhrMYR7+sAIZd6T5lrUSIL/Z7akZChYV7Dedcir2CBw/WMllCE4SWQHjGsQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CH0PR18MB4145
X-OriginatorOrg: amazon.com
X-Original-Sender: akiyano@amazon.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amazon.com header.s=amazoncorp2 header.b=aizTPejD;       arc=fail
 (signature failed);       spf=pass (google.com: domain of prvs=32944d1dd=akiyano@amazon.com
 designates 3.221.209.22 as permitted sender) smtp.mailfrom="prvs=32944d1dd=akiyano@amazon.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=amazon.com
X-Original-From: "Kiyanovski, Arthur" <akiyano@amazon.com>
Reply-To: "Kiyanovski, Arthur" <akiyano@amazon.com>
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

> -----Original Message-----
> From: Bagas Sanjaya <bagasdotme@gmail.com>
> Sent: Friday, August 29, 2025 12:55 AM
>
> Convert cross-references to kernel networking docs that use external links
> into internal ones.
> 
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---
>  .../device_drivers/can/ctu/ctucanfd-driver.rst       |  3 +--
>  .../device_drivers/ethernet/amazon/ena.rst           |  4 ++--
>  Documentation/networking/ethtool-netlink.rst         |  3 +--
>  Documentation/networking/snmp_counter.rst            | 12 +++++-------
>  4 files changed, 9 insertions(+), 13 deletions(-)
> 
> diff --git
> a/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
> b/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
> index 14784a0a6a8a10..b7b314de857b01 100644
> --- a/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
> +++ b/Documentation/networking/device_drivers/ethernet/amazon/ena.rst
> @@ -366,9 +366,9 @@ RSS
> 
>  DEVLINK SUPPORT
>  ===============
> -.. _`devlink`:
> https://www.kernel.org/doc/html/latest/networking/devlink/index.html
> 
> -`devlink`_ supports reloading the driver and initiating re-negotiation with the
> ENA device
> +:doc:`devlink </networking/devlink/index>` supports reloading the
> +driver and initiating re-negotiation with the ENA device
> 
>  .. code-block:: shell

Thank you for submitting this patchset.
For the ena driver change:

Reviewed-by: Arthur Kiyanovski <akiyano@amazon.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/SA1PR18MB46647E011B94C5CC701F7104D93AA%40SA1PR18MB4664.namprd18.prod.outlook.com.
