Return-Path: <kasan-dev+bncBDGLD4FWX4ERBTWC5S2QMGQE5QMEKVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id E5A649500AE
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 11:03:12 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-2cf1a80693csf6061934a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 02:03:12 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1723539791; cv=pass;
        d=google.com; s=arc-20160816;
        b=z19mrzGsISmvmJ1U41RvkRpy22SK5/o54Gcb16CTxeyoBP7giyA9dsP+ig7PnY2LXw
         OF5h6hA1oiu41bkG3gFfpTZrUw7c356VbRMI1v74kOwEjXi5JoDrrw1VJBPuyhi0OAGf
         xjilpv0qmzY3nU+hAXVWXES0wrsr9TEi1In2LMrZ40J3IrdDL474Sz+SUFSQOwcDhA8H
         sm+fb53xayr8EkufTRXTzQaVQaQhaBdNtpBQZ7ZrdV/iC4pz7MD47z7AWUQcyhfXXWIr
         DxVR7rVDshSffkoOzJ8TebCn6LqkmVOdDL52+lgMwqfWLRJK7v702RJSFKaU3k1mXb9g
         AQgg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:content-id
         :wdcipoutbound:content-language:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:dkim-signature;
        bh=zZsM5KbfgPNqHhh2aa5y56bSZv6uxaPnPFpyoq88nAU=;
        fh=2OZCvqgsRVsEmMavgPRZGRtMb0G++OswbHMKJuevsOc=;
        b=V6bBI0aZxhdwKTzulHKyRZz3kcaymY5PWnEtyVQkMYeJLW1Q0T2DSN59T1PacmShLI
         pHLUUxEvq0ZFajky1bcehgk55ADv9tMWk4vEaRuHiIYWirwQKTzklhwRqjN4qjMttQIw
         ZHcNz08QLSV03SQcoPwsp+H09uZKrzBA39D9uL9adOfgaaDwkA+0/ejKl1GcHnYwg3Ix
         L4cNFvDUUxsNPosLdIQsZTnXn22dFryRonNA38nr9FqAO+P4Cg5rPrVh6P7BOugkunWc
         pUrvNzPt+gmbm/LDJPCeVHcFKWISbQJMVxcq9G94Blsp/L+ihSfsX5F53Tjmz4rEpyED
         i8vw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=OxuK0e+n;
       dkim=pass header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com header.b="OGhmV+/B";
       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);
       spf=pass (google.com: domain of prvs=9484972d9=shinichiro.kawasaki@wdc.com designates 216.71.154.45 as permitted sender) smtp.mailfrom="prvs=9484972d9=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723539791; x=1724144591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:wdcipoutbound:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=zZsM5KbfgPNqHhh2aa5y56bSZv6uxaPnPFpyoq88nAU=;
        b=MXNbWHKFbR5/0B/cYStNnP1v5hZpriRogwaZbec5wN0oMTWtAFdB6Q7dmoHjdLvf6f
         A6YkBumv9BVtcg6iZl65KgdDJq+QpAm6u5OaiWGE74ZhMBZFA9cmulKLgf3N3/mmfB9G
         gSTZBohDAZhikf9NhQYISVCZlX+XF2PW5mOWybSOZ2Zew/V35CM8lhyVCbiwIst/021s
         kKk+WzrrlvPcCA1Dt73f7irt4CIC3L9QQEfsdMQklqRxEyngoEQqt8YtD2BuP54SBZvO
         YzZRGIAy5j+ISUFokPpIJ9/GRMmJmBiW0SDoks5MyVzOthnOWW1ytFjHMdNBjIMoH4T/
         wlQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723539791; x=1724144591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-id:wdcipoutbound:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zZsM5KbfgPNqHhh2aa5y56bSZv6uxaPnPFpyoq88nAU=;
        b=O1VHmu93bRAzKcqncUX4HdR6j1tcmW79a2Ih/JNzof34d7QsXfGwp4aQirf2caAMVm
         MZ2JxZ32+wzUvDluG465QJao/1j1z1C8bqIsDU9BM2Vut1l2BsFhOgq7OZ9aemZNhn4T
         DVSxMqsj2Da5IRGsjsFX70BiDifHxCOtWsR2qul28u0++KL7qbp+DyECRxUeAUUwCIqL
         Q2ZTtBL4T2vJGmaHc1OiNNTP1jJmrAb0XysbcCE+2U06N0hvoF65P8lB1CeRXq7voLu5
         QrllIUJj5y85E26fx7k2eXLDpJUEwWZjWrTNVW8Fy1CIYYPCWm0X+Wzij0tP6TPheMXe
         uuDw==
X-Forwarded-Encrypted: i=3; AJvYcCXSRbnmBpLeP3mE7m5t+gLyvfWSgX7xx0D9xU6UfEzDUg0P9cc5Hs0SzKZ29bHASy9z1GES5w==@lfdr.de
X-Gm-Message-State: AOJu0YycLtQCnWtKLAhJtzz8rwevxeCMNYX0v6ozH2OkkWTqpL5N8RHV
	KGLWMl3S6NkW+rO7tS4FY1xgiP1zXuxehHfoLbBCkGhR5usf76Cw
X-Google-Smtp-Source: AGHT+IEjGJMYRgR9mhbTT/0q7MuH6bx4AUrRMi3c3fGu65oAjxyg6c1t45tYKDi4RX9ksrj0UIVL/g==
X-Received: by 2002:a17:90a:2f61:b0:2c9:6d30:81ee with SMTP id 98e67ed59e1d1-2d3924d6d9dmr3383678a91.8.1723539791053;
        Tue, 13 Aug 2024 02:03:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f00c:b0:2c3:dc3:f285 with SMTP id
 98e67ed59e1d1-2d1bb86b76els471020a91.0.-pod-prod-01-us; Tue, 13 Aug 2024
 02:03:10 -0700 (PDT)
X-Forwarded-Encrypted: i=3; AJvYcCW4CyKh/Uz0SE48XQTrVns3wA7/5gVD3uxSM8vpTpU6OeLFamtQia67gDER08c/MalUwV7rNnHvTbQ=@googlegroups.com
X-Received: by 2002:a17:90a:d794:b0:2c7:ab00:f605 with SMTP id 98e67ed59e1d1-2d39254ebe9mr3049304a91.20.1723539789748;
        Tue, 13 Aug 2024 02:03:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723539789; cv=pass;
        d=google.com; s=arc-20240605;
        b=WFM3/QQVpQ0Z7i6HNjh/lnO6CiFk6epoVi2+5v74sB1QZzjrLLNT7VgPDJXAnlmtf7
         quIuok1FBF9u8lqpyIcpNj5EQVGsUIbOYCbbyFCsDSqRaJuI+PS1csX6DoIGYoevCtYE
         23sLXz4YvHJyCQM5oyFJAPynU74nYsR+nx6QffdMlVPn0hAE8PSEZ8me5AUcebpMlJSa
         bl/5Gm8Uf4uVziQuOQpbwQv28Q3PbQahUccKi8D5MkDNnsJpVEb9eZRrlMcvhwE38KwG
         3OYS5f0Ru+cLY24oYGX+E4fOmnGcoK2UQ6CchA/hSTnAYfZcJRubW1n0A3Y4SGIy0iPZ
         ZYbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-id:wdcipoutbound
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=4twhXU/hTjd72uBogUfmMAHmT2uwOOa2pl7UMWWktPU=;
        fh=mMvgyET6K+TK8b4q+njXrVQfXHOUxGyHNtliy8cgRo0=;
        b=CRnJUUoClSHHkwV4tyFpgLR2XzfT9KnjZTu6WCtLlkWleuxGnlZOCSnZ4f575gVASk
         NKX3yOwmIdjo+1a0KeYZKxKxlRPw3aJkQzTM0zZN9OW9WUOs46OBf7RPwW0EXTVKWTFO
         Uvpi39izL522GZsgM3Y4Exw672Bx0bu0EOODJ0XABszOtfeLWxdaIEMfSffEcXQorQB9
         hIilIpLiLanyjF7VabTJLFoUMuxULOTnzG4n8jLKZ2YRv0GhbhovKttvzavLzXBIURxy
         2tn07g6tRnmsDDhl/hgz30CExCUU0IG/7S8H/08ZKOMzlR/DeBJKmdHXCMg2OdLzTnr4
         Y/Pw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=OxuK0e+n;
       dkim=pass header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com header.b="OGhmV+/B";
       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);
       spf=pass (google.com: domain of prvs=9484972d9=shinichiro.kawasaki@wdc.com designates 216.71.154.45 as permitted sender) smtp.mailfrom="prvs=9484972d9=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
Received: from esa6.hgst.iphmx.com (esa6.hgst.iphmx.com. [216.71.154.45])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d39881a3besi104710a91.1.2024.08.13.02.03.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 13 Aug 2024 02:03:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=9484972d9=shinichiro.kawasaki@wdc.com designates 216.71.154.45 as permitted sender) client-ip=216.71.154.45;
X-CSE-ConnectionGUID: n9Sp5RbaRUW0fFOoxl+0Cg==
X-CSE-MsgGUID: wGzdz0r2TqiNco1e6yaxKw==
X-IronPort-AV: E=Sophos;i="6.09,285,1716220800"; 
   d="scan'208";a="24184661"
Received: from mail-westusazlp17010006.outbound.protection.outlook.com (HELO BYAPR05CU005.outbound.protection.outlook.com) ([40.93.1.6])
  by ob1.hgst.iphmx.com with ESMTP; 13 Aug 2024 17:03:06 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Bo5/UO+kuf7dO0MTXOMuGbpvfVskPRywlIExauK5wBapvHXbYWS63SYc20hipXQNiWzc2+kWVF8+WXrUb72A6jDJsP59WP+BOXkU2iVWtH9mklqXI2aFxCXNpZab0F1o9GsdAjedCVp+duBhD9wqRJ4zpYRqvsJEiZhZfuBmfm8VDyL8C+JU5W4gbEQeGSpAiOklp6GKbL0pmQ6Pmicq9234kM90UFgPQAK9URhO5O4uGAeUV96gKPWBqy4j1XcVetdbe6fdXmDdRqj0Beu6aWsOClTL+/TYBkchUjlsFyLxP3MLxzYBojCPkMcJvUay4nFnu3kBmggdYJV47sQ/Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=4twhXU/hTjd72uBogUfmMAHmT2uwOOa2pl7UMWWktPU=;
 b=DZIM/tVJBHnrH3DDJ+r2lwgK+mVOZezUWq6/cQJTFfqygj/AKSgH1a8MPI7YMi4MaMugB9nqAPc6Ry9NP7XdOJNQPK0Q+n1uNC0hVZRGWS+fo/2oPEqIL+SqoFfS2lmNJ0iowoX2yO4exZGJlt0BtLXZVdn7ywiPiM1yviJShYKV+4X5GXgDgu+HD7avFcuCkPdA+LLvAecI9PQv7g+sKD406ONeET0E4Xo7XRO6B8FHFnW7F0a0DRVijlsMD6K1fTUx76Hl26OiWb1ZQtm/k9uuXyKVANgoZaSvyNgZEQt8Dckc2FyybXHsrHCb+ONenJdMjjpgbTo/XleqGa5OWA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=wdc.com; dmarc=pass action=none header.from=wdc.com; dkim=pass
 header.d=wdc.com; arc=none
Received: from DM8PR04MB8037.namprd04.prod.outlook.com (2603:10b6:8:f::6) by
 CYYPR04MB9030.namprd04.prod.outlook.com (2603:10b6:930:bd::10) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.7849.19; Tue, 13 Aug 2024 09:03:04 +0000
Received: from DM8PR04MB8037.namprd04.prod.outlook.com
 ([fe80::b27f:cdfa:851:e89a]) by DM8PR04MB8037.namprd04.prod.outlook.com
 ([fe80::b27f:cdfa:851:e89a%4]) with mapi id 15.20.7849.021; Tue, 13 Aug 2024
 09:03:03 +0000
From: "'Shinichiro Kawasaki' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jann Horn <jannh@google.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew
 Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, Pekka
 Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo
 Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, Roman
 Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Marco Elver <elver@google.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	David Sterba <dsterba@suse.cz>,
	"syzbot+263726e59eab6b442723@syzkaller.appspotmail.com"
	<syzbot+263726e59eab6b442723@syzkaller.appspotmail.com>
Subject: Re: [PATCH v8 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Thread-Topic: [PATCH v8 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Thread-Index: AQHa7V+aNJWuNJQxqEGdTCA84xSRzA==
Date: Tue, 13 Aug 2024 09:03:03 +0000
Message-ID: <vltpi3jesch5tgwutyot7xkggkl3pyem7eqbzobx4ptqkiyr47@vpbo2bgdtldm>
References: <20240809-kasan-tsbrcu-v8-0-aef4593f9532@google.com>
 <20240809-kasan-tsbrcu-v8-2-aef4593f9532@google.com>
In-Reply-To: <20240809-kasan-tsbrcu-v8-2-aef4593f9532@google.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: DM8PR04MB8037:EE_|CYYPR04MB9030:EE_
x-ms-office365-filtering-correlation-id: 46bf5952-472f-443a-99a9-08dcbb76bd43
wdcipoutbound: EOP-TRUE
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230040|7416014|366016|1800799024|376014|38070700018;
x-microsoft-antispam-message-info: =?us-ascii?Q?8coSqLX+6LPdSJDAaFM52MTqWFWcB1L7y7bnao69DzuNxEpUTvfED7KKh971?=
 =?us-ascii?Q?UsCivObhNUOfjCdhWJH1rSQnLpSGL1iIgf2Oar3LoNPRJRLDBtpRxpPmuhlI?=
 =?us-ascii?Q?bUuTnmbHh1vLALkkCnLOIbXpugyv564X3AsOaBTaTU0fXcA0wmBPE7Y6n5Y6?=
 =?us-ascii?Q?gAemuKrXgeqA4r6DNNuT9DdvONbxj3WOip+Cbp4P5UXTZJ70dKWOUs5bIJs5?=
 =?us-ascii?Q?J8roVW9c6NAKPPEB0oT2iHNSDev+WMZokULk5ODA76JdXQB17Yto4Rx3XHbm?=
 =?us-ascii?Q?ubkPgRPS3FatPWS0yX9AEPidB48vcw92XQCeRzN9MM5uCBv1++QlKQxMLO6F?=
 =?us-ascii?Q?SnDK22jI0g0Afl5dFOIOJ8y/MzpQenviHoq4RGK6iNuVLhqTpgQP4W+p7HbT?=
 =?us-ascii?Q?YgwkvQK9uOdT8GPpQXqeUNAQqzu9NK+SaUpjd1Ubu0MUFMSOdTm6nW6yFGqI?=
 =?us-ascii?Q?adY9WzmHBfyIWrxUzDbfQtEpnlEe+03GTGu9mdrZHKApv52D7QoYSN892Thd?=
 =?us-ascii?Q?OSxR31iD2o51ugiUAmGUfS1o9Wro5DsZojG0yPJ/gEzzOgJu37EZIRW95VVi?=
 =?us-ascii?Q?sc3pDvxrgDHANLN7aG/ETLTVFYJOVagHRdMKrrIQuJNgW1Lu69/AW+G6dlg2?=
 =?us-ascii?Q?WlOfis77eMfwaP0pAhEGB6aHCOtdOxwAt8QzWyTx9pMshgxoDN4s89MRnKVo?=
 =?us-ascii?Q?Od8ysvSMSuzV/28w+q8XxYjuW4AXUThw5Hxo4xqhIRzHffPyowwq4HNibYAk?=
 =?us-ascii?Q?4otNeuBgQlyMLGcqCBZyNOcsVsid8L9jf5J16MCHc3x0lGPiucDbw5mbK+by?=
 =?us-ascii?Q?55HdLPRx5+x3sZqEr0MlFoReFIPgtV8R3wUUboiSHURAzzYDhKKJnto0bbYt?=
 =?us-ascii?Q?HvOkqFnbQk3bOvJjAgZmxVWOp1Pq1QEoGiA09jDbrNB7bsIQ2aEGKPcqBrEh?=
 =?us-ascii?Q?Euy7a4vidJ39XIT28A5g3JKQRr9R5pTw9d7hdctPnxAjEccJYCvz9XXIEj+G?=
 =?us-ascii?Q?G83x/uYSb9RNKh7oyKTn2uM1qYBjCE+Lh+5HjPugaNJJ76iCnp5zHw4iJ035?=
 =?us-ascii?Q?6xoc1eQLJgd8w0w7a2Bpzzdw26oULN3ixtcei7ElwDCs/3qJtSgWIBO2zEla?=
 =?us-ascii?Q?i2mrngAAZrkYkUgGmG+8lXqmH6U9Ikp7jkmqmivQfgKW4TDakRwRz+0TJM95?=
 =?us-ascii?Q?PJmNRw2uxYvjfdjpbEdgmXAz+QMFrEJDPt44ei+vEvxH8Myyxr/fSyvPb/OO?=
 =?us-ascii?Q?/cCFVfQKhHXMWiL39LCPSustHyaNqr79vQ6BrguE2ixS/9XLWs12m+WikHLb?=
 =?us-ascii?Q?cTA3LZh+KE7AaH3oOTDexv2QRu6YB5I8yuFWTP2aJ1QCjvVwn4OGHRz4o5sR?=
 =?us-ascii?Q?QKntCGfk4YRxy7464IPX48uR2ee3eQArXJ/G61q2gFV6/OHyIg=3D=3D?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM8PR04MB8037.namprd04.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(366016)(1800799024)(376014)(38070700018);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?WgZOy94GEo8p2HdyYUFN/d0U1rljaKWe9pczvRkkOX++Z8vota9UvabHvJgj?=
 =?us-ascii?Q?VbJvc5eXZOj5XF6yMGgZw0WVn6kut1JI4KdqBfAqvVsgXP4/BbSv6Rttda8s?=
 =?us-ascii?Q?Q6/PClF4VA8itH2hxEzXKnifEw8cOLggvmMGL0e5R0GQa8R03XiTfR+kudxE?=
 =?us-ascii?Q?4TyzsjsDoB1iRTHCvdRVeoejlX/T6vqeKW9HMRr71E5jXHXNul/H8XZ1L76T?=
 =?us-ascii?Q?wR1gVemv3uWavcGU8XnCyZc+/ksdnh/AtjA5W/f44fmn8XlOwuMeEAp/K46g?=
 =?us-ascii?Q?mhnxmmKZj5Wf/AllHtqVtXvuIGb248Y3zZdn8BB5LzqVEbprFwFYbh+NiFuZ?=
 =?us-ascii?Q?DcIu8Db74gwLKAFm/qadtbayZLuAuVkFnp2E5KB8VTmfpl019NjPEDJT1Hw0?=
 =?us-ascii?Q?/b3duTfACTi9/PwSaWJ9sFHr4HKaq3ilbvTc/KJLmZ8WGIqjTngnIBks/Amt?=
 =?us-ascii?Q?ydBpiuorIWD6VOFmAE9gH1o4gG7bJ4dpbbcnpndIR0YOzG6L5u9EVf09Tswo?=
 =?us-ascii?Q?rqbfIH0BuTD4NKUsTPFk7+/IdZn1MVy4Yers0s1zeql+ah/rUO4rMDzDCXO2?=
 =?us-ascii?Q?aK/qp37EN4y97oCg9/zQMILDQInlRDlRMwJTA2hcqgUDIG3ZesOgvEK9/HDn?=
 =?us-ascii?Q?vGKiIlEFZdZZ7ON+J5GD8fCUM3jnOvzqYuok5JSiPo2birbd7i9A6zj42mof?=
 =?us-ascii?Q?MqVB9sdL+tagqbSSQVyul69vInGYFaU16GH49F7tJQ9sK6J8Sw9DwrwMIeMA?=
 =?us-ascii?Q?xOfKZWXbhrHfRDk5thgWwX7t77ZQEaDYLfqKsuYvd+pBUuXxIiWZ94PADqrF?=
 =?us-ascii?Q?HnUtstoACoMmZ95ZliZtl+OmzWIBqM6skROYwLYTc3eUYRxEwh/47pvYgYu0?=
 =?us-ascii?Q?jPbvvUiCG1KxjbuiYIwBTSgzev/Sm2QE/IDGIeYGz6L+Dp2TLiBmqKhLL47G?=
 =?us-ascii?Q?79QyBt96AIf04656b3wLwB/xjXTPI0t7uo9RCWVJOWyDH5wWaDHEOlyj8ePd?=
 =?us-ascii?Q?s7qzX0L5Qut6657XyEhMJ1b4/9901MUZ5acP9PeGpNS5yrkltBF3tEugBPUm?=
 =?us-ascii?Q?84BPHfkYl4T6U1lDHWwQMrftQe5xjRqLlrUwnucumXoeuRd6gJjbXsTlg74o?=
 =?us-ascii?Q?GmzbB+wTKfJVJP6DS2Bp4L51Tc3hoT56tiuZ69CbvenVGzy7RaOmmOGZHkgE?=
 =?us-ascii?Q?/vXoRSFQzGjw5mcY1YQUcHysAYPK/vlUIpEE1TtH3JBHLKiea/hC5SFvklc3?=
 =?us-ascii?Q?j29/qJv/4gb/54/kk6Hi8A0QrGxQig5B/70ZK2NHTYF6pEa8Y6TFdIPCluK3?=
 =?us-ascii?Q?RMHMUq/wdsAHjRuGpfmvUr9C5oUT3QUjJClBTVcN4hFHHExKJKwfmaAeB2ME?=
 =?us-ascii?Q?Cwo5LFasN2fbxkTwC/fwiBsY4Bp8i9KvJRjJ3ld6XOdrAMkAHowYmEP3q6g0?=
 =?us-ascii?Q?5mUAHmuwm42Py1uhhw1krEdkj3cCM0zPsu0tRA3an4BmjUeaYUxFyp3Vqtl6?=
 =?us-ascii?Q?znByx5A6BxqsKMyj0zEeG3oE7NQtmLBCQlUUbJBNwS6cf+O1GUTXMC9bCml9?=
 =?us-ascii?Q?mavYnsXGHsimRhKOFgJmZ0PxIMOT7CkP4S6N9lopkj5gqastUAV1DGyS0A+/?=
 =?us-ascii?Q?tZtf8CSw7+CaHkJShzclfcw=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <C91B75D4747BC44B891F5C921CD33BB2@namprd04.prod.outlook.com>
MIME-Version: 1.0
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: eEm0UmV96YE22FJy5esY2N58xtHhiXZCcBcMDlC5c0dSLA+FHZtOsZwIjHfM7J1CvUNWw3cIQD9S9vB94XGc/Buy4xhCASbdqTg99wgBzuErxuJuiE41MRLAdLvyZh7es+fftrAq6tRKIJ9NITRDHAPUUbVy0ugqw3uOH2OCrbG7B3qSzrxll0WyZAVZbV8eVTeEYHzEzXZV+4DEEhg+m73QlXorHsF1OUx+h2QN7EMI5weA+wb+AxgNubLgXRmtK0j2XKhss8msXcWQD+h9a1OjyRO/Zw4ecFB7bVco6o1dL6b5wrcpKVh6ciFP7TQkU1bFbdve5SzPZS1AjAO6nw0F4mHwjFWvJQTi1ztP8IOHZ5hf8i3JPK1Kew69yf0DwVkL95UeQF4RCZNJ5brspq3hYKtd+UkfOCIb2PsuMg9wsHhdtUxRBOoXsRcalF/P/dX5GVlgupQTLkx7qi6hriKRGkBLCITkvPmUbSPIxDF/ftAGstNlGRbqeRIe14EL4eC4ehAVV/yxuVDAM+4IW/DYFjTrxm0yoCHtt3uFb34Qm5hU46v8JZkxGiiLBfcwkWM+On+NqW3l6YD5gVuqcduSNdBR4eDNjUpk0wO6bbBLMLJbHZzhxnhXccJEWZYB
X-OriginatorOrg: wdc.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: DM8PR04MB8037.namprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 46bf5952-472f-443a-99a9-08dcbb76bd43
X-MS-Exchange-CrossTenant-originalarrivaltime: 13 Aug 2024 09:03:03.5373
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: b61c8803-16f3-4c35-9b17-6f65f441df86
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: bu+Aum/wUCih4Ao5P6lwuTfQbs/2lfiPh2SrSODzoAq/MM+z35HUxzBEu/clNTPLgGC1m8j+pTlDkBIoRKZzmNw31Dl5dWH89w7omCbkfpc=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: CYYPR04MB9030
X-Original-Sender: shinichiro.kawasaki@wdc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@wdc.com header.s=dkim.wdc.com header.b=OxuK0e+n;       dkim=pass
 header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com
 header.b="OGhmV+/B";       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass
 dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);       spf=pass (google.com:
 domain of prvs=9484972d9=shinichiro.kawasaki@wdc.com designates 216.71.154.45
 as permitted sender) smtp.mailfrom="prvs=9484972d9=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
X-Original-From: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
Reply-To: Shinichiro Kawasaki <shinichiro.kawasaki@wdc.com>
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

Hello Jann, let me ask a question about this patch. When I tested the
next-20240808 kernel which includes this patch, I observed that
slab_free_after_rcu_debug() reports many WARNs. Please find my question in line.

On Aug 09, 2024 / 17:36, Jann Horn wrote:
> Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
> slabs because use-after-free is allowed within the RCU grace period by
> design.
> 
> Add a SLUB debugging feature which RCU-delays every individual
> kmem_cache_free() before either actually freeing the object or handing it
> off to KASAN, and change KASAN to poison freed objects as normal when this
> option is enabled.
> 
> For now I've configured Kconfig.debug to default-enable this feature in the
> KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAGS
> mode because I'm not sure if it might have unwanted performance degradation
> effects there.
> 
> Note that this is mostly useful with KASAN in the quarantine-based GENERIC
> mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> (A possible future extension of this work would be to also let SLUB call
> the ->ctor() on every allocation instead of only when the slab page is
> allocated; then tag-based modes would be able to assign new tags on every
> reallocation.)

[...]

> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index afc72fde0f03..41a58536531d 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -67,12 +67,44 @@ config SLUB_DEBUG_ON
>  	  equivalent to specifying the "slab_debug" parameter on boot.
>  	  There is no support for more fine grained debug control like
>  	  possible with slab_debug=xxx. SLUB debugging may be switched
>  	  off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
>  	  "slab_debug=-".
>  
> +config SLUB_RCU_DEBUG
> +	bool "Enable UAF detection in TYPESAFE_BY_RCU caches (for KASAN)"
> +	depends on SLUB_DEBUG
> +	# SLUB_RCU_DEBUG should build fine without KASAN, but is currently useless
> +	# without KASAN, so mark it as a dependency of KASAN for now.
> +	depends on KASAN
> +	default KASAN_GENERIC || KASAN_SW_TAGS

When I tested the next-20240808 kernel which includes this patch, I saw the
SLUB_RCU_DEBUG was enabled because I enable KASAN_GENERIC and KASAN_SW_TAGS
for my test target kernels. I also enable KFENCE.

[...]

> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> +{
> +	struct rcu_delayed_free *delayed_free =
> +			container_of(rcu_head, struct rcu_delayed_free, head);
> +	void *object = delayed_free->object;
> +	struct slab *slab = virt_to_slab(object);
> +	struct kmem_cache *s;
> +
> +	kfree(delayed_free);
> +
> +	if (WARN_ON(is_kfence_address(object)))
> +		return;

With the kernel configs above, I see the many WARNs are reported here.
When SLUB_RCU_DEBUG is enabled, should I disable KFENCE?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/vltpi3jesch5tgwutyot7xkggkl3pyem7eqbzobx4ptqkiyr47%40vpbo2bgdtldm.
