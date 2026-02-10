Return-Path: <kasan-dev+bncBDGLD4FWX4ERBBP3VTGAMGQEWM5JUQQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id CK/mIIg9i2neRgAAu9opvQ
	(envelope-from <kasan-dev+bncBDGLD4FWX4ERBBP3VTGAMGQEWM5JUQQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 15:15:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 017FC11BC6B
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 15:15:35 +0100 (CET)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-7963f2fadc3sf12453957b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Feb 2026 06:15:35 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1770732934; cv=pass;
        d=google.com; s=arc-20240605;
        b=VVkiMVZjZg53bXo5iM8niKaI5i5U3tw3z2sGKV3N5Gd48VYz2CrLH119J4SfJtbeXa
         gowUXaf81V0mf0BnPyTNz//wvOzsEQVOkkxLigGMCguQyOCWyHJQvWmtyHS8PNG6dEUF
         4kc4dgeNQeWIgHMylJqI4kms+ifYP3SPbbzxE2fj6RbE7hS6zQMqReLSHLx4GGgAv22y
         OHXC+rmv1EfnYoJ4yfhn/Zrs4gA5SfrcF/3L2VJT1lS3+C5itj9q3B682TNED4qzQ+di
         l8yadUJxyj7FkcyAw/Ve26vM1MJMtYrCE6RawPbs3M2KFWq6t/SbKSsu66l1UzdncdO4
         fjwQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:content-id:wdcipoutbound:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature;
        bh=bsJcgk9uXK+Kb0xuOo0llwcyTFAgMUhEJNqcg51U7Cg=;
        fh=eMmQKwdAHvEt2h7szT5J0Ggw0uBa54qqI5ifpVONf4U=;
        b=Y3NB0NcRJVW+8V0k/jVvpsd4MJxZp8OctJUR/ebbZVxzjLeR4s4LxfWkZigU0f/3lQ
         viXh8tANRIlvZmA414HaavznyH+2SVHQZ8a8Yxkut1UyvTZ0eTkMbgHUfZ0njzG2Zsst
         1l+roN2fX0MYGFjbB9U0wnoiAHptrjrFwly7mPE0QaaQoSO6ICzZ5yqJl0BEzq8VNvTo
         PX2DyMvXbesDLEtYRKZVccjM9IN5wUfyFWDZgJ794OhTuLUc24AU2jiZGkwM8JyMq8yn
         T8FwKgQ9PpoIauru0cNFXgRS9CWVVfEgYoPfprCVaMHjbw60EsKGAMZ/NS7/egi+Zppp
         UHSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=QvNfXlsv;
       dkim=pass header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com header.b=w73+AXfJ;
       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);
       spf=pass (google.com: domain of prvs=494c0bdbe=shinichiro.kawasaki@wdc.com designates 216.71.153.141 as permitted sender) smtp.mailfrom="prvs=494c0bdbe=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770732934; x=1771337734; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:wdcipoutbound:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bsJcgk9uXK+Kb0xuOo0llwcyTFAgMUhEJNqcg51U7Cg=;
        b=n11lPqJzo1Y5fshoekavSfKyZ+S5A5x1PZOBaILbDd0kYDyFn+84o3nbeuAvlnr5rZ
         awCFYkNPysAhQ5IFWUJfgyhdSM+XY8xiuovATn/Wx0KBtTHJkxGcF51Mq9app6+J2wLV
         MjEF98TQlUzypARkmY2bFqE10ythoQSIVyYux1ihYxwCCcEF75+rg5/vD1myLCWYHVP2
         y7HO/a774xoUZ+cCAybSmv08P7HC7XJAgUzGHUlSJkhKD4IUJfb7sqCim/PSYB0fqTvZ
         xWITJZ+IseuPMkFXacnJsjjpl7TeX9iOCGzGSenIu3XwtoaFuEVtK9fopeRmU22DZ4MK
         JA3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770732934; x=1771337734;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:wdcipoutbound:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=bsJcgk9uXK+Kb0xuOo0llwcyTFAgMUhEJNqcg51U7Cg=;
        b=hx80wdTaWeEpUR7HwgjjPV8nkNWdWD87uvnupCcOUGvXuNRvSb0dwzDPaM9UwLx7C/
         XSE5nx1uXPrkrkSoohYBJEaJ2NxLdcVCQMxVenyAavi8yxTLsmRp5XyLTcethO7v98qA
         vEPafz49kCXvyYVMB6NlNeURmPyBBNimETW9WIUNUxaHT/pAi8yB1oTQ/LVvdPUR0wms
         oW2dbqmi3EMk7NX2aUEOqei3TozPSFKGRajntqpmyYyVc4HdnVi18srMo2m+6T48+0+5
         w3a5hfXvHKcWgJTk1wcRGexdv6ugormnPU9UFHEFI2cDsccdeo8kCHb/QSydXPodkKrP
         PS6Q==
X-Forwarded-Encrypted: i=3; AJvYcCVZkQxh0sDpOCCrhzQ3Q2C4Fbgc7fpQy+X1yr+OdJlNOE2j3jtjlyIeTiry8fBxEixJm+r57A==@lfdr.de
X-Gm-Message-State: AOJu0Yx2uU4vQZrY22aHu6wN/mJ3S4tMKm15aMuuV3RHRLuNqtBOIPMr
	M73eusGXkzVmynL038ghuH8qVxfH75nM3KQbAnexEsCVK/L3VDiJBaRx
X-Received: by 2002:a05:690c:88:b0:794:e08a:9196 with SMTP id 00721157ae682-7952ab249bbmr294852367b3.34.1770732934046;
        Tue, 10 Feb 2026 06:15:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HCm/wy+NtnKjJe0+FZP7UzulvsEb53IztGEJ52A1E0DA=="
Received: by 2002:a53:ab44:0:b0:64a:cec9:f26f with SMTP id 956f58d0204a3-64acec9f3a3ls2663563d50.0.-pod-prod-08-us;
 Tue, 10 Feb 2026 06:15:33 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCXMcHZbq/jPTcWz39XC4SZWp3VWOlgoH1bgJMmPgKQnzYB18XrQK4J842+bSmEZlWqe+ehgTLigolM=@googlegroups.com
X-Received: by 2002:a05:690c:39d:b0:794:cf56:5bf7 with SMTP id 00721157ae682-7952ab2482amr292121417b3.33.1770732932926;
        Tue, 10 Feb 2026 06:15:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770732932; cv=pass;
        d=google.com; s=arc-20240605;
        b=VEUMZu4PLIY5FL9riMP830KKNMxnRi0Qcd81Lwf4X3x5fF8UjWN909z6txPe6Zw1lW
         9UoRGy/iCOn7E6wQrl8EUuUzU2YXmgi+oRlwuL+IXIzcZwaPYlTcryCdheSwJ9PDJgce
         Y2i6DgsaPiV+4W2D3Ix+ZbaZZLP2BWKFZR4vjbOXzLW+mvEws9LjqTKg3crSVdA8CARU
         txFQK07wohR4RwPBu8mSKu/Xg/8ed614kM5NGSZ85FKbPcrvypxUwmTcFQIIQpfhEvAK
         vKmDAWQQ8RXTJlGM03x5CTNypu1tENMmdGlMIMaNFBrsiGGLhZBuxpKLkAOFZ/92lxMW
         vFCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-id:wdcipoutbound
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature
         :dkim-signature;
        bh=UiOoIkGOOQwH5CkJl9f1htageQjeoAJDkR774GH1jVY=;
        fh=TK/9xA7FH9VC5C0D61mItE8QZBXPRNVPz7vLmw4+r+k=;
        b=IIJhDAIfy6i1by+zdaqE/VU53yIKk+tzH2CLGYLW/GKJ+68yRPSKHj+PxGHoXNFL9v
         JWacN0IAsHGArZU1j9XP/1DijyeNpoGmmxpEZ/JqICD723dRZwaLb798SYQMO4oLJgwg
         kesXw0Eyak1LXsSAo7vfUbNFrHkSNQytcqKyLoMW4T751iJ9gw+mUQxSn527v/6qxePk
         Ex6OrgnIrbpyNQJsh6q6w1tgC91p8HUJ7t7JNKAP0zn5io2ewqy5UEUnuo1n9B91b6e/
         0xoyErEVlEk3xgGmzLKsjxJzn3GuU/CzLQsPBQ//dElfrXflzKfBlxMoRd7LFIt9UBU4
         thEA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@wdc.com header.s=dkim.wdc.com header.b=QvNfXlsv;
       dkim=pass header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com header.b=w73+AXfJ;
       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);
       spf=pass (google.com: domain of prvs=494c0bdbe=shinichiro.kawasaki@wdc.com designates 216.71.153.141 as permitted sender) smtp.mailfrom="prvs=494c0bdbe=shinichiro.kawasaki@wdc.com";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=wdc.com
Received: from esa3.hgst.iphmx.com (esa3.hgst.iphmx.com. [216.71.153.141])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-79529ff07bbsi5389307b3.1.2026.02.10.06.15.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Feb 2026 06:15:32 -0800 (PST)
Received-SPF: pass (google.com: domain of prvs=494c0bdbe=shinichiro.kawasaki@wdc.com designates 216.71.153.141 as permitted sender) client-ip=216.71.153.141;
X-CSE-ConnectionGUID: mCul8janSsKq6ht17ZUCjw==
X-CSE-MsgGUID: 3GBhcBrySp6CYxkbwdB2yw==
X-IronPort-AV: E=Sophos;i="6.21,283,1763395200"; 
   d="scan'208";a="141069300"
Received: from mail-westusazon11010026.outbound.protection.outlook.com (HELO BYAPR05CU005.outbound.protection.outlook.com) ([52.101.85.26])
  by ob1.hgst.iphmx.com with ESMTP/TLS/ECDHE-RSA-AES128-GCM-SHA256; 10 Feb 2026 22:15:30 +0800
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=JGdrZjkJeF0aREnkFBM2CGAe5xiuAmwW0+cSd8YvMbjnLiPMzVUVFAUi3ALiyh/tiFUkET61tS9OHXkd9OCs7XK8vQ0w6gN4DvHInrrSAXmf8q1HqEQ3riQ3rCJP4wXHAYHFCoYui3IyJhKg3FwzdcOOd7iLt/VCej1NZUtmBuzSkVGs/nMYAnmluxbzQDpPqQXhymEc09IIuzntKZj1VJvjLqzPX+oLkSsrb+ZfYJ6IvCWJm4NYMNsp7wU8UJ0zfIBUhXyen7whiwUfYrHA2FvklWypzQimPFn4ZdjTFj+Zmo6nzttaw0rJkpRWl8M6v43IB/8AEBvPsefmWjnSqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=UiOoIkGOOQwH5CkJl9f1htageQjeoAJDkR774GH1jVY=;
 b=TTll1rt5hmbP0TGGTY5W8jb2UcQVrlyr1OtR/hf3U8nPJX7q8BKVbD74Q9q0oD2lP7lauojPbZ706m0sjGnnoQwgxXNzEL4Idv+UTdoXsEetD0kOD7Gt9uBHsRLFqiKuvo6/1vBHIlczNKgTo2osmNtb92hFaFiNpRa9A6g8NNCkuhaGNnsInz3DjmyZ1Yh4uOPnY59IoY3g+WNm7nMXFd1hJNGBSn2gaOapO9KvP8ornb64PZv9x98Et9zOSYoSBnIkLxD7XZNbW2NJ0JO71VOSoz2KG3hrIBt7TUB9tg1IGEkZ1FeYXLWTp+YhZ1J7WAEYL8etdKDklrVvlhVu6g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=wdc.com; dmarc=pass action=none header.from=wdc.com; dkim=pass
 header.d=wdc.com; arc=none
Received: from SN7PR04MB8532.namprd04.prod.outlook.com (2603:10b6:806:350::6)
 by DM6PR04MB6394.namprd04.prod.outlook.com (2603:10b6:5:1f0::21) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9611.8; Tue, 10 Feb
 2026 14:15:28 +0000
Received: from SN7PR04MB8532.namprd04.prod.outlook.com
 ([fe80::4e14:94e7:a9b3:a4d4]) by SN7PR04MB8532.namprd04.prod.outlook.com
 ([fe80::4e14:94e7:a9b3:a4d4%5]) with mapi id 15.20.9611.004; Tue, 10 Feb 2026
 14:15:28 +0000
From: "'Shinichiro Kawasaki' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
CC: Thomas Gleixner <tglx@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
	Ihor Solodrai <ihor.solodrai@linux.dev>, Shrikanth Hegde
	<sshegde@linux.ibm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Michael Jeanson <mjeanson@efficios.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [patch V2 3/4] sched/mmcid: Drop per CPU CID immediately when
 switching to per task mode
Thread-Topic: [patch V2 3/4] sched/mmcid: Drop per CPU CID immediately when
 switching to per task mode
Thread-Index: AQHcml+PLO/xV8naRkaVyFCdn6e9irV7v52AgAASugCAABQdAIAAFDWA
Date: Tue, 10 Feb 2026 14:15:28 +0000
Message-ID: <aYs8qWWC5JyE3z44@shinmob>
References: <20260201192234.380608594@kernel.org>
 <20260201192835.032221009@kernel.org> <aYrewLd7QNiPUJT1@shinmob>
 <873438c1zc.ffs@tglx> <aYsZrixn9b6s_2zL@shinmob>
 <20260210130308.GH3016024@noisy.programming.kicks-ass.net>
In-Reply-To: <20260210130308.GH3016024@noisy.programming.kicks-ass.net>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: SN7PR04MB8532:EE_|DM6PR04MB6394:EE_
x-ms-office365-filtering-correlation-id: a6a90a71-e553-4499-2411-08de68aed7c3
wdcipoutbound: EOP-TRUE
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;ARA:13230040|7416014|376014|19092799006|366016|1800799024|38070700021;
x-microsoft-antispam-message-info: =?us-ascii?Q?WZkABCEKxvOuxTAMR4OrR9GDPJt7JNqEqc+SIqXfosfq/zqfPZCc1wFkT9dA?=
 =?us-ascii?Q?JqNA90lLcBGAIQTlYAtPyBsbqrk6thB7CYxl7Y+OUWdYSpEn6A6c4thn1D/7?=
 =?us-ascii?Q?ruFIRTgX3ABbj86hRKTv+tRS91zRoU5eGdnOSm9KQ1vzmxd9ukuCX99ckfub?=
 =?us-ascii?Q?TLzd9TlmXbljNf5YTmct35YAtCe+HNbZTz/ZUnwANMBaH8CN4nOjP021M2uC?=
 =?us-ascii?Q?tvJgPuzNxmPTJ7dGtqryH8wImzKOhLnuP8+OWtUtrCgWk212efu9MVk6eiu2?=
 =?us-ascii?Q?wfYUWrwirAk9AEpLKl7AYuVKrHGRICDHqG541iKzw54a4bQjVL1RUdVrPYoR?=
 =?us-ascii?Q?VGYGDkBtW/pg9ys33LDweChpncUegAvgMEywTHdxdNyV+dwFKGojRP65F5ma?=
 =?us-ascii?Q?H3HTsG7rGNsm1KV96EnnKVX9cLzG9XSi4RIvuVk7EE/UEdTxMRpTc3Yx0rzs?=
 =?us-ascii?Q?0MV60dLUOS1eOmrN4PP3RiSsUe+DGlaC7ut3p+oserdbn2x5VrFfzzuwRc13?=
 =?us-ascii?Q?iNzaoKjxwzgDNXfrHdJLDVvxEUqSfU2X/E4iPSKVy9qkzj05NfKo2O9pzVy5?=
 =?us-ascii?Q?uKC7S2HxwvLCiAqxclGagxlcXsxDPZgiSGT6Pj6jdUACWHLhh12P5nc9rrmi?=
 =?us-ascii?Q?+oR/1Tu8DMQluc7M7w0XiZXbgV6Rsgbo8vVQgxANXY6/kHs2SqygeFGhd9Mc?=
 =?us-ascii?Q?rSqi2UAfJZ4E3N1XLV+NHTTEftR2e/XGRzL1syCYTONhO5f2wQhPmP9rG/M9?=
 =?us-ascii?Q?/HR775pLg4mzeOBtfIOCxf7YBDG9IwFLO1lMhu04wloovl5ybhBDpysVgHsi?=
 =?us-ascii?Q?oQwS+yRDlxlOXHEc/yS8whCz31WsEVreKtWHsdYyGcxMTmYRFcjKQVdmqQZj?=
 =?us-ascii?Q?wG4hqXM80YTwTXoZMlYe/ekjIlexRwdKkjAQNl8HajECOGogxjwjPqGUkq+G?=
 =?us-ascii?Q?48BdavnfpdjpMaDkXAYoy+jcDmOcj5avF09X4BKNssUrgJk3wMR/3QlfhiHd?=
 =?us-ascii?Q?jjwCeX42zLJjVr2wGQyT05iEGuqKvutcP88fwx0EmXyptg+r0JI1VfZlVrhG?=
 =?us-ascii?Q?dNpusTksgJY6a8I/MNkArwugIbq6RlT5zY3EIJYzMMMrPTkEQDjigrL32M5N?=
 =?us-ascii?Q?pSjCnfou7DRdJKE46XcCsP/g3SKI92fJFVKKbULDALUzyn6Imco4JaWmtE3Y?=
 =?us-ascii?Q?GnMt3O8VT9+wfFqXxQjTeMHHg03lUuiyXmxX2NxdcdClcB+K9jNJy7Mwu0AP?=
 =?us-ascii?Q?YaR7JhFvh6E7r/QEcgUT83Mdgn2MF7RU+JhDNWhDMqaavJQGEezelUMKZ/0A?=
 =?us-ascii?Q?YXVOHu1DFuh2YK4UVi2+ouOxKixUPsl5NFn7z65Vmw1I6FUgMQUYAW1orjrk?=
 =?us-ascii?Q?u8XbrAkauYF8SZJlnJyJUBMyJ/hLXOO8a49Qmx6mwxJp0SKlA6fq4q3KjB9p?=
 =?us-ascii?Q?9LzRjand8LfeNNcPHpg9vz7GCVJQ2hWe3jpsYnA4FUi25sYMFinP0F6byFyv?=
 =?us-ascii?Q?YzAwuvgu6QAXLrc6XT5Ypo8V/WxBr7xF3spv3oXDBE4pODikTeD9JqCKTjZS?=
 =?us-ascii?Q?nw+5Q4Kxj5ARA9T8DGGiBEx+c0evAip8T2VE5tNoB7drJwMRRnOQBmhiYSNU?=
 =?us-ascii?Q?1M6wAZqIjhhKldTWT8jAqe4=3D?=
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:SN7PR04MB8532.namprd04.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(7416014)(376014)(19092799006)(366016)(1800799024)(38070700021);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?us-ascii?Q?1hrw/jZyATPP3zfajSAP3YqajOJLSxQUYvZUacrjfMgbf0EBwDoy63ejbXKI?=
 =?us-ascii?Q?Qpx0zzHYSCOQW1ytCHM8J88IZJGsJuKAHN9JFjuyatR5mpyu/d59jjPXi3hg?=
 =?us-ascii?Q?NqbxeVjgKAox9hJWh8lmvwK0dtY/3MiaTuLo9tLKHmG+agy08L43HZWJYrFl?=
 =?us-ascii?Q?0W7l/8QlcV52kGbT6Lj5JTCmz7vt/WBqvkTTNC0p4yh8Qxqcml2Jy3kR3o4T?=
 =?us-ascii?Q?WWkxrSHhxcj91v0vXTXpJ2hjQPvONgHMTw/iBRwdtabDlc2PlKfjb2CM09xY?=
 =?us-ascii?Q?0MdUteuHriUt5+fsDv0keMhtRAVNNg53o4fa0nsQ3rLb9kYYMBAK7CasndD0?=
 =?us-ascii?Q?OhnH5ED3H/lUiQw20TwQHnu7oPmKNNhz8zxvREjUmoUEhyHd7NB8ON4KZx5s?=
 =?us-ascii?Q?j55KAgdJ8wOa1STLaffbC5vK384LuroCe4uYUPM40QiIG4dXuRaWy6M+1/4d?=
 =?us-ascii?Q?KyFuoeT/rXxbSroDrA6EV+UJkGXX6ZAN5862Ho9AENJgZ50EGN3RPVeux92a?=
 =?us-ascii?Q?bpxw2lV9xCWjPbrGBy1Hl6J9brLUd53NUiAaIpKNBv0LRPluj6YgdEab4nxn?=
 =?us-ascii?Q?cMfkHJRYOaMNgaP08U6R0TdvsAWW0EzHHPpeCU4SgJiocyjkTsjxexQlLAaP?=
 =?us-ascii?Q?f5Vvqjtudy+eXuUBFlQnoHCfliZz3Ogq+/NWymL+/zZG9zyc5QNSGrdLzaYj?=
 =?us-ascii?Q?M6rN1+7B4nem30pSLpYwIHMFNZL0ZOAeyDahJWkJb0H0qI3GTm/NyQviwyPb?=
 =?us-ascii?Q?yKEemgxSeGmoy719f4lxzsmYFMUSteXeYHpxMFoBp7vgQyI6vSjPeyk7e6A7?=
 =?us-ascii?Q?oP0JDGaYVV6XF1nkRZ2qslMhWGxOSnVTy0aZRDB7V0gSp7Jz3lM/zx0AcgIV?=
 =?us-ascii?Q?1tPJDDFjmmvoqKOZjO+PH9AIoE4euTQaN5TZlk0Uv4o0TVx3421y6Bd0hoxF?=
 =?us-ascii?Q?Gq42NUV+4lkL+tyW1118I5sYD4A+bNgDxKYeKJMSPAOIsDKI4X1S+oZVFVSv?=
 =?us-ascii?Q?RSfzRAwxkSOm11hWOAEIWADoJ7yP/QUzcWsz5VbENmilVAX8gjhKFXDr1qYl?=
 =?us-ascii?Q?QLFoEYgcIZf8oJ153T5bGZRqt0H39PhFld25jCjPFJTPgjju5OtC+nznq/yv?=
 =?us-ascii?Q?Ea83hC4pYYxSIHRS85akx9a0S47UzW5AXmXQLU5AwbGmbekW/R8VpzcD+p/y?=
 =?us-ascii?Q?OmtXlojUR/4SWqEhO6lSgAvlVDHSoUM6LF6y4NFNLJLG416k8dMV6wM0VZRW?=
 =?us-ascii?Q?GixqzSIamRGjwN7rSgtfF3mdarVMpEHFaomDzVGxSME1Gu5gR8Zg8bS/cSfo?=
 =?us-ascii?Q?V9GrkA1ExWCaewZVrJpzbdcQFTNVvCJgPhsKTpVwc8yJ5S94XdP3WAWN3aeq?=
 =?us-ascii?Q?14htKEWaZXdMqWdPvhuNBTLC632EkgkuZ3UBgHJMhNHDnFcFKmHcUjjL8qT4?=
 =?us-ascii?Q?KnhHK8gcLY7TPEcp3kuTUK4AvNdSO62Le6KSOzdMt/hPN7531XJblD7WwHwk?=
 =?us-ascii?Q?dOyuEfeVuXa/LKFkkDVGy01gHlaWUXZ/c6ZAfb5YlJ4yk7o+mmIDJlnNKH8x?=
 =?us-ascii?Q?558sYwHPaOktMMOMBP9VxB/8tmY7975nDrIaJpovrjyoOWD8fbRm+77RWV26?=
 =?us-ascii?Q?ZGsR5I5Fy+GjhEvboCfLjDK2xntKT5/8cyI5Ess+jPeDIC3ki9KCtu7JYLkt?=
 =?us-ascii?Q?NLRIpYqnPBce4glA5fM0svGztn0qbWo1E0XI5gft4QhIEXfYueLJGRloaA6v?=
 =?us-ascii?Q?gooElGYj7eB/mmpd2G0dLVjm+ChkG1U=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <9BAD071272E9964190107EFB81CAAB3D@namprd04.prod.outlook.com>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-ExternalHop-MessageData-0: lCZjHWrsdZYAbQWEWDB7C9ZEEg2WOpgpdfxCTJ7p4k9z+jEGzxK9RS42oqGYb4O8duFJtcIU/tT9JnsR2zVvGfTtQq/6fub2n6FTeYr4uQh0KP/H4C/SN0sOAZiwQuWuZfGijXQJwx4dML+4bVCNuEpi2NyeejNPx6pSZcl52ns1GKeqtp2ZAHuu78efEl3pa9uYpMgU6K3gkHNXDzhMqNHUJ8wjQ9ujkB0KFzWTfyLbZYv/oLOdgNJWZgJL62JAGc5C2qqkMX86Mtx2oYYCbpN1Lc1F29snvNw0qA8yuCMsn5N3PwNa4eteFYIrME8+GWXTJAMi81655Xie+0Qmqa2wKHTyJ4uQ8xbjF1Ots1duEBXo7FYb2X+U0Kl6cXePmGC7vRp5E7dislaqkt8uqBNQndwEJ5+d2u2FFsEOVH2jMwdAmq30utDwerB83477L01ggjm/uPtad/k4KK25DKoOfwoRVBQmptqPh+VC806rWq4ZX1u3oLu0SNnZJQkIyKC5Lg8YHkC06w1io7Pl0UgKvAGiHUNyejLjJZHrof/GnvT1ZffBVK5c/JJWTbk9nnd30lqqcfk7hFyN6zHLvEtINUVAMYeBBHTP6TPG+GZSdjFROePaumKbx3cIQuao
X-OriginatorOrg: wdc.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: SN7PR04MB8532.namprd04.prod.outlook.com
X-MS-Exchange-CrossTenant-Network-Message-Id: a6a90a71-e553-4499-2411-08de68aed7c3
X-MS-Exchange-CrossTenant-originalarrivaltime: 10 Feb 2026 14:15:28.6595
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: b61c8803-16f3-4c35-9b17-6f65f441df86
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: f0mt/F+oIHGTgTAh2xkfReeMY70N6RApMD11mECMCuKMJqU4zHx0fEMnBaDQdR6HGDUSZhfBwlt2xpJXbVG7661VPII2QUCNhIhwDOZFkX0=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR04MB6394
X-Original-Sender: shinichiro.kawasaki@wdc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@wdc.com header.s=dkim.wdc.com header.b=QvNfXlsv;       dkim=pass
 header.i=@sharedspace.onmicrosoft.com header.s=selector2-sharedspace-onmicrosoft-com
 header.b=w73+AXfJ;       arc=pass (i=1 spf=pass spfdomain=wdc.com dkim=pass
 dkdomain=wdc.com dmarc=pass fromdomain=wdc.com);       spf=pass (google.com:
 domain of prvs=494c0bdbe=shinichiro.kawasaki@wdc.com designates
 216.71.153.141 as permitted sender) smtp.mailfrom="prvs=494c0bdbe=shinichiro.kawasaki@wdc.com";
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.21 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDGLD4FWX4ERBBP3VTGAMGQEWM5JUQQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	TO_DN_SOME(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,vger.kernel.org,linux.dev,linux.ibm.com,efficios.com,gmail.com,google.com,googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	HAS_REPLYTO(0.00)[shinichiro.kawasaki@wdc.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-yw1-x113c.google.com:helo,mail-yw1-x113c.google.com:rdns,wdc.com:replyto]
X-Rspamd-Queue-Id: 017FC11BC6B
X-Rspamd-Action: no action

On Feb 10, 2026 / 14:03, Peter Zijlstra wrote:
> On Tue, Feb 10, 2026 at 11:51:10AM +0000, Shinichiro Kawasaki wrote:
> > On Feb 10, 2026 / 11:44, Thomas Gleixner wrote:
> > > On Tue, Feb 10 2026 at 07:33, Shinichiro Kawasaki wrote:
> > [...]
> > > > [   65.768341] [   T1296] BUG: KASAN: slab-use-after-free in sched_=
mm_cid_exit+0x298/0x500
> > >=20
> > > Can you please decode these symbols (file/line) so that we actually s=
ee
> > > which access is flagged by KASAN?
> >=20
> > Sure, faddr2line points to the line the patch touched:
> >=20
> > $ ./scripts/faddr2line vmlinux sched_mm_cid_exit+0x298/0x500
> > sched_mm_cid_exit+0x298/0x500:
> > arch_clear_bit at arch/x86/include/asm/bitops.h:79
> > (inlined by) clear_bit at include/asm-generic/bitops/instrumented-atomi=
c.h:42
> > (inlined by) mm_drop_cid at kernel/sched/sched.h:3746
> > (inlined by) mm_drop_cid_on_cpu at kernel/sched/sched.h:3762
> > (inlined by) sched_mm_cid_exit at kernel/sched/core.c:10737
>=20
> Could you please reproduce with the below added?
>=20
> Just to double check that that cid value isn't out of bounds.
>=20
> ---
> diff --git a/kernel/sched/sched.h b/kernel/sched/sched.h
> index bd350e40859d..dadfd6abc1fa 100644
> --- a/kernel/sched/sched.h
> +++ b/kernel/sched/sched.h
> @@ -3743,6 +3743,7 @@ static __always_inline bool cid_on_task(unsigned in=
t cid)
> =20
>  static __always_inline void mm_drop_cid(struct mm_struct *mm, unsigned i=
nt cid)
>  {
> +	WARN_ONCE(cid >=3D nr_cpu_ids, "XXX cid(%x) out of range(%x)\n", cid, n=
r_cpu_ids);
>  	clear_bit(cid, mm_cidmask(mm));
>  }
> =20

Thanks for the action. I have applied the patch to v6.19 kernel, and reprod=
uced
the KASAN. The added WARN was printed as follows. (Now I'm trying the fix p=
atch
candidate that Thomas shared in another post)

[   73.897104] [   T1031] run blktests zbd/013 at 2026-02-10 23:09:21
[   73.987761] [   T1049] null_blk: disk nullb1 created
[   74.417726] [   T1049] null_blk: nullb2: using native zone append
[   74.436675] [   T1049] null_blk: disk nullb2 created
[   75.983893] [   T1175] ------------[ cut here ]------------
[   75.984939] [   T1175] XXX cid(20000003) out of range(4)
[   75.985515] [   T1175] WARNING: kernel/sched/sched.h:3746 at sched_mm_ci=
d_exit+0x37b/0x530, CPU#3: cryptsetup/1175
[   75.986573] [   T1175] Modules linked in: dm_crypt null_blk nft_fib_inet=
 nft_fib_ipv4 nft_fib_ipv6 nft_fib nft_reject_inet nf_reject_ipv4 nf_reject=
_ipv6 nft_reject nft_ct nft_chain_nat nf_nat nf_conntrack nf_defrag_ipv6 nf=
_defrag_ipv4 nf_tables qrtr sunrpc 9pnet_virtio 9pnet pcspkr netfs i2c_piix=
4 i2c_smbus loop fuse dm_multipath nfnetlink vsock_loopback vmw_vsock_virti=
o_transport_common zram vsock xfs nvme bochs drm_client_lib drm_shmem_helpe=
r drm_kms_helper nvme_core drm nvme_keyring sym53c8xx nvme_auth scsi_transp=
ort_spi hkdf e1000 floppy serio_raw ata_generic pata_acpi i2c_dev qemu_fw_c=
fg
[   75.992120] [   T1175] CPU: 3 UID: 0 PID: 1175 Comm: cryptsetup Not tain=
ted 6.19.0+ #387 PREEMPT(voluntary)=20
[   75.993151] [   T1175] Hardware name: QEMU Standard PC (i440FX + PIIX, 1=
996), BIOS 1.16.3-4.fc42 04/01/2014
[   75.994146] [   T1175] RIP: 0010:sched_mm_cid_exit+0x37e/0x530
[   75.994773] [   T1175] Code: 01 00 00 e8 74 90 48 00 48 8d bd 30 01 00 0=
0 48 83 c4 10 5b 5d 41 5c 41 5d 41 5e e9 5c 27 f9 ff 48 8d 3d 75 cf 85 04 4=
4 89 e6 <67> 48 0f b9 3a 48 b8 00 00 00 00 00 fc ff df 48 89 da 83 e3 07 48
[   75.996798] [   T1175] RSP: 0018:ffff888124bb7b20 EFLAGS: 00010016
[   75.997442] [   T1175] RAX: 0000000000000003 RBX: ffffffff95e37da0 RCX: =
1ffff110272ab021
[   75.998296] [   T1175] RDX: 0000000000000004 RSI: 0000000020000003 RDI: =
ffffffff95e49f30
[   75.999094] [   T1175] RBP: ffff888139558000 R08: ffff888139558108 R09: =
0000000040000000
[   75.999958] [   T1175] R10: 0000000000000003 R11: 0000000000000000 R12: =
0000000020000003
[   76.000812] [   T1175] R13: 0000000000000000 R14: ffff888139558178 R15: =
ffff88811d6baf80
[   76.001632] [   T1175] FS:  00007f72777fc6c0(0000) GS:ffff888408490000(0=
000) knlGS:0000000000000000
[   76.002579] [   T1175] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   76.003299] [   T1175] CR2: 00007f7276ff97d0 CR3: 0000000104970000 CR4: =
00000000000006f0
[   76.004088] [   T1175] Call Trace:
[   76.004476] [   T1175]  <TASK>
[   76.004793] [   T1175]  ? lockdep_hardirqs_on_prepare+0xce/0x1b0
[   76.005431] [   T1175]  do_exit+0x25e/0x24c0
[   76.005870] [   T1175]  ? __pfx___up_read+0x10/0x10
[   76.006389] [   T1175]  ? __pfx_do_exit+0x10/0x10
[   76.006867] [   T1175]  ? lock_release+0x1ab/0x2f0
[   76.007401] [   T1175]  __x64_sys_exit+0x3e/0x50
[   76.007835] [   T1175]  x64_sys_call+0x14fe/0x1500
[   76.008355] [   T1175]  do_syscall_64+0x95/0x540
[   76.008790] [   T1175]  ? __pfx_do_madvise+0x10/0x10
[   76.009336] [   T1175]  ? lockdep_hardirqs_on_prepare+0xce/0x1b0
[   76.009900] [   T1175]  ? trace_hardirqs_on+0x14/0x140
[   76.010458] [   T1175]  ? lockdep_hardirqs_on+0x88/0x130
[   76.010969] [   T1175]  ? kvm_sched_clock_read+0xd/0x20
[   76.011534] [   T1175]  ? sched_clock+0xc/0x30
[   76.011980] [   T1175]  ? sched_clock_cpu+0x65/0x5c0
[   76.012998] [   T1175]  ? __pfx_rcu_do_batch+0x10/0x10
[   76.014067] [   T1175]  ? lockdep_hardirqs_on+0x88/0x130
[   76.015102] [   T1175]  ? entry_SYSCALL_64_after_hwframe+0x76/0x7e
[   76.016316] [   T1175]  ? do_syscall_64+0x1d7/0x540
[   76.017297] [   T1175]  ? irqtime_account_irq+0xe4/0x330
[   76.018350] [   T1175]  ? lockdep_softirqs_on+0xc3/0x140
[   76.019355] [   T1175]  ? __irq_exit_rcu+0x126/0x240
[   76.020361] [   T1175]  ? handle_softirqs+0x6c5/0x790
[   76.021380] [   T1175]  ? __pfx_handle_softirqs+0x10/0x10
[   76.022421] [   T1175]  ? irqtime_account_irq+0x1a2/0x330
[   76.023426] [   T1175]  ? lockdep_hardirqs_on_prepare+0xce/0x1b0
[   76.024526] [   T1175]  ? irqentry_exit+0xe2/0x6a0
[   76.025475] [   T1175]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
[   76.026569] [   T1175] RIP: 0033:0x7f727d48df89
[   76.027485] [   T1175] Code: ff 31 c9 48 89 88 20 06 00 00 31 c0 87 07 8=
3 e8 01 7f 19 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 31 ff b8 3c 00 00 0=
0 0f 05 <eb> f5 89 95 74 ff ff ff e8 9a d0 ff ff 83 bd 74 ff ff ff 01 0f 85
[   76.030452] [   T1175] RSP: 002b:00007f72777fbd30 EFLAGS: 00000246 ORIG_=
RAX: 000000000000003c
[   76.031767] [   T1175] RAX: ffffffffffffffda RBX: 00007f72777fc6c0 RCX: =
00007f727d48df89
[   76.033032] [   T1175] RDX: 0000000000000000 RSI: 0000000000800000 RDI: =
0000000000000000
[   76.034377] [   T1175] RBP: 00007f72777fbdf0 R08: 00000000dd4d2955 R09: =
0000000000000000
[   76.035605] [   T1175] R10: 0000000000000008 R11: 0000000000000246 R12: =
00007f72777fc6c0
[   76.036884] [   T1175] R13: 00007ffd89867320 R14: 00007f72777fccdc R15: =
00007ffd89867427
[   76.038169] [   T1175]  </TASK>
[   76.038894] [   T1175] irq event stamp: 116
[   76.039771] [   T1175] hardirqs last  enabled at (115): [<ffffffff941114=
d4>] _raw_spin_unlock_irq+0x24/0x50
[   76.041167] [   T1175] hardirqs last disabled at (116): [<ffffffff941111=
e2>] _raw_spin_lock_irq+0x52/0x60
[   76.042569] [   T1175] softirqs last  enabled at (100): [<ffffffff9151ad=
c6>] __irq_exit_rcu+0x126/0x240
[   76.043945] [   T1175] softirqs last disabled at (63): [<ffffffff9151adc=
6>] __irq_exit_rcu+0x126/0x240
[   76.045320] [   T1175] ---[ end trace 0000000000000000 ]---
[   76.046319] [   T1175] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   76.047489] [   T1175] BUG: KASAN: use-after-free in sched_mm_cid_exit+0=
x27c/0x530
[   76.048669] [   T1175] Write of size 8 at addr ffff88813d558b90 by task =
cryptsetup/1175

[   76.050476] [   T1175] CPU: 3 UID: 0 PID: 1175 Comm: cryptsetup Tainted:=
 G        W           6.19.0+ #387 PREEMPT(voluntary)=20
[   76.050480] [   T1175] Tainted: [W]=3DWARN
[   76.050481] [   T1175] Hardware name: QEMU Standard PC (i440FX + PIIX, 1=
996), BIOS 1.16.3-4.fc42 04/01/2014
[   76.050483] [   T1175] Call Trace:
[   76.050484] [   T1175]  <TASK>
[   76.050486] [   T1175]  dump_stack_lvl+0x6a/0x90
[   76.050490] [   T1175]  ? sched_mm_cid_exit+0x27c/0x530
[   76.050492] [   T1175]  print_report+0x170/0x4f3
[   76.050495] [   T1175]  ? __virt_addr_valid+0x22e/0x4e0
[   76.050499] [   T1175]  ? sched_mm_cid_exit+0x27c/0x530
[   76.050501] [   T1175]  kasan_report+0xad/0x150
[   76.050506] [   T1175]  ? sched_mm_cid_exit+0x27c/0x530
[   76.050510] [   T1175]  kasan_check_range+0x115/0x1f0
[   76.050512] [   T1175]  sched_mm_cid_exit+0x27c/0x530
[   76.050515] [   T1175]  ? lockdep_hardirqs_on_prepare+0xce/0x1b0
[   76.050518] [   T1175]  do_exit+0x25e/0x24c0
[   76.050521] [   T1175]  ? __pfx___up_read+0x10/0x10
[   76.050524] [   T1175]  ? __pfx_do_exit+0x10/0x10
[   76.050526] [   T1175]  ? lock_release+0x1ab/0x2f0
[   76.050530] [   T1175]  __x64_sys_exit+0x3e/0x50
[   76.050533] [   T1175]  x64_sys_call+0x14fe/0x1500
[   76.050535] [   T1175]  do_syscall_64+0x95/0x540
[   76.050537] [   T1175]  ? __pfx_do_madvise+0x10/0x10
[   76.050541] [   T1175]  ? lockdep_hardirqs_on_prepare+0xce/0x1b0
[   76.050544] [   T1175]  ? trace_hardirqs_on+0x14/0x140
[   76.050546] [   T1175]  ? lockdep_hardirqs_on+0x88/0x130
[   76.050551] [   T1175]  ? kvm_sched_clock_read+0xd/0x20
[   76.050553] [   T1175]  ? sched_clock+0xc/0x30
[   76.050554] [   T1175]  ? sched_clock_cpu+0x65/0x5c0
[   76.050556] [   T1175]  ? __pfx_rcu_do_batch+0x10/0x10
[   76.050560] [   T1175]  ? lockdep_hardirqs_on+0x88/0x130
[   76.050562] [   T1175]  ? entry_SYSCALL_64_after_hwframe+0x76/0x7e
[   76.050564] [   T1175]  ? do_syscall_64+0x1d7/0x540
[   76.050567] [   T1175]  ? irqtime_account_irq+0xe4/0x330
[   76.050569] [   T1175]  ? lockdep_softirqs_on+0xc3/0x140
[   76.050571] [   T1175]  ? __irq_exit_rcu+0x126/0x240
[   76.050573] [   T1175]  ? handle_softirqs+0x6c5/0x790
[   76.050577] [   T1175]  ? __pfx_handle_softirqs+0x10/0x10
[   76.050579] [   T1175]  ? irqtime_account_irq+0x1a2/0x330
[   76.050582] [   T1175]  ? lockdep_hardirqs_on_prepare+0xce/0x1b0
[   76.050584] [   T1175]  ? irqentry_exit+0xe2/0x6a0
[   76.050587] [   T1175]  entry_SYSCALL_64_after_hwframe+0x76/0x7e
[   76.050589] [   T1175] RIP: 0033:0x7f727d48df89
[   76.050591] [   T1175] Code: ff 31 c9 48 89 88 20 06 00 00 31 c0 87 07 8=
3 e8 01 7f 19 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 31 ff b8 3c 00 00 0=
0 0f 05 <eb> f5 89 95 74 ff ff ff e8 9a d0 ff ff 83 bd 74 ff ff ff 01 0f 85
[   76.050593] [   T1175] RSP: 002b:00007f72777fbd30 EFLAGS: 00000246 ORIG_=
RAX: 000000000000003c
[   76.050596] [   T1175] RAX: ffffffffffffffda RBX: 00007f72777fc6c0 RCX: =
00007f727d48df89
[   76.050597] [   T1175] RDX: 0000000000000000 RSI: 0000000000800000 RDI: =
0000000000000000
[   76.050598] [   T1175] RBP: 00007f72777fbdf0 R08: 00000000dd4d2955 R09: =
0000000000000000
[   76.050600] [   T1175] R10: 0000000000000008 R11: 0000000000000246 R12: =
00007f72777fc6c0
[   76.050601] [   T1175] R13: 00007ffd89867320 R14: 00007f72777fccdc R15: =
00007ffd89867427
[   76.050606] [   T1175]  </TASK>

[   76.100141] [   T1175] The buggy address belongs to the physical page:
[   76.101101] [   T1175] page: refcount:0 mapcount:0 mapping:0000000000000=
000 index:0xffff88813d559100 pfn:0x13d558
[   76.102440] [   T1175] flags: 0x17ffffc0000000(node=3D0|zone=3D2|lastcpu=
pid=3D0x1fffff)
[   76.103496] [   T1175] raw: 0017ffffc0000000 ffffea0004edd808 ffffea0004=
f85008 0000000000000000
[   76.104692] [   T1175] raw: ffff88813d559100 0000000000070000 00000000ff=
ffffff 0000000000000000
[   76.105893] [   T1175] page dumped because: kasan: bad access detected

[   76.107458] [   T1175] Memory state around the buggy address:
[   76.108369] [   T1175]  ffff88813d558a80: ff ff ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
[   76.109509] [   T1175]  ffff88813d558b00: ff ff ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
[   76.110672] [   T1175] >ffff88813d558b80: ff ff ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
[   76.111823] [   T1175]                          ^
[   76.112661] [   T1175]  ffff88813d558c00: ff ff ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
[   76.113829] [   T1175]  ffff88813d558c80: ff ff ff ff ff ff ff ff ff ff =
ff ff ff ff ff ff
[   76.115000] [   T1175] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[   76.116174] [   T1175] Disabling lock debugging due to kernel taint
[   81.299309] [   T1577] device-mapper: zone: dm-0 using emulated zone app=
end
[   81.659065] [      C0] hrtimer: interrupt took 1305020 ns

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Ys8qWWC5JyE3z44%40shinmob.
