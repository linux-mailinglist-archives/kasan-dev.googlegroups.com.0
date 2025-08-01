Return-Path: <kasan-dev+bncBCD6ROMWZ4CBBS42WLCAMGQE5OE3KPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id D9151B17F96
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 11:47:57 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-313c3915345sf3298274a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 02:47:57 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1754041676; cv=pass;
        d=google.com; s=arc-20240605;
        b=AGQX9P7nlBjtnarP4c+35MKdN+l7l30we03uc07zgMxe1xb5ivhujHi+aKDa6dAnWS
         wrAa0M6Exods0xmEzQ367rHpcIOt468/u8pZ5XHEKu5ps9JaXIypco8f9dAF+iSM/74X
         N5RfX3dB2mP0TzfACsFxNzoVVeaWgyJC2H+ZYuiLnDx7uNkE+jdvk9UAbACrajvcq2w9
         OBHxnBogUJPDcOGE4iZJmtYBY6V+mRkVnq5M7cVgqF8w/mXQlOhTjBmCf0cgr2IdF64F
         Rh/YRPEMTM96jh18jv7znrijpgHsvpVkrn3bzkVk2I9omXk9HCXe41AbA+b7oOMa/2I1
         tquQ==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-disposition:references:message-id:subject:cc:to
         :from:date:authentication-results-original:sender:dkim-signature;
        bh=ykeDYfqgCJKqZXSwwC+HD4s7j1vHr776ppcWyWCMlZg=;
        fh=G6oVB5tZLyhbe8hWj4UF3KPyzYeu5tuoCWZuX32oZZI=;
        b=YGtFfh40XEKbyCCbm89DN/dnPbKN13/XuKIA3RoV23WBYVfTUKjHHmZQd03tNctNzi
         0f7IxySm7ulQ5azcZDonTg58DCXPDpAM9OCey2OK/oehD5KJNjgx1FC+lu1g2pY0WA6X
         nMkAAz2iOopulKHCMEq8p4bg4Jjt6aza/PUeBjO1RxN0E1t/ijV7yGokiGoVvYas6ZcG
         582fmA3VkH+WNRnuEyhMQXXRJEH158beqiigfSknk0hMIKaOCJaK5aUm5jhS+yogOh8k
         jSjoZe70o7UQQK5g1xTQW65zuqkElf8qe1mAicUs25U/ZGUqvX4q4Vidn5vvLU3nw/F3
         FK1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=a2RaJpEW;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=a2RaJpEW;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754041676; x=1754646476; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ykeDYfqgCJKqZXSwwC+HD4s7j1vHr776ppcWyWCMlZg=;
        b=g+FKKVfr95PfH9U841MhdI/VvnQkgrLo9tkQhOteG+GDuo3GrCIzq3BcqNvdQty1Zd
         Vjkgww4i9L0wCDsWWxx+UIdy2y6E7fl8oxYMHzA7DUjhUqthf37cmMfvRp5JmlJwWijm
         H1J7Pl+qbFUrgKGTk9vAqtl1GfVCBxHeUg1wbhEb+t11S3uRuGFzlxcg+bF6I0v+/DNP
         jjiWoJ6qIKbpZ7cyGA7fCgsm6FuJGOqM/d9zOcSKgdA7ocAHPcpnhkiF6J+8ylhljHj7
         i+rLUn2rqjkFXbcq7g5D+wnwdAFZAkAN2I5CHok63slsv9VMTZ2T8A3Rw8xR81/7Y1BB
         L7EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754041676; x=1754646476;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ykeDYfqgCJKqZXSwwC+HD4s7j1vHr776ppcWyWCMlZg=;
        b=Whc6w/8e5hDOOTKKE67eshUo8tW0IlqtEv7lU7iaxeM8MAUjPJNkF/Bd+uYc9zIXl8
         4L7ahgvhK1J/n+6lBnRe80AOzes1CNQ7GHSgvD4UJdAhi1zlCnPnviOkeJivr+Y6a9xs
         3Dbu0cU8nriz5/kNzO6mqA/KHkAFahHAo2jzysQIlf2BsRieaNZrKtj+N1PzVzJwRNLm
         G3CVSEldnX3HUFRlSEARH7HNMgBxp48I1LVTO5mKHq5PSLDJOuMub45cJmwXkz3DYB9l
         T+FjxhLPGb0fxm7v+UFAPx8MSJNZCESsVwZbSYQRpM+qzeRu1XiyRbdQ1n9+fsOP6qBx
         u5Iw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCU9cLxYHJbuzt1NxE5GELxrOC3MS4o4hz1phtuav4agiEBpXsQwQzB5cGei/1kRrvhne4IpBQ==@lfdr.de
X-Gm-Message-State: AOJu0YwVKKXRjwG3y5x6ZETR61JMuGRHqpR3kU+O6tg+lyO58J8tWFf5
	vdbvi38QjtTc9co/x0bE16CidNOXxWKw7mrVoXAF6SFszgTsd517k5k3
X-Google-Smtp-Source: AGHT+IHi6gGd4uo/HkFezPXNDp4Mc1LQrT8IAiDpd5AJWWeoSwk0MBYWR7y0exFm9o2qamSZy577Ng==
X-Received: by 2002:a17:90b:2f8f:b0:311:e8cc:4253 with SMTP id 98e67ed59e1d1-31f5dd8cdf5mr16481306a91.2.1754041675915;
        Fri, 01 Aug 2025 02:47:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcKmV4uF8L+YeTD9gdt/2djCdW2u7TN/y6IPU5GOtqoRg==
Received: by 2002:a17:90b:364a:b0:311:9c81:48ad with SMTP id
 98e67ed59e1d1-31f8abc2166ls1820247a91.0.-pod-prod-03-us; Fri, 01 Aug 2025
 02:47:53 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCW1+z5xttUPSkzCfvRdvP8B7SumOA0Te+dBIcAKoVqR+kebpX5J+GYFnof52FvMhSi0HKlWveUV6DU=@googlegroups.com
X-Received: by 2002:a17:90b:2f8f:b0:311:e8cc:4253 with SMTP id 98e67ed59e1d1-31f5dd8cdf5mr16481135a91.2.1754041673316;
        Fri, 01 Aug 2025 02:47:53 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1754041673; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jy1v4vc08NIjwJVy3/Ex5Nj15eVrZdQCYz+j/wwAGpyLA86SxCxe+R6agw6Yd0tc2+
         pkHl/frclgcZU+0fWeRndTlDGYi/WQ8D6mPJgvb3zb5imR2+O3mVjjJBiSNoNmUzj9BE
         8et80iVgGDphPQhj2Ltf64FQuOoYOo1J2Q8ISuq2Q7uW4vwIgoi5WcgjkfdcbNtNDMfM
         KXMSluD1EuZxljk+k/vvA9LJ6JIh8WfEUnzaEeRZZtArDCJr8ZXKBv6iT7p9OC3cxMj3
         tyhUtyOu3mxd07E8bnnEUGB0Mz//tibMACeF6XpYpE0PWxr+vcNJFtNryPgvkDXVjbzy
         cQSg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=jjs1yxxR1JT24VgoIX/HLRCKcXr0f8bQpi8KsdOMhpQ=;
        fh=fogSrtGw3HTrWuYyv7kjD0gNtPGZ7m0NHAQ/ZwFMMx0=;
        b=KbmHlXRsmEzyc/oCF07n9j/xD5L0mgduUpKKRMYhFun7BMGBpEqDIqKXCcxFDVmF+U
         wNtwJX/zBW1ltXjrynPmSpqAwoq2ITAZ4I0I07/QddAv++Q82DfQ/ihPKu5QaI2DOYsw
         jfW9Qsrahj2bBVnLfmw+ahQch8g9DIbOrSVGdRjw9QpBKNpsvf/gF7DQ/G1oLbAwlPh8
         MCgU/Q7lTxdEvM94RSjB66TrCfDTDhAhqMNFrIAEEphgsTTqWKg4/rB1jMxGZZUqVuew
         YzrWh11w2twQBrNst/TlNY/ctxLTTA8FooCnbYhFReEC0NZC84G0Wb2VfJDY58WtHWSe
         QpzQ==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=a2RaJpEW;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=a2RaJpEW;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from PA4PR04CU001.outbound.protection.outlook.com (mail-francecentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20a::7])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32102a56dbcsi13119a91.1.2025.08.01.02.47.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Aug 2025 02:47:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) client-ip=2a01:111:f403:c20a::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=GOFerXCa7vDk35vsboH49JTaQWF5UNnQZfzntxBHC59gHem8q1ztCDxA37axH7aSzhsL7fx9obaUcM1U39Tl57OHBEVfKGsuIy6/9jd2Z5OpDsJPufbgHeLqkyMhw6QFqS/mt6JJfnuFEa0vXzt0vPn6t+0DyhBdU44F+TSKUlAxDsAB3/Tuh3s/GHlHXFORzsVnGTGDRxaGIOzuvdmocOs09BEl3tmViSV4GLSUcxqMQK+FGM6E3NjoemOtNQL+jp5e8ad5QUA1QEgjC4KUb54pBT9u7LgEKpXgxgzNNT9T5Rp2yjbxOAa1LiJTAbzKzrYzL9RKGdjclWpGvj2J+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=jjs1yxxR1JT24VgoIX/HLRCKcXr0f8bQpi8KsdOMhpQ=;
 b=uoajT4ysTX15Dpk6IRxOTdjq4xThpTtnRKHwqQZ45mPlxRxI6sh+ouUhk1WpiEDAL6nrNJN1j9BvHUBwczLB7Y+J2XRmqwCJF7vSxu0ohV/3eFz0I07x6Vpy6ZXavqd7stILDuC6qtUeHTAp8ffLmWh/aPtMn6wby2xrvC/gPBiMajZDgzI1aoKWvIXvyj85bSDRvi60KimbGTZQEavxaZY6JfXjdZpV3XDhdxHoFEYKW8qx4jGT7FXLczALrJrxQm5KXVA7/tKRIInNYYo2u/HNJdUqDCzfC9aTZaA3cm7xH9yjk+1q+26NmFqVxxKdblsdDgkl/R0f8EbJzZAxJQ==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=linutronix.de smtp.mailfrom=arm.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=arm.com;
 dkim=pass (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DU7P251CA0010.EURP251.PROD.OUTLOOK.COM (2603:10a6:10:551::27)
 by AS8PR08MB9195.eurprd08.prod.outlook.com (2603:10a6:20b:57f::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8989.12; Fri, 1 Aug
 2025 09:47:49 +0000
Received: from DB1PEPF000509ED.eurprd03.prod.outlook.com
 (2603:10a6:10:551:cafe::a6) by DU7P251CA0010.outlook.office365.com
 (2603:10a6:10:551::27) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8989.16 via Frontend Transport; Fri,
 1 Aug 2025 09:47:49 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DB1PEPF000509ED.mail.protection.outlook.com (10.167.242.71) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9009.8
 via Frontend Transport; Fri, 1 Aug 2025 09:47:49 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=G/S+sMsIJH5WdaZ6AFS87BhTJNRbJ3DgKKiZiU28ugyIoSFBP2Ev6c7Q296sen+P2dXu495r2oSMM3Ks7rbniaCChz+r8aQ3lMeUQTFWVYkzoMYXBy6vj/AGbB9W0DlldJdNg58/Ai7yFgRgyfet7hjltS6jRSuMRT3nOI7m89Py3r2RYvKGjQm5m3kTYaEGaLSGhQLPCCWBSsfxBgcALmrJKX/GgXx8ZjekEQMVRzspw0v7nbWKYX5XnmN/1hREimfN7U9xI/m1ya5kSVkqm0RnXelmMrknO1bCvQt434RPdlH/K8MTutrD8zIEbCuoTUaI1+JOB7s3+PHlW0ZIVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=jjs1yxxR1JT24VgoIX/HLRCKcXr0f8bQpi8KsdOMhpQ=;
 b=TMq69DzUYmidNxq3JHJBF8X3WZU52uK1basnHQNcY39O/0keuHsg472FtQ1ibzGS0xWBCrVhqBzxa60DgT2FK2j1zPD1cZbNFx+EkRh3/++rec9/k/mEt1syn3WrQUisSZrbDjk8C32riBgCwuy1yx8d4Z6YLb5sgFbO+/LclGe2vZy9ZYqyElh3nGzVOqRc8l8YfeBRdZN9XDox+/dwc6QiZloZ9ShsKHWJ3mN2BP5rg+vFu9ymPakQJhW2Az1k86pozVPuOIRvp+SJR85yS3yFyOvF3JOGV0G02oiXYyY4nVnOAITao6xig2nI3unclnXyd4bwB55Y6W05F3seRA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by AM8PR08MB6385.eurprd08.prod.outlook.com
 (2603:10a6:20b:36a::22) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8964.26; Fri, 1 Aug
 2025 09:47:17 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.8989.013; Fri, 1 Aug 2025
 09:47:16 +0000
Date: Fri, 1 Aug 2025 10:47:13 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Thomas =?iso-8859-1?Q?Wei=DFschuh?= <thomas.weissschuh@linutronix.de>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kasan: disable kasan_strings() kunit test when
 CONFIG_FORTIFY_SOURCE enabled
Message-ID: <aIyNIdN5dHTgzzQP@e129823.arm.com>
References: <20250801092805.2602490-1-yeoreum.yun@arm.com>
 <20250801113228-5a2487e0-0d90-4828-88c7-be2e3c23ad3b@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250801113228-5a2487e0-0d90-4828-88c7-be2e3c23ad3b@linutronix.de>
X-ClientProxiedBy: LO4P265CA0132.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:2c6::13) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|AM8PR08MB6385:EE_|DB1PEPF000509ED:EE_|AS8PR08MB9195:EE_
X-MS-Office365-Filtering-Correlation-Id: ff662d9b-55fc-4567-0807-08ddd0e079ff
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|366016|376014|1800799024;
X-Microsoft-Antispam-Message-Info-Original: =?us-ascii?Q?BlRpSKwrLcnfX2DmNZ6eEaqW256gMI9qQsY69kV2YQgfj9YKVipgMi/VxwED?=
 =?us-ascii?Q?zW0goIT4tdPsBUaagzrkoWIyqQsx8lcbqxI5GSJFX1jSmheR7u731LcAMnN5?=
 =?us-ascii?Q?cRfqIhQK7UoU0YfbNj4FnkauKjxpkTdA6Eq3VX0QV2GkUj8A9GV9pjky8mxu?=
 =?us-ascii?Q?IwdkpWi/Mwziw4n1SyLEkFNg8DacfRXE1mCHkuvUBBlC8Syi7LktNCEIFzmu?=
 =?us-ascii?Q?l3D9NoFnIs1zAstx0K7aR6YWp3pXLsY9JUlBgSPJRqp2XjsURYAexwatZ4I9?=
 =?us-ascii?Q?BSfYVfQB9ygo7QOY2PSEOBPEcXbKCNT78Y4XZ8xYr4inDe1cBnIXlhNDw+6K?=
 =?us-ascii?Q?P4RdynjqrdzKeOdCGOtDUeVwBzuj8Ky3xvp/ilGu2um5SmTYtD6ut109tT1P?=
 =?us-ascii?Q?QN4/nYso0tHDcTZtM/PWyiKWX5hE56UbVrCqXyIhbzQgJq6lm5948Bg9ec4c?=
 =?us-ascii?Q?vo2CWINffWNL+VHqYTEHGtPqMCEOkWVM4VmCPIDJw95gd32GfJsGw+Ix0nhr?=
 =?us-ascii?Q?xnRKjFwvuQMQOMehXDEXH2lySn7JmIlO06mu3iK2bXLYJnkMYS4TDNZhFigo?=
 =?us-ascii?Q?mLqfg+TqDH195GY7v0bgPEBfaCMtz38d/a8frsO+lwmzvVeLrZgNoPrF3tnp?=
 =?us-ascii?Q?w3Yym7cMMt8UnaqAmzZyz/0Vims/zTeaepiekjxLvRasJDPKtsbdvRIEz81r?=
 =?us-ascii?Q?R7MMRx1AtxEJVj0whcEP5TMXkuR0J0kf3JUsBLhxgVewxLoQrIrhX6y58H/i?=
 =?us-ascii?Q?VkqVAYylrNecoJWMDHw9LV12IkUxJZ8MVii8qicMaPX8/83INI1NKpabXNXA?=
 =?us-ascii?Q?Io4vfRT8Rtb5Q1s+K537AVR0vCdXah3rk+aF6d+X9isuDK5gT2tHi2X05g1j?=
 =?us-ascii?Q?poSjZiJkMLFfZ1hJTG+7idhNimCW7gdy+3eCEQ98aGskF9d0P3bjornfbWkW?=
 =?us-ascii?Q?i1ApGRG4EhSXh4Q/i7HKEQsvbtUdsCdPBbgNntcJzUPcMjrYuCkevVcm3h4b?=
 =?us-ascii?Q?Nk5AhVw2jtgMrHGMRQVU9wUsV5qFM5YRYM5S+gDpNXW/h2SzEYiaRi4am+H2?=
 =?us-ascii?Q?X2r/7ysWsPFdS1x5MZ6fGXhImBSZT3R6DR1fCjctsgwBhms5bEFm+mhNSkxw?=
 =?us-ascii?Q?k4o5x0OhEoUycBGc2T8kirRK1eM1NFBxRO4ikP9j0Op66QUXouVxSbI3F8c0?=
 =?us-ascii?Q?FdtffqJTqgEvYlXhQEjDP3NfECBSGYCrZSxBpQcoQZsJgm0niQ6PQCrE+rPl?=
 =?us-ascii?Q?8aegVnI+vkCOGlHcJ69GxkSdDM5OLvOnQeN8CDA+CjhQYvpgZVyPz1C9CGLN?=
 =?us-ascii?Q?KD5f/HmoTs0jhEDU2+w7ywb6Z/xy5IGNC9f+lprXSIF7nd1ZLvhZuWeUtBEX?=
 =?us-ascii?Q?JeROzh1//GfT9iTgx9EAsKFDqjQTsG8vXdsx8Y6ylEMJl7yH+D5M8NhY6sxY?=
 =?us-ascii?Q?wCZsE1wtGLA=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(366016)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM8PR08MB6385
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB1PEPF000509ED.eurprd03.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: c4983e28-efae-4fb8-f600-08ddd0e065f3
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|1800799024|36860700013|376014|82310400026|14060799003;
X-Microsoft-Antispam-Message-Info: =?us-ascii?Q?tR78OOhimaY0VufK97Xta3YsND3ZehsYB2TMYtYuINMIby8owHgcSklCkWFI?=
 =?us-ascii?Q?vIkSPtLdoMxZzSOQ1q6/g+3LRrqxyDheAgefAGR38XmSNEgCBXMbl2d1fxfq?=
 =?us-ascii?Q?eGGp+zhhiyd31L4qHf2/omj5fEYFDeyj4e5uRGbW67B7JG3guYEy9qusNV4j?=
 =?us-ascii?Q?tSmvn8QBhtGIr4a9hdp+nAXuyy6swwY5XL4YZYwwHmiiAXvF4CQiqxoEu9i4?=
 =?us-ascii?Q?MKg3G9Z7gRM1xwk95I4UcbxdN0BZ3H7wwjLCdHrOQoWPCsUGzfh18ztk9r8z?=
 =?us-ascii?Q?AdykkPJtIFSinKji8UXOmANHTXHCNdMNGalCufYCnthb44Hgvg3xIU7U5luD?=
 =?us-ascii?Q?aujAyThhIAv+Eqykd4H7HuLsokSHabNy2jfc3YwgNHdLoar9MdKADuv9G7uy?=
 =?us-ascii?Q?74aYS8ix3/wGicHTfsPHsH5jBPBDXPBTgzKI58wQe44xLQ37KgsA/WdjkqsL?=
 =?us-ascii?Q?6aIC1UIMgPF8NGVle5GoRSkRTzeOBFbktTfvpAyPiFhnhl2bfj/ZaP2kg2nn?=
 =?us-ascii?Q?aRm9ANfrtsYd4pGcccvn1FaOcAZ4LSp/SbtLC67SN9jtau7L6tidU/Ed3KCk?=
 =?us-ascii?Q?V+QDHRBy+vjx6SJmGWPUpgce3oalgYFQrEONClre6dTQD3CVvKHnCoxcefts?=
 =?us-ascii?Q?6ZEGt4LM5b1noPk4n4pm5LrXbg71WD49wyYEQgEbPMCQHiMdcFK29ILdk1ob?=
 =?us-ascii?Q?ATQwNNyQccROb7IXaPh0Ep9fGfkswRgOdegCd1TS1s90iUJsQu2rg2dCLWFd?=
 =?us-ascii?Q?2Lw7yXYVJxAtJtx06ZbmG1AGnf8tV4MjLRmRPmiKMs1Ls7Y+dEJuw2ulDSez?=
 =?us-ascii?Q?58/Ya9r+O1Yw+JWeLnZPY8HTxYJeiZkvLBn5+J4mEuWLG3LFfAgHuF+wWyUK?=
 =?us-ascii?Q?0XOtbajQd9e0ktEKLd161YPXda06CBQy4fRff/lm+HfdPGyNzy4pc8g/ih2C?=
 =?us-ascii?Q?KTPJitG+hZh24ZFdUkD0PkEIQ/WAmyyH6TN4UtWZEbjTJmMysE7J+x0a5Air?=
 =?us-ascii?Q?mYcNyLvqrDKLP2Lsk2dHv1EZXZWSsDcl7BgVcGooNDRtbHl1L0/PvtgZCl9o?=
 =?us-ascii?Q?pcYqelgOvYytfpNk1gIE5xOD47Q0ROo7x9XNA02ZdJ8LVFf02EQ55eslDESM?=
 =?us-ascii?Q?+NWefozmUkGAw7Jdbanvjw5JsrUns5/V/tLHBoxfCDShG5An3hZN6kdoxNUm?=
 =?us-ascii?Q?fEbyEqhYw+21XiHk2Vo6ZKIEVUv28jSLDcyKAZx8HF+8LdjkDuzzQLOsBjGb?=
 =?us-ascii?Q?l4QjhLQKT5tBxPbT1ioQO73V9mCrO+ep864wWvJZ3WCom4eCoolDuAKBYHng?=
 =?us-ascii?Q?i87ZrFsiPJ+lfMpg/eZkSoH/b4c3XeOdzpx+H/+ASbIlRIcL9SpigJ8z3SMl?=
 =?us-ascii?Q?tOViRtVm23a5rYyinaPWJjikv/F+oK/3CYOGaahDzo+x+Hh3HXaaLlIbb2ds?=
 =?us-ascii?Q?y6NDASo6z0NMaAXO5u4qBdenwC/PQjz4zjTuFoI9QBslCUL5BAHC0aNUBm7b?=
 =?us-ascii?Q?xWX6oElx+Lu9KtisSDgYntJ/E2sto0lmyiNN?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(1800799024)(36860700013)(376014)(82310400026)(14060799003);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Aug 2025 09:47:49.3504
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: ff662d9b-55fc-4567-0807-08ddd0e079ff
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DB1PEPF000509ED.eurprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS8PR08MB9195
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=a2RaJpEW;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=a2RaJpEW;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender)
 smtp.mailfrom=YeoReum.Yun@arm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi,

> On Fri, Aug 01, 2025 at 10:28:05AM +0100, Yeoreum Yun wrote:
> > When CONFIG_FORTIFY_SOURCE is enabled, invalid access from source
> > triggers __fortify_panic() which kills running task.
> >
> > This makes failured of kasan_strings() kunit testcase since the
> > kunit-try-cacth kthread running kasan_string() dies before checking the
> > fault.
>
> "makes failured" sounds wrong. Maybe this?
>
> "This interferes with kasan_strings(), as CONFIG_FORTIFY_SOURCE will trigger
> and kill the test before KASAN can react."
>
> > To address this, add define for __NO_FORTIFY for kasan kunit test.
>
> "To address this" is superfluous. Maybe this?
> "Disable CONFIG_FORTIFY_SOURCE through __NO_FORTIFY for the kasan kunit test to
> remove the interference."

Sorry. I'll refine the commit message with your suggestion.
Thanks

>
> >
> > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> > ---
>
> Missing link and changelog to v1.

Right. I'll add

>
> >  mm/kasan/Makefile | 4 ++++
> >  1 file changed, 4 insertions(+)
> >
> > diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> > index dd93ae8a6beb..b70d76c167ca 100644
> > --- a/mm/kasan/Makefile
> > +++ b/mm/kasan/Makefile
> > @@ -44,6 +44,10 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
> >  CFLAGS_KASAN_TEST += -fno-builtin
> >  endif
> >
> > +ifdef CONFIG_FORTIFY_SOURCE
> > +CFLAGS_KASAN_TEST += -D__NO_FORTIFY
> > +endif
>
> The ifdef is unnecessary. If CONFIG_FORITY_SOURCE is not enabled, the define
> will be a no-op. This also matches other uses of __NO_FORTIFY.

Right. However, it would be good to specify a relationship between
the define and configuration.
So, some usage of __NO_FORTIFY in Makefile using this pattern
(i.e) arch/riscv.

If you don't mind, I remain as it is.

Am I missing something?

Thanks.

[...]
--
Sincerely,
Yeoreum Yun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aIyNIdN5dHTgzzQP%40e129823.arm.com.
