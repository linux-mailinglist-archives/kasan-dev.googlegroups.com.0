Return-Path: <kasan-dev+bncBDD3TG4G74HRBUF3WGCQMGQEGGNWXLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 204BB38F7FA
	for <lists+kasan-dev@lfdr.de>; Tue, 25 May 2021 04:15:46 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id b11-20020a17090a800bb029015d195273d9sf15195724pjn.9
        for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 19:15:46 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1621908944; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gf7h/gSzBVeODuCaAeNkwvXmf+keHw2DL+OJTRacU3Fau9ZqkrZvyKsnDfCOWPeJIv
         xrzKmN/Kr2j+06b8DhjZWdM5SG0PGsxJ4H7h30PdMErp3ZqLTo/njOU90WgPVRwirTlc
         bpTSKnpKCiXixyhVMGnuvc/kLdtLarj1x3HXtAzr+fz8v+P3kXhNAGSc4zq/0+/sP140
         3Yq4ENlLW16j1I5C8zkSgBgGvh+vu21CgZxR9ZvrOJA3tNg1zICbiDHWerMMaOGlJ0DU
         1W59GLjBWhLjbIvpIkvkrN0EvTX5A4YMOcY1wjRpsiwygkUu5RJUoET3CqvWHaXca392
         4v3A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:message-id:subject
         :cc:to:from:date:sender:dkim-signature;
        bh=juHb76BX3d8PPiqUb0GZwrLTHvmbV/pxJtxAYFqoA8Q=;
        b=tUBY6nc2DFDp4DpSYsHaN88UuarO/QIEY46EabW8+eRen8l28bGvsISIA8DQ5KZA1W
         +H9JpLA08jSVWg2ZrTrQCk9Ykfx726tX82HWhqASlyLD1t+EGPZBK04pRH+KKZ1cKWFV
         5ywZlDsRr7Clo9AeTwb9EgiCGO5SzSiEWlZzklUm4GYRqJC6ziotagK6Ih7I+5WzNaUI
         gLWDi5LlqXNwIEuPtGYjIPfI1lzZajaqlLPizWEGL3ptKue16GzDjM90KVDhY6Rc6qvT
         ycUt98duA0HHveFg57muXPiLWO6ieMiRc2kvuM5P+k5c3OQbX7J3LxFtQTx9oWW2S+gF
         4nSQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b="dGIYpE6/";
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.92.42 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=juHb76BX3d8PPiqUb0GZwrLTHvmbV/pxJtxAYFqoA8Q=;
        b=AKfuOtarfbeVKCOh4UheKWCTiMeu4aFwCDiD1i8hleZncxwwDCaqzNE2UONXXEsjKu
         ojkznHcKDCGdaYKxmpaq+fA/JCLvRzQTuLsVjbrCFyiJLL0apGqpnSC/CjZgz91xEQcy
         jYF2t2LdvU3rzn/RSW+jEQLb4Hc8FOuXu0qJj0TJgOou1qJ/8AYogPXq43QeEljO44lP
         mEeazlgfLfiuHZ4CVZylzusBxdZOMgCCXnrU2AmKT5z7SJCAhzlt+wyr85Jv0jmau2Kt
         PGmMsWePT0yl19B7eOY31ffgYRBwwIBPhHKl87OdRwMx+Q/DTAA0mBHdT88YfQqVmon7
         c2XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=juHb76BX3d8PPiqUb0GZwrLTHvmbV/pxJtxAYFqoA8Q=;
        b=YMliZpaxCgnz9Sf5OIQD9wSRROx8eRnNWIEAFC6W+eJcSkIZSfRPhfyw0umivaRE3J
         jcZvhbXEqwzJer2vY+q7mftku4947YBJOqJm8SKy22nkxKtBCgpk/ihLMhyCS9N2rz/J
         5g6pQFPJDn5/nl8ClEcE0UVHCYK6GRG9CQbDKS6emFL12aE6j/eOtJllRyPn7Znqx+/S
         4h+McXDiDWjDSDlh/ObDOZJVp1ZHOrMkZEZIhlaQfikLd8AvCbzebDC09rTq3znQnqT5
         KlsVOakL8yir9IELMPeIoO6FSka8t+FNOibzYDBrsBB2jx3GudloAsJQJWdCWj1e5Eyg
         MGBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cbnIF5LBC+gX4idqcO9VzJj1OTy0hIrbzDMEP2G19+kk9lGoV
	0POo1e1JCTPioqVDOU0Ler8=
X-Google-Smtp-Source: ABdhPJwG5PZ0wz6w4+fJO1b5n4emDYIg8ASRAVq66sUzyANEvTtQ6vDkGIsuZTURWAZXqiTbsXyG5g==
X-Received: by 2002:a17:902:e04f:b029:eb:66b0:6d08 with SMTP id x15-20020a170902e04fb02900eb66b06d08mr28399712plx.50.1621908944328;
        Mon, 24 May 2021 19:15:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5209:: with SMTP id g9ls5358238pfb.3.gmail; Mon, 24 May
 2021 19:15:43 -0700 (PDT)
X-Received: by 2002:a65:6849:: with SMTP id q9mr16410562pgt.377.1621908943702;
        Mon, 24 May 2021 19:15:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621908943; cv=pass;
        d=google.com; s=arc-20160816;
        b=oYjcJkBXAcLI+7Xdkw4yAv6HXSJkhNz7ZpZQSmCZ6nGjNuy359KxXWfTPBrN3CSWEx
         OU4pl5VWb4P8jMj8dJ2Iy6O11noaYI4bcf7XO4k+c/yv2QdpXqche6hJ+/7qgLeJ6Uw4
         6VfAuQ+8eW282sqqkXZnaoPkI5/pK2zDVbOLitngVfsW7YbpRHqXmd20ao5HiFXdTjXi
         KeVYMZKCWALQbe4asIMHemiTE5ZPsxLGw/ZcDFzdcI/DSr3bMd4qDWI44PbrF9J4roDg
         ly7z9yz/wOlmeoPGSDO7PrxWd/AgkpZD/0c8X891I9jvEQCfZIY5JLJMDdim3qy6gB3P
         R90g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=OqqF+n+11qDDy72k7ENFhqnzOGZxQVziq1p3+y0CQQU=;
        b=yT/uhH5poE9kwhgOGjHsxQAqcYXIffPCP9KxcfkgKRv3u9kZU6yya9jWjEhYoafDNw
         19q8ZQC8H2PmKwyNY3OgzspKtd3oGi0uigSOVJoOQIsQDzdoKAH/9ROzGqf7EYNbNy25
         /dWBmAuqmSSubDOK8woPPCm6k8qMa3YdIbR1GWuQjH4nVEtQf1AsAkXstihLBmZHzx3W
         q2HhkEnUPLU4qkTGx21Svt4zHj9DBSp+qalU5+NLnnunaiYgybRS4/A/y6RzY1faLi5/
         juUcf26YU7V3gc/JhrJpLqveG/Jb8V9iRiabKhjzNG2mNpRp4B4jjS43N+w2qRs/epjD
         bkWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b="dGIYpE6/";
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.92.42 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
Received: from NAM10-BN7-obe.outbound.protection.outlook.com (mail-bn7nam10on2042.outbound.protection.outlook.com. [40.107.92.42])
        by gmr-mx.google.com with ESMTPS id a6si1974266pgk.0.2021.05.24.19.15.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 May 2021 19:15:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.92.42 as permitted sender) client-ip=40.107.92.42;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=ZKobQDw/RpTDt0j2ENYF1M3yU2ehIMrofhwnA4Tvdb2V+uNKN6M8htPAvJmb0WyJEQctJQvwmnypS4Jw4Ybt4sGATwgsgRACML3+rY8WindNYpIyaX2vKnavK1rWBNKyj8kPTDvq93pOp7T0zb2187ww6bsfOfy283NxTcvmGZXDp8QpQ1VaJz8pKRS6ko1SmnL2KOZ8GOr74fBFBVweAPJZkS+sXo8iBjwK/wxqmBPX8YUT4ujMN63PP9lvEmXov9vid3PkQdXcgsfdn1tahRjYohmQi/sO4oLsh/xDbkp65HOna23goiKO+tMLMCx/EySUepB0AmCAJsz4/eSXuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=OqqF+n+11qDDy72k7ENFhqnzOGZxQVziq1p3+y0CQQU=;
 b=lpBqq4/8tFdEgyG+R5jFKtBVdcZfllFirKk9eZrJby5ArrbvW67i7Ggxk4deJ25Tbh5YBxt8Y/SHd6AhCRlTRNHPpCSN23aE9GfGQ5sWD7Pjt5MSevUjkBxJWSCP9OWG0G85Gg6Yobu8KAVvPlTvjQlqcP7D0kWrpJhRJXitoH3u+GU+i74ZUsVvzwr7U/OFi1K4bxYBrdsBlJREk69sr0aIoLIj27mjfVvCpxYFR2GmEEFYpt0KXUvXKRC8mNL9vXU53zrlwJyLQdZKas0RPXysCLsLPS1nMOAIEvHxeFkVqACq4x+QR+DgEtuHY2YIEnXB45QYfTD9/gEh6R9Bmw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=synaptics.com; dmarc=pass action=none
 header.from=synaptics.com; dkim=pass header.d=synaptics.com; arc=none
Received: from BN9PR03MB6058.namprd03.prod.outlook.com (2603:10b6:408:137::15)
 by BN7PR03MB4452.namprd03.prod.outlook.com (2603:10b6:408:37::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.27; Tue, 25 May
 2021 02:15:40 +0000
Received: from BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791]) by BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791%4]) with mapi id 15.20.4150.027; Tue, 25 May 2021
 02:15:40 +0000
Date: Tue, 25 May 2021 10:15:30 +0800
From: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
To: Ard Biesheuvel <ardb@kernel.org>, Marco Elver <elver@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Andrew Morton <akpm@linux-foundation.org>, Mark Rutland
 <mark.rutland@arm.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev
 <kasan-dev@googlegroups.com>, Linux Memory Management List
 <linux-mm@kvack.org>
Subject: Re: [PATCH 2/2] arm64: remove page granularity limitation from
 KFENCE
Message-ID: <20210525101530.7e7b1f6c@xhacker.debian>
In-Reply-To: <CAMj1kXGtguQ=rG4wM2=xXaDLBvN3+w7DRFeCGCeVabTGLinPuQ@mail.gmail.com>
References: <20210524172433.015b3b6b@xhacker.debian>
	<20210524172606.08dac28d@xhacker.debian>
	<CANpmjNNuaYneLb3ScSwF=o0DnECBt4NRkBZJuwRqBrOKnTGPbA@mail.gmail.com>
	<CAMj1kXGtguQ=rG4wM2=xXaDLBvN3+w7DRFeCGCeVabTGLinPuQ@mail.gmail.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [192.147.44.204]
X-ClientProxiedBy: SJ0PR03CA0222.namprd03.prod.outlook.com
 (2603:10b6:a03:39f::17) To BN9PR03MB6058.namprd03.prod.outlook.com
 (2603:10b6:408:137::15)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from xhacker.debian (192.147.44.204) by SJ0PR03CA0222.namprd03.prod.outlook.com (2603:10b6:a03:39f::17) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.23 via Frontend Transport; Tue, 25 May 2021 02:15:37 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 515e258f-3da1-45fd-946a-08d91f22fe68
X-MS-TrafficTypeDiagnostic: BN7PR03MB4452:
X-Microsoft-Antispam-PRVS: <BN7PR03MB4452C59F831D2739C53ABB78ED259@BN7PR03MB4452.namprd03.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:3276;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: zviMw5jEdEdVoz8yZ2arhAEuLxIRvb2J6BRMeu5DMgqmd5G1NSeuVTD5+RqEC+aiPCOmSOpRWFSF0LWjDDt/av5b54PoL7sY6JSHr/xqsRXAND/qaHwOivNgJ2VjvkJBM0rvHYQlvlfg0OJFs+LAfX03PznlgW+kL7ThZVaeX1Hnxd97nHXcr0aHPQBoJ+cvcDhlahakAyHUArreMMQb/klBFFItTCoRhpguWlnGWrqv+tzwMWMv11bxXY/ipvnW6Hp0OUmykJ3q/QIDL2PwKYC8L2LAfQPUVWfw+oLIRGDGlbhe5ThlkhCA7c3uSKT881r7OkI732jOOTX/YxmtkWpBIquzv6P9ozyhTN+W4U44HWMxgSrS46TXE9Sg/+90BjO3vtZLzsO9GNVII/+LNC/quu9gkH/Cy2TzcP1b9UOciqPKuDqmYT8qIJNt4eTf1JUoCS3cNuBFX8O7/xF+fBx+OnjCxxiAF6+U/OMhm50Z2zgN3OuhuCsFX8/vOJJgTZHoudRxwY2UDI+AzzEdxD22vA61g9cC30k/fWkzHmbXPYs2P0SQoisk8npXqHUdaNCJgGFzHHsHi/GFbp+PCXk/g0Ve6iQb+ow80SkZn2ysaMYdUuRudYDM+0qraKrilFbDZ9MziMibOBeKEbcN3Z3pU4ZZVTVEKn8se2456wcKF1orDcTZ0SCr6OX9Xk792z2W2+CVTHW6ZYYRfRdavjeDHfkygkowXycLWNhuBpNLUIGCxM5MuSQ2UuClPVPcAIp4gpo9uMpwSZmwPjh94A==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN9PR03MB6058.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(396003)(136003)(376002)(346002)(366004)(39850400004)(6506007)(7416002)(52116002)(83380400001)(1076003)(66556008)(478600001)(66476007)(66946007)(26005)(6666004)(9686003)(7696005)(110136005)(54906003)(2906002)(316002)(966005)(5660300002)(4326008)(8676002)(38100700002)(86362001)(956004)(16526019)(8936002)(186003)(38350700002)(55016002);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?us-ascii?Q?iS/p+j6CaoGKcTmVO1Uez8ZbQwUIGuTJTCOn3wz1x/DjcR46KjrTcWLryP3Y?=
 =?us-ascii?Q?AgUFosk2WIZO5LTxoB6hm1v3vELokznP/pxZoMy4JvkKFWGycO7FqCngQ579?=
 =?us-ascii?Q?1X4OyIHqdyxzBzCdKW9HjPy9eMLbbihE5X/9iz1reQUkc29gw/U4140+yti9?=
 =?us-ascii?Q?8uOeOTVBE7QBg1qWwdY7cobEKmpM2wuVgxFvCzAi02ODVtzVUmhlt2uXbMjT?=
 =?us-ascii?Q?X58U9l2aQk6wKQ6uOdfYq4ot7w4fMaKOxMByLoWW1Y2Uq59teVMFi/A5JhQM?=
 =?us-ascii?Q?tIQAkzduA1XOpljTQSelsU9bsAZaSybtQiEVmCQ8b+WO/tvQwsaoeWVEtYcf?=
 =?us-ascii?Q?QdDIo/9fXjBFC/3yuvnXRCiDeuO6Y3qQtsVNXKd4YTqlh+miL5Zf001TJms2?=
 =?us-ascii?Q?B1E7UAiNAhHp0BiNQO78CnRrrHXz2GJox6cuReNv1tcaYoCCTQNLg+qYgXt2?=
 =?us-ascii?Q?i67msQw5oaJgJM8wqKnzkGDyU9r3CbcgjCW3VWNtBrJnDExtcXv5+SBlNsYS?=
 =?us-ascii?Q?44JjymdQf2+0b/j01Gm0YyLbGfxtIbq0ZHcaWbmxYAGr4mjplgUgnhzm+AAn?=
 =?us-ascii?Q?28jAoEaUITe0QMW5HWxyNzz6Hu9xydD2Wsvq7Qk3SCXyKw1j9aK2Wsu452z0?=
 =?us-ascii?Q?VqR8lliE8NKhgCFbEPEFlAwNXQx+9hoShQ3SKfvIfoko+NlMieJEDBoUWFLC?=
 =?us-ascii?Q?dWu6d+e2SCVpr4nfUxwXZrhG+FkZgjo8SgkYkK8HAKsG/d+mvAEo+55cqpEP?=
 =?us-ascii?Q?uJ/Nvp+eLO3YWH4K2i5K36xr/tqglhB8B5wWWIUXlkoCCCL+RUydNklA9KW3?=
 =?us-ascii?Q?dxn9ubGrKcndwrBQ40GJuOpIy5EdcwwUMgnQ3vtNEzfiYambcU/4QEbCWvLp?=
 =?us-ascii?Q?ibfw/tLGBdpQHvDMhLoq2+k/6xkiiDarf6/D19ZXCPa4hbEm2teJRU2Gcspk?=
 =?us-ascii?Q?d5ZRWnsHD6l02pphS7lbruf4pvCYI3UQiJvbf6gCeYWIqy4dvvpSMq4UOL32?=
 =?us-ascii?Q?9OELBz06jjwpU608HmSx4fEnnwIsCnOxF2k5txJr6vqGTPAR2bPQW5iIUpeT?=
 =?us-ascii?Q?du5i9sP3ucBQyRXNVicN904nn2eeNkRv4zJv1jvtjhTVspcaF0SamSeR46M6?=
 =?us-ascii?Q?twE00SIPcL7yxd2ST5STF9inaB74Ex447GPURiJYfzJ1o18pi2VOfVXBEAVR?=
 =?us-ascii?Q?70pDER6QabSUWoLvwEpQ7g3dpY1rABfxeaUfhJ7fgu26l7ICXVWDuBTW4r6p?=
 =?us-ascii?Q?mkhdrQ5yJv5gSanY3JhQqmRzSXhM6drDC4fp053wVfeDlBArSF0VJ1lFU7c0?=
 =?us-ascii?Q?E1PZlm1tkstux9SCzdsjjky7?=
X-OriginatorOrg: synaptics.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 515e258f-3da1-45fd-946a-08d91f22fe68
X-MS-Exchange-CrossTenant-AuthSource: BN9PR03MB6058.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 25 May 2021 02:15:40.8087
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335d1fbc-2124-4173-9863-17e7051a2a0e
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: SW+HA/6VA4ROoTGovVdaZ+5YWB888K2uyWI4uZti5TIZaQJU3d0b+LQ7CTYDf5sEQoNBg/lNAAUsaVJCTB/ngw==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN7PR03MB4452
X-Original-Sender: Jisheng.Zhang@synaptics.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com
 header.b="dGIYpE6/";       arc=pass (i=1 spf=pass spfdomain=synaptics.com
 dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates
 40.107.92.42 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
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

On Mon, 24 May 2021 20:04:53 +0200
Ard Biesheuvel <ardb@kernel.org> wrote:


>=20
>=20
> On Mon, 24 May 2021 at 19:31, Marco Elver <elver@google.com> wrote:
> >
> > +Cc Mark
> >
> > On Mon, 24 May 2021 at 11:26, Jisheng Zhang <Jisheng.Zhang@synaptics.co=
m> wrote: =20
> > >
> > > KFENCE requires linear map to be mapped at page granularity, so that
> > > it is possible to protect/unprotect single pages in the KFENCE pool.
> > > Currently if KFENCE is enabled, arm64 maps all pages at page
> > > granularity, it seems overkilled. In fact, we only need to map the
> > > pages in KFENCE pool itself at page granularity. We acchieve this goa=
l
> > > by allocating KFENCE pool before paging_init() so we know the KFENCE
> > > pool address, then we take care to map the pool at page granularity
> > > during map_mem().
> > >
> > > Signed-off-by: Jisheng Zhang <Jisheng.Zhang@synaptics.com> =20
>=20
> Could you please share some performance numbers that result from this
> optimization?

I didn't have performance numbers so far, in fact I even didn't find a suit=
able
benchmark tool to show the gain numbers. IMHO the performance gain comes fr=
om
two aspects: the efficient use of TLB entries and the depth of page table w=
alk
when TLB missing. IOW, the performance benchmark tool used to demonstrate t=
he
optimization of arm64 block and cont support can be used here too. Would yo=
u
please give some clues?

>=20
> (There are other reasons why we may need to map the linear region down
> to pages unconditionally in the future, so it would be good to have
> some solid numbers about the potential impact of doing so)

I suppose this feature is similar as RODATA_FULL which can be disabled if
not used. Take the RODATA_FULL for example, it can be disabled if all
modules/drivers are builtin, there's no secure side affect too.

This series tries to keep block mappings or contiguous hints as much as
possible. In fact, as for KFENCE, it's achievable.

PS: Searching the KFENCE patches history, arm64 experts said there's no
safe way to break block mapping into page mapping on arm64, I suppose this
is true during system running. I'm not sure whether "no safe way" conclusio=
n
still applies to kernel initialization or not. Maybe for arm64 KFENCE case,
it's safe to break block mapping as x86 platform does?


Thanks in advance


>=20
>=20
> > > ---
> > >  arch/arm64/kernel/setup.c |  3 +++
> > >  arch/arm64/mm/mmu.c       | 27 +++++++++++++++++++--------
> > >  2 files changed, 22 insertions(+), 8 deletions(-)
> > >
> > > diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
> > > index 61845c0821d9..51c0d6e8b67b 100644
> > > --- a/arch/arm64/kernel/setup.c
> > > +++ b/arch/arm64/kernel/setup.c
> > > @@ -18,6 +18,7 @@
> > >  #include <linux/screen_info.h>
> > >  #include <linux/init.h>
> > >  #include <linux/kexec.h>
> > > +#include <linux/kfence.h>
> > >  #include <linux/root_dev.h>
> > >  #include <linux/cpu.h>
> > >  #include <linux/interrupt.h>
> > > @@ -345,6 +346,8 @@ void __init __no_sanitize_address setup_arch(char=
 **cmdline_p)
> > >
> > >         arm64_memblock_init();
> > >
> > > +       kfence_alloc_pool();
> > > +
> > >         paging_init();
> > >
> > >         acpi_table_upgrade();
> > > diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
> > > index 89b66ef43a0f..12712d31a054 100644
> > > --- a/arch/arm64/mm/mmu.c
> > > +++ b/arch/arm64/mm/mmu.c
> > > @@ -13,6 +13,7 @@
> > >  #include <linux/init.h>
> > >  #include <linux/ioport.h>
> > >  #include <linux/kexec.h>
> > > +#include <linux/kfence.h>
> > >  #include <linux/libfdt.h>
> > >  #include <linux/mman.h>
> > >  #include <linux/nodemask.h>
> > > @@ -515,10 +516,16 @@ static void __init map_mem(pgd_t *pgdp)
> > >          */
> > >         BUILD_BUG_ON(pgd_index(direct_map_end - 1) =3D=3D pgd_index(d=
irect_map_end));
> > >
> > > -       if (rodata_full || crash_mem_map || debug_pagealloc_enabled()=
 ||
> > > -           IS_ENABLED(CONFIG_KFENCE))
> > > +       if (rodata_full || crash_mem_map || debug_pagealloc_enabled()=
)
> > >                 flags |=3D NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
> > >
> > > +       /*
> > > +        * KFENCE requires linear map to be mapped at page granularit=
y, so
> > > +        * temporarily skip mapping for __kfence_pool in the followin=
g
> > > +        * for-loop
> > > +        */
> > > +       memblock_mark_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> > > + =20
> >
> > Did you build this with CONFIG_KFENCE unset? I don't think it builds.
> > =20
> > >         /*
> > >          * Take care not to create a writable alias for the
> > >          * read-only text and rodata sections of the kernel image.
> > > @@ -553,6 +560,15 @@ static void __init map_mem(pgd_t *pgdp)
> > >         __map_memblock(pgdp, kernel_start, kernel_end,
> > >                        PAGE_KERNEL, NO_CONT_MAPPINGS);
> > >         memblock_clear_nomap(kernel_start, kernel_end - kernel_start)=
;
> > > +
> > > +       /*
> > > +        * Map the __kfence_pool at page granularity now.
> > > +        */
> > > +       __map_memblock(pgdp, __pa(__kfence_pool),
> > > +                      __pa(__kfence_pool + KFENCE_POOL_SIZE),
> > > +                      pgprot_tagged(PAGE_KERNEL),
> > > +                      NO_EXEC_MAPPINGS | NO_BLOCK_MAPPINGS | NO_CONT=
_MAPPINGS);
> > > +       memblock_clear_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> > >  }
> > >
> > >  void mark_rodata_ro(void)
> > > @@ -1480,12 +1496,7 @@ int arch_add_memory(int nid, u64 start, u64 si=
ze,
> > >
> > >         VM_BUG_ON(!mhp_range_allowed(start, size, true));
> > >
> > > -       /*
> > > -        * KFENCE requires linear map to be mapped at page granularit=
y, so that
> > > -        * it is possible to protect/unprotect single pages in the KF=
ENCE pool.
> > > -        */
> > > -       if (rodata_full || debug_pagealloc_enabled() ||
> > > -           IS_ENABLED(CONFIG_KFENCE))
> > > +       if (rodata_full || debug_pagealloc_enabled())
> > >                 flags |=3D NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
> > >
> > >         __create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(st=
art),
> > > --
> > > 2.31.0
> > >
> > > --
> > > You received this message because you are subscribed to the Google Gr=
oups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, sen=
d an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://urldefense.proofpoin=
t.com/v2/url?u=3Dhttps-3A__groups.google.com_d_msgid_kasan-2Ddev_2021052417=
2606.08dac28d-2540xhacker.debian&d=3DDwIBaQ&c=3D7dfBJ8cXbWjhc0BhImu8wQ&r=3D=
wlaKTGoVCDxOzHc2QUzpzGEf9oY3eidXlAe3OF1omvo&m=3DtRid6vgpMdeQY77uEe7j0LTyjaW=
0r0d36StAfCnvb0A&s=3DtcnSvCZSGJgJk-0AOpFpY1Aaiq27DeGLpguxNv2M9yE&e=3D . =20
> >
> > _______________________________________________
> > linux-arm-kernel mailing list
> > linux-arm-kernel@lists.infradead.org
> > https://urldefense.proofpoint.com/v2/url?u=3Dhttp-3A__lists.infradead.o=
rg_mailman_listinfo_linux-2Darm-2Dkernel&d=3DDwIBaQ&c=3D7dfBJ8cXbWjhc0BhImu=
8wQ&r=3DwlaKTGoVCDxOzHc2QUzpzGEf9oY3eidXlAe3OF1omvo&m=3DtRid6vgpMdeQY77uEe7=
j0LTyjaW0r0d36StAfCnvb0A&s=3DyI-AmsxRY2eoRcsCUfVwogWd3PeVgXO2-3bc6juyiXw&e=
=3D =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210525101530.7e7b1f6c%40xhacker.debian.
