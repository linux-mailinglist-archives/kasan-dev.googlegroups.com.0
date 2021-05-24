Return-Path: <kasan-dev+bncBDD3TG4G74HRBVHCVWCQMGQEMCE4G6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id AF5F138E34E
	for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 11:26:45 +0200 (CEST)
Received: by mail-vk1-xa3a.google.com with SMTP id a28-20020a056122013cb02901eb816f5778sf4695791vko.10
        for <lists+kasan-dev@lfdr.de>; Mon, 24 May 2021 02:26:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1621848404; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ibh4rvSjOTfjM/GpFu2QDw0WZRITCOtr8tEvwS8AK+Wdshr3x70vI/T2bl8UdMPnmn
         XcFmXgqAOZ6WYD/9PC3uK4hvfqDUAMXVbMmdlYwvTNRl6soKXe4HzXglNLaM2QNeY6bs
         PHLatGKICClP8/sL7TpfcV/pcj57tqS5JiPyqvGyNg3RFi4bNFu6Key8wg4F5L8RG1Ew
         O6q7oJDaJ0Iqa4FW1vF4rP4gLkBXiributsvjXC40fjZVGCAtdeuGXiTGBNxSZHxaio2
         v/YT3mIKHdht8I9fVsJKG86EIQGXLU2ZHUhCknMlzdlqcwR0fukNfOZQCgGqL4d7f3lG
         5J3w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0akY4DUs3Qv23xO33PfMgyIOKv5veUmq2JBq7Scv2kc=;
        b=iAGSIeNzuYAjvbKLv6iVmldEdbkWxcVuiJl9cbN9XOpLwObR/jm/kQKLCqfcnJxEmP
         B5GUnhwRfXHEL3HXx2I1DLlNIwfR54JX1PJiil7KpRJBgdrTLMB8Rq5LNN0Jovme1dmh
         jkk17fr4ZS5G7p1sMUNd9ALCsY3R6BpGl5/m25Khnonu2yujgiHLLdSPBy4AxEVJ/yzY
         OJu3IsFQrJkRVNeBXJw9iybKnuX9+A3yVs8iOhkkzbSDLuaKSAHPgqtILTMJ0d7V2jzg
         Rya1V+xn0MeYcEo9S5QYSeiuX1cfuxpK4qQ5iioN1DibD/JOI8CnBWD0T8Mwl/l2V6aj
         jqnQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=ir50RisU;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.94.60 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0akY4DUs3Qv23xO33PfMgyIOKv5veUmq2JBq7Scv2kc=;
        b=qkvE1INQVLlyLTg8vQ44iprNw4Vtd6J/uPkB/M5tZZgTm59YcrzXbJqdosEcgJ64Mp
         InPBK+ddmqj9GNTzERHJSKD5bfOgHY0YF9F7f7WgGCV98pnvSlu+rwkXkh9K+lbN8HLG
         p59Xjnk2ZELJ/pD1zRyGDUp3DVp/324KAog8zzbiM7bDQ6aTGGU2J1hHG0nuXOe9m6kX
         /SbY1Q0uyiwtVn71e0FvU3/eDbxXY0GnHe9D062OM9XBhthuAQokDo6tr9NcP36tGqAN
         87PnpWwOvpoLwjy8NzpaqCxw5EITIn4XCIHh/JSN9zavJI1079/LnenORum2ppT25Wxe
         GB6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0akY4DUs3Qv23xO33PfMgyIOKv5veUmq2JBq7Scv2kc=;
        b=e3DITUR75vFhPjvNOyvTRzqzgncccC6me/OQgccIIj1FYHQo4MKCrNhkWNheI0dcxV
         I8G00t7Iv/P08DuA5YA3+qjw3SmThB/8hJs+0GZajXM0DcuiQGp2JXF5qNSjUtIVa82g
         V30nhuOiBBA+OqVvlYlopvQmZrIlsVOMs+FxGZ9QdlxxfSvOayBTKrj+XE4MMqvZVtzj
         M9zgYAMQe3QWUMwndNqQV0DtpXfvpZtM3re4FHOq6jFQqt6yLzbqpLEi/1qJ60Igq96n
         XHGIw70v6l3Sdspz9FczY5RRd28siU0SMznYLOZhq1OsKNoBL5gXiIlK9mBe+CcePacj
         +nzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327xgtGY3KbVgZUl5GoImwLpCnSsApw4kEBZB46qBZ+4OJhvTL/
	J20dby5g54MLo+Ssknxt5bU=
X-Google-Smtp-Source: ABdhPJw1T2Q6cB535APst9k45vaGNSv3RzZtdPYBk2D5Ni4tyvMvOp2Ue0lUoGJhO5cG863OazlrGw==
X-Received: by 2002:a67:fb94:: with SMTP id n20mr21928393vsr.11.1621848404816;
        Mon, 24 May 2021 02:26:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:21c9:: with SMTP id r9ls2385623vsg.2.gmail; Mon, 24
 May 2021 02:26:44 -0700 (PDT)
X-Received: by 2002:a67:f9cc:: with SMTP id c12mr17992798vsq.27.1621848404390;
        Mon, 24 May 2021 02:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621848404; cv=pass;
        d=google.com; s=arc-20160816;
        b=hjoOVRJquvrOtuUCTiwRnzz7wjVMXOxtqBkCC2XDndTsIoLqL/hbgKxASTKOX9jsk0
         g/Lh9BZP0Z8+Qo3gfrXVwFgrb7bQKv4GK5yTMtSLEFOhPsg9E3CQezFNfqAxS8cf5oO8
         /gDh9aEWfbOUbKYUeXSit3GNAk2xaVsQObosHWA45YOPDY0iE3m+dG+A3qYvGqFllQZP
         Rm/VYKzVxU9ulz7s3p8QGz0q9yzn+BQ/O0zguyQRvhdM4B/NZ8MGPrAHXAtP4nv3h4CU
         r9W6LvS7VPm/k6Hbsmel8QAsprVlO9ActnTRkASwI0tWH0Ug+lY/sxmHK7lz1bpJtAo5
         sO5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=yg7gEh75KCSRWy7ZOkeyvERqafWSItL3pI+nkwcPGtA=;
        b=Vyhn4lkvnOKO1Xo68z90bN/kHUQXwzHdQgbh6m12xYR/lX1ezfd+Km5xJ/bed/q9oo
         9Slc3Z3ROu0ZbNtR//yXW4327Q+GZZaiWbpwsuRR19U3gfk6L3NmFI7QiH3kSjKzBDos
         +wrZVjfS3Q14RV4AOYMxAa+IP382cH2Hbp11iamUiC8mWgpzY/k1DBmPc6zRnr7cc2hy
         PCpeSlbpQ3jqBv83E4qmcAvi/V/U8lnU46tDNpqDTGbqigdLhQOl80oyS9LSO1KKW4LR
         qXj4l7IwiCiq0KnYaVKIo2j7zvVh5+IFX7ZBZ8Ss5tF27eSh7MIrWM9LpsZ8v+tJmwZQ
         WwRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com header.b=ir50RisU;
       arc=pass (i=1 spf=pass spfdomain=synaptics.com dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.94.60 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=synaptics.com
Received: from NAM10-MW2-obe.outbound.protection.outlook.com (mail-mw2nam10on2060.outbound.protection.outlook.com. [40.107.94.60])
        by gmr-mx.google.com with ESMTPS id p6si1109644vkm.2.2021.05.24.02.26.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 May 2021 02:26:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of jisheng.zhang@synaptics.com designates 40.107.94.60 as permitted sender) client-ip=40.107.94.60;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=nX39UVXdJCf7e9SDYY3SnExtNZTlM/qhrjJhzV9M7522IO18MokMRrWAkybuRB+siXvnhw2DPp8w+b4LmHdDKw5uoteZVEx0S6/ZgbnICghrRwM50nrluWHyPFmrHwXWwQ11GykanDAkK4fGz3N1CPqSllPjCVMH3k+4n9WMhvtIqwE/tB9Iely3Wi11/S/y9QX7e1UTMXkFEiyCGGT/RTzzI2G/IFCtz0AySYIR8LdP1p4RbooBxoZLqSmSinIhnFbDGG3gEPNi89Yhw4XhcU/HyUELiq3dIbWS4cmF640jlWOA12YV33YBTrmEQSZBhEkjmHqe3xwVAWezEN+THw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=yg7gEh75KCSRWy7ZOkeyvERqafWSItL3pI+nkwcPGtA=;
 b=Obcq4+9dfdVzrIJAxdKjFIBC//MfcNaLKYFV3MsFUwh4qUBqTPqreroDf/7SZWwKSmN1XWQ6dZ3XTo7hKCdL+98NWn/VNkFmhjg9dLNdmDnClrnvak4rWwp37gTpUCxlLF+awljbJFiBP/fRoZfq+Y631DLBTjELHTPORUCWqiZ5UlcSP3Q1ly8DYXpFREkMVL+EDXXgkyHXJdGQcAhqQr62BlUzoH06aVU7EQMdIEyX94zimCxwPTuuFxbq921LXSr22COhnTrU+c/wK8w7LxE0eu8IuovebIgnxH48LCt61EVeW9KUhMQ+/jwty8dgNls/6VzopedEpRYbknWztQ==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=synaptics.com; dmarc=pass action=none
 header.from=synaptics.com; dkim=pass header.d=synaptics.com; arc=none
Received: from BN9PR03MB6058.namprd03.prod.outlook.com (2603:10b6:408:137::15)
 by BN9PR03MB6188.namprd03.prod.outlook.com (2603:10b6:408:101::18) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.23; Mon, 24 May
 2021 09:26:42 +0000
Received: from BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791]) by BN9PR03MB6058.namprd03.prod.outlook.com
 ([fe80::308b:9168:78:9791%4]) with mapi id 15.20.4150.027; Mon, 24 May 2021
 09:26:42 +0000
Date: Mon, 24 May 2021 17:26:06 +0800
From: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will@kernel.org>, Alexander Potapenko <glider@google.com>, Marco Elver
 <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
 <akpm@linux-foundation.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: [PATCH 2/2] arm64: remove page granularity limitation from KFENCE
Message-ID: <20210524172606.08dac28d@xhacker.debian>
In-Reply-To: <20210524172433.015b3b6b@xhacker.debian>
References: <20210524172433.015b3b6b@xhacker.debian>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [192.147.44.204]
X-ClientProxiedBy: BY5PR17CA0069.namprd17.prod.outlook.com
 (2603:10b6:a03:167::46) To BN9PR03MB6058.namprd03.prod.outlook.com
 (2603:10b6:408:137::15)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from xhacker.debian (192.147.44.204) by BY5PR17CA0069.namprd17.prod.outlook.com (2603:10b6:a03:167::46) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4150.26 via Frontend Transport; Mon, 24 May 2021 09:26:39 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 8c197b04-eea2-480e-953a-08d91e960aa9
X-MS-TrafficTypeDiagnostic: BN9PR03MB6188:
X-Microsoft-Antispam-PRVS: <BN9PR03MB618860A27C69CD333610A1F8ED269@BN9PR03MB6188.namprd03.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:7219;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: SF+h0OIsltN1lo+OaBe4aSGbPShl4BSOCnElbhf+6MFS0zB7SkagxwLHhB80m+VRU/s3tvIaXZ2t/iqf1IIsc0M83/ebn6LDmSzzEcz7gyFbOzEK/LH4K1c3DDuzwDGY9roYuz3PG80mb+cLeuokNsHi9N70Sm8rcJcLrfzGeFctOiuYWw5JDjjKg1YVWGSWbbYz83Zytc9iGISAPaagEr9B/qP7XVhRS1Ebuu7P6fow/TMWw+AHivN9SsFN5iJPk2nO12+xJFnDNBN38oItGx/HYWKlZWaOU+PcF4bh2vxbHVDpH0+/3/dS5jl0Hx8/WYxxqLCskB1jU6iPfb7SwQGNdB2kDbwzBuAVfLB/rlODImNFOixJhV9JEcb5yCwjRgWmp9yE4y95ODtwjs4D2jhu+fQBOJbdSxTuYF4kRuNdACKff33l6szDOaKQtUSxZKNgb9xISUubSyjKX6n+4NzOIwCjIeYTe9JPWaEOo3yjECGq/DPJrptyPPODWaMQ5Z2T8AKIV1Or7sE7q343gl5Oqfe8OiAh82nPJv5TvfqFMbdBPkwgVeZs6NZbWzrfxLE9dpkVmiZVPRp7f5Ce2H2X+xa3rZvSIrQDUQDkH2OWdLRgRKD+6eRlsokn+z+xr9go9hEKFnD2YPzmmWS7fIGvYaND2t3MayNM8tN2iaY=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:BN9PR03MB6058.namprd03.prod.outlook.com;PTR:;CAT:NONE;SFS:(39850400004)(346002)(376002)(396003)(136003)(366004)(66946007)(1076003)(316002)(66556008)(66476007)(5660300002)(478600001)(2906002)(4326008)(110136005)(7416002)(16526019)(186003)(26005)(8676002)(52116002)(7696005)(956004)(55016002)(6506007)(86362001)(83380400001)(38350700002)(9686003)(38100700002)(8936002)(6666004);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?us-ascii?Q?UMRXa/8B/HR+Zj5sJLRrpbu6M9wOShn17El6lixBgoA6zyPHvz/MEfTPyLFf?=
 =?us-ascii?Q?/bNl2f8Kjmq1meXyKJlD0gwAYx5YuoqN3ld15VpB6Ueo24uGYXsigHv6ryWX?=
 =?us-ascii?Q?D68nawANsn7KRrCFOLU1hy9zsYPZ5bwKEr8bA0Ow97IcHa4jJrVCQEwYgY/x?=
 =?us-ascii?Q?SOBTKkUnhr2ZXLcdFi8ohTyg5I7B8ox0jMgUVkhWO0RpO5LHeBMDUOmGdlin?=
 =?us-ascii?Q?qP49TsglGs5s6/EhSOK8haXkrjdC7L864o5/PKcoa1H9Xp/p0OypBzEVDtFJ?=
 =?us-ascii?Q?6/PGyZhe4ALaFgi+6cCPrhCe0sX0VFaHUtHqPI1RUL7OqQhrJVPRXDuTgFZB?=
 =?us-ascii?Q?rFN6XOP+alHZXmtwvFw1CEfJgMSBtSFT0t+s8yXQzY3Q5DrC+M+gUJ+RbxU3?=
 =?us-ascii?Q?moUE0yK8pcz1LcXggyCOidjHFh0kQXDAzEcXga5W/3YHvsTaLCraw6Hix36O?=
 =?us-ascii?Q?ymynSHV7MoQLkcvB7U0B8r95av8hfmJc/y0xlLPRyc+sEQFhuQaOc14z1G6S?=
 =?us-ascii?Q?vnQ40mdNB+SFTQLDibwK28dX9wP/d0QalvNakdka9YQhx9TMDEa+oDqfoTKO?=
 =?us-ascii?Q?4OQx9z61ng8uq5Wq+/IH2NEOujTCHQBnXPSZJdwh+cjzh8w6/s0WAUjj0eIh?=
 =?us-ascii?Q?4BpOPP/e7vYpPhI+ZVPbD2tFhpGFXxvA44+vFt28wwCzYImUTXQGAMtRn8vb?=
 =?us-ascii?Q?MPtSM8rytuLv8FkT+JByIIYpeGCLapuSoP6GttHZWoOrZSds/mDESVgDddNf?=
 =?us-ascii?Q?ZQ/S4FmE1iMgHuMtqFSUY+2YB1YhPfQn8c+ph2xeEIoAcfu62725115fldph?=
 =?us-ascii?Q?KjdRDyW0d0za7QB2SWG3BHbLs63iDofBW2kYn3NBei/uOOiiFInTb/thQ1bB?=
 =?us-ascii?Q?MJQELZyFXqVWZOeMlXYle0IAHplb7Ccvls24j0BfgMhndCHf8VGlUyINLIpC?=
 =?us-ascii?Q?4E51GoaS4c/o7aUVVL6OhhnEYyKNx+SJYfY1D5lQIOQKKQfPh7Ca4Cjz/ljF?=
 =?us-ascii?Q?m67nAwZXqxEeHZl91j0my8o0P1k1DTTYTPr/y+Zrzo3RnbUoF4dicH5TTegS?=
 =?us-ascii?Q?+yGBlpJv7PyR5OrIcaM/HsxzEV3j5BCGek/55E4yNzW4Qubhi6uIVDd0P/t7?=
 =?us-ascii?Q?mj+SyEA/x+4zpBW/NIRb042Qvx2VUiypCWywbeb8NwWUYsJLt0U0Gykr+cyr?=
 =?us-ascii?Q?5R+TNmXX7C6ITEvjGrTNAQTMPer52aZ4dMTMPIZnJuDJ4B0JHELF1yvk5qrA?=
 =?us-ascii?Q?bD7Pw1qVBTmPCa7YyongTgPHoKeev7pH/HSdbaBlJRzw8zHaSXzUZVOyuApJ?=
 =?us-ascii?Q?3UJ61mf6kiHCIIaymYgCdaF5?=
X-OriginatorOrg: synaptics.com
X-MS-Exchange-CrossTenant-Network-Message-Id: 8c197b04-eea2-480e-953a-08d91e960aa9
X-MS-Exchange-CrossTenant-AuthSource: BN9PR03MB6058.namprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 24 May 2021 09:26:42.3445
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 335d1fbc-2124-4173-9863-17e7051a2a0e
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: FE7kNrSIND2LUEkAK/e8daGnfIx3pGkUxnh9tTuwVJBHl2LtYGMWyvCvF/TmC13ugR0b4MqYopw2Heh9vVJhSQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: BN9PR03MB6188
X-Original-Sender: Jisheng.Zhang@synaptics.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Synaptics.onmicrosoft.com header.s=selector2-Synaptics-onmicrosoft-com
 header.b=ir50RisU;       arc=pass (i=1 spf=pass spfdomain=synaptics.com
 dkim=pass dkdomain=synaptics.com dmarc=pass fromdomain=synaptics.com);
       spf=pass (google.com: domain of jisheng.zhang@synaptics.com designates
 40.107.94.60 as permitted sender) smtp.mailfrom=Jisheng.Zhang@synaptics.com;
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

KFENCE requires linear map to be mapped at page granularity, so that
it is possible to protect/unprotect single pages in the KFENCE pool.
Currently if KFENCE is enabled, arm64 maps all pages at page
granularity, it seems overkilled. In fact, we only need to map the
pages in KFENCE pool itself at page granularity. We acchieve this goal
by allocating KFENCE pool before paging_init() so we know the KFENCE
pool address, then we take care to map the pool at page granularity
during map_mem().

Signed-off-by: Jisheng Zhang <Jisheng.Zhang@synaptics.com>
---
 arch/arm64/kernel/setup.c |  3 +++
 arch/arm64/mm/mmu.c       | 27 +++++++++++++++++++--------
 2 files changed, 22 insertions(+), 8 deletions(-)

diff --git a/arch/arm64/kernel/setup.c b/arch/arm64/kernel/setup.c
index 61845c0821d9..51c0d6e8b67b 100644
--- a/arch/arm64/kernel/setup.c
+++ b/arch/arm64/kernel/setup.c
@@ -18,6 +18,7 @@
 #include <linux/screen_info.h>
 #include <linux/init.h>
 #include <linux/kexec.h>
+#include <linux/kfence.h>
 #include <linux/root_dev.h>
 #include <linux/cpu.h>
 #include <linux/interrupt.h>
@@ -345,6 +346,8 @@ void __init __no_sanitize_address setup_arch(char **cmdline_p)
 
 	arm64_memblock_init();
 
+	kfence_alloc_pool();
+
 	paging_init();
 
 	acpi_table_upgrade();
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 89b66ef43a0f..12712d31a054 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -13,6 +13,7 @@
 #include <linux/init.h>
 #include <linux/ioport.h>
 #include <linux/kexec.h>
+#include <linux/kfence.h>
 #include <linux/libfdt.h>
 #include <linux/mman.h>
 #include <linux/nodemask.h>
@@ -515,10 +516,16 @@ static void __init map_mem(pgd_t *pgdp)
 	 */
 	BUILD_BUG_ON(pgd_index(direct_map_end - 1) == pgd_index(direct_map_end));
 
-	if (rodata_full || crash_mem_map || debug_pagealloc_enabled() ||
-	    IS_ENABLED(CONFIG_KFENCE))
+	if (rodata_full || crash_mem_map || debug_pagealloc_enabled())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
+	/*
+	 * KFENCE requires linear map to be mapped at page granularity, so
+	 * temporarily skip mapping for __kfence_pool in the following
+	 * for-loop
+	 */
+	memblock_mark_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
+
 	/*
 	 * Take care not to create a writable alias for the
 	 * read-only text and rodata sections of the kernel image.
@@ -553,6 +560,15 @@ static void __init map_mem(pgd_t *pgdp)
 	__map_memblock(pgdp, kernel_start, kernel_end,
 		       PAGE_KERNEL, NO_CONT_MAPPINGS);
 	memblock_clear_nomap(kernel_start, kernel_end - kernel_start);
+
+	/*
+	 * Map the __kfence_pool at page granularity now.
+	 */
+	__map_memblock(pgdp, __pa(__kfence_pool),
+		       __pa(__kfence_pool + KFENCE_POOL_SIZE),
+		       pgprot_tagged(PAGE_KERNEL),
+		       NO_EXEC_MAPPINGS | NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
+	memblock_clear_nomap(__pa(__kfence_pool), KFENCE_POOL_SIZE);
 }
 
 void mark_rodata_ro(void)
@@ -1480,12 +1496,7 @@ int arch_add_memory(int nid, u64 start, u64 size,
 
 	VM_BUG_ON(!mhp_range_allowed(start, size, true));
 
-	/*
-	 * KFENCE requires linear map to be mapped at page granularity, so that
-	 * it is possible to protect/unprotect single pages in the KFENCE pool.
-	 */
-	if (rodata_full || debug_pagealloc_enabled() ||
-	    IS_ENABLED(CONFIG_KFENCE))
+	if (rodata_full || debug_pagealloc_enabled())
 		flags |= NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS;
 
 	__create_pgd_mapping(swapper_pg_dir, start, __phys_to_virt(start),
-- 
2.31.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210524172606.08dac28d%40xhacker.debian.
