Return-Path: <kasan-dev+bncBCJZ5QGEQAFBBWGW26MAMGQE4VXRGWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DB935AD290
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 14:28:09 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id ay27-20020a05600c1e1b00b003a5bff0df8dsf6222719wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 05:28:09 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1662380889; cv=pass;
        d=google.com; s=arc-20160816;
        b=v5D6QyXNRGoZ088d0rW9T/BJNsQ5q7Etk8m5OA5i5qQxcYsPwlqWL3hU1ZZPpqVfVu
         Lza939IigXrap9PLJi36zfKcQoqqF6aoeUpZTkRzPrns42+ZsHy1wJOotKCaibtViyTy
         EdJxQzHtbTqxNueWQ8mrJtdDM5AlcqitIcWVGr0+9s/p+YYLlwFYx6PpY3f8+QLBQptr
         rRd3mL1lshczyQE5c/iOvP5m42LmtJuzIhmZ6wfY8rUVa3/MqUJHaFH3l69rFPaAdEeU
         mfgZLuanJNAAZGtwLqtu9mINoiMnRpUt/lXqOLy7776C6P3f8jlgKfaQNx3zIeUV0l31
         thGw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=t4bV/m2YHcv2H1rfQq+OjbfOcNgBLB3NE2Rs9UdU7zA=;
        b=OyJW1Ym1IMzEcau06Q4C3w3E31kRyVi7HpOcTJsfEz6I/k+QXGmHW2/6ABf2DPC0p7
         5EddF4tJCbdKasYsa3q99L/ELewqxVbRB6Eb6c/oIwccABarI8VcV/HRZrAbf2wQtx47
         nyliPF1B36dz0ccW2KmAg3nz8UutW0Ay2C4oU6+4/TDk+0G7BlZySD9o8V0z8T/nyyxb
         KRJ3wGCIFJEE82W9tapPith0C0u3UOUoM0Jdk8A9avP9pier/fYZIPbTkIN6GTquuOAE
         fS7mJYMqcHsCJ7X98nApI1LtiH+EahsrFimWHYpz2oh1sqw+uU/IrpwSCb7yQt4H/23g
         nyEg==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=fJhY8s6j;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.2.130 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date;
        bh=t4bV/m2YHcv2H1rfQq+OjbfOcNgBLB3NE2Rs9UdU7zA=;
        b=qqR4tjYmZj+ta6CUa9tW94S/vRRU2UUa4q9gAnA/D9b0l7vb6CjhR11zRQ4QbDY6zX
         AkUUMoeh5dcocmDNNt9BilGUsUW5lNzs6yqjPd3DAoldX3dI2SD9WyTXY7rOapC1W/UF
         aasDXsmt7DY0mvMf2FlMLw07Byhvu0qIH8CSDUjkO039gU/pGJVaHJuWQI73toJfOZon
         5kvUd6wMOyXi6JoO7s2NjJVLwMatOBgeY/fHDWBPrmLNMwuJCVgQNVDAssTJh6N/mtIZ
         WxuZDvBPMeFG0YWWQA8Yx6bJHb3H+wTwA9OHTPvOqxt74Ws9QSYUL6EHenB1L7RaOxVv
         bedQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date;
        bh=t4bV/m2YHcv2H1rfQq+OjbfOcNgBLB3NE2Rs9UdU7zA=;
        b=trwA9TE5GR4eYlsyM+QqRj7rWgh9iYJcXMZKjDMtKa7U+BuUusYQmg5n9wkuCcESbo
         N0Tf0JjrIRgV++DDIxSpmUXnwdRLNPN3WuuPq85J/DDc3n/6iUIpjcsPZuaHupa2+2In
         7lfqrVNtyGdFWmQbnQR1AiXe3il6ZItDNxa5hBDVqyVuj/BVewEVkPTQd9J3wMoMvfe1
         aZOjhbUk3FotTqnhQgieCm0k494dW1mYwaL3B21rUrxQxnf74qxwc5wgCChmcCUlVXFV
         mpM+fjy4QhWl1/IzyKGheHcCFF7c52i+BDzCHReB0wNkqBpASeAhHxUTSg2cSJcRF1jR
         UUoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0HmzX/QSOx3G3K6jzK8fFBS8mNLZWh8Mf9Ts82tkp2OJBmSIAW
	YMOBoMcD7nCfK1P/0YiC0qY=
X-Google-Smtp-Source: AA6agR5vtCW2ZkjpWqjt0xDrrs1NgGhjGywrJln5mCcAWvrwyHYNBegHgiB17Undl3jTlyKAZAIuWw==
X-Received: by 2002:a5d:574a:0:b0:228:b90c:e5ee with SMTP id q10-20020a5d574a000000b00228b90ce5eemr1374861wrw.328.1662380888919;
        Mon, 05 Sep 2022 05:28:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:502a:b0:3a5:a469:ba0a with SMTP id
 n42-20020a05600c502a00b003a5a469ba0als4777227wmr.2.-pod-canary-gmail; Mon, 05
 Sep 2022 05:28:08 -0700 (PDT)
X-Received: by 2002:a05:600c:25ce:b0:3a5:a3b7:bbfe with SMTP id 14-20020a05600c25ce00b003a5a3b7bbfemr11050753wml.115.1662380887936;
        Mon, 05 Sep 2022 05:28:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662380887; cv=pass;
        d=google.com; s=arc-20160816;
        b=oL5hqAN1uGXCiHqJ0mINiVMxfjLHKOOMWVguQjOLipf2l4U/od9a9Q3pqkX4FcehOg
         fQs5mZREk0NX9FRZjQi2YIW6zVZqQaZvZ5m+/IfgXjpFebn8+ZL5rg+ZGtVZH7pxQT7e
         uJwEY10fhPkUCteYQ/EUJnQgTUdBXKfuIuWx8qIdPNBD0TzBnmuLHQoROyLvcQA4VIE9
         TBlmrAxQMgWNwHpZy6zcr0QMq/y2LXBKSRVo/nKwVha3o3QI5sAAj83eI5/zE5gbk+Aj
         H8EqA8zdvEucPAu/0S0Mv2DUic3p8BbnX+4dD9WbUMM3FRm8gij8mT7di99TZ8tSp7+Q
         GanA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZMdyDeV7btMAUHDJfsyyjiGN4a44HHGw7/KNGpxBIWg=;
        b=dFEV3x0X7QphsnolWO0b4ABGDMjSyNc2myU1zGjlmfpm7c2pex8Hcm1El/htaWmHP/
         5Qki4R2hU4XN4fowHLvWlZK2f9oAKKeF3EenRvSO7PvnGRPyNE5V0/oKUymBfcfqEVWn
         jKtMtCxeW6/9EFH9pqUPGyVSP2KM3t0agkFBZyy+7doQA2WFwdtIeVt0YR+J2HUR59ym
         XlVAmCb1vQSWAc7gv2gGshF/3egy3zSN62fqtueS1xMpNxa/pjCJ8V5dxbdN+/HgXwY8
         tyj6mELBEWKecLVN5DZReZLdZIa2FwddJSoJeOXwXnZq4eb3Y4X7TuzBPWPKKqla6GAh
         Q9EQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com header.b=fJhY8s6j;
       arc=pass (i=1 spf=pass spfdomain=nokia.com dmarc=pass fromdomain=nokia.com);
       spf=pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.2.130 as permitted sender) smtp.mailfrom=alexander.sverdlin@nokia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nokia.com
Received: from EUR02-VE1-obe.outbound.protection.outlook.com (mail-eopbgr20130.outbound.protection.outlook.com. [40.107.2.130])
        by gmr-mx.google.com with ESMTPS id n186-20020a1c27c3000000b003a49e4e7e14si934252wmn.0.2022.09.05.05.28.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Sep 2022 05:28:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexander.sverdlin@nokia.com designates 40.107.2.130 as permitted sender) client-ip=40.107.2.130;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=SRpumYC2x+BQroizR9uLAGDQGXmSHcOJsXz8y14lyR4uaNktVCxOCqR21oNiYgigCWGO2fIOrwZEfOd1MwKWcKliSE8Zp6569BL2InIZIHwLebz1vOnTKuc4MuirW7IbTL/QDBvtsNcPIvd/8TeIIQbuQpg/zRJDHgMAtmdNgnscgYrcAuESRK0xp1Tn2YbPDk2tTiDDEDiKTVYvU796Iwg82a+zfmseLYwoTZ/kwIVlY3AHiYxsKuTLfsa/jNr9KEW2yM/C4f/s+Vm4152qca+KZWhp9xW3MmpnMlGLg6ri2ZLaAtwt0+vsdqXmxMP5GwDBBaztSQoDOr0vwuxtYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZMdyDeV7btMAUHDJfsyyjiGN4a44HHGw7/KNGpxBIWg=;
 b=g6VxykbY9PXN0FQ/1iYTZ8EqSVaYYc+ayKM0AhT0RgDMD1kA4VyI2IUvzyWPoGIg8cehEb+Ssjbw/hqNqjvSQh2SL+WepuJIU2K1oq2Ay/iFpc7kEjyoJNAaBTMSOa5FHcm57Dsb3zRMya+UeUvVW2QK56KC/jzOqgnECMVBecsMRY68LVKuz62BrGtdJKYaLEXA2Vi5qQSVkpJHPE/7BdJOfwKFBPRGH7TNIoDrJgZLFxer0W2qurwDiNwhvCwqgUpMCYxsU7Y2VaJ5tcNqgxkC7dyqkQvyMYKDhtj0Re51uEVxwNQjXnHXcW93hjv2W87UVfTzB9MQj26lxsatWg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 131.228.2.8) smtp.rcpttodomain=linaro.org smtp.mailfrom=nokia.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=nokia.com; dkim=none
 (message not signed); arc=none
Received: from DB6P193CA0022.EURP193.PROD.OUTLOOK.COM (2603:10a6:6:29::32) by
 AM9PR07MB7890.eurprd07.prod.outlook.com (2603:10a6:20b:303::9) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5612.12; Mon, 5 Sep 2022 12:28:05 +0000
Received: from DBAEUR03FT025.eop-EUR03.prod.protection.outlook.com
 (2603:10a6:6:29:cafe::72) by DB6P193CA0022.outlook.office365.com
 (2603:10a6:6:29::32) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5588.10 via Frontend
 Transport; Mon, 5 Sep 2022 12:28:05 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 131.228.2.8)
 smtp.mailfrom=nokia.com; dkim=none (message not signed)
 header.d=none;dmarc=pass action=none header.from=nokia.com;
Received-SPF: Pass (protection.outlook.com: domain of nokia.com designates
 131.228.2.8 as permitted sender) receiver=protection.outlook.com;
 client-ip=131.228.2.8; helo=fihe3nok0734.emea.nsn-net.net; pr=C
Received: from fihe3nok0734.emea.nsn-net.net (131.228.2.8) by
 DBAEUR03FT025.mail.protection.outlook.com (100.127.142.226) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.5588.10 via Frontend Transport; Mon, 5 Sep 2022 12:28:04 +0000
Received: from ulegcparamis.emea.nsn-net.net (ulegcparamis.emea.nsn-net.net [10.151.74.146])
	by fihe3nok0734.emea.nsn-net.net (GMO) with ESMTP id 285CS0Mi008828;
	Mon, 5 Sep 2022 12:28:00 GMT
From: Alexander A Sverdlin <alexander.sverdlin@nokia.com>
To: kasan-dev@googlegroups.com
Cc: Alexander Sverdlin <alexander.sverdlin@nokia.com>,
        Lecopzer Chen <lecopzer.chen@mediatek.com>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        Russell King <linux@armlinux.org.uk>,
        linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
        Linus Walleij <linus.walleij@linaro.org>
Subject: [PATCH v2] ARM: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
Date: Mon,  5 Sep 2022 14:27:54 +0200
Message-Id: <20220905122754.32590-1-alexander.sverdlin@nokia.com>
X-Mailer: git-send-email 2.10.2
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MS-Office365-Filtering-Correlation-Id: e57da00e-418c-445f-b00e-08da8f3a1508
X-MS-TrafficTypeDiagnostic: AM9PR07MB7890:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: PT40EXaVjYj5qqCPbaMvrHmrrCjFmEDyFy5S6putdHWsNdmfIhvQD94ouI3i7Cs+EzqRUGP/snaEimr5hk5Zx0jH9+hpO/fh+7jF7QZKJiHnLi/+Jj7h8FHMlMxZtH40buUnOWza3ntMRZMK72v9xlO3kndRIW5TMqhRELxaFDN1bfbduBVtxKs5pvKI9vVJKajaylqC4q3AB1mHWRbmQAKW5rCTsnL5JXMnSoChf4yWn+1IDrjWMrbYNgXOwyREM68UiUV2h+Ld/dcVnJZqRvErU8OYV8q/LTlT9jkgl6bsKslOJb/3yBGpHJ6bp3pPb0YslIIgPUtFkNCkqjmlV/3XQHIxVdjxEvjA9GCRsWvkKLfWjG7iCmRdUV1NXl5kPQBvbmL436ToeNi/4SALWUz53IRJNrzDnJa+vVqkHmNWVDsI+5AVu0H5YppuJVJ7cBtn1mSyDPZ2FNwRA3iNFsPKfRMWEBJDnuTi8cBLBp5RTRLhCAiOkJ70kI1LQtPc3vDMqlQRR//NAxw0ecN83c3UXRwkH0uYESRMGsmn2rau6j7wP6BBZBEQo7Tnwly7aBSL0wGe4qWQIAi7I6VaMpdPW01Ylf8ZT5QIvHCIth3jh5MBF8rfxY8Mo4pmSL63oz9Gc0fY4bBEwxvQyOV35neNvqgIcjdGAmjlYSQdWqp1d0ftMt63kAOG3rAYrgwr1aeU5SIdvSHHSxKVdL4aZ/b/ECXfvj39+EZCPWdRquE8d3itwlC9l9Zj2KvVkwxXyCIxZVU2K9TE/n8hiuJGGJ+Lxdcp0Bn7s644Dp0fKQGrOQjKlJSTNiopC61vt0om4KqPGGtHldD6JeZwhYVCFXY9Aya48JhqnLqr0iKMpqs=
X-Forefront-Antispam-Report: CIP:131.228.2.8;CTRY:FI;LANG:en;SCL:1;SRV:;IPV:CAL;SFV:NSPM;H:fihe3nok0734.emea.nsn-net.net;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230016)(4636009)(376002)(39860400002)(396003)(136003)(346002)(46966006)(36840700001)(40470700004)(8676002)(4326008)(70206006)(82310400005)(316002)(41300700001)(6666004)(45080400002)(6916009)(54906003)(83380400001)(36756003)(86362001)(70586007)(26005)(1076003)(2616005)(336012)(186003)(47076005)(7416002)(2906002)(81166007)(5660300002)(82960400001)(356005)(40480700001)(36860700001)(82740400003)(8936002)(478600001)(40460700003)(36900700001);DIR:OUT;SFP:1102;
X-OriginatorOrg: nokia.com
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM9PR07MB7890
X-Original-Sender: alexander.sverdlin@nokia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@nokia.onmicrosoft.com header.s=selector1-nokia-onmicrosoft-com
 header.b=fJhY8s6j;       arc=pass (i=1 spf=pass spfdomain=nokia.com
 dmarc=pass fromdomain=nokia.com);       spf=pass (google.com: domain of
 alexander.sverdlin@nokia.com designates 40.107.2.130 as permitted sender)
 smtp.mailfrom=alexander.sverdlin@nokia.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=nokia.com
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

From: Alexander Sverdlin <alexander.sverdlin@nokia.com>

In case CONFIG_KASAN_VMALLOC=y kasan_populate_vmalloc() allocates the
shadow pages dynamically. But even worse is that kasan_release_vmalloc()
releases them, which is not compatible with create_mapping() of
MODULES_VADDR..MODULES_END range:

BUG: Bad page state in process kworker/9:1  pfn:2068b
page:e5e06160 refcount:0 mapcount:0 mapping:00000000 index:0x0
flags: 0x1000(reserved)
raw: 00001000 e5e06164 e5e06164 00000000 00000000 00000000 ffffffff 00000000
page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
bad because of flags: 0x1000(reserved)
Modules linked in: ip_tables
CPU: 9 PID: 154 Comm: kworker/9:1 Not tainted 5.4.188-... #1
Hardware name: LSI Axxia AXM55XX
Workqueue: events do_free_init
unwind_backtrace
show_stack
dump_stack
bad_page
free_pcp_prepare
free_unref_page
kasan_depopulate_vmalloc_pte
__apply_to_page_range
apply_to_existing_page_range
kasan_release_vmalloc
__purge_vmap_area_lazy
_vm_unmap_aliases.part.0
__vunmap
do_free_init
process_one_work
worker_thread
kthread

Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Alexander Sverdlin <alexander.sverdlin@nokia.com>
---

Changelog:
v2:
* more verbose comment

 arch/arm/mm/kasan_init.c | 9 +++++++--
 1 file changed, 7 insertions(+), 2 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 29caee9..46d9f4a 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -268,12 +268,17 @@ void __init kasan_init(void)
 
 	/*
 	 * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
-	 *    so we need to map this area.
+	 *    so we need to map this area if CONFIG_KASAN_VMALLOC=n. With
+	 *    VMALLOC support KASAN will manage this region dynamically,
+	 *    refer to kasan_populate_vmalloc() and ARM's implementation of
+	 *    module_alloc().
 	 * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
 	 *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
 	 *    use kasan_populate_zero_shadow.
 	 */
-	create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) && IS_ENABLED(CONFIG_MODULES))
+		create_mapping((void *)MODULES_VADDR, (void *)(MODULES_END));
+	create_mapping((void *)PKMAP_BASE, (void *)(PKMAP_BASE + PMD_SIZE));
 
 	/*
 	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
-- 
2.10.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220905122754.32590-1-alexander.sverdlin%40nokia.com.
