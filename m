Return-Path: <kasan-dev+bncBDV6HSHYYYKRB3FOSCBQMGQE7DQ5DTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1630234F8C9
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 08:32:14 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id i90sf160980uad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 23:32:14 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1617172333; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yr/t3UCBKSGZlKIc6b4pR9DsCfUwpTmk0ZDprNTQpYUfCqw3uAZdOoRuUgKY5XICI2
         sbsUEz1LMQysjWLUrD7DsqO2zE58Cx5/ojW/K3IHbd8ZE7coEVK1+8FXeO3s/IMzOYBO
         8APKexfTDlMtXA5/vIAXOSS03pxSvAWHEFGQVBZfuqzA3OpyqMA1C3qyEqN0YV3oTd5T
         8UF1vz8zv52dIJ6OReVt+kfKlipWSZK3CxDw9yySdtZCv8tuPnCP0qwvA92kTssqAZNh
         0KzUhJGIcpUK/WC3Jm/AlZbiaxtSZbf7lDQa5b9Ko8Y6S5fyAURh3vI95B6PDG1qB9as
         +GjA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Pydb55QkdtoT56s3s4THXBsBHDjefBWvphP1oGv+W00=;
        b=tb0YLNTgTRIL5pzbyNdicJTr/SdFk5xwF2WcgE2rkhXbTxXY4BNpOPSbrRMyAaQC4R
         kdXAFIWTbVJahxLBZpEVrqVuz57cXIKLnzRbQhvim+5hgwA4ymi8zL05iHMzWGjmVHSt
         F6k4oeDKbskodfGwvpb30PPNqt8eo/ouKNkDz0LPKbKVdLVhJ1+Ib0UKPzs5gC+6KjEq
         fyXfCdhbYWpikkRGC67pAdDLv5m/WVSu97gArGgCKlObWMHOdZ1XtntUmUCWl43AK/Lj
         rBXfrKDOashpjAyi7cIKLig1UCVEFxxk3vaG39SugA3VO8pFREVf0gPhhuoD2NZrwRSM
         xayA==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=ks+beTcE;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.237.57 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pydb55QkdtoT56s3s4THXBsBHDjefBWvphP1oGv+W00=;
        b=LKg7g9PlGyeWZxOTAOxgpwx+oJF2aA0lJZv/9YICRdgX81+7EZ690I0ukXnjyVz2yZ
         0nQgsR4T1S4ZRt59lqrRIUuUQihwdi8eIYzKMGHuDqK+ofigiNZ/7l++HHWd7ahkzvOj
         BdvsyPNPvoh+DmiIzIhxtLbMB1qX/bbSj9nIQj07djvTPXFNUmx1vikniZXnKGaNXppv
         j46I9wpxW1ZbRXGdX4xi4CKuDjEVNIQMBs/UUbRfCtIUoiFeQDVn6ug2K43Hh113ONlg
         RXpI7Uu5MOuOgI7d/2PbukdfieITcmuKd1q4NriX1maeLGJeJnfT2tzq4laEZ0yRaeF4
         SdbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Pydb55QkdtoT56s3s4THXBsBHDjefBWvphP1oGv+W00=;
        b=jKUP5FsVL7dD5yIlyZ3fGja3S4lY3C9YWnDTmUzoX99qCfwWp1OoueEZwg4dIBxJjl
         8Xky8O6KKw5YKzKQ5TnnRVjVt4zP+fwCaVdQM1H2h/JKm4SoXvjEneZ2MDpIaqHHyPMf
         xlUHqz0NuVao+BktwIRq1Na/BfWq4KIGxpqDzOJD1WFZJoX2/EbP7il5hQQ3CUtohlIt
         ukFbEqmWM+gDyPZGX2Nh33QZVZTY5B3k0I/aBRUTPv5TVnfTOvLC6JSQ5HZPty+nWnpt
         M3ITO+oFvsEiNc8Njryq+XfP6S07lgpFYbE2v9ajF1dnCbUIM+OLlYFDp2VFUJ5DCzA9
         vOlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xIuFh3R7bCkvbFBpkl2GOHS24Oup/+JvCviQHfqdgDAgqyS91
	ofg0NcqpR5q0BPx0zN1AXZ0=
X-Google-Smtp-Source: ABdhPJxOi0gWss0e9LD6y6JdeHDHejOrBuXteJwRW5BS8PTTBkSC7/KRB3i26dnaQwrAjRz7IByzgQ==
X-Received: by 2002:a67:f595:: with SMTP id i21mr644342vso.16.1617172333034;
        Tue, 30 Mar 2021 23:32:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2366:: with SMTP id o6ls117953vsa.1.gmail; Tue, 30
 Mar 2021 23:32:12 -0700 (PDT)
X-Received: by 2002:a67:db84:: with SMTP id f4mr680460vsk.20.1617172332562;
        Tue, 30 Mar 2021 23:32:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617172332; cv=pass;
        d=google.com; s=arc-20160816;
        b=P6Vq1y7Rd0gLXK+y0stdRTO+b06yvmCLpeZeBDjYpJPurCE2aAl92nmqHL0BXsJoDe
         sKjfczH1szQYSGUThNbWhvtfpQUzoHkz0iUTfp+QAHF/rs88ZsMA22sDcKa7+14dpNNa
         F2c1RWxJTt1UHjMiFEjyJcn+Ajkjc8mPeaIXE3qQdVMoMhgtURZ1g2vfx8z+kKxcJ4bc
         8nHaCWUpQUmWYJoeyJtcqTl9uaooXSlZSfT+Ph3ls/P/Vk2eapUTHBPAF1GiMNiyQAo2
         wq3knzMeAH+v6ynD+I/p9GASgL3rs9bk0cbQPQY7piQODpRpyX1foJEvbSBeGK2bGtPm
         VH0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qEqcDhcW6FQMs4pep4HqmM9C9yhqHFG2+e79B07Z/F4=;
        b=gq71ymHV/uMPFnqbGW5YOsKNXB9f7O3yM4KYrW6WcFM2uXe+X9tLbnRnbUCNI+WW6R
         gl8G3rUnAZXxxEip+AvRF0jrTDDXB+5aq5o5tCZn1S304Cc8aubSHaNz/c6xkqRZ+oS6
         6A3pOOk3c1MgBwKZ8bP13GBZIo74aFYxvA8oY1QDa6loZDnzAUec4akeqiHj02cIZ1pI
         2fTvCf8emtVf73fXnr7B0int0Q93Hj9XjIM7SocOBNB0+ZXXlo1t/IT50q7EOYExTyAk
         9oAulqaXSs+7/5bXbFSzkLp7JSoCBrbagYEIhdFaJaf5vGB/JDLzkP4jHSbxxtt4d459
         F3mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com header.b=ks+beTcE;
       arc=pass (i=1 spf=pass spfdomain=windriver.com dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.237.57 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
Received: from NAM12-BN8-obe.outbound.protection.outlook.com (mail-bn8nam12on2057.outbound.protection.outlook.com. [40.107.237.57])
        by gmr-mx.google.com with ESMTPS id u21si85370vkn.2.2021.03.30.23.32.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Mar 2021 23:32:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiang.zhang@windriver.com designates 40.107.237.57 as permitted sender) client-ip=40.107.237.57;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=X7zHdk+p9TM771MpWe08sIDLUjD0RosLJ8XipxtGeITKOlwjtVkabb36PHePWv9fS17OGjjgkAnWGSdhFUnEb+dHlGb0L3dAm94LCMMKbYh31aLPn+cUH1SKnX3e8D4U/3T4upQG7NCaG9Va22mM72GURjAyQvc/mp5SMwZ/DoE0sjySUVgCvaBnaLoAhvBRUQXfcDFhYLpYVJtT/NuXPLdX9Tsbipt5r9tU70HXJc2pbUm+/YNHk4K/4PNqQN6kL7Jpb685fgoYrAKNI7YgaA8PNWGnxksN8so41lKWCD5duI7bUn8L68t/UasJItlP8TRS5ZqlRod/NQTfzY65Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=qEqcDhcW6FQMs4pep4HqmM9C9yhqHFG2+e79B07Z/F4=;
 b=h7+ngq7u6r555tOcTdghZA5uOaa3Yf2B0OVC9w1krNeFxYf9hruUvTcDAgAwElIso0SOaF1qCJf4w5Z6/AqCJOi1Av7mGSJxlB5AxERZrcDLs+8fev8BDfB3qKZVWcNbj1AnVVFzuR8V/cQPvcUQhYk61yq78niBYWNsrXJHangUwrl82RHKgPNS6NHVBow8UvphDxnsjd+WrUBOhlfpm/VWOkBFS6hXGg+M7xnOpz6OTaBrADJxhv6jg5iaTwp5EjAACEBxndtCAie19fLt2EJ5HN+CN5wPhkY8qCNfyIPV75eXhv3D2LO6g2PxVFdMRofZidMVjx6gJ/b0GTDv3g==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=windriver.com; dmarc=pass action=none
 header.from=windriver.com; dkim=pass header.d=windriver.com; arc=none
Received: from DM6PR11MB4202.namprd11.prod.outlook.com (2603:10b6:5:1df::16)
 by DM4PR11MB5390.namprd11.prod.outlook.com (2603:10b6:5:395::13) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3999.27; Wed, 31 Mar
 2021 06:32:10 +0000
Received: from DM6PR11MB4202.namprd11.prod.outlook.com
 ([fe80::60c5:cd78:8edd:d274]) by DM6PR11MB4202.namprd11.prod.outlook.com
 ([fe80::60c5:cd78:8edd:d274%5]) with mapi id 15.20.3977.033; Wed, 31 Mar 2021
 06:32:10 +0000
From: qiang.zhang@windriver.com
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	matthias.bgg@gmail.com,
	andreyknvl@google.com,
	akpm@linux-foundation.org,
	oleg@redhat.com,
	walter-zh.wu@mediatek.com,
	frederic@kernel.org
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] irq_work: record irq_work_queue() call stack
Date: Wed, 31 Mar 2021 14:32:02 +0800
Message-Id: <20210331063202.28770-1-qiang.zhang@windriver.com>
X-Mailer: git-send-email 2.17.1
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [60.247.85.82]
X-ClientProxiedBy: HK2P15301CA0002.APCP153.PROD.OUTLOOK.COM
 (2603:1096:202:1::12) To DM6PR11MB4202.namprd11.prod.outlook.com
 (2603:10b6:5:1df::16)
MIME-Version: 1.0
X-MS-Exchange-MessageSentRepresentingType: 1
Received: from pek-qzhang2-d1.wrs.com (60.247.85.82) by HK2P15301CA0002.APCP153.PROD.OUTLOOK.COM (2603:1096:202:1::12) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4020.0 via Frontend Transport; Wed, 31 Mar 2021 06:32:04 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: dd49e09a-554b-49bf-4b5d-08d8f40eb603
X-MS-TrafficTypeDiagnostic: DM4PR11MB5390:
X-Microsoft-Antispam-PRVS: <DM4PR11MB53903144FA428BC7F83220CEFF7C9@DM4PR11MB5390.namprd11.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:4714;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: RVcPtm1r7jU3e0suHSjyUaki1KQ3JW7ITvMTSMNrgIxxRnjDp1wX6+1lhmXAqyQ4XoQ5iXVa/36cCzkLSvF6F0c39TRun9CUWYPRxnp8BtcvP/82abvHveIs2SIoMcZuan9/RupoXUyBNHHrtR0VT+kmcGRWCVfL07GvEjvQu2SOzebr7qvOqfmbK5a4/MkUY43TTcEmmetmNFowa0yAI+pjyEJmytw46SKZiBmVoNMWG9XlPZ0VAfRtTFqXdDH5lsOOILKzWRntFdphrFgDwXpWMTOXHQpEbROSZLIM5Ka4PA+ZbddTznGTUDQQUu69cpJ4WurF3fhe+1hvm/979AJ+QLjQ5JEuYf27+baME1pYl1i6U5BEPCzUIN7+xroFfruqHa84j+whfGTNXzFQRVajPMW3eCjBJF10KBFOv9mQy4No6tflwDqdQZ4aLMdH1QXggw/ionY/xL77XDFVhc/lfpVp0qddDAlTwaI5nNSHRQizt4AifKcF3PGAmOo7JCFIicKhQc8zuYQQkP+1YuhJ160br5lAljhEgxSbCMEzZEheZQcbYOq/+pBkOaqe7rWc8v7By9SqgEu5xF8K5/PqmF4L+YB38k9Os2PWRuPxL4a7oo9Lv7HPhj6qS49E+/3KzD4/fUpFqT2luRfMgg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:DM6PR11MB4202.namprd11.prod.outlook.com;PTR:;CAT:NONE;SFS:(4636009)(396003)(366004)(136003)(346002)(39850400004)(376002)(8936002)(66476007)(6486002)(6512007)(956004)(2616005)(8676002)(9686003)(5660300002)(83380400001)(1076003)(86362001)(478600001)(2906002)(16526019)(4326008)(316002)(186003)(6506007)(26005)(66946007)(7416002)(36756003)(38100700001)(52116002)(66556008);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData: =?us-ascii?Q?yzZBrXXR6/+3eToA59N0WY9X3CF3fv7Woe7wbf7lYcujQK4ON8SugGBbmSE3?=
 =?us-ascii?Q?uns+PckoZ2UB/MeYgPD0rxcQkWAEKxe8HaGgW/Zie1gdYztJwkKOMPb01q4G?=
 =?us-ascii?Q?vXnctNKRKeDPTiD/Vko3m9oVfYQvwQjSW/f2/TqBgzHULIUB3QI+qztGHHdT?=
 =?us-ascii?Q?j3kylqDWjBAF5IzCzF2HXKBLNyMpER58niPm0kvnnmLbdcUnlkTdS/wDyggU?=
 =?us-ascii?Q?Iq38pP1dDCjEW+LfW9277PWr6g+IrFinAsbRxUvkn7MOUt8JQkpfnyUia8wi?=
 =?us-ascii?Q?ahx0QHwsbVEDPAA1HxoyhB68pw5BAQBV/5/tHmS6zT3mQavVBOZsdd4QpraS?=
 =?us-ascii?Q?RqZ7ox33oFGTqIn8iVB124/3I1O13D+POT9oI1V7056E3cC6XKLYQo8Bz51j?=
 =?us-ascii?Q?IisVgdIh9cMnIkMsNwUNK6rozGg1s2cTEZXc0tuI+Q+OyB9IFObWlYIvE9SX?=
 =?us-ascii?Q?5wv2ULnG7l6cUC9QOINri7wxdVzYnBQ1oGulqloZr7fgnLSHSdAxT6ptXP1C?=
 =?us-ascii?Q?BT5DHFNrz9cWaKC0zU7sAJObW0OKWW3qiYpixslIHZdiJcPpvClMG5mOY+ba?=
 =?us-ascii?Q?Ga4tT8rz6Lw5PZIiHNYya6bx9IxK5VurgZWgX4zDu0fOVLyGqQHm8uHmIWLf?=
 =?us-ascii?Q?eMa4hcoYZIjle76xsETF8QF1HCIGp8ed6U9LfLpK3JsRYePyI/QOgApUfSa5?=
 =?us-ascii?Q?TOx6CXPHlkT/I8rOTr2AvKeZ0z0CXnvCffcUYB7z10AWGKzh+PqXvzStKkqD?=
 =?us-ascii?Q?3YO5aCLzK54pawPgwY/v1YWCjO9RkdqR6RpP4eBjHdv5GPGwAgESq9EOgcIN?=
 =?us-ascii?Q?XTIbmekG4F7ntequUArrrH5whpGmBZg5qN4/u41bOAh4B0LKfJbILbnTIC0p?=
 =?us-ascii?Q?01UO6w+w0WYyxg9yDadCKGq2h50/AH9tTNEF00jYJJ2K7SoKNbhyP+2yfrBB?=
 =?us-ascii?Q?pND05VzXwKmVE9ul/AAmIqvDvSZQCW6vX4BA6+lxCG2OaWITrhWJs83A/Uud?=
 =?us-ascii?Q?gh0G5eoD1jcAgmg6/okpFdSKgbMedTSgK2YbrdTh/vYqKcDuqkn1IEjVn9Nk?=
 =?us-ascii?Q?EWqFMTjfINheEBagk4l3Osfq6nRaYERsAMNH418diREdx0BjsnzxGsz7cnFY?=
 =?us-ascii?Q?aHlBASMWq1NWiR91irG82SMHSvN04VlFoP3IRbkbH66HTqveNybaV//ZVnTu?=
 =?us-ascii?Q?Bkc+CGDm/2acbG1Negz3t30b3lHFyjvG+qPjB+JdPf2iovBcfwDlajsaN777?=
 =?us-ascii?Q?UWbZ4kbkLveUbFS/ZcsIuVcQ30VnSk7edNBTYK0Cj/X7WkrLMyHCiwpmJUN5?=
 =?us-ascii?Q?dabl/6ATy9mzUqCZvSPJhjns?=
X-OriginatorOrg: windriver.com
X-MS-Exchange-CrossTenant-Network-Message-Id: dd49e09a-554b-49bf-4b5d-08d8f40eb603
X-MS-Exchange-CrossTenant-AuthSource: DM6PR11MB4202.namprd11.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 31 Mar 2021 06:32:10.5256
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 8ddb2873-a1ad-4a18-ae4e-4644631433be
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: YcocxZg9NV65/zr2ot3ylCvL71qxdN+qZ1GXLaCfkZn9pN/W7B/4Gd95coQcmUls9T6AZwgvwIFcOX1Issu/J5VsH/5KCbJSxwvB3lBotew=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM4PR11MB5390
X-Original-Sender: qiang.zhang@windriver.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@windriversystems.onmicrosoft.com header.s=selector2-windriversystems-onmicrosoft-com
 header.b=ks+beTcE;       arc=pass (i=1 spf=pass spfdomain=windriver.com
 dkim=pass dkdomain=windriver.com dmarc=pass fromdomain=windriver.com);
       spf=pass (google.com: domain of qiang.zhang@windriver.com designates
 40.107.237.57 as permitted sender) smtp.mailfrom=Qiang.Zhang@windriver.com
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

From: Zqiang <qiang.zhang@windriver.com>

Add the irq_work_queue() call stack into the KASAN auxiliary
stack in order to improve KASAN reports. this will let us know
where the irq work be queued.

Signed-off-by: Zqiang <qiang.zhang@windriver.com>
---
 kernel/irq_work.c | 7 ++++++-
 1 file changed, 6 insertions(+), 1 deletion(-)

diff --git a/kernel/irq_work.c b/kernel/irq_work.c
index e8da1e71583a..23a7a0ba1388 100644
--- a/kernel/irq_work.c
+++ b/kernel/irq_work.c
@@ -19,7 +19,7 @@
 #include <linux/notifier.h>
 #include <linux/smp.h>
 #include <asm/processor.h>
-
+#include <linux/kasan.h>
 
 static DEFINE_PER_CPU(struct llist_head, raised_list);
 static DEFINE_PER_CPU(struct llist_head, lazy_list);
@@ -70,6 +70,9 @@ bool irq_work_queue(struct irq_work *work)
 	if (!irq_work_claim(work))
 		return false;
 
+	/*record irq_work call stack in order to print it in KASAN reports*/
+	kasan_record_aux_stack(work);
+
 	/* Queue the entry and raise the IPI if needed. */
 	preempt_disable();
 	__irq_work_queue_local(work);
@@ -98,6 +101,8 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
 	if (!irq_work_claim(work))
 		return false;
 
+	kasan_record_aux_stack(work);
+
 	preempt_disable();
 	if (cpu != smp_processor_id()) {
 		/* Arch remote IPI send/receive backend aren't NMI safe */
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210331063202.28770-1-qiang.zhang%40windriver.com.
