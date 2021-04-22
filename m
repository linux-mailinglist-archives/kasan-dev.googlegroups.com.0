Return-Path: <kasan-dev+bncBCZLRWEX3ECRBLHBQSCAMGQE5PSMRHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id A017E367BE7
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 10:15:41 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id t123-20020a632d810000b02901fcdcf045c3sf12106107pgt.17
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 01:15:41 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1619079340; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2+pwUAybZjtSTXlIaqRMxBknxtmdr06VR9uwvvltDb6CDQZytFZKJxy/IHOFivWAD
         Fl1FKXcRf8lro098KAGbOjUo7fLTRNmeFsrA//ouSnihZb4Mpg2PmAQc0sh7JH8pshvj
         ekm9eekd7yoaIi0ZUBhuz95o7qZnmb+07EBbFZFRG9PKJfZ1RQTmDnSmD6qqg217mtNL
         pIz9xJeeS2nHXSpwDbnAid5t3IvOIbP5smGWTH2TV4tq2yl7TjVbML8XJLi1qjwRA+bE
         vdnwKDBdK5xA8fVVq60TiMj+JWNngqVGxjTaM9KvSsMFSPjIQZ99q7vD64/Mod5PsyNE
         sXxQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=QMKjuwlDjhs+iJKrUTdel/YnqZV8dzcgWAY9u96TS6c=;
        b=swC3jh/eMDT8fNrHkeSXYMF9ONKbWTrSBBH7vxUim4VVHLXL7zajWigDKSKyLi/SsP
         /VK1kKEz0hL9G+cfalZk5iCOxzEt7cFjspOxoWrx73/VOksNS3h0IsxNO9PIS7WzaPis
         cZYWClksgpCb5kNiiuDSdv18jj+XtYBKZNxU6kyzREh6NJKGmUMSmfUo1l+BUdlVPkV0
         VjaydP3btssURmMq9jB0mOoViTE8AR04SbBhGIOIAHu8IL30aC7RUhSCaHvaJeQMu5gM
         PO1KklfQM2x3VfzXjTjp2ONkCF1+eSN2/yFgLcuqSmFe26Y/7HcM51O44YOeCqyxYvHz
         XICw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="e87c/9FM";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates 40.107.95.81 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QMKjuwlDjhs+iJKrUTdel/YnqZV8dzcgWAY9u96TS6c=;
        b=eqEsIST+nXE0xq/B5BrrzmQSMPXCvgkbIGPFjOdwau+iTYBHmLZYon0ZOA/HXrFHML
         4U3r9V6c6uOsiaICby+bZnUHfwQeYY8Hz6LatCdpF70icK8yoZqdPYMP9oZ4unfuQMlV
         w865KGXUY+YfDljUdM2JrRVUGktUZGjZzH2ZFVBPB8HH+vazcpgkvWlTe6stIV9smXRI
         Ep7u9RtU/2KX6J9bTcEKHCy0mb/DBazpS7jfyFy8LdNaNBZR6GSMCTtectYMXCongpK2
         qcQtVyTYu2W8sr6e99Oc5KJz58vedbPW2Qh/IDRqN/1U7Ygw/GDbqzErsJdZrUImXep6
         YV/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QMKjuwlDjhs+iJKrUTdel/YnqZV8dzcgWAY9u96TS6c=;
        b=dP8O6kPRoTlCVe1qts/6qfx9qOswbNFicoHMnfXlRjvFI3r5u+PpzApDNXsvpLF6ve
         v/RX+K8MrdqHuwye5n1uhD+DuVxiwtEaadkObeaNP6iFbQ5mAstXvQQPLyZmaRaQdgpS
         dvi1AoC+B2nzu2gbZ96VP1YxfngBIk6Y7yGyri6O5lt3tkvPfkeSNGyzsGFWXk2HqCMR
         iUtSfXQ75FDgWKB1qQnS6AmspuFctcZuOJiR0S5DYQGuq9M0vojJpjuYbLCYRPTgxMjI
         XmjElceTpHreMEhaNyi09PV7dAnsocykvUwhBV/Ys7VcxUjeodHVwYYKFbQ6ce8Mv/a1
         pRWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JAUfcHRSqN02UMnsbLHLW8fNSKa38kDZhHmPAMZhK2N41T8ah
	Uvz2PbhSAvvR2C05SvlkdVw=
X-Google-Smtp-Source: ABdhPJzFohfEPN6Du8hrTV56qtYyAujetQUOkbxt7Ud6/zkzo0RNObHZPSiuRdUVNmKCsfTR1xnzBw==
X-Received: by 2002:a62:ea10:0:b029:25a:9902:43f3 with SMTP id t16-20020a62ea100000b029025a990243f3mr2105783pfh.68.1619079340259;
        Thu, 22 Apr 2021 01:15:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bc47:: with SMTP id t7ls2444637plz.3.gmail; Thu, 22
 Apr 2021 01:15:39 -0700 (PDT)
X-Received: by 2002:a17:90a:ea86:: with SMTP id h6mr16074055pjz.52.1619079339604;
        Thu, 22 Apr 2021 01:15:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619079339; cv=pass;
        d=google.com; s=arc-20160816;
        b=p5cX/hP3nCBhJoDcJvxdWREmqrYprJDtqs1bI1/xBi0ujD/BshvptoTe2OrVwsz03a
         8tXZMEAboo8fqygGv7ACKL9YZdm2ZsnLmTCHaLIcIvOr0cnFiZpTc3XeVx0aBJmhjiTt
         VkgkUt3JS3Q5IWrRdT8I9Xkc+o1kbBfuidTo5MMCTXMHqrXyOZt4gD0yQkkI4iBLpSdm
         jN0Mau3Wg6SW34dlIvDWY1J0lFrn7lPY7/qnfxgyU4OnqsV8GzV+oAW8BjnEYAMuVo0h
         KwsBfr+wrPx1iH5fo5X2pbP23tJLe+bWgBHm8RBOMNgF2TUpI2mvrbKy2heNMdM8oB2E
         IrPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=AmrFbzLXqyCvnKwsPoePx5gw9HpN/jnKUZHcl7dka6g=;
        b=XrqLkLTBbSua6xnhcfGIO53uEmhXoY9ZMQPfnGWqWpPg6ZTuWofYNPZe9dg4vUmPt3
         Cr3vbvmsVkX3MX+5fwkRgcU/OhHuGk9DBN3E9+mO7BQdqdWr5w3n6lDJcF5CS+xjXtEg
         qdWXmifKZbeXL8L6z8pihTR8roHBRMv/g5fML5IjNRkSKINqIH6yDZjIGXTVd6aTTsPd
         ZTwIqaKNKwbT7pz37L8ZcRMexyLrKMuGjkjGwGe2yRsk6j/wiCF7AD84gLy+ilse6+8M
         DCUpPPLgN0rhnOqjREA+gINq4ivsP5JZeCdcU3xd6+GJTYe5w+FVXOo5EeooF8kiyf1c
         ylrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b="e87c/9FM";
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates 40.107.95.81 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (mail-dm3nam07on2081.outbound.protection.outlook.com. [40.107.95.81])
        by gmr-mx.google.com with ESMTPS id r141si291658pgr.5.2021.04.22.01.15.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 22 Apr 2021 01:15:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of jonathanh@nvidia.com designates 40.107.95.81 as permitted sender) client-ip=40.107.95.81;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=Wo69zory96Utknbi2bpOzH+Wc5fqmiU8PCEgEGrxOw8PoDp5iLFqtRlIrWwYWhZckBM7Y77ieVrhQN8hhG5E3eXUZDc/lKsoLAMQpqXoLdw5QnXXjxjR3UQvDb8creUNW7qDiz5hAwqD0OC2Ao1bOAb8orzjK+kFxSDn3Z0gaKjQWWyIGYBsiHhdcD8s+TpM4v8XBOtJrH3GIEo6iE1tG3eu+Rs9ow47lxc0EE7L2kb+jF6tg5TQ7xaPS0TnPHw/MflOQVw8GRb6bw5J+iTqFr63a5voS12pWISq4MPtKfzp/BqmEDKCtzrY8XR8kY82i5+DfruewWsfcsP1mMxfnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck;
 bh=AmrFbzLXqyCvnKwsPoePx5gw9HpN/jnKUZHcl7dka6g=;
 b=W7VAKswUNrC+1B3L5S62JFMycpMw3lfu+TbTg0r7M2k52BUolS5uvpMNbgwemVgmWoPN8Pau9O1EpDVhonIiRmYuBx34E00D6uqwH2HShjklkqZtiyc1YSyrYlUPBHpiN1bcUnE60M91BnRoCmxHs6Jg0dJ+yeAII3nxLnkoP1wynTlCpdVEW5JnUOzQwF2Z92/aeipkZfM2X5f5N0WhKr6DycEDNgngpVemytIDGSGLMyPjMscCpL0lA5uuga0H5/sOYYyTDCHliBM9uqsVoshC2tvfWfO9G0HzGri78Lbh0AQ9ny86WkVJzNcDWux3T4SV+rmEOjW3mQ0hHpPgDA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass (sender ip is
 216.228.112.34) smtp.rcpttodomain=google.com smtp.mailfrom=nvidia.com;
 dmarc=pass (p=none sp=none pct=100) action=none header.from=nvidia.com;
 dkim=none (message not signed); arc=none
Received: from MW2PR2101CA0008.namprd21.prod.outlook.com (2603:10b6:302:1::21)
 by DM6PR12MB4548.namprd12.prod.outlook.com (2603:10b6:5:2a1::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4042.19; Thu, 22 Apr
 2021 08:15:37 +0000
Received: from CO1NAM11FT015.eop-nam11.prod.protection.outlook.com
 (2603:10b6:302:1:cafe::b8) by MW2PR2101CA0008.outlook.office365.com
 (2603:10b6:302:1::21) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4087.3 via Frontend
 Transport; Thu, 22 Apr 2021 08:15:37 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 216.228.112.34)
 smtp.mailfrom=nvidia.com; google.com; dkim=none (message not signed)
 header.d=none;google.com; dmarc=pass action=none header.from=nvidia.com;
Received-SPF: Pass (protection.outlook.com: domain of nvidia.com designates
 216.228.112.34 as permitted sender) receiver=protection.outlook.com;
 client-ip=216.228.112.34; helo=mail.nvidia.com;
Received: from mail.nvidia.com (216.228.112.34) by
 CO1NAM11FT015.mail.protection.outlook.com (10.13.175.130) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.20.4065.21 via Frontend Transport; Thu, 22 Apr 2021 08:15:37 +0000
Received: from [10.26.49.10] (172.20.145.6) by HQMAIL107.nvidia.com
 (172.20.187.13) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Thu, 22 Apr
 2021 08:15:33 +0000
Subject: Re: [PATCH tip 1/2] signal, perf: Fix siginfo_t by avoiding u64 on
 32-bit architectures
To: Marco Elver <elver@google.com>, <peterz@infradead.org>,
	<mingo@redhat.com>, <tglx@linutronix.de>
CC: <m.szyprowski@samsung.com>, <dvyukov@google.com>, <glider@google.com>,
	<arnd@arndb.de>, <christian@brauner.io>, <axboe@kernel.dk>, <pcc@google.com>,
	<oleg@redhat.com>, <kasan-dev@googlegroups.com>,
	<linux-arch@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>
References: <20210422064437.3577327-1-elver@google.com>
From: Jon Hunter <jonathanh@nvidia.com>
Message-ID: <0734b0e8-b4c0-05bb-b90c-de89edb61b5d@nvidia.com>
Date: Thu, 22 Apr 2021 09:15:30 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <20210422064437.3577327-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Originating-IP: [172.20.145.6]
X-ClientProxiedBy: HQMAIL111.nvidia.com (172.20.187.18) To
 HQMAIL107.nvidia.com (172.20.187.13)
X-EOPAttributedMessage: 0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 9d710e30-c035-4cad-4b5a-08d90566cf64
X-MS-TrafficTypeDiagnostic: DM6PR12MB4548:
X-Microsoft-Antispam-PRVS: <DM6PR12MB4548FCE178160AD74170443AD9469@DM6PR12MB4548.namprd12.prod.outlook.com>
X-MS-Oob-TLC-OOBClassifiers: OLM:8882;
X-MS-Exchange-SenderADCheck: 1
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: 0KTlrxID9+XCJ4fyydsUEi9epDHmEVgBvdgfqpG+VnfI+n+qHha2Wbp5v9G01L76nQL0fKDgZOOHKkQKM45PnBCKrDjH0kw7s/NSerUqB0XK9ItMKMLXTQFGBA6bH8AzOoQgw7rGB2UfIBZ37VEDnQhwpu0sIb65c9DSaCXTsDQew8oMI7ez1g0wWhMyV3M9Gk6aD3XJZnPth3egajqo8T/x+LLbQcJzbLvAwFOZBEOa5LSvBkGULXEBCYcoqXEG8WxhN9BfxFGBv+9NE34V0mPF0dvchXhaRnGIz6WXzniEQtsC7JytlMfwUOtU5LTs4KA4qWAv+zmlfu8zE7Ez/AfRcc3gV9P2urSS6RUt9spnmztu8mL3gzmrgDpljul6N8xPIThMyP8iVIdmg3isoS2IyvyFO1oKP0Zo+KY31m0WEmI86WFrN59ZVISDG8SNZTq3QJAtFabuBJZKB1jl2G86oFXJ2Sl6uLeVS2jnN78qnjDUJ7VvIE4AxqJU8Mkz/C7YHm+B0UwjLV9R8s+Rw5yj1HrFSN3VVUZOuC2U0mfJV154rCM38Q4wRyMP0KS5GmsjrpjqAAbw8tH3z3pWk6/Q2CyHOCy/QtPRyr7aJDSNJfUUwynLngqzTBV15px91hYZ1mp8sZTa7ar8JHVWIcXF2asraa+kEIIdlFiLeUvtaarsxY5fniWHPmO0vDqM
X-Forefront-Antispam-Report: CIP:216.228.112.34;CTRY:US;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:mail.nvidia.com;PTR:schybrid03.nvidia.com;CAT:NONE;SFS:(4636009)(136003)(376002)(39860400002)(346002)(396003)(36840700001)(46966006)(26005)(82310400003)(478600001)(31696002)(356005)(16526019)(53546011)(2616005)(7416002)(47076005)(2906002)(426003)(8676002)(36860700001)(4326008)(70586007)(316002)(8936002)(70206006)(336012)(86362001)(5660300002)(110136005)(36756003)(54906003)(31686004)(7636003)(82740400003)(16576012)(36906005)(186003)(43740500002);DIR:OUT;SFP:1101;
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 22 Apr 2021 08:15:37.2796
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 9d710e30-c035-4cad-4b5a-08d90566cf64
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=43083d15-7273-40c1-b7db-39efd9ccc17a;Ip=[216.228.112.34];Helo=[mail.nvidia.com]
X-MS-Exchange-CrossTenant-AuthSource: CO1NAM11FT015.eop-nam11.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DM6PR12MB4548
X-Original-Sender: jonathanh@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b="e87c/9FM";       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of jonathanh@nvidia.com designates
 40.107.95.81 as permitted sender) smtp.mailfrom=jonathanh@nvidia.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=nvidia.com
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


On 22/04/2021 07:44, Marco Elver wrote:
> On some architectures, like Arm, the alignment of a structure is that of
> its largest member.
> 
> This means that there is no portable way to add 64-bit integers to
> siginfo_t on 32-bit architectures, because siginfo_t does not contain
> any 64-bit integers on 32-bit architectures.
> 
> In the case of the si_perf field, word size is sufficient since there is
> no exact requirement on size, given the data it contains is user-defined
> via perf_event_attr::sig_data. On 32-bit architectures, any excess bits
> of perf_event_attr::sig_data will therefore be truncated when copying
> into si_perf.
> 
> Since this field is intended to disambiguate events (e.g. encoding
> relevant information if there are more events of the same type), 32 bits
> should provide enough entropy to do so on 32-bit architectures.
> 
> For 64-bit architectures, no change is intended.
> 
> Fixes: fb6cc127e0b6 ("signal: Introduce TRAP_PERF si_code and si_perf to siginfo")
> Reported-by: Marek Szyprowski <m.szyprowski@samsung.com>
> Tested-by: Marek Szyprowski <m.szyprowski@samsung.com>
> Reported-by: Jon Hunter <jonathanh@nvidia.com>
> Signed-off-by: Marco Elver <elver@google.com>


Thanks for fixing!

Tested-by: Jon Hunter <jonathanh@nvidia.com>

Cheers
Jon

-- 
nvpublic

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0734b0e8-b4c0-05bb-b90c-de89edb61b5d%40nvidia.com.
