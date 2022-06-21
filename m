Return-Path: <kasan-dev+bncBDY7XDHKR4OBBJ7BYWKQMGQE4M662TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id CC24A552B99
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jun 2022 09:18:01 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id c8-20020a9d67c8000000b0060bf699241csf6826505otn.16
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jun 2022 00:18:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655795880; cv=pass;
        d=google.com; s=arc-20160816;
        b=dhfn6je7VBH9O1n8z5IQ+DguSTW/qDPoZQshyO8xp/j1VQfLYW1sHZlQnFWaHNzFdR
         v4U4ECGkOy9vMY7Npk0pUweiwj0OLOlSyc62RGKrVvNLPPTlExV44JCtMha5ot7FR71r
         z+zkdrfa7BiFZnd409HK2ttWZObQ+uVcTjk+1AnNvTWa8vcsdC2OmYV1VpR9XUqjKGN8
         xQWWkgRYYyZRDJo7mleb98g4jqieuSuAEUXv8QJrmsD1hzQlAn3EuLYOApjpY9caRGb1
         icmCzcXFIdQ5oBGK82GtBTmgSNeE0roFRBJCM+r+Evga6q7ecyggtcsN3h4F2NPmEYy1
         7RcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=G01XjkLR7s1UO69KMcmw8OPLVox8bv+p4NhoY1SxEKo=;
        b=hOtacGBzYexggSyifd/3+eWlYZGejF83qLKIZ9Z0MBFS47DFnGVwfHbrM2UoscgsCP
         blgmEi0NyVRimnUnFDhON2oOiOhPA38kepmLwnII83ej1H4tTvgnwh6OiQNQFBcdhSwr
         YnYUI9r2fjOIllKvyjWw2/ImcoquwjmCULLFVMSiUtJuK0qSTRlVmmHH4WLGfMit03gJ
         lk37nfaLxjCjKJnD5Px3y1AlAZszdNlrtvtFozBCZxYxXP9jDtA+Gv6PYS7pTYSfUjTS
         /SvMu2WA8R9DILi/GRM/qTxGQeWYnoSnKZEa1F85jFC0A7MhHGwot0A0ZKHVf8vY1AZW
         bFgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=G01XjkLR7s1UO69KMcmw8OPLVox8bv+p4NhoY1SxEKo=;
        b=jQ6iZKYpfbVicqJs8gRC+luYPf7uRJI5fQsnlAi2JmwGZLbr9eXNDWgwXZuc48FvJw
         cdfhavSI7zZK/q+p7QzEvxAGIkYHxDR3SgSZaZDdDOC/iNhPNIB11j5FkySW9iKaXe7Q
         WveIJut2mYlcVyrq4LDgyElJJBJq8jy0l9patTfS/JBqtBarJ2k3o75wuhroGPzo0aTU
         ExzKteRNyilY7Z3MQnwAnseDmRJwX/UFdVGd1dlfdPCdLmbQnkV8Je/O1hySwqG5Whum
         HHdPMoq0VaG3UOzQy/ndD8YnREkWkxodIrbkSvj2youRZB3XS3Bxf4sJmrT5gdEVQHsm
         +euA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:subject:from:to:cc:date:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G01XjkLR7s1UO69KMcmw8OPLVox8bv+p4NhoY1SxEKo=;
        b=Zm2+l/HRgjNmUmc91X7OFQMokuBYPByG14qdfzWvDDFHyL3QV0FLXpH1rm/T3gB10m
         C1PSaoyfHbLktaJgnQ9LQgvCicVNz+QCDaBGmoYsccO+R4OKZ6GLu3udbbS2oSJ7pzRm
         CNYsZJ6N+ACmt9h2mC1d722RFAudzpCdeDBAWWXJQe8gIOTHqkWXGvaVl0qxXvQiiJuL
         DqDgd/niYoP7y8AO/WlafNVB/quPfj+QpN/suGModqmTfMFw/ruHQn4eo+8ypy6R7ykS
         DV2Kar8BKU7f4BLy3+uMr80V5BaXVNvLg03eqPImEWyuuIaFcK056uYtNJf7PZGC3cev
         Tfbw==
X-Gm-Message-State: AJIora+gR5+/IrQPUShEAEdnx2x7jmFTcHmhVy27diZ76yyep0xmMctW
	d2YeEy3wnVLAi6LUKsXitic=
X-Google-Smtp-Source: AGRyM1tDnbULfSdjQd0ur65UrmGAQVf6aNynm0id3FjjvhdFKfAs5SkomnR/iRFa3F50Fd+013dkYw==
X-Received: by 2002:a05:6870:d59c:b0:101:7e59:d723 with SMTP id u28-20020a056870d59c00b001017e59d723mr15827865oao.165.1655795880023;
        Tue, 21 Jun 2022 00:18:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a9a4:b0:f2:dc5c:8024 with SMTP id
 ep36-20020a056870a9a400b000f2dc5c8024ls4875514oab.0.gmail; Tue, 21 Jun 2022
 00:17:59 -0700 (PDT)
X-Received: by 2002:a05:6870:9586:b0:f1:d7f9:f0da with SMTP id k6-20020a056870958600b000f1d7f9f0damr19620785oao.259.1655795879492;
        Tue, 21 Jun 2022 00:17:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655795879; cv=none;
        d=google.com; s=arc-20160816;
        b=NTW70BzCFD4hMzbEKRPUzHof2nXZxLHW57Zy9cn7wJrBfx/UZ/3jG1KFO5uIVl1Vpn
         bnXiZboNriDOeITTUG/JDoGTVsWC/rvQgKOoQDGQS2WFKIdcc8MqDtaFEWJ9Grc651jT
         ncue0wJU50g9vuKfMIhwQ6DSvg3DxD7Wy0aKb02MTQrYQDfKdlCjgqke/lkZS8IZp5hm
         y/uE74q1O5/aGKovcs6A0kiL6vsLVymFv77NqUCZrFpU3mpb0D12rWNcfvgIhXagBq3x
         6gJmt9Xk/Nfgm800W04RVeaWu5HrrV6FW8ha7z2Tsz0qgAt1w9ybN+F7CPR3DbGHTB7C
         SZeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=DJ/mLScYgkYxk9E1YtLasukRocJZ/IoTGvxSUZS9gXY=;
        b=GKhW3Z/dORAYpPuvOJ7TGouM83SAsKR6xMLfeTaWSa3JKsu3H8jVL87F7O+9UZ/phg
         749q+HGZ8bo4TnT7y8uGLOXJ+tdrFuTTOg3ReqowLouzGyLMIKAeq+lAMPJiY++SYdsQ
         Vm0q7wuEILTZKmbhcTq4fQcRyLtm4SDjMgg4cl4GZ0xGMPApjx88faHE2AjqxfDm1Udb
         yByUQ1al75tAiA2ZuR11tIQEeZDo2zTEFJmV57Mw4bME5I2Z2Qc5xj3BVpvbaEb5xM7m
         jFtQCCnQFrDb19wqovKpYgMJjVNTPPT4JsRpFB6BHSw+LXaolaatkSos3zNDVW8NFRbb
         f4zw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id l18-20020a056830055200b0060bfeb3a0c0si732067otb.2.2022.06.21.00.17.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Jun 2022 00:17:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 073fb03cba0f492da81bfb9d16a26fae-20220621
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.6,REQID:f4cf376d-e335-4209-9b4a-1699ca9b5cce,OB:0,LO
	B:10,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:51,FILE:0,RULE:Release_Ham,AC
	TION:release,TS:51
X-CID-INFO: VERSION:1.1.6,REQID:f4cf376d-e335-4209-9b4a-1699ca9b5cce,OB:0,LOB:
	10,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:51,FILE:0,RULE:Release_Ham,ACTI
	ON:release,TS:51
X-CID-META: VersionHash:b14ad71,CLOUDID:278e16ea-f7af-4e69-92ee-0fd74a0c286c,C
	OID:801f2789e3b7,Recheck:0,SF:28|17|19|48,TC:nil,Content:0,EDM:-3,IP:nil,U
	RL:1,File:nil,QS:nil,BEC:nil,COL:0
X-UUID: 073fb03cba0f492da81bfb9d16a26fae-20220621
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 866569992; Tue, 21 Jun 2022 15:17:53 +0800
Received: from mtkmbs11n2.mediatek.inc (172.21.101.187) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.792.3;
 Tue, 21 Jun 2022 15:17:52 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkmbs11n2.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.2.792.3 via Frontend
 Transport; Tue, 21 Jun 2022 15:17:52 +0800
Message-ID: <5949bc710889be1324d5dada995a263fd3c29cb5.camel@mediatek.com>
Subject: Re: [PATCH 21/32] kasan: simplify invalid-free reporting
From: "'Kuan-Ying Lee' via kasan-dev" <kasan-dev@googlegroups.com>
To: "andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, Marco Elver
	<elver@google.com>, Alexander Potapenko <glider@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "Peter
 Collingbourne" <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Date: Tue, 21 Jun 2022 15:17:52 +0800
In-Reply-To: <f7f5cfc5eb8f1a1f849665641b9dd2cfb4a62c3c.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
	 <f7f5cfc5eb8f1a1f849665641b9dd2cfb4a62c3c.1655150842.git.andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Reply-To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
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

On Tue, 2022-06-14 at 04:14 +0800, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Right now, KASAN uses the kasan_report_type enum to describe report
> types.
> 
> As this enum only has two options, replace it with a bool variable.
> 
> Also, unify printing report header for invalid-free and other bug
> types
> in print_error_description().
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/kasan.h  |  7 +------
>  mm/kasan/report.c | 16 +++++++---------
>  2 files changed, 8 insertions(+), 15 deletions(-)
> 
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index e8329935fbfb..f696d50b09fb 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -146,16 +146,11 @@ static inline bool kasan_requires_meta(void)
>  #define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW *
> KASAN_GRANULE_SIZE)
>  #define META_ROWS_AROUND_ADDR 2
> 
> -enum kasan_report_type {
> -       KASAN_REPORT_ACCESS,
> -       KASAN_REPORT_INVALID_FREE,
> -};
> -
>  struct kasan_report_info {
> -       enum kasan_report_type type;
>         void *access_addr;
>         void *first_bad_addr;
>         size_t access_size;
> +       bool is_free;
>         bool is_write;
>         unsigned long ip;
>  };
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index f951fd39db74..7269b6249488 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -175,14 +175,12 @@ static void end_report(unsigned long *flags,
> void *addr)
> 

Hi Andrey,

Do we need to distinguish "double free" case from "invalid free" or
we just print "double-free or invalid-free"?

I sent a patch[1] to separate double free case from invalid
free last week and I saw it has been merged into akpm tree.

[1] 
https://lore.kernel.org/linux-mm/20220615062219.22618-1-Kuan-Ying.Lee@mediatek.com/

Thanks,
Kuan-Ying Lee

>  static void print_error_description(struct kasan_report_info *info)
>  {
> -       if (info->type == KASAN_REPORT_INVALID_FREE) {
> -               pr_err("BUG: KASAN: double-free or invalid-free in
> %pS\n",
> -                      (void *)info->ip);
> -               return;
> -       }
> +       const char *bug_type = info->is_free ?
> +               "double-free or invalid-free" :
> kasan_get_bug_type(info);
> 
> -       pr_err("BUG: KASAN: %s in %pS\n",
> -               kasan_get_bug_type(info), (void *)info->ip);
> +       pr_err("BUG: KASAN: %s in %pS\n", bug_type, (void *)info-
> >ip);
> +       if (info->is_free)
> +               return;
>         if (info->access_size)
>                 pr_err("%s of size %zu at addr %px by task %s/%d\n",
>                         info->is_write ? "Write" : "Read", info-
> >access_size,
> @@ -435,11 +433,11 @@ void kasan_report_invalid_free(void *ptr,
> unsigned long ip)
> 
>         start_report(&flags, true);
> 
> -       info.type = KASAN_REPORT_INVALID_FREE;
>         info.access_addr = ptr;
>         info.first_bad_addr = kasan_reset_tag(ptr);
>         info.access_size = 0;
>         info.is_write = false;
> +       info.is_free = true;
>         info.ip = ip;
> 
>         print_report(&info);
> @@ -468,11 +466,11 @@ bool kasan_report(unsigned long addr, size_t
> size, bool is_write,
> 
>         start_report(&irq_flags, true);
> 
> -       info.type = KASAN_REPORT_ACCESS;
>         info.access_addr = ptr;
>         info.first_bad_addr = kasan_find_first_bad_addr(ptr, size);
>         info.access_size = size;
>         info.is_write = is_write;
> +       info.is_free = false;
>         info.ip = ip;
> 
>         print_report(&info);
> --
> 2.25.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5949bc710889be1324d5dada995a263fd3c29cb5.camel%40mediatek.com.
