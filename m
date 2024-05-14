Return-Path: <kasan-dev+bncBCHI74ELZABRBBNOROZAMGQEQM6FUYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A1328C4B69
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 05:14:15 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-de604ccb373sf8471091276.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 20:14:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715656454; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gv4TvRCfloR3W8qhM8lhrvYVHrfyo/FAFwdFFvr2RuLz5BeJgzfvU16elLIgTzDAhL
         ITSvHOXxaSq1k09hC7MH1C1VdQwkuIMQGUkbC7EG8NOIQdnm2mzAmJmXzEqUSW1+T4Y/
         F/u9DNrbtotjkmlJoCYyYpDIRP59NwFFrfIgPpxGB+IKZYFrqPfLqg7kBypTMG5+P4xh
         rBIeKjss0CZlzLGsjOocCNMdNv2xO4GHpd2RWLCKHWfUYlCRJYJkGmN/2z64k5iewOYR
         K/fguKTC3reXS2mp46djY7c1fqVr340LwGJeNb0BbCT6q2J7sNx7viQJ/auscylgQWj5
         n1Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:dkim-signature;
        bh=IuGDeDIGoDUqVIkTJ+XpNA2qNj2HsyW2hvZ/TQLFL/8=;
        fh=NpkKs+5I7kRWHuGlEpV6Fo5wdsK4sowcRDIlOLWV9VA=;
        b=zw6Gg1vCS2ju2aYZflXigs8edSHokBes4NSzlf8PrPo++HOgJMNkIjGt+YK9371pZ/
         1Ido3UfZjgsJVlinSth4LCmBqiWhn3TFdyKTlm77wgk3i31WUeVT6NRLAaj2Ktr5ZT55
         /S3r7TiAhUAPmhV155JCCOFeB/d76W8zRwO72R0isQxpcZpb2s273DVFap14nxv26S5L
         ltsCrPlN6S0aoxlABeVvWn6VMq5Um2TjIxwuHO4qSG4MRMd2qCpo/zVQP0O9xxmESyTW
         gIZBLN27DE1ymfmjMlSf7woknZMr0veS9Xy1tc9FdenWnfAvKCLSw8Fxmcc0E6bXIZHG
         59Lg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of linmiaohe@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=linmiaohe@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715656454; x=1716261254; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IuGDeDIGoDUqVIkTJ+XpNA2qNj2HsyW2hvZ/TQLFL/8=;
        b=ZJ8V/HjkJ0NjZ8n5vpWTP5F5K8TAYI18ovSfSsmL6JEBaV6VKFZ4JXfz8EHwlkr3OF
         1W3KGDLRxURClVKKAvaZYAjcWXSjT35Yg7katWmVKPjieqcooh2Sk1cHNLf6WfCcwz19
         wl883B+B1CpNy+oSZIkUvs/Pclo15nudU8dfVDIzaJfww7n5n8awHy3hvOuyu72346bp
         OEYiQD5oesRz9/1lecTzMVWFpYYVfHWfeOzXABvKVf8NKGbtFBNJyvdrdngaGHk71sKT
         YGa38MWkhBejnVWhNKcweqGn+F4luDxFqypKt4OzbmuQH/MGNz5H0n4TL4t0uaP+dlnl
         jqKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715656454; x=1716261254;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=IuGDeDIGoDUqVIkTJ+XpNA2qNj2HsyW2hvZ/TQLFL/8=;
        b=h2yu9Kg205gWz21tg7t7Td6UH3BzD7H1oaSIEWvIJloLRReA0sKcWPaAjYd3C+sIXX
         QSm4+vup/da3o3lwh4nhcQ11YlQRIrS8jsh7mx4pL4Lpgz+qDuijjFYN+mfmnApCfOHy
         1cPuJlvbwxsjxDpVCBCx+3N/7PKzOFZ0npNwizzpYbcXy85Ma3KR1tPYlkQ/ZbfRL5tH
         9q/2Rod4EeC7R3ZJoIG1sq8CXjpeEwQtxiPexT71vr+WuUxMxSLXDBM3gcYxjh394Xts
         xoVnJmffcDY6Jx56CcXtyPffVWcK8XAga6gG0/HVtYQ85pUk3JiICTR4L9He21xxnGGV
         K0mw==
X-Forwarded-Encrypted: i=2; AJvYcCWUF3AVRodLoxRPzTzzhEQvFHdmJR9REVrH/inH/eQGZVuR7eJFg3S7737lWvxwWHeVD1lSL3+J3koF30cnpmN+Jul/sJJhJg==
X-Gm-Message-State: AOJu0Yz/AwnmZ+5Ko3+uJYzuLQrZo2UiK/NeoykTTknEojiWYz5rAoPP
	O+OGIU0wQf2TUBmm/ATKoJBuYCn+oPA7r+q6Ipf3vAKIynZkj55x
X-Google-Smtp-Source: AGHT+IFSDz1vya+5JB4GtvBPXVO4T5MAaoaFq0pJkYrLa8dSc4dxnVTfzJs089ZMKLFTQa5SociXuw==
X-Received: by 2002:a25:dc0e:0:b0:dee:8af8:c374 with SMTP id 3f1490d57ef6-dee8af8cd2fmr3811571276.61.1715656454078;
        Mon, 13 May 2024 20:14:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:a2c7:0:b0:dcb:b370:7d13 with SMTP id 3f1490d57ef6-dee5c9007bdls4348236276.2.-pod-prod-04-us;
 Mon, 13 May 2024 20:14:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVck4tuq7IP1cnOjDdf3Nj0b6vtJJJ7Uql/wyTZIrf7+RGPlOog8EwUJCBblHOVggeAXxXavHP3aD5iXRiALklCZRq/Xu7oZ5AEPQ==
X-Received: by 2002:a25:c7d1:0:b0:de5:9d13:48ac with SMTP id 3f1490d57ef6-dee4f2f6deemr10842309276.5.1715656453204;
        Mon, 13 May 2024 20:14:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715656453; cv=none;
        d=google.com; s=arc-20160816;
        b=Hmncn4Zp4uEnMSX+XnF4b+xz/Elst3xYbChoxHrFdWqCVc1//liNNk+SDtodH5wljW
         iME8AvcotMPE5jnRp/sURlHRPvXB77rOEKx4vGS4si7y3w26t16mm8v50PokSQdPbHw3
         Ik7lLs7X2y5bHaf/bF/lsJqGBGsOanPkpxhqqP9CkRKDuMhwP79TfTDw3gg/Z6kxtpj6
         4CTOoFx8220jVtVx10meQm7EEIym4yMJ193Sv1CJ1HPFsAN24spYiFq/bpMPQGcIzfxR
         jv3t2QkAcOr6K4mbdloCnoP9sw9JPuQKeN/UvN6uF+Ue/PqHPoApqOrBy/+chEsUPjX5
         Shtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=nDBHbsvE12wluIpHNBZpri0ZuNTmkl5ppgd5I+oGwFE=;
        fh=fEY9FKKYjCjXU2OYu/DJl24bw5Sb8po9NHdVUCtk37E=;
        b=K+2jwkdUlHbg/K2GtGiNtJB1BEH82FLR5aRIREiQrIEfm9n1GylBkSQ/wprlzBo3pQ
         9xVWBP6tnRFvGOX53ZSeYQlCCS+LP3PsXywxH63XaILN0MYxcU3711P+Z8EXZ90PHL87
         2vrdcOkyYpUX9gl+AC4x9u3gAXSohyGoj9VyA8KPl4pVVr1QnuHpMyDtghuArUy+uOR+
         5pDy/Eaczydu+Y604zRxVgX2X3B6s2WaY0J8KfeCXh696A8iNcSxYG1KUsY/WQgNTMk6
         MdPKRhAbKUk3DZWqEJi24j7isLcJT4hqZ7QvmMf6EwjYsN4hjCaJOBP+DDJMSI1H1cho
         24wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of linmiaohe@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=linmiaohe@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-debd38b05c9si508284276.3.2024.05.13.20.14.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 May 2024 20:14:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of linmiaohe@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.88.194])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4VdhFG4HLpzvYT1;
	Tue, 14 May 2024 11:10:42 +0800 (CST)
Received: from canpemm500002.china.huawei.com (unknown [7.192.104.244])
	by mail.maildlp.com (Postfix) with ESMTPS id F2CD014038F;
	Tue, 14 May 2024 11:14:09 +0800 (CST)
Received: from [10.173.135.154] (10.173.135.154) by
 canpemm500002.china.huawei.com (7.192.104.244) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.1.2507.35; Tue, 14 May 2024 11:14:09 +0800
Subject: Re: [PATCH 1/4] mm/hwpoison: add MODULE_DESCRIPTION()
To: Jeff Johnson <quic_jjohnson@quicinc.com>
CC: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Naoya Horiguchi <nao.horiguchi@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Minchan Kim <minchan@kernel.org>, Sergey Senozhatsky
	<senozhatsky@chromium.org>
References: <20240513-mm-md-v1-0-8c20e7d26842@quicinc.com>
 <20240513-mm-md-v1-1-8c20e7d26842@quicinc.com>
From: "'Miaohe Lin' via kasan-dev" <kasan-dev@googlegroups.com>
Message-ID: <27d7476f-f0c4-b8be-0b62-b1740be5dbe9@huawei.com>
Date: Tue, 14 May 2024 11:14:09 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.6.0
MIME-Version: 1.0
In-Reply-To: <20240513-mm-md-v1-1-8c20e7d26842@quicinc.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Originating-IP: [10.173.135.154]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 canpemm500002.china.huawei.com (7.192.104.244)
X-Original-Sender: linmiaohe@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of linmiaohe@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=linmiaohe@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Miaohe Lin <linmiaohe@huawei.com>
Reply-To: Miaohe Lin <linmiaohe@huawei.com>
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

On 2024/5/14 3:37, Jeff Johnson wrote:
> Fix the 'make W=1' warning:
> WARNING: modpost: missing MODULE_DESCRIPTION() in mm/hwpoison-inject.o
> 
> Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
> ---
>  mm/hwpoison-inject.c | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/mm/hwpoison-inject.c b/mm/hwpoison-inject.c
> index d0548e382b6b..7e45440aa19c 100644
> --- a/mm/hwpoison-inject.c
> +++ b/mm/hwpoison-inject.c
> @@ -109,4 +109,5 @@ static int __init pfn_inject_init(void)
>  
>  module_init(pfn_inject_init);
>  module_exit(pfn_inject_exit);
> +MODULE_DESCRIPTION("HWPoison pages injector");
>  MODULE_LICENSE("GPL");
> 

Acked-by: Miaohe Lin <linmiaohe@huawei.com>
Thanks.
.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/27d7476f-f0c4-b8be-0b62-b1740be5dbe9%40huawei.com.
