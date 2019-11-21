Return-Path: <kasan-dev+bncBC5L5P75YUERBUE43TXAKGQE2JJROXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B6BFB105C98
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 23:23:12 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id j3sf2626095edt.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 14:23:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574374992; cv=pass;
        d=google.com; s=arc-20160816;
        b=tKIBo3lLvLRt1ZIsNPJpFhuLj8cWk+PksuKEuNFlbi2hHZWt7RR9vDhDA705fF7F4l
         aF+bhKWRxMqNyIOPj2y6dHjKCZtj5Losk8CpseRUWREmOyFQtmD7YQWoXnuVxnxgc2Tp
         0La/REHl9V0tfJW8PawFGCsMhF0cqa00kfQvP6+ko4zA/Rp4/CZzyJRAiUycmNf3B3mO
         +e854CRdx7/6u1MQ3BiJAjHwdoGzjUpWTSXWt1WZ/BCBBtzTGgnkhk6J2otTKvOwcPnN
         C5rJe+R9TcZlZ56lJtf7nIccrzK5UNXLkFaZuiJmeAxbZa4yh59vgEhUjxEH9wF7SRcW
         908Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=jX6OeobOpBXjS0VkQyjK4XnfGVvDflWYheJf+mpMK14=;
        b=rBMxvTEyNU9MexxLuhcrnrS1Cb1UYNj3JqGcSIlzE6ST48DFPhut1p6BkuHjV3e3Gl
         NfC27LdIh1+DG6giIRy2vkBFJwNhgyqBPA+5ae7IDEJypyjWOzD4HnSSqMGIXWNCodgw
         Qcx4S6HD41O5223skVGWrJV7fMtO2K7/pudv3XqBJulv2tYsCjNh3MaaUw3G2WTsQYEq
         EfRSD9zRrXBrZNpXeEDJhUAr/D82sG0vgFQMkXFIHsJwUUUkXuBfa+w2t3Mm5EG1egvA
         Qud6vaZ/EChxAca5eDams8eCTxiTNGQkDCcKTGSDQXQcqDbuNm/LcMkpA1sNngLlFz0B
         E3Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jX6OeobOpBXjS0VkQyjK4XnfGVvDflWYheJf+mpMK14=;
        b=cFryOJC/fF4XnJ/kCaIDZ8U0xppq7gKXK/kP6XSLkPKl6pgqkL6lI/1B2yHHCIihO9
         4GZHQ2t5v6HWYnpvVreoXe1co+fyS5NuGD4EajTG33FJIzq+apX7rRtyuqMjVSqABVQi
         WFeX0VRS0SzFRSMwmxuO9ERRatbO5n2kj4sxLqPDp2IP9z0w20/YdhmgK/7bIVAI0IN7
         0a61Pls/QPxcoE3qHuBPVOASL8+OUmdjK/enRQO5bb9u1bTUourOo/6K4Lng2FATX1su
         FKi4CV6AxrJRu11UC049F23DsT4jhyab/+BTWcc2r+huuWStyGJj9Pm6bq/ic6IDSKff
         Y97g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jX6OeobOpBXjS0VkQyjK4XnfGVvDflWYheJf+mpMK14=;
        b=GB3lYvrIJgw/+uDnMcjtsNXH2hpZMyFiYXGVJyH/VMzL2fKes8WKR4XmGkAy5VTUBs
         6Utz2AHuLzJfolV8Vds0fEzSzO2G/42H5vnjJk1riSdVNnHgztA1LMYGiUoSqy7VhWex
         0C681kTubvyBVurwZHdXZnBxWBjye6kSBVcwQUlhJTRSy4oc37ZvEi/RU7ka+7jS149f
         dlWMLaoFWR0x7KZdmRufPxAchBvds4rzwl7/WYtFevb1nAsBxqowJvTWS15XrP+2hLLf
         QuJhNuwENDnHeJ6Fd/JZ6DmjQL0Q7YzugfINzsalEOolkG/sJzTQjoa+7qlkhQL3G/3l
         fNhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV3nox+V9BfuLwnulVMHMA2KOCgSc5QXIRw/OQmeECL9jE8ndZi
	hLlGk1YObIcA/gsgl5FF3ic=
X-Google-Smtp-Source: APXvYqwzcf4khMtc+IIPl2dSOeU4UrLGa/z0qfncGI6zJggUoV3Fg/9hRG7pWPZPYsDiCc3oRxKtGw==
X-Received: by 2002:a17:906:52d3:: with SMTP id w19mr17227903ejn.268.1574374992418;
        Thu, 21 Nov 2019 14:23:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a17:: with SMTP id w23ls3175334ejf.11.gmail; Thu, 21
 Nov 2019 14:23:11 -0800 (PST)
X-Received: by 2002:a17:906:1d41:: with SMTP id o1mr17195485ejh.333.1574374991952;
        Thu, 21 Nov 2019 14:23:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574374991; cv=none;
        d=google.com; s=arc-20160816;
        b=ZUDGzzpQxYyEgIzwc13tdCNsiQZoGNWJL9m/wXPbZBvHwe3uNxD7niCjfH+h/MGUr6
         +FpELoIu/xIyej4TBn+FMdLDSicdL0HDQ8htc/by0JwR1KAoFtK9LUMsueieWmwXZu3c
         MAsUhcKk8Fgo2q7Z7moJYptvR87Zm4VusIE2beQ49/as3sSHugjirBp59D0g7b61/ShL
         U77D00SPoXHfwzfqcOb4276ybkxsAXMgXcKXzHgMi/6utlTGxn+sTNcs09rB2CCSU/rX
         pYF/rOsB5lmzugJfsnyp5IxBfZuIkrwQvY55WPuIsZTVlENH10mIZ//szfZV30p8uN2u
         hwUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=gIww5Y07vN6W+V6n3azwLcMFkSweWNQ7zQvPEI8IlH4=;
        b=rPT0D1skg+Pi/8MVIUEFTLe6nEoSNBes5WZAC7KOpz5bhreSTIDcDMOIRQKTD1fIZE
         30abNof9B9l64h7NdiwEniEbDfC+WYSkw+wmz+lP3fzjAbLyz9TQ0poxTniC/bfTqo/J
         Slzkt9i11LbYHsZ9a2iDG/p9Ny7t+BLGubuPMFBc0wuZcKlOKDVw8/x5ScmskZOCXT1e
         4LFfcfOc1g1m74OQUJzXtGzeA65eM+uDX13MJmTdOzowGhqh2UgzwneR7vmkA4XUrNF2
         gBEV/Rm/BwcwwDfYUQH1LVWwot97TCAtcjBZtS/zumh9GUhsyCTPTcVcQLlsz4ggUXZG
         7TdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id l26si193217ejr.0.2019.11.21.14.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Nov 2019 14:23:11 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [192.168.15.154]
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iXuqu-0007wC-R0; Fri, 22 Nov 2019 01:23:04 +0300
Subject: Re: [PATCH v4 2/2] kasan: add test for invalid size in memmove
To: Walter Wu <walter-zh.wu@mediatek.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>,
 linux-mediatek@lists.infradead.org, Andrew Morton <akpm@linux-foundation.org>
References: <20191112065313.7060-1-walter-zh.wu@mediatek.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <619b898f-f9c2-1185-5ea7-b9bf21924942@virtuozzo.com>
Date: Fri, 22 Nov 2019 01:21:17 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191112065313.7060-1-walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/12/19 9:53 AM, Walter Wu wrote:
> Test negative size in memmove in order to verify whether it correctly
> get KASAN report.
> 
> Casting negative numbers to size_t would indeed turn up as a large
> size_t, so it will have out-of-bounds bug and be detected by KASAN.
> 
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/619b898f-f9c2-1185-5ea7-b9bf21924942%40virtuozzo.com.
