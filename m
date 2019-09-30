Return-Path: <kasan-dev+bncBAABBANX3DWAKGQEUV73O6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8813FCA1ED
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2019 18:02:10 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id b67sf3203666qkc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Oct 2019 09:02:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570118529; cv=pass;
        d=google.com; s=arc-20160816;
        b=PHfodup/cDl/C9iDnJTZSox1JyxRJrCfUHbkU7Mt+wPjpNBjwfHEkK4do9xzZpiugQ
         aCMCrU0/rKo32Wz/Axmh/aXfwlWbfM9C7cRDRBrWYVRaiBSMEuu7Ig/vd83R+Q7jtsXz
         dSXe234jn8aBRjo+gOadLKxYLtxPQFWJ/nKZeM2nmAa6bB0oNitpoOTGv+S/5ZnJAlUl
         UnEvBTshz+96k6VfaNxL9CPvei0BmGr9SNmWrxVbyU/BT2SYxaXEkkOVB0k3p6cz4408
         Ld/xSC86KQne3qoIm6i+TwJUDBWhKnjFpU7+ooUXsGwik5VNkk/Inzrd5HPS1K0cc+FL
         J/FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=m0b6aFBpXjB5Ml9D2QAasD62ZUo/HtIWrPXF7DL9brU=;
        b=Dp3AYb5H9sJEuO9WucNUuiTuZpbOcuE7/eHoRn7pzuUZ21lWE69z4YT5VsxH+kwuX4
         GFFiZe1hKKTs/FuHEuxlNbo3pcPxJlq7gtT9Zyj5atxqJVwH9oCho1oeISC6hIqiBSEo
         4CxeC/q9UAojgO+6OpuEHNeCl2gmL2c7EFNIQ7KXTxyEltQvMtiRe6KfflyKk1ZOmYqz
         V0SWiJ0/ymzeU1oORwH2f0GAWj02VHghbAvzr1zUlXdf6uupnmX81WXIGW5ATO7M87jQ
         ImVYriF0Y9I2z0o1Qsrz+tETQs0hTpx6oNiwsBFOhVD/1uxWyhyEQVlL1yG5PWJIWVL9
         +5cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.27.33.1 is neither permitted nor denied by best guess record for domain of marc.w.gonzalez@free.fr) smtp.mailfrom=marc.w.gonzalez@free.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=m0b6aFBpXjB5Ml9D2QAasD62ZUo/HtIWrPXF7DL9brU=;
        b=BZirCTpoxU1MGw4Lb8BkmTPjMDc+l2E7bwZZYyrjVwH33oL3Ff1GvGTa2jNJbGDVJF
         Qpqs2wq5b1Ep/zYjNT3CJTx3pSqJOeeYBO9Dp1ewzQnwb1xpRj54anekYT2GiarJqu2L
         b7kMzx0ZeP0hAo0LS3gwY7zQODiFTyodMOdPL36dYfzPz+TlKM6aheM2bWvKkPXb1ru7
         TcdLgD3DqtO+SZwLJUfkM13nNsVdOprSpOHV1AqIxFfc1fkmxyD7Q+BpMxqFATaOUpon
         raZ+ZwpHPm/Br9abL5+uMkooIF1OiwYeRzN4vSDpoNqF34iee9ro7yPn/qJHYlW0dYws
         HClg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m0b6aFBpXjB5Ml9D2QAasD62ZUo/HtIWrPXF7DL9brU=;
        b=OeQL1SrvZa48RXt4HlotAKI3jG83kDVjxqJk4icuHBzK7jYt7H9jiiXc/FrViRWtVL
         EJc6ARJSBrqd2SL68R9BMkUDitu2Ad8HZ3cUUdt4yInXfVvDGG6WtWVsNqAKk+hykhLX
         5E9LcgKTEUX2Igo1p/W5bNb6XLlIiHs0tbn0kdPliH44ksBjD0mNNED8LY2TtQfpMXMf
         hb7N07/dvsLthdFc3BGWOH0vnqTqvldowDHllwPpBdedbPuQ4roJMQRGNO7ojR5dLQxG
         RJNscuq1oeJb/P4RDqE8jCXxdhIg++8wzhbXDTvOIlRvUzUB952Q/rebP4IJwv3oYDBZ
         YNNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVJVSBzUJy6K/oKcGqxoNxAVvY13zpB/efgELUY/33Zw7PTM6tJ
	maUTJPYq/No3iD96UkXVSlM=
X-Google-Smtp-Source: APXvYqwJXYzKgGITpDsby/DAoy0AbYoWn9jgfLpxVSVTOA/AplCMuSpQJyvv/Aq3yHXro/BNsmac/A==
X-Received: by 2002:a0c:fb43:: with SMTP id b3mr6342372qvq.187.1570118529292;
        Thu, 03 Oct 2019 09:02:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2c55:: with SMTP id e21ls534875qta.1.gmail; Thu, 03 Oct
 2019 09:02:09 -0700 (PDT)
X-Received: by 2002:aed:3689:: with SMTP id f9mr10733824qtb.5.1570118529186;
        Thu, 03 Oct 2019 09:02:09 -0700 (PDT)
Received: by 2002:ae9:f80e:0:0:0:0:0 with SMTP id x14msqkh;
        Mon, 30 Sep 2019 01:57:41 -0700 (PDT)
X-Received: by 2002:a19:2207:: with SMTP id i7mr10732466lfi.185.1569833860919;
        Mon, 30 Sep 2019 01:57:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569833860; cv=none;
        d=google.com; s=arc-20160816;
        b=AzmLRTalV1bTUSMQkb/klM0Znd4gRvoSsSQ3/g5W9fa1m0qNufZyUqAalXUomKIS7w
         d0HWjXKpkz4D6BbfZNmbgyJBSWs9UjKxizhSsrwPxnYoFCdjTdwx12zuvDEuVVLi2xdN
         M8dbWIa4tjHyLVJtKSDYKfThP91iDojCw6uA8VAQhGMoU7gEzYuA+IcqQAVBiVQd987x
         Bb+F1ADrV3fBTkfMs85SK7g+BQfRS6HHY6WcGt00FV2sNtDJVgjx3QkvpJoGivm4g0F+
         XD0yx1OfXHRfXkvOieRXa7E7niqCzYWQVSa7LLnci38fVsXMo+9Ke/wZnSULlKsIS/g5
         c2WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=mgLLwzKeGJEt8dy/bBZPEztvUg1OpWUVMz/vD9hzvdo=;
        b=ifMND2hSpoanTykULW75TNef7hHrD4zqhUVMnzVI5R4RZ48MFJAar/0tJU460tx2rL
         FTTjoy4OicRu1mv4DH6dF7ZjGyA7jnI+zM636+jOnH8hGaom5YQ+fcaiV7+emMI1n1bM
         Eo/BTWMxOL2zPG9RxjiP1ZVGoeTmiaP664Jwgrb35x7ZrEowCu3IEE1KgIYtMUTBZc5m
         mcFNMjTmztGoOVlDdJeeRpraXF745hCyfzvn7wy2LJlp3j3pnOvW62RRjz1rqOd49rTx
         DftpHqakLxrWsv13L8BtCLDIrWr7itHk41Ak0s2MRHLMu8nctlZrXse2nTlMkokadDcW
         rpcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.27.33.1 is neither permitted nor denied by best guess record for domain of marc.w.gonzalez@free.fr) smtp.mailfrom=marc.w.gonzalez@free.fr
Received: from ns.iliad.fr (ns.iliad.fr. [212.27.33.1])
        by gmr-mx.google.com with ESMTPS id o30si649604lfi.0.2019.09.30.01.57.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 30 Sep 2019 01:57:40 -0700 (PDT)
Received-SPF: neutral (google.com: 212.27.33.1 is neither permitted nor denied by best guess record for domain of marc.w.gonzalez@free.fr) client-ip=212.27.33.1;
Received: from ns.iliad.fr (localhost [127.0.0.1])
	by ns.iliad.fr (Postfix) with ESMTP id 5FC0020289;
	Mon, 30 Sep 2019 10:57:40 +0200 (CEST)
Received: from [192.168.108.37] (freebox.vlq16.iliad.fr [213.36.7.13])
	by ns.iliad.fr (Postfix) with ESMTP id A431320274;
	Mon, 30 Sep 2019 10:57:39 +0200 (CEST)
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
To: Walter Wu <walter-zh.wu@mediatek.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Alexander Potapenko <glider@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
 <1569594142.9045.24.camel@mtksdccf07>
 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
 <1569818173.17361.19.camel@mtksdccf07>
From: Marc Gonzalez <marc.w.gonzalez@free.fr>
Message-ID: <a3a5e118-e6da-8d6d-5073-931653fa2808@free.fr>
Date: Mon, 30 Sep 2019 10:57:39 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <1569818173.17361.19.camel@mtksdccf07>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Virus-Scanned: ClamAV using ClamSMTP ; ns.iliad.fr ; Mon Sep 30 10:57:40 2019 +0200 (CEST)
X-Original-Sender: marc.w.gonzalez@free.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.27.33.1 is neither permitted nor denied by best guess record
 for domain of marc.w.gonzalez@free.fr) smtp.mailfrom=marc.w.gonzalez@free.fr
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On 30/09/2019 06:36, Walter Wu wrote:

>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>                                 unsigned long ret_ip)
>  {
> +       if (long(size) < 0) {
> +               kasan_report_invalid_size(src, dest, len, _RET_IP_);
> +               return false;
> +       }
> +
>         return check_memory_region_inline(addr, size, write, ret_ip);
>  }

Is it expected that memcpy/memmove may sometimes (incorrectly) be passed
a negative value? (It would indeed turn up as a "large" size_t)

IMO, casting to long is suspicious.

There seem to be some two implicit assumptions.

1) size >= ULONG_MAX/2 is invalid input
2) casting a size >= ULONG_MAX/2 to long yields a negative value

1) seems reasonable because we can't copy more than half of memory to
the other half of memory. I suppose the constraint could be even tighter,
but it's not clear where to draw the line, especially when considering
32b vs 64b arches.

2) is implementation-defined, and gcc works "as expected" (clang too
probably) https://gcc.gnu.org/onlinedocs/gcc/Integers-implementation.html

A comment might be warranted to explain the rationale.

Regards.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3a5e118-e6da-8d6d-5073-931653fa2808%40free.fr.
