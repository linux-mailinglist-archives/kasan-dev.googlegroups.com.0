Return-Path: <kasan-dev+bncBDQ27FVWWUFRBFPTRP2QKGQET5FKVFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 645031B7867
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 16:37:11 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id p23sf7281909ook.9
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 07:37:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587739030; cv=pass;
        d=google.com; s=arc-20160816;
        b=sTOjSvVrbkh1g+HUYSn8+vliW9Pol0Mv/8NY+o2OfSJIopgWtmrHMs5Og75lnhnAVH
         7IGoHOmxkBAIg05BOefH3qHbtryF7pTT2exGOdyunipxczvL+jcmdlHiOyWQht6MD9ej
         eLEaVuoh8BnGKDh2+xVsSI/qujEJwYTAsgSLXZ6259bJnzqsQMFFk61tBM9/LRsAw9zi
         mOD9s1OdiAmIKZSo+uu0M3Dtbu/pEkuJ2pzien7jr/8BYG6xBEBoKMGOsYHf1/1VIGhv
         tFMFmkPt8yIlcYexPpcI4V1wZT7rblrqj7ZpeozXheMLD8IKby1COyBmJ84FhekxgTuG
         pRxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=OIJfhAMgzm7CIOcYzTaIFC+EPRozFrKNK8mptLxlDhw=;
        b=Dq3/3q4X5Y6B2ljKilcWenIG0f8C2R+Fw7WLCPTW6iRiGSOXBp85RRr4dQ427mCTNu
         2Rfjzdq7GrUJChoSHK10t6syH70VYs03MnhBuwlqo8wYzEoqWGivDF100U0JcLgw8Yed
         rbuK+tuKWGnGUGQ6qprovdPKu2AgCAAlOTZKQ6FYGyWg7FhVToANYx/5bzjGseImhfIZ
         q6cC/3ahZbLoFltMJdvQ1ndE+QKZIbq3Bn+ef8vF11L8MiLU1RTKN38Ss4Js8zWLzy5q
         3fzfisfakqKsR7sX9mDvMAbOfJwVDSOvfA9ciAkaYsoMcwqfzNalKaS0jLadu83A6Hj5
         6+jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HDLuxwmJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OIJfhAMgzm7CIOcYzTaIFC+EPRozFrKNK8mptLxlDhw=;
        b=d9HMgzKemkPiYajT6pxv638NnTfrdI3RwyEdy57x87ifvE3hh3Ff3YzDuDlrf5y9x0
         6uDL9POnlk4vnhBcau+ZqRHexmc67AsWSp3R5WNusI+asBdab6zQvRexj7PUkzvcIHc7
         Xl6ZHC/cDcxOajXYlBRSUoRwWepdf8o1uRrHPuUjuAfc8q50a/l3ZUhtK2rXBr4W5Rf9
         1ahAyOX/VhLBdFx103bYADzTQVSdwU+bZkg39B42VyHcGxDHBk8EkWZVpbDaOjCjHvZK
         bxCu34hWEzMNXRVuVRLHfdfrQvBdq0zi2s/iuvW0c8bf8nv33V8TkaXaeKBHvplpLCpP
         UdIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OIJfhAMgzm7CIOcYzTaIFC+EPRozFrKNK8mptLxlDhw=;
        b=Qrxnr5L25raO8ukpEwno5EaDrcfo3NvV3QeYDER6GwXBKqKd88VDFBeBRe8KsexdK8
         4kZlrIQeDFsgbLQgmJq6RRwCuEiOhLDVTw/3Uxi7y5Fn/rqzNuGcYbycYOeeWXSCvzgv
         K1tYKaExjvjnXxli/KDmbBCBzktCXen2TOizKCbMY1lTE7ZC4P93Wdi5jkO8hxFvxhWB
         QItqMZRTO5gODsdpvjfsDMy9ylH5osmap9CO3pjS+zBNOHFwQ/DeZZOWmEIJ8DmS+nqh
         E2b42jm+fwl298A25uqFTKncj4Fm92KQOoRW9kRo1cMwXVePUvtk4v2C8bU70uPw+QN4
         t4Lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubCJSJ/sgyIiV5LQpn6Apu2wzQGnj8oPhIAYDRRb1oJ+bKpK0V/
	Opr1FTKcIo/2oA+BKWw/7K8=
X-Google-Smtp-Source: APiQypJS213p1+1+8sHpo+uDUHU/3aDN4OBTpvhDvgRwHPV4ErY1pD1Z5FnZCnACP5FtzE/epvGFFw==
X-Received: by 2002:a05:6830:da:: with SMTP id x26mr8286996oto.259.1587739029936;
        Fri, 24 Apr 2020 07:37:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:1b0d:: with SMTP id l13ls1829489otl.5.gmail; Fri, 24 Apr
 2020 07:37:09 -0700 (PDT)
X-Received: by 2002:a9d:7f04:: with SMTP id j4mr8374066otq.185.1587739029594;
        Fri, 24 Apr 2020 07:37:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587739029; cv=none;
        d=google.com; s=arc-20160816;
        b=m5vNi3Oc3sJa0Inopq2f8E4WJv0C/p6kovQBqJ/G1vZd8kH78pq2HCLK0rxbSm3p8e
         rWSAceYWIKcphXuYQTJduhNrA2qiqWvr3Fws+x0K0+qQryJWe3lTlAZap9W1BDn3DFWO
         3frcBO8WVExm+Lg48I5ihmTw64V6Jcpb1euz2KA6MJUC8Y7bVex6iZvLGq42vmAfetYC
         wloEcxjodXUHr3rAD6TE2/SgD0QZTkoeXSrtG5bnziT1BWgUTXPeTaeOq4a8wqdTI6Yq
         F61Q88hMfGGcM77DDO1nOW8Jz8GX/T2EqMEhZ9N9f0HI62DDB4BvjAB/FpJio8EqQrzo
         TX2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=KAaTm0Hse3RKPU7ib8Tu6J/z1e4Og8KZuvKFi+it9Vo=;
        b=vCc9bbszN/qx5yjMqrgZnOWqEuUquDD/JClX2SRsuO9ahwIiG85aacM1mVE17Ahogh
         OT+GTHtoMixVpqcaoIJG0M/kqDryksCF12Soh24hFjBEmq8A4BAS6m/OQcTYrwqGbY6Y
         HrmxakPcEDZUpTLQeW8St69fTK9FTcY7n11kOK4DA3OHR3TN3gvDj+PtRAcwsSCiSI3H
         v4vS/3EOtJmr0mU5tO+HMaA2lrZQkwr6RhUPh1OOh5WKWs/6HB35Wu+5ESqjt55AUptt
         mGE6gPevdA02yN3lbeNPSdBZAsGI7liojuhV1Lm9XguZ+bNmiW7Itg7SlbC1/j5qLSBs
         hjJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HDLuxwmJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id h17si112954otk.1.2020.04.24.07.37.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Apr 2020 07:37:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id d24so3798362pll.8
        for <kasan-dev@googlegroups.com>; Fri, 24 Apr 2020 07:37:09 -0700 (PDT)
X-Received: by 2002:a17:90b:374f:: with SMTP id ne15mr6294987pjb.181.1587739028730;
        Fri, 24 Apr 2020 07:37:08 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-fd06-aa7b-7508-4b8b.static.ipv6.internode.on.net. [2001:44b8:1113:6700:fd06:aa7b:7508:4b8b])
        by smtp.gmail.com with ESMTPSA id p190sm6182787pfp.207.2020.04.24.07.37.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Apr 2020 07:37:07 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, Christophe Leroy <christophe.leroy@c-s.fr>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH v3 3/3] kasan: initialise array in kasan_memcmp test
In-Reply-To: <CACT4Y+b7omyQ0bBBApOs5O_m0MDZWjoBi3QV6MxG4h_14gUa2g@mail.gmail.com>
References: <20200423154503.5103-1-dja@axtens.net> <20200423154503.5103-4-dja@axtens.net> <CACT4Y+b7omyQ0bBBApOs5O_m0MDZWjoBi3QV6MxG4h_14gUa2g@mail.gmail.com>
Date: Sat, 25 Apr 2020 00:37:04 +1000
Message-ID: <877dy5t0fj.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=HDLuxwmJ;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::644 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Dmitry Vyukov <dvyukov@google.com> writes:

> On Thu, Apr 23, 2020 at 5:45 PM Daniel Axtens <dja@axtens.net> wrote:
>>
>> memcmp may bail out before accessing all the memory if the buffers
>> contain differing bytes. kasan_memcmp calls memcmp with a stack array.
>> Stack variables are not necessarily initialised (in the absence of a
>> compiler plugin, at least). Sometimes this causes the memcpy to bail
>> early thus fail to trigger kasan.
>>
>> Make sure the array initialised to zero in the code.
>>
>> No other test is dependent on the contents of an array on the stack.
>>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
>> ---
>>  lib/test_kasan.c | 2 +-
>>  1 file changed, 1 insertion(+), 1 deletion(-)
>>
>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>> index 939f395a5392..7700097842c8 100644
>> --- a/lib/test_kasan.c
>> +++ b/lib/test_kasan.c
>> @@ -638,7 +638,7 @@ static noinline void __init kasan_memcmp(void)
>>  {
>>         char *ptr;
>>         size_t size = 24;
>> -       int arr[9];
>> +       int arr[9] = {};
>>
>>         pr_info("out-of-bounds in memcmp\n");
>>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
>
> My version of this function contains the following below:
>
> memset(arr, 0, sizeof(arr));
>
> What am I missing?

Ah! It turns out I accidentally removed the memset in patch 1. No idea
why I did that. I'll fix up patch 1 to not remove the memset and drop
this patch.

Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877dy5t0fj.fsf%40dja-thinkpad.axtens.net.
