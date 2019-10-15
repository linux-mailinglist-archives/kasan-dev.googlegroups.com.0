Return-Path: <kasan-dev+bncBDQ27FVWWUFRBWOOSXWQKGQESBHZEFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id CD786D6F94
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2019 08:29:46 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 63sf15467426ybv.11
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 23:29:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571120985; cv=pass;
        d=google.com; s=arc-20160816;
        b=s/aapTfb1fW41PuUExdk9Tisflu/f/Rp/3D6lQcwofCI/J+ZbaBaRcXqItn1byj1U+
         ALPryLDl7O0DI7KPVqRUxWxtzQ1FxEbR50GMNhBKRUeicOxBRmfe3tWJsw1GTEuvAROv
         okcNNCUMUBH9IrNiz0sOQC4jxClN9+EzX9X1+O52QRA7PZRGUexzpiONlXh8neOtLFfo
         4y6g/ojp2s/yHaba+8zsUqWznMwl7wbnBUIiGqeF71ktpBKb1w98nz16t4w0/eFbSi+O
         ojax0XOG+ot3h8YBQThRgMHg7AN65j5NDj/dv6isMnRXiK4Zr1HgdU9pHpPY4sD+PYNE
         C69A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=ZVsECDSHeNpPU+P6vx8jbPolwMZ3nVaRdXmwisGh5dA=;
        b=IY7BbzkC1mfNiYdiex9nTV3z2yHSn0WBiX5fY7r7S1pZegSy/hB3970V2Ish8h2Ymc
         cuM87iJEPstpiLkQPMgeovY644P+wooSjD7a/wozzNGI1481y/BtIIreddnsP6bu9MX9
         +4rb+1yeXx1zfKJKR8U7SpITLC6VFwpuxtvpalPsVuw4fcGGXQpgx7rP19Nu+F7fvNJV
         VzbKVl+loKQV7TBpa5KTc1skGqXZZDdmRO0PtH+5aCuP86ceyg7DC5ZC06R23fBFLgbo
         jj80XQAYy0cNxKc+QK7OCHkK2jOJV6Rh3XOsxSt/4jILe8TymSpjjqxcmBlgpIX19Cs4
         U87A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fvMKJxrK;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZVsECDSHeNpPU+P6vx8jbPolwMZ3nVaRdXmwisGh5dA=;
        b=achBRAQ7m+teidTTnwNhsC0hSVc5/KrJXUiDjcAjnyPbe3mjq5JO78sdUUdZjbE8eW
         OQG3+TwH3pxQX0Q9oeJR9w12hXgWCFCd2ta4IDE5Hyx/lsU/xkIEGfdt4v+0oSJwDJNC
         ysdst9wv6lIQyikxY20YZnm46b4sTJXWS34JvYDocaqCoR1toa9M9SdVJOl9AvtI1H0A
         BOa99OSFChBCKcTTQ7AFBKykjL/R8MxhaNBvAyMaSFuvqvxm2V3H8NunT4cXdnQy82Cy
         w5dJVg5+YayFq0Cd5+gANXWdmNTxZDYAxLe5rihTIxXIfkbqyk20wY6gasfglhO8HANv
         RvfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZVsECDSHeNpPU+P6vx8jbPolwMZ3nVaRdXmwisGh5dA=;
        b=jlZGEMnbdCKXU3aSt+CtMdMQ3KGDQs4icjboJ9CyKK7w6N9ak6VmraAnovq7Xydufg
         LfiHqcfEKicYNRv8ZN8VU8SA6VXIFLuwG1h3OiDrS4h1uR0eZkc2LkOAlGiZO/X/dcH/
         uGi4+muXD2eGorczJg/FBcijGWAHYUscdmQ4ORarZT5NaeNeG03KKyxV3JGNRuWEdRRV
         g74ALDeYjuHZX260l5PHhgSlc0GuLqv6PDYNCzNXg6JYL+POj9OvGdoHl5gW/7vxIlka
         +YYHMkKzIyRP7sB1mLhju3I4rQgr4FHa20PqXL7ydFqJrAS5LV/35AR6aDEXZ8ORrLAt
         rFvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVluZo6+PRqUXndPAE6dresRukQSnllgwwHQAmJCYSkfcM6Qp2/
	eNThBre9pUapzh5qtiOeGns=
X-Google-Smtp-Source: APXvYqxKoLiJBoCN8kGsOrpsX6n6sjZTetVUHTYT24iqyws4Xy0zoRXON57PFdaEjnZo1yvAhUJYhg==
X-Received: by 2002:a25:3a43:: with SMTP id h64mr23347902yba.36.1571120985568;
        Mon, 14 Oct 2019 23:29:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8109:: with SMTP id o9ls2683009ybk.3.gmail; Mon, 14 Oct
 2019 23:29:45 -0700 (PDT)
X-Received: by 2002:a25:d70f:: with SMTP id o15mr22336985ybg.192.1571120985080;
        Mon, 14 Oct 2019 23:29:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571120985; cv=none;
        d=google.com; s=arc-20160816;
        b=sR13p3rxDbGWgv63/1vGBq90Qd6GhC/Z2noLJjsJVDZEMhLudZmU9kSzUMdUy/Xhq/
         7blLWg/RdGs/W17hL1J8RmpR6ZU2m9ZPo3TbhPQsALD/FmXxO/IAE5Fus3saIjcYd6cr
         laPKAZ4JERB/KQfmzuRDaGKpyMo5pski01hc2f4oboo6oJPS4cKYHqndI8l5Vh/HdXf6
         DV5mNJr6Qr32Juqde5KZy3mp+ElDUvXjNp0pGrNUJDlkVNoNWRDdnpUD2w6XkcY6Nhh0
         0uZnOQ94GPWpUY/6tDci7px3mvSAXZj3loeMsBBQjjHVo7oeXCtRuX/R4Qu5Pe5STHoZ
         d7nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=EVslka8YIIComg0Mb0g4qEN93Z7Bcof6eewif1bv3wA=;
        b=HWyXrzRmM+Mkj0fShU2uy5W1UDXV9bIHmZIChmgt9YVESqbOhkBbg1dAHhUIh9iBr3
         9qbYiBV0MTF6tulamBrJKwupT8dY5P65GrGiFa001ymSmO49LztjumTh/dmLT6yOCLZs
         kkwBFJfJ0VXGSiy6klt9+X+rKj2mIdp/ZWSrFmu/XlO05HQ5b6GMHgBtKwY4wJqXwfgS
         zvc90eh478JlFbaa9ih8H5wkug5RfBdTvxUa4UBlTT3s85p4ETQebfyo1k7JZ5naDW8H
         pLYQzsZbq+EzopnAcnUjXh91bVeHx9wqLcRs76g1B0Jgtr1EyHb8Z78Q/933bx2bSz8E
         OVaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fvMKJxrK;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id r9si740792ybc.0.2019.10.14.23.29.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 23:29:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id q12so11783703pff.9
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 23:29:45 -0700 (PDT)
X-Received: by 2002:a17:90a:9201:: with SMTP id m1mr41063558pjo.42.1571120984449;
        Mon, 14 Oct 2019 23:29:44 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id s191sm14125845pgc.94.2019.10.14.23.29.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2019 23:29:43 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
References: <20191001065834.8880-1-dja@axtens.net> <20191001065834.8880-2-dja@axtens.net> <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com> <87ftjvtoo7.fsf@dja-thinkpad.axtens.net>
Date: Tue, 15 Oct 2019 17:29:40 +1100
Message-ID: <878spmttbf.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=fvMKJxrK;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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

>>> @@ -2497,6 +2533,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>>>  	if (!addr)
>>>  		return NULL;
>>>  
>>> +	if (kasan_populate_vmalloc(real_size, area))
>>> +		return NULL;
>>> +
>>
>> KASAN itself uses __vmalloc_node_range() to allocate and map shadow in memory online callback.
>> So we should either skip non-vmalloc and non-module addresses here or teach kasan's memory online/offline
>> callbacks to not use __vmalloc_node_range() (do something similar to kasan_populate_vmalloc() perhaps?). 
>
> Ah, right you are. I haven't been testing that.
>
> I am a bit nervous about further restricting kasan_populate_vmalloc: I
> seem to remember having problems with code using the vmalloc family of
> functions to map memory that doesn't lie within vmalloc space but which
> still has instrumented accesses.

I was wrong or remembering early implementation bugs.

If the memory we're allocating in __vmalloc_node_range falls outside of
vmalloc and module space, it shouldn't be getting shadow mapped for it
by kasan_populate_vmalloc. For v9, I've guarded the call with
is_vmalloc_or_module. It seems to work fine when tested with hotplugged
memory.

Thanks again.

Regards,
Daniel

> On the other hand, I'm not keen on rewriting any of the memory
> on/offline code if I can avoid it!
>
> I'll have a look and get back you as soon as I can.
>
> Thanks for catching this.
>
> Kind regards,
> Daniel
>
>>
>> -- 
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/352cb4fa-2e57-7e3b-23af-898e113bbe22%40virtuozzo.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878spmttbf.fsf%40dja-thinkpad.axtens.net.
