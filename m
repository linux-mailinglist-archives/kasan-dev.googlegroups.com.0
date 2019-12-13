Return-Path: <kasan-dev+bncBDQ27FVWWUFRBQVJZ3XQKGQELHLLMAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 164C711E4CB
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 14:40:20 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id b5sf1912414ybq.23
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 05:40:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576244419; cv=pass;
        d=google.com; s=arc-20160816;
        b=vLjiHu26PrqVlxTaF8Ww25JACa2Aeu/NxJjm00ulZFf6nnqjFfX01ai7+xXSJOLoY0
         TbUZeVx5O5/Zu5K/bHxTjdlun8ye+8vucrrZ25oq/yp1Ha+BITWiRmzLuSoYaEoplOPP
         vOizUwD2jN4ZK46aSBydVX20AK11jmd3v1mD+aEE45A78xW0MHiJNjzskyGi2NJFXXyc
         Wii42MYQmdWVyp8jsu+gwyk9jxshu+zkkO6ZwjOWgjSbY9ZjAMwhvXiKqRIShwTvVyu0
         XkaF+RXftj0M+ArNTwjR1oGOVVzXhVo6HxUIJnB8z+11anGeRe4TfwVaDAh4qOftupX9
         QF0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=pa1+hRbdXQa27F/KBwKj18XW1It7wp0x5LfPatiqz1Q=;
        b=K+j9wl9a1t/TwZcxFozjVkGzLDkkAsLINAkJuHgel1cKDRlSD2YLmzsJME8ZVSfNoC
         vFrFzthFUgOJRzZdAxtpmJNNw/1m5A5S0EjnvAeXOWhI9Hh7uPkNd1smM38kuX6gP03v
         AAKtJ2Y4pEKfbUb3CnlQ75KHhz+UkFtyn3ElmWJ9l1VKNUMY7E4dMP+KKRz8NzyBpent
         7k7v+j/eVCs5lNqpk/FtIXhwDXG+NMjjZNVdAE+wh/BgY+f9z8jVnroSPWy7y4DFzVTO
         zTZxMux6cbHngX5w3YKeCfk0TFwdihGMSKad8IwJbOZbLXxcR2C2411Z3DBDYD208UMj
         nOTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hmi5MJB7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pa1+hRbdXQa27F/KBwKj18XW1It7wp0x5LfPatiqz1Q=;
        b=qhWmCJ79mgsM54ECqm7AmwU220ahgVve+KsIxu0t8J/gzHKgqGn86B/X2eS3HAdQUT
         vPfjG7JAPcrGOew1Z7wjZLq8RHnvlJyEWmlI4TkMbTGhrO8fPkUCOkRYnmSi5HGLTNx3
         hAmI4CyYQFC/tZGuOosOps25xveueGc7HaVPnuTvCxQMYphZN+Zjtsqh1CGnWZcAuDXh
         P131bHDJf4O2inzYLMEJlMdu6VtHRA4GmXRRIv1VaIhRgmzCNLV8HGMmqCAJDzyYHREX
         OF4zQI4BmlD6ZtsnZ9roUn15uZZleoAELpyQzbPkVOxpRfhwZVpPMWQz0WRCzJEikc26
         Vg/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pa1+hRbdXQa27F/KBwKj18XW1It7wp0x5LfPatiqz1Q=;
        b=mIlll/0hWJ/rfqWHMbl6o07SFlsaiO0bpt08V9qsPH2Udv2Znb+9Ml6tDA2KpmIH7r
         HoiiyHZye4HsnC3c/aWM7MS0qjHfx9byNUKmLg5jY6PZAelxKJPXfGtuI0AiX/4nKB7Q
         36KHPcnF69uq6dPd72ZeRP2H2TA37TQBWRCS3AuuQVbqyf0jThUDkVAL0fbBs3fwpHDY
         rbVJrtR8vP88E6qgDykbrR5OVh2vJc+Rs3P+5oFCus8RS+K16ejYduTK7qlxwLtiwEMd
         ovZchjygiwiod0ND0EI23j4nalNqJkfhY7b3J8zvX7l2eO1gKELqWOMiY6gokYuhXrrL
         v0Yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVl0tAQg1V07oEwSdebDpxtKnLfXI3efjgOLBC/MOtU1Y94kndY
	G4+NCP6xnHs4kYhxgwoQR5Q=
X-Google-Smtp-Source: APXvYqxdMz1FHnzqo6joZq9XfsxpJMDtysQ2ZNKKeBX68FHPz4vi5JRA1I7614cE+0w+z1yzec4SSA==
X-Received: by 2002:a81:f20e:: with SMTP id i14mr7667302ywm.262.1576244418874;
        Fri, 13 Dec 2019 05:40:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c945:: with SMTP id z66ls1408120ybf.16.gmail; Fri, 13
 Dec 2019 05:40:18 -0800 (PST)
X-Received: by 2002:a25:7451:: with SMTP id p78mr8684212ybc.22.1576244418472;
        Fri, 13 Dec 2019 05:40:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576244418; cv=none;
        d=google.com; s=arc-20160816;
        b=H1aEUBUKE9fVKGIt6FBFiu+EqwPDYdnUmdLwQIczBNltm2IISq6jmnDqdchYgZg78M
         XT3J1R5F7QLLYlh+52WKuqfIfSHe9DBmLPnJnsMzmc+gSH/muONCxjAihJdioECxs2wF
         MBMZKdrEkbPsKOV4PXxfWe69fo31sxADjIfbmw6z/VK8I0TwSQsjpQZwbpZ9H7DvlbBQ
         d3D1F/VIf5yM9RwlXVlWI2wkKuU+n0IPRK/l5Hr3KIpXlFP2gAXltZLfrkgMWNv8/Cgn
         vutyWaCECwptoqs/ixeMtyVeObsu/+KvM9fXZ/Egk6g/H5TAjLPF4IMNaoaH0jWhffXr
         ahOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=/eZlIcE4bRaQxd77WQWCVd4CAZbU8bs/M4S7Zue3IL0=;
        b=KaY/jKj4lwgAfR8BtQ3rpbADJDKbXJTy17zVMu34iglxm+y6P/zchgamgU8JQXpqzC
         SO1VeH0AI/7N9fEhGKphHl8DRf3J5inIJFAPRjXYrb036vIYYuUBO4Qxdp+F9hN7Lejz
         RpRcJa1NWTPAV1awLRtK6P08mktTJM1nWC+nKLVKkn0GZqdWxy9A8PRd8ug+O7f+b3YK
         jxk2l39OliCr1UHvExEXuwUdVSrVdsER2nfkAIFLZ1v/PVUBieiYXMZgXExcpdnHW+4a
         DP75OUeZQ9YYcx+21m+/z4AYGCCXrfQJrQlfQjb+TLOn1dfABveG4pBmE/KzP//aYhhX
         Ne+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=hmi5MJB7;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id a8si179532ybp.2.2019.12.13.05.40.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Dec 2019 05:40:18 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id k197so1582072pga.10
        for <kasan-dev@googlegroups.com>; Fri, 13 Dec 2019 05:40:18 -0800 (PST)
X-Received: by 2002:a63:770c:: with SMTP id s12mr17493474pgc.25.1576244417558;
        Fri, 13 Dec 2019 05:40:17 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-a426-f10f-bfc4-6b9c.static.ipv6.internode.on.net. [2001:44b8:1113:6700:a426:f10f:bfc4:6b9c])
        by smtp.gmail.com with ESMTPSA id i4sm9547075pjd.19.2019.12.13.05.40.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 13 Dec 2019 05:40:16 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <464a8b50-0d4c-b1ea-485b-851f7cd7643b@c-s.fr>
References: <20190806233827.16454-1-dja@axtens.net> <20190806233827.16454-5-dja@axtens.net> <372df444-27e7-12a7-0bdb-048f29983cf4@c-s.fr> <878snkdauf.fsf@dja-thinkpad.axtens.net> <464a8b50-0d4c-b1ea-485b-851f7cd7643b@c-s.fr>
Date: Sat, 14 Dec 2019 00:40:13 +1100
Message-ID: <87mubwbayq.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=hmi5MJB7;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
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

Hi Christophe,

>>>>    - We run a lot of code at boot in real mode. This includes stuff like
>>>>      printk(), so it's not feasible to just disable instrumentation
>>>>      around it.
>>>
>>> Have you definitely given up the idea of doing a standard implementation
>>> of KASAN like other 64 bits arches have done ?
>>>
>>> Isn't it possible to setup an early 1:1 mapping and go in virtual mode
>>> earlier ? What is so different between book3s64 and book3e64 ?
>>> On book3e64, we've been able to setup KASAN before printing anything
>>> (except when using EARLY_DEBUG). Isn't it feasible on book3s64 too ?
>> 
>> So I got this pretty wrong when trying to explain it. The problem isn't
>> that we run the code in boot as I said, it's that a bunch of the KVM
>> code runs in real mode.
>
> Ok.
>
> Does it mean we would be able to implement it the standard way when 
> CONFIG_KVM is not selected ?

I suppose, but KVM is pretty important to me!

>>>>    - disabled reporting when we're checking the stack for exception
>>>>      frames. The behaviour isn't wrong, just incompatible with KASAN.
>>>
>>> Does this applies to / impacts PPC32 at all ?
>> 
>> It should. I found that when doing stack walks, the code would touch
>> memory that KASAN hadn't unpoisioned. I'm a bit surprised you haven't
>> seen it arise, tbh.
>
> How do you trigger that ?
>
> I've tried to provoke some faults with LKDTM that provoke BUG dumps, but 
> it doesn't trip.
> I also performed task state listing via sysrq, and I don't get anything 
> wrong either.

I'll try to disable this and see if I can trigger it again.

>>>>    - Dropped old module stuff in favour of KASAN_VMALLOC.
>>>
>>> You said in the cover that this is done to avoid having to split modules
>>> out of VMALLOC area. Would it be an issue to perform that split ?
>>> I can understand it is not easy on 32 bits because vmalloc space is
>>> rather small, but on 64 bits don't we have enough virtual space to
>>> confortably split modules out of vmalloc ? The 64 bits already splits
>>> ioremap away from vmalloc whereas 32 bits have them merged too.
>> 
>> I could have done this. Maybe I should have done this. But now I have
>> done vmalloc space support.
>
> So you force the use of KASAN_VMALLOC ? Doesn't it have a performance 
> impact ?

It has a perfomance impact when allocating and freeing virtual address
space in the vmalloc region, yes. There should be no discernable impact
when using vmalloc space.

My team is actively working on vmap-stack support for ppc64, with the
end goal of running syzkaller with vmap-stack and kasan. vmap-stack plus
kasan requires kasan-vmalloc, so for my purposes doing things in this
order makes sense.

I'd be happy to have a later series introduce the split and then make
KASAN_VMALLOC optional. I would need to understand the implications of
splitting the address space from a KASLR point of view: I don't want to
accidentally overly restrict the available randomness.

Regards,
Daniel

>
> Christophe

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87mubwbayq.fsf%40dja-thinkpad.axtens.net.
