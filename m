Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4GV36BAMGQEPIZ4VSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6584C34360D
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 01:55:14 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id x201sf15342779oif.5
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Mar 2021 17:55:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616374513; cv=pass;
        d=google.com; s=arc-20160816;
        b=NzTQHDJRM+zhdszdk1NAb33M4bKTq61ZMP1yaBSyd66OEkjekyAgfQKifnU29HzkS4
         FFvTlS81N2sLOL7lOoxMjU2sLCMoCgu8ljVuwwmUenvsWkqXZI8XzM/b+KeqV/YgKrnv
         ijpRD4RPSzwvO2Btx8qpbsCXgkDZgPyoS5UlGAfBwGlMhGKgxWQzrK+UCHgoWTPM3puD
         5h7W8VFaFAH8ZyEWzlNVLOkPXCDSsbZlMF5kC5RFQIuS1lNr7BP9Gz0f9+nfyodqrgsk
         b/rdjye9rDjqSnMf71qnu1MCdJeCCuodBBARK5PrYAITGCU1V+vieJIPpafzztE8ZIrL
         DCTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=KP2zpLKXYthlikwciYRXkrlyNDMrWY2CQjmQDwvzDvI=;
        b=aK8TmixzQPquvyp96e7qxmdsPIszqSkgjgX+5Eopf2jL5fKcYP/L9O7F+1o9ofHvL6
         wUtM3P3VFZIHFYW5pmMxNRlh3qFwiGXR7RRsM7gso1jpBMXg6vmHJqi356yYGASwRmEG
         1ehLRc8tETp0UJG7XoRgVWjf74oZu2uWBVggymGieMBB7QFX+K0A0veuMN/bdXvbt2Wy
         tcBnn1fhjLjqLhGnUopApw+BJEm9cChRmUh3Q4bpWoG9MvwVkoJySwQfKPzXjnmpGmkM
         qT1VtfkEzGiJ73LItOHSCJ1B9XJfj95oqsilrQ9P/zxBs91KctkBQyG52mLrgNj+dNeW
         b1qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XjyhafFA;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KP2zpLKXYthlikwciYRXkrlyNDMrWY2CQjmQDwvzDvI=;
        b=Pp5l/ZDqnnyR/Wzp7njtpEy4P0NYZOfU7+o7fYWByA/IxbGjOyBXKbKH4/XjdX1tjA
         spANkZMqroUMNWrxXBO/1r6gi8w45yfRnrCHDcuMjnRLxIt/h62NokXbpEn4YUG2Vg+4
         vDjIRo5SnyeV7yqHkY2YxLtYe7ZyGIRQ89FSt2pHpKwGSiibIcjgqNJWopPuE8E47SQf
         bX7BNcyXa6U9sb8pxs6jJeYKu7qyvck2M3Joo1jYRCHntl2ex9/gkgVhsI7tBetseSAa
         Och+64AEHb6zYqzBZrgUwHWN+WJvePsBS7gmBw4dS+dQH//v0hDzotNc/VVsmVBfXE0f
         uBvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KP2zpLKXYthlikwciYRXkrlyNDMrWY2CQjmQDwvzDvI=;
        b=qgImhGFckZWMYmPdi3qE7Mp65sxc8RkbI4c5butCOonwXaZao4X2sxNPJaR3EkHsYG
         DAA01Jw68SVKRYK9aPGKKfsrb20SBgI//GF0wXRZcs5ceEyNRhB2GjDq6bMN6r+TaMFJ
         gikC2Q8Lb3GYqxYmTwTBUW4lhz5S8Xhb27EJSUtdwVOXJSlq6+VW8Kljh65L4b9Dzgy5
         u8jrtncvAl1FZuF/Uv8HMVpkD5/V9HVuwLlQyGiRPx4kTdUpHUp+UVHcoqKNBVNekeBs
         sEr3txbTqbG5uCpyOnw/GZTuWcKWK9XJ/preYsbnpIuhlejrFgTzGMkPuO+v8udf+FGF
         QY/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bihnensfe/Kg+m1TRNvTNhLPWN0u4lalC6L1dFpgaJqY4aLzj
	OWJ7ksMdSiv74IvcVhwWElE=
X-Google-Smtp-Source: ABdhPJw5lNPITkUZOiGwUeuvzBqGJ2oGwqsoQapZvRxPFHZVHYlM/eoh1jOCSq0BBRtZB/R+uwwHMA==
X-Received: by 2002:a05:6830:110:: with SMTP id i16mr9253657otp.230.1616374512846;
        Sun, 21 Mar 2021 17:55:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:aad0:: with SMTP id t199ls2580990oie.7.gmail; Sun, 21
 Mar 2021 17:55:12 -0700 (PDT)
X-Received: by 2002:aca:be04:: with SMTP id o4mr8011859oif.25.1616374512503;
        Sun, 21 Mar 2021 17:55:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616374512; cv=none;
        d=google.com; s=arc-20160816;
        b=DQhSwb4MUnu43re/yQIyOFzJ/Bo9V/EYvFs9eN9lteiFr5scuUc5rd9u6ZlSfyQMDK
         7c9t+M8giOmZPTja+77OdaSjm8ee/Zi1wqYn34wtwwbvWr+7ID+oRYqSB6+EaYpc2Vrd
         yAPHTjKD4AzxixDi739P2CqpfBv33uV7p8mhK98dKdorKdxvs2pP9aF9Cko0csVBMseR
         wJS3v2DZqVwHxBbYsxlbrec99Q+QQrfbRlg9nWcJ6k+4WQ7V0Gtl8ZV8ltGpxNByeya9
         /y85mCzUNgUDQul13W4i8wwYbsLxP4MFnkVQcV00xl5MKSXhDvBHVc65M9eT3IvSB2vc
         Ap3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=YhjptOa1YLY02YG0NxjiEXQDPMTypn5KHITe161ubW8=;
        b=Cp8GMhLqDZseOVdaWg7095Sa3ue4VeQ7pHT/v6nOhL9ipz1WK66RQomsqWfPQ/QQbV
         W1IYdEA6j2u9h7YpsiKvExoby3pgM2AuiE3sSOXmapAz/JeN2wUL99SIOEJkE1rNfsRL
         EErNWcDxb2MDi3r8BY3i3Bco8DWyA3e4KvqUM5i8YsGd/A1df/GHxDynWdqwXo2iTYnD
         +j/3tvUo91PCDtqrw0CkuXWbCUZd47vwFHbvdiJBlhxhM9wMFav0RmeIrjDLaQ99FbD4
         E8qg+Re3D587uPqhZz1ld1xnpz1Wx3R/CEKUByDB5kuDy46m2i1u1LhSyDSQae9Jc1r4
         s3mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=XjyhafFA;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id w4si694541oiv.4.2021.03.21.17.55.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Mar 2021 17:55:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id f2-20020a17090a4a82b02900c67bf8dc69so9537194pjh.1
        for <kasan-dev@googlegroups.com>; Sun, 21 Mar 2021 17:55:12 -0700 (PDT)
X-Received: by 2002:a17:902:e546:b029:e5:ec5e:6bf4 with SMTP id n6-20020a170902e546b02900e5ec5e6bf4mr24400618plf.41.1616374511814;
        Sun, 21 Mar 2021 17:55:11 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-b0f2-84a1-ce9a-a0fd.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b0f2:84a1:ce9a:a0fd])
        by smtp.gmail.com with ESMTPSA id j21sm11603072pfc.114.2021.03.21.17.55.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 21 Mar 2021 17:55:11 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Balbir Singh <bsingharora@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, christophe.leroy@csgroup.eu, aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v11 6/6] powerpc: Book3S 64-bit outline-only KASAN support
In-Reply-To: <20210320060259.GF77072@balbir-desktop>
References: <20210319144058.772525-1-dja@axtens.net> <20210319144058.772525-7-dja@axtens.net> <20210320060259.GF77072@balbir-desktop>
Date: Mon, 22 Mar 2021 11:55:08 +1100
Message-ID: <87o8fcatxv.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=XjyhafFA;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102e as
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

Hi Balbir,

> Could you highlight the changes from
> https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20170729140901.5887-1-bsingharora@gmail.com/?
>
> Feel free to use my signed-off-by if you need to and add/update copyright
> headers if appropriate.

There's not really anything in common any more:

 - ppc32 KASAN landed, so there was already a kasan.h for powerpc, the
   explicit memcpy changes, the support for non-instrumented files,
   prom_check.sh, etc. all already landed.

 - I locate the shadow region differently and don't resize any virtual
   memory areas.

 - The ARCH_DEFINES_KASAN_ZERO_PTE handling changed upstream and our
   handling for that is now handled more by patch 3.

 - The outline hook is now an inline function rather than a #define.

 - The init function has been totally rewritten as it's gone from
   supporting real mode to not supporting real mode and back.

 - The list of non-instrumented files has grown a lot.

 - There's new stuff: stack walking is now safe, KASAN vmalloc support
   means modules are better supported now, ptdump works, and there's
   documentation.

It's been a while now, but I don't think when I started this process 2
years ago that I directly reused much of your code. So I'm not sure that
a signed-off-by makes sense here? Would a different tag (Originally-by?)
make more sense?

>> + * The shadow ends before the highest accessible address
>> + * because we don't need a shadow for the shadow. Instead:
>> + * c00e000000000000 << 3 + a80e 0000 0000 0000 000 = c00fc00000000000
>
> The comment has one extra 0 in a80e.., I did the math and had to use
> the data from the defines :)

3 extra 0s, even! Fixed.

>> +void __init kasan_init(void)
>> +{
>> +	/*
>> +	 * We want to do the following things:
>> +	 *  1) Map real memory into the shadow for all physical memblocks
>> +	 *     This takes us from c000... to c008...
>> +	 *  2) Leave a hole over the shadow of vmalloc space. KASAN_VMALLOC
>> +	 *     will manage this for us.
>> +	 *     This takes us from c008... to c00a...
>> +	 *  3) Map the 'early shadow'/zero page over iomap and vmemmap space.
>> +	 *     This takes us up to where we start at c00e...
>> +	 */
>> +
>
> assuming we have
> #define VMEMMAP_END R_VMEMMAP_END
> and ditto for hash we probably need
>
> 	BUILD_BUG_ON(VMEMMAP_END + KASAN_SHADOW_OFFSET != KASAN_SHADOW_END);

Sorry, I'm not sure what this is supposed to be testing? In what
situation would this trigger?

Kind regards,
Daniel

>
> Looks good otherwise, I've not been able to test it yet
>
> Balbir Singh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87o8fcatxv.fsf%40dja-thinkpad.axtens.net.
