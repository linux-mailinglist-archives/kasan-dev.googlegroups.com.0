Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4GJ36BAMGQEOBSLXSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 4118F3435F6
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 01:29:38 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id f10sf25997740plt.6
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Mar 2021 17:29:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616372977; cv=pass;
        d=google.com; s=arc-20160816;
        b=nDDXbrkXUc/Ypjk9cchIK2/tyIewmbqJIvOcj5U756766kr4HjVdnWa6nB1pz58wnE
         6x7fD2lQpfrqNX2VvrkFJABadcnluT5q54zmLITMC7EMeQPNOSRM1VsQx8Ipjit8GC6/
         zdwDeLIpLsGC9V1GX8ZCozNLCU6oC/vY8W+aXaZ61sWvMRElAmSgA3ltXFV8KP4HmOrg
         Gr9GLlVSaxYVyFVPBblXw0/64SzUuh8fOkzyAlejaVRUe1I7FjcpJvrpxCZlBAtaYREq
         8cYenknqIRVxN9lnMK4S4s6a7OJnnP/brwvyM8QaJiPt2pXIhzVyBhWpQlCV4UaLUUq4
         sIrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Yvn5oDZpF2mesy1J+hAf7RLJOJeGjg3BDT/oG4037rg=;
        b=ZDFwAcRNdsNNTpfxjuiozASC6YXGk1ntbZD2YoTD1Ue/T4qWJ1yvSPonX5KvClQB6X
         81pLSWoMpgcMlbeb9j3ioPMvsNFb8Ttn2LDz8cnZY6xJ9FJbpDM4IoQ08/XSfM8CsCC9
         HYL8Rm4gKg40NR0g0sZobqZ6NJtEfjqK4H2+DhjhD7xZbxCjk/iEdHV3rcgwQ07v0Dtj
         ouaXxOj/m6Ygrg7mRkGW5q5GSqIqvI/SfarFpLOx8CGZGDSDF1Vkv8oOTOFf54Ws+nIq
         mDGi+ThX7WAZSmdSIGPGDBd1q6h3vjBZELA4K4LKRhU9Yo8dRKbzRH+0dvWqXHRUJ0TV
         ZLPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=LIWwyHHN;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yvn5oDZpF2mesy1J+hAf7RLJOJeGjg3BDT/oG4037rg=;
        b=U5Ka2qPOqOEdNXdXk0oLzMYfgZ9J8X7Uw6OO7qdvy3HN74NyjFwyA8GNqMCrtiGqoA
         JNXhsqxZ2jFFVR2da1WTnaotlD11sZDW+By4YHPi46/4LtVHjH2xYqGfsw//ceoRpXfw
         3kGtZrThXwpAIiLUAw/6ToasUUDNqPSXb74CRNffbME7073N3IDzqorPu3sZRKR4kVXR
         fE/20ir47N6qkHBht8/3lN0gvyhkHuJoln0GF/++Byiv10XT+Zu9XV9eAtuowMW1j1QR
         8fOR4miCVPpmXYgiKzMIwzDz4zmSoMGkS8gthgh1MFnpEBcKnudN5/EwCrrtFUvay86q
         ShxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yvn5oDZpF2mesy1J+hAf7RLJOJeGjg3BDT/oG4037rg=;
        b=o2u7/YYsITlKlvL1J/PzaLLZu+RjfAvyDMsssAE0tLejn7ZIXxf63sSI91JIjZLCDc
         vd/BkuIjStfBPLRiOz19UO/iJ7k+0Trr1w3mOmI9xUiZMHBlutQ7y0v4GdsihURAC3a2
         0YnX3frfHhWlNN7XmN5h7XtknWmkNLdRxpwA+kJUkgeno9ifl7uacdeqO2F7uAQyS9Xx
         JE74BTAp2+6D3xf6mRflBqWn2t7mA/cg+Vn16LDlVUjF2tQ3mKogjPlrrY+I7vlmtn9V
         Ic5PjgeyqJA9bqGcPNrIswA6J/iYkwI6UhJa4Hsz9XrI+wDFZDZeN2MlYKmiQXTlwH14
         JeHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532CNkZn3LZIBcat5HmNJOVJhgRZ7kjw0fa2bASCWvtaTlpiLtJt
	/aK/bGW0ZosMp3+Qq0Nv+YE=
X-Google-Smtp-Source: ABdhPJy3NvVdCSTA0XjfNrHLeM0gqRrZEc17I/XNHS01x2SgCzXPYRzQEda9g7xY3kUCfkjJ3EYLyw==
X-Received: by 2002:a17:90a:5d09:: with SMTP id s9mr10171432pji.228.1616372976982;
        Sun, 21 Mar 2021 17:29:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1057:: with SMTP id gq23ls6497885pjb.0.gmail; Sun,
 21 Mar 2021 17:29:36 -0700 (PDT)
X-Received: by 2002:a17:90b:4910:: with SMTP id kr16mr10191329pjb.26.1616372976380;
        Sun, 21 Mar 2021 17:29:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616372976; cv=none;
        d=google.com; s=arc-20160816;
        b=BUe2T+L33PHEY3pLBLSTUYirkrvaq7zazIn+z0nfWC5ldOYvqstH5XgSwLWeiappI4
         jwuZRw5MJBr1vHaa5EG5NoWbv3ur/k8pAHxdrrkUFDC/ZMVw+K7uR5zO/JHJWDE63ogX
         TfoGU864unb3nh6Tpu+JAkBMFnUsW93H1twsa4yfnwTY9QJc5YG/lSudQLIU3J4gjUBY
         NF0vTYm+iC9Cz7YfAoYO5sVlZJ/MOtq3r2OyGpFnr4Sz6QZ7/2KVAIQpMkVt0hUd/n2i
         Ww8+LgqBw4eW8/rNPWLN8iC+0kbChfa9//ovZVCI3PrG2sS9ZE1wKbU60YDXVxK/p/Fc
         a32g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=mN9M2gHDmHAMZP+50/Nsn8lRknSmspKGtmjuk7ePwS4=;
        b=g1njku8BUxKYGSQKZIEtqnQTrghm4sZHnNeCPx4ouE/86nJNVxa1tllk6HwyuBXxiC
         htvIW4deIPhdMAQTsPPpTFP1I5lV5rPJ64I6c+55tk823t5EdamtKLItIJWvxKObCPZu
         DUgRQ1CfEZMzJwtBIyrs3bEPGG4C4UEJVOl2GSDmkUgIRreD/9pnZ44N+D3+Tg08znkA
         iBf6OnOOdwvY5Mo0LaFEOOGJUSPprH0KiALQ/+zpz/uMSlN7WtebJ0dqPpBRY0Xw2A1x
         hQXVD2kaShmemOOjmYNYGQvvPqHqZFVqkwXluvmi/smxU8o3cVPjTjnh7aD77rap0tKt
         KCqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=LIWwyHHN;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id md20si958280pjb.1.2021.03.21.17.29.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Mar 2021 17:29:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id ha17so7469357pjb.2
        for <kasan-dev@googlegroups.com>; Sun, 21 Mar 2021 17:29:36 -0700 (PDT)
X-Received: by 2002:a17:903:228c:b029:e6:4c7e:1cbc with SMTP id b12-20020a170903228cb02900e64c7e1cbcmr24592365plh.38.1616372976026;
        Sun, 21 Mar 2021 17:29:36 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-b0f2-84a1-ce9a-a0fd.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b0f2:84a1:ce9a:a0fd])
        by smtp.gmail.com with ESMTPSA id i10sm12299634pgo.75.2021.03.21.17.29.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 21 Mar 2021 17:29:35 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Balbir Singh <bsingharora@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, christophe.leroy@csgroup.eu, aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v11 1/6] kasan: allow an architecture to disable inline instrumentation
In-Reply-To: <20210320014606.GB77072@balbir-desktop>
References: <20210319144058.772525-1-dja@axtens.net> <20210319144058.772525-2-dja@axtens.net> <20210320014606.GB77072@balbir-desktop>
Date: Mon, 22 Mar 2021 11:29:32 +1100
Message-ID: <87r1k8av4j.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=LIWwyHHN;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1036 as
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

Balbir Singh <bsingharora@gmail.com> writes:

> On Sat, Mar 20, 2021 at 01:40:53AM +1100, Daniel Axtens wrote:
>> For annoying architectural reasons, it's very difficult to support inline
>> instrumentation on powerpc64.
>
> I think we can expand here and talk about how in hash mode, the vmalloc
> address space is in a region of memory different than where kernel virtual
> addresses are mapped. Did I recollect the reason correctly?

I think that's _a_ reason, but for radix mode (which is all I support at
the moment), the reason is a bit simpler. We call into generic code like
the DT parser and printk when we have translations off. The shadow
region lives at c00e.... which is not part of the linear mapping, so if
you try to access the shadow while in real mode you will access unmapped
memory and (at least on PowerNV) take a machine check.

>> 
>> Add a Kconfig flag to allow an arch to disable inline. (It's a bit
>> annoying to be 'backwards', but I'm not aware of any way to have
>> an arch force a symbol to be 'n', rather than 'y'.)
>> 
>> We also disable stack instrumentation in this case as it does things that
>> are functionally equivalent to inline instrumentation, namely adding
>> code that touches the shadow directly without going through a C helper.
>> 
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> ---
>>  lib/Kconfig.kasan | 8 ++++++++
>>  1 file changed, 8 insertions(+)
>> 
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index cffc2ebbf185..7e237dbb6df3 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -12,6 +12,9 @@ config HAVE_ARCH_KASAN_HW_TAGS
>>  config HAVE_ARCH_KASAN_VMALLOC
>>  	bool
>>  
>> +config ARCH_DISABLE_KASAN_INLINE
>> +	def_bool n
>> +
>
> Some comments on what arch's want to disable kasan inline would
> be helpful and why.

Sure, added.

Kind regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87r1k8av4j.fsf%40dja-thinkpad.axtens.net.
