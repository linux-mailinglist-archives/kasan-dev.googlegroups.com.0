Return-Path: <kasan-dev+bncBD4NDKWHQYDRBGEI7OCAMGQEJJT4BAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id E9CEE380FE4
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 20:40:25 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id e19-20020a170902f1d3b02900ef602eb0besf7371578plc.22
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 11:40:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621017624; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vy5cGKlHEDK5aStgj6wwH3awd9tm+o0I1+Ut0u8yu9ABgI0agwOz5s44wezBYLt2/A
         gC9+UpPaED7v+/ne198p+iPG7EXJqVGmHG13V4u1w/9yVoLlmp7dKftyOqOeKjwjZHkD
         uz4bUlrXEs1BQ8zbqZQEIGAXpSjqZBVZTcNTahsOfRETrKGC4ytGs6fTs2A2ERUfY7BF
         H0n1b8P/kQwdkwAaQ2947pxWUhlIpafAp6oANBFDkYys4E5C6JC7bhkrE8uWEJh5bare
         2+OJNs9n+WgYMBNjRvl9ZNYL6DqkXz3cVRhAPzpq8IWlReUuRc3THmenEWqIf9Wa4JIj
         emLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=j3+KTKrzrplWDFAam0csC/+Q6IAbEgYA0jJNEU1cpXo=;
        b=xRx3uuSCWDvSI8ODGRzPa8uI4m+nUBsWpekg9HETC9MPF9bj00/K1FIBCMOynj+SDx
         jfLusA4vFiq1X5/85vJwgzmn4f+LCnK1w3BNlVuSOO9GwWpH/SFXTMPqRDE0ltNbkypI
         3LSsaBmKkC6WUpgSLbloTjsD0brb2gTosDqN2p/FBv/Q8HIW/guoCV+iBTsy5zGEfelB
         bch8EDD8EDGVHedsUdUc9JGFPbBc3RPgqMxR4aJFTsgufQ/xV0D+yBvPlNpBGqvsbzqD
         V7IaCr/616HHvUE9H2GbCsq0LLFFPntbIV9T4UeZ7YMXbmG0j3Wm3h+AjGVOPq8gz8zn
         IMbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gYbkQcl9;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j3+KTKrzrplWDFAam0csC/+Q6IAbEgYA0jJNEU1cpXo=;
        b=mUDSy3j1qNZNqQDyIvVQO29KgfckL3AN4GG+3+B3Z6wnwMFJqi3wujD81Q8/jWLN1Y
         onvecpop3BIDPnq8aMyivW/m4ZVsl/39QL7+0mOyCtRDktJXDULdds+qgvi1HxIYxhCj
         RMRkxhAtHAHju6MA5Ui5mxZI3Nw3dJNmBfNBVNaCZjSGfBv5znndVNUVW1hz0WVEp/qi
         mUEFe9BzQgC3qKMCTO3MtPCWYzTpKuePlqeZtNHENwG5nTqSRSFYoPhFdh2QJkywIReD
         VRR/AYARbrU4JkdffPq5nBM+jnvqpVVUAfV3NkC5yIibVRtQIB4PsbnzDs1xw0v063Cz
         2e5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=j3+KTKrzrplWDFAam0csC/+Q6IAbEgYA0jJNEU1cpXo=;
        b=Oa+OaUzsFEsQmxtniZGHMvq1pBe+B28APGishJm1nnMM3dUg7c/8QciniYb6snMiZJ
         mSM9akKZVRl7U17gY/w6LW5V3mr6iV+DempQETLNQsn0P3JPB6jRUVIe8A/68SDnD6fN
         Z5MunDjAXL1sRChp2xfBCkxUQCWDFpUqzDJVkl0qT9/KhWv6vz36YdMLfwojtzsUmezr
         q5OEvZGWOx5Jyt5MJ1Dw0pjCH+lkcKNj3TqTI75/OUNB92dqJHay3yBdlMKcp0qexcaa
         jh97DaU+YsVpT2HC5//1rlWWau/rnKDWJnKKKL7u3pTedtWxt+voJWRwAT7zFupHYUaj
         hCOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bTxoFwhsK+WGQduhXsXLqdhNuKB6LqFltO9+1FipgP3XK/a+5
	6KezdEQAXjEb11TQORRiddQ=
X-Google-Smtp-Source: ABdhPJwA688Slpfkp8bS5BZOVy94UpUSsuGwJD4+/VDNuGefJw/M3a98wMnlbUfIYaOtJLoiRIpquA==
X-Received: by 2002:a63:6207:: with SMTP id w7mr49717616pgb.260.1621017624633;
        Fri, 14 May 2021 11:40:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7208:: with SMTP id ba8ls5355987plb.10.gmail; Fri,
 14 May 2021 11:40:24 -0700 (PDT)
X-Received: by 2002:a17:90a:5649:: with SMTP id d9mr2431184pji.163.1621017624125;
        Fri, 14 May 2021 11:40:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621017624; cv=none;
        d=google.com; s=arc-20160816;
        b=iBN4beByg1gizs45X6oOLjM2ZPA9TXOPlw/e2ntV3jOetYUFVtpZhttHgfeplGrgq3
         lG9rezi73NFbtzAnMWLxOJrHbbXYTR7kpaOeS1lw0cg9TyNl1sSlwEBKrbtVW1geSXrI
         Khzmoq5fj6/WE4dyjZSiM4a6GagW8JbU5HIMBGU5sf4gzkw1I3ju2V53bq/oYYp33olB
         A0G1PN0ZWvrrcV0M+tr7t7OScDxY7QwFlsK6/d9UIv0tZiJnKup6e6WTjYOmq1DATeL/
         2V84WAWlErBN/V236Q44+K26v6jAZCcx5l9xs8X+Udeksj9pC3Xfhq9DvJtfkdbIw2Au
         TueA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=LbDu3sHQ95uVgf/U5DomtxuEDnFI9q7Oe8vSaICEHN0=;
        b=kMf3gFk3KQ6AL6AQuzrSYzqSFEKGqWtCY6BMxd0EvD8QTuFIDgk+4T6b8sKaocQgMV
         twMr00ILCr0nhl+zgsX+nrCZFfMccp3oXeYVqWBHcOl21qEobeCt3HpgawtGcID7iinn
         snICc5/s2Ad5ceFyPOdmDeXxAi2C5Hksptm9sYMe2qDaz7QZ53tVTb7e5q4tesWohTCy
         M9H39PvuiJ4vMSpksYO/mFcJBFvZ593JMyWGp0mXk+G8VMLgXeockwQcZIRAkdOfjXQz
         9wRXEfckrRnY4sTscmC0haX/QdS00+8N4FgGfa0Vxh/9f3GHw3rQLHDBgthEvBaVr+Pc
         JF7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gYbkQcl9;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i2si534480pju.2.2021.05.14.11.40.24
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 11:40:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5158361444;
	Fri, 14 May 2021 18:40:23 +0000 (UTC)
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
To: Marco Elver <elver@google.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 "Paul E. McKenney" <paulmck@kernel.org>
Cc: Arnd Bergmann <arnd@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 clang-built-linux <clang-built-linux@googlegroups.com>
References: <20210514140015.2944744-1-arnd@kernel.org>
 <YJ6E1scEoTATEJav@kroah.com>
 <CANpmjNMgiVwNovVDASz1jrUFXOCaUY9SvC7hzbv2ix_CaaSvJA@mail.gmail.com>
From: Nathan Chancellor <nathan@kernel.org>
Message-ID: <ad7fa126-f371-5a24-1d80-27fe8f655b05@kernel.org>
Date: Fri, 14 May 2021 11:40:22 -0700
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.1
MIME-Version: 1.0
In-Reply-To: <CANpmjNMgiVwNovVDASz1jrUFXOCaUY9SvC7hzbv2ix_CaaSvJA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gYbkQcl9;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On 5/14/2021 7:45 AM, Marco Elver wrote:
> On Fri, 14 May 2021 at 16:10, Greg Kroah-Hartman
> <gregkh@linuxfoundation.org> wrote:
>> On Fri, May 14, 2021 at 04:00:08PM +0200, Arnd Bergmann wrote:
>>> From: Arnd Bergmann <arnd@arndb.de>
>>>
>>> clang points out that an initcall funciton should return an 'int':
>>>
>>> kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
>>> late_initcall(kcsan_debugfs_init);
>>> ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
>>> include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
>>>   #define late_initcall(fn)               __define_initcall(fn, 7)
>>>
>>> Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
>>> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> [...]
>>>
>> Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Thanks for catching this -- it boggles my mind why gcc nor clang
> wouldn't warn about this by default...
> Is this a new clang?

KCSAN appears to only support x86_64, which also selects 
HAVE_ARCH_PREL32_RELOCATIONS, meaning that the initcalls never have 
their types validated because there is no assignment:

https://elixir.bootlin.com/linux/v5.12.4/source/include/linux/init.h#L240

In the case of CONFIG_LTO_CLANG, the initcall function is called in the 
stub function, resulting in the error that we see here.

Hopefully that makes sense :)

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ad7fa126-f371-5a24-1d80-27fe8f655b05%40kernel.org.
