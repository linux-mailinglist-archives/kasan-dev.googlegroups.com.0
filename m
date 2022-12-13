Return-Path: <kasan-dev+bncBC7M5BFO7YCRBJUQ4KOAMGQEFABG3VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 6468E64B6FD
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 15:11:52 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id f39-20020a9d03aa000000b006705c6992dasf8706861otf.14
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 06:11:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670940711; cv=pass;
        d=google.com; s=arc-20160816;
        b=gg/VC/ZKPVmsSMgc2NZ9nYlc5Ey5qqnuVLOi1UW7hdkHQGUdbUq3b+IYg+KQbqC6La
         rA3t520UlwFwuCRAtyfdLx+5LiYHsShMknpGvX2NWHUQVW5+DIqJgTTQyvy8PRveSW/H
         u+3GVNGAS/JmzAviogVNILKuOqhxE4rEWoRbetpXe6zcTyrGsvqgtZFmOu2nEPzdVeVb
         UyERCLbFIEI28suR0U6J6/1Tcys87evgkwVGynq8MK6wC+6achkyVpNtRuWr9DSUdB+r
         BG9G7DxADqhtz0XTIhzd0KziWdbF9tJCfsreziYjix7RIei0uENdLIqz5yIxgxVwPcOz
         Z4Qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=0AM3E4CJG5wAiJOsI+BLYAb13zPpiNqn89h28tp2DUE=;
        b=AHK1Z6kMheheBKL2OJm56glXngHuYmmGIDTYJxPyJ7CethtjChEosvNPNVyTp4TEly
         UOcSNLu3Y83EfzIPQpvdVyVOXnR4jt1lR+GjT8Dycx/UxBvoMJXqjUv887TuuFSALwGS
         gdogpMATcqavomExboz/8N8MzqlMHiVA5VXGfIKZHa6gT+7NAm82rfy4JzaXRt9q8ZFu
         Mvm3L1DRniY0vYNyVnBxyD3hxnDuEnzqAYCPemLgn4bFSUALIrTq2QX+rmjC4p0V2BLc
         kriMNHF3uso2Q+dApDlYyYr2W7rcXmLxJ+bbjX4bX56esgNnCSjz9U3VnJkIN1jLDF1u
         sDXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=odseQVN4;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0AM3E4CJG5wAiJOsI+BLYAb13zPpiNqn89h28tp2DUE=;
        b=S7eKd+u93tL/soWWhxb7bp2ihQd21tVAjeKCg5W+ERWIiG1y18zxvvjbwMODPLy/DE
         iPC79dlqc0W8NynxlfwQyA8cf3L8Mf/Yfjtw5bepMn6u6iHPX5jb+OSgtx6RBHz1dKTE
         WzlMHi1wvzAU8KOo0ZkaJNODRoACLNmySsVb3m1/5jcmGM9jo+PLjVGpqUxexIKZmVpV
         +4B4kOTx+8WHXwiUb3RTw0Ft0v5nvwWk5GaljUSKwud39yyDMcaPJlFbNb7VnSPiQBaL
         5bx9eeXF/fQi0YdHu4UIZw8P4cI6A0/XNaIdrLzhWZoRi4rju11U1M0FQuzGZKHb7rUa
         4Hmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0AM3E4CJG5wAiJOsI+BLYAb13zPpiNqn89h28tp2DUE=;
        b=7AoXQZeZgt1mh5PDgXcBMc3CSIEcn+1e8EXmQM4k0yjEZJDhRhZuEGSsjYvM1TDAt3
         9ErWqWZHGiiDTUn8rixdRSMnVRE3YRR27f9f56KyVUPxTyoUb5G2feOKRdhX32fumPMi
         JEZn8uCs7VZYbUXxkvtPLkwmrBMsT5v4IUWSQP07yP7eVo0Bl2D9HHio51g+Q62nFgP8
         4WQwshegOkhgZrnoIbIrDTO3jZm9UZxZss2KQLFjJgiFI5S/l0U8rqKNzkZrUme7PLNS
         lHdUYj6uAmiFmZC4FHxWm0aotSepK9wPySmLreRezhDE7XOrpiZajxtuci5CUIVZuEOM
         sJUQ==
X-Gm-Message-State: ANoB5pnFvmKLWWYT0I+AjK9pkLQCooAwByZl+IyB29EoMsKki6MaNBBu
	bN+E+bbKUNBSrw258ILrMQc=
X-Google-Smtp-Source: AA0mqf4ycIYLixEt8LKnKYzg4BxdJTCfUr479VrByd73rpwdr6//6qZ6B/H5gAHwxHAK3mjBppWGTw==
X-Received: by 2002:aca:171a:0:b0:35b:872b:edfb with SMTP id j26-20020aca171a000000b0035b872bedfbmr149866oii.166.1670940710795;
        Tue, 13 Dec 2022 06:11:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:e28f:b0:13d:173c:e583 with SMTP id
 v15-20020a056870e28f00b0013d173ce583ls5476993oad.0.-pod-prod-gmail; Tue, 13
 Dec 2022 06:11:50 -0800 (PST)
X-Received: by 2002:a05:6870:7390:b0:144:fb4f:82a6 with SMTP id z16-20020a056870739000b00144fb4f82a6mr10707326oam.56.1670940710268;
        Tue, 13 Dec 2022 06:11:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670940710; cv=none;
        d=google.com; s=arc-20160816;
        b=Qj0CWR2EWksLnBZZJZEY+1ojy9OeSRoFyEaQCLc3p4yJiC7VXs91Mt4WMxTpHr9xsX
         brR7+JNx1cTqgD7+T3q4xtsGSKntct2D5xSKqT4LbA7ec1vj3ax//cd/gyWZZxdFrlPT
         0P8Q6ic6pCfOfZg1G5YB46/onbJGxBsZwidtwXj4qh0Vdixt93CMMOgUnU1ZdMs9KK9D
         ed9E+QK56owXqh1KqTUn8XqR/CaI0TlpEeiTqR04K9BpNz76esHJuuXnIxAdhrO1Cp5z
         +QepMVC0NLNNHn+HJ+816+is1Xp6E2CLsLgAkO3opKWmjcHQ5cRFlErZf60uQrDSYqCp
         KIig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=T9fBPZ3cvhwxlIbAToCD1RhaObrm4/4AXeDAeYG8TUw=;
        b=LcWJIsw5i5ZB0axqaslEbzV7mT7u+Osh4wJncgY/WQ4Js3sB3GSavYIR3CylT/dyiK
         vm0ifc06s2c62qBGQMdPlxU8h252IKKD4chAiXrXzi1cegdiNV6/qvLLuLGI/nY0i8LQ
         ecWtd+UWmI28Tnvgl92vwbI6xqgAp34Fk60P1O5bAnBHLUvvjo/w5DHB8pavLhXep4c0
         AgZqSuRHh7kmbybD5m9e2XO3NIzuJGKr4Gi7B6P6l2VU+a+D6f4+8UAb32Y6lC1JIuHu
         AHdslk7L+6aYtIhiQT7cx0hFnBjRLW3b8tlueTFQcxqsKaTN1Ix1G6e1gdwKsXMjKVG5
         Ml7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=odseQVN4;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id ep2-20020a056870a98200b00143cfb377b2si404952oab.2.2022.12.13.06.11.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Dec 2022 06:11:50 -0800 (PST)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id v82so14288513oib.4
        for <kasan-dev@googlegroups.com>; Tue, 13 Dec 2022 06:11:50 -0800 (PST)
X-Received: by 2002:a05:6808:1987:b0:35e:4393:8d71 with SMTP id bj7-20020a056808198700b0035e43938d71mr12693104oib.28.1670940709975;
        Tue, 13 Dec 2022 06:11:49 -0800 (PST)
Received: from ?IPV6:2600:1700:e321:62f0:329c:23ff:fee3:9d7c? ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id a30-20020a544e1e000000b0035a9003b8edsm4561548oiy.40.2022.12.13.06.11.48
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Dec 2022 06:11:49 -0800 (PST)
Sender: Guenter Roeck <groeck7@gmail.com>
Message-ID: <fd532051-7b11-3a0a-0dd1-13e1820960db@roeck-us.net>
Date: Tue, 13 Dec 2022 06:11:47 -0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.2
Subject: Re: mainline build failure due to e240e53ae0ab ("mm, slub: add
 CONFIG_SLUB_TINY")
Content-Language: en-US
To: Vlastimil Babka <vbabka@suse.cz>,
 "Sudip Mukherjee (Codethink)" <sudipm.mukherjee@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 Linus Torvalds <torvalds@linux-foundation.org>
References: <Y5hTTGf/RA2kpqOF@debian> <20221213131140.GA3622636@roeck-us.net>
 <48cd0d18-a13c-bf20-e064-2041f63b05bf@suse.cz>
From: Guenter Roeck <linux@roeck-us.net>
In-Reply-To: <48cd0d18-a13c-bf20-e064-2041f63b05bf@suse.cz>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=odseQVN4;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::232 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On 12/13/22 05:27, Vlastimil Babka wrote:
> On 12/13/22 14:11, Guenter Roeck wrote:
>> On Tue, Dec 13, 2022 at 10:26:20AM +0000, Sudip Mukherjee (Codethink) wrote:
>>> Hi All,
>>>
>>> The latest mainline kernel branch fails to build xtensa allmodconfig
>>> with gcc-11 with the error:
>>>
>>> kernel/kcsan/kcsan_test.c: In function '__report_matches':
>>> kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]
>>>    257 | }
>>>        | ^
>>>
>>> git bisect pointed to e240e53ae0ab ("mm, slub: add CONFIG_SLUB_TINY")
>>>
>>
>> In part that is because above commit changes Kconfig dependencies such
>> that xtensa:allmodconfig actually tries to build kernel/kcsan/kcsan_test.o.
>> In v6.1, CONFIG_KCSAN_KUNIT_TEST is not enabled for xtensa:allmodconfig.
> 
> OK, so IIUC
> - e240e53ae0ab introduces SLUB_TINY and adds !SLUB_TINY to KASAN's depend
> - allyesconfig/allmodconfig will enable SLUB_TINY
> - thus KASAN is disabled where it was previously enabled
> - thus KCSAN which depends on !KASAN is enabled where it was previously disabled
> - also arch/xtensa/Kconfig:    select ARCH_HAS_STRNCPY_FROM_USER if !KASAN
> 
>> Downside of the way SLUB_TINY is defined is that it is enabled for all
>> allmodconfig / allyesconfig builds, which then disables building a lot
>> of the more sophisticated memory allocation options.
> 
> It does disable KASAN, but seems that on the other hand allows enabling
> other stuff.
> Is there a way to exclude the SLUB_TINY option from all(mod/yes)config? Or
> it needs to be removed to SLUB_FULL and logically reversed?
> 

"depends on !COMPILE_TEST" should do it. Not sure though if that would just
hide the other compile failures seen with powerpc and arm allmodconfig
builds.

Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fd532051-7b11-3a0a-0dd1-13e1820960db%40roeck-us.net.
