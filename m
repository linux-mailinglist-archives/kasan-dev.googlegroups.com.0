Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBYFQ4KOAMGQE2I6KUII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D4DC64B846
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 16:21:05 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 9-20020a1c0209000000b003d1c0a147f6sf5782109wmc.4
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 07:21:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670944864; cv=pass;
        d=google.com; s=arc-20160816;
        b=kXuYt6TRa/Zjkdi0kBv54UwoLbFgRKLE8EGGNdpbq5/7kW4PvT84Uqh3M+r3s2ABBO
         cxjYHdWleiRWajSptOq9rp3jTo9UjrdD0zm/3EQBsLxswH3j3HZu0unWUBQU0H1TkTns
         ZfVjk0nnErUmHe7pmy6TFCJbFta8otFeUmZLO9XRehBhc0keRpqF878aSK43IGSik6Ip
         aDHv/FyRm+l13DMqvk8OfnoHQqtNvYWsxJwmXPc/p9Rz6ftmi+G+pv0xUQB2m5p814pA
         5/sXmFx9mX2QxdoWxPBHomNYZ4vS0ZXGpKgdUTHLucba0IJvqG1Vm+IVh+iDAOHM/KNf
         Wfhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=e+CeaYDdf5E8D8JTIhz5/mWzYb17Lyn0asT/aL4/wBw=;
        b=jrXph8opBQoMX3AQ19s9mCoFEk+Vrma9G/cnZ9Vw6xM4PTHxdjLPdepcPk4AlaTkQX
         puHJrpMY/hUMElKEKACEQxm1IPPIrojc4GBe+ie+i5Zxk3kVL+sRa1s0wwmtzvHcBs+P
         KMBI7ufiw8haEjqHvoWNXqEdO0/fid1okAosvvhxEOH6+6pcUBekSd74m20yFYP/hLuT
         eBp9qehcnnJfpMYGgtowyF8/1gk1vkDIIr3VHuiCRa3gbyC6KAL+9eLP6s3SKRpFQZaQ
         k0WA6wU0CGSS6x9OTkMEIMU1LkvIf4nCyIy2YpHE8fNbGCWndUh9vUVr49ZflVmzQN7n
         ev3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nx8nCOKH;
       dkim=neutral (no key) header.i=@suse.cz header.b=dkWRA5cJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=e+CeaYDdf5E8D8JTIhz5/mWzYb17Lyn0asT/aL4/wBw=;
        b=bKkPTF+bR80X58Z98oPyhjKiHj0ZsYgOHe23ao/sgX+XtgnEUDAPP68wMsgcVyE6T1
         WfxP8JI1Qx/zX+HuiWYfxoqLy0mQJeqrtcuoj4urEBObRaJe4WXa2UQrUYK7nOsu/jDc
         yNQfoc9TC3V29HTJoz4+3hV79Rq1crn5sOgEEdOSgcix0nEXmApHpO+UIYuKx7H5XLp4
         2b0RxHMUPZwl/sS0jUUFK7G17qj1pTjy9cxD/Q3tVbdTKTghyaluG9o+gKPaX/qlUeks
         +gw8mdzc7Sr3fMk8cGjh40lXB9fGFIgTOhzewsy+e/yIaelnfo/1OvzO1rXRKG9qnvGr
         Ay2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=e+CeaYDdf5E8D8JTIhz5/mWzYb17Lyn0asT/aL4/wBw=;
        b=y1BHohRBXtdQ739AsFQF1wztDW+RkTuwOUOoaCNgR0zSzLYo2mYsGV7bcIBM/eN7R1
         t749xqd/HM9uT9VxX0dymEn9xLw6WR9QrvVZPk3w5GoWWnrU7CI8f1aa+xvH02rCNxnL
         N3e+2c+TyzkWWdxKWAKJHhhFL0GWS4rASeMHvBC9T5DkExCI5s8riRAPb5Qap3GhgfxD
         3e6+HTlpJbij550meHh2F173EgnMKDIC+Z08lZKPkiW0ooNHXL2c/EFwbxPzPn4hBu/M
         uuKxJuqASfDPcpk+XDJFme4I+RQCHw2duBXfvGvbTbjMOgJIKNnlsZ7HNXAYWD38q2tc
         Ok7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnuC+/h+2qBLR0byv06qTS729XeUeRbW0d5jBMYHbVDarfdeVvB
	L5VmfGZvfs8fNZDfY9Su2mo=
X-Google-Smtp-Source: AA0mqf69ck6lRPWLtEdoHoLPpWFHofqL84QPIiHl5Xvnelo9uLusTY+LT6etzV0mKH7YFPP9OstciA==
X-Received: by 2002:adf:e347:0:b0:236:76de:7280 with SMTP id n7-20020adfe347000000b0023676de7280mr60235586wrj.194.1670944864592;
        Tue, 13 Dec 2022 07:21:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3d1:be63:3b63 with SMTP id
 m23-20020a05600c3b1700b003d1be633b63ls12265823wms.1.-pod-canary-gmail; Tue,
 13 Dec 2022 07:21:03 -0800 (PST)
X-Received: by 2002:a05:600c:4e92:b0:3d0:89f5:9296 with SMTP id f18-20020a05600c4e9200b003d089f59296mr16506917wmq.17.1670944863250;
        Tue, 13 Dec 2022 07:21:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670944863; cv=none;
        d=google.com; s=arc-20160816;
        b=tTjfKqepxRuvYjOX+80XdaMuoxaIOEZ3rOsKZkuVcGCNl5X9KsFwp6dBeFGtY1a7gy
         Jt8fPO4i4NwgAgZFwkEYdsnEVRtl8hTETW9R5tRE8PNNqEhRLgMf4oW4LtiHdh15z/AW
         y6wooipnPN2GnKlFyA4w1CTggtJihKhB1P4BdpazZhh0FL8u9f76bavthppr27+z6FD2
         na+lvGLaSUPJ0bt3c40AQyiZicNIY7kYu7JsEvfqfi2fjUECFpsYDtTnmB4OfgUxMAIp
         ODv2RxsBAnbh/nYqzyfudEGrCTjGjkBMqcQcm9uuN2SggZadzZk+Oz7LaRxYSgvcCAWr
         0jdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=YiZIoKh/H3JB8O+68Jo0nbSuac+QbMa/5AjW72iFLcQ=;
        b=NFdXyStuYLLDexfuCuDzfc2dcZ76e+JUl9RTSAPeS8cEZeabwqhJvWS16E7HD+GmSG
         Zvo+79V55z2fwhup2foDI3RZz1SImauPwuicEwz7yuuXfzHPsbHYg39K+PsFI3NPbM/p
         QhUD8dG5WLS6DZLjim12KQ+R1nx/9lvmxfHbD2cYbrKsC8EO+EkD5QVRwFqZWK+6XPSv
         GvF5M/Y54tHuE6NQeQv2zMIWrc2tpsvsYuI449Pr4OtXvuptfdaJdM7xaUdBtDNwyXCV
         i2+Egkxf9TqZxvwzol0mE2DwfXbHDGahPKD57u8C/VUpSrQ0ytHW99Am6Ni302pvwOub
         GsZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nx8nCOKH;
       dkim=neutral (no key) header.i=@suse.cz header.b=dkWRA5cJ;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id 65-20020a1c1944000000b003d090dbdab3si120061wmz.1.2022.12.13.07.21.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Dec 2022 07:21:03 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id DB4461F8B6;
	Tue, 13 Dec 2022 15:21:02 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id A849D138EE;
	Tue, 13 Dec 2022 15:21:02 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id c/e2J16YmGMsEgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 13 Dec 2022 15:21:02 +0000
Message-ID: <97c5df42-c6ea-8af5-a727-f1fd77484a59@suse.cz>
Date: Tue, 13 Dec 2022 16:21:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: mainline build failure due to e240e53ae0ab ("mm, slub: add
 CONFIG_SLUB_TINY")
Content-Language: en-US
To: Guenter Roeck <linux@roeck-us.net>,
 "Sudip Mukherjee (Codethink)" <sudipm.mukherjee@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Marco Elver <elver@google.com>
References: <Y5hTTGf/RA2kpqOF@debian> <20221213131140.GA3622636@roeck-us.net>
 <48cd0d18-a13c-bf20-e064-2041f63b05bf@suse.cz>
 <fd532051-7b11-3a0a-0dd1-13e1820960db@roeck-us.net>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <fd532051-7b11-3a0a-0dd1-13e1820960db@roeck-us.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=nx8nCOKH;       dkim=neutral
 (no key) header.i=@suse.cz header.b=dkWRA5cJ;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/13/22 15:11, Guenter Roeck wrote:
> On 12/13/22 05:27, Vlastimil Babka wrote:
>> On 12/13/22 14:11, Guenter Roeck wrote:
>>> On Tue, Dec 13, 2022 at 10:26:20AM +0000, Sudip Mukherjee (Codethink) wrote:
>>>> Hi All,
>>>>
>>>> The latest mainline kernel branch fails to build xtensa allmodconfig
>>>> with gcc-11 with the error:
>>>>
>>>> kernel/kcsan/kcsan_test.c: In function '__report_matches':
>>>> kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]
>>>>    257 | }
>>>>        | ^
>>>>
>>>> git bisect pointed to e240e53ae0ab ("mm, slub: add CONFIG_SLUB_TINY")
>>>>
>>>
>>> In part that is because above commit changes Kconfig dependencies such
>>> that xtensa:allmodconfig actually tries to build kernel/kcsan/kcsan_test.o.
>>> In v6.1, CONFIG_KCSAN_KUNIT_TEST is not enabled for xtensa:allmodconfig.
>> 
>> OK, so IIUC
>> - e240e53ae0ab introduces SLUB_TINY and adds !SLUB_TINY to KASAN's depend
>> - allyesconfig/allmodconfig will enable SLUB_TINY
>> - thus KASAN is disabled where it was previously enabled
>> - thus KCSAN which depends on !KASAN is enabled where it was previously disabled
>> - also arch/xtensa/Kconfig:    select ARCH_HAS_STRNCPY_FROM_USER if !KASAN
>> 
>>> Downside of the way SLUB_TINY is defined is that it is enabled for all
>>> allmodconfig / allyesconfig builds, which then disables building a lot
>>> of the more sophisticated memory allocation options.
>> 
>> It does disable KASAN, but seems that on the other hand allows enabling
>> other stuff.
>> Is there a way to exclude the SLUB_TINY option from all(mod/yes)config? Or
>> it needs to be removed to SLUB_FULL and logically reversed?
>> 
> 
> "depends on !COMPILE_TEST" should do it. Not sure though if that would just
> hide the other compile failures seen with powerpc and arm allmodconfig
> builds.

Hmm yeah it seems rather arbitrary and not fixing the root cause(s). If some
options are broken and it becomes apparent due to a change affecting
allmodconfig in a way that enables them, then I'd assume the same could have
already happened with randconfig? So it's best to fix that, or at least
disable those failing options on the respective arches deterministically.

Also worth noting why I resorted to making KASAN depend on !SLUB_TINY:

https://lore.kernel.org/all/14bd73b0-5480-2b35-7b89-161075d9f444@suse.cz/

It's because KASAN_GENERIC and KASAN_SW_TAGS will "select SLUB_DEBUG if
SLUB" and apparently Kconfig doesn't consider it an error, but just a
warning, if that conficts with SLUB_DEBUG depending on !SLUB_TINY.
I just realized that KASAN_HW_TAGS doesn't have this 'select' so it could be
compatible with SLUB_TINY but I disabled that combination as well.

I suppose something like "select SLUB_TINY=n" doesn't exist, as that would
make the KASAN choice "stronger" than SLUB_TINY.

It would probably be the cleanest if the KASAN modes that need SLUB_DEBUG
just depended on it instead of selecting it.

> Guenter
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/97c5df42-c6ea-8af5-a727-f1fd77484a59%40suse.cz.
