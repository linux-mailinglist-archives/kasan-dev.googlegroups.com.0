Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBVP34GOAMGQEKI3CV2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2111164B627
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 14:27:50 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id h10-20020adfaa8a000000b0024208cf285esf2928055wrc.22
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 05:27:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670938069; cv=pass;
        d=google.com; s=arc-20160816;
        b=hF4UJxKT1s043nFkY335mQXBGgoV6Kxo2seEY+JvuSY4l7nywaYz/iQW20TBZ2paWU
         l3nN+2pD/tpAnyY6jKxPimPvn64ePaOGc1RBNyS6c6PjoOvJf9OqLdHGKE5Eg3ftrrAH
         uAdHZk3S0TA3ASOirn5sI3d28CrcWqWB4t9J29qnQAPD/8xA45DyJAwoHAnQ6jNUYNgp
         IwmZOxZaax/N8ZF501fqauvpHY18w+givdAvu3VJ5nrOkaa7ZPQyjQaJGfxyeOzFNFhF
         M5UMhgdRcs0vk8UfgdHI8JF1i8giZIIwJSlArdguyeONRHzUlpZr+V7hl3DxFu2vzvm1
         mJeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=kxCIsodmhlUc6LJpfCl4hJNT3nQKDMd1QwdTLtqqJWs=;
        b=f7Xaij6xd5+9GJJYV7ULFjmnddr27lMyKJ1Khmr2EP6cmPnizJGbjz84XYWUC8X+fA
         eI6CxpUuwkW5w90oLkwEHsyJtJqXWZE3jZ7lq1/wkYei7ki0D3rI3TrDyJHbFr/wpK8S
         8SQRTMirfhzQ5XFnNuwS+FvnYn+uEE1hBwasShyeDkq4ip6TDyyJmGdrg7VwLfYWP4Aq
         efYIopUlg2UrH5FGkQUfLsBf5BKBB5RN6bSyGZiO1+96M2x+r6sLwwlhDdtZjKillkO6
         e88DQjG6EAhVlJKWKhjFO1rFOtHGpIy0NTEa2R0Ykgqv7Sj6ozmMpo4ZrjHUB1f/DEuZ
         oHMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=POrVO0Y5;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=5c39LK8d;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kxCIsodmhlUc6LJpfCl4hJNT3nQKDMd1QwdTLtqqJWs=;
        b=r8TM1ll3yvJgrapHtn0gwxNj1SAKs0A/8c8YDtxCsH4AznwJ0S2dzCY8j1xRg4Gdpj
         xA2nhzMm+b0jJTuElP5W+UOaNq7P2Xs2slbgnSAcQ/uQ2JDUTGtusk5PdT7mcsUroX3C
         YuTnFBVTlZMf+FUqFpO4PTIWHlGIVtn7PvVA4iIO05H4fP+r9F74CtZReEcYOo74V1sl
         bkY7pSOUf/3jiso5xkE1xtZEtc4Ge6bsqc6zgHdQpYl2BWP3+oom9uC1vEccAI+9RicZ
         lvepDzHp6aRmAF1wCdV6dIeYoA+tFaiCy5+sPjebQ4fhxitIKoLp5NCT2S9/Btm9+MgO
         hZHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kxCIsodmhlUc6LJpfCl4hJNT3nQKDMd1QwdTLtqqJWs=;
        b=XQaYzTLZlUFs4/zUinnCTj/9Qs8owqSowkD4rJteOHLDGGDbOR9rp5MFMbLUVYls3n
         6G/1KaMmqqWcGEnWn7hJycFJBHVkC+ksrQIFC9ktrkb7N1uLdK6Mru+DiAJEgcpphqkO
         uSjZojQiopoBZKtx3K+HzzAxYUYlkGo6V+yHsnh3Kyn8gjv3sIF8V6at90YAHnT68tlF
         dqOfWxdKgLHppFzLl+aEFKbwKTalPSLNAVeLJTZoMDmVTn/FuU12cLVqAt7ciXmYh0E/
         hGSwlAgbd/+fYfHug3aYud8zVSOgpuYQS6sMk4tU57oTEitXxCK8bmH+tUnkABHZAo0R
         6jdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkJ7dSHEAURFOMmIFZalPlW0kglF0oIyXtqUFauVHCj7cZA8x3B
	LulgXQhSdKQ4HCAfIcxDHZg=
X-Google-Smtp-Source: AA0mqf6x88aiBMUVJxz2EFS8LBycdlmZmf5Kia/ncAJTRPJMFCcaAQkiSu++vO6eF67DJb/+tR6JBQ==
X-Received: by 2002:adf:dbd2:0:b0:236:3cf5:4528 with SMTP id e18-20020adfdbd2000000b002363cf54528mr59211647wrj.355.1670938069573;
        Tue, 13 Dec 2022 05:27:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:218b:b0:3cf:afd2:ab84 with SMTP id
 e11-20020a05600c218b00b003cfafd2ab84ls10791760wme.2.-pod-control-gmail; Tue,
 13 Dec 2022 05:27:48 -0800 (PST)
X-Received: by 2002:a05:600c:35c8:b0:3cf:6e78:e2ca with SMTP id r8-20020a05600c35c800b003cf6e78e2camr15777558wmq.5.1670938068316;
        Tue, 13 Dec 2022 05:27:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670938068; cv=none;
        d=google.com; s=arc-20160816;
        b=gHfTpLp0wJxJkrDoSDahTNAqDz9Hx4BY+RHDBhKhz+pGHEDcr9OYUeD6L4zzNitN4V
         TDEVelld4sPUwBi9B79QcELVQFq9EsZfhpWmsO0o+FUFL9rDdGVhqDFhCeqcHJUXobOZ
         /CPHohFMPvP8ijP0q0b/5sx/pj3cnENLUX/yvO11QG/hwno9P89ixgKi9wOEBsYZ34Vd
         7ORRaWt7k1N2B9aMNCYRen36bvTJ2lxzeeY0bc5HK93Xj/6EC8pzw+9KOrioAJLMwial
         6wnUlldwxYSedpIANCu3y6WXld6IN9Wds3xAHdz5mrcYaRScIx8EBu5XSdd7e3a8WMfb
         t9Mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=2t/UYI9MSV5VugIDUL9AEWRw4BbvAyzLCXl4/1d9eQs=;
        b=LZzR/HnlxlUmkAY4n9yJD/fgcXYJW8tSxowlTf3u74rg3A98df8Cz9whtzCVPZQear
         tBfkAKH554UDyk2NQDd1pSiwqh+O4caZ9BahViXRkVaV57GUkTb0MdIpQANC+zpgovj0
         Titw9woJ2NqFyxtd4OGS0g+BFUFerJyViYljfkOcnIx7ibj1dscRDRJdDzdxnNmMkZhQ
         yHBhf3yw73296DoxIW2xaDCgqbL07fmyx/dea2ZrmxwwROT8J86LfP9MMcYBciezW/kz
         sMjFfsgnmo0ELs7H7yqRFrBn9H/9KalYh1rfIvN8z57QWCQESo0O20XtGbvGKoYYeOj4
         Dn/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=POrVO0Y5;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=5c39LK8d;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id by8-20020a056000098800b00236e8baff63si650497wrb.0.2022.12.13.05.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Dec 2022 05:27:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id EFBF0228EB;
	Tue, 13 Dec 2022 13:27:47 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id C7810138EE;
	Tue, 13 Dec 2022 13:27:47 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 4xX+L9N9mGPCTQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 13 Dec 2022 13:27:47 +0000
Message-ID: <48cd0d18-a13c-bf20-e064-2041f63b05bf@suse.cz>
Date: Tue, 13 Dec 2022 14:27:47 +0100
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
 Linus Torvalds <torvalds@linux-foundation.org>
References: <Y5hTTGf/RA2kpqOF@debian> <20221213131140.GA3622636@roeck-us.net>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221213131140.GA3622636@roeck-us.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=POrVO0Y5;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=5c39LK8d;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/13/22 14:11, Guenter Roeck wrote:
> On Tue, Dec 13, 2022 at 10:26:20AM +0000, Sudip Mukherjee (Codethink) wrote:
>> Hi All,
>> 
>> The latest mainline kernel branch fails to build xtensa allmodconfig 
>> with gcc-11 with the error:
>> 
>> kernel/kcsan/kcsan_test.c: In function '__report_matches':
>> kernel/kcsan/kcsan_test.c:257:1: error: the frame size of 1680 bytes is larger than 1536 bytes [-Werror=frame-larger-than=]
>>   257 | }
>>       | ^
>> 
>> git bisect pointed to e240e53ae0ab ("mm, slub: add CONFIG_SLUB_TINY")
>> 
> 
> In part that is because above commit changes Kconfig dependencies such
> that xtensa:allmodconfig actually tries to build kernel/kcsan/kcsan_test.o.
> In v6.1, CONFIG_KCSAN_KUNIT_TEST is not enabled for xtensa:allmodconfig.

OK, so IIUC
- e240e53ae0ab introduces SLUB_TINY and adds !SLUB_TINY to KASAN's depend
- allyesconfig/allmodconfig will enable SLUB_TINY
- thus KASAN is disabled where it was previously enabled
- thus KCSAN which depends on !KASAN is enabled where it was previously disabled
- also arch/xtensa/Kconfig:    select ARCH_HAS_STRNCPY_FROM_USER if !KASAN

> Downside of the way SLUB_TINY is defined is that it is enabled for all
> allmodconfig / allyesconfig builds, which then disables building a lot
> of the more sophisticated memory allocation options.

It does disable KASAN, but seems that on the other hand allows enabling
other stuff.
Is there a way to exclude the SLUB_TINY option from all(mod/yes)config? Or
it needs to be removed to SLUB_FULL and logically reversed?

> Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48cd0d18-a13c-bf20-e064-2041f63b05bf%40suse.cz.
