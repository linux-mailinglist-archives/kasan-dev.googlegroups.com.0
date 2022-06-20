Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB26CYGKQMGQEFAGMOFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 29BEB5517EC
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 14:00:46 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id c5-20020a056512238500b0047954b68297sf5414324lfv.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jun 2022 05:00:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655726445; cv=pass;
        d=google.com; s=arc-20160816;
        b=yVLZKLx9U2G+QI22+XgpDPgXXxWWUYbuPT53xPvPEPeQxU4UR3IVS2Gz6TqtivnohC
         IMQupxaQxZv4EHw1UE9oq67dTIcNw7Oi1xxPK10+jg/cZ/Ib0WM9psQXXNGKHZE1+px6
         OLdxkWnJvyhUzqIVr5S5CpmCmxDE2sTOAcFyRzmNZp/yZl+RlvkZQb6EqPgCl7xDMntx
         HS6wvQlnORs5Ck2drliR17x+3Xyiyeki/uwjxinXkQUQzGBYiwtqrj2DYUsOQ0JZMHix
         e54eZQjPcmsGkMTVkahEVYcnKvjMdM1pivE3hkL6GZrwYauwJy3o26vBAf6Dpj9z2NWM
         TVPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=joFTWV4FlbVwSvmzew22BJcQ2EHrOuvmzxaTmznPbOc=;
        b=fRMrUi2L/HVmyVYlP35uvdJes78CPsh5nnzYKQ/0HMiZ6nEfvfGukg/awb2T4VRCpT
         iFvEZzB3+nVcuGQ8eMS1BT0Uzq/PtkGsjghVENgXIcyBt5X14kg9ImQIdgZrzqOZ8hyI
         OOnubDZTGNdp0cnXsE7JnQSkBqpt1OXv3TAvCE9GOkiL3Ng2DPSFAfakqeC8GoSnJlrd
         1pPacrfVwlGiV/Et9nY3+idXaWYysjeaEYYoIS8Lj0oYKqUgrRBZ/em/+36iy1zrPEDy
         VsCyvT3D90c/Q96tlCYrWGgkxvqoEB+mLtPiCfrEye2Pjm+LMcfgMYxqWltKxjU2Yijo
         8BYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0QbMavM0;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=joFTWV4FlbVwSvmzew22BJcQ2EHrOuvmzxaTmznPbOc=;
        b=WPyBq/FBTZaQvjh0A920Q1mOihZH4IAjHUP+oyw6/vcq2yunePimfCgSQ8heL+km9D
         QIIN+eOoUpE5Z9qAVmNK6Zzs4ebrfRkHqyuq++HohM/Zuc3CfUeUUvccj6DRZVCkBs9j
         Rw0WTCWC4Iv03rTDJIB0l385X6CjUtmytiEL9tUcOqZciN+7nDL2ZxPOTwBx+n/luRXz
         Q0A8wXwvg7I0jOMCkpr56xG7BveU3tcpob0qQa56NfQ4UgeadmIqia/YObO6wz7NmKP5
         wk+wlhV68F9x8rejWM24cPOJtXUZCmK8wkMh66TYAcysVlADrjKXiiqEtUmh9AwSotrm
         W9/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=joFTWV4FlbVwSvmzew22BJcQ2EHrOuvmzxaTmznPbOc=;
        b=hKUh6KmWPGwRCuLDSuXOQIzcue7U6gG7IHLJpOWKwCbxcLGcevqgPhVSgl4b2hWm7v
         FDobZ6UKfWsVKeh3CXEOKpt+ipiz8EoIh0BK8gs36KAQ/e1xCtoVGD/dvpSnlGuplV5i
         a9CB1y6F5SzXlIcVcYVTpUE3IAbSD2G7ultysqAli9ckDYTutEhEfJmLarWUb/ryR0k5
         mN42cEfJhhmQTclXSg6gNlvKKoFoui1cvrZkR6FTgKsDVxhVQznOR8TDyE24Ly8fK526
         dnje1NOA/93zyVvQx9chLd6rS8akZAmEl3U1Gsrq6w8xGaj4EgM0C4ar9TUKdFKR6uO3
         WmEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+2sZ1SHAElCaKMo2FPVZ3rEJcwN1UivG8i5iuYL+7TC0wwo/TY
	BKs2GApyix7w2CeaFiCj6fQ=
X-Google-Smtp-Source: AGRyM1s627VAuSMh7C6R/h/7fbqC8LytfHPj/cj/UxKOECfEmctOwM4S76oluNchddXHED+1CFK08Q==
X-Received: by 2002:a05:6512:22d3:b0:47d:a6e4:4232 with SMTP id g19-20020a05651222d300b0047da6e44232mr13424724lfu.671.1655726443637;
        Mon, 20 Jun 2022 05:00:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls11938lfb.1.gmail; Mon, 20 Jun 2022
 05:00:41 -0700 (PDT)
X-Received: by 2002:a05:6512:22d0:b0:47b:8fe3:957f with SMTP id g16-20020a05651222d000b0047b8fe3957fmr13777806lfu.435.1655726441778;
        Mon, 20 Jun 2022 05:00:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655726441; cv=none;
        d=google.com; s=arc-20160816;
        b=oKaTWcB4gmgDVYdKuy54dzhRQNJ5aHWxrUd0vKDizcFoZ/9gn73nV3waTfHifjaXt4
         ILifH2Iuw2Wb0n9tKYbG+J8EXVG+Dsxf8LPjM8/fDwXwB3uaGM52IZV7NGMq9QCBCHd9
         JX9BLUIPtQwzymbV0n3uopy5502XVMOkjgyW5lvv5xyLrssJ1Fa17NDp/v3iGdbepG8t
         XK0beZ3uJhZ72kmeptC7jDqejbpP9zVqYMY9pNoVDGFDWvroefdHA1IS8mXXgnv/PtgP
         PNRYbW6ZaO4Ig4kVEYrHyGdbExtOc+z9TcrB3xtsidpsB6uax+hBEGn1m50csZGIiw5w
         XE0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=6rWFG3uWKuuKdwZT86iOp2RBtyzj8xN/EPYd8WQXuuY=;
        b=khGAoQaswu5hF4DOpovsfLjVBI94OEtcvo6S8GepitzLjySQLJZnkMuXFbfMXamF8f
         PS+EeN3qLNFHdET+paZ5xVmjsLGlr3/gjADUCiiHNy1eoukyt4ndKeAH03rYG6+wJWLX
         l8aLVM7bbhvXkGqIJkmdqPX3mUdjUXhFip9ATlz/PB4GiGXyc67YeIk6MzqKqjvYTm0S
         WYD5Bz0rvIGCpa6frNrdczAcOVCxOzZc+IQ06mWP/yCQ1u4NwekyqGMBkapk29zG7UhF
         +sJ4J+he7oJpzLpxgr1wpwkYU8CwprYN6IKekXsEuhheCW2EiJHYYmtH64mIroYbWpmL
         d/mA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0QbMavM0;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id u7-20020a056512128700b0047f6890422dsi178921lfs.9.2022.06.20.05.00.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Jun 2022 05:00:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 3ABC121AD3;
	Mon, 20 Jun 2022 12:00:41 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 1AC13134CA;
	Mon, 20 Jun 2022 12:00:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 4ZbUBWlhsGLaEwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Jun 2022 12:00:41 +0000
Message-ID: <93bf8148-ecc1-75fb-423b-2a76c7252c4e@suse.cz>
Date: Mon, 20 Jun 2022 14:00:40 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
Subject: Re: [RFC PATCH 1/1] lib/stackdepot: replace CONFIG_STACK_HASH_ORDER
 with automatic sizing
Content-Language: en-US
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@gmail.com>,
 kasan-dev@googlegroups.com
References: <20220527113706.24870-1-vbabka@suse.cz>
 <20220527113706.24870-2-vbabka@suse.cz>
 <CACT4Y+Y4GZfXOru2z5tFPzFdaSUd+GFc6KVL=bsa0+1m197cQQ@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CACT4Y+Y4GZfXOru2z5tFPzFdaSUd+GFc6KVL=bsa0+1m197cQQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0QbMavM0;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 5/27/22 14:02, Dmitry Vyukov wrote:
> On Fri, 27 May 2022 at 13:37, Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> As Linus explained [1], setting the stackdepot hash table size as a
>> config option is suboptimal, especially as stackdepot becomes a
>> dependency of less specialized subsystems than initially (e.g. DRM,
>> networking, SLUB_DEBUG):
>>
>> : (a) it introduces a new compile-time question that isn't sane to ask
>> : a regular user, but is now exposed to regular users.
>>
>> : (b) this by default uses 1MB of memory for a feature that didn't in
>> : the past, so now if you have small machines you need to make sure you
>> : make a special kernel config for them.
>>
>> Ideally we would employ rhashtable for fully automatic resizing, which
>> should be feasible for many of the new users, but problematic for the
>> original users with restricted context that call __stack_depot_save()
>> with can_alloc == false, i.e. KASAN.
>>
>> However we can easily remove the config option and scale the hash table
>> automatically with system memory. The STACK_HASH_MASK constant becomes
>> stack_hash_mask variable and is used only in one mask operation, so the
>> overhead should be negligible to none. For early allocation we can
>> employ the existing alloc_large_system_hash() function and perform
>> similar scaling for the late allocation.
>>
>> The existing limits of the config option (between 4k and 1M buckets)
>> are preserved, and scaling factor is set to one bucket per 16kB memory
>> so on 64bit the max 1M buckets (8MB memory) is achieved with 16GB
>> system, while a 1GB system will use 512kB.
> 
> Hi Vlastimil,
> 
> We use KASAN with VMs with 2GB of memory.
> If I did the math correctly this will result in 128K entries, while
> currently we have CONFIG_STACK_HASH_ORDER=20 even for arm32.
> I am actually not sure how full the table gets, but we can fuzz a
> large kernel for up to an hour, so we can get lots of stacks (we were
> the only known users who routinely overflowed default LOCKDEP tables
> :)).

Aha, good to know the order of 20 has some real use case then :)

> I am not opposed to this in general. And I understand that KASAN Is
> different from the other users.
> What do you think re allowing CONFIG_STACK_HASH_ORDER=0/is not set
> which will mean auto-size, but keeping ability to set exact size as
> well?
> Or alternatively auto-size if KASAN is not enabled and use a large
> table otherwise? But I am not sure if anybody used
> CONFIG_STACK_HASH_ORDER to reduce the default size with KASAN...

Well if you're unsure and nobody else requested it so far, we could try
setting it to 20 when KASAN is enabled, and autosize otherwise. If somebody
comes up with a use-case for the boot-time parameter override (instead of
CONFIG_), we can add it then?
>> If needed, the automatic scaling could be complemented with a boot-time
>> kernel parameter, but it feels pointless to add it without a specific
>> use case.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93bf8148-ecc1-75fb-423b-2a76c7252c4e%40suse.cz.
