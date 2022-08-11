Return-Path: <kasan-dev+bncBDWLZXP6ZEPRB6FJ2OLQMGQE7QJQVNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0032C58FA6B
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 12:07:53 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id z7-20020a2ebe07000000b0025e5c7d6a2esf5303418ljq.20
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Aug 2022 03:07:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660212473; cv=pass;
        d=google.com; s=arc-20160816;
        b=BNbgGddO8L5cKxe+wC3yafnRjmYtPfsmNgaiRRR3S3i0BrP3k9SQ0CSAuLgEFUdu9D
         Ald3N2TzCDWF9733OGdCTLkJEo9Arx8+6ldys///PwACXegF+6bqIZovHFbfHODOwor8
         D2AgIk6/2pAyIanKR3nrTcSOxMsn/1ZFNDxI1boOb5fUSmEIDJxm9lKw3vJ7+CZj3Nkh
         tu5QzT/7rE1SiryQw9Th1SSZOLNgz3oyhZUVt1m5Q7fbhBXwkRkvc7/GEFOx1daxzaMm
         Ie7bBNsebJt0OK4tKG21VZShOxFym4A2MPwD8OBQ23Hl8Vyj/uNIBX39CEVM70HRavrU
         SUiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to
         :content-language:subject:from:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=F1nfqZtIlc9akUYnFfKElFrbvH1zxUPSbsPhIFOh/uE=;
        b=kxLOYt8g3ywf0SByAUTemFO5pCmVRT89aFGNDjRFXrNLSoNxBtphShhfmyGDHBikkK
         UZR5X8uvBCIbtWF9q/s9eF6uGyRw7O5xmBpboWfcmR4rDcs7Iy4lNWqKn1EwYnO9DZVJ
         AIntwJtYSDgGoVSgCkpgQpnCFs7Ap88kbR54SOzC6l/aCH5roXir4kzfr7Zma4OXokU4
         xLDIfMaoJizDSqs/wcWhKFto7GD/EoKJnvWrQZcOFj/zoLGGrzdgSVM7td0iyt/MBOeF
         KPe62dLzIUwYZ589kLdnhOt7M5Qgj/4PbqvTQfFcGgCwBlrNCpcV09xuYcqCmhRY+FhP
         9G9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZNWqhyyQ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:content-language
         :subject:from:user-agent:mime-version:date:message-id:sender:from:to
         :cc;
        bh=F1nfqZtIlc9akUYnFfKElFrbvH1zxUPSbsPhIFOh/uE=;
        b=CYTSkDQp8UfkXxlO9ru8+KJkQCN/vryR8siufraZ6/w3HAIEm2G2hJ2chMX/0NllmT
         fPguF84DlxugOOFbDPHm7X272HxTnooMHrD/LBGyIMX4ofsuYunBdPZQmANwdJuwqydG
         Eb8sOkXRY/PXmj8nERFv/yZOw0vU4yf2tO/3vIJNSxxLJEmfmCpfH2TKIJ2bISk9SE6j
         /cIcaffmZrDCWi4czdLZtnY56MBNNaI7KLUqF7H6YVTIePyacA55icbMhnEBsm2/eLBC
         st6QDhPE7/TvANPvo/zTr8OZc5tG2qg26x+PioEPmjw4brloKpgxODvjEM1lMxsxvBAO
         hp6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:content-language:subject:from:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=F1nfqZtIlc9akUYnFfKElFrbvH1zxUPSbsPhIFOh/uE=;
        b=2185+jaDoGOKZNwr+Jo/2waBYJrqbJu5QvadaWUJDjEz7uV/GhNNGhBtsYTUDZWWqM
         zx/BjP856rgLedy0+NXrbFdeN2qiQJ6J4N3cpZtCFCV5nHO/LgV/IvVHn6nrS8/Ihtm8
         MOxFKruZbFHIk/4c3bKZJ0MLjHXOeRD3iXVanEa0jpmx73WeoxERPS+oVS/cjMPrJJTt
         V0V5J7hhabvUrV6M10C+syIjml1nk/spiCbGW53HS2nxBHAS+CUJtIQhc4grqJmsdD+5
         bV+OoKcitO0V3t6P6FYvv2c1th/8Gx2Jnkac2cwNYpZCLAr3GlHSORgpNQkYfTE5kJAu
         iIVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2PTxKs9RiBE0gCHdypBgRUudFaUxsyyIe65nCoMI345/68bzYx
	iLKOHGB5CBvp6TAOCHNYk9Y=
X-Google-Smtp-Source: AA6agR5HfKz/hYL0WB9GdwLutjBkyICjRIPj84ahbBCO3SXLUuXpNnH5YT02hrkjUArkpddbQsmX+A==
X-Received: by 2002:a05:6512:3da0:b0:48b:3976:b323 with SMTP id k32-20020a0565123da000b0048b3976b323mr10239967lfv.402.1660212473165;
        Thu, 11 Aug 2022 03:07:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2112:b0:48b:3a68:3b0 with SMTP id
 q18-20020a056512211200b0048b3a6803b0ls782821lfr.0.-pod-prod-gmail; Thu, 11
 Aug 2022 03:07:51 -0700 (PDT)
X-Received: by 2002:a17:907:1c8f:b0:6e8:f898:63bb with SMTP id nb15-20020a1709071c8f00b006e8f89863bbmr24258569ejc.721.1660212460938;
        Thu, 11 Aug 2022 03:07:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660212460; cv=none;
        d=google.com; s=arc-20160816;
        b=plIoH1HWftbYZE4VU4UZkSin0XsslVx0Mhd49CgdqxSDnigKM0QKpOqnpE133fcMq5
         VQnUZUiAbw5mo/E832ihMMKCE70/PU4b3JPxwQWknrI893Mb45Z9rQlUFkVINBuy2FEY
         xlW+sRkbky/+jdAp8Df/osiN6nIEhIr+YRlcUPjtNFgzwrBodhfK8tJXNhdExPsll4yB
         JDyLBVk7/gMtyWsEhUx3e272mi8xynrbtIJjgNzCGwQSX2YdbTtYqepoawi+JHbq7LEK
         +3b9ZEH8I/LgpyVajSgXCykBYrKtcBhRAU9iVql8kxDh5BAtwz9WjFZrfgkHHfgA9shl
         3o9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:references:cc:to
         :content-language:subject:from:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature;
        bh=mCxIbVIOyyg/Zymr2tIkgto6cQ3worjVRRoTjkKlzPg=;
        b=JPN8M973amc3qKMf/iGaKpXxLrLl3ztsPxl7/SZG1mdcveBo5KWHq8aVFyNvzsu37r
         aV0Pd1D5gaPC5Rvn0LEOR25KeJxPUDgzZI0bp1nqyqyb+jqjQVQ9LJJFxi0qHwfrS9hB
         9UZUdQJdol06DbD12VwnMR5V199IfxDWUeQZZudusI1KXBUltPlTCaUgJqsSkpAtQnxJ
         L+fvBZ/mXEcOR8NgfBACmbIYIMaF7mB3S56Pe8zywtqGIS7xUpc0pceEGyusze4f276Y
         fiP9d8+tr1uOFRTdoL9Re7/Hx07O/DLs8SRaTC+ZUwOIsYQltfMgqgfEQ2DudTX998ZV
         zG9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZNWqhyyQ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id jx2-20020a170907760200b0072a6696083bsi151783ejc.2.2022.08.11.03.07.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Aug 2022 03:07:40 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 860A5204E2;
	Thu, 11 Aug 2022 10:07:40 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4C97513A9B;
	Thu, 11 Aug 2022 10:07:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id MhDqEezU9GJiAgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 11 Aug 2022 10:07:40 +0000
Message-ID: <6b41bb2c-6305-2bf4-1949-84ba08fdbd72@suse.cz>
Date: Thu, 11 Aug 2022 12:07:40 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.1.0
From: vbabka@suse.cz
Subject: Re: [PATCH v2] Introduce sysfs interface to disable kfence for
 selected slabs.
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Imran Khan <imran.f.khan@oracle.com>, glider@google.com,
 dvyukov@google.com, cl@linux.com, penberg@kernel.org, rientjes@google.com,
 iamjoonsoo.kim@lge.com, akpm@linux-foundation.org, roman.gushchin@linux.dev,
 42.hyeyoo@gmail.com, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
References: <20220811085938.2506536-1-imran.f.khan@oracle.com>
 <d3cd0f34-b30b-9a1d-8715-439ffb818539@suse.cz>
 <CANpmjNMYwxbkOc+LxLfZ--163yfXpQj69oOfEFkSwq7JZurbdA@mail.gmail.com>
In-Reply-To: <CANpmjNMYwxbkOc+LxLfZ--163yfXpQj69oOfEFkSwq7JZurbdA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ZNWqhyyQ;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/11/22 11:52, Marco Elver wrote:
> On Thu, 11 Aug 2022 at 11:31, <vbabka@suse.cz> wrote:
>>
>> On 8/11/22 10:59, Imran Khan wrote:
>> > By default kfence allocation can happen for any slab object, whose size
>> > is up to PAGE_SIZE, as long as that allocation is the first allocation
>> > after expiration of kfence sample interval. But in certain debugging
>> > scenarios we may be interested in debugging corruptions involving
>> > some specific slub objects like dentry or ext4_* etc. In such cases
>> > limiting kfence for allocations involving only specific slub objects
>> > will increase the probablity of catching the issue since kfence pool
>> > will not be consumed by other slab objects.
>>
>> So you want to enable specific caches for kfence.
>>
>> > This patch introduces a sysfs interface '/sys/kernel/slab/<name>/skip_kfence'
>> > to disable kfence for specific slabs. Having the interface work in this
>> > way does not impact current/default behavior of kfence and allows us to
>> > use kfence for specific slabs (when needed) as well. The decision to
>> > skip/use kfence is taken depending on whether kmem_cache.flags has
>> > (newly introduced) SLAB_SKIP_KFENCE flag set or not.
>>
>> But this seems everything is still enabled and you can selectively disable.
>> Isn't that rather impractical?
> 
> A script just iterates through all the caches that they don't want,
> and sets skip_kfence? It doesn't look more complicated.

Well, yeah, it's possible.

>> How about making this cache flag rather denote that KFENCE is enabled (not
>> skipped), set it by default only for for caches with size <= 1024, then you
> 
> Where does 1024 come from? PAGE_SIZE?

You're right, the existing check in __kfence_alloc() uses PAGE_SIZE, not
1024, which probably came from lack of coffee :)

> The problem with that opt-in vs. opt-out is that it becomes more
> complex to maintain opt-in (as the first RFC of this did). With the

I see. There was a kfence_global_alloc_enabled and slub_kfence[=slabs] ...
that probably wouldn't be necessary even in an opt-in scenario as I described.

> new flag SLAB_SKIP_KFENCE, it also can serve a dual purpose, where
> someone might want to explicitly opt out by default and pass it to
> kmem_cache_create() (for whatever reason; not that we'd encourage
> that).

Right, not be able to do that would be a downside (although it should be
possible even with opt-in to add an opt-out cache flag that would just make
sure the opt-in flag is not set even if eligible by global defaults).

> I feel that the real use cases for selectively enabling caches for
> KFENCE are very narrow, and a design that introduces lots of
> complexity elsewhere, just to support this feature cannot be justified
> (which is why I suggested the simpler design here back in
> https://lore.kernel.org/lkml/CANpmjNNmD9z7oRqSaP72m90kWL7jYH+cxNAZEGpJP8oLrDV-vw@mail.gmail.com/
> )

I don't mind strongly either way, just a suggestion to consider.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6b41bb2c-6305-2bf4-1949-84ba08fdbd72%40suse.cz.
