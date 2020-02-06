Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBH6L6HYQKGQEIYGFFRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 12951154BBB
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2020 20:14:40 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id m15sf3939434wrs.22
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2020 11:14:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581016479; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZF4dO0a4wHm3IAg4/kwz5/mOvghPSDyWisISEknUFI9NF2w5Dva1KcT339jSgsu6/d
         11g+9ODv/EwggE2jLeNwE+kgdHgrGvFA27v0h7Ed1FWxaDjfvNHH2dZTKMUE1kPsgdME
         BHeMpds3zLDmlB0F64EqBEvF/p1jhqkhf6yRK3pcDCRSOIIopvlIumUXmwgMBbB+u0hi
         T+s0SP3Fr1NqhuqWZbLTv4K0lH56cPQ9pzCuwxqAUlKzPoXNqFB41fnp3O/35Hkx/HIu
         XHy7ekfexa26pLIcWZXgEmmWBT6wR0PdX+5KqMW5dSp8Fca8cJ+ZVqubz6EJmd+xy+gP
         giKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=WZ6vY6daleIIcRx2H5ep9X630fhSfquV4HaJlN4+Qk0=;
        b=yuPbxn7R6sKjpJCurKRgpEMB8WPIqk/dTZ1gC9NxdGeG6160vqavSmI5mNCO3qGOHZ
         qDLfOxdYv5+HBA96rPajE37SsXO02QLmP4VO72e+fBKw6MixMD3YMLNzITrdVbFJkPgv
         W90dMHCB83xTIQsdMyAoRNe7PoFMd8nZZnbT7JR6HfQ2zVW2qTu8BNtXUjmczY7WT1Ul
         xS1Uh8x8UA/ZvBstZVbnfDysc/o6L0aAdlVZRXuVdywRxF4hq+QOKRMkuA3lJfXPu8qP
         oLbWyxSY4pxBQV6V0rqbXZ0DNROdu2TRKmnVf3sN6akv1JxW4nnAakTex5pih86vyn11
         DZeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WZ6vY6daleIIcRx2H5ep9X630fhSfquV4HaJlN4+Qk0=;
        b=Resle7R09havd7n/HU4D4qcqP62wCE/R0LiXEqIzarji3i59Mj+snmLNQ/JQtnBaMi
         VR2A4taOb1vH7zzS4jr65ZCXFkAVBbShCkN0e00cwCnOMvmXxKqMk1RrWcH+/Kx9dKvO
         xIreZFL6DsMFUtMGiqxgqiE4DnTADx9+YQL3XQ4ctZJ/sWL9CiiyPK74vVSB3rJjcd8m
         W395RziVA5XS4VvE1qALUiSESILi6s7fcBYeNGm/8WyYX98TdbTgKvAx7vYo+54luE/E
         d0Wnjzyw5NrG/kXSZdldyAEvbM65mulciSGrVH9P+9LbILZ1BSmx/oSU+w560oTad8qW
         tZEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WZ6vY6daleIIcRx2H5ep9X630fhSfquV4HaJlN4+Qk0=;
        b=i0fIM4Wd9Eu04zjmc1gJNvwTwkAnDbBeQ+DXEckwECnHCBSo3r4onZ07oWGDTSNCuD
         xQtJLZ/3PWVB3ahtr6n293rk/K/Ibw97N7Gnz7MUpacaKKuwHjqozPpwUiZwU1Tnp1hG
         II1M557z45R1lFIV5EqZS0kiu5mEB9TV7SWrBASxobrpz1Kgy+zhx90+Qcyd5ldvj9Ih
         pKPK/yrpo2J44TOOcPuy36ZF/NRxuaU09hJOhpAVHMN2cIvcjoMWIW2AJ7Lizkiwm39O
         jYNFvcc2vyeqI+wkcImLqkLg0rO5cbpvEC6/dQ5j3RLkfrvZwjHaEV1ZMcIRDX0KjLVW
         c9vQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXparrvU3kzn6/kznyOr5KvpqlCJDkhAIpJUQ+ugHmGX0KCrOlH
	gob2nE7wzJ1WqVsFpN+xwsM=
X-Google-Smtp-Source: APXvYqyVihVb2AX/I7oCKuMRZWgeoxMjaSqMqqKR9UvFrKZaxNwdR2d3p3/OeuZVZzg2ploP9tfjxw==
X-Received: by 2002:a5d:6451:: with SMTP id d17mr5469146wrw.255.1581016479815;
        Thu, 06 Feb 2020 11:14:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:6385:: with SMTP id x127ls6325474wmb.2.gmail; Thu, 06
 Feb 2020 11:14:39 -0800 (PST)
X-Received: by 2002:a7b:cb8e:: with SMTP id m14mr6318145wmi.66.1581016479314;
        Thu, 06 Feb 2020 11:14:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581016479; cv=none;
        d=google.com; s=arc-20160816;
        b=k/lnvj7+W5Yx5PSyB16dzJ8Zudi9xKDFsMSU7BIJHQt9zJSsY8QND7a3LPVQWSMNvq
         5sjdj6NLsD70WM4jBoyS/NaFARdKkEq4K+owlTW1C/q623hNWO3pc6b2/fvcIZdrSbNJ
         CWgXQyGQVYSl7sH8LLV3sVasTuLfjZ6qrQ2JYsMqhzYZWT9Jj2M+NvKsZ6Prouho775x
         sqo4F6SOZ6WNSbsF/ALuxBh3mXAFxU/A/GYagEDNYr66BZ2ggfPKFSKUMe1FhaNDBeLE
         kKF505i7qN7PMacBaQoAeXsQ17p9LTeeKtziqW4OgyNllrfQIM53dhvU3WsihBcHiGaU
         EZCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=DaMzmdp9KPwoYdjy52GXeRjHpG71fTyHHrhWGiOklGo=;
        b=Xxp6IYQ3Am6PxeprDmtwHGZd0URNFaB/8KN6/SYc2yxbpkLb+1H2zBjt70ZI8TvEr1
         o9iFgfGbhvAn1Ag79eo4ExUKTlsvsLyJk7OovD0EwgOvY155zBfZ7aMS9KlLJWvSukZs
         l2Faz+/MLGA/s2niMtfr3xto3f77s4ZO+d5Cy/zTkbahhfjcpPRoS11LPJNjuSNGd0vI
         jetjSlG+UuVbwRpwnuobdpc6QG9OqBnibldeB/wi8zmTacSB7qyRbwApBWglYJLYnHMa
         d43gTLX4uHDGclGcdU12fb7jaXWm92C304ED7QvYH91Ut9Sm7u6GSzLxMvY1es8W/rjO
         tAHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id i15si21269wro.2.2020.02.06.11.14.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Feb 2020 11:14:39 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1izmbg-005xA3-5k; Thu, 06 Feb 2020 20:14:32 +0100
Message-ID: <c264bc73e22be04c5e8422858b8eac97f006f16a.camel@sipsolutions.net>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>
Cc: richard@nod.at, jdike@addtoit.com, Brendan Higgins
 <brendanhiggins@google.com>,  linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,  linux-um@lists.infradead.org, David Gow
 <davidgow@google.com>,  aryabinin@virtuozzo.com, Dmitry Vyukov
 <dvyukov@google.com>,  anton.ivanov@cambridgegreys.com
Date: Thu, 06 Feb 2020 20:14:31 +0100
In-Reply-To: <CAKFsvUJu7NZpM0ER45zhSzte3ovkAvXBKx3Tppxci7O=0TwJMg@mail.gmail.com> (sfid-20200206_192212_045280_EBE78060)
References: <20200115182816.33892-1-trishalfonso@google.com>
	 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
	 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
	 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
	 <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
	 <CAKFsvUJu7NZpM0ER45zhSzte3ovkAvXBKx3Tppxci7O=0TwJMg@mail.gmail.com>
	 (sfid-20200206_192212_045280_EBE78060)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

Hi Patricia,

> I've looked at this quite extensively over the past week or so. I was
> able to initialize KASAN as one of the first things that gets executed
> in main(), but constructors are, in fact, needed before main().

They're called before main, by the dynamic loader, or libc, or whatever
magic is built into the binary, right? But what do you mean by "needed"?

> I
> think it might be best to reintroduce constructors in a limited way to
> allow KASAN to work in UML.

I guess I'd have to see that.

>  I have done as much testing as I can on my
> machine and this limited version seems to work, except when
> STATIC_LINK is set. I will send some patches of what I have done so
> far and we can talk more about it there. I would like to add your
> name, Johannes, as a co-developed-by on that patch. If there is a
> better way to give you credit for this, please let me know.

I think you give me way too much credit, but I'm not going to complain
either way :-)

I'll post in a minute what I had in mind.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c264bc73e22be04c5e8422858b8eac97f006f16a.camel%40sipsolutions.net.
