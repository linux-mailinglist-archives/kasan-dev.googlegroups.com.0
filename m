Return-Path: <kasan-dev+bncBC33FCGW2EDRBNHKZSFQMGQEFF6BXWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 255E3438015
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Oct 2021 00:03:33 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id d73-20020a1c1d4c000000b0032ca7ec21a4sf161829wmd.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Oct 2021 15:03:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634940213; cv=pass;
        d=google.com; s=arc-20160816;
        b=q1hcoi3IPQZY8AYd5d6ZcfMFQt+BNE2xmXM5Lpl214VaCmisu5y8AK2mA9XhAofHmO
         ju4GItxoTEUnNzMoxMg/aVOd4WY1bl/ZbpDQY93o+pS4ljJ5DndTnW9oj+XhGBi9tAkv
         iKN0wkYpsDKa+YT3a0VE1uwXEecARhtr4vkXRrfBqFuT7hmvUZtd9S4xJE1y2PIKUePl
         ll8vkkYMSqV8A9VJKKCME7apathnGmvkhan454g76eVJQfhGT1Kven7iMBLW/kPn7aDq
         NMK7C07pQktXz01/sSlqe6VAzEXBA74P7aYpSRb/EFa7DJQDRXdcW4ztz16Gt+Ud3cFg
         BjkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:subject:from:references:cc:to:sender:dkim-signature;
        bh=2oV0rSA+9KRFUxqXxjB1r4R0mwi/qaHTrSnbC98j2So=;
        b=EIZrUIJIe1w6yq1ViYqRGy5Lv/p2uUQgk4kBqYppCWfLyc0lIPo8KU16DTW0Omc4X7
         9JqV0d/QlbtMsJ4M/UPG+57mfo4IFJFGKdctK5VQjRYtbAXUeBWWHK5T2+NUVyFGqwuw
         Zw60CCvo8GJ8y8/2Huh5Q4aUWqVEsloYjdYjnDT6YmyHUN8CI9Pa+gNadhkGWzcwgKvZ
         b2GL2OtOXrz0t6EGm9zDAOKpRXBCzJmDAkBc+NHWyK2qyzkow+XgIsnV3aXdfelROXrH
         bHjQqoaX4te5I8vcmE3lEOcETr5UZYGqbgJ38aYVGOXiDB8Izrm6/lcPLpbiZ2d/x+Mo
         2Slw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=aqtQLCPA;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.61.106 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:to:cc:references:from:subject:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2oV0rSA+9KRFUxqXxjB1r4R0mwi/qaHTrSnbC98j2So=;
        b=Lqf6JmU8jEtMKgbb0ElTYldERJc+d1YVKxp6rZwdv1RD6oFbs/WnPIh2/J086kAjPr
         f0nG213Fw6gDXiluyf/3NbtIsjDFZX4mq56llosnE/m7cB3V3Qu8pDOMCKq7gsDvO7zw
         ekcMsh+mAnM9Bdzz6qAVOOQ+RcT2SJxz6/bplYXOANaHGbqlE13e2EbMsdzO9NJM2cJK
         cM6OP/85D7MUbE2b91BkBM6Cv+TB5C9OdYN28JRNbHBhgJFpAHVwbSkJsew7YwSY58o7
         xRTzB1PnmXZ9OyRf3L6OMiRnQly0r3rAYHF7d02RC3zI96ArTM/jeMrygWXq5OYedDWA
         J+xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:to:cc:references:from:subject:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2oV0rSA+9KRFUxqXxjB1r4R0mwi/qaHTrSnbC98j2So=;
        b=1k2iqsMUQ1p99mjqvMUfnPP752mssQWifJYibYOLT516pgR8dJrKIqNPClsvTWtA+d
         fq+7/eVDkWOXbfnZCao6WJTxpLDL75mrUt3L12WqntOalXjGWlC51MId9QrLru6B7kX3
         mPkuihAAKU4/tKo3C7q1ww3VL/r5+Ft6G51+0mIb18qwtZHq+3UrxNDFEbFACvRj2ujd
         g8v0TE9LuRaj60GpaLGOCCiz/UOE+tXa7q8+TYV+MnCqhDr1LyAhNOUaEcR3ebPMN4kN
         2ErJGItJ4r+ybjNB+X6sVKCAvQOMe1A4IUUE3Z8YIJAW+gDx33OL+T43RjADSuAFhJ+C
         KnVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xOyD21tQHEumFtkWbZQWrtEJY0t7ZWaHWtXvNbLtXd4pz9hqE
	9XG/1tADpg6KTDI84xMdDgo=
X-Google-Smtp-Source: ABdhPJx9FIj0Q7sjKbkSarHMql44Sx/i7jTRdE1FmJhbi7EZ+6u9kKVS6WI/nnzXTt16BpQrfa8C8g==
X-Received: by 2002:a1c:ac03:: with SMTP id v3mr32093453wme.13.1634940212855;
        Fri, 22 Oct 2021 15:03:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b9e:: with SMTP id n30ls63780wms.1.experimental-gmail;
 Fri, 22 Oct 2021 15:03:31 -0700 (PDT)
X-Received: by 2002:a1c:4c19:: with SMTP id z25mr2550890wmf.4.1634940211788;
        Fri, 22 Oct 2021 15:03:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634940211; cv=none;
        d=google.com; s=arc-20160816;
        b=LVWWY/X05ejGysGCHnEsHCg/K10vEUk1m59qIrBYsysy4rPyyH8dK9vvsA0FEeRvgX
         uKlGe3qPtJR3l1YrLZI+NaNKCPbhNTyT/DJcnBDWPP9Ip+ppdXW5Y/FMc6WnAa24GctI
         2v46104aewoTCyOPc1qVRXFZM6Ezlj+zC4E/Xfnw2C2nBcCYA9ZMOA48fGS1hfNiR0Gc
         cCTI74eBD8Qk4Lsrnp30GBKsCSlx/v5siGfMtnLrQWzAi5YbhtHfZi17JXKDWD06FHho
         miFygugn6bTa9ds2eNCz8fyp+EUXAz76baWDCzaSwrmMhTgmeO6uKJTy1k5kDU1BLpyF
         UjFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:mime-version:user-agent:date:message-id:subject:from
         :references:cc:to:dkim-signature;
        bh=lsq3d60soXZSZmqhrSEGUvUdArwGIFVirEq6+pvpD2s=;
        b=b6uWIUdk4WPkr4erlC61uX3wYqZ9jV94l5ez3pBV1MFepTXb0AV65uiPGx367MRi4c
         DAZUthmGFdTWmRV5AMYUeAgZt7ceAIvh++X1ZJvjxmQJgj+wuspyelSf5MrU9BkSXbNv
         b+ltYw00dX7DcFK+i8BjusXX2jA1//d2RHGexZhfG2cz4PDM+uck1Nc5nzZ3CsrFgB6q
         GrX/OdMraRrYHYyghdggO6eLFIDK6OR4bbhdwKyCXLIRfu/Z5ksyuWV4yCL3vl0IKZB7
         K8vCrgXnZ1+a9xU0fLNsq7S4gLLOP2TvqDZUMKz9hDoie7OUtVyulbWRFbBdW73Zksmh
         7WXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alexander-lochmann.de header.s=key2 header.b=aqtQLCPA;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates 188.68.61.106 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
Received: from relay.yourmailgateway.de (relay.yourmailgateway.de. [188.68.61.106])
        by gmr-mx.google.com with ESMTPS id w22si244148wmk.1.2021.10.22.15.03.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Oct 2021 15:03:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of info@alexander-lochmann.de designates 188.68.61.106 as permitted sender) client-ip=188.68.61.106;
Received: from mors-relay-8405.netcup.net (localhost [127.0.0.1])
	by mors-relay-8405.netcup.net (Postfix) with ESMTPS id 4Hbddv2B5yz6w03;
	Sat, 23 Oct 2021 00:03:31 +0200 (CEST)
Received: from policy02-mors.netcup.net (unknown [46.38.225.35])
	by mors-relay-8405.netcup.net (Postfix) with ESMTPS id 4Hbddv1pmhz6w01;
	Sat, 23 Oct 2021 00:03:31 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at policy02-mors.netcup.net
X-Spam-Flag: NO
X-Spam-Score: -2.901
X-Spam-Level: 
X-Spam-Status: No, score=-2.901 required=6.31 tests=[ALL_TRUSTED=-1,
	BAYES_00=-1.9, SPF_PASS=-0.001] autolearn=ham autolearn_force=no
Received: from mx2e12.netcup.net (unknown [10.243.12.53])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by policy02-mors.netcup.net (Postfix) with ESMTPS id 4Hbddr3XTvz8svs;
	Sat, 23 Oct 2021 00:03:28 +0200 (CEST)
Received: from [10.128.131.224] (unknown [37.120.132.67])
	by mx2e12.netcup.net (Postfix) with ESMTPSA id 5B203A04FB;
	Sat, 23 Oct 2021 00:03:20 +0200 (CEST)
Received-SPF: pass (mx2e12: connection is authenticated)
To: Peter Zijlstra <peterz@infradead.org>, Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Jonathan Corbet
 <corbet@lwn.net>, Andrew Klychkov <andrew.a.klychkov@gmail.com>,
 Miguel Ojeda <ojeda@kernel.org>, Randy Dunlap <rdunlap@infradead.org>,
 Johannes Berg <johannes@sipsolutions.net>, Ingo Molnar <mingo@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Jakub Kicinski <kuba@kernel.org>, Aleksandr Nogikh <nogikh@google.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org
References: <20210927173348.265501-1-info@alexander-lochmann.de>
 <YVQkzCryS9dkvRGB@hirez.programming.kicks-ass.net>
From: Alexander Lochmann <info@alexander-lochmann.de>
Subject: Re: [PATCHv2] Introduced new tracing mode KCOV_MODE_UNIQUE.
Message-ID: <927385c7-0155-22b0-c2f3-7776b6fe374c@alexander-lochmann.de>
Date: Sat, 23 Oct 2021 00:03:16 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.14.0
MIME-Version: 1.0
In-Reply-To: <YVQkzCryS9dkvRGB@hirez.programming.kicks-ass.net>
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="CDzUVjhiPtClmKUvK9yUQsAHucLgloZvz"
X-PPP-Message-ID: <163494020654.20467.833133958238456166@mx2e12.netcup.net>
X-PPP-Vhost: alexander-lochmann.de
X-NC-CID: yTucXSprgOVIdQ7m3pFnHtEZSL80pRmPiiPjZRCUXJtPlaTCDtHB87NH
X-Original-Sender: info@alexander-lochmann.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alexander-lochmann.de header.s=key2 header.b=aqtQLCPA;
       spf=pass (google.com: domain of info@alexander-lochmann.de designates
 188.68.61.106 as permitted sender) smtp.mailfrom=info@alexander-lochmann.de
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

This is an OpenPGP/MIME signed message (RFC 4880 and 3156)
--CDzUVjhiPtClmKUvK9yUQsAHucLgloZvz
Content-Type: multipart/mixed; boundary="UBwMM8vn54PR4LUbz1olAyRhXFoyVHnMk";
 protected-headers="v1"
From: Alexander Lochmann <info@alexander-lochmann.de>
To: Peter Zijlstra <peterz@infradead.org>, Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Jonathan Corbet
 <corbet@lwn.net>, Andrew Klychkov <andrew.a.klychkov@gmail.com>,
 Miguel Ojeda <ojeda@kernel.org>, Randy Dunlap <rdunlap@infradead.org>,
 Johannes Berg <johannes@sipsolutions.net>, Ingo Molnar <mingo@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Jakub Kicinski <kuba@kernel.org>, Aleksandr Nogikh <nogikh@google.com>,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org
Message-ID: <927385c7-0155-22b0-c2f3-7776b6fe374c@alexander-lochmann.de>
Subject: Re: [PATCHv2] Introduced new tracing mode KCOV_MODE_UNIQUE.
References: <20210927173348.265501-1-info@alexander-lochmann.de>
 <YVQkzCryS9dkvRGB@hirez.programming.kicks-ass.net>
In-Reply-To: <YVQkzCryS9dkvRGB@hirez.programming.kicks-ass.net>

--UBwMM8vn54PR4LUbz1olAyRhXFoyVHnMk
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: de-DE-1901

Maybe Dmitry can shed some light on this. He actually suggested that 
optimization.

- Alex

On 29.09.21 10:33, Peter Zijlstra wrote:
> On Mon, Sep 27, 2021 at 07:33:40PM +0200, Alexander Lochmann wrote:
>> The existing trace mode stores PCs in execution order. This could lead
>> to a buffer overflow if sufficient amonut of kernel code is executed.
>> Thus, a user might not see all executed PCs. KCOV_MODE_UNIQUE favors
>> completeness over execution order. While ignoring the execution order,
>> it marks a PC as exectued by setting a bit representing that PC. Each
>> bit in the shared buffer represents every fourth byte of the text
>> segment.  Since a call instruction on every supported architecture is
>> at least four bytes, it is safe to just store every fourth byte of the
>> text segment.
> 
> I'm still trying to wake up, but why are call instruction more important
> than other instructions? Specifically, I'd think any branch instruction
> matters for coverage.
> 
> More specifically, x86 can do a tail call with just 2 bytes.
> 

-- 
Alexander Lochmann                PGP key: 0xBC3EF6FD
Heiliger Weg 72                   phone:  +49.231.28053964
D-44141 Dortmund                  mobile: +49.151.15738323

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/927385c7-0155-22b0-c2f3-7776b6fe374c%40alexander-lochmann.de.

--UBwMM8vn54PR4LUbz1olAyRhXFoyVHnMk--

--CDzUVjhiPtClmKUvK9yUQsAHucLgloZvz
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wsF5BAABCAAjFiEElhZsUHzVP0dbkjCRWT7tBbw+9v0FAmFzNSQFAwAAAAAACgkQWT7tBbw+9v3r
3w/7Bv8kyg3mPcCinEzZ9AnnM/yQ20THcNhazgLOZNfSMOqGKhyu2lCwY8A8TakScZAd+si/iU/v
d6n14El+O4hTXzqjq42Kyukl9F56f45qPd8CXciiSnkCcH2LO7t0MEck6KobaGDe1km0QBoXc/kN
hhyG5Yp5qduw34Ltj8kaylCUzSOqYiRFmZ2Ws7aA5HkGTA8zgoRm4BZj/YEqpUsoFeGsUglvMtlt
vPyG479llRhv3DVE3Kal7pxGTSVccFg4uCMsBGFzl5nwLhrkC9P3c2gzkbzcQ6rUTTCnBEZAnU6o
6G4lZER0xOW41J8ZxdCfk3JadcKM/w245pu6SBDHKNE+oLm//+BCbhAReB/74WqPI4XvkQP623Gk
x6mFm6EeXA72C/bWQg+V0VrFdbnkBACI88QMcEyzDHTddNno3/jkFx3rOQx7ZbVjY98Xw0p6Nf/P
YjPM3qj1LEg7wKV12oQEBIHGo6oLUC4f2NUpl4DtYKCpBjBF4iMqCbkTmTtGi7GCyzFfiUDscafB
3Y9BzfzJKM5zlgsd9n29jAWzUCFhAByzJsFUY78c5JjVylnUugdLuBoichLvh1r4Hg67AX1TB84N
cvS0Y+c/jgXEV4/EeqnfaBW9Uk8yhdGLytC6UpAhGNNkK3r5bhU1WY6PiCGGR5XbFIkbw9+i6L5Q
ST8=
=9qA3
-----END PGP SIGNATURE-----

--CDzUVjhiPtClmKUvK9yUQsAHucLgloZvz--
