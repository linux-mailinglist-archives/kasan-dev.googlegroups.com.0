Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBX5RQDYQKGQEGQFSV4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id DE17313D581
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 09:03:43 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id i9sf8977762wru.1
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 00:03:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579161823; cv=pass;
        d=google.com; s=arc-20160816;
        b=JRZKmqeYM5XWoUiyabBtl0RSD6Aj74ul3W3A54xfr5EV045e1XQJPWTdxG3qNS9zCv
         3gU08XU7QRkEkW5Hsg/sHellFvgHPSKN7vr5e6+gwJ68eyAMCSvwC4870kN+y85x2Umm
         u/ExFljk24bVscswPHxnpsOf8427u0F9Airbtge5kPf3xjuCURSqZ8hsaaksIVrHJE7G
         Y7K4ffuhAqU3BW8eUB4FL91pzkTNHh48EI5Kbg0GsxvEkEDIsSzh6+/O88Qvs2EwSNdh
         Ne5rXy98PU14ruwLAsgRuI55BQMSm0T6c7v3UV93ycrdr6vGYsjotVC6p2ABlCBw6TLy
         O4Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=AABMAxvd7inQdDpmH5/3hMtuyTm++KocUdjICuM2QVs=;
        b=QN2eBsmrhrepQ8ExsrAbid0mjNZ/ELL45k+vvVojCukLpFIssZ7O1Mb8dB7HUW1Diu
         ir83RThZC8IGmCF8L+cyRl62xahNdZkJM71RqKQPfTqoeRBkg3hYn1ECQEFNH8zpENiT
         umzhyMnRySCBXbJmONmb7wBggNNNDtDMMQoAGYDhqA6Ep+kmzF0j9B+eHT+elIs2vzbz
         Snv9Av5k2PsMcWSgB4Bj3kB3z6bKuWso3X6kvnoW2kza9pRYZbBu1N98QvRZyAv0fJw2
         t8yIVIpHNxr0Lapn4K9oUTjlZJBvx24nEdkPmucbkOy0HqB138MtCAu2w+lWhjaAPYhM
         UvXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AABMAxvd7inQdDpmH5/3hMtuyTm++KocUdjICuM2QVs=;
        b=mzoyEOgGOTUYn3JInLCAqNsks6+wnqQ75M4xg70z7opD+tUNDOrXUk2u5XdjHGF/BI
         Xb/43LTJePXr+ysp5kAAAHH7Ub0EtLHFGZcjbIpcrQF48r6lQE+vYZwT9Cxk+5/wR82D
         yPNEAciPl8/Q9sXM0A8nj/34+7mFKQyldWGghvA2WK52BEjCoo6RwZ4uJ31q1Jppmy5K
         GxV8I1aGAkIH24B6hjT0K7rQQYaIqSmni3MqX6Yh8jLm2WRuzFZUv3OAv/ylGTFXi0ME
         JBMR/ufS2tlocbvj4XiV5r8mpzbGQ7TLt1XMMpKf9E8ecIZdS13rp0Zf4fDUnkNPThcc
         e7gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AABMAxvd7inQdDpmH5/3hMtuyTm++KocUdjICuM2QVs=;
        b=lCZ9P8tg9gvTcEqMXBsc4nTZlT+DJmuOczR50bM7e9+lmv0hkfqcjapeAwVQZwjzX4
         zOEoRrkbdVCKOuV2JPYMe8VfOVFqQ7r53wJTRTrKU2p7m1CNNJuoXeL9Fa49MjoI8muK
         gUgTg8TWyGXM3bncGqntccPhat4R71nT6dF/ML6ndhaiuDO3F2CNrMaAWVOAfPC0j3q1
         3hzp6x07Y2v62yX4IBeCO/DVShc0vi5JOw4+nfgxC91ZsHx/awS9R9x8hwyucQgahuFN
         sbjlbkbD1W+ftSHIle7HPmcpLffr3Jp+YlGJspCQ7aqdj/pH4tZFgbkmu3rXE644g46E
         MlMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXmG8RZb3Ic1FjHz3xe2lXqx5FWjF43JWyEBU7mgBOeCpaPj2Iz
	OB514chI9SQHQ3SRkaMMbGk=
X-Google-Smtp-Source: APXvYqzc8VnDKb+0SKc698V34m3omlE9UElpf2r709AbdH16uOqJLgqT7bYIedqwturdLbcFDxrkUg==
X-Received: by 2002:a1c:3d8b:: with SMTP id k133mr4040599wma.161.1579161823521;
        Thu, 16 Jan 2020 00:03:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6912:: with SMTP id t18ls7649827wru.7.gmail; Thu, 16 Jan
 2020 00:03:43 -0800 (PST)
X-Received: by 2002:a5d:6305:: with SMTP id i5mr1846555wru.119.1579161822973;
        Thu, 16 Jan 2020 00:03:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579161822; cv=none;
        d=google.com; s=arc-20160816;
        b=poyUIJyAWMTTxPtp4RZoxIwKsbLwz5xRhqekixfsrYQ/iqy6O5Rsc9iYbuJRapNJCv
         OYUiUHkqKCqM5ogebUIfdQL/NeqQeO78mIY/rzrVG63H8olImfv8lu0SHlf0xt0NrMIq
         /PDUh5dOcIgXG+ZCUvuSaH6koomTevEpmfk3aqcm4bWyhPuzjrlHUQ+ObaHEBYKCUMRE
         Q6Xt8GwFWoTHpncFmI3RDGEHR4kk0zzLq0nWADn+P6qMY4wHYSZ6H00tVHvLgzO24Rc4
         GXHythT3357py24wro0SjjlQ+6zrPDZbh1+MIAKUFjMElRCO0qGVUim6Azy9vSAnERLD
         zqlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=/8teiy/eZy3HypUMmCXg9Jl5AK6uICeWDUBuxMFHmxk=;
        b=l4D1ZseplSRpJ8zlveUJAXn7gYeZz+cf8Yi0S1Dk1LcD8W6e6y2bJO1yXZW/Y65Jx5
         1qJctxZJvoRPDD/EDw4ou6rJI5ZkhG3v9yMz07xU9SXAjxnVRcxV3lZk9qJAViQZkiH2
         boOnZY7Eu/mvsNecfNyC/kzUF/fXQ5ax2jx5JC34HsGPi3SXutHRs1RkYaIjQAYY/ngw
         SYjwrkTXtRLP0dqkR3dLqUXEAXrQKgQO+XCWJExh0074aF8X+FNtPlSEGrCjM3/tGTsb
         ng02kgBMbyyIxc8jx2vEULwjH8EQNDx4tERbrg+mIjjA7V3NtrPonjHhjUQDfDnyItsp
         1VtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id b9si978842wrw.2.2020.01.16.00.03.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Jan 2020 00:03:42 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1is07s-00BWUR-LH; Thu, 16 Jan 2020 09:03:36 +0100
Message-ID: <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>
Cc: richard@nod.at, jdike@addtoit.com, Brendan Higgins
 <brendanhiggins@google.com>,  linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,  linux-um@lists.infradead.org, David Gow
 <davidgow@google.com>,  aryabinin@virtuozzo.com, dvyukov@google.com,
 anton.ivanov@cambridgegreys.com
Date: Thu, 16 Jan 2020 09:03:35 +0100
In-Reply-To: <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
References: <20200115182816.33892-1-trishalfonso@google.com>
	 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
	 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
	 (sfid-20200115_235651_948442_0F0A0073) <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
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

On Thu, 2020-01-16 at 08:57 +0100, Johannes Berg wrote:
> 
> And if I remember from looking at KASAN, some of the constructors there
> depended on initializing after the KASAN data structures were set up (or
> at least allocated)? It may be that you solved that by allocating the
> shadow so very early though.

Actually, no ... it's still after main(), and the constructors run
before.

So I _think_ with the CONFIG_CONSTRUCTORS revert, this will no longer
work (but happy to be proven wrong!), if so then I guess we do have to
find a way to initialize the KASAN things from another (somehow
earlier?) constructor ...

Or find a way to fix CONFIG_CONSTRUCTORS and not revert, but I looked at
it quite a bit and didn't.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b55720804de8e56febf48c7c3c11b578d06a8c9f.camel%40sipsolutions.net.
