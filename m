Return-Path: <kasan-dev+bncBDIPVEX3QUMRBBU5WCNQMGQEOIDL7SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 06E716234A6
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 21:33:12 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id n4-20020a056e02140400b00300cc49a4d0sf90738ilo.0
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 12:33:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668025991; cv=pass;
        d=google.com; s=arc-20160816;
        b=oNgxUqShJNSfPT9ZkyZwRTt19GsrX4Cd+5YO5di1/Gv//hxCijS1bmgjvVqg3bZlOa
         yOZMmBSQn1SH845vvteXR65CoWDoAhBsfI5+H9K8nu0wsm1nReqF+IvXlG/A50odU+b6
         ZTEudY40xL/wq4H8BOcuVDNNsClZ9zUtuoECY01xCdZUgSPyy4GCDsGMvbqJfDg5GaEx
         YJZyhBU+oaeMzlQoSADORSWEm6vaglStrbC3rNoXGThYAeYr8YLp5i+e647xZoYdIqKp
         GkwRYhafniARbzm3Ew9zQNhE8c7C4IYxDHRdfwgFOOWXtxs/NLeiFxHr7UTs7Pa2nUQD
         6VwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:dkim-filter:sender
         :dkim-signature;
        bh=wZTjU2i4We8IKw8rjrVfKoGfTj+w+Ou6mjGyyvpLWxo=;
        b=ILkD5edqsmRArwx6T3Z6NjHT/Dp+W9nOLi3QP1p8UrdnnYHAPptY2grHNPjhyJDVhV
         s3mnUFKuOG842u6JmG9RnzAqWDMS+xV1Pb+pPVycyRqADElyXVc363l8I/MhN2bmkLWM
         SkAF43WsqIQJaqorEdDl5m39swmzuFNhCmg4yWszkWHekf4jsKKhFuVoqu02JXZ05UYl
         okdMyjVjX9wYgubuIbT/DuaH/36nbqzt976SkGyGQbL7XkOzHbSaygekRVkckf0H+mX0
         ymo9alidE27gwq3azYxulpDPZvj6NhrvnUD3Wy5aXLAHTcvfAb8Nx2x4K9bs6hCeHlQY
         gDGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=AcVNt6yC;
       spf=pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) smtp.mailfrom=corbet@lwn.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-filter:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wZTjU2i4We8IKw8rjrVfKoGfTj+w+Ou6mjGyyvpLWxo=;
        b=SDB7+llLgzoWmrGPWZb2FHGFk0NLplBtcVwFwS6iu+tEsJ00yxD5VJXii3rRlps5Q1
         gd8N8mG0QZVW7fuNB6Zsbn5gwkLiYn4UJzwDZLqEUr2cFIcEl5vI+Sco6GHVvToe+8yv
         j8Q/n/CChHbVHhISq83Snm1shRDD1ShzeGex/b3avIYose8SEna0lCvdIWi9HPr8K5QM
         DrS9HZMHs+TeRBgew2fIz7qMuQfbE6AhTIspP+faHI42ZoDuj2xygoXEALBZY5te8dl2
         aoyXPj4DMJ3G1jk1DCc5QmOy1PIQ/Nb3pdEix1xF+zTvHeAH8hyM4lEzZzG6rlVNttmJ
         O4gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:references:in-reply-to:subject:cc:to:from
         :dkim-filter:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wZTjU2i4We8IKw8rjrVfKoGfTj+w+Ou6mjGyyvpLWxo=;
        b=hjfr8GQ4xQYqlhk8fCIEyP2Sv3NbNtJyGTqvu6EyxPBeKajxpk3ig99am9njs0Dd/Q
         14fQE3z3Tz2ZlGJQv6x/JooBn1Dt/D97q2KUK5pJSGHrV5/86x4vmu5Il6Wa9OpeogKO
         UbCaOPyiBXsvAAMz8TwMfb/2mD24acIdgyy7YZ+3uoxRo3CEbWqrCzrHU0Rcs3NsJJK2
         zgCWgVfumGnzIqOr6HADz4uOZ7geMMH/CBS7bZzEbsvJNjj0BrUAFANW7rVzqfjewYb6
         mzaZPmCCWLK3cIXq7ZBhj84YTEfp3g3oH1zdeyjLo+9xNNzVb4wOx3Asbb75X0J/qhNC
         EHfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0eJ74FammiWOVKKPVsKulNsZGDrU4cbUxA8xKV6/HTWAo9k4sr
	ND4rlW2aeenupf7n/qIx1/w=
X-Google-Smtp-Source: AMsMyM4WBxlO13GAlnW4OhuVqbobOrQkiFlgr+s7WwTXajjuMAEpuXF6Bz8YfRt77qh5Mp6e/m9u5w==
X-Received: by 2002:a5d:9617:0:b0:6c6:fbb8:f86c with SMTP id w23-20020a5d9617000000b006c6fbb8f86cmr2164446iol.36.1668025990887;
        Wed, 09 Nov 2022 12:33:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2a86:0:b0:374:99b0:f48f with SMTP id w128-20020a022a86000000b0037499b0f48fls14376jaw.5.-pod-prod-gmail;
 Wed, 09 Nov 2022 12:33:10 -0800 (PST)
X-Received: by 2002:a05:6638:11d0:b0:375:39ae:8d9d with SMTP id g16-20020a05663811d000b0037539ae8d9dmr35154642jas.94.1668025990479;
        Wed, 09 Nov 2022 12:33:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668025990; cv=none;
        d=google.com; s=arc-20160816;
        b=jbvE54R/3Ih2B4cuP6+xHkcugFZYdflpyBhrmPIuIYsyEkShqc2Ba620itjNhtz2RC
         KoRE0J//ElwdfsQzccmGdN6ejaR44Pxp7fMZcQ8qdo1J2O29m0BPRzYakSqr7Iivja0I
         1Tf/slBEJkSwLfejR9s92p21sJs20hbCUgWHjdjdvkczBKHvhnP3CKLjTT91TMfrPJSQ
         e1S8tEGSTqMyky3tpc7mu/fV6xFqMgQRLtUCkHhpj4dMV5+ncX+LwR7MVAOwVI4RClSR
         mbnRTv5HlPRybskCdQAS/I0PLpHipK49yjv3sn+vE/iUjJT/zrb9ZoczAT+NzGAugCDi
         84IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature:dkim-filter;
        bh=Ktj4Ju320TNrN83Jdb75n+OnSn/xfGhemx1ROTVxYnM=;
        b=pxJbYT2tXzoYmC5abeyHB3oFgIDLEL8N1IEi3q9mHt65Mnnxj/rOwT2UlmUedWjfuN
         7CBBGwJllebZo+OJyekuQDFly0wQczdHyRFbmeTeCdfFCmfd1pArvA/j810L0IB2ZvUh
         CEQKw235pFzfmunvX0Pt+vnce/eB5OxQuRFfR47eNLqc8GGXEYW8ofkiI433N7HK1t7y
         Nzew9GBPC1qvBTVtGADKRbSBsIYmXMSw0hooHiiXeY2beslWLmso0ZO06qGyc43z6zlM
         thlixRpm7L5K9nJmj51xNfXIAbbUP6xE+pQNoMr0SuRsq/1gT6H1ciEnfHiirByoylVr
         CaXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lwn.net header.s=20201203 header.b=AcVNt6yC;
       spf=pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) smtp.mailfrom=corbet@lwn.net
Received: from ms.lwn.net (ms.lwn.net. [2600:3c01:e000:3a1::42])
        by gmr-mx.google.com with ESMTPS id i7-20020a056e02152700b002fc5c99ad7fsi615254ilu.0.2022.11.09.12.33.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Nov 2022 12:33:10 -0800 (PST)
Received-SPF: pass (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as permitted sender) client-ip=2600:3c01:e000:3a1::42;
Received: from localhost (unknown [IPv6:2601:281:8300:73::5f6])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ms.lwn.net (Postfix) with ESMTPSA id 6F6A2735;
	Wed,  9 Nov 2022 20:33:09 +0000 (UTC)
DKIM-Filter: OpenDKIM Filter v2.11.0 ms.lwn.net 6F6A2735
From: Jonathan Corbet <corbet@lwn.net>
To: Alexander Potapenko <glider@google.com>, glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org,
 akpm@linux-foundation.org, kasan-dev@googlegroups.com, Bagas Sanjaya
 <bagasdotme@gmail.com>
Subject: Re: [PATCH] docs: kmsan: fix formatting of "Example report"
In-Reply-To: <20221107142255.4038811-1-glider@google.com>
References: <20221107142255.4038811-1-glider@google.com>
Date: Wed, 09 Nov 2022 13:33:08 -0700
Message-ID: <87wn83kgvv.fsf@meer.lwn.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: corbet@lwn.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lwn.net header.s=20201203 header.b=AcVNt6yC;       spf=pass
 (google.com: domain of corbet@lwn.net designates 2600:3c01:e000:3a1::42 as
 permitted sender) smtp.mailfrom=corbet@lwn.net
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

Alexander Potapenko <glider@google.com> writes:

> Add a blank line to make the sentence before the list render as a
> separate paragraph, not a definition.
>
> Fixes: 93858ae70cf4 ("kmsan: add ReST documentation")
> Suggested-by: Bagas Sanjaya <bagasdotme@gmail.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  Documentation/dev-tools/kmsan.rst | 1 +
>  1 file changed, 1 insertion(+)

Applied, thanks.

jon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wn83kgvv.fsf%40meer.lwn.net.
