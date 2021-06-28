Return-Path: <kasan-dev+bncBD63B2HX4EPBBKPF46DAMGQEZVTHVDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 328023B6656
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 18:02:51 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id m15-20020a923f0f0000b02901ee102ac952sf11164288ila.8
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 09:02:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624896170; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kffwi7alkCH6TBIESf7PYT1ec4Qi1Tuoan21d79X3oc8XLNPOERa1qQTkBK0jnuiHd
         ACKTGPhOYVCIyt/7Tuo3vVdxxTobc5QuOGl79ogV1FM/pgyIOJz28jvQLx/2dZr7xCeT
         tyRX11Ne0NjOL8kZqaeijaGF7oADngstcfIrFT2eiA9nLz5dRYwSRTffO9d2Q3ARx99k
         yKOuFtbPWjTKpydDCkEiSPbfIYL/RtRHcfXMfrlODWmhBAhgvz0NJNNzybKi/glac/tM
         hCo2oZhhQwJDopHzKx1Uu288P33ZxJlBpaOpKeoUbkB3mKznYG3naUVZ3P5ybuyHN6Ar
         Kz5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=mTF5pxcxVrKEHgUxuUM5v8JC2EY+e6jEivX0RJuvNhI=;
        b=y92uZt5gEMnLBFvxWNha3FKaaCsKGp4ScnAUolPudx89VtHvZkF18ImgwlGWiuqlym
         dkuiZIUeq8PB0zTRRTaDH/rVq1IaGHDAjnz7jymrmyG5fFty+RYQRiVRGFOUNZt8iMTn
         3n0ZrbCRzbYu2WOScsziHe0KijoqxsPVP8Ny6DWJUp2pFJpIGZj5o1rB1gO266Yvaqj8
         6HiI50TQq12KR+U79Rht74Cw4JAlw5jl9d3zXRT15Yvt7TxXjebK3dmihHkzJtTvuqH+
         D8pC7tlJrbS1WtsT2gydFRYzV54/gGae46nfwhgamRkX7M41fH6OPwPv4ZhRmdxCdLbe
         k3Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=E1RMJxN4;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mTF5pxcxVrKEHgUxuUM5v8JC2EY+e6jEivX0RJuvNhI=;
        b=OGfMOImS097ugufDyfsaSCdGw8noeIvYDzMnjx8NbT8aZWZL84X9zvIF7pxAqcSMIQ
         5s8GB7CNhF2GGGeTSZVOkSuwDrM4hFQHdn5yT1XmHBlmEai6trsVJ0Vuwl6XZpRu6GGD
         ABAfSOK39tGhusZRaPt0lL2MaMonamBvJFxYmvwzn6rTYT63sPtfMMO/TBhmwIM/qqYw
         1G9rTp+mMyHlQ96c6N6DNTVFv/FnBYSuR7ZkDMCGlQXIOEEmLHzQS+i34qv9hHVcwT4M
         JPa9SKCA88FH7+STDMF+ykAP+dEobLScWsB97xuCxTAXD+0XrnzUUs3+NX7UgShLl4JW
         x3nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mTF5pxcxVrKEHgUxuUM5v8JC2EY+e6jEivX0RJuvNhI=;
        b=HbQLSIY9MzMIMs0UskGIWPAc3AGISauOMTvECOy9japrrmDap9DfIa4zfX4RJXEq2x
         JI6GdG+4vBe1DbLfLxRbE2qScPMP+HGYucXFQueY4bHz0PDLgENUeQAskqPiTM913tnd
         LsvuqJZscnX6u3wyJOn11qS5EnxR4zDvTMkFA7esmtqx9RT5VVlbkymOcoRy3vphZ5BU
         +gNBAUBoXmV7UWjZFBw1y9w9U4HT0LQgcJ1+n1Oa1OVwN4wgNJdbTzpSBbAfHCD79tJ8
         2LG+jwhxoLKUuzaJxwAAqMJTYTS4rvZgvN9/1kSWzN9MxOFkThFubR5UaMrmwavwv5af
         ZM9A==
X-Gm-Message-State: AOAM532r9Ggg5AUrZJ6apR2oZ5o2wkF5ohxyhTyfU+McAtAy5nTeigRo
	HiGUiGAjQkXpYbcmvnpBl9I=
X-Google-Smtp-Source: ABdhPJyBQgh6ekm9jitxOvEvcFfUJ7YtTsfC3ehVSfGyKuvm65oVcG71M7HxtJqq1/FmP3ZdPSkvqQ==
X-Received: by 2002:a02:bb85:: with SMTP id g5mr258155jan.61.1624896169846;
        Mon, 28 Jun 2021 09:02:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:33a6:: with SMTP id h38ls2947796jav.11.gmail; Mon,
 28 Jun 2021 09:02:49 -0700 (PDT)
X-Received: by 2002:a02:c906:: with SMTP id t6mr250325jao.117.1624896169374;
        Mon, 28 Jun 2021 09:02:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624896169; cv=none;
        d=google.com; s=arc-20160816;
        b=Td1bxab2v2Vu6dN9zAPEKCB+bWNb6IQ1HSpa2qScNjaX4oRxxiSvVQ3Z/EAWLIs9EV
         VOrGpvnk6F3A7HVZGmpV4qfiR4OhVmP+TdzLUx8GPNoADmn5ahTy/b5MOHP1A8Tow8Ed
         P1t7s+7XZDVn2MvtHCPlzxZCmEfroMURR8tmE/gcALIQM9u9cmiiXEkLiEva20KbFLfE
         o+lLxkjYRdHILDJY0+Hsz/X8JqpVqfcUTby1H/tnS9ShxsPBWs+JZr6vQBC5TxXyLSme
         jovC3XK0tl/5Om55snf261TCv1Ymd4amO3BiDVJwRCOjldU32FqS/ALsjDXMgZzs3wPw
         hP9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=ugXdaejItuqiINTIGxLcTT8F6BiP5jb1opsZBA3iE/s=;
        b=p17sZ2ZMBjgeVvADKqNmOIyI8oZHq01zIh13ngszsrmHktNa6ADA+np6JQD9oMbD0n
         njWylQkmwhU5ZMUSbjL4+A9No+3pmziZWXva+JlOWLn5js9U+MqWgK5/HTiDp/nAkP5g
         O/VUQJYVPXvM56sCwVovQXYPpMQnA3KehWnLun/b0JR+yVZ3nsyQG7+ihKcjI5giHHAr
         XqJTLKgET1MKsOvgpcjPzgfAHGmhgV2ldnPK5QUBkV5Py/gGYO95PU8MQPhTJXqIcOO9
         muhYnJEYofbWVN2W8SkzdYBeTqeig1xXUA/jrN9yZhkd2C9PsCslbeNd+qSW8EDPP79J
         Pzkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=E1RMJxN4;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id x4si1517842iof.3.2021.06.28.09.02.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jun 2021 09:02:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id a2so15811094pgi.6
        for <kasan-dev@googlegroups.com>; Mon, 28 Jun 2021 09:02:49 -0700 (PDT)
X-Received: by 2002:aa7:9a9c:0:b029:30c:8189:7c16 with SMTP id w28-20020aa79a9c0000b029030c81897c16mr5572906pfi.76.1624896169019;
        Mon, 28 Jun 2021 09:02:49 -0700 (PDT)
Received: from cork (dyndsl-031-150-011-223.ewe-ip-backbone.de. [31.150.11.223])
        by smtp.gmail.com with ESMTPSA id a33sm4672457pga.68.2021.06.28.09.02.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Jun 2021 09:02:47 -0700 (PDT)
Date: Mon, 28 Jun 2021 09:02:38 -0700
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <YNnynlQRxr9D3NJJ@cork>
References: <20201014113724.GD3567119@cork>
 <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=E1RMJxN4;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52d
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

We found another bug via kfence.  This one is a bit annoying, the object
in question is refcounted and it appears we got the refcount wrong and
freed it too early.  So kfence removed one layer of the onion, but there
is more to be done before we have a fix.

What would have been useful in the investigation would be a timestamp
when the object was freed.  With that we could sift through the logfile
and check if we get interesting loglines around that time.  In fact,
both time and CPU would be useful details to get.  Probably more useful
than the PID, at least in this particular case.

Does that sound like a reasonable thing?  Has it maybe already been
done?

J=C3=B6rn

--
Given two functions foo_safe() and foo_fast(), the shorthand foo()
should be an alias for foo_safe(), never foo_fast().
-- me

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YNnynlQRxr9D3NJJ%40cork.
