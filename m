Return-Path: <kasan-dev+bncBD63B2HX4EPBBMGD4P7AKGQEG7XBZUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E1042DB119
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 17:17:53 +0100 (CET)
Received: by mail-pg1-x538.google.com with SMTP id w4sf4585120pgc.7
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 08:17:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608049072; cv=pass;
        d=google.com; s=arc-20160816;
        b=aGc1w2wVkPagZJJRqZ3i3zWd86LbGUaoYt3rRgoMwUAhgh18TXVHIsOus9EHcNrM9R
         tzpQrVHskEJTb+56r50Fhdc5PdTqVOZWTWFHE4FA+Ujc8ffe00JAHBofesBNo0q77tmR
         dWo3M0DPnWcgNUquqmEUvfshiWnKx2QwkHX/6dHPIvmJGesExuhb/MLU/nFX7WLVdcu8
         ba8vxejRisK43Od6SDrUeQSer19p9VCJBMpryXCcuaXG8/9gsi2rKqa+8pkWGiNjlHLD
         F+eSujUAS4l0yxmdJLMnc144LhzZLONZ2Po4NqQ4QjsxXfBLri0WhMXeki3/8fxOQll1
         H18A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=cj5gYUCzjIcRqt1WYxGAy1jKB1C8Ikn+gS7vlEZSbF8=;
        b=vKhnJhd+xtJp9dWT+qiQcsjF9tf9EKyQohiXJXwd5Vf22yiXDmN7l/APXfYCSLpT8t
         WPzEUV1MG5JDuFaQpeHoMiArxN3qDXCnFvCgagJrBSxK8IWaMbE6aEGl2x16ASqSvZfw
         9JP2MUB3bujYUmOB4DQXqPCvpMtvvWdNmt5mMwPv3u/6u7AermQf/rLSYnvvLFDo0pIY
         6Wit4XEEo8XAHsIzGf7kOMc8CnIIFtF8/uZV8VtxeYv0fGMmmjMsc96IQN+WHUAHdgHb
         oVo7GLlJKNdyrpNlsbFpqtMf7q6VoZF5hkcrsCPhG79LdqYnvK+gmb6AiiIhokmNqj0o
         E7vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=X402qEpM;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cj5gYUCzjIcRqt1WYxGAy1jKB1C8Ikn+gS7vlEZSbF8=;
        b=rN1FKO3ZTsTIqq5s6tmum+MZdXbwZVKcBgunkyMkCipNN3baEEQjauO5/pQm3CUmSO
         kvT2ZrzFKtvXGym8OzSpwKgX/B6NNPy4uE5Vyu5ECrqsxyPyWymZGDdrjNN5/XAYrUmm
         imfWyM98S6dNd9HChcBfA22JUrF/ujqNBKs6w6m3UXiY9arPcPgsdbpAp31o/J8g3ctS
         Vxr0KTt110fqfP6wqenun4bSljaa3CDAZdeuF5XU24cgkR9svlQe/T3C77MV/oMDmrmN
         sndqQCw961g1Rh0eS9twXwOPwZIqQHjttr+iI2X9Uscxo7u1tr+3k4Kk4gUWhWtxY5fe
         d1Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cj5gYUCzjIcRqt1WYxGAy1jKB1C8Ikn+gS7vlEZSbF8=;
        b=BoQBZ+bSKgqiHXJTIlG9h8JymGpsQgYKoiKfFzdsISD5VrGimbMErloN+nGc0v7KDv
         bLB/vzolU7aem1uLeyQ7Wo1mJMFYgEzUOIQWxvpgqs7tmok89TjIsw9JVdMJNWpl6n8w
         3oE0+Nlk4yztNvH4gudi5aLlSu87ZFuG0bNMZM3rhmk3ehMGamM70Bf/bW5D8cs9zccM
         YsbuL34E9d5TyoSK8UwRgdY6u/77xCbc7hxK1pNnbpntB4rixh7BeET6OVhd4RsZy4Mf
         tGvpu0Z1DXcbTR595FN3OUztqk6M44wBrWhaHHiVXQY92YuSNnQehCLtNw6MVXNfVnPZ
         aFFA==
X-Gm-Message-State: AOAM533F51a8UTgKFeJPctzlw8PP9NtGZh5MMaoaSFgyNJ+66bItnGi5
	wjaXuNB5kV5p62RGiOSVVD0=
X-Google-Smtp-Source: ABdhPJzkHa2o/UINAHPiJo7NZAMa1CK1EVibj47U/YNsKrZKnh6YMppIDQENX5gFyTeSTKrzlfAhcQ==
X-Received: by 2002:a17:90a:6842:: with SMTP id e2mr30661785pjm.190.1608049072269;
        Tue, 15 Dec 2020 08:17:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96d4:: with SMTP id h20ls8010709pfq.5.gmail; Tue, 15 Dec
 2020 08:17:51 -0800 (PST)
X-Received: by 2002:a63:4102:: with SMTP id o2mr29742035pga.166.1608049071657;
        Tue, 15 Dec 2020 08:17:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608049071; cv=none;
        d=google.com; s=arc-20160816;
        b=heemtNqe0Ua3saMeXzahq+LneJSEyr01ZZEVuXMgjHvz1Nr5aKqj/sCkuriSaY3uQK
         GQ6eXdNtovxeAs/dxm+gUZzignEmYuH1lWEoANOg7LUjg/3tz7r67LHbqzRY+hvJmRf2
         gyq0lxcWzBKByfVZ+5P7awoZFLwM0ZVu5fDR9kmNHXCD/VtyUzfBErWB4YOD+S0y571c
         P/GEcHokyMigLOzv/MTS4ggu9/qZKQSHEp7K/wsvbzHEzbNXiAllhHlFUfynXl4E2zPz
         6LNjATGT2fonkvGTndF3aRKlfYuO2lyYJqL+POcRtDn5R4fI8Tuq/H0Q7G0xYTyiJogj
         7lxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=gYV9bQtU6AtNO6Tp8rdUH5Eqr1GoPUTwZBKT8B3ZCSg=;
        b=hAzLYRhnFOux2iQOMPIRX1nhyyiglxshLUEuDGqwyp2cBVK/RRjScfUTkVyLyyHRii
         gSUNOILIwbuwaweW7Eg23MakPQlFGx2iiW2k/aJLMUv2FhNAKf/aKbWRsjsSU8iknzCH
         tp39V665tbIXKy88/bwXndAWOTlaKnVCSUVxL+sKZXRJgrFHMbJI5ZfUjFlNOZLBxrNS
         WstaqAYa3GyZM1Ig6/FRhdQdESgIG5I8THcpt+0VKn9UWTWat+LOSgOTSZBfcb7OLf9r
         W7C0rVZSgILBPdLb45gfAjxYZVz/M7qbtmOXQwXtn5VDt/ajTLjoJAMPBT+NwpG0epNv
         +41Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=X402qEpM;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id b18si162131pls.1.2020.12.15.08.17.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 08:17:51 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id z12so1491817pjn.1
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 08:17:51 -0800 (PST)
X-Received: by 2002:a17:90a:6fc7:: with SMTP id e65mr30779410pjk.116.1608049071403;
        Tue, 15 Dec 2020 08:17:51 -0800 (PST)
Received: from cork (c-73-93-175-39.hsd1.ca.comcast.net. [73.93.175.39])
        by smtp.gmail.com with ESMTPSA id j5sm24583448pfb.195.2020.12.15.08.17.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Dec 2020 08:17:50 -0800 (PST)
Date: Tue, 15 Dec 2020 08:17:49 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: stack_trace_save skip
Message-ID: <20201215161749.GC3865940@cork>
References: <20201215151401.GA3865940@cork>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20201215151401.GA3865940@cork>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=X402qEpM;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::102c
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

On Tue, Dec 15, 2020 at 07:14:01AM -0800, J=C3=B6rn Engel wrote:
> We're getting kfence reports, which is good.  But the reports include a
> fair amount of noise, for example:
>=20
> 	BUG: KFENCE: out-of-bounds in kfence_report_error+0x6f/0x4a0

One more semi-related question.  Can we distinguish between
out-of-bounds reads and out-of-bounds writes?

I have a log-scanner that generates a one-line summary for all
interesting events.  Back in the day that used to be "Call Trace", but
being more specific allows me to skip over lots of stuff without opening
up the actual logfiles.  And small details like read vs. write can help
in that regard.

J=C3=B6rn

--
There are 10^11 stars in the galaxy.  That used to be a huge number.
But it's only a hundred billion.  It's less than the national deficit!
We used to call them astronomical numbers.  Now we should call them
economical numbers.
-- Richard Feynman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201215161749.GC3865940%40cork.
