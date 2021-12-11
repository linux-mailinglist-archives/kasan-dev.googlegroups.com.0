Return-Path: <kasan-dev+bncBC27HSOJ44LBBVVS2OGQMGQEQ62HZMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B37584714D4
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 18:01:11 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id o17-20020a05600c511100b00343141e2a16sf818634wms.5
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 09:01:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639242071; cv=pass;
        d=google.com; s=arc-20160816;
        b=aWykgEboWtETQ2F8vzhFvI2lRj0mTlhZ9ZtUi+kDUXkeJOlBDHU9P/0rxfDmbmBvYU
         j6zr9XzTrL4lWDgmApwy1ooiK28oOSwnMQvLATjojWTQWWGquhE4dEk0XamTFFZTrXDU
         YExxKfYoF2sBkX1JPiYHPNrPqdHPm6NHnzwA5dyVa1SOJHteBY5vcOLvXmasyhmUP6mz
         rmaY08gzvfQxTnWPuCXjYmtSDxcYaFRx8D9qh2NriIpZz1At7kFIjNlFc0jSl06gvNx/
         9LNdvLjfIOgOPDyJgIn2oEG+EOg8NteyG5oNuLY7XZM3gKBkGU5+hDSPJe2vsvBRTkYN
         1IlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=fkO7T/aOyZcfmt0TGbklhfctszGqAVEZiJpzBrg+uFg=;
        b=W/QCgjiqRK3uCwRxng30ptvZq19VH2v5Ag3Roj9sQoDhGHKc/iLsFOXY/tLwus7HPA
         mD2KKM9vPwHnl7H2xpfeRRquJACOhDi4d1gIocQ8/slOWHDteZjR7Wcjh/K4llcQrTCq
         GJRmeZ5mv1dtp+lhTWlqyFCb2mOBCmgxq/AMGgglY8P2gLItIYQJVgJiMLc5aFw/N4nG
         ofm5HWw0BQYDfAWF/qCVKdIuVAC8OHhNF4cUzs614YXxxRU6eGaPLiXlyiCslu/euE9C
         hrowpv/ikvtG56IBCyIn3xxwoR+p5nfrruyDnYe+WKFyUz6h5ud0pEQTUqNOKrxQVeL2
         YJYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:mime-version
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fkO7T/aOyZcfmt0TGbklhfctszGqAVEZiJpzBrg+uFg=;
        b=gj4wayUhaaxi5TEV97ks6QJBrFFS0T1Pq8dW4cHsLLAOI/4OKcbM5i8+AEuiFBqIMu
         5cRxD4iHfMEf4c8Vnsf8GX9f5YokbPhyZHHXEoB9xFbI/iIwwm3HpBiymkBM+F3qvOAt
         6Eu4xvfj/gXk2IPwCcQt4p0fmSxHjYgDyhyHmqNqWmultttlqnnfXMFTSagpDVrOp+2f
         3G2Dz7RNVQNSuGwoQl6lV6vofoFI4/PFRElE+4M1ak1aw/IrcEMN5D2Q+JXM+tp3mmwi
         ogHgXGrDWnBqJTdMPgSaBr3P+2Iu956erLpaRP/unB8IZWtWVm+DLPtNpsm1vXwdZBZY
         aCag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fkO7T/aOyZcfmt0TGbklhfctszGqAVEZiJpzBrg+uFg=;
        b=8FrrrYPsVxo8frOqREVjd7OzUBilWl2qA0x2lHViLVpfnuhSZ0m1Fo8r3+VEQc49Gj
         GHsV8A+G/ImlyoTvGVzsSJRSVm7tipsD866BePyojpFaXNswNFQiWcQljNuN5eOXo7ip
         wsO1Bp35uTp1R6gzr0Wqx0gzcX7jqBmgHKxFo+3+5iDpsBdNJzXSf5G8VHPzwuu+vzLN
         RwHW1IWzwZo7bNFisEIromB0OcsZyk/O22zVZj4dZeTSuNQl6TatKMAAmXKpB4EQZP7I
         px4K65aeBHOuOr635gk6KVpeDKJ4AwczKupjIATX983qT+2N1CUD24qRa3vzrU7qF60X
         E6hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/ABdvC/fuPPBR5bpmbvyrl/xzB5Kw0fFk6udUSg/40Y8Cm9XW
	Iz/J3Up5cc+GFZzlPe5H2OE=
X-Google-Smtp-Source: ABdhPJx23jz/5+QkUkoLLW/+uoGBMCoOud9WyS5ZybU81OsMLSzjYmxjOMRfjLmfdIPsEfZX7vP6LA==
X-Received: by 2002:a05:6000:1289:: with SMTP id f9mr20568337wrx.329.1639242071165;
        Sat, 11 Dec 2021 09:01:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls1203959wmc.2.canary-gmail; Sat,
 11 Dec 2021 09:01:10 -0800 (PST)
X-Received: by 2002:a7b:c763:: with SMTP id x3mr25066033wmk.31.1639242070298;
        Sat, 11 Dec 2021 09:01:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639242070; cv=none;
        d=google.com; s=arc-20160816;
        b=OuonDhnaNcWWBjV/0ZBddvfzDWfgiaRsU+Th+tboFSX3mq9KLjBOAYzISrF+lYu2WR
         BYp4XjdMGdj5pFPSq0PMVMDRWtlrl6z+JkqeFwgEWO70xJGYNyjDsKIQQfFUjatGH9Se
         5+YEZtq3EnQrHXKzXCyjixFyUBf9veebDz5BiQgqJ15bgXwBbgWABU4PFMZzLRql2tsU
         vgPSw4dXiqsFMlgMXaenBl0m3EqUXeCMyx7oj5/qMP1FRmY3RReF+SHSQU7J/QFAStX3
         klC4yUtR9JvKdiBGhgaJ05UHXv/xr8YUK73/dBpJV+VGGZ/EABoOcw3psmdTH9op9AAw
         SnfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=6eKmioURPOfmT7J1Y2asSqNKPR3PLLF4lI1j/pu9iAs=;
        b=x8hx9FJilkfcCjDgT3bEfJ3laOYjf+pdsMhQQ/eCZOZL8KlIxy8vHHpX0HWmvwZ8CD
         tWY25qjJEo5VHAUex3LquFV/FTViJ2iDUoh0V13nNHNwPU7UlcGQjSE/VlrFfZPjb4bf
         oeCCyV1wmQoaLlRzg9+bJYfk90qcb7Gt/+ds2xbmf2ghTLPQ4LT4SPLpnoUJNPSpbSyu
         uThRMu8eTj6TA5Aqm8B43p4mLbvDy0mb+S1qGMM5v9nWoFhcTy2BqFn0FwCi0mya/1Xw
         pwN8iKr5sretmnWnaJ1TSL1ohBIo9HtXs3Rg0wTdPfSGPf67kx+FC/E4NiEhnK6gZxLG
         uZ3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id z64si104146wmc.0.2021.12.11.09.01.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 11 Dec 2021 09:01:10 -0800 (PST)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-61-1s9Z_dAWPDe0SOxPMZbbFA-1; Sat, 11 Dec 2021 17:01:08 +0000
X-MC-Unique: 1s9Z_dAWPDe0SOxPMZbbFA-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:994c:f5c2:35d6:9b65) with Microsoft SMTP
 Server (TLS) id 15.0.1497.26; Sat, 11 Dec 2021 17:01:07 +0000
Received: from AcuMS.Aculab.com ([fe80::994c:f5c2:35d6:9b65]) by
 AcuMS.aculab.com ([fe80::994c:f5c2:35d6:9b65%12]) with mapi id
 15.00.1497.026; Sat, 11 Dec 2021 17:01:07 +0000
From: David Laight <David.Laight@ACULAB.COM>
To: 'Jann Horn' <jannh@google.com>, Marco Elver <elver@google.com>, "Peter
 Zijlstra" <peterz@infradead.org>, Alexander Potapenko <glider@google.com>
CC: Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>,
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers
	<ndesaulniers@google.com>, Elena Reshetova <elena.reshetova@intel.com>, "Mark
 Rutland" <mark.rutland@arm.com>, Peter Collingbourne <pcc@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"llvm@lists.linux.dev" <llvm@lists.linux.dev>,
	"linux-toolchains@vger.kernel.org" <linux-toolchains@vger.kernel.org>
Subject: RE: randomize_kstack: To init or not to init?
Thread-Topic: randomize_kstack: To init or not to init?
Thread-Index: AQHX7UIUmxdq4YrWzkyiG3jb/JAMzqwthFQA
Date: Sat, 11 Dec 2021 17:01:07 +0000
Message-ID: <d35ca52c81e7408ba94210c6dbc30368@AcuMS.aculab.com>
References: <YbHTKUjEejZCLyhX@elver.google.com>
 <CAG48ez0dZwigkLHVWvNS6Cg-7bL4GoCMULyQzWteUv4zZ=OnWQ@mail.gmail.com>
In-Reply-To: <CAG48ez0dZwigkLHVWvNS6Cg-7bL4GoCMULyQzWteUv4zZ=OnWQ@mail.gmail.com>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Jann Horn
> Sent: 09 December 2021 21:16
...
> This doesn't just affect alloca(), right? According to godbolt.org
> (https://godbolt.org/z/jYrWEx7o8):
> 
> void bar(char *p);
> void foo() {
>   char arr[512];
>   bar(arr);
> }
> 
> when compiled with "-ftrivial-auto-var-init=pattern -O2 -mno-sse"
> gives this result:
> 
> foo:                                    # @foo
>         push    rbx
>         sub     rsp, 512
>         mov     rbx, rsp
>         mov     edx, 512
>         mov     rdi, rbx
>         mov     esi, 170
>         call    memset@PLT
>         mov     rdi, rbx
>         call    bar
>         add     rsp, 512
>         pop     rbx
>         ret

Jeepers - I don't ever want that to happen not ever...

There is plenty of userspace code that allocates large arrays on stack
(I bet some get into MB sizes) that are correctly bound-checked but
the expense of initialising them will be horrid.

So you end up with horrid, complex, more likely to be buggy, code
that tries to allocate things that are 'just big enough' rather
than just a sanity check on a large buffer.

Typical examples are char path[MAXPATH].
You know the path will almost certainly be < 100 bytes.
MAXPATH is overkill - but can be tested for.
But you don't want path[] initialised.
So you cane to pick a shorter length - and then it all goes 'TITSUP'
when the actual path is a bit longer than you allowed for.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d35ca52c81e7408ba94210c6dbc30368%40AcuMS.aculab.com.
