Return-Path: <kasan-dev+bncBDRZHGH43YJRBIMEWT6QKGQEWW6WKVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AD4D2B0209
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 10:36:34 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id c79sf1949497pfc.20
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:36:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605173793; cv=pass;
        d=google.com; s=arc-20160816;
        b=hpXZWbQPd6+YJUEf7nP0v6b4HppM9sBvY40cgaqxDs7hgVkrWklRPUO1BUwbxpJkZu
         cTaUyKPN/HAM7nY2RzCKL3sTMXQ5T4nlZriFIk4vLdPxXTPnK7Ct2DrMpUUEZDpgaZng
         IBukto50NdBrYKyIdbHP/8TnP088pGR5mqGa0Bv/FnJdezQ3VYbMBe6lOb98CzmGSkjQ
         A8fKEIHBqPiORSBOuyXP3WBgzPuD6WJhlL6NZsoxuBcIxUEwoD77I8YufXvdw7TU6ZXh
         hF1zLJPvZtaXZIkrOQPbd4PVfat0lz2NWp10VTcJo6+h0oU/HCha7a3nyEi3IRC9Z3Md
         WUTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=KAmqQPrrkjBXe+gHFTStoNKd1PbZNjZig1en9hqmEjQ=;
        b=HsH+3F1e9ZZLeYx1q2hJnDlJE0q/SmLqdciLJLSpRtn+qYNF+/5lZTRntr4u0d9ZJv
         qK38QDFJPAjivNG+xKQOY+t9rw7vze6CmE+5zKPL7VqXTSQ8LRMl+fjgNEHg8okROL7q
         J2dcCgsj8XCv6pvwAyvVn568VraPZAs/7AHn+tGhBT76+SsuUqC+KRj2qrsixlsrxJxk
         4kgNlPABfFAacA8hdTUHuM1673AUPLk+l97YS943ZVjtNWADkIZHu106trXEx2v7nHnb
         bWIUC1pc9rQAjRIFnm1abrzd+j/1p99R8B65jTXPOwHwWZl/3bbZlTGMLaAcigKdupJK
         n+/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=cwM47uyO;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KAmqQPrrkjBXe+gHFTStoNKd1PbZNjZig1en9hqmEjQ=;
        b=Gk83EhfHyeG6tDow5yvnYJm9YcY/0j3A7fAzIsH/E1byZv6XzKoSP5POvzKbYFkm3H
         eL1sdHaoqP5Qva81dNVjiEwUl7t/1FPXz33qrUL+bkDIfSyGGCqWYfPW4lIQXOCb0RK1
         lmz0KSGEBcD+wMThuCm14V2/wI3LwKRAmh2cZnt4yYieptidvBgWwTTGmW91i6ZctHcH
         DCcA9i/d8sA1kgIgNAss9DQruv0e4rnoduxfE6b0FKN1jb6dNH3fgcjdzPhbg0NkCD+T
         /WbsuZVVtsPsGg+uQiUfX+Meb0o5bpBr2YIchtvG5bEhSe286V7JUym5kOc5G4w9DK8s
         ybsg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KAmqQPrrkjBXe+gHFTStoNKd1PbZNjZig1en9hqmEjQ=;
        b=UaAcDG048RWYClyVtDlkkAHNVOQy3SEDtB4t1sXjzNI1Hmvd9+YeC9NGcyTkdU2Ias
         bzifWoLSTFaqSnfGfFZyKKBKE6ikwYUsgUYRaROwh4/CXQZFDY2OHj+TXFFrt7JGKUAd
         +FXd24aOxCLw0jThcHUWWA7qnMTPgYjed7up1pzrGGrH9yP9fgH8xjX0BhH1lsMhlEf0
         kQ5vzlxYom2sl35CiWzfLDDOdNgEqmhsnnfGQvGRGB7x2+kzjcdpimZMqu04cVo/TE6q
         utQ3A2LqZrc/35814NdS7XwNAwtNOg7wcPk78b2tuSPhkW7w0fwo1nFWSTrSV1ZdRkVL
         xoFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KAmqQPrrkjBXe+gHFTStoNKd1PbZNjZig1en9hqmEjQ=;
        b=Zi0tDpw+MNWttstzrQEK9GQ9poA+/eQ4Mdpsaa31fk2SUOo24tQLZLL6/W0mXQ/0Fi
         0YALYSzDfmyqWBO/EarQ0rYL7Yn3wpTwd9Vrpcjek5v7UUS3W5bY7WKp7dCShieDqXh6
         LdPcSn043fMMCksoz9J5Yi/IU2peP1miNEgM3fnNmwpGs1POS0gjmll4D/NkWsHOAnA3
         qQkcY+xLLKRBuxE+ZgJllXHj5NaZCTewusZPY8x6b6jyGkw1TOMSYtitjH1QQHK9YO8t
         PW76JHWvf8b9AW767UgnmFMRbLiQwULWIrFJrWfuw5vQ4M4QTpxN7bKhKBbQErRrGHAc
         rgPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532b11GKdcyLgHr8E+BhUpCWUuL6QPGTKH+yAidbf9yi3L4wnnUf
	TwkDusknjJXJsIgVqMxDDzo=
X-Google-Smtp-Source: ABdhPJx1bY2rUv9mDC2f6nQ6gVNIJboQz9UiQG/W6fF21ORdZOcD2etDEc2IB9+zVcq8ifrt9ljnsA==
X-Received: by 2002:a05:6a00:13a3:b029:18b:d5d2:196 with SMTP id t35-20020a056a0013a3b029018bd5d20196mr23118386pfg.62.1605173793306;
        Thu, 12 Nov 2020 01:36:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:784b:: with SMTP id t72ls870495pfc.1.gmail; Thu, 12 Nov
 2020 01:36:32 -0800 (PST)
X-Received: by 2002:a63:eb4a:: with SMTP id b10mr25067865pgk.416.1605173792760;
        Thu, 12 Nov 2020 01:36:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605173792; cv=none;
        d=google.com; s=arc-20160816;
        b=sX56bF/oClbIMDoPLsOUkg6Qc1dKSSFLbyONTqJnyUQbs3L5lTDWxAXt5jPSZnu2B8
         i9mDEUVIRJFDxgk+sQWT0iGuKdAHRGDbNxF3PJlN0Ilq3JwJMgXtpqtDIrWShj5+HatM
         Dzvw6qgO2ZhOSCTbGuKrvVbsQkp/tLh/qRejFyWZvThdJWZLGv5WoCET2IuzYRFntek/
         aCtCF+KWhzkPsRyRkd4+bpn65jcocXyuussRpmY41QVkAeK3nuIJwcCHvOqH/nBnQHnH
         Ks0HQ76+Xdliyu5gw9wTobTieZWhtLxcnlq/LuqDgoPjwNtp/RCa+5htpyYGdpZG/km3
         zBfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sTS5WgslFCC2reGOH2FyGvABtQkS4qb5R30Fuulj5m8=;
        b=lv5lDlc/gawAcDQzrqL5T1zFIw71Je9BmUlm99DAc3EugbSmqke2XOqW80wEwJmHMV
         eSbvVHpD/jtkhrZhycJgQBT6jYYpd/AOGbFhO3UgT7aARkraXtdfRbNNVRlrpZ0dz3EG
         I+KA8K+eoFS70JPYhTALa1h4NlpTxxb6abBJMZ4S6QxtU7L7fvGNNP0GtR3OKLtpCDU8
         XuyKBQW94OybpvUBBbfb1nR7kID0uE7fYOTgvSbrUbM63TYFPkIprkEbilusKGWXvJ1S
         PnzwL+sFmQNW0SQBVy+oVegsDWA8FW6NwMm/r/zogpNW2AckhTHG4Zh85haw7h/5L9LP
         smUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=cwM47uyO;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id s9si197927pfm.1.2020.11.12.01.36.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 01:36:32 -0800 (PST)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id t33so4745920ybd.0
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 01:36:32 -0800 (PST)
X-Received: by 2002:a25:61c5:: with SMTP id v188mr34927594ybb.422.1605173792160;
 Thu, 12 Nov 2020 01:36:32 -0800 (PST)
MIME-Version: 1.0
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
 <20201022073307.GP2628@hirez.programming.kicks-ass.net> <133aa0c8c5e2cbc862df109200b982e89046dbc0.camel@perches.com>
 <CAMj1kXF_0_bu0nbJyUU-yBDCOAirRvGkX-V8kQPVh_GHO2WM-g@mail.gmail.com>
In-Reply-To: <CAMj1kXF_0_bu0nbJyUU-yBDCOAirRvGkX-V8kQPVh_GHO2WM-g@mail.gmail.com>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Thu, 12 Nov 2020 10:36:21 +0100
Message-ID: <CANiq72k9y-sh1fUyxdvXgYEfZOS_CSwRK+LyR6nVtRaOjYJbwQ@mail.gmail.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias macro definition
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Joe Perches <joe@perches.com>, Russell King <linux@armlinux.org.uk>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, X86 ML <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=cwM47uyO;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Nov 11, 2020 at 8:19 AM Ard Biesheuvel <ardb@kernel.org> wrote:
>
> I am still not convinced we need this change, as I don't see how the
> concerns regarding __section apply to __alias. But if we do, can we
> please use the same approach, i.e., revert the current patch, and
> queue it again after v5.11-rc1 with all new occurrences covered as
> well?

In general, it would be nice to move all compiler attributes to use
the `__` syntax, which is independent of compiler vendor, gives us a
level of indirection to modify behavior between compilers and is
shorter/nicer for users.

But it is low priority, so it should go in whenever it causes the
least amount of trouble.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72k9y-sh1fUyxdvXgYEfZOS_CSwRK%2BLyR6nVtRaOjYJbwQ%40mail.gmail.com.
