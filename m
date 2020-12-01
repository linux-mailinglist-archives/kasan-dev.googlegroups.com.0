Return-Path: <kasan-dev+bncBD7I3CGX5IPRBMW6TL7AKGQEGHNABZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id EFC1D2CADF5
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 22:01:39 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id b184sf1123326wmh.6
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 13:01:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606856499; cv=pass;
        d=google.com; s=arc-20160816;
        b=AB9PgxjGOXfL7veZRHW3euocIWrvpj2QZRebmx4bmazb2ptQ/oRag6qUj8MNt68IIl
         WyjHu4GhGdvBr6es0BRc51h1Hdc+eWHIpiy8khsFdYyj501b32PT4ztLZieqcTgueDV5
         AuIKGc+i8xYRE8uUl586H7kb6jbgrxgA0hc91ty17vljVhT1UXX/rXAJBVJMrmF91brM
         cPDRcD0ahP3v19SKz7/k6E0ljnr7wwYRHwjbz8ymK2SI2gFRMgczTGhcHplW8BRLjG8o
         6Qj6Hfyki0WVF1S1KnJjvTwWE+xf/5BDdYmc1IiqZFpkM2hOEOJWodDiWeklI5lyrUOX
         WbMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=AOTKuI1JXgSei+NVluAOuWauhkJRuUCYr3dzk+3+nT8=;
        b=mnQvcohcDnEwFfXfzHYmoUWUutRqpqgvG9kl8qwBfr0USsCfv+IU7u5rCoytepTCys
         k/nEgbuK9axgT0XM9g0aBdRebVAgxdx7pip+gEX1+JCk+rA9e7so0CY4KKXl+rkqFsbj
         k6zHYGzXMfU5zm1HEeA7w5q4mcifniW/p4f0VIFEULKDUTCaTxY3Lq/vF2LIF87sd8Tx
         BRonM21BuI9YRHfoYM2G23OjjcAz8T3raInOudfMH3TzFvKoF8kCBJeHglFwV8V0754A
         JPSbKp1gLW41bY9shiDbrXHOGXY5dGQMEsIC1n87YFrSswpHFMLRpkHWqT5taf3upqkW
         9FJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b="GLG/t2Ix";
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AOTKuI1JXgSei+NVluAOuWauhkJRuUCYr3dzk+3+nT8=;
        b=o8owZg86WtPNr5DGF5OdpQSG9e6Fait5v1DlnfEHjz8aruUCgNB0Ldw0N/nIp1DJNQ
         8tkhh4pDYKg6FKXgAYaUfcnmJ6E+I2IQcKocN7+k55Bx6WaIyrmOD3PBwtsycZVfqHtU
         +z+bnHPOhuK8l0HCr9tY58wfQlLSWMCYEd96LKy/tQs8F6ybrGvFW12LCtTIcu1snqF2
         Fs3NJFw0uJRC91xNdmFo656ubMjVG6ibAOmT/0x7MV5LXyNhjyLEqQi5LSfqx7HbXvhG
         HdWLYrthjdL1DJ438l3ziOolgLONsebAj/yOZTH+z8isKsPo+wJSYXvY6SJH/AyEZCMZ
         hZuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AOTKuI1JXgSei+NVluAOuWauhkJRuUCYr3dzk+3+nT8=;
        b=Q4BCWWGYbW3Q93dZJGSIzNFBmIhpxAUA8EgVvz3/RrsyK8/Ncq3J9qRJHbZWHvBz7U
         AxyrTRWc0uj6SFnrl1pyPTJrFonkHw7sIr3JSNE76aRaNtQTNfNU0IR+eujVVaZHZ9lI
         ucX6bubrzK1FHAfNLNUvvjgsbPKDU1Dys3YTFlRjiR9BK4t2QcfL/c45OIc3wPLaVEfn
         TjJLqBm1tODcr2YYBgoRuEUV5ssm1zs1fqsNMQz+stiWIwTHoMb7o4zlfTCJxD8DCW8x
         PWHdB7YvRkM+FFPwoI+XYPczG3cqgIk0VbVw/L0RSYFO5OOwnHW63l2Cvx2JlkPGotEs
         87fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531f8k4VD+KgG5xJAg6vSVpse4VKuSyt9lN2LmpLgrNtis3fY7pS
	7J94hcLWvyS8IjG/RMQyfbQ=
X-Google-Smtp-Source: ABdhPJzoDJg56Z0b2SqMJEs9mVa6DfJSgzNUpjV4RAXT8gZ9oy3owCG2us0AD9uXF3s3mScxFulANw==
X-Received: by 2002:adf:e7d0:: with SMTP id e16mr6430359wrn.114.1606856498680;
        Tue, 01 Dec 2020 13:01:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls1978807wrp.1.gmail; Tue, 01 Dec
 2020 13:01:37 -0800 (PST)
X-Received: by 2002:adf:8b8f:: with SMTP id o15mr6305977wra.311.1606856497750;
        Tue, 01 Dec 2020 13:01:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606856497; cv=none;
        d=google.com; s=arc-20160816;
        b=Z4d2e+flYYRV8+4c82qq8fyiBCowQcRxC4C/smCHRhnRookLo+r38BkAT2azfjl4dz
         hmtEkmdM5X3BbqP/Boi8tiGX9UDhwGxyrTN3tPO3IDuz7ZMBqc9zKcKINAtU0aPDs0c4
         wak9dncV2H8Zx+bPPaLWBy7QKx/DW/HcJ5jGtP6FzZPpMqHbi3lIBkDc7+uu1f8FmmQX
         kbwzpJ1NLQ8DOPgcz7N8k7vp4oNmGU97UoUw+BlRl30oXDsbwOn7la4vBTzaDAadwBcx
         RohoAVRI734aoXK/tPBCVspPXKk8s4Zta6U7BRL9XwlLO+UDhMdZe/wJydLXRinxzPB1
         Gyqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=b2FxREJM4KjZutceZCm25hg4BRQNyF6TpYcPtf6exnY=;
        b=hmnspEwxnLRJsA5mBzf8Kibe3l2xM1KzzrKGptm8GcM0aWP2+eASsOB5RpaopDPLew
         Wtce0EtBf71OV/CbesXHC1I7TkWvRmMEGyEH4nJgkqgHZIXNoPEpmwenq6V/Iw8mm/5C
         qf2wS3STxQLWV8PrDx3VLBAziwgI1qvoDH4JYf2w9tmVdHRd9o/PeB7UXba9KeZ2WlO+
         2W8k/DLM7SuCk41MdAt5l+ASM038fC7u+xBrehYL/yXygzGIp42b7xCBe3zYuSjKw2ec
         5R9hR3fOQKWVSqR6InGI2U2n4E6pbg8QcKQTdIacQYqaH6gQYCvo5N28bF6GgGmqorTn
         Au/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b="GLG/t2Ix";
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
Received: from mail-ej1-x642.google.com (mail-ej1-x642.google.com. [2a00:1450:4864:20::642])
        by gmr-mx.google.com with ESMTPS id y187si86128wmd.1.2020.12.01.13.01.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 13:01:37 -0800 (PST)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::642 as permitted sender) client-ip=2a00:1450:4864:20::642;
Received: by mail-ej1-x642.google.com with SMTP id g20so6627321ejb.1
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 13:01:37 -0800 (PST)
X-Received: by 2002:a17:907:28ca:: with SMTP id en10mr4806924ejc.268.1606856497381;
        Tue, 01 Dec 2020 13:01:37 -0800 (PST)
Received: from [192.168.1.149] (5.186.115.188.cgn.fibianet.dk. [5.186.115.188])
        by smtp.gmail.com with ESMTPSA id n22sm445316edo.43.2020.12.01.13.01.36
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 13:01:37 -0800 (PST)
Subject: Re: [PATCH] genksyms: Ignore module scoped _Static_assert()
To: Nick Desaulniers <ndesaulniers@google.com>, Marco Elver <elver@google.com>
Cc: Christoph Hellwig <hch@infradead.org>, LKML
 <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Masahiro Yamada <masahiroy@kernel.org>, Joe Perches <joe@perches.com>,
 George Burgess <gbiv@google.com>
References: <20201201152017.3576951-1-elver@google.com>
 <20201201161414.GA10881@infradead.org>
 <20201201170421.GA3609680@elver.google.com>
 <CAKwvOdkhBTjjtEm9dc9irp8hpWoEDEAMj_Zp4ntKspgDkjrATg@mail.gmail.com>
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Message-ID: <764b18d4-b519-9f27-f66b-7cfdab61b313@rasmusvillemoes.dk>
Date: Tue, 1 Dec 2020 22:01:36 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAKwvOdkhBTjjtEm9dc9irp8hpWoEDEAMj_Zp4ntKspgDkjrATg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b="GLG/t2Ix";
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
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

On 01/12/2020 20.56, Nick Desaulniers wrote:
> On Tue, Dec 1, 2020 at 9:04 AM Marco Elver <elver@google.com> wrote:
>>
>> On Tue, Dec 01, 2020 at 04:14PM +0000, Christoph Hellwig wrote:
>>> Why not use the kernels own BUILD_BUG_ON instead of this idiom?
>>
> And to proactively address the inevitable: why do we have both?  We
> looked into wholesale replacing BUILD_BUG_ON's implementation with
> _Static_assert, but found that they differ slightly in the handling of
> integer constant expressions; BUILD_BUG_ON was reliant on some
> compiler optimizations in expressions making use of
> __builtin_constant_p that cannot be evaluated when the compiler
> performs the _Static_assert check. 

... and _Static_assert() is a declaration, so even many of the
BUILD_BUG_ON() that have a bona fide ICE cannot be converted because
declaration-after-statement.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/764b18d4-b519-9f27-f66b-7cfdab61b313%40rasmusvillemoes.dk.
