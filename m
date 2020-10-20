Return-Path: <kasan-dev+bncBCMIZB7QWENRBEXHXH6AKGQECTXGUQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CA4C29343B
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Oct 2020 07:20:19 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id b4sf855780ilf.12
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 22:20:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603171218; cv=pass;
        d=google.com; s=arc-20160816;
        b=xxW39tNrSEKM7IprXBtUZWDrBEbyFJ2KVRuyL5s2YrMbkEeMlKrwbnSdO+6KfFQDmj
         GYQa8X2W6ZR4LoAIGx8s6McogKYdNMH0O2Ii6GmEI6GxpsFkawcNWde9zty+iFna2ACK
         s7MX3xqBVHmFvxP8BqYkKWfoxsAzW8Bh6RZed9jeM50qO0VpUVx2k92ri6HxRzhoIH/j
         rW4HrsStmLOxnJVkn3nmIc4/KlZdyfLgY+hyL1YlVH09YorDAxzjNX/roZKvelncC3dy
         sZruYwu1h8Do0lRiEQbMSSQ1ABQwavMFkZydL+Z3tyKKfn3FeDXSHn7Hov+vKw0Z0tAV
         jqOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=e0eyr1fZZfk19rqeHQ1HRW6TIavT/IG/Eu+OzK4hYnk=;
        b=tld77awISXmsqWV26Ufcc4YlpBZR+KMFePGh7MGqlWdnW71PrCYz9QQHjGhnGd724z
         B01hQWQaYJOTcU3kLSnIXwUxMnFbhGo+yFmiCFjwIVXIYMj3zipEsy3crkhCiI13sSMm
         R9Tm7WrILiVSRPkwKfmDEkqtz15ZwzNd1CDu2Qnl4SdZzXGDfUqwVW0CWt6rnmvf02zs
         h7/rhJ+Q1Ma6Kj8058JCMrwDXbCuApRY4xUD2BGP6sBEl4ku+ve4frKrCybzK59Nu+CD
         +BD9dwkfdXDL0lM7PmQPVyd/pgPEC0hfPI43H/7ACsuw3ufTWEy2oRAh4TQFVAGyZhug
         ZOBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nFj+RhH5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0eyr1fZZfk19rqeHQ1HRW6TIavT/IG/Eu+OzK4hYnk=;
        b=d78NWpZ1BljaPUrYSFosdFSWzenYBUR7B6JEr27fT7MKfHLwSPJlc25e5dsuLD1fjT
         /BgMRuK/BCdn31ABNRICihRaZdnTdMAo1D3ZCS4ez0LUkLTKmQsu2v8AcDLn4c6A7fSE
         z5d4L/DqNWaC4WL0I0nd3CyMbfBcSKjclh/zwYASwmM0aZbvAwLtGmKt34QEn7Zg31KV
         wwuCLFMzF0kE/x8FckHF/XB8S3DcAuejBtibAiW27STyagU1lxLbiqzZg15lARuiNzVD
         vXh+Mk4lLL8/sO/aoF7iQoJa6z2vLezLulSxINVLdAo2agyvJ+zhP2YVHJnFR+NyD4y0
         ul4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0eyr1fZZfk19rqeHQ1HRW6TIavT/IG/Eu+OzK4hYnk=;
        b=dTO3TJHM/VJtzjQNx1uY7Pb5USSGmO6w9luz+S+Gat96elJo07nFYbSrxN57+EmRLM
         sOA6R0lauZqes9lPEvvvR6n9A93pKLrAGXOvknEpjnEaBBqB4k127j9Ir3sfyPJ0iCie
         aFE3OW3q2wpKqJcNA+Qpwn3h1tXkSmARnY3gy3uBzWx7XDuE59Dkb1w7VfBe+hVBx3gL
         DhaHRJ85OC4haxwRjsciA9mnrNpEn0RBH0+oui8+k64pDXlB7lNZNChZVNbG+7f/eIHd
         8GdM2+So7MCFfX1kCsmbhUWYhx7RUXJQy7ugCbxkzVdI6O3LWcZ8kUCGAb/qvT3rAP7i
         Ps1Q==
X-Gm-Message-State: AOAM531b2yutrxSFCzlLAgPdM8Lz5uo6KMcJVe0B7qbUUgiJfesmj76z
	UfPcCPzzwbDtiElVMYjU7/M=
X-Google-Smtp-Source: ABdhPJyqHN+Vs9wTtbDqPFLTmWFNOJVcq7jdeuKtX2UZIjJedKWc1M/a4LcU+LdTWjkZJM+P2qOgog==
X-Received: by 2002:a92:1943:: with SMTP id e3mr761915ilm.140.1603171218209;
        Mon, 19 Oct 2020 22:20:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:77d2:: with SMTP id s201ls183202ilc.11.gmail; Mon, 19
 Oct 2020 22:20:17 -0700 (PDT)
X-Received: by 2002:a05:6e02:13e8:: with SMTP id w8mr764612ilj.139.1603171217898;
        Mon, 19 Oct 2020 22:20:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603171217; cv=none;
        d=google.com; s=arc-20160816;
        b=WU56aVjT4l6OkvuU+5ZAfGlc6Sgl9+IviGqxLMBWn1vz5uy99qGP5rRRB/xbxhwgPD
         bKSsRliymq0eLLmTUhF470b65fbFLjwily+xhsawDO9uLKwdkkABw+8SlD7+T6tLOaJR
         UjVCm+w6xhzv47nlPpQQKp8ZOFU+PXb42ssEDUW41nfHLyEzEpBlY8P72ymG3UKBSG9K
         aIu34eF+ZjlwzR6SI8mX9Y0Bo6VGgZWxjvnkarOoIf1+x/u59rQCyIincV8FRd1PdqbQ
         2rKLIs0NuZfPiVkWdDBvzdfmSDoPcWwSBs0wmVLGL4xdWGhYnA5q/Jp2hsIkdPpPnyQg
         +TcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z9wYYqXSCH9hJsvZCRRfPmiplKII60fDiq3y/0UOTRQ=;
        b=CXQ1ui6ZNOdCl4zIn9CCu2VN/0YgkKIUpDiF/XTDxJ1uN63ETWY0mkqstyYC9W5jVC
         DcL4bVR7Z3OQMYf7x86DBLfWQ841OcJg1kFXqLuFhxarPbgEYp+u4s4LlpmHrJPxvnoD
         +huGv/dl0Oovuz81XG39iKzV4qTxJxLCR2JxmpTk8J8RwwD5JPNvu1IGJD2UjbxjlKrP
         zun7x+0WHowNcZ9Bqo77unMPwiTkFLoelrq2+2t1nE4qUHhA8gC83vZUq/rWARRuObuS
         BgmGwncQffh9J20pna9u48X/y11RItMvjZlOyiR37GonKHIvdcpdlv+S2suECkUNAC31
         O37g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nFj+RhH5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id o19si51996ilt.2.2020.10.19.22.20.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 22:20:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id x20so582047qkn.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 22:20:17 -0700 (PDT)
X-Received: by 2002:a37:9301:: with SMTP id v1mr1244436qkd.350.1603171216987;
 Mon, 19 Oct 2020 22:20:16 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <CANpmjNN3Ax2_CfxXixh8-NipXOx7s8vprg23ua-M_tvUKZGq0Q@mail.gmail.com>
In-Reply-To: <CANpmjNN3Ax2_CfxXixh8-NipXOx7s8vprg23ua-M_tvUKZGq0Q@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Oct 2020 07:20:05 +0200
Message-ID: <CACT4Y+a=twL5eKnpZE18g4j57+PEYMPC0Loyx_mepn4u+hJTxg@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Serban Constantinescu <serbanc@google.com>, Kostya Serebryany <kcc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nFj+RhH5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Oct 19, 2020 at 2:23 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 14 Oct 2020 at 22:44, Andrey Konovalov <andreyknvl@google.com> wrote:
> [...]
> > A question to KASAN maintainers: what would be the best way to support the
> > "off" mode? I see two potential approaches: add a check into each kasan
> > callback (easier to implement, but we still call kasan callbacks, even
> > though they immediately return), or add inline header wrappers that do the
> > same.
>
> This is tricky, because we don't know how bad the performance will be
> if we keep them as calls. We'd have to understand the performance
> impact of keeping them as calls, and if the performance impact is
> acceptable or not.
>
> Without understanding the performance impact, the only viable option I
> see is to add __always_inline kasan_foo() wrappers, which use the
> static branch to guard calls to __kasan_foo().

This sounds reasonable to me.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba%3DtwL5eKnpZE18g4j57%2BPEYMPC0Loyx_mepn4u%2BhJTxg%40mail.gmail.com.
