Return-Path: <kasan-dev+bncBDW2JDUY5AORB2NX2SEAMGQEOXH6ZHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 492E23EA50D
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 15:02:34 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id e13-20020a05651c112db02901b29ccfa84fsf1942114ljo.22
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 06:02:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628773353; cv=pass;
        d=google.com; s=arc-20160816;
        b=sP6k6WN4RbYDho8p9iQ/RH+SVvAHXII35M0o6cy+yloogkJH9YkZQqCkfvTDuNYasq
         4mCzcVMPowdx3sA9sR3e9mgRPIK2LynZFQnpoGUl9kKgp+2eydFFi/zYhCZgAWgjmexp
         Ym/k0ttW3pIjED26JdwgPuWZA7pkNlQYqsR0F7JLVmmA0Bg4ZzxPk/bV2+gdrX4Ylf7N
         Ib3LnKltBLwDK5IWGLhz/gIVsq1W/tCbpRYx7F1XEzSwCB/JlwXPa3Qp5AExkeMI4bJM
         hVy+P6SgFiHq1lxB7HLe1VtZfsJjqF2OCP9oipoRnzC93oo3LAN5IubhifVuIVdnBzto
         uLpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=+4SvMzE0W6rqhSzehFKze+/wJM4gz2TDIRexCNpNCKk=;
        b=uvu2sz0JEbBTgH4HuVrKCcLqR3JvEAH288EWa4kkPBOcP9PDDbXuW1oztxpjKDVFRz
         8qqC8B9pzroDslZog1W9GfcHMVp9kiW5XX0Cg9q5vwlfnPOJktiRAafuSrghDCgkJgE0
         d2wpO/e8o1JWJF89NaMKcCw8WTes1xk9F6FW+7NXL3WBFdlqdOLy0ouG1NCUPGwHXyga
         MsHUAzNx1IfuyegVkRLhB2fhmlBVWErnxwWx31D2avoJFE/YgdKYDboDZxmZ5JQfDa/x
         yBcIjs0VGi/dRKFwm/xBziY9AnP71e0I8Mk2S82h9vJNRqUNon/G8P7P5fQqSvr8kxAO
         fQQQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=AyScEMSO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+4SvMzE0W6rqhSzehFKze+/wJM4gz2TDIRexCNpNCKk=;
        b=bdqYKReDJgv1RqMFjeWNVbhk2Lb4vOq0AgeABbFShFguFrldMOfgt2daEx3SdCnLfX
         H1LauM8KT7wylvGVUMUvvQgVyuyF7vYx8MSA9nqca/C1xQ+nCHqN+LR86K7E6qoVWXm2
         qcJOmnT6ua/Gh6P6OmXGWO9JKmle/ncTSQzwkSuVorIWeHqYgqkXPKB4kbvxICQPtPG5
         ytO7NHF/JURZn969Mntd1t+RlG0zhBuNmH+iPF/TM9WfjHdvNTew9ee/ZGsXA4JUrFA4
         c7fNXRn99V14xv2fXc5/y5+970vWO8+xUW9jhcTrl5KJ6EOEBkdluaDi8bg5y6kx8sS0
         5RSw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+4SvMzE0W6rqhSzehFKze+/wJM4gz2TDIRexCNpNCKk=;
        b=qQQoEpFX+IknPkxOvCrhhN/yeNDTJvfumW0JB8Mj/iFuig+12aUM1ScPhMUFNHmt1d
         UZ0EVU4Pu9zVrl7a/wPjxJx5a4cOk/pXkBy9hioFuGwEE3YVdRW3hPm/ME9XRDDzwCBh
         wHNSQbc4Exa0PR7T51wAU+Up8MNIJO8ub1EuGYMAUiBpJT+AAUmrpQC+fHDyqbPmE+kh
         YRnkdMeGZmPwlUX+lSLuqjCSP6OdvWpZy7BR/Sc26zCWHbFHIMqRAHVd7zlMYjT8LwUW
         Uc2pUhsieQW7kzXqbLiX3GgGtQhLpmWQW6wd+zRZ42iHIGwx3luwwBKGLVqrK32OnDvn
         QFBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+4SvMzE0W6rqhSzehFKze+/wJM4gz2TDIRexCNpNCKk=;
        b=pUESaCjP9qo2jnvwad3W+sGaAzgoyVnp9Svuo5Qd1Iqr/kMVD7cO4pr80APRVwnXyO
         z2wNOyRoxCZ1Mm/BOLwTAkqgwlZ7wv3GhsscOmmxpTRcYX4CEZ6Z8kTaycdB5X3U+GpI
         qkVsKtt+wjiWuD68DHf3VePFb0zU7VobZdPf2M+qpbn8NFe0Ua0xsNluG414rbsnwp7i
         4qMmtjqc3xh9LwPykKdIG/H3jDM2Waqjle4qZn5pnZHlrnCAlI4MbtREj7GG80c9xW7U
         EwSEboTndGIrQvwGflb8qVFumXKiVybQx5KnYYRmLXmr+ADwOiOwo1EgsSo1AnwJGwIo
         gZ0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SXZGPvPY3c7pH5nVrp0+UjvJd0Jrh5agwIxAcAbghDViEJ+eW
	0vL/Nph4gvutuGXOuhvMJ0M=
X-Google-Smtp-Source: ABdhPJwZaH3WW5oQg6+JCItHzvRlqvqpVhV16sZr/UhjSfqY7PReXskVxLCbqTRdnWiFvPWsTaalDw==
X-Received: by 2002:a05:651c:891:: with SMTP id d17mr2837348ljq.24.1628773353729;
        Thu, 12 Aug 2021 06:02:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:691e:: with SMTP id e30ls451079lfc.0.gmail; Thu, 12 Aug
 2021 06:02:32 -0700 (PDT)
X-Received: by 2002:a19:48cb:: with SMTP id v194mr2476803lfa.332.1628773352580;
        Thu, 12 Aug 2021 06:02:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628773352; cv=none;
        d=google.com; s=arc-20160816;
        b=tU3aBRpV9XJ2dLzLuOSAphR/9vmVneMgIDl+4f4KfcrX7RY5hDP6ZZRTsbz3bfUcDj
         cHqm2eC4lFjtKsVcyQHCovyxjyjqo53hh3Oyz/QASbNf1F3vLLIk/ZEtOlnxuZfe3yKx
         0Sty2WOFBYIiIuHuzJOwawCupkJCa10qsBoUsobl3P9qnfvfR/BdTMq/KJz5J+BEi0T4
         zYvc8TByGmgseVL6NDZhR3WNiKE/PJt9lJ+39l71zkPHyCHoj1OMLeDvG2OsDM2qyjoM
         kVr/6FqiSAa3d/AxLxlTwVBz3vpS7yUg/yyj9PfFX7hLe/O8wSJzDj1Eeaozw4RF5zwZ
         q68g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A7pHKxayGFMZlOwIq/bHkeKVOMFNUJ88V3SLok4nSRM=;
        b=LiOLR5bJkEtsSzfvDp0B0UIvd1i9rVvJnR0fqoeesUQWqicPtdaoOLp2Ev7Js/Fjil
         BJ13SckkymaUjVrdDNrOODEZ0VCKMAxiUlrZ/mxwy3r1ACP80hZVydLk8MRKotKNR/IG
         8Gw8y463riWZVYZAAbVg1lz9Jh/qyqEcvrQD+4bT9IW+K5g9ayXwdMdL9l18NpXmHJkP
         n0NGuXwhdrb3/B/Dhw5it5IPpIAokMcdhZ9S3x/+FnEdkaBXY56TNIG3whRnuziz6yg1
         7Rj2PHevJz1G6WNVrl+uPR6bgarZV6/RlxyDepDxTQf4fGTNVTe79p/DGCpiebp1PttA
         MKBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=AyScEMSO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id q8si171393ljm.2.2021.08.12.06.02.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 06:02:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id go31so11380101ejc.6
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 06:02:31 -0700 (PDT)
X-Received: by 2002:a17:906:53d3:: with SMTP id p19mr3522667ejo.509.1628773351053;
 Thu, 12 Aug 2021 06:02:31 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <c3cd2a383e757e27dd9131635fc7d09a48a49cf9.1628709663.git.andreyknvl@gmail.com>
 <CANpmjNM6hn8UrozaptUacuNJ7EtsprDJWDmOk-F6BaNZ6Hgchg@mail.gmail.com>
In-Reply-To: <CANpmjNM6hn8UrozaptUacuNJ7EtsprDJWDmOk-F6BaNZ6Hgchg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 12 Aug 2021 15:02:20 +0200
Message-ID: <CA+fCnZfGagaxUkrr5FxaQwTVr+C5OpmahPgiwCuXeZkp2nNOkg@mail.gmail.com>
Subject: Re: [PATCH 2/8] kasan: test: avoid writing invalid memory
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=AyScEMSO;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Aug 12, 2021 at 10:57 AM Marco Elver <elver@google.com> wrote:
>
> On Wed, 11 Aug 2021 at 21:21, <andrey.konovalov@linux.dev> wrote:
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > Multiple KASAN tests do writes past the allocated objects or writes to
> > freed memory. Turn these writes into reads to avoid corrupting memory.
> > Otherwise, these tests might lead to crashes with the HW_TAGS mode, as it
> > neither uses quarantine nor redzones.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> although if you need a write primitive somewhere that doesn't corrupt
> memory, you could use atomic_add() or atomic_or() of 0. Although
> technically that's a read-modify-write.

Interesting idea. I'd say let's keep the volatile reads for now, and
change them if we encounter any problem with those.

> For generic mode one issue is
> that these are explicitly instrumented and not through the compiler,
> which is only a problem if you're testing the compiler emits the right
> instrumentation.

On a related point, it seems we have no KASAN tests to check atomic operations.

Filed https://bugzilla.kernel.org/show_bug.cgi?id=214055 for this.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfGagaxUkrr5FxaQwTVr%2BC5OpmahPgiwCuXeZkp2nNOkg%40mail.gmail.com.
