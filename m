Return-Path: <kasan-dev+bncBDYNJBOFRECBBZOHX7YQKGQEUR3AIGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id CA42614B074
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 08:33:57 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id c16sf2420425lfm.10
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2020 23:33:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580196837; cv=pass;
        d=google.com; s=arc-20160816;
        b=F4YdaLjLkQsrr7NsAKjWjib+pDAozABq502odD42ARbmTDJ9joKEpFA7nbPL8B6s7/
         KvA0JEM1tVbR6h0kJynremQs4UDf5h4gEXf1Jj0KGo6NWMfK18+kzkTzb/zvVYEwNifp
         Y85H3jx4uSY1gz9nxunMWibTPi/j1ZqIP6dY7BvNz1DqqMPoxaryEpKSGfKZi55bHCZ+
         cumKiSfKjiOlLbxAOqUnlH6xsQhOpJId/dR9shHOp7m8+xj1kStMN2vLolu3tRRBK0cL
         nupEO1mduea7Z8B6jJw6WuYgiREcfUu09/PcbTEklf9xxAwfBlgd2jVRp0cvR5H+on4j
         NQTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=XHGVJkKEy+uABcAFXuKtRvOM8G6/9H/yn352mjxyd9I=;
        b=bkCAWyiIwNBbdzua1yon2oiNr2aI/XX3Gnj8UC/50c5imvTQ5ht+Rjr396drrFAX0Q
         fHjkBFFm5v1cSgVbqILRCtbemZiEy5je3T9YQj9vpicTrAepQhQmXbfuIz6jpIGNYZCT
         MVqL9MKANMXWVybusVVXO1wHiU9LWHTQwZWRSxjfynuwjwRjuuedlLjxtxH/VbhJZB63
         5SixL+SauaPh9tG1qsAwAEFIfsUFqBcWciVv59cYV6MpoLM4Bq9/ysLVy132TefwYUN7
         f+tV6IP+0uDheZjpSD6cvlnixAaNFV6uTeJkSO5xCNM9CnuRzx35bDy3MCCG3IdrUfIf
         aKKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=dwotw4Ka;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XHGVJkKEy+uABcAFXuKtRvOM8G6/9H/yn352mjxyd9I=;
        b=p4n5cLTLfHcI6cdAc71cXGYuH9d/bS9D+EvRt8DLF+b3k5lVMrX85IlkRojZUM/lXU
         PkBjB89jqoCble39rtvK4i2sr4+Q3znlrVEdmjbtPr5I30IzKy2rIGssv/AVajs1Jtx0
         U3OqTfkrHG6LlbJWb1wsXLvAeXi0nm1AB/fMoPsO1sfcSztm66hWelQbsPn4HJkPDOzQ
         EH5C67hhk3OJH+15fgx6CLaQasViLqa3hqKD3RE2dllMxTZAJd+Ax0ItfsqtcA9TewP3
         6mlAWkQ3VaTn3u5SywmmyhMg7bozm68y9qM8zGgUcU023TJmAlTyjlx/PvVtOJGCruKr
         +9BQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XHGVJkKEy+uABcAFXuKtRvOM8G6/9H/yn352mjxyd9I=;
        b=Kk19/lg696HTi3ySxfB1i4XhdKZTla7RxUOGu4ZItVS8oFVI4/NNrl2QayxEzq/fSz
         2fzwMqCs6gvXKAOp0NOPIPXH3cHTYACYzRs2WqF45ti7foO3S2hDoSotwOVUu9lxEcrZ
         aBGROimv04+p5JbJcXGh72VFcHSmW2x+twZFBMtQyf++deM+auvrGkUz347btXuHKuw1
         DBLCSKjuf1jEAeeDu3SZPypl34UkcypvXApmdxElpPZjO/crU4yDDV5UZPoSVW19JUPU
         iiaocaUbuqWZicHlZW9BmZnwwXxEO6hymUjRgW6Ev0mRnv6iYVsaAMczg7rTSaLFTZty
         p5OA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUi47roVZh8A3WwFuiROi5HumEq6SdRNJ22f/P47MuLPiEYcuhV
	g4wAoVyfXKLy/c/LoGKB1ts=
X-Google-Smtp-Source: APXvYqxn/unJilfVaC2rw8OxGCeWev6gbgAld7oWCZRl7pjDD/2ppTMNsw0gpnFHouEDfrAxoFlS7A==
X-Received: by 2002:a19:6d13:: with SMTP id i19mr1592760lfc.6.1580196837299;
        Mon, 27 Jan 2020 23:33:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b2:: with SMTP id v18ls1552538lfp.8.gmail; Mon, 27
 Jan 2020 23:33:56 -0800 (PST)
X-Received: by 2002:a19:c3ce:: with SMTP id t197mr1593446lff.174.1580196836710;
        Mon, 27 Jan 2020 23:33:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580196836; cv=none;
        d=google.com; s=arc-20160816;
        b=g44XaDOM+mu5qg+2tg8UJ+J/JtF9f9jbSd46PzUG4/ve9D1UdXZGqhdV1iMaxrkWbL
         U7tZq2mgENnOxrhGqPKMIM4Y1CRKrgX1Qt1z+fedCYZdbaKxVdPeP44/B31n6lk0mr2C
         NsjtUD1nq/b+if612HOF4UyqoILCnc2uh8mRGP6zFxPFogNhQrRfDw6o9ZQyKhCp+BVs
         K+h1tfS70wddyYFlTD0aRl01jD2uQS3+rEmt7dhlkcuPzOU+40acgp0bblcpUYGF5PXj
         zXUmIFdgtBjjuLxbCkEGHc6HgjLfEq60Y0bTObh0wEoY5Fa+Us9FTbRcFFX+2TgnUP+/
         Q6VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M8/h2bPEqPWeThJEypD1fDrIV3uZkJ0Spf9SsxFALTw=;
        b=kOTL/VCM0Vlv/OdyQEI7WkdM5rXgYbPeurAE/J3ypj2IKchncuCInLlvZZ3bbF6gbR
         dM1ZOB74b88WZIELlW1/rPMnEGtJNyfBIYnT5WMc3597OcIJt/vtvxcklv+Co5yzNQyX
         CnjBZmgdGBjv8MfYTwczc2D/j4dJ5Wej12Sg2uzIpt5kg8hwAEp0zk5RJ0xI1Jo6tjZ3
         T+FxQUfCWcOhf9A8vCIDh+w1JWTBHaN/CoAFNOETb5QYDWNn0xi3kzhqk+kJ/h5OBuDq
         v/QGQ46Y7oVDrDpXwL75dZe7GB5g01TEH37EDMNjCXFEXGe4mcWTiGGahpYj/zO+Ip0R
         TMyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=dwotw4Ka;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id b10si26083lfi.1.2020.01.27.23.33.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jan 2020 23:33:56 -0800 (PST)
Received-SPF: pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id q10so14758438wrm.11
        for <kasan-dev@googlegroups.com>; Mon, 27 Jan 2020 23:33:56 -0800 (PST)
X-Received: by 2002:a5d:65cf:: with SMTP id e15mr26280990wrw.126.1580196836110;
 Mon, 27 Jan 2020 23:33:56 -0800 (PST)
MIME-Version: 1.0
References: <CAKv+Gu8ZcO3jRMuMJL_eTmWtuzJ+=qEA9muuN5DpdpikFLwamg@mail.gmail.com>
 <E600649B-A8CA-48D3-AD86-A2BAAE0BCA25@lca.pw> <CACT4Y+a5q1dWrm+PhWH3uQRfLWZ0HOyHA6Er4V3bn9tk85TKYA@mail.gmail.com>
In-Reply-To: <CACT4Y+a5q1dWrm+PhWH3uQRfLWZ0HOyHA6Er4V3bn9tk85TKYA@mail.gmail.com>
From: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Date: Tue, 28 Jan 2020 08:33:45 +0100
Message-ID: <CAKv+Gu8ZRjqvQvOJ5JXpAQXyApMQNAFz7cRO9NSjq9u=WnjkTA@mail.gmail.com>
Subject: Re: mmotm 2020-01-23-21-12 uploaded (efi)
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Qian Cai <cai@lca.pw>, Randy Dunlap <rdunlap@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Brown <broonie@kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Michal Hocko <mhocko@suse.cz>, mm-commits@vger.kernel.org, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Ard Biesheuvel <ardb@kernel.org>, 
	linux-efi <linux-efi@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ard.biesheuvel@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=dwotw4Ka;       spf=pass
 (google.com: domain of ard.biesheuvel@linaro.org designates
 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Tue, 28 Jan 2020 at 07:26, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Jan 28, 2020 at 7:15 AM Qian Cai <cai@lca.pw> wrote:
> > > Should be fixed by
> > >
> > > https://lore.kernel.org/linux-efi/20200121093912.5246-1-ardb@kernel.org/
> >
> > Cc kasan-devel@
> >
> > If everyone has to disable KASAN for the whole subdirectories like this, I am worried about we are losing testing coverage fairly quickly. Is there a bug in compiler?
>
> My understanding is that this is invalid C code in the first place,
> no? It just happened to compile with some compilers, some options and
> probably only with high optimization level.

No, this is not true. The whole point of favoring IS_ENABLED(...) over
#ifdef ... has always been that the code remains visible to the
compiler, regardless of whether the option is selected or not, but
that it gets optimized away entirely. The linker errors prove that
there is dead code remaining in the object files, which means we can
no longer rely on IS_ENABLED() to work as intended.

> There is a known, simple fix that is used throughout the kernel -
> provide empty static inline stub, or put whole calls under ifdef.

No, sorry, that doesn't work for me. I think it is great that we have
diagnostic features that are as powerful as KASAN, but if they require
code changes beyond enable/disable, I am not going to rely on them.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu8ZRjqvQvOJ5JXpAQXyApMQNAFz7cRO9NSjq9u%3DWnjkTA%40mail.gmail.com.
