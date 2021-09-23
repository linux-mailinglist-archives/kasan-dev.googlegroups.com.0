Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEWDWKFAMGQEMMWISCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 13AFB416253
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 17:47:32 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id w187-20020aca30c4000000b002739938efdesf3762721oiw.21
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 08:47:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632412051; cv=pass;
        d=google.com; s=arc-20160816;
        b=hifxV6ClLDFC5Z3Ak4mmiYKNbVkzumoTBPXDkHTJXr3dJCTQeY1ozKm9ZID00J0h7S
         yKfJw8ZzWav+hWaom8Z1oll/8tbfMUEEuoUcaTnJdiU887TmNxJW1H5KivxY/9pcIofr
         3wTUbIQCk4bNqB+vU87zVcDb3CjGxNcYfQzj5CMlEXH0Mq6zlzkOlFKrqn94DB12CRGq
         Gr6rCVc2v0NIv0s7sV2bXjvKedHs9QAMwK2lj8ROIM3hL2hs0Tg5jQvON79kCQin2aId
         ZmehlfPrsboTRTH2PI3xhqq+K3dj2usyUEHo8ZDghPMTh48+/ZfGoh7CJwJBkXb6CEwD
         lK5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TrSPfRd0JrAUXFIYpjaLEw91GgRNSSTvErhpCIjydDo=;
        b=qURACVlwu7UDIjWRbmZJM581HFhlzD2BL/sUl8XZe1KNErE6ajhEgVNkrAXH58gnM/
         cyGoGZuoy5KUuDSnOHiJkjHQBae0VW0JuVAGz73zLFyR3YaI1C/d43k5QUF6MzwyvrIR
         yVCJDFGwg4eXArcz4MFLRqWYFEXmCcIMfeQwQorxBwqKQXOrz5c97syVGt76gnL7VmOJ
         yC06xwLfoC9VX/dyezjhMWPjxIiCFfJ+Vn18BiknrjZFz9+m1AfsqFwOtvqIsUTkbtwP
         tPFgPhgbuNuBy8BvuUN8Gja9uPTXUzxLeHh3Ru/odRznx8jHzM7aRRTK/C06jOVp2Wg3
         abvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mTZSIMO+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TrSPfRd0JrAUXFIYpjaLEw91GgRNSSTvErhpCIjydDo=;
        b=QAjwksuEcWP0PIQAa3eEObf19CQHMP5X/m9D1WnK3JWms6gun8Ramyi+jg+pH0Tf52
         ClcKc2vaOEIbjan6GeWL/DP5nkh8k6ptRGzL9C+BE5uB2Glhk3YzwLdEo8pCZzRUpKme
         fTr/MN/Oy1BtHMu1mrZf2NhbjLHeY4leTgKYFvMbwQIxpDywWsafEYfWc7+/f7VveweV
         HTrHG2B10C5Jgk1HYtDIksrNdzHkNRep/fZZSYNgtqv+6kdK4M+ZhBZDF23On8TvPUfC
         bKKE3hU0hd8CMRMcGk1ot51mWeVZL2n/h6HBWllb9miaBSAqA3cokFYi0iQ7/pxfhhyb
         lCTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TrSPfRd0JrAUXFIYpjaLEw91GgRNSSTvErhpCIjydDo=;
        b=7tkfMFnh65TgTo9b7wENMnlZjASFvhnx14Gfh4LG1U6mAeCphrQsNZH6nZu8366gGt
         dNbxRS66yPW6k7oK6oRdr6NKrmmyuNOA31zrMzRHukNp5Dl3bixTqwOL60Ngr9CLwNbm
         jH6IYQi8gT61FUol+yxq4QAIqcZK09vN71D+sHjfdoRVxDUabgARK35GvWe2yJRTcyut
         bFM5i4zv0SldIb2Ln3bqwJ2IsGo9ifj7pY+OEP/WEe58W1zO0zTHWLsg55VuaPPc+zBo
         lUChiV/PcP2r2O/1OvBcZBBhDIApnRyRev4CmH7KlEpPHomnoIDRqsNrS7bLZip7hNTl
         Lpuw==
X-Gm-Message-State: AOAM531nRwFa9zRj8wE0Y8PKRJyWl7tz1fwc+wkF8Jh61hT5tmrYZJ6Z
	rkb3wTFfUw+jttUjRRRCCTg=
X-Google-Smtp-Source: ABdhPJzHBuZCc3wRLQ1DKbv+FTeEgos1mG7/qaItGJ1rQgwbJd5kv5EFHTZ9o/bO/lwM+BmbZorD6w==
X-Received: by 2002:a05:6830:82b:: with SMTP id t11mr4869420ots.319.1632412050861;
        Thu, 23 Sep 2021 08:47:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4408:: with SMTP id q8ls1846150otv.7.gmail; Thu, 23
 Sep 2021 08:47:30 -0700 (PDT)
X-Received: by 2002:a05:6830:70b:: with SMTP id y11mr5054448ots.281.1632412050485;
        Thu, 23 Sep 2021 08:47:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632412050; cv=none;
        d=google.com; s=arc-20160816;
        b=x6AfuE/2xVvVdBoayIooizlBAt3z4IK+PX9HuTK/OfHzJZSn/3mws+RXEj3gaAGY5N
         ruwaZmdiXX1GhDFVyY5Quj8rtH4x1fopohvYCuVz99Ssv3WglEC274YYq49hGoVhm+7f
         ChZqstkWttZinbkY6/F/mRe6oC6fxqKVUN2LtP31Iu99JReE4zCYUTtu5DxuDx1HzmXE
         sdTVwL35KNDTpsUKGZdgz+QQUpzolTLUoTC6Q2lAFlDLsOYmqY5v3pYnmwPxF19oo5+q
         /XpjJV7DlA8FM2ff8+PQqGprGETGPglsYFcDokYdYOt0BMGnXBH1tqV22JOExKTGtsz8
         ptAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=mQ7J4946rPgf21nD+uOWBbdKEn3T7TjKfOLDKhMFyj8=;
        b=EuNaBqKMFDeI2hEn1jnajKVOtNSrE/Edblx5MSpsDZgBAStwwKlBE1W4lrjhmJzDtt
         nK7731QahqrgBWstzwJdBXJ027fmpKT2UWDHO9GDar/qfJI3NGkPZYdNsM3eARctZohO
         kxv+W1zGUn9cG+63/CWvfmhYxNRreTIyV9j2CoHi2i6YQIJFEuxOJ5Z2uEEKTl+W/qVq
         /xJnw1NcGxqlKZ93rFXa49ijBOrBTAZmnRvsvveYIePK8zIM90+Pws06zrRKm4k5g9tc
         izpqigAW6TAzNXhISiDl0+xHPXC3e7hyS6whpuG16WtuhC2Y+OnqkGzEwEUV09VMu8Iq
         s0SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mTZSIMO+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x834.google.com (mail-qt1-x834.google.com. [2607:f8b0:4864:20::834])
        by gmr-mx.google.com with ESMTPS id bj8si29047oib.1.2021.09.23.08.47.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 08:47:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as permitted sender) client-ip=2607:f8b0:4864:20::834;
Received: by mail-qt1-x834.google.com with SMTP id a13so6568169qtw.10
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 08:47:30 -0700 (PDT)
X-Received: by 2002:ac8:7482:: with SMTP id v2mr5389401qtq.235.1632412047701;
 Thu, 23 Sep 2021 08:47:27 -0700 (PDT)
MIME-Version: 1.0
References: <20210923104803.2620285-1-elver@google.com> <20210923104803.2620285-5-elver@google.com>
In-Reply-To: <20210923104803.2620285-5-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Sep 2021 17:46:51 +0200
Message-ID: <CAG_fn=XGFY4kWSzTa4kX4Y0CPOpvQfhBzgZFK184ZptzyC6-CA@mail.gmail.com>
Subject: Re: [PATCH v3 5/5] kfence: add note to documentation about skipping
 covered allocations
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Jann Horn <jannh@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mTZSIMO+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::834 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Sep 23, 2021 at 12:48 PM Marco Elver <elver@google.com> wrote:
>
> Add a note briefly mentioning the new policy about "skipping currently
> covered allocations if pool close to full." Since this has a notable
> impact on KFENCE's bug-detection ability on systems with large uptimes,
> it is worth pointing out the feature.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Alexander Potapenko <glider@google.com>

> ---
> v2:
> * Rewrite.
> ---
>  Documentation/dev-tools/kfence.rst | 11 +++++++++++
>  1 file changed, 11 insertions(+)
>
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools=
/kfence.rst
> index 0fbe3308bf37..d45f952986ae 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -269,6 +269,17 @@ tail of KFENCE's freelist, so that the least recentl=
y freed objects are reused
>  first, and the chances of detecting use-after-frees of recently freed ob=
jects
>  is increased.
>
> +If pool utilization reaches 75% (default) or above, to reduce the risk o=
f the
> +pool eventually being fully occupied by allocated objects yet ensure div=
erse
> +coverage of allocations, KFENCE limits currently covered allocations of =
the
> +same source from further filling up the pool. The "source" of an allocat=
ion is
> +based on its partial allocation stack trace. A side-effect is that this =
also
> +limits frequent long-lived allocations (e.g. pagecache) of the same sour=
ce
> +filling up the pool permanently, which is the most common risk for the p=
ool
> +becoming full and the sampled allocation rate dropping to zero. The thre=
shold
> +at which to start limiting currently covered allocations can be configur=
ed via
> +the boot parameter ``kfence.skip_covered_thresh`` (pool usage%).
> +
>  Interface
>  ---------
>
> --
> 2.33.0.464.g1972c5931b-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXGFY4kWSzTa4kX4Y0CPOpvQfhBzgZFK184ZptzyC6-CA%40mail.gmai=
l.com.
