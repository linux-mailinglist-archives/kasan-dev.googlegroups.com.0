Return-Path: <kasan-dev+bncBDW2JDUY5AORBPNZZSEAMGQE4HZSVNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 59F883E874E
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 02:41:34 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id nb40-20020a1709071ca8b02905992266c319sf67429ejc.21
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 17:41:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628642494; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tyop8wvGWmRKY4lbOdxmZkeyDmCPjU9HH1hSOzj1P9nRFo8aqve6XnZJilY0USrbFz
         3TADXkSjHyoYbZlaBxjMnO2PbwN70Q533zp+xdI6sUSX5iU5BSI9d3NoH5RNZ3gFxS8i
         x2n6mykIG9Woq8Dn/zQU57oboGltiVNh+65HJaVtUvkzSV9vsU6SJqBbXvCMaPLUt0MR
         /kPml2z0jfCs63Qu7IHIUrlOXzAg6DP2yB5w8rBMSdqHcnGVneLmU9OSGWJiXEm6CsU0
         agYxfJEwB5yCJzdPaY/DqFYOPDC0BhyKjBsmBkxCCUfV7Hs+qxZrvz1MaTNHcgFx015W
         1ekA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Xii09QodZJzGvjoas/xUleFkiuI/DZd/42OhTqvMBu8=;
        b=csSri99EtNNhDCCD3mGqj5z6Gs42522lOXplo0p/1X+5Ej6Yd5v5wgkcww8TwDqI8j
         tjId/pZ/M+wyppuIGTSIx3tmOTasvMLzRoJfc88+rh7wribPoF/z2vbSHbR/wQvw2vZl
         P32UI/6E2P2M6InN7tGpdYqzXyA6UJswZuiiB6SQgYfDVNdwTRDVVm5kybeyX9jpvsul
         NCbehO94LOom90H4ifE9UnurEYRj7IKyFIWbFSo1SZJ+NDH56RRMNoyGnryHIETbhi2o
         5vOcO5sWRnK7BDWS74tCDxZ8K7WEKMC2Ob0XvMMjQqnwNSDn6fEJnuB7nFsSZbF6kzO2
         jy0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VpErF9Be;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xii09QodZJzGvjoas/xUleFkiuI/DZd/42OhTqvMBu8=;
        b=gx7vz8lYiDz+q5Od0jKgMiVbWlTu7phMMaQtgzJZUjRZH3+47N57AMDjWeeNz8gh7V
         IqBuKmOiyW9KX83bvHYyJNOu5nG9O43T+Wx7EIRk9HmKwHWrUqYHS2KeXhZEjprudZFT
         ZvSIGBD8VRidf1XDiQf3bDOyRAildy3LqWlLdkBNA/9pEsbcUiJ6AAxYqHljzHBuuoZ4
         Sd9ms8wK8L/S/C3KN8bDqZn4ZtbwuSFLPr47T3V2qRtek1BbE/aMf3tHCrb7rcoGw5rG
         Y/vjrOXcA+fCX5r1FBQDWDM0SP8HW19TPLndR7rqSJGL4a4T/HobyUDpx2W07bKo+AWa
         Fn8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xii09QodZJzGvjoas/xUleFkiuI/DZd/42OhTqvMBu8=;
        b=N5AoHxZ3XSVOL1ZaIOInhE0e3yHjSo6ocNokhbl4zDf3tWANqF/HTKOUO3Ui4ok045
         eWtdy1jXks4yPiGIs6NUq23B+ABq1/ZzyhpRk2xtlUQg4mBGg//aluqjU65rchgxJUc8
         44MghoojWvalt92fbRLnTJqgwl0QbFfrB2xeBzweDMSXo/JlszvtCrQSUUhj6MHcFXoV
         YdlF4EeqmbsZdMzyqb2XCdzVXCfyfWAw5TBW4Isgp1QIkOR1i5abetHIVCUsdo7kC2rE
         slkmxxGxYyUORZq2KfRUjA7XOzmLS61TlklJPUPECM0EujK92makurvdahHyLxjE6Az4
         9R5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xii09QodZJzGvjoas/xUleFkiuI/DZd/42OhTqvMBu8=;
        b=VdXYb2gfaXmEHmh9lfs+hbxL+IFZKkaPPwhHfYKuaILFZ0KcpiUFIgHqFj30G7KtSW
         Zc50CuCjG1HInRcoIO3DL4y7dhfUMzu1dqsZLUfyfV89/8Pj/ixhih+S+Fysy7wZp677
         p7M0F/k6hDMqrbCoTIjYfQzNXyfaCiHkozarf5k8xgtSlhKD2MUeELUsjJ9teZCNb/Eo
         bWUb41nIrCU+27zfZoMgN/YUi00Plw2iV9HQO9hSprgygmaA0rjf6UHFIx3poHY75TfJ
         UDJjIYN0Uj6K+4pem0z235h9OQVLV3EjlV9ihhiWU6YxMxewcgY39han9yGxsQ4SzTNn
         o7WQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xnzIOfQb4tz8/8P/Bz3XzzwB0n9fikXlAE4a/Cuo/dXSlE7k0
	+h+eBr/8jyyrxXLeyvGiELQ=
X-Google-Smtp-Source: ABdhPJxfJJ/g4SRTPq4x5iFSxP6vGf+1mlTmEUEn5uAQhsTnG2PJDGBqWvxDQLQVLtYB1gphmeynYg==
X-Received: by 2002:a17:906:fb91:: with SMTP id lr17mr1105614ejb.110.1628642494103;
        Tue, 10 Aug 2021 17:41:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:46d8:: with SMTP id k24ls224051ejs.5.gmail; Tue, 10
 Aug 2021 17:41:33 -0700 (PDT)
X-Received: by 2002:a17:906:ecf1:: with SMTP id qt17mr1044689ejb.339.1628642493205;
        Tue, 10 Aug 2021 17:41:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628642493; cv=none;
        d=google.com; s=arc-20160816;
        b=uFhUUgR36nSpaMzOko2BJurNiuFuaLxIFNjxqeOHqQmIix/Jl0T2WiiU7NxVoPGp8P
         /FvK1+1i8Rwl7goBBb8MMlOJtbWD619/a7GF0ejrk9P2+6R0XxOIzF77SNBEDk6nS8wb
         0zFoMzrt1ncOb3jQ+lFvHlSOgtEFrQLsWY15/1kDzcg2QNc5AKVRU4qm6sivXO7DLPBZ
         FNuHK3Fno7qKIAa+8Ed2lzU+0t9s0t962D7y13vbK0aqJJAVDIYVkl8E+j37YlUjLDVQ
         6SFmD/S1L0brCC9yj+uV9Agif0/d0viwfddN/Pb+GAvTV6rDocuw6e3b28z599O4HEbf
         15EA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+IKe5IV7lT/U5uUeCk8dwVAQVUVWQi0SX4MD0PFARrk=;
        b=vb0cDYiucg8fPLKrSlQZuOwabvibMRdd+YQFZkmIa9Qdw64GpoZcvZDyzpY3/yWQer
         yZh/crP0TmwfUOm83WitpZccLW7yfV5fRRFaemjHWLBGBtGU3d2HAlH3ojLj+vgZAkyV
         xnlgsjAcL5ht9R2GciI+a6EOLXuod+vMCoRF4bOHrAPLTt5X/GKnU17L4W7WiqbvI8mM
         kxToA5Hwy0wY6luJRjz2kir4oUUX4OmnK4N4vRSSJkSoc/ZZa7ZGw14UjvL0z9uawx9+
         Zk6tCmdBi+ldqCwAR2EzZ58qcGO4g7aYstEoJnLmy4I+Z4dCb35oeFmfhsAsT0lVaIMt
         K2/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VpErF9Be;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x632.google.com (mail-ej1-x632.google.com. [2a00:1450:4864:20::632])
        by gmr-mx.google.com with ESMTPS id w12si1526194edj.5.2021.08.10.17.41.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Aug 2021 17:41:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632 as permitted sender) client-ip=2a00:1450:4864:20::632;
Received: by mail-ej1-x632.google.com with SMTP id qk33so653251ejc.12
        for <kasan-dev@googlegroups.com>; Tue, 10 Aug 2021 17:41:33 -0700 (PDT)
X-Received: by 2002:a17:906:d147:: with SMTP id br7mr1138362ejb.126.1628642493014;
 Tue, 10 Aug 2021 17:41:33 -0700 (PDT)
MIME-Version: 1.0
References: <ef00ee9e0cf2b8fbcdf639d5038c373b69c0e1e1.1628639145.git.andreyknvl@gmail.com>
 <CALvZod6d=Ri1K-cZMi_6MXuDnoRPdz5mCPN6DXRB8YyotV6d2w@mail.gmail.com>
In-Reply-To: <CALvZod6d=Ri1K-cZMi_6MXuDnoRPdz5mCPN6DXRB8YyotV6d2w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 11 Aug 2021 02:41:22 +0200
Message-ID: <CA+fCnZcQEEkpe+OtCYfWZb1nzov0FChQgTF3yuK6=M5bN_YLWA@mail.gmail.com>
Subject: Re: [PATCH] mm/slub, kasan: fix checking page_alloc allocations on free
To: Shakeel Butt <shakeelb@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=VpErF9Be;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::632
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

On Wed, Aug 11, 2021 at 2:18 AM Shakeel Butt <shakeelb@google.com> wrote:
>
> On Tue, Aug 10, 2021 at 4:47 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > A fix for stat counters f227f0faf63b ("slub: fix unreclaimable slab stat
> > for bulk free") used page_address(page) as kfree_hook() argument instead
> > of object. While the change is technically correct, it breaks KASAN's
> > ability to detect improper (unaligned) pointers passed to kfree() and
> > causes the kmalloc_pagealloc_invalid_free test to fail.
> >
> > This patch changes free_nonslab_page() to pass object to kfree_hook()
> > instead of page_address(page) as it was before the fix.
> >
> > Fixed: f227f0faf63b ("slub: fix unreclaimable slab stat for bulk free")
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
>
> The fix is already in the mm tree:
> https://lkml.kernel.org/r/20210802180819.1110165-1-shakeelb@google.com

Ah, I missed this.

Please CC kasan-dev for KASAN-related fixes.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcQEEkpe%2BOtCYfWZb1nzov0FChQgTF3yuK6%3DM5bN_YLWA%40mail.gmail.com.
