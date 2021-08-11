Return-Path: <kasan-dev+bncBDR4DG4XUQGRBP5OZSEAMGQEAQH4R4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id F3FBA3E8725
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 02:18:07 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id m14-20020a0565120a8eb02903bcfae1e320sf234682lfu.19
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 17:18:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628641087; cv=pass;
        d=google.com; s=arc-20160816;
        b=YDX/ttltReIV+zBeQk9G/raouiF3DT9Fwdvsnx+s8RDYJ2575RGYNCMHp1jhlUXLMG
         UckvVIWJuBPj4dG30t5yC4weg5Ky+FjEIiO4yFv44QLY2+Ui4jgE8W2a5KUEkpFEfq1T
         qzjgzU23Ybda+pv6M1OWCDW+3wArk98GEDtnarRdLurwfpQE9Kb+cyg/I0S4b4Zzddq3
         DdYvjL+jMjFV1hfqpCqeaSo1qtBYa1f7U3x2Fw57+SEAeFzn0LDiqC2K3z/qY7mcydP+
         MRHohIPtfpNzlV0A6zSCuAmjZLjli1nwa0gS1rc4HsE8So/GlrG8qtcZR15PpG5xgA1M
         0kRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NZN2UebGn/hrSPQG7EnWFktmmpAIWf4MLKtvYhB5IFM=;
        b=tGocE8YEKvilp0NCaGKPwFICtu2dCqeoVZRqslvhba+pvAgxP9Id+fqmRjNRCM6qcL
         ImwltD9iZxWrtsgn2wV9iwytYrX8y8u4ggBQxX67YgPkM9xpMw0Q8pTBD8MZgHEdhS/u
         IHdnbAr3RsgEHLsXnZsP6OZ0+WO/1SS1k/nOCxV1zqyH2mVfJ2rzmEnsEtDEjsniNJi+
         72i0bfdYOAGEKGvsIaJhsdkUIyAAcGsrI+L0JoqsjnYGyGFeeWQWcVRi7rLU07fhjTzh
         BIQ+qUVqEgXZBQTS7XhInmcxqsFETQWvuCJenxa3QG1sXrOx0b55FF+JeIbvZFi1X9jq
         Yo0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KjMIw7uH;
       spf=pass (google.com: domain of shakeelb@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=shakeelb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NZN2UebGn/hrSPQG7EnWFktmmpAIWf4MLKtvYhB5IFM=;
        b=mhFPTfppjmxFbeVU1Qqd3JrheimJOnMcWWPaZ24fj9gMnACstDzY7RbRSRbuBJcC5X
         MBcFKz7IFS9WwZWv5Y8uZ3VxbsoK0pP8WBGW7vsdDpanQAB+LuPkZeaatNr9ey7VJAAy
         sBZgepB/HAVObDQXYmBorPQ1mjHWIXhyKLFGPsfLyVBRcv2P7U1qX9z3eHf+KpQX2Occ
         wwOuwNLu/G0UmP1D8F0t9Xd5bP3sTnMaQXJgRa+FheY4ZYV9X2r27rsgoujBVS4vNiKC
         JgOWrxqnZ10dJYajUyfHoFaTJadlbqtQy0r4tA2vDEPCuz2x6912itrQM/AogdKk8CV/
         fooQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NZN2UebGn/hrSPQG7EnWFktmmpAIWf4MLKtvYhB5IFM=;
        b=d4S+g46Opxb7aNX5lfgSSQD9wzM8mZG4+Hi6xNU5tr80Md1ezxght4M4E1E6caopG3
         IaKqQBIvGJbgiFIIUsjt1BmFRAwZ1cDVlmVDJiZPG8Hu4CpbuYwoi4pv5r3PGHiZGMUZ
         jegJyHmKpmH2wALXH+MD0VZcP7euf0wholy+5muCfqc6g3jGorUWUJibhFuhpNip9h55
         9myZY6NOIzMvrKqv95fps7GvWb0N2VBJidMjwoXgGaqv62EGP59rZvc7d2JJOGuxkbNe
         iN2Clzzduc5f0hEtA8xRpf6tA7BsxaTaNvAbASjJJoUF+IiZVES4B2w0e8dtokU/Trt7
         SDLw==
X-Gm-Message-State: AOAM531SmDGJaBAUTu+NIEU1uKqtX79ehVQqxLMOmfCcyPiUVp4XgO4r
	NELSD/X4uxVGrZqaAgEHgOk=
X-Google-Smtp-Source: ABdhPJym1OoEuTqrVF1G04s0CE0TyZSE1orwCRJQYNFt+m13sMHEHx+a3Q20qrsAR5GHmM/uuxWmLg==
X-Received: by 2002:ac2:5147:: with SMTP id q7mr23752784lfd.283.1628641087545;
        Tue, 10 Aug 2021 17:18:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f02:: with SMTP id y2ls450462lfa.3.gmail; Tue, 10
 Aug 2021 17:18:06 -0700 (PDT)
X-Received: by 2002:a05:6512:3486:: with SMTP id v6mr23727358lfr.535.1628641086434;
        Tue, 10 Aug 2021 17:18:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628641086; cv=none;
        d=google.com; s=arc-20160816;
        b=Fo2LQ9eFinKuxejee4ANWbK+aEUPLXR0napVAg6YHr8dg43NHwYBW+0ko8jaT/sf7R
         OfEl6QB1UhZzl4w4tk0KotCw9BMSB0jvEKdTNL7HfR9hVx7/w5hyn+uSCBcy6fDyoiIN
         sbj2SOuW2HnN/HWELFgO7uxpLas2Z4fO1Gl9kgUU4EIzfGeGkIlGyqfh6eoa23d6qTY0
         A8jZ3IJAsLfWxnsMasEhWbHsJqE5NaH69ThpaQ52z3w4zCrpeTCyectTGLoGaDPddxo4
         wzYOHTomf4lDYtjfZ5smZRIX4cVeMj3zvaP7gWPPbzYqMu0Mruy041BvxVW2rY5Z3NBF
         IhjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KkFE6Z56Mr1EKMwPtDhJ4HsMjjvC1ODc/Bi7DtZL3y4=;
        b=uSUriJLmOfusiTcjnXt5mUMv6lqbpflVjCHVlpsjOilLoNA/WAuGk04nV0FyWfGbAj
         EtkOHFIiX4H4ubgqMZjn3oHzjjeNZ8C+UVZYOWSrsgyEq6rSv1oMrDebBsFBi0Q3lMRM
         ss8b+gppyZOCJErKXtQEF6EL0HOW+Fu1nFO3DmYiTtK3hHwTxdws06Pu61DWqlaT2Ge9
         pbZY4JrOvleSxc29ePb+uzzzlnhNXxIgMFRghnJpUo8vixX7vlzTvEVVDhDVvMK/TJCj
         X1169E61KtD5ZIXvPMTBHMrMgMMIV0ZlWW4BtwEQlqpEOp7kYa2mQXUxBVHD8Yax8jVE
         3WZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KjMIw7uH;
       spf=pass (google.com: domain of shakeelb@google.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=shakeelb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id g5si917726lfj.3.2021.08.10.17.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Aug 2021 17:18:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of shakeelb@google.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id t9so1648101lfc.6
        for <kasan-dev@googlegroups.com>; Tue, 10 Aug 2021 17:18:06 -0700 (PDT)
X-Received: by 2002:ac2:57cd:: with SMTP id k13mr24099569lfo.117.1628641086038;
 Tue, 10 Aug 2021 17:18:06 -0700 (PDT)
MIME-Version: 1.0
References: <ef00ee9e0cf2b8fbcdf639d5038c373b69c0e1e1.1628639145.git.andreyknvl@gmail.com>
In-Reply-To: <ef00ee9e0cf2b8fbcdf639d5038c373b69c0e1e1.1628639145.git.andreyknvl@gmail.com>
From: "'Shakeel Butt' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Aug 2021 17:17:53 -0700
Message-ID: <CALvZod6d=Ri1K-cZMi_6MXuDnoRPdz5mCPN6DXRB8YyotV6d2w@mail.gmail.com>
Subject: Re: [PATCH] mm/slub, kasan: fix checking page_alloc allocations on free
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev@googlegroups.com, Linux MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: shakeelb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KjMIw7uH;       spf=pass
 (google.com: domain of shakeelb@google.com designates 2a00:1450:4864:20::12d
 as permitted sender) smtp.mailfrom=shakeelb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Shakeel Butt <shakeelb@google.com>
Reply-To: Shakeel Butt <shakeelb@google.com>
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

On Tue, Aug 10, 2021 at 4:47 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> A fix for stat counters f227f0faf63b ("slub: fix unreclaimable slab stat
> for bulk free") used page_address(page) as kfree_hook() argument instead
> of object. While the change is technically correct, it breaks KASAN's
> ability to detect improper (unaligned) pointers passed to kfree() and
> causes the kmalloc_pagealloc_invalid_free test to fail.
>
> This patch changes free_nonslab_page() to pass object to kfree_hook()
> instead of page_address(page) as it was before the fix.
>
> Fixed: f227f0faf63b ("slub: fix unreclaimable slab stat for bulk free")
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

The fix is already in the mm tree:
https://lkml.kernel.org/r/20210802180819.1110165-1-shakeelb@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALvZod6d%3DRi1K-cZMi_6MXuDnoRPdz5mCPN6DXRB8YyotV6d2w%40mail.gmail.com.
