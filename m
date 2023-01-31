Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFGX4OPAMGQE3PKXYZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 680D7682A50
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:21:10 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id m15-20020a17090a34cf00b0022c8b9a0625sf3499902pjf.9
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 02:21:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675160469; cv=pass;
        d=google.com; s=arc-20160816;
        b=D6bJaEbBmUbnOe4St4eHtKkJ5PrKBNvpDyj26rwWkUbuyzF1R0KJJUIcr1Y8ctB4AH
         5CYr1OG9eWE7F/a2cVjAcdtY8zSnS9PXRaBIaCjGGwYIPndP8xeMkesrhAzot4gPQoHk
         CNdBqUJ1E5t/i+qB0IXG+U0jOXPuSY7qpRE9XM19+hyyHXbxuOYmALhQMosw+nRiM5+K
         mwkLYs/65e0n9teapPzb85xrqc1mPd320qZxbEHSSqiYrI4/GXoox0u7I1PMIkg7zeus
         Jb4YIiUtUToF2vc6Lfi4tb7S0iOyl2FjeJ6mSLUAmvyrZJ5r/ZEgIug4OJ+upufG6LcZ
         kBxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0lh6OIWXNnxO9+WxwqlfgJPPuiZYwan+casZFcfmL6A=;
        b=mN4YpguMkGoEGeYZYKLzUJaqo0vl8SXPGgvfr61dMY0q02cBAc9caaAjue+D+tokb/
         TmaCcxExmEA4qHipkIClKYuijxh6WX6JZmExPA5cGvi10cvtZCbsdnD/w1kRJpcurNxx
         fmupACHHt6moPkYwdGglfUB1VlVPGyrTSiCFTEEr+XgeYSNdq7GHKswAUaiYGGYmIpmS
         /dTbC7yf/qVk0JsMEH0x70FKHQOnHiUVOeJRfe2yJvSxsPoYPLKhgMV7HYwHqwngFqI6
         YJz5Vc4ASR8wsOSy271LZxt4ALVyrXVtm97vtymKTrn41g1AyLCQnt/DSycbwf7Zgz1U
         HekQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kPzlMIjk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0lh6OIWXNnxO9+WxwqlfgJPPuiZYwan+casZFcfmL6A=;
        b=lS9rDqcwCXHdTN1JgV6DqR6lTEdMHP20uYalVbAz+XjDefqub0wo7Cq1sfXBOw8Pi9
         OxGLh5oxGouMLWTv4Wm3On4z/6hdjJW5HQiMBsZcx0nzmoPqm7Y7rDpXoM3xW8sT41ZY
         6xiE9kQ9P/rGu2+Cs9IKjvNXXPLTycX8/7p5YlgtAIU8HTrw+1noS+QU5BP/+JCiAsiB
         xGQINEBQeEjBKUaI2jjPHJx+YzVjfdJxQpQLuUUsSY3yjh+ihczuALWW1+ESC80tpNoe
         gkqOotZiwXIWtbKhQgNYw02nSkreGwFn30VOk5oikmQe3T/0Sa4XZNI0iuxS3WjTNkFK
         Ty/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=0lh6OIWXNnxO9+WxwqlfgJPPuiZYwan+casZFcfmL6A=;
        b=baGnaemjRe1bobqupjB7XLUBev3d4ehx8sXB2Vk9Lndf8cprYNo48JkWT56BFLYNWc
         zBzo1fZIA48NiwFntfK1sNwdim4CTFJuJd+sTEuIfjVmBvW0N7c0zLWsDvU3Q5YkZZij
         hFHZZwA+79Gj/CEmEYIEt9X6f6FwXpTVzcAdBkkTjkqpM56FTqExeHMrmvHUt9g3iid5
         Mi0Ma2C8wkgFHEZAJY+quzU13kjUjCDhGCFKjIDx7xl7uewgG8Jmu3ED5rMgYhCDmq5e
         lJoN+j9OlgYJbhXyXth4pkKkG+tA7CVrXOKvEIZPx1VIud57S43DPrfb7ACotzK+fIRm
         us0g==
X-Gm-Message-State: AO0yUKX/FIj5bJtYC9a7C/AtZ7pPqc+5zQh72LJ+2SkBp8+G1Og1qJp6
	ZaaRjXl9OWSXlHnsNTdnBOA=
X-Google-Smtp-Source: AK7set80Gm0/ZS+SuK4NLzqbzEWFJ++8X62V+z29lwF9ezRH4gwCz4nlcqUy511MtPpMZEflnLXdFg==
X-Received: by 2002:a17:90a:6a06:b0:22b:ec69:567c with SMTP id t6-20020a17090a6a0600b0022bec69567cmr3543086pjj.57.1675160468714;
        Tue, 31 Jan 2023 02:21:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e9c2:b0:191:1e85:3329 with SMTP id
 2-20020a170902e9c200b001911e853329ls16080745plk.3.-pod-prod-gmail; Tue, 31
 Jan 2023 02:21:08 -0800 (PST)
X-Received: by 2002:a17:90b:1e44:b0:22c:9953:76c1 with SMTP id pi4-20020a17090b1e4400b0022c995376c1mr8456773pjb.9.1675160467999;
        Tue, 31 Jan 2023 02:21:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675160467; cv=none;
        d=google.com; s=arc-20160816;
        b=RLVZPdzTWwM2LLUhFOk8ANsCCV+oyUHyF7id8mEB572Yz1NmNKbDds2hRi0+0wMPSN
         +YRA8KLt+27TO+mWuTyUpx8F4taVRpNB3keBSHpFDAb2RhZ4dS3a1KfVewQovBpg4UB/
         YRYwvop7s9f1FzVI5jTbsKqswTgxR0lJclKuhD2u74EU7CsWlwablrfi4qBGi6muATNk
         EB+KQdr6NW/M5D2IjrgbFNp6c7drtYicmDUT1cb76ZIIoEC6sguRDx+mdbYt8UojJMnL
         yapFuHKdeufTkV0G3xAgq0eujyYoVDe92AuWOhnN4JqN9tROqNY48m9uc3RHUovmVoX9
         Rv5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JccB23TS0/KWTmAaso9Rq5suOvDS6HlaZd7+/LF1Vkw=;
        b=N3CNCxK6bYrJXlVEH1P96Ntjn4+lKDmc8lF/Hit60gHBk83/90wfLxf+3p3tnDw8Kz
         avHU6qvhw1NB8C9+MfXL8sbq86DM1Ez8gYYUcsKk3XBY4ZThqqBH99cIShVsLKg6A1SX
         /0Vk3VoI7cBM70t1NwyDBg8+NFTxa1wT/ElOpHJtRzxtffDJ9NaITOUZxNGE0wfvsha7
         onhN0B82pNJvClci8fCWJs0P0XZ5FVpLxOUAhNzLtvcRR+K0BH9yg5hhes+67enEMl5m
         C5MVVCAg1dKAfA/Sid4CnKMfdqKpOuBoih986Jg3q9xD8qvy+XavdYT5ibxNQU32qI0Z
         DkPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=kPzlMIjk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa32.google.com (mail-vk1-xa32.google.com. [2607:f8b0:4864:20::a32])
        by gmr-mx.google.com with ESMTPS id cx3-20020a17090afd8300b0022673858f16si91984pjb.1.2023.01.31.02.21.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 02:21:07 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) client-ip=2607:f8b0:4864:20::a32;
Received: by mail-vk1-xa32.google.com with SMTP id i38so6748866vkd.0
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 02:21:07 -0800 (PST)
X-Received: by 2002:a05:6122:2498:b0:3e8:a035:4860 with SMTP id
 by24-20020a056122249800b003e8a0354860mr2503258vkb.7.1675160467019; Tue, 31
 Jan 2023 02:21:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <632393332c364171c69b7c054b3b2233acbfa996.1675111415.git.andreyknvl@google.com>
In-Reply-To: <632393332c364171c69b7c054b3b2233acbfa996.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 11:20:30 +0100
Message-ID: <CAG_fn=XJBf3JCwwpc+ykMt2KqyA=rfw_AMU7yW67KGc-UicC-Q@mail.gmail.com>
Subject: Re: [PATCH 02/18] lib/stackdepot: put functions in logical order
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=kPzlMIjk;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a32 as
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

On Mon, Jan 30, 2023 at 9:49 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Put stack depot functions' declarations and definitions in a more logical
> order:
>
> 1. Functions that save stack traces into stack depot.
> 2. Functions that fetch and print stack traces.
> 3. stack_depot_get_extra_bits that operates on stack depot handles
>    and does not interact with the stack depot storage.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXJBf3JCwwpc%2BykMt2KqyA%3Drfw_AMU7yW67KGc-UicC-Q%40mail.gmail.com.
