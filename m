Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDMIVOJQMGQEMKH5Q2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id CD37A513A17
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 18:42:54 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id g23-20020aa78197000000b0050adbdbbec8sf2994782pfi.23
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Apr 2022 09:42:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651164173; cv=pass;
        d=google.com; s=arc-20160816;
        b=jsYd5x/Z4i0okODKnrko9u/VPnlZo3nMzd2iocfxTbxTNm/nAxACoMqXZoxQMDjNSg
         WWSH2UBu7xCrdDjYZF0fShE2hMosnmQp8+ro/HqonBEHr1HkzsDWe4pvvPWXXHflPqBY
         9AfLweeY0Bk8ZxibWYkHibSgqqR50ltRx4lUYcmAC+n4bebikQM4C6bnCfVt4cl8K6Jx
         dhpq0UAaj/DHsDrbinwgW7AX+P9Ffu6FZMEQcV/ImIC/A4r8sfW6FnkXLyQ/jbxv/LX1
         4TVE0OndPp/739832F8UrxjLiqbDQYRpd7JV4ObV4SrW+hrn3Zfso5Tu4dGHDzlQAOiw
         uNqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U8k9iV0bc9N6fAWx79zWgBfyekJbfzHaWKmAfckBTEw=;
        b=vUAbeVvXMeSmjvIXpY0zw2fIu8gtyLPKLRhpf+EXDWvyJj68mUOtXFaOwTgWbquE9n
         o//EQyO39U9SUS/+R+Wt6JR0j65nyAXs5grwhN9bxEs/N8UfbwoXKv37jmZ79mC84PWf
         WODLwn8G4UzqG+rKiuCaTV8Pl/CYNQOXVs4V6OPjiwU5tQ9Gvd4cgufK1o8NxswKOrLA
         Np/kf3s2CdYMt1RhLSHNLs5JhBxSB+ltH2/FfWdlZoscgviILEGKwIxlO1B+GsqqyIXq
         QFDJJLAJnQvsQ4wFBDqqBltbX980MQa5QOsF3cYdUZ4r8E3yfUf5F8qlyI7t5D9sl4ej
         65Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gmEWLK/G";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U8k9iV0bc9N6fAWx79zWgBfyekJbfzHaWKmAfckBTEw=;
        b=DJ7mKjV54D525RORJmTrpPTPVdXEh2CJVskxwdj9fQw+AFeiSCR9FVtXXC/AdQUgok
         PaMU+KVqZtc++aNlL/5Jod7UE00UKdGFr8BibLje/N2u2V2I43on23Q/EfDra8l1o+BX
         GsyOMNleb/LkbdWtXplTavpGdB95OEtxIeM3+6sJJfIjCmExu8GtLOOQQ+C9RMpRo5OF
         3mxjvo3lx4f2kza01wm+FOoDaIDwFt342NZFI58kjQoe+GwRWmZOo86QFOITE25JS673
         en1g2QUermfidY1X4b07e6MPGW3ZFisIeif211vsbzgDYavzsazqmjdoVITdmXshSQn2
         ujGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U8k9iV0bc9N6fAWx79zWgBfyekJbfzHaWKmAfckBTEw=;
        b=raMbx0fmyxOkimTEtv+9t95rRUxjb6Po2FXFMnopSZwnelPpYqobQRcvl/N1Ze9sYO
         oNeSmTms5+7ehV8+WFfP3GcjpCS3RhgcPauvLlWGQUQPO/lLeBFGHdBfkLJunzSgcdlG
         2EFFRPUedBj1P0WEefob+okeWIfA9WL3Len8Hf4vnWsZt5IdwtO1gQqjsiXUh89yuTHG
         ZMCDVElRIjxd/PeDAah6kfnw94k+ZLvC7m3gnwCH3eZzqSH++Sze1qT4Ndy6+eIX+yYh
         QSNjyBTv2enNXtY8BRLMzH5Tm7HZF6xvOBwBUXQ0pzTn8GFoA4Afe+QNP6Vj1937P9DN
         JfYA==
X-Gm-Message-State: AOAM530CAE1TC2dnVevs0h8LLDV4Ip8MMqXywaQXOd9buc40EpZd8nHi
	pkWScKNLwUgFG08C217ov28=
X-Google-Smtp-Source: ABdhPJyh3RFw1EvqHYe9YlVJx34sV0jHD8h5exwxVqYDHet3dIvJ5xiCu0kn3CC7doY/282bFn0JZA==
X-Received: by 2002:a17:902:ba8c:b0:14f:d9b7:ab4 with SMTP id k12-20020a170902ba8c00b0014fd9b70ab4mr34951529pls.23.1651164173433;
        Thu, 28 Apr 2022 09:42:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1311:b0:50b:76b8:3bb4 with SMTP id
 j17-20020a056a00131100b0050b76b83bb4ls191541pfu.1.gmail; Thu, 28 Apr 2022
 09:42:52 -0700 (PDT)
X-Received: by 2002:a05:6a00:2408:b0:4f7:a8cb:9b63 with SMTP id z8-20020a056a00240800b004f7a8cb9b63mr36177778pfh.33.1651164172829;
        Thu, 28 Apr 2022 09:42:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651164172; cv=none;
        d=google.com; s=arc-20160816;
        b=zDTQEjCVnCw+Yivzw4YsSwmMQc40qYgBemOmL8IQ5RZH+D9UTRxsiyfCJZmyl970gk
         T9A+78qNLQ3Ul79JMv78xzJ6dLy5eqsZCH19688RQkMWHg2/NKgcsp4wcyX6wt+iMaV7
         V7cbKcnVyhMGaDZu0gMHS9BDspgTEkeqhpD+NgqwNqgGurKlv00KsM5Ruh3G9JD5Ge0U
         jY3vnqxjc4MaMJjG8M5faey4hm1fSZC3odY6Q7R9cgSmYdf3HHYBHAiYXfsxwAnRt9ZY
         rK/KjYdlTc2ATPHIXoJ4S/dDDPHXtXhehaXl37iUsPFnwfod3i1WS1o9Zpia2oOpqv35
         w26A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=r56JqmyEKwLfjjTuw56FZ5cxoCmhZkz1FIGkAdMEzhg=;
        b=U8F3xMuazcVU+2PWbfZHIK1tN3bP6SWIkK9mxXdR3wPzAPj1ElJvkL32KrwY6/MeXR
         WmVySCfN+/wQMj2idCgmX+87fg/WcGHSrRxoj8b1l/j5lDEttEU2MuRaF4t5v9KCM/KR
         g/YMy8TbxCLnkqnnHGVYpbXlVXT+HMI3WEfv9WJDQvwq3DEDIk79AkBJS4NVx1zGcowr
         eqOto9jdRL2hQcbzszhdOjg3TsH9BTCZzmqd8MsORFXPLlAq6L/731z63lnBBCDz35c8
         Kmpg+qhzbLrzDbIHjT12GD33zUFfrTJY2ObzNVb9mqWrRqqeDWeZAvVROqSRqNpJs3PB
         pD3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="gmEWLK/G";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb29.google.com (mail-yb1-xb29.google.com. [2607:f8b0:4864:20::b29])
        by gmr-mx.google.com with ESMTPS id s48-20020a056a001c7000b0050d44c10b11si368273pfw.3.2022.04.28.09.42.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Apr 2022 09:42:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as permitted sender) client-ip=2607:f8b0:4864:20::b29;
Received: by mail-yb1-xb29.google.com with SMTP id y76so10079068ybe.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Apr 2022 09:42:52 -0700 (PDT)
X-Received: by 2002:a25:9bc5:0:b0:644:c1bc:1f12 with SMTP id
 w5-20020a259bc5000000b00644c1bc1f12mr30361921ybo.138.1651164172335; Thu, 28
 Apr 2022 09:42:52 -0700 (PDT)
MIME-Version: 1.0
References: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
In-Reply-To: <3167cbec7a82704c1ed2c6bfe85b77534a836fdc.1651162840.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Apr 2022 18:42:16 +0200
Message-ID: <CAG_fn=XFOA-qsvPwjwJ0iZH1Wy54aS7QtD4ETVdp9L-yvOkiWg@mail.gmail.com>
Subject: Re: [PATCH 1/3] kasan: clean up comments in internal kasan.h
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="gmEWLK/G";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b29 as
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

On Thu, Apr 28, 2022 at 6:21 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Clean up comments in mm/kasan/kasan.h: clarify, unify styles, fix
> punctuation, etc.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Alexander Potapenko <glider@google.com>

>
> +/* alloca redzone size. Compiler's ABI, do not change. */
s/Compiler's/Compiler ?

>  #define KASAN_ALLOCA_REDZONE_SIZE      32
>
> -/*
> - * Stack frame marker (compiler ABI).
> - */
> +/* Stack frame marker. Compiler's ABI, do not change. */
Ditto

>
> -/* The layout of struct dictated by compiler */
> +/* Do not change the struct layout: compiler's ABI. */
Ditto

> -/* The layout of struct dictated by compiler */
> +/* Do not change the struct layout: compiler's ABI. */
Ditto

> -       unsigned long has_dynamic_init; /* This needed for C++ */
> +       unsigned long has_dynamic_init; /* This needed for C++. */
"is needed"?


> -        * is accepted since SLAB redzones aren't enabled in production builds.
> +        * is accepted since slab redzones aren't enabled in production builds.
s/accepted/acceptable ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXFOA-qsvPwjwJ0iZH1Wy54aS7QtD4ETVdp9L-yvOkiWg%40mail.gmail.com.
