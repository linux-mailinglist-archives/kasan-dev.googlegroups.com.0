Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBF76535QKGQE2QHLUUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B444284383
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 02:49:27 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id p19sf3720720ejy.11
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 17:49:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601945367; cv=pass;
        d=google.com; s=arc-20160816;
        b=B9FT5BKVJO4JMvNShM8fOxPEXo3E+TlWghp0jhzcqpeNHi+9SoYjqDV7e9Ol/UIoAP
         M2S7USiMJ9ptKUIHYE92N+I6duYSC0AOq/YGrri8KFZTU4qjWZXPCgB/bsLYR+ulZ394
         YxWMEJGg7fBs88+ZiOJ5ljZvtFuVRdjj/oWS+Squpr5z47dfxY1Q+V6uh9fzf56ned2o
         9AUEFZ37BVlVIGx2QNFBVnnJBiMCWmpm1ye35i1bHB2yxdjSUfJvPYgDOy2u9vYTHD+P
         9I2AH4+UQYxWvl0RpBu6PGA4Iybix+8wKLtgGfetWB8LV0smZeBvktVcl7tP0y2VF/SJ
         1nrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YZ76HUr16bXI6kp9/uPw7CeOqwRwaeZSnmUnuM6Ya70=;
        b=PLCY6M28e1PcUI6IjJmKoXPXx/msDdvtMJhgCZXm5ijJc/HUCN1rx09Qt21yOGHHas
         SAdmXVtYPQwqQRdbredsqd2T9vxyPNLA7izUNpUbqR8qomZqpxir8JZgImqVz82lA+kW
         Yld5F/HAudq5xLaXtt1gd+DLGu7fGGw1ENJZBjsKbB5J+789jnAtyLTPkT1k59kB6yzR
         6CpkbiH/JJ04BEkjZnJhhOu5uW1ZsKpPTo1VoId5ijCRCjrWQaAEREASkJ4dgp65HVND
         ConifDGMlLYaQruWFHlCQRemEgm7pW7JDpcoR/ffK++rnCxEgamsqKzeLUT7HoWYLDWh
         Yh8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=deEOQpGo;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YZ76HUr16bXI6kp9/uPw7CeOqwRwaeZSnmUnuM6Ya70=;
        b=Vvtt2IVrqlHbHe20DTeig4DDXaMeiB2M7r6bPzGExCnEZXSkVhTZ5KDnACWDUfVJxt
         xmM93GDKAQJgcbbHbUMPcSQR75vWPjY+KPQis6uzRecWT3SamCvYNqr/yO4o0K5rEHdw
         RH9p7beTVb99udDUiO5wPICKF76+jU8WMp5dNKYup4PWR+CdMhtyAt0AcC2V9WqK6sDb
         oYXveFFglsY4vkxdoF9P84jUA3lbJy3mUTpCY+3RTsZCqSOdAeriJeKKniHI8+09KjCv
         7VgzcbtCEqYsgBM4ZWXNyhLehOmcAqv5T3B1Fjhvc0hk6h4moF+9W5QOGvAGT55r0nPQ
         XJAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YZ76HUr16bXI6kp9/uPw7CeOqwRwaeZSnmUnuM6Ya70=;
        b=IigIZ2RXJ51vfi0qO57myAUOrakeHqZZKRx2sL4wZSUvYNHyQUPIFkKSu6y6Aw+5ux
         L06YTjJpK36GJHfIxFQcxWh0z0i46UUNJLR8iy3DFIg82zsBBZ0dPJbjsCPWPmrwTuxP
         EqxYQfdEAK+0T8LH+C/C7sD4Rm8EnzcLgm92OxfxO485dOAk8XvNqxBhI95p0eWKFwcA
         kusd5u/5ROsQ8zKjuyl8kFWHWkEpiKgndiyQ3upOJ4zNmh/D4vkUpO14cj3KHhzDPmRF
         H8nfIz3xfYwBppvxnZBqmS6vNYv4XORWF12L38Npw5zHqn0Uy5E1GwACWvS9AmAaxbhO
         P1VA==
X-Gm-Message-State: AOAM532wqD8lKESVveZWL9/e/kH/kfaITieA9QTbGhGeUKJKTQ0EvRmb
	QmPaEQ0f0pXf0ZFgLo7Qrxc=
X-Google-Smtp-Source: ABdhPJwbdCiBsOUBCa8PnswJIqAKzLxsEAzqn4OzGpjsXdMQxtulCHGz8cI6UpYUOUwjuB+93TIEsQ==
X-Received: by 2002:a50:a143:: with SMTP id 61mr1189018edj.57.1601945367340;
        Mon, 05 Oct 2020 17:49:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c545:: with SMTP id s5ls7262684edr.3.gmail; Mon, 05 Oct
 2020 17:49:26 -0700 (PDT)
X-Received: by 2002:aa7:dc0e:: with SMTP id b14mr2630610edu.17.1601945366526;
        Mon, 05 Oct 2020 17:49:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601945366; cv=none;
        d=google.com; s=arc-20160816;
        b=nO8fpZbuRxjHU8mVUQfABBSLC5VCnjusHZ8J7Ltm6brAlO2zE5Te/otOAmwJ0GESX0
         1IwwWzH0GwHUdggGrqgemKDyF1axeueJHpTkz2e2zA8SD8lWurvv449UBk8HZFg7Td5l
         3ihq0aS58ro1ApbuaOXXVxT5+GtD5yszlwvo+QwnNyUTZtVIlHANiw8j43DiealcHA8P
         gr4acK8gflHysVmRv7YrrmHzrk+OLPChvlkZavykg8kDFE8nyAUjx99kxbU+Ei7BY4IO
         DBhkRipL+7uwG5VryI06bJEsqWDwRiQdSQJfJqAek7XMD4SfofSTMK7cNINWFpAxPaUi
         arWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DSqKb3Tej8m7nFeWjbSYdo/k6NG+xT3qX97daJHfAaE=;
        b=iZHNCcjUKSTaoScx9RyXtWBOu7wBQmg8hbXFmG8uXc8jMPIztuU1rDOEnoCS1lD73e
         q3xbQ45739RW9clrcThPik7CKem7aUAuyN4W9Iu77azTS69JaLlrHmr3bVE+Gu+b24Sq
         RUCgKWni+9Xgx4+zJXbm6k3EyyQXqHL3W+ONzqAj1mVIN/UtzuSkuQKymUTz3KY1ID5m
         JRyg82zB9ROSEup1e1yDo9SdrnKqQRAZdXoM6I2ooOMhgfAmz+vVQLBnR87ph8eR4tVF
         KdkqVvU+GG3HpLwGU3ZY8UAR8rhMSR9EpA94A2AuXICYHFpXRgAEjUf5DlAtc7TW10Fv
         sI+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=deEOQpGo;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x542.google.com (mail-ed1-x542.google.com. [2a00:1450:4864:20::542])
        by gmr-mx.google.com with ESMTPS id a16si60813ejk.1.2020.10.05.17.49.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 17:49:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as permitted sender) client-ip=2a00:1450:4864:20::542;
Received: by mail-ed1-x542.google.com with SMTP id l16so4352876eds.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 17:49:26 -0700 (PDT)
X-Received: by 2002:a50:fe98:: with SMTP id d24mr2504183edt.223.1601945366080;
 Mon, 05 Oct 2020 17:49:26 -0700 (PDT)
MIME-Version: 1.0
References: <20200929183513.380760-1-alex.popov@linux.com> <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
 <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com> <20201006004414.GP20115@casper.infradead.org>
In-Reply-To: <20201006004414.GP20115@casper.infradead.org>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Oct 2020 02:48:59 +0200
Message-ID: <CAG48ez3VKw=B14r-BeAOxGtPExc-G4FYNymRPgFKUKUMsn5Osw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting use-after-free
To: Matthew Wilcox <willy@infradead.org>
Cc: Alexander Popov <alex.popov@linux.com>, Kees Cook <keescook@chromium.org>, 
	Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Peter Zijlstra <peterz@infradead.org>, 
	Krzysztof Kozlowski <krzk@kernel.org>, Patrick Bellasi <patrick.bellasi@arm.com>, 
	David Howells <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Daniel Micay <danielmicay@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Pavel Machek <pavel@denx.de>, 
	Valentin Schneider <valentin.schneider@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, Kernel Hardening <kernel-hardening@lists.openwall.com>, 
	kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=deEOQpGo;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::542 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Tue, Oct 6, 2020 at 2:44 AM Matthew Wilcox <willy@infradead.org> wrote:
> On Tue, Oct 06, 2020 at 12:56:33AM +0200, Jann Horn wrote:
> > It seems to me like, if you want to make UAF exploitation harder at
> > the heap allocator layer, you could do somewhat more effective things
> > with a probably much smaller performance budget. Things like
> > preventing the reallocation of virtual kernel addresses with different
> > types, such that an attacker can only replace a UAF object with
> > another object of the same type. (That is not an idea I like very much
> > either, but I would like it more than this proposal.) (E.g. some
> > browsers implement things along those lines, I believe.)
>
> The slab allocator already has that functionality.  We call it
> TYPESAFE_BY_RCU, but if forcing that on by default would enhance security
> by a measurable amount, it wouldn't be a terribly hard sell ...

TYPESAFE_BY_RCU just forces an RCU grace period before the
reallocation; I'm thinking of something more drastic, like completely
refusing to give back the memory, or using vmalloc for slabs where
that's safe (reusing physical but not virtual addresses across types).
And, to make it more effective, something like a compiler plugin to
isolate kmalloc(sizeof(<type>)) allocations by type beyond just size
classes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez3VKw%3DB14r-BeAOxGtPExc-G4FYNymRPgFKUKUMsn5Osw%40mail.gmail.com.
