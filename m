Return-Path: <kasan-dev+bncBCCMH5WKTMGRBAFDUWLQMGQEB7WHNTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id C06D258804C
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 18:32:02 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-10d6ce04410sf5104541fac.23
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 09:32:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659457921; cv=pass;
        d=google.com; s=arc-20160816;
        b=DKyGgAQGzpCXzTOZ3ic7gThk4SEB6jP9SmRJ01+uP7fFaQ3KZv4rn2j/XZ+UIR+Rrt
         B28275WhHq63gWW62v7XE+avmcy4KdWNNQvctlfotSJghR386ZbG5XN4ZWsrXg5Sbqx/
         6i7zof1m90WZMWn8iNNOIehEY6exlk8Ll57hPQnwH+kAlniWa1ammECmvNEnxJLJvbnf
         2gZL/WVp9FTHsATkVX838TqojzmlCJWjh5k8SKfM/2xMPLtyWrtLearc+22i8LwWfRn6
         WdZsDLoo3YgrqaPMjAbbxr9Z7FhIjyYisKyL1VCcXhS5JsR+OosZ4gHXCSAP/QUMaAZA
         Bo6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cNEseLIi5HjfZ6GGa36qkJZ7a3JCOMoPcnHg+//+xsY=;
        b=llC5UYgumA3ETZ//0Hvhqd1SkeG0l8s4F0TDB1xA9lamF2gQUAMdvbklReoTnaLo/R
         xXK7a6K09FMp1qntfMxxm7nD6WXvfcay6+nIAfG9bFFAY8L3RgGvSskUkzbX6KbNgMBh
         ZSAiBO6pk733Y31Uy/2JjlY1GGvtjl13UuJOEgogPAfz5l3Ajb9sQfPrAO6S9t4IqYIF
         pFFeTlbdjEIUbi81ir7pglXhIkQETVreTvwgFKrVWfUjeCxnqvzK4JEW1/RKEFtz5hJo
         uiPxw8n9uW7QxlxxTYZHfyBGDnjjc08Y+T3K5x2N+LF7G4rWTkuJaPlT58DpaHxeP3hn
         FImQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C4yceeMr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cNEseLIi5HjfZ6GGa36qkJZ7a3JCOMoPcnHg+//+xsY=;
        b=kweKod3Dz48OabCTt090ZRQfmz+YBfnRdIGgnfGfQZ5PNLVgDrOeIJeiBLpM+M7okD
         YzV0n2HPf7DmZNjEGvdvlCbxxgVR56pasHPJ6xvIWL89Fh6wgzVwyjLC/50aINhuKntL
         ITlm0EzPU+hR+7895aU0Mupj9LKhIWTwV3mK5qUXqFqjU52j+3wPMe+7hMyQI4Pl8wLO
         B6VnED8dU3SdZ2q2eemFQLVXfBmDTWw52/4FT7LcVnNYn600mlcTe6NHtsGZZwV+dReC
         F+NynI5DwhfWJLMjzzB+CWXxnkZZmzFP1yNLr8+5a0wkUpuSwePG8zG+mCFWjCXiyFtv
         3tdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cNEseLIi5HjfZ6GGa36qkJZ7a3JCOMoPcnHg+//+xsY=;
        b=xMDa/Kc8gcA0OthkoP5LXRVQVwRcYfRuRSmFA9dX1F8v2JRpA7q/tv5rrQkd6QBMa/
         2bfsxJGb7yqVlIarpOuHlePSaZMq1BaiLc0V405FmXptJ4h4rGqc33YzgpwGnbTUULXA
         TCoO0CmAZVu6fr55iyKWa96MuukfZLja6vFZWI76r7V8DKhG+V9plp8bJhmRJjv1t+xj
         p8dWlqFXZw7WciiWttl9u6HxH8ATMe1Uyl0PXqK3gmDijkrKo/oKQMbXMtdgKQyuuw7P
         e3kBRoY6yQ6J3dn5J3DM0H/juIfadXNXr+odUCi/CSnPgAxoFYgsvuswTdJ4qCRUCZF6
         q1vg==
X-Gm-Message-State: ACgBeo3Wm906nus07t7XODDUG0fA0YvctOiDgadK8DYcez/XF1QUZ5n/
	J0rxkHrTWyr8H/t3MXST3CE=
X-Google-Smtp-Source: AA6agR4zQ653BAd7HCa/syISqfgqw+8NJ7ED9kPxqfw2NeenYmw6N0dDnOmx3ZhuLfKAjwQkcm38Ig==
X-Received: by 2002:a05:6808:1592:b0:33a:78f0:117 with SMTP id t18-20020a056808159200b0033a78f00117mr149291oiw.24.1659457921114;
        Tue, 02 Aug 2022 09:32:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:6c52:0:b0:435:9227:131b with SMTP id u18-20020a4a6c52000000b004359227131bls616129oof.6.-pod-prod-gmail;
 Tue, 02 Aug 2022 09:32:00 -0700 (PDT)
X-Received: by 2002:a4a:b401:0:b0:35e:de93:43a9 with SMTP id y1-20020a4ab401000000b0035ede9343a9mr7048571oon.80.1659457920505;
        Tue, 02 Aug 2022 09:32:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659457920; cv=none;
        d=google.com; s=arc-20160816;
        b=l/VfrNRSy9rcfYVz23Ie2HkKIObZNPrkk/sc5pnFUtRPs1JKuZCjRmKNsbkvzqBjhO
         088q+YHkBz43vai2XDmHtzzREjouonfoc84vPMyH9TCnkpfqgFocC8bMFhHirUKrwc+z
         gQ40bmOOMLX1qRBrzFld3L6I77bKQXZjMtf0HiVfC/L+OK5gjjBv7pXl2si9jPnJ/rI1
         KOgl0GqM8gxp9x422N9NDfXW5fnBVwMGJ3uHbfSadGccn93OB1vV7jK1cZxbm8dmFWjq
         2Ajt1F1OMnt+KSm1QZSkWTyvpS/n/9vGKWbqQtha5qsjMkYVZg8BNr16jF3+t9QcXe5s
         sunQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jBLRsOY6b2BWFCEwUDOOLDtlfS4iNN5NSPXBB7OTTdA=;
        b=vi0dYdTJcADkk7vrmEIMA1uSLO4KYpwmq9Cbt6fMhozxXMeON39e3hNB8t1Yz0Ghzz
         px7u/lGACoteYi8fgLgEwlQa9liodTxZef7ZweNhrzBBiWrt9NNSfEX6JhjK69BwHghP
         q27KBrmoCnRePvGK746WwJAUcMM/460vOwF7om+bHFc6POSxLv6VAMZ+W8YtdGCB3vnd
         UJvMHzTC4RhoamwBTlafkRWWAKct0G+0OQsjZeX/gOtceNLVMoWX7DOZbvb0vRARKsrF
         GbHw74Vdu8rQY049q5QXHPMakm41OUVMwegs3/5BOSMi1qFJu2YNMVUkMCXnzt/3oAH2
         51nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=C4yceeMr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2d.google.com (mail-yb1-xb2d.google.com. [2607:f8b0:4864:20::b2d])
        by gmr-mx.google.com with ESMTPS id t14-20020a056870638e00b000ddac42441esi1250582oap.0.2022.08.02.09.32.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 09:32:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as permitted sender) client-ip=2607:f8b0:4864:20::b2d;
Received: by mail-yb1-xb2d.google.com with SMTP id 204so23237564yba.1
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 09:32:00 -0700 (PDT)
X-Received: by 2002:a25:b9d1:0:b0:671:49f9:4e01 with SMTP id
 y17-20020a25b9d1000000b0067149f94e01mr16899347ybj.398.1659457919894; Tue, 02
 Aug 2022 09:31:59 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-16-glider@google.com>
 <CANpmjNOJ-2xim3KM=9O=sfSgQXZi81R6PQj=antfHnejaOOogg@mail.gmail.com>
In-Reply-To: <CANpmjNOJ-2xim3KM=9O=sfSgQXZi81R6PQj=antfHnejaOOogg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 18:31:23 +0200
Message-ID: <CAG_fn=UBVs+QgdWDa_UB_zs0OUO=-zjcoH+8NY7obUm20rkBOQ@mail.gmail.com>
Subject: Re: [PATCH v4 15/45] mm: kmsan: call KMSAN hooks from SLUB code
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=C4yceeMr;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2d as
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

On Tue, Jul 12, 2022 at 3:14 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 Jul 2022 at 16:23, 'Alexander Potapenko' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > In order to report uninitialized memory coming from heap allocations
> > KMSAN has to poison them unless they're created with __GFP_ZERO.
> >
> > It's handy that we need KMSAN hooks in the places where
> > init_on_alloc/init_on_free initialization is performed.
> >
> > In addition, we apply __no_kmsan_checks to get_freepointer_safe() to
> > suppress reports when accessing freelist pointers that reside in freed
> > objects.
> >
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> But see comment below.
>

>
> Remove unnecessary whitespace change.
Will do, thanks for catching!


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUBVs%2BQgdWDa_UB_zs0OUO%3D-zjcoH%2B8NY7obUm20rkBOQ%40mai=
l.gmail.com.
