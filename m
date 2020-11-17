Return-Path: <kasan-dev+bncBCMIZB7QWENRBRM7Z76QKGQENWJRHNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id C6B1D2B6244
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 14:27:34 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id t10sf14616409pfh.19
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 05:27:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605619653; cv=pass;
        d=google.com; s=arc-20160816;
        b=MxLAWznLYb/yWfCRdpT97K51f24TxKUcTzFKGrAaqxN8jXVfFma9tmvNTRvc60RoRL
         XFOZD6PCR2UoRrWECojFq0hGoDgAmiLlrpNFm06yEFZBT8hLtEIMPFdlwvsDko33ieXL
         4ho97RlxpecPRJCmPxP5IKXJU1390JfDdShTdFm9AF+9P57y3CLmqbWuTccYKVg+l6Zx
         EYEYWAVIVt3QkGoxYtkYXSDn7kANzv61bu4o+V0779OTefU5J7PpMt1MMNtbXYw/EF5B
         BooQTgBlvmm5mjQOM/jBCrniDkbJz/MZG+cEfre855K8yKv3vJgNko9ha6PuGhH4SkKf
         CwYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AsWxQQsAHHKQae8hR3TwJWoV193jDQL/HK1z+ssl6Zw=;
        b=VQo9N+B4ZDA6x/1ZhGWEfx0cbb2SkZ5ko94vMC2LrlJU4PlJFNnJwQOzfTKCZcLMBX
         zBxumUF+7tSCdRrF61XeGKZExgYZNgqT+TtYKpwlO9hH//f3fCUDzY9ik8lN39MyEdJp
         2iwdmrtqNbV2PcbXqChLcGGgLPMDPgwShr96SnOwpNhOzEUlD4MuRnOwPRk8ZIn/vy4g
         vJ1WklTcSlpHvMejrhCiivJ1n3zbQN2CSPwWMNOozFFfx98nRYeVEEu4HVn625IZVf5/
         MQITN+wN4498r1hQ/adL6L9EwxLkTpkh0CYW4NZfnbSX57HNRc0W8FO7TLtah0WsShl7
         oDrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZJJ5+s5q;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AsWxQQsAHHKQae8hR3TwJWoV193jDQL/HK1z+ssl6Zw=;
        b=phuiCtpQrw4y2eUhVI0CJecQrErW3OqviI0OJDY1liRTlMcvqLZd+sD/NQnnY4Ue+A
         jMeeP/A6gE9quR7db2dAxGTiXX+cNllq/fVIWRav92nGm/CqEx0tEd0z4gbgk92wNo/T
         VL2sUoruDxQchI8HFIAeTpBnYRKnI4TRwv843i0Pi7Kqxmd1cIHmiyYWqjexprcB/9wB
         XgABPMj/C6/4FNVXCiYvprW9tk+bTzeV6kbIRDjpcf5htUwNl5vrBXi5+6NR/sZAFUw/
         ucGC1+VJ9VTdNyZyQ6czZ77syecTBgi1c9yBgsoc44gVG1cgI3LRo20dzOIj7aVw+pjb
         bbDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AsWxQQsAHHKQae8hR3TwJWoV193jDQL/HK1z+ssl6Zw=;
        b=GPrMHXPCtNO3LxKsbVQIQe3AnJoJwa0SVxCOPhN3bVXYhIg9c/7c+hs0IVe2xDneJW
         WqyN05uXUQ+o3pFqw4VCe+8vzneFWevsghyZONYZxOhgOtt8+maTHjY7RW9UucYkWkyT
         Sd1kmndLDjFqUWlUcbE8xi7H1aJPibGk/5O3H0MxY5FL4BK63hKYZ8s8heVQu5I9G66Y
         rNIvopX0EvQDOOh9tCQiMz35nncTmL3otvLysE9lh9JfdcYQQxWTEhCDCVNP4kDEDS8P
         yK+kyKT1z7EuaLFotFnKMMqXxWJpM+OkRYm9sLyB1h+2g+RB5/gr5PZ0VcJdYQ2m+lEB
         8PnA==
X-Gm-Message-State: AOAM533t6FD5L/+OPAc18sV3ExkqkNRy2wl2Zzl1jMtr1FMfzl4kBBbL
	FDEz/t31NtFuJ3Gvn2ahf5U=
X-Google-Smtp-Source: ABdhPJy7UCNu5b8RpF3kA+YHFHOfwFtW9bt6/zi5+h+UhNO+j6NyvRgGL32SwOBvgAb/NT6XM/ggqQ==
X-Received: by 2002:aa7:9f9a:0:b029:18b:a203:3146 with SMTP id z26-20020aa79f9a0000b029018ba2033146mr18367413pfr.36.1605619653508;
        Tue, 17 Nov 2020 05:27:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3712:: with SMTP id mg18ls1685226pjb.2.gmail; Tue,
 17 Nov 2020 05:27:33 -0800 (PST)
X-Received: by 2002:a17:90b:805:: with SMTP id bk5mr4722880pjb.78.1605619652966;
        Tue, 17 Nov 2020 05:27:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605619652; cv=none;
        d=google.com; s=arc-20160816;
        b=XBTkAy7peax6bBgy8UY1KCC699w/qbrazb3T9EPCSNrSv0Jjw3U6T/rJ0R4gr40Lg/
         bBjaBmqDmN+y4ECgQxwfSz4B4uQ2TFC508gQ81pJu4m9ONw6yl4x3su9FGxeaPxvN4DB
         fkpr3JYGqdAiUk9l8XNTmwsdv3iOSx0985xNds1NZC1cyTRXPD8hMti7gS94C/IjxV4j
         zK62EJB5ytaMKchYR50cgJJnncMuCow0w1vexn09NF3nohuLV223KINyjfpR6g+y32Zx
         wJTb5qwnyZ1qkeLSpVm3FmuUHq/NU8esBEPG21mpYMIFnmjotEGVnffc58TVFADJHgoc
         08hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Rm4APUToOIfygYhEOvJkSoAG2E8GzKBKMf6ZHBmKcsc=;
        b=NzIIQRw3+cZiZRB83KCOjpOAoDnKE0Bz07JlZZVYZHTPKk/hz61i/+IZSDTrd1P1eP
         X2dqAKgeTcJR26AmtfRLP3+IM2VBCtStetitYl9M3p8Fch+bz3WYRYX1G3N/PVzJ1531
         E/eDJryUwjTLalddoGca2zMOXnwg9bqgiHkuq+txwu1ZL/x7fmTv2DOWrx+oeJAJ5lcI
         +2sX4jfEZQXzfwSqaJ380jsqbu+3GsFzf1+SdK0sFFAsDaFLNGQjte4ndIEaYvOcVH7L
         jsrSCBRTnC7uYPlecvkLGtwtvrdSuVmEnG5G6Yx1WbTfzqs0K6l5e5dX/xEilOdKserA
         q7Jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZJJ5+s5q;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id l8si220561pjt.1.2020.11.17.05.27.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 05:27:32 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id p12so15507632qtp.7
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 05:27:32 -0800 (PST)
X-Received: by 2002:aed:2b47:: with SMTP id p65mr18425153qtd.337.1605619651889;
 Tue, 17 Nov 2020 05:27:31 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <52518837b34d607abbf30855b3ac4cb1a9486946.1605305978.git.andreyknvl@google.com>
 <CACT4Y+ZaRgqpgPRe5k5fVrhd_He5_6N55715YzwWcQyvxYUNRQ@mail.gmail.com> <CANpmjNN6=5Vy5puLbhOQxSNUNptFA9jKKqnU4RXRcLb4JT=hJg@mail.gmail.com>
In-Reply-To: <CANpmjNN6=5Vy5puLbhOQxSNUNptFA9jKKqnU4RXRcLb4JT=hJg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 14:27:20 +0100
Message-ID: <CACT4Y+b7NxEJmnYdoEcN68-t0ns2Px4JWbTrFFkCQVMmdXXKmQ@mail.gmail.com>
Subject: Re: [PATCH mm v3 17/19] kasan: clean up metadata allocation and usage
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZJJ5+s5q;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Tue, Nov 17, 2020 at 2:18 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 17 Nov 2020 at 14:12, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> > > +        */
> > >         *(u8 *)kasan_mem_to_shadow(object) = KASAN_KMALLOC_FREE;
> > > +
> > >         ___cache_free(cache, object, _THIS_IP_);
> > >
> > >         if (IS_ENABLED(CONFIG_SLAB))
> > > @@ -168,6 +173,9 @@ void quarantine_put(struct kmem_cache *cache, void *object)
> > >         struct qlist_head temp = QLIST_INIT;
> > >         struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> > >
> > > +       if (!meta)
> > > +               return;
> >
> > Humm... is this possible? If yes, we would be leaking the object here...
> > Perhaps BUG_ON with a comment instead.
>
> If this is possible in prod-mode KASAN, a WARN_ON() that returns would be safer.

We only compile quarantine.c for CONFIG_KASAN_GENERIC.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb7NxEJmnYdoEcN68-t0ns2Px4JWbTrFFkCQVMmdXXKmQ%40mail.gmail.com.
