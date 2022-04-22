Return-Path: <kasan-dev+bncBD52JJ7JXILRBBGRROJQMGQEXKXH7QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C0C250BEE2
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 19:40:22 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id x23-20020a170902b41700b0015906c1ea31sf5101647plr.20
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Apr 2022 10:40:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650649221; cv=pass;
        d=google.com; s=arc-20160816;
        b=IePmJZhQLe7YwSEzHqJB3tKKbXzhwUCLoRAiLEx8GFkfMtm71QhI5f1Ai/6zQRcXAT
         y3aLjpiVnR8w18iouKNeJjDsChs6ggoufj8qBX3CUMQBa+gZ75W0DknrXvomhlN1tGUJ
         eKmFC7zJbOT2JopLb6RYeXrIx7D5NDDn6SSuT4Uq3y6nQCHF0M0rErdp0bR76RphkFrc
         vsWW2xp5jKqfmTz2AOkQG2gHf+/7yuWxvR5fLrjZTZUVD/M4NafYhzOnkKEhdF+QerSz
         y4JuI5ajN8OjdBVnTdlXNfoqKGOrutZfy0H7B5z+pk6JbNCzO8Q9pnXvEv+aelZk43rb
         pwnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=L4LYNHkZwfOQBnjzVcV2D91j0O8hYrJs/tMI7ekS7N0=;
        b=qQHGzxtYw2cqHMXrxUus+0h0G/oe6xF6wjXz39fsyU41vtn19LJ5KqTmWHGClrI5GI
         qGhF1EwU5RVX+PmymqwXohB7ZlszjPvTWjLFAGYYdvt3Lpoj9qiOJ//MyHZSK9zBkniC
         sppENqcXe/l/rDYt9XUKCaGRZQnG+RlN+RNSgJeyMTTpL6dcaeW7HU6P1O/brYNWcErU
         tRxGb+OiU79ICDg512QVJtWgP3F6q7LIwnfipZkrkKI//f6PWwZevGKboarCa7p0o/BU
         33FrENCh92qD3Ie3IlvRaaJ4sHiWTGIz/Kf+izIx3S+4wzOcqNW3ujewo8cApWp0wi42
         sIqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EXx39caV;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L4LYNHkZwfOQBnjzVcV2D91j0O8hYrJs/tMI7ekS7N0=;
        b=Bi0izIH1QToKJrpvmyZLnlDKasQR3D96hICHntflBjhcvSVum/uqs/2Eia6bwIx836
         7SmZtIoRM4xBghbCPdyDZyVSaSnBFA+2p9OYtl0cLgM1W8te+oiBIHjh0YBnTHHUEqKL
         VCnGfpSRCY7EGuj0W4Qh+xuwLIUzTHSyw1Hzjw0eAxI0kFB2cnfa+tnx7CRhw5rfdBog
         lKHFlha1fmb9Q2vSbn5oyXXA9QwzuS7AhipFEzQ888pNzLT1bebPCKeSWhKhxXNLK4TE
         w5wXaUqFNBfkbWMknM18OgrKC5cFVOfOhEsyJZ6VnwqCrNwHnynsNBkxkju8gK43q8fQ
         mBMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L4LYNHkZwfOQBnjzVcV2D91j0O8hYrJs/tMI7ekS7N0=;
        b=uNUvZA55xM9dPHER3QKNHyElCdgGSTH7tesqF19iLTD46jvZf3TB23sACDsRfP3KSV
         4kMd7rGUwNpne89kbErwQMcogE6i82eh1a9uP/NYgouTBvCx26NmIJZtS0uw96sRrOq6
         DaWSD0hLOqyGQwlHKxw0qnfyaIqLd3qG8tVAIKk6G2azle8HkNkuDrwiebAKXojrNoqG
         Pgw2G+bZ2nO+iNJF8UPU23mgQWMJCbdCYVDOhcR32LUzboPfDS+Zey6w2HmQ/Jd5bYSm
         PTPoRk4df9+8dIPROpE52Ff/d8y7lspPeZ66rtLduEk0XRjY+nF4icwWZoA3lcKScBi1
         ngJQ==
X-Gm-Message-State: AOAM530aAnWx8rzLepMSkUF+dGEVG3AvUjdXh3oa+od+Ax0log38vDkx
	LXPP2XQRu2OJB6S7dMxXTxk=
X-Google-Smtp-Source: ABdhPJxy9miB9NnQKcRCfQBn/QBBXKdm9cIcxEBg33ZVEVq0Cf/SbSFb5Pp+mBLrZ9u1RPrNZDEypg==
X-Received: by 2002:a05:6a00:1d24:b0:50c:f8b5:974d with SMTP id a36-20020a056a001d2400b0050cf8b5974dmr1719003pfx.76.1650649220924;
        Fri, 22 Apr 2022 10:40:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d4d1:b0:15b:3010:ed1e with SMTP id
 o17-20020a170902d4d100b0015b3010ed1els4057428plg.9.gmail; Fri, 22 Apr 2022
 10:40:20 -0700 (PDT)
X-Received: by 2002:a17:902:e9c4:b0:158:f77d:afb7 with SMTP id 4-20020a170902e9c400b00158f77dafb7mr5693696plk.143.1650649220298;
        Fri, 22 Apr 2022 10:40:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650649220; cv=none;
        d=google.com; s=arc-20160816;
        b=FP5sNjWRs0Vjv/2FzCwpjFQjWu6X1ozJW6h6wGl1TMMkVySJDVWqJJ2LDDJpj22Onr
         gt1PTmmVGMsapqo1/45rOTiI/Xjl4J6FQZNNubhFpRoZCocNKQM4j5F9CTF6uRuuI6m/
         UsLZonHzvca3P9vms2o47INeQNBnk2FQ3i2XmYVP1r8CbwtcSWN05oV3r4kovYdNPf4r
         WKQIYF3asQWoqahwrWDT49edyTZHXoYh0G76p8VDEAGGlQDJ9w2RD1R3Bphly9Abxv4Q
         NzaK4C8U5cBFREkChkG8WUhEM3L05GI/rSioXHQv2NaueFFrVai7IKCWZJkqZHu6UYCO
         adhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1B5OLyPzDad+a9/JvoswRLL9dkqWt3XLCqj2yVlzJ3g=;
        b=BaM+frKO/0DzG9MuY5jH3mEL60DOQHoltRCBK1YvV8pkPYhM8Dr60p017PwqqoHasq
         vQMxHgSJ0jlNMX+IsGBakYdzNl0mNmOD11CtEkEcKJUPlVhNffbr44oNbTI7eDKf2dpX
         WC0YxjKmVQ5HVY6m7SycFH2pcISnQHS22OQKsYJ31MZb3Exxj8JxtlZhydqaBG5K7XjS
         wVr8yx4iV5Y+2boS0hdoqrm2rnE/AX9LVNqfb5f9x6nEQGjfbnYesz/PR4k5jsz3EX4R
         9O0M1ZIQA98D913yMRaubfHN8CC/e18/h/nzLaNwy20R8n3c7Fj+J6SB9hbLt1b+zYb4
         OeqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EXx39caV;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe31.google.com (mail-vs1-xe31.google.com. [2607:f8b0:4864:20::e31])
        by gmr-mx.google.com with ESMTPS id ls13-20020a17090b350d00b001c62073e04asi931225pjb.2.2022.04.22.10.40.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Apr 2022 10:40:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) client-ip=2607:f8b0:4864:20::e31;
Received: by mail-vs1-xe31.google.com with SMTP id b128so8075525vsc.13
        for <kasan-dev@googlegroups.com>; Fri, 22 Apr 2022 10:40:20 -0700 (PDT)
X-Received: by 2002:a05:6102:390e:b0:324:c2b1:f077 with SMTP id
 e14-20020a056102390e00b00324c2b1f077mr1825856vsu.67.1650649219372; Fri, 22
 Apr 2022 10:40:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220421031738.3168157-1-pcc@google.com> <YmFORWyMAVacycu5@hyeyoo>
 <CAMn1gO5xHZvFSSsW5sTVaUBN_gS-cYYNMG3PnpgCmh7kk_Zx7Q@mail.gmail.com>
 <YmKiDt12Xb/KXX3z@hyeyoo> <CA+fCnZdTPiH_jeiiHCqdTcUdcJ0qajQ0MvqHWTJ1er7w6ABq5A@mail.gmail.com>
In-Reply-To: <CA+fCnZdTPiH_jeiiHCqdTcUdcJ0qajQ0MvqHWTJ1er7w6ABq5A@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Apr 2022 10:40:08 -0700
Message-ID: <CAMn1gO4WOcFqwkcAFi1mXbBrPxz-BqgQ027unx31iCO2fyL=2A@mail.gmail.com>
Subject: Re: [PATCH] mm: make minimum slab alignment a runtime property
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Pekka Enberg <penberg@kernel.org>, cl@linux.org, roman.gushchin@linux.dev, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, David Rientjes <rientjes@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Eric Biederman <ebiederm@xmission.com>, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EXx39caV;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::e31 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Fri, Apr 22, 2022 at 9:09 AM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Fri, Apr 22, 2022 at 2:39 PM Hyeonggon Yoo <42.hyeyoo@gmail.com> wrote:
> >
> > > > kasan_hw_tags_enabled() is also false when kasan is just not initialized yet.
> > > > What about writing a new helper something like kasan_is_disabled()
> > > > instead?
> > >
> > > The decision of whether to enable KASAN is made early, before the slab
> > > allocator is initialized (start_kernel -> smp_prepare_boot_cpu ->
> > > kasan_init_hw_tags vs start_kernel -> mm_init -> kmem_cache_init). If
> > > you think about it, this needs to be the case for KASAN to operate
> > > correctly because it influences the behavior of the slab allocator via
> > > the kasan_*poison* hooks. So I don't think we can end up calling this
> > > function before then.
> >
> > Sounds not bad. I wanted to make sure the value of arch_slab_minaligned()
> > is not changed during its execution.
> >
> > Just some part of me thought something like this would be more
> > intuitive/robust.
> >
> > if (systems_supports_mte() && kasan_arg != KASAN_ARG_OFF)
> >         return MTE_GRANULE_SIZE;
> > else
> >         return __alignof__(unsigned long long);
>
> Hi Hyeonggon,
>
> We could add and use kasan_hw_rags_requested(), which would return
> (systems_supports_mte() && kasan_arg != KASAN_ARG_OFF).
>
> However, I'm not sure we will get a fully static behavior:
> systems_supports_mte() also only starts returning proper result at
> some point during CPU bring-up if I'm not mistaken.
>
> Thanks!

Yes, either way we are going to rely on something that hasn't
obviously been initialized yet, so I think we should stick with what I
have since it's used by the rest of the KASAN code as well.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO4WOcFqwkcAFi1mXbBrPxz-BqgQ027unx31iCO2fyL%3D2A%40mail.gmail.com.
