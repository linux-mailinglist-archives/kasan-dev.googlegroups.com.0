Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQ5I42AAMGQE6UDXR6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 43E8B30C8E2
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 19:04:52 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id k7sf24539509ybm.13
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 10:04:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612289091; cv=pass;
        d=google.com; s=arc-20160816;
        b=fakq6rTLN+bfNF8IwpafHAfTQ66vGjKconenIkJaeHEcaDYtOgM0sWwWSEXSSmckI2
         wkFykym4BnKYDMbd/F2TJeyUdzC7ECw2wlfgPNClK+FLJP/4K5EHhn8yNFGJcF9YLYTf
         5WlgerP5K3VrAz28Kn4sOOpzkaFXmYgbnW1+wtRajGJxhv7PMqc3c1OF2x0QotWFbDg8
         uhurnFJGqGgraKA1WWmu3i+UpUCvQHyL8rrrdDZI7nt3WKNqMlObppx6TNTVxEZoHRuv
         31qkndn1q0cV/9W9BqhQVUmWdvGkVsZ5vVb3Rm8gVn/i7xFzGP3vR43/bWaj2faX8hBV
         6XcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6dZvMcn7LTJFG46XSfAVbZDUaxeM1uGObuDZxPWQJqw=;
        b=hWPp7LitsRzi4bkkT0M+rFigKF8jSrqZXlEFrkFyCc2y4h6Y+GZPQUxObSC3UoHsiR
         2WvIby/apdEshrLlMVxA3kENLulAt3WaXrsybPwPH9tVhQSVS1F4cggzTDo8pJYSJLTb
         FDPZZYAn1WbwaBmyQt5BYWbnX6c5QJqIwgqd2isrC3gb3A7D32+hpAjt5/seKBSLOvLM
         0UPGILkJVdcHjitZhTJipXEk5TDDIAXIliFqPTHCEHM/yAcK8pFtk9qZR4j+r/RNyLTd
         +Wm3ka5ArkKj4V0UwGcarkf5AGRnzAsB7nZkWZ5d6pvlse++JkclTM3pBOmkLIHcyoDi
         59Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bmHbrW4w;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6dZvMcn7LTJFG46XSfAVbZDUaxeM1uGObuDZxPWQJqw=;
        b=UL3uwAHI+XH/uebzlhPkZafy6kmvp4GHP65EiANImjKszGls0ciGyEpdPBXO63SUBp
         fml+FyweYzm2q0B6KV/zQhM5puGPzSu/hW4Fx1fUJYxgGHsHIKKV2k1KybTTH84BuaJr
         LtUre+Z+i8nXAPaAoHZ9Xm6Yy0j1KIa0+yXh4OjLNYIgKx7RIV7iYtW2UaUrkInCQCBp
         nYrh4uzii36U3uPW0ghUi/oLqbe2ts9Udxmmqfr88MwgOkyIlBjJqILvdXFHk0WTFJxb
         bNd1zFALWn3obAFdw9ooDFejxoyBHcc12v2wBxVlLZ0sQTP6fseONojnNhAE2KC7PExN
         fDdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6dZvMcn7LTJFG46XSfAVbZDUaxeM1uGObuDZxPWQJqw=;
        b=EGzkag9njNvPOckKzqFx1yS/FPMRkKrYqP3NVXKDL9sWvNp65FJfQJZAmtf3MGR3nV
         ul4XRR1vYgFN+oRCOeEfLwlVy3lPl40mJZ3a+QkoaLqL6NSTwyx6EzqZPSBIq3hvWgR9
         IexMMAwqM062FQUgKbs7pWl9p8KQpBKnEImkV3ut2ASlBHuPbGaNv5MhClN4pDJRfZH3
         ZhB7hWIxEVHPjMgrFRZmy8KzdnYw4Uk6/dx49uiV4TXspJZBiNbtYwXjXwdaZSP6Er7M
         RBi33Up5ZxZfdbjMrM1qAqXys9HNPgggA4JLkJowK5g933jYSlYWav8mnS8JEO6blI9M
         lSxA==
X-Gm-Message-State: AOAM532L81c7vXE2EajpseNypTaDLzu80TwXPjNPfQZJmiBFitShgiYB
	MI1sapruXa6LUH52B7a7v1c=
X-Google-Smtp-Source: ABdhPJwTfwExXjrmTLSfXBp67jtniWbYHh0QtgRIi7gtgsniVbOCa3Pv3QLYKZeVdHZHuQPFe5HdBQ==
X-Received: by 2002:a25:9d8e:: with SMTP id v14mr23277021ybp.206.1612289091352;
        Tue, 02 Feb 2021 10:04:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d612:: with SMTP id n18ls5034327ybg.9.gmail; Tue, 02 Feb
 2021 10:04:51 -0800 (PST)
X-Received: by 2002:a25:d089:: with SMTP id h131mr22256882ybg.409.1612289091061;
        Tue, 02 Feb 2021 10:04:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612289091; cv=none;
        d=google.com; s=arc-20160816;
        b=tzi4CAGLQBEUSjEWxKW1cvU5sYfzFtRdPDNKzSaeJY6TxTXuSKavgsmdtNroHmqAJM
         oygavDybGG+1SBapY2yywTbiEEjeAUpesRr+CUSmpnmE5OPnwHJ7LiMeOKHPJX5cFHiT
         D/UHOcG1ddwhPgstnKx/enQDsv0iuQyE6guLltk45i3qVbF3lDwgNS55ulWD3NYW1Pu0
         6B3NDHB1nBkXx4bv9AnT78DMHmt3e0fk7U1DR+AbJjilNFDTmIoGvFNiaEkTz0d14QQ3
         tjW4N/0p+5M3xWs83bS1giocrhcSxAJNzZ/VqkeuUQpNV/YnlHf82aB3wK3C9G7+9r1d
         tGEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bkJ396ovGQTUsRhCdFoZILK6dCLPexHJ2EGZdWor+hw=;
        b=P9BwroH+dTyWK48CPsawQCovGpvfwIvfZ0jqLHCjNeOoy7pqYRZz1HztnVxhP1PWBU
         UE1JgmdYgHEwOC+Wg09zh1GK/FpDkFOAnIycVOSZw7j+r3PJN1o/u7CQJsJSk9i1cHqh
         EmOwadqTwRAh7AOKOleh19TTcYsuP8cISIkcFZF5zJUDySnxjhiRNWCgdryqOlHNFlYd
         bqRk299fTuMn58FiaHNO8Zi2mityBf6m6Uq7vB2bcs5y9iCrgDz4GX6Ij6yTQfRFYzOx
         AE95iBfBSllhyVTwO9eV+K0HnJOUGNwgOu62Ve42J84fZf86puoCnegw2Yh3IFsK+KT7
         t1LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bmHbrW4w;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id b16si1279547ybq.0.2021.02.02.10.04.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 10:04:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id m12so2759862pjs.4
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 10:04:51 -0800 (PST)
X-Received: by 2002:a17:90b:30d4:: with SMTP id hi20mr5325944pjb.41.1612289090058;
 Tue, 02 Feb 2021 10:04:50 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com> <17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
 <20210202154200.GC26895@gaia>
In-Reply-To: <20210202154200.GC26895@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 19:04:38 +0100
Message-ID: <CAAeHK+y31RvnR2UPtekuscAd=Ogk5zouW_kzxPm7-mVotpqQOA@mail.gmail.com>
Subject: Re: [PATCH 10/12] arm64: kasan: simplify and inline MTE functions
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bmHbrW4w;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1033
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Feb 2, 2021 at 4:42 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Mon, Feb 01, 2021 at 08:43:34PM +0100, Andrey Konovalov wrote:
> > +/*
> > + * Assign allocation tags for a region of memory based on the pointer tag.
> > + * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> > + * size must be non-zero and MTE_GRANULE_SIZE aligned.
> > + */
>
> OK, so we rely on the caller to sanity-check the range. Fine by me but I
> can see (un)poison_range() only doing this for the size. Do we guarantee
> that the start address is aligned?

See the previous patch in the series. kasan_poison() checks and warns
on both unaligned addr and size. kasan_unpoison() checks addr and
rounds up size.

> > +static __always_inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> > +{
> > +     u64 curr, end;
> > +
> > +     if (!size)
> > +             return;
> > +
> > +     curr = (u64)__tag_set(addr, tag);
> > +     end = curr + size;
> > +
> > +     do {
> > +             /*
> > +              * 'asm volatile' is required to prevent the compiler to move
> > +              * the statement outside of the loop.
> > +              */
> > +             asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> > +                          :
> > +                          : "r" (curr)
> > +                          : "memory");
> > +
> > +             curr += MTE_GRANULE_SIZE;
> > +     } while (curr != end);
> > +}
> >
> >  void mte_enable_kernel_sync(void);
> >  void mte_enable_kernel_async(void);
> > @@ -47,10 +95,12 @@ static inline u8 mte_get_mem_tag(void *addr)
> >  {
> >       return 0xFF;
> >  }
> > +
> >  static inline u8 mte_get_random_tag(void)
> >  {
> >       return 0xFF;
> >  }
> > +
> >  static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>
> This function used to return a pointer and that's what the dummy static
> inline does here. However, the new mte_set_mem_tag_range() doesn't
> return anything. We should have consistency between the two (the new
> static void definition is fine by me).

Right, forgot to update the empty function definition. Will do in v2.

>
> Otherwise the patch looks fine.
>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By31RvnR2UPtekuscAd%3DOgk5zouW_kzxPm7-mVotpqQOA%40mail.gmail.com.
