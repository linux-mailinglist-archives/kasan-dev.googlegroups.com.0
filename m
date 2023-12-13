Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBGC46VQMGQEOSD6LJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 80BD0811A0F
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 17:51:18 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-6cede2117absf2801552b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 08:51:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702486277; cv=pass;
        d=google.com; s=arc-20160816;
        b=XMbZy2or3bKp0WJ/XJpI5zqYtCBE0lQhbv4S8Aqq5s0zs1G0o9etU5gNJ4KPrNwi6s
         m3Q7CmRw17LugFEHclwTlOg+v2uLqQOHtIX3H/KQjyJYksMQcTn5i9ZzNq5XadORXlH0
         IQNdmHRYE91a+CMyBPdH8Bod8VG1vVbi3VTY0wcAh/Cwa+YF+vE/aTJaQBvXEQCwhQIT
         4XNm+DtczjxUYInrmRIFhDvpkYNm8ds0rbrWmbu22PnDSkDoSI4fdxDawM7FJxQHhsLs
         jibzqM+orxH1K1za75eru/7MddPbQplkEIJ136xJnLgkpdfKlqsu8Jz1SVNMJTGPfEIx
         UcWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=saaiIN9bOW/ihcCtSOkLpgsV1v/hGlCAhQX+VKJqSBE=;
        fh=3FKCVC//Yac2hNhdFRoFMslNZC8BrjZt1RZflXUZVZY=;
        b=GwrN2XauhQ/ldHrbkrEOoW9sXgeTE4r+Ptb9IxNTrQmkO8Zj5/FkAgGezJul+VC7Pl
         LuHyH9e3kxxpklMFfzaCEHEQIGKA4GFB0wIxZRfiBf6kbrrfBGnSKjWmLICegnRtJP7C
         x8KpMIPHIp1ryuikSbpCKUAqyh1JL79SgneBqOSQECqNlfKU0G7CxTh19GOUqaQHgS7Q
         Cx5YlnF1a7elduMdNdEFFXF+TPma6cylwHuKM+GH3u5yqfLCIsb3rsP0v3F6jcKNVAK8
         7wpIBAleI9lN2xDH7OQqwIsh8+7az5D4deBoeKCYnqkGQw5W7gCbpgAnjeFgGKy7semV
         6xsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iVrrLWzn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702486277; x=1703091077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=saaiIN9bOW/ihcCtSOkLpgsV1v/hGlCAhQX+VKJqSBE=;
        b=T1oC3f4u05vWbp1Za3ggMnlzMAAP7AvfdMX0uILeP1VAqFLg5V+gZRst0spKUw70dN
         beAiP60HFA9rRMMGsoa+4hwTYa7WIHZVfwjlGj0T7v5viF8wux625EQL7qTeaC61UCG2
         bkGh03M3hxL6mKloU+rv/jLcZa7Dr4xo/uv0v7vPfcW8GqIPQrG0PK1LyXC+OxzfNIDW
         4YFs7B2ENDhDg514kmbJz/R1W0b0NqAtcQUe9MkWvKUYdGpJFsP9bzd7hbU8q865Jicq
         lxFnzBjfG4Oa3b5uluB3jm9o+khg2PpcshBBJfHM86TqNwrZjog2LIf3YpcBD486Q3UV
         JlTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702486277; x=1703091077;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=saaiIN9bOW/ihcCtSOkLpgsV1v/hGlCAhQX+VKJqSBE=;
        b=OYGMmGe7EBpwDmP+zCo40aVJZXBvVZi3nOl01VPI1s6fXpblORHPFdEkEHIqJ0YgzF
         KzxB31Ad7A5OKVa9s1d/MNG6DtAWTgObEFKMjx76Xb0XR/HLSt2QGO/LsscWMTPW0w+h
         Z04vOlAG9LygN/HHW1GXjqgDMPCx8hkPDy1pFOsBcyRg8pfbPFreVzcMRPXS8uWhuQEw
         5ZhX+S0J5GY9xqAKpFsaA7L61dKPa8T1b6ljOdSvBjvcYMZ/qOPpofGLZJIClyj+If+R
         0S3MunNxRwEpEnYp54qAF5BkxLUmAOC23kC40T5OysZRPLusMuzmong7Rgt9K4044ZgO
         Pn1A==
X-Gm-Message-State: AOJu0Yz6junGr4oM7UhmJBeUKJ5DWYYcbbst32Dfl7KsiinNk6IefwK5
	BNaP5ecdV9kISp+3vXFB4t0=
X-Google-Smtp-Source: AGHT+IEv52WkhnKY9mDijnDseC1bqLefcvX/+XBjRML0LPvJtZT6kGIPQAWdIz9Rm4mmGFn1sl9gxw==
X-Received: by 2002:a05:6a00:b51:b0:6ce:4fdd:9d32 with SMTP id p17-20020a056a000b5100b006ce4fdd9d32mr3986442pfo.69.1702486276777;
        Wed, 13 Dec 2023 08:51:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4b43:b0:6ce:f521:4ecc with SMTP id
 kr3-20020a056a004b4300b006cef5214eccls1655415pfb.2.-pod-prod-02-us; Wed, 13
 Dec 2023 08:51:15 -0800 (PST)
X-Received: by 2002:a05:6a00:886:b0:6d0:8895:2cb with SMTP id q6-20020a056a00088600b006d0889502cbmr3276270pfj.34.1702486275589;
        Wed, 13 Dec 2023 08:51:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702486275; cv=none;
        d=google.com; s=arc-20160816;
        b=aKrm0sFzj6kmy180g3Guv97vESVviNkVKaCPcH0Cxazq3sFXtClxKZ2XDDd9+esYjQ
         yzCdUA9BMetJIbS/yoJCWHBtrqx1l0EHQlnRd+9v82KXWlpShL+sHpiVCfpKt1NXZf5f
         l4YFHyi2sNegzqTL0r8zcFfDul+g0JKY3xJeHFh4M7ynUN/8lvbnJNymxxkl7dKWL3H9
         etSx7ZaQh5TEQ3R9D3waYSq13lOrMX9pKTzT+uDDOHXBauuhubXfzbpPtf//6Un3YcAw
         dOL5LXBSneXE51O+cYVVUGbg8grHjWMZ4dKzVtikXHT8l2aRqeocf9gjk65JPmKVcI5A
         eOWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+aZ9Gls1BogU2MReoFJauXP2UgnNIXaBIdamecIfCjI=;
        fh=3FKCVC//Yac2hNhdFRoFMslNZC8BrjZt1RZflXUZVZY=;
        b=dfwQ5FKKngdxrlRxVk+ORtEL5fBYNRo2+aJ7QVNpWM0bIfWG9MD5VLheOgxfRGcGHz
         2fqv9AT3cwCWR5wv3KOu/qhRzunMV0PFc9fJz1QO/kO+GReNZJhp8l/mF6e1kLX4WS+c
         DBCE2Nc2LRxDpjWYjbiG5RZIJTfV9+3SjjYce2K1L04ccgb7I4Y9RqNim1J0ni+LXCPU
         0Aps9qQGG12MF68EbTtBwNs/vsaBv33FE9RZw1o+e1GBryI7BO6Ar6kw4e97R2JPLJDf
         bn8sMMZRmPApjoK6eNEpc7k27KD+0COIARhf2pr2lVFby31i1+/0Bv7a+Xi/ARyCHW8V
         7W/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iVrrLWzn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92b.google.com (mail-ua1-x92b.google.com. [2607:f8b0:4864:20::92b])
        by gmr-mx.google.com with ESMTPS id x24-20020aa793b8000000b006ce77f21362si766105pff.5.2023.12.13.08.51.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 08:51:15 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92b as permitted sender) client-ip=2607:f8b0:4864:20::92b;
Received: by mail-ua1-x92b.google.com with SMTP id a1e0cc1a2514c-7c5ed425e8bso1860991241.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 08:51:15 -0800 (PST)
X-Received: by 2002:a05:6102:188c:b0:464:498f:3b6 with SMTP id
 ji12-20020a056102188c00b00464498f03b6mr4870448vsb.22.1702486274436; Wed, 13
 Dec 2023 08:51:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702339432.git.andreyknvl@google.com> <432a89fafce11244287c8af757e73a2eb22a5354.1702339432.git.andreyknvl@google.com>
 <CANpmjNM9Kq9C4f9AMYE9U3JrqofbsrC7cmrP28ZP4ep1CZTWaA@mail.gmail.com> <CA+fCnZcGWXbpwCxk5eoBEMr2_4+8hhEpTefE2h4QQ-9fRv-2Uw@mail.gmail.com>
In-Reply-To: <CA+fCnZcGWXbpwCxk5eoBEMr2_4+8hhEpTefE2h4QQ-9fRv-2Uw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Dec 2023 17:50:36 +0100
Message-ID: <CANpmjNPEofU4wkmuqYegjDZgmP84yrf7Bmfc-t4Wp7UyYvDc7A@mail.gmail.com>
Subject: Re: [PATCH mm 2/4] kasan: handle concurrent kasan_record_aux_stack calls
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	syzbot+186b55175d8360728234@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iVrrLWzn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 13 Dec 2023 at 15:40, Andrey Konovalov <andreyknvl@gmail.com> wrote=
:
>
> On Tue, Dec 12, 2023 at 8:29=E2=80=AFPM Marco Elver <elver@google.com> wr=
ote:
> >
> > > -       stack_depot_put(alloc_meta->aux_stack[1]);
> > > +       new_handle =3D kasan_save_stack(0, depot_flags);
> > > +
> > > +       spin_lock_irqsave(&aux_lock, flags);
> >
> > This is a unnecessary global lock. What's the problem here? As far as
> > I can understand a race is possible where we may end up with
> > duplicated or lost stack handles.
>
> Yes, this is the problem. And this leads to refcount underflows in the
> stack depot code, as we fail to keep precise track of the stack
> traces.
>
> > Since storing this information is best effort anyway, and bugs are
> > rare, a global lock protecting this is overkill.
> >
> > I'd just accept the racyness and use READ_ONCE() / WRITE_ONCE() just
> > to make sure we don't tear any reads/writes and the depot handles are
> > valid.
>
> This will help with the potential tears but will not help with the
> refcount issues.
>
> > There are other more complex schemes [1], but I think they are
> > overkill as well.
> >
> > [1]: Since a depot stack handle is just an u32, we can have a
> >
> >  union {
> >    depot_stack_handle_t handles[2];
> >    atomic64_t atomic_handle;
> >   } aux_stack;
> > (BUILD_BUG_ON somewhere if sizeof handles and atomic_handle mismatch.)
> >
> > Then in the code here create the same union and load atomic_handle.
> > Swap handle[1] into handle[0] and write the new one in handles[1].
> > Then do a cmpxchg loop to store the new atomic_handle.
>
> This approach should work. If you prefer, I can do this instead of a spin=
lock.
>
> But we do need some kind of atomicity while rotating the aux handles
> to make sure nothing gets lost.

Yes, I think that'd be preferable. Although note that not all 32-bit
architectures have 64-bit atomics, so that may be an issue. Another
alternative is to have a spinlock next to the aux_stack (it needs to
be initialized properly). It'll use up a little more space, but that's
for KASAN configs only, so I think it's ok. Certainly better than a
global lock.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPEofU4wkmuqYegjDZgmP84yrf7Bmfc-t4Wp7UyYvDc7A%40mail.gmail.=
com.
