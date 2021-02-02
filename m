Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY4442AAMGQEY564WCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D08B30C7FA
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 18:39:49 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id h13sf15483652qvs.13
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 09:39:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612287588; cv=pass;
        d=google.com; s=arc-20160816;
        b=zZELqcd3giQlUZsOLL6PXVKI9kBLD3TR5PZu2e9CX8FrjRRYL5meDS9bu0W2RiW9kB
         rl3HDNrUtuYjeMvRdlzCBsz/CQXSTIlSDav6qoZl7eI1m581KRa9P2SEKv5kolgQKqK5
         6WqDkL57S1v0ZqIza+C/gXBmsVIWdzzHANVZUSTy7IINshRpYeAP7j5Waf+63gBpYuqN
         HFY6XsrQ/xAZCcjW1C2J1Mu+v9nKVTFQfympnLXD14N99j3E6eb0CBSfDZmDTx3JZlUV
         1eIMa80qKQQjjhlC/xozb++946yR/gKzVMKeM6pfGd7yKQAsqRhYNFmuB40lCUUxbqXe
         m9EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OK2B+thK5z0wpmlLmvOoxFi0qBILTqdRTmu8m/89Etg=;
        b=gFVj/xV6k4roNqRUwahmqvVZ+od0yI2OehuA9CklsX2VxfyAr1/SomBPnUon+W0bQr
         iMeSyenVE9LAnYU7/XPR7rEc+DCOlHbSe2qmwv6wfZW062JYKyD5Y9Zlh8CTm4ZwYlhl
         qWkvFACEelFgD3A9OLvA85ABZhrVvR1FXRCIG1Hr0EcIzlSqebzWy/Mgwek5aEhlrOk4
         9HihYRrtkbwhl33F+iM9eilq+dFWH2fuNNCnZyoOr+elDhXitGxuJHDIO+P1GGJJcdQL
         DYvUluCIMxb+lem5/jkBWuW26FR3LXK7ha56ylve8JQil0bsxF+B/YTkxix7Pd+GPFjH
         hoLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PXjuYV0c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OK2B+thK5z0wpmlLmvOoxFi0qBILTqdRTmu8m/89Etg=;
        b=g/spdM437GlimS6KoaMuwmTYgFSViD7I3UUV8oQpwR/FAH0NZA27X1hprAV5UGYF2v
         sRjqIxMbcIkggKzgwPX6hfPn0fc4BD6U3Vvd3PwdjrMlCm4UDVrpPcuQsagG6RY6FJRr
         tJ35OcWV/wrjtNScIi9DHDPB95IzWK7+RqFiDXkndsMrCRWuKBXDGmNKlRVj9SPeWm3R
         g0y4zeyY1nurXhWjd0zx2F4C5Dd9oxReFREB2/3Fu9BSRMpOFdkWJvCAYLDjtKb4Caf/
         ysO2p6iIgQqCCakmektKlU+KGcwnhm9ekzivcReIIqLbg7/g9e/JkGNgFB2/u1w+4LQb
         ioqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OK2B+thK5z0wpmlLmvOoxFi0qBILTqdRTmu8m/89Etg=;
        b=Jl6rWo+TdwJ5VwQdcZ3S73kglXHcz/gSHDK99jsd0i2cJxMjj8DHyujs70xucW1+t9
         g1WQnue9CG1QBF9g/Twd5tqT+IkVIaWSbW6h4koI30yhrsH4d2CtDytFsOpPvLhgHzzO
         +KQCr9P/shUWeKdNBHVwDrmHS/QyTkeZwBLj/Ex080oRy5KfyF++yYplT7wqnV3yjYmc
         wbjwb087M8IUx+VRffliO2BmZ1Vhwz/p5siYfjQCDQZtqru/RY4t5hYsJGAvBOftpKHy
         hH4LK1K6blF9bAtVx7TyAZjMcAnUcSAUXiVSuI9/Ecepabpbm+ZiQbt7N2Fgr1zQ42yv
         cVAA==
X-Gm-Message-State: AOAM531EU+Ji7OeIBaPHnXYCPi7kLhU1AJEpQ7N/Zbokyf9gfMotMPH4
	9bfnCQCppOiGOO/kUSBMei0=
X-Google-Smtp-Source: ABdhPJxI/dgAKxcHxZ4DvEMfVT5lkXaG2zoAhYBswf54AiyCkoLxNlT6CKLO8hFNaDBheoSmVWvDJQ==
X-Received: by 2002:a05:622a:453:: with SMTP id o19mr21287056qtx.344.1612287587891;
        Tue, 02 Feb 2021 09:39:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:90b:: with SMTP id 11ls10883212qkj.9.gmail; Tue, 02 Feb
 2021 09:39:47 -0800 (PST)
X-Received: by 2002:a37:a2c3:: with SMTP id l186mr22510914qke.106.1612287587430;
        Tue, 02 Feb 2021 09:39:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612287587; cv=none;
        d=google.com; s=arc-20160816;
        b=NXHH3qptRCQoopXvb/0YOaTZAbfvgCxkOqP2EpsjIMp9JbYIJ/4s1BHDY1yOmUVU1a
         Ty3l1Uz5d8EXiQ4U/n7V/RZk16ZBevZt6u5Sbgx+LMO1GYRWFjVlEGBuCwYGJsVIhE5n
         NO/NtLvjwt24O2koM0skOolLyvsGFGVWwjBPVcfnzScxmoQFonOSfpZSxU008D2Tys4x
         00AqQ1trkptditJ0xKYHhQ33IkVNZ0zsHYjU44a+vb+AeEypcgNz2PZ8oxXfjRPu16Cu
         Mtjd7oT5ZpTSoGFJyiu0J4GPV2AFnPqJmB5rKGoUrk0LCWQp6yoogVohTUIRFe1cNKj7
         vdiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BII6X9VkkCmC/J7Ey1mCa41oEbJr520MWQnzH5Xhv9Q=;
        b=G/zA0fVIGZzr2saX7o55ghBysImcGMdszzW34Udw7Sd+rP2CBuz+9w+fIfDiULLEj2
         G12I52WM6Fp7SvbL3llQhwJNllHtIWHQijqk6FcKGfc3C1Cmj+kkJf+WiQk0sisdSOXq
         bqBkx0QyMv+wx9BRn3gtKV7pitK/WzzRel5UeDvArDE4cOydknQgVx8xasQKii9ku/Fk
         xsh1nZqcKwh3EmK6abvAAF1aBJIRaLEmZNLIwqA2zSYlOCBnc5rPvnUZha8Vdm8yPSiD
         dNrbBK5d7577gqz7tUcQEq0B3EdnWTqLBgNiPIpzC3Uu/XEuuFJKoGSRiN4A9xiWOhr/
         A8FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PXjuYV0c;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id m8si766264qkh.4.2021.02.02.09.39.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 09:39:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id 36so20626494otp.2
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 09:39:47 -0800 (PST)
X-Received: by 2002:a9d:4687:: with SMTP id z7mr16664460ote.233.1612287586711;
 Tue, 02 Feb 2021 09:39:46 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com> <b3a02f4f7cda00c87af170c1bf555996a9c6788c.1612208222.git.andreyknvl@google.com>
 <YBl9C+q84BqiFd4F@elver.google.com> <CAAeHK+xzBpdzO7BmdVZe3_g5Di+-AGyYAO5zBVvOpEUtXD8koA@mail.gmail.com>
In-Reply-To: <CAAeHK+xzBpdzO7BmdVZe3_g5Di+-AGyYAO5zBVvOpEUtXD8koA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 18:39:35 +0100
Message-ID: <CANpmjNNf7i4EoehOC_Zx_gHax3AU7HTxWBXfeTkJxZv8ezYgcw@mail.gmail.com>
Subject: Re: [PATCH 02/12] kasan, mm: optimize kmalloc poisoning
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PXjuYV0c;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Tue, 2 Feb 2021 at 18:16, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Tue, Feb 2, 2021 at 5:25 PM Marco Elver <elver@google.com> wrote:
> >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +
> > > +/**
> > > + * kasan_poison_last_granule - mark the last granule of the memory range as
> > > + * unaccessible
> > > + * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> > > + * @size - range size
> > > + *
> > > + * This function is only available for the generic mode, as it's the only mode
> > > + * that has partially poisoned memory granules.
> > > + */
> > > +void kasan_poison_last_granule(const void *address, size_t size);
> > > +
> > > +#else /* CONFIG_KASAN_GENERIC */
> > > +
> > > +static inline void kasan_poison_last_granule(const void *address, size_t size) { }
>
> ^
>
> > > +
> > > +#endif /* CONFIG_KASAN_GENERIC */
> > > +
> > >  /*
> > >   * Exported functions for interfaces called from assembly or from generated
> > >   * code. Declarations here to avoid warning about missing declarations.
>
> > > @@ -96,6 +92,16 @@ void kasan_poison(const void *address, size_t size, u8 value)
> > >  }
> > >  EXPORT_SYMBOL(kasan_poison);
> > >
> > > +#ifdef CONFIG_KASAN_GENERIC
> > > +void kasan_poison_last_granule(const void *address, size_t size)
> > > +{
> > > +     if (size & KASAN_GRANULE_MASK) {
> > > +             u8 *shadow = (u8 *)kasan_mem_to_shadow(address + size);
> > > +             *shadow = size & KASAN_GRANULE_MASK;
> > > +     }
> > > +}
> > > +#endif
> >
> > The function declaration still needs to exist in the dead branch if
> > !IS_ENABLED(CONFIG_KASAN_GENERIC). It appears in that case it's declared
> > (in kasan.h), but not defined.  We shouldn't get linker errors because
> > the optimizer should remove the dead branch. Nevertheless, is this code
> > generally acceptable?
>
> The function is defined as empty when !CONFIG_KASAN_GENERIC, see above.

I missed that, thanks.

Reviewed-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNf7i4EoehOC_Zx_gHax3AU7HTxWBXfeTkJxZv8ezYgcw%40mail.gmail.com.
