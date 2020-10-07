Return-Path: <kasan-dev+bncBC7OBJGL2MHBBINH675QKGQEAJWRH3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C094286163
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Oct 2020 16:41:39 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id k3sf2433868ybk.16
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Oct 2020 07:41:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602081698; cv=pass;
        d=google.com; s=arc-20160816;
        b=QvFMCuSo/+CoYYMvtXqR+erjv+UBwGK+/Z1JPYtGMzysOBhbTZRRbCUmgLChy+W2uB
         vBSveCuNBJdYFkT6GndJCsySspuz8Gwi2Ex5GzzgLlaglNrpfPy4sgQudhxzAc7a8tUe
         x58RGOGMA6M/McPJJnPZUBjD4kzjR4y7ab4kZEv15Gr+im9jirIuzxdTDWB2zrV5vLvX
         5fS2K5q4heajFeDRWKVQMjcG03Pph95TJOFiWocBCtodyolNJHY/15WmCpjfGUVDd1UL
         SU3gU8irOfNJZubzB7zMVsbeuY/Vc3Rtral+cyG6Gaz/T7leepickrAkEPLKoNNlBy9p
         N5nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=meFkH4UNxK3GKvH1CW0VCZshxWinoppvc+ARcQCkFdE=;
        b=m5KLHlSGi+wh6Rd5I9ocAhsmvt+431IHsTde7GrnZH0iXpXxycqq4iP9bEg8u8NH1C
         uUEicL2K5/Y2JtZZlYPxbdv8t3/u7gbrvIeMP84VEKQd2WF7+qs1h6/UtqnqMPSTnojE
         Kx5YW0gdYlKvQaZL/l72mXmuUyZ3XpBkiweS3LTpAiOaoFISXN9zPbizQA9OK98R+/gq
         6RqgdNsky6a9IUZVOvICd662+y63zo1wcCDCBOK5Q9i1nXehbHdeWhBJHWcSbeRXTLtm
         a2smAGWHx7nOhZfsdup3DZvb3I8wgeqOb2V4dCzgJgmCODIBmG3b66IcyJc7tG9AGyzZ
         3wMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="G/1uZ6Me";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=meFkH4UNxK3GKvH1CW0VCZshxWinoppvc+ARcQCkFdE=;
        b=Ojy1XpgGD3e2QYiDnvIHPuT234tA8Ui9rn+NeIQ07qfZ7Jo/HMaipqmuL8DGXzELoE
         dSvPrqo9MoV1cTl3TcGundyMm9gdQkpVN/BrcpjxXJZvCyDN5I+WZhBYrNQYEIL2YInI
         mKjXTmsbB3AJf3xLkeIriSYA+/oMYnE3qe6bNDClPt+r4pvSNPnIjczBS1f0mlHijWbW
         jELIB7zHWNQ8GaWt315yoForzVFt3CaInZlvbPrQENTqj3TD+6fIxnvXcbDD/VrcEFa0
         7AX84Iny+xTVxbBS8eeKLJnEmvf6rSl8x2G/3H7yENmuLL6FJZ9gyIxwXIFNEaUqGBww
         OUzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=meFkH4UNxK3GKvH1CW0VCZshxWinoppvc+ARcQCkFdE=;
        b=KVojNC5R67zRAzbbz7T1DA9xP+VrgSA8DSetR/6vRrFhcvQos+LLmOCHdf9QfmrRCu
         iaocF+SjikB2wfeVNmBXP1xP61OMhjbrf6cNUIedFC9s1e10QT41VUurP/Da5wbkalz+
         5sdyfYvBsrjRoHubAUCvQmZooAZPxYzdDsoc9DtRtvRB+EmztqB+W3RPZImxjWLR0L2j
         KLz+u0gad8r0/xIIQyYrtXkNZZ3ZjoUsyEnx9A56O5fi3MW1nRHn5QVq3qnFsmwRz6HK
         vtHJhrhQy5xd5GECYjUJ/1dFj5N727BtCIIva3boIfqONaD4pfgWAMQY3WhpOL5jeAni
         91AQ==
X-Gm-Message-State: AOAM532jTnGAT0g+3sk+wMFiruX6XJo+RqjqGxLYAC7/RuyTj0JcyRXQ
	+hltKxxPWgsroA1/Jw3zGD4=
X-Google-Smtp-Source: ABdhPJyNz69YTRkW9Gg4UvjUsd7VLrbZy171+OFQ5vCd+0uc0OyYILsYEpHmPa4lbhhuVHh5UC8Rtw==
X-Received: by 2002:a25:c0d5:: with SMTP id c204mr4671279ybf.515.1602081697953;
        Wed, 07 Oct 2020 07:41:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:20c6:: with SMTP id g189ls1116021ybg.1.gmail; Wed, 07
 Oct 2020 07:41:37 -0700 (PDT)
X-Received: by 2002:a5b:dd2:: with SMTP id t18mr4524899ybr.163.1602081697422;
        Wed, 07 Oct 2020 07:41:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602081697; cv=none;
        d=google.com; s=arc-20160816;
        b=RBcra8UCEywaqEwdvO1r3NhREEOekMXLKWMzsf/x0AsZ1+SIXj78rcFPRscJ/ILLFe
         4e+ecxBCLjvz21UTZHr3tI5mmfU7mb75K9UPIyBDZ04SlmhLMjSnL8ZxbXs33MFa0Bvw
         ZGYbv+mJmWPknxSGc8+P5oNfEjZxqzafGBWuxQyokWcDDBvyUnNsXcvYBGORw5yr+oba
         HpUru+XC1VrO2L7iMrHM/7R2IL27cHjmql/iciPkT8e7omgyeTIceZbhCo3+XZ2lAvlK
         Mm0nfjSSgiUa0LKJYUsWXCx08u7b17MqJk3jCTJk1HH2UX2iMgGGIkhdNAgWRJtJcrRx
         sXuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ln7qxyNzii1scl8HLSA2+oOjYgQ14R9ppJu+tWqxheQ=;
        b=C27+35Qk0Sy5R5v77nqw4cFsj7HGLb80rpjxhSpEv8NDbW4X6+jYSjCKjjxjevFbys
         +dvfowdCn3MQPC3qH9O3B5C5VdMvRU+69A74i5x29Wp1TO29pT7Vc8AfMSg2Uxi9NQIP
         md0pOx+P9cje0QiUltW2rvyx7uDqkGw2T/ToDPlUeOyasYP0zrRMvqGt6IVHXEeoFenT
         W7B1uEmy5Foi9pUh3P0fnphkSV0cuYrWKLqyyCCyIH3y82i0CGcHh4QmC3yH6uO00On+
         qqeIyWBiL19+wGuFyElJn0m9tGsKls+WBzzSop8gZToLhHN1pAOCpW5SCD9v/kpq2dAM
         HIlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="G/1uZ6Me";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id s69si201079ybc.4.2020.10.07.07.41.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Oct 2020 07:41:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id q21so2414844ota.8
        for <kasan-dev@googlegroups.com>; Wed, 07 Oct 2020 07:41:37 -0700 (PDT)
X-Received: by 2002:a9d:66a:: with SMTP id 97mr2142529otn.233.1602081696697;
 Wed, 07 Oct 2020 07:41:36 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-3-elver@google.com>
 <CAG48ez3OKj5Y8BURmqU9BAYWFJH8E8B5Dj9c0=UHutqf7r3hhg@mail.gmail.com>
 <CANpmjNP6mukCZ931_aW9dDqbkOyv=a2zbS7MuEMkE+unb7nYeg@mail.gmail.com> <CAG48ez0sYZof_PDdNrqPUnNOCz1wcauma+zWJbF+VdUuO6x31w@mail.gmail.com>
In-Reply-To: <CAG48ez0sYZof_PDdNrqPUnNOCz1wcauma+zWJbF+VdUuO6x31w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Oct 2020 16:41:25 +0200
Message-ID: <CANpmjNOZtkFcyL8FTRTZ6j2yqCOb2Hgsy8eF8n5zgd7mDYezkw@mail.gmail.com>
Subject: Re: [PATCH v4 02/11] x86, kfence: enable KFENCE for x86
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="G/1uZ6Me";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 7 Oct 2020 at 16:15, Jann Horn <jannh@google.com> wrote:
>
> On Wed, Oct 7, 2020 at 3:09 PM Marco Elver <elver@google.com> wrote:
> > On Fri, 2 Oct 2020 at 07:45, Jann Horn <jannh@google.com> wrote:
> > > On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > > > Add architecture specific implementation details for KFENCE and enable
> > > > KFENCE for the x86 architecture. In particular, this implements the
> > > > required interface in <asm/kfence.h> for setting up the pool and
> > > > providing helper functions for protecting and unprotecting pages.
> > > >
> > > > For x86, we need to ensure that the pool uses 4K pages, which is done
> > > > using the set_memory_4k() helper function.
> > > [...]
> > > > diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
> > > [...]
> > > > +/* Protect the given page and flush TLBs. */
> > > > +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> > > > +{
> > > > +       unsigned int level;
> > > > +       pte_t *pte = lookup_address(addr, &level);
> > > > +
> > > > +       if (!pte || level != PG_LEVEL_4K)
> > >
> > > Do we actually expect this to happen, or is this just a "robustness"
> > > check? If we don't expect this to happen, there should be a WARN_ON()
> > > around the condition.
> >
> > It's not obvious here, but we already have this covered with a WARN:
> > the core.c code has a KFENCE_WARN_ON, which disables KFENCE on a
> > warning.
>
> So for this specific branch: Can it ever happen? If not, please either
> remove it or add WARN_ON(). That serves two functions: It ensures that
> if something unexpected happens, we see a warning, and it hints to
> people reading the code "this isn't actually expected to happen, you
> don't have to wrack your brain trying to figure out for which scenario
> this branch is intended".

Perhaps I could have been clearer: we already have this returning
false covered by a WARN+disable KFENCE in core.c.

We'll add another WARN_ON right here, as it doesn't hurt, and
hopefully improves readability.

> > > > +               return false;
> > > > +
> > > > +       if (protect)
> > > > +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> > > > +       else
> > > > +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> > >
> > > Hmm... do we have this helper (instead of using the existing helpers
> > > for modifying memory permissions) to work around the allocation out of
> > > the data section?
> >
> > I just played around with using the set_memory.c functions, to remind
> > myself why this didn't work. I experimented with using
> > set_memory_{np,p}() functions; set_memory_p() isn't implemented, but
> > is easily added (which I did for below experiment). However, this
> > didn't quite work:
> [...]
> > For one, smp_call_function_many_cond() doesn't want to be called with
> > interrupts disabled, and we may very well get a KFENCE allocation or
> > page fault with interrupts disabled / within interrupts.
> >
> > Therefore, to be safe, we should avoid IPIs.
>
> set_direct_map_invalid_noflush() does that, too, I think? And that's
> already implemented for both arm64 and x86.

Sure, that works.

We still want the flush_tlb_one_kernel(), at least so the local CPU's
TLB is flushed.

> > It follows that setting
> > the page attribute is best-effort, and we can tolerate some
> > inaccuracy. Lazy fault handling should take care of faults after we
> > set the page as PRESENT.
> [...]
> > > Shouldn't kfence_handle_page_fault() happen after prefetch handling,
> > > at least? Maybe directly above the "oops" label?
> >
> > Good question. AFAIK it doesn't matter, as is_kfence_address() should
> > never apply for any of those that follow, right? In any case, it
> > shouldn't hurt to move it down.
>
> is_prefetch() ignores any #PF not caused by instruction fetch if it
> comes from kernel mode and the faulting instruction is one of the
> PREFETCH* instructions. (Which is not supposed to happen - the
> processor should just be ignoring the fault for PREFETCH instead of
> generating an exception AFAIK. But the comments say that this is about
> CPU bugs and stuff.) While this is probably not a big deal anymore
> partly because the kernel doesn't use software prefetching in many
> places anymore, it seems to me like, in principle, this could also
> cause page faults that should be ignored in KFENCE regions if someone
> tries to do PREFETCH on an out-of-bounds array element or a dangling
> pointer or something.

Thanks for the clarification.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOZtkFcyL8FTRTZ6j2yqCOb2Hgsy8eF8n5zgd7mDYezkw%40mail.gmail.com.
