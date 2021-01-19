Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJOCTSAAMGQEF7R7ORA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 701A72FBE9E
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:12:55 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id l191sf16678027ooc.15
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:12:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611079974; cv=pass;
        d=google.com; s=arc-20160816;
        b=pfhymZsoX5Ox5ebdaKaHgzqjkmK6QdhSOAIVshsk0fLb/EVebdqZfzK2OYtHoEeUuI
         LjZfcYzdMBJ6SiI9+lix+2VwIpAOiBtEjCWIhlmMjlXeR5Hes8HyLduySG1FJoQckeQU
         E2O+dXK3OlS8gOz5PYg+Mn6n7vAjVXSRs2JbYR9JilS70siT81ZZ6GG0X/akJZZL3Dty
         kr1ZjyWW5Q8Cs2/uAce4BlJQ8tD3OBVztBhgpFjaB32vi155tO0UNr22/SRJ5uj0e+Er
         JnGrFpyvtdX/o82ZXI0h1CjZJfWHmY2VaZisNgsJm8qZlb+tCumA37aOa0R9vhD48mLn
         +6xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=EpSKSxhdj254Q8DUb+5drzzopK36x2TuHfHs5y1pyts=;
        b=FCeIsR67IHcjyI13iuYBGoen2HP5mi3ncX4SCJln7Ke1APcn070wZn2Qgua1T3w/k4
         EbeCTUod+cSfFAhyf8GSsw1xQR7ItdunVumcspEomYHBgXg/PMytpqg6o4+pQmlpZqdU
         2lRwRA1hsRRjP+mqSE8Dhdy1iUc9DIpwij3kq104jtBSEnAG/rDNKZijjIWER+CBcRH5
         PO2HYUcdzNavDDOp9iT7PgXfCikLcLpHePi6WvsbLMPco4phtzGvgoPttoWK+PIAxEwb
         m+8XNHV0h+RXyklE03Q/kXGMBeGaA/u7qr+6o1m1hL4EcdrarRe8Ht90HTQY26PSNls7
         s1YA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iv99R8t2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EpSKSxhdj254Q8DUb+5drzzopK36x2TuHfHs5y1pyts=;
        b=AUZ8xHiBBpcrylUyBmxfR5O58M/UOaclAOB/N06x4LSVbbZtdLauijD9myON0UNHqX
         Kh1tit5jz/iMLAsOFL6KEn696ttWTv08jC10dEFbbEfhpsspqbgf0gxMRpDcZ7+HlRgj
         Am5rSKTUf0sZG8zqH1iwmqawUYGHI4FFt/bSWL7P9YrahvseuyVtEmDgwEBzZ/hUmMku
         KDqCB+sTajeYrHylVqF1XVQoK0kFJ0eCNI4RmluniTmjKz9KIO1eGqPIJ3b4tH73iMbm
         +O3ru0S46ousE4T5+y7RFac+OniYidoWwRPYVLaypADbpIat7/V9vjLKEYG5Ys1FfL8+
         X+nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EpSKSxhdj254Q8DUb+5drzzopK36x2TuHfHs5y1pyts=;
        b=dGHnS/RmHeAN+OCwRlbLsUDqvEO6BMiUbDkknTi7fBNyja8lL2RfahFm1mfuu9i0oN
         wrVjXNKRlOhJdy2iuaJ4psacN28kHLzfJ00cdNIXFTCVSqjO4TsgJcxxaETuowGV5mla
         r5hILVj1ZC9la33RCvNOUU1FH0hR+7Ll+mNWq5TNiJj500XG/eYGMfF974wvequIfdd1
         /gNRSMUta7I1/XgWfZQm6luE33Fo0t3I+dNuuMhbLOoWQXrc1OpW/Eg4HRKMjxUVj0AZ
         CltsSgJbjhIjKus7XGMpj+eXKv2KdTnJWayC7JoK1C8huw7kfVhKUn8dr+twIg7LBQXa
         wu5Q==
X-Gm-Message-State: AOAM5324Nnp3+8WyNt976W152PKUmIhoj9ZVexN052ldA0HujbZ5VOfO
	CsR+YjfnDkiEUlUXarYPtIE=
X-Google-Smtp-Source: ABdhPJxInRJc9mJYqwoOdA35yluplXVjHBCpPVCLX8g5uNTE1V5KEHugYeAaRsLQxK4nKEAK4dEH6A==
X-Received: by 2002:a9d:6003:: with SMTP id h3mr4209494otj.264.1611079974053;
        Tue, 19 Jan 2021 10:12:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:7259:: with SMTP id r25ls1455927ooe.3.gmail; Tue, 19 Jan
 2021 10:12:53 -0800 (PST)
X-Received: by 2002:a4a:330b:: with SMTP id q11mr3661080ooq.90.1611079973664;
        Tue, 19 Jan 2021 10:12:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611079973; cv=none;
        d=google.com; s=arc-20160816;
        b=MTwqdP9ikBxEIrXshRRpgaTGVoT6FL5WLr5bz24F9FyIi1aO+SWBTYU3OzSMYzm9aU
         1sY9WTiHA3C2NbcSE2FmwDGMjXYfMBvLQV2WUUbd9wlujp1O+R58nYTamn+gV7atPNbe
         1uVvcC+AhbiynE5j1Ndq46V1tAo+1NorVyp8PKYmOim3KaCvtW0t5b03z39To7+XGqCv
         gQj32pTKPyxI9EnTxITZlI32h1GMOk0+qnjSKp7iB7fOcL91EIxUPmyuDtm0PgxyhGTM
         l+1RwypXF1jxudFKqMFFAtJrZAQkk74IKE8/yMkgd0Ls508/YNtaIwKjRjfwX4EohqvT
         F8Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FOoggJCbzXRMl4jyfsPuja537UMtpRuFG/6/vUZLLVw=;
        b=W2McDK67tYs1cOxxPU43dGtEWrLIPG2VyedYLyzW5QjBqB6NBd6XlTSp5r2TIBtVVV
         bCNrjDq44xA5yhy7LyalJXj0Xg7baoejaews8PvL87BC07vZG5CykHhNNzlHOgrFuxDn
         6XmYGbvT+qJAnyOyc/21XCHmYVb6vkI+vaSQh1oEeJeOvsbTwgGAYdQs97LjXZeSGEJm
         UszydKwPW1hcvxAuHKFKc8+SRIgRhgnpxrdtaDby4yzQtaIfh8EFWAPtKYkQeEm13TQO
         CYa61Eo2NG7jNz9cxRCjElSxzJ+VenJGxCAQiHWvEiEmN3tw0U5RYoZZzrF1TD2nDmRm
         Iacg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iv99R8t2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id l126si832556oih.3.2021.01.19.10.12.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 10:12:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id n25so13474556pgb.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 10:12:53 -0800 (PST)
X-Received: by 2002:a63:4644:: with SMTP id v4mr5582075pgk.440.1611079972778;
 Tue, 19 Jan 2021 10:12:52 -0800 (PST)
MIME-Version: 1.0
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-6-vincenzo.frascino@arm.com> <20210119144459.GE17369@gaia>
 <1bb4355f-4341-21a7-0a53-a4a27840adee@arm.com>
In-Reply-To: <1bb4355f-4341-21a7-0a53-a4a27840adee@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 19:12:40 +0100
Message-ID: <CAAeHK+y9sw0SENeDXLLBxD8XqD396rXbg1GeBRDEm7PnMzMmHQ@mail.gmail.com>
Subject: Re: [PATCH v4 5/5] arm64: mte: Inline mte_assign_mem_tag_range()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iv99R8t2;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52c
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

On Tue, Jan 19, 2021 at 4:45 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Catalin,
>
> On 1/19/21 2:45 PM, Catalin Marinas wrote:
> > On Mon, Jan 18, 2021 at 06:30:33PM +0000, Vincenzo Frascino wrote:
> >> mte_assign_mem_tag_range() is called on production KASAN HW hot
> >> paths. It makes sense to inline it in an attempt to reduce the
> >> overhead.
> >>
> >> Inline mte_assign_mem_tag_range() based on the indications provided at
> >> [1].
> >>
> >> [1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/
> >>
> >> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >> Cc: Will Deacon <will@kernel.org>
> >> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >> ---
> >>  arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
> >>  arch/arm64/lib/mte.S         | 15 ---------------
> >>  2 files changed, 25 insertions(+), 16 deletions(-)
> >>
> >> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> >> index 237bb2f7309d..1a6fd53f82c3 100644
> >> --- a/arch/arm64/include/asm/mte.h
> >> +++ b/arch/arm64/include/asm/mte.h
> >> @@ -49,7 +49,31 @@ long get_mte_ctrl(struct task_struct *task);
> >>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
> >>                       unsigned long addr, unsigned long data);
> >>
> >> -void mte_assign_mem_tag_range(void *addr, size_t size);
> >> +static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> >> +{
> >> +    u64 _addr = (u64)addr;
> >> +    u64 _end = _addr + size;
> >> +
> >> +    /*
> >> +     * This function must be invoked from an MTE enabled context.
> >> +     *
> >> +     * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> >> +     * size must be non-zero and MTE_GRANULE_SIZE aligned.
> >> +     */
> >> +    do {
> >> +            /*
> >> +             * 'asm volatile' is required to prevent the compiler to move
> >> +             * the statement outside of the loop.
> >> +             */
> >> +            asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> >> +                         :
> >> +                         : "r" (_addr)
> >> +                         : "memory");
> >> +
> >> +            _addr += MTE_GRANULE_SIZE;
> >> +    } while (_addr != _end);
> >> +}
> >
> > While I'm ok with moving this function to C, I don't think it solves the
> > inlining in the kasan code. The only interface we have to kasan is via
> > mte_{set,get}_mem_tag_range(), so the above function doesn't need to
> > live in a header.
> >
> > If you do want inlining all the way to the kasan code, we should
> > probably move the mte_{set,get}_mem_tag_range() functions to the header
> > as well (and ideally backed by some numbers to show that it matters).
> >
> > Moving it to mte.c also gives us more control on how it's called (we
> > have the WARN_ONs in place in the callers).
> >
>
> Based on the thread [1] this patch contains only an intermediate step to allow
> KASAN to call directly mte_assign_mem_tag_range() in future. At that point I
> think that mte_set_mem_tag_range() can be removed.
>
> If you agree, I would live the things like this to give to Andrey a chance to
> execute on the original plan with a separate series.

I think we should drop this patch from this series as it's unrelated.

I will pick it up into my future optimization series. Then it will be
easier to discuss it in the context. The important part that I needed
is an inlinable C implementation of mte_assign_mem_tag_range(), which
I now have with this patch.

Thanks, Vincenzo!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By9sw0SENeDXLLBxD8XqD396rXbg1GeBRDEm7PnMzMmHQ%40mail.gmail.com.
