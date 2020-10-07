Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBZU2675QKGQE5OPAONI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id E2B622860FD
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Oct 2020 16:15:02 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id ga21sf842930ejb.14
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Oct 2020 07:15:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602080102; cv=pass;
        d=google.com; s=arc-20160816;
        b=S1XUUxQaLuugRxmxUrCQVUdplfbDmtDLFSPilmBIl1i4IuYg2DUYCYlkXB0tssPmVq
         rFNCfGGtUoC6ZhROS7jhyA3rKYDml8DAEnusg8IDS6IpN+lHbBe+1Nto4Pz0qGGjU4CZ
         NgMmPPY73rHnr+Xa5S8B+gnepe+8etQN3AWKlj4LcnIKrHuSeLRMaocTesyiXPUMxxAg
         McBnlk95XCc3owAaqzheF5mzu+k2cOUroPQEepsKFGYa2KqEem86icZ7JP8ieCrssTKm
         efST5+MW5weeN0TaRCo41mHdKIVkKhd1ojGxYV+JA/ASIpjalinF3EB2T66/6vsOmGw2
         evzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+bN4iQMdvEFSBN5puxmml56DbZ6Abd5RL84dTLQ/UKk=;
        b=ZDz0PkzTYu1D8EMYa3zdxmk9GG9Z1e52njv/lMZR8PerO3X9DEZuTTs2mewyyLNIRm
         FUiGx2zjI08Sn6HWuKzXNsfNb/soHTVOAHfl5Zu4bcUKxsgZgv+Lw9LLBHM/dJBaH6xy
         +XvTc29EW8HJG96Rn5Q+YblBtGHHtMqzgNLlMlszYXeh3aOB3o1G2dAxPdLCWxi55b2M
         k3u00InOIzFm+l7R2tBV12KI1l/2kr3Ucz9AqOlodsK6sKwK5BJ1bAqIe7szWM6NUYrp
         87BVpQrEGeIemoVsuEQZcg8pq/BUc8Cd8EzR/+5Gaze3aV8VETLPvxyFTASznmAmv4MY
         tn2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WCPWazuY;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+bN4iQMdvEFSBN5puxmml56DbZ6Abd5RL84dTLQ/UKk=;
        b=iC5GPkvuTHTAU1lNKoKa5UXJIsamr97AE2cu5DPA+tMscTSqo74lCw/3rWQ9ZVlAgZ
         1+Vb7314EMEjrzynO2lVj6i5DB07HrhVN7CxonOPkFL8y4jHRwfJv36wbRuZw6aRbs1P
         NgP2K8wtom1qkV1fkdqlRwHWVYFPRKlWLaMcMREIOzoQ8yszzBsb741e+MziVruCKY7v
         TmoKOAtVkmeeZ25XroaxihpsqO+iX5xnClB1C4Rd4XHGDn7AuNcManexOb/n9mXeB8WP
         56gaXUjN3R0oI3lDZNJlef/e+sNCHEWgZT1DLHycYTf/FMg95v81Xtinv4OfYee74f5V
         V9ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+bN4iQMdvEFSBN5puxmml56DbZ6Abd5RL84dTLQ/UKk=;
        b=ALuq1zsikBH20PUxArNvKEdO8Bd+lOUuf7biMvN3z6Fhik5JnQUUB0gajq5MyU6Afa
         o3BW84F5cCu9TUjQHku0Rf6WHBvoaxoPTkO9U/7xn4eVb5WXU2beKwsN0qMwLv0nG63A
         E3nG/6ahR2eLIvgVH1X67g010cM1uQpHvCRx+TQxG72VbCIfgPivV8uevFd04Lc5O07o
         vsDwTpScWCt1OadG8liUKiymq+7OtNGNY+QwFfsBGVNWSCDfie2QfBt6wSfglWhePXiO
         TQNvwHxGMdcfMDMjpV2oFRs7e32sgSqzSi9WVHWr2gON6/aYMv4Py2k6gQDD/xkrSS3y
         +0VQ==
X-Gm-Message-State: AOAM530+G2qE/NPx8bK00r8cTMrkvu6TDc0tgjD4sAyuHmyRkHJ2ZfKL
	h1ehwhGlNE6Nl91KW7PMPkY=
X-Google-Smtp-Source: ABdhPJwRmO+zP0g3on/YpyfllBiKZGBy508VMh60GyqBzXCw5e//TYubfZkSSQ+CR2y4Az46cpmk1g==
X-Received: by 2002:a17:906:1b01:: with SMTP id o1mr3739947ejg.539.1602080102524;
        Wed, 07 Oct 2020 07:15:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cc8b:: with SMTP id p11ls1105664edt.3.gmail; Wed, 07 Oct
 2020 07:15:01 -0700 (PDT)
X-Received: by 2002:a05:6402:7d2:: with SMTP id u18mr3836050edy.69.1602080101612;
        Wed, 07 Oct 2020 07:15:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602080101; cv=none;
        d=google.com; s=arc-20160816;
        b=r5xnzVcQo5ffN4tSJDnOkEN6afLp6pZET4CA7IuNPEyfDetNOaJlN7SuHVyTb/DWl6
         qa9U6I5SBAYXuDtlU5DSFMyLyBWMGZbtyvDQ8e83gYVFt47j4z7bCd0vqQysfZViS7JS
         huB9WQgTp2FRrVG79gs6ePboJczcsENs3jsyeskRAigavXPBisRC2B/J8Hb/DqudQi2h
         VJqmhroJJoOI9x3MYBhh5PIVQS/zjTBXX7/vAxrzAq4fjKvVZJ+3vVT1RUpk1Ld3KMRe
         BoxHAV+LlgK0Mm5HWiXIxSZad6CwTdi85BR5HNSUvdHSGzwURhAedsPfFVCGcjESlxzZ
         MdPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MIy1jMlxCOJ0Y5mtMw96kWf8MP2ZqHwIF09OmCxHd/s=;
        b=f8wH/ig2BiQPxPVZxU6o/BgCB5AwlN538n258A636ZGjRw94lvFFNUX+YTcDgTfe9I
         1DlnndC8JYx/8qwlhSetDJv5mnH2LZyADouA72mcG8k21Ci+IMOCVORMYJyFAKODyBrg
         94wQK4aj/rewqNKEWYYUMavLcNZlJh2q/rco/N1jWgi2lpxWf7rmXvG7prA7jOf7AEwy
         hFKRaqOESbzSapyk2YZoG5P7AHdQ1mgfbZVnEc02m/jotkBSimxoeZUTgtqRt2hhglNP
         GTdI4sNe9wSxi7GNrMYh+BLkHmwXfR5fij+yp4jyU5y5vxkHyhz+UHrBo8dJdkUbwI/K
         G0OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WCPWazuY;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x543.google.com (mail-ed1-x543.google.com. [2a00:1450:4864:20::543])
        by gmr-mx.google.com with ESMTPS id dk15si83836edb.2.2020.10.07.07.15.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Oct 2020 07:15:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) client-ip=2a00:1450:4864:20::543;
Received: by mail-ed1-x543.google.com with SMTP id t21so2338659eds.6
        for <kasan-dev@googlegroups.com>; Wed, 07 Oct 2020 07:15:01 -0700 (PDT)
X-Received: by 2002:a05:6402:b0e:: with SMTP id bm14mr3934250edb.259.1602080101068;
 Wed, 07 Oct 2020 07:15:01 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-3-elver@google.com>
 <CAG48ez3OKj5Y8BURmqU9BAYWFJH8E8B5Dj9c0=UHutqf7r3hhg@mail.gmail.com> <CANpmjNP6mukCZ931_aW9dDqbkOyv=a2zbS7MuEMkE+unb7nYeg@mail.gmail.com>
In-Reply-To: <CANpmjNP6mukCZ931_aW9dDqbkOyv=a2zbS7MuEMkE+unb7nYeg@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Oct 2020 16:14:34 +0200
Message-ID: <CAG48ez0sYZof_PDdNrqPUnNOCz1wcauma+zWJbF+VdUuO6x31w@mail.gmail.com>
Subject: Re: [PATCH v4 02/11] x86, kfence: enable KFENCE for x86
To: Marco Elver <elver@google.com>
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
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WCPWazuY;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as
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

On Wed, Oct 7, 2020 at 3:09 PM Marco Elver <elver@google.com> wrote:
> On Fri, 2 Oct 2020 at 07:45, Jann Horn <jannh@google.com> wrote:
> > On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > > Add architecture specific implementation details for KFENCE and enable
> > > KFENCE for the x86 architecture. In particular, this implements the
> > > required interface in <asm/kfence.h> for setting up the pool and
> > > providing helper functions for protecting and unprotecting pages.
> > >
> > > For x86, we need to ensure that the pool uses 4K pages, which is done
> > > using the set_memory_4k() helper function.
> > [...]
> > > diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
> > [...]
> > > +/* Protect the given page and flush TLBs. */
> > > +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> > > +{
> > > +       unsigned int level;
> > > +       pte_t *pte = lookup_address(addr, &level);
> > > +
> > > +       if (!pte || level != PG_LEVEL_4K)
> >
> > Do we actually expect this to happen, or is this just a "robustness"
> > check? If we don't expect this to happen, there should be a WARN_ON()
> > around the condition.
>
> It's not obvious here, but we already have this covered with a WARN:
> the core.c code has a KFENCE_WARN_ON, which disables KFENCE on a
> warning.

So for this specific branch: Can it ever happen? If not, please either
remove it or add WARN_ON(). That serves two functions: It ensures that
if something unexpected happens, we see a warning, and it hints to
people reading the code "this isn't actually expected to happen, you
don't have to wrack your brain trying to figure out for which scenario
this branch is intended".

> > > +               return false;
> > > +
> > > +       if (protect)
> > > +               set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> > > +       else
> > > +               set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> >
> > Hmm... do we have this helper (instead of using the existing helpers
> > for modifying memory permissions) to work around the allocation out of
> > the data section?
>
> I just played around with using the set_memory.c functions, to remind
> myself why this didn't work. I experimented with using
> set_memory_{np,p}() functions; set_memory_p() isn't implemented, but
> is easily added (which I did for below experiment). However, this
> didn't quite work:
[...]
> For one, smp_call_function_many_cond() doesn't want to be called with
> interrupts disabled, and we may very well get a KFENCE allocation or
> page fault with interrupts disabled / within interrupts.
>
> Therefore, to be safe, we should avoid IPIs.

set_direct_map_invalid_noflush() does that, too, I think? And that's
already implemented for both arm64 and x86.

> It follows that setting
> the page attribute is best-effort, and we can tolerate some
> inaccuracy. Lazy fault handling should take care of faults after we
> set the page as PRESENT.
[...]
> > Shouldn't kfence_handle_page_fault() happen after prefetch handling,
> > at least? Maybe directly above the "oops" label?
>
> Good question. AFAIK it doesn't matter, as is_kfence_address() should
> never apply for any of those that follow, right? In any case, it
> shouldn't hurt to move it down.

is_prefetch() ignores any #PF not caused by instruction fetch if it
comes from kernel mode and the faulting instruction is one of the
PREFETCH* instructions. (Which is not supposed to happen - the
processor should just be ignoring the fault for PREFETCH instead of
generating an exception AFAIK. But the comments say that this is about
CPU bugs and stuff.) While this is probably not a big deal anymore
partly because the kernel doesn't use software prefetching in many
places anymore, it seems to me like, in principle, this could also
cause page faults that should be ignored in KFENCE regions if someone
tries to do PREFETCH on an out-of-bounds array element or a dangling
pointer or something.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0sYZof_PDdNrqPUnNOCz1wcauma%2BzWJbF%2BVdUuO6x31w%40mail.gmail.com.
