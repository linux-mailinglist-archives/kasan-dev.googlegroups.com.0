Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVHN3T5QKGQE2SO37OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FDDD2814D7
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 16:19:01 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id m6sf700082otn.13
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 07:19:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601648340; cv=pass;
        d=google.com; s=arc-20160816;
        b=aO86qvnan8g2+uiCPF2Qm+Qv7u1y6vnnAwCzZ6jN2obVwuXbqaESbv3h+N9YwMUpmW
         BfjdZyBxGrPz7+UY3d7TbIZ7gwsQLHj+5OGtki0DAt6GWDbecIwdFK0f3dumDLmI4pQj
         M4yg+AE9hRLRHyIj0eyg/+N1iutQP5E7yM2J3VAkWPHsaU20CExcCkveeCkqVxmB031g
         x6I86L4s62mZ1WQbkH92wxBfJuBJuTHe4X7upKis0rTf6sI/b/hLtSQM9R1YcsjrMyQ9
         vixvUTUQrvHJTdEZ3yYbhDZ1likExjjsZDFsvYjNHApi8DzH3Or3B0sulxf5Wrfo1UWd
         1M3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UAyNy1ZDTRPHubIy8VyJzqZYviqbDJvZEZA0VFpPWjU=;
        b=dmD68kO8GmroYwvk9tlRlnS8fyV1gCQ/5v4tI4E2myIHLz0jhwQH0qERVjQm4kyjWs
         CwANwXgVPdzx4rX60O+qWjPRcMpUcanKb/pJ/jaWGd64u8Bpw8o3cg+4k+yBdHwMIfly
         xNuaNv82vBeD0ucLXtO+4BvFVqBJaPXp345tS5/7gwNTVmyXLhs9067IlNLs+i7yCBOX
         Ea1dYMqDyxd+h6MdFCbD5PszYMLeQhkrU5qfIHawakzK1/NFoWHVlrqrFJVeD+Z0uGnz
         JHMViKNmkAmntpH8gVeDERYNt7RFsRi0ig5f3UlCyyrq5fG8iYUW94XTpSyXFfdw8ud8
         +iiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="WbL9t9/X";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UAyNy1ZDTRPHubIy8VyJzqZYviqbDJvZEZA0VFpPWjU=;
        b=aPbW6Lh099IGjANTpVjtzqHYVyDqB3R3DEZRFflSAiidqNJnc16k9e+Vf61hBxRSde
         dsNtRmF/EicjTxadwrhSQ4+Jo3ygH5Y4+evdJVwbtwyQ56c6Dulj+bV5yiNZJU/OoAyS
         Jfbqo67k0e/l+MEJvwgNJGHFWJw6tY7/VQ35n9P6rmkNqBT+Trg6AQtokT56KywKHrTo
         aLjwXv2d98k4oJeJeiisq0ppdYah9YlG0yglr2Gy3N8aw2PEEzgtQbtonwOcnvhoGwWZ
         1FeTXxAHRubSVsemeHZULny8Cy5shateexobrK7UqlOmSSN79tQ9BupmWC6AVDI6Phpp
         kl1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UAyNy1ZDTRPHubIy8VyJzqZYviqbDJvZEZA0VFpPWjU=;
        b=ZxBmEgSBRZo7B1DrRIlZC44NMSP29inCssv9nkd1zysE3uePyJswHqlTCzy7ZumTia
         6LK8cd8X7U5lBbw2ndoTtXo1v338IgI69XrxhTVM1C3kODlXB86fYtGAyZqBVFfQjP0w
         qfjgS4QQuhM6oiR8QwMpqPlvX7cxUSgAGpnbUhC8BTXilerJJYNUjjWfJgxQ9dxMY9R/
         eWai6W/IbdUqrIG4osN/Kibb6nbOta4B+vzsMDnlkT4oaJWDfuWur74rc5IJK/6LRRX2
         aQHL+WfBWqzudATmdJq44x2Jba7NIF91gjzkST6aZ7Bq8E8VW7qQT/MUi6TB0FlQu6E5
         LjTw==
X-Gm-Message-State: AOAM531J9rGDINaEXEIGX0QI5As2899J3ZkujNGUe+9r4X1rsCo/9jIR
	pHB6qQTptShoEQBJBn80sxo=
X-Google-Smtp-Source: ABdhPJza4QOfkyRegDC5B/Swgs9cX54goD3A/R7Kdlm6FdwiTHz3WNypyDc/T5GShN5+EXkJGpMC3Q==
X-Received: by 2002:a9d:23e2:: with SMTP id t89mr1981347otb.196.1601648340357;
        Fri, 02 Oct 2020 07:19:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5c0b:: with SMTP id o11ls417712otk.2.gmail; Fri, 02 Oct
 2020 07:19:00 -0700 (PDT)
X-Received: by 2002:a9d:6a19:: with SMTP id g25mr1944922otn.267.1601648339978;
        Fri, 02 Oct 2020 07:18:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601648339; cv=none;
        d=google.com; s=arc-20160816;
        b=TCIPyGbyjH3yt/KU9d78bUGMsZNph+RYTNAjm3PcaMptFKPxcAkaceV3IbBG4iLGWA
         ZW/Ng9koyc2RjNz5e1EjcpMxh3WrLsb1pFZu1ZVW8b4+4Fy3ZW3SOq8mHNiv4manaScp
         GeXlcGq5INlRtIK8O+9xQAqwZJ2t60Wndk7mWSs6HeSEGYL5dJL2xbSVbcuovDEnkkgq
         X+Oa1X+TkQogA740MdE7WcHkhPWdHQ0HunZ9EBTjNJdhCYK8wB/2RZikyVwxlL1AScOn
         uPmvPnLBmxj/nFosyBVICJkhxAlDqZ7dKKl0AV4hTZCR64XCovFetPeRMAmnWZ6htP+C
         A0Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tYH/6hO5lgQzTOW7dEpfFVSSkr8P55YhoTlw55xP13w=;
        b=DiIR7b0vw7lqwe1XSpjRhgXghlP5euVwcYe6N2KecmySMH8PLSZPFZ0A0qPtPeqIOi
         5rK3HCiqD5nBwsiqSJnFGD6d4g15kDUqZFFpzr0hAmeJwUp0dN2GfRtLUUEPlE8vpCYf
         rrxnCOGw1tE9cZ6vvb5Uq/LNMYVv5m+tGi/9sNzesOkZqaNeeSsXFC6cSKJ7SmhoLinp
         mytZIOU/SsPIwY1PMcMxKBjWox4b48Tg/CbzVledpjfdNF6IrE6FjcoWK6VYeFdWDbzH
         F91QGOPMUmmzeuBnGAJMbUrIFvAqYaIUOqBD85HmyEgCqLxglq2ouWlBuZcrdo5hwDn2
         vpoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="WbL9t9/X";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id l18si141615otj.1.2020.10.02.07.18.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 07:18:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id a3so1371487oib.4
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 07:18:59 -0700 (PDT)
X-Received: by 2002:aca:3d07:: with SMTP id k7mr1392880oia.172.1601648339445;
 Fri, 02 Oct 2020 07:18:59 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-4-elver@google.com>
 <CAG48ez1VNQo2HZSDDxUqtM4w63MmQsDc4SH0xLw92E6vXaPWrg@mail.gmail.com>
In-Reply-To: <CAG48ez1VNQo2HZSDDxUqtM4w63MmQsDc4SH0xLw92E6vXaPWrg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 16:18:48 +0200
Message-ID: <CANpmjNMcdM2MSL5J6ewChovxZbe-rKncU4LekQiXwKoVY0xDnQ@mail.gmail.com>
Subject: Re: [PATCH v4 03/11] arm64, kfence: enable KFENCE for ARM64
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
 header.i=@google.com header.s=20161025 header.b="WbL9t9/X";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Fri, 2 Oct 2020 at 08:48, Jann Horn <jannh@google.com> wrote:
>
> On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > Add architecture specific implementation details for KFENCE and enable
> > KFENCE for the arm64 architecture. In particular, this implements the
> > required interface in <asm/kfence.h>. Currently, the arm64 version does
> > not yet use a statically allocated memory pool, at the cost of a pointer
> > load for each is_kfence_address().
> [...]
> > diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> [...]
> > +static inline bool arch_kfence_initialize_pool(void)
> > +{
> > +       const unsigned int num_pages = ilog2(roundup_pow_of_two(KFENCE_POOL_SIZE / PAGE_SIZE));
> > +       struct page *pages = alloc_pages(GFP_KERNEL, num_pages);
> > +
> > +       if (!pages)
> > +               return false;
> > +
> > +       __kfence_pool = page_address(pages);
> > +       return true;
> > +}
>
> If you're going to do "virt_to_page(meta->addr)->slab_cache = cache;"
> on these pages in kfence_guarded_alloc(), and pass them into kfree(),
> you'd better mark these pages as non-compound - something like
> alloc_pages_exact() or split_page() may help. Otherwise, I think when
> SLUB's kfree() does virt_to_head_page() right at the start, that will
> return a pointer to the first page of the entire __kfence_pool, and
> then when it loads page->slab_cache, it gets some random cache and
> stuff blows up. Kinda surprising that you haven't run into that during
> your testing, maybe I'm missing something...

I added a WARN_ON() check in kfence_initialize_pool() to check if our
pages are compound or not; they are not.

In slub.c, __GFP_COMP is passed to alloc_pages(), which causes them to
have a compound head I believe.

> Also, this kinda feels like it should be the "generic" version of
> arch_kfence_initialize_pool() and live in mm/kfence/core.c ?

Done for v5.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMcdM2MSL5J6ewChovxZbe-rKncU4LekQiXwKoVY0xDnQ%40mail.gmail.com.
