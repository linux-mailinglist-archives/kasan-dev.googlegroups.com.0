Return-Path: <kasan-dev+bncBC7OBJGL2MHBB36B3H5AKGQE7CEZUTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 68C7525FF84
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 18:33:52 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id c19sf2985603qkk.20
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 09:33:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599496431; cv=pass;
        d=google.com; s=arc-20160816;
        b=LdIJx1HirxCrAHryecnFPTAUB98D1WNKgbc1BnVi0yVTd7OfYID1BUg025CmoYQoRR
         5S9dXxNp+oNEu//K1cUilElkBnNn1vIdYIs0SXOZ1jq4ec70MAYRmPcFElhFdAEwq1yQ
         dda4ZxfyjMEwY5z9l7eUdqrsHOV0830HeRshkp6ncjKzqn/l4UeMVFc9eB/S1Eud7Ezn
         deU8Z3xu5FllQGQjrdc7SHF4xbTpzNy8CRSkL+nWyxq10CkqDX5PRhc9MrbaB/l+3tGY
         6/r91ChQd27Z4WfCgoukB1o9lVi19GG2WPKYi9Ng+CzssNAn9A/yjRdmUddNrBUGHc20
         nqRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xHqGDlQ3SihFiZ+k8UY+PrR9Pm1DTONIIKsa116CWhI=;
        b=E16nbr3R7WasJm5/wsKgpOTEuADMrtKI+s/n9vdfY/7XnvwP3E6KTVvC2xzqfhlljf
         p6iyGF1bTr01AV6sXCVGCXsUNo8WoowMPmACMTmo8Ru+zuw+UNZGXJLrFomKru4nZmJQ
         Bor4exbB0Yk+1str+JEnvEsNjfwzj5nZ0TXZARez5VfrvtrGrFZT+kcWK5IwN1pT4D79
         4jfJVMPh7utydp8vdp/7x6Lzyn6rzdNmzIyiMGSiVfE3jRLOG+kW2U4BaFoG60EX3XWe
         ZfAFsESwXVp9lGOb+COtUCcHcORf4bwTBllvuAI39bWwjV9Nz8Sjchkvgu64/NJt10zJ
         iTbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a1u7+crG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xHqGDlQ3SihFiZ+k8UY+PrR9Pm1DTONIIKsa116CWhI=;
        b=RP+0soeJ6J2+q/UMyzw6ohZIwsk0iH3YS8dTduJxFEGkOFC46ZU+k/zcnKh2c3nhyo
         +gwiy70FDPI7+/viEIMrt7DH+mNAOu5aJ/DUhCeP4/U2cWLGPtgC9AI+WR6I6+I0DtHB
         2VuuLsC0BpggMfC7/0efVlB32dLzAlfAsy5V9lVDfSlIRNEvFUaKQudMbunu1kGojbo1
         OidN1I20ATWCb7l0Ofu9SpCDCcDTlbNhMrTjH5bLVoJNThPOs6EixSP3JCTqoFsNjgnO
         0E/h99c1lyN+3PCg9W+tlR6ruueNFgNBWdDHM5trbpSU+SpdMemRvhoCeXUDUKq7y54y
         uqJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xHqGDlQ3SihFiZ+k8UY+PrR9Pm1DTONIIKsa116CWhI=;
        b=IHnbULfLTLCtLt7dkZV9/6ytMpBtbvCCYjLPyGQ/AJez+4mNlodwI3BhKDh8+RjmKb
         sDcWE/VdMgUelKGINapkb+wpqICRKs2ibhTgMFctTJx8Qbjnqca3R9McpexlH+SrOPGm
         DzV7rJoU80wsUcmltTfFnhZ60G0BRiC/RBg6tuzS9tPsbTIsHty3Z9+H5JBJ5ehbHMw7
         7blFB6TQg7CsPnda9yXAdlT2PaUGOmUX6rEj83Xe4yJHqGyKpKuN2E+qYI9AX3aKfJNG
         JoDEepdHLkRsO6qce5haPX6oBAOh4sT7zeNlJQMMutnSCfk4MLUFzgto7VLuGi88JiZN
         tb8Q==
X-Gm-Message-State: AOAM532aTtt01Z4nNFU0H7HX0DVbpJ/VbbRAm9ie5SKp0s5j2fXoFVh3
	xFygnf8UbDxsE3iIJUv7FxI=
X-Google-Smtp-Source: ABdhPJwYhLH2FLrrYIus9SP2rVTfOpSCjUUjtN8gZOdGnoom5vuJ7TaVdVR5kxPwgh5WKhmfj9LXuA==
X-Received: by 2002:ac8:5194:: with SMTP id c20mr21341952qtn.344.1599496431344;
        Mon, 07 Sep 2020 09:33:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:c20d:: with SMTP id j13ls8341293qkg.2.gmail; Mon, 07 Sep
 2020 09:33:50 -0700 (PDT)
X-Received: by 2002:a37:a484:: with SMTP id n126mr20744108qke.5.1599496430802;
        Mon, 07 Sep 2020 09:33:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599496430; cv=none;
        d=google.com; s=arc-20160816;
        b=m2Bk+fzJb99WmULofANsvYMCUJyF7Jg4j/vOgBrIpguwRIALK9eYmVZROn7cyTAIMU
         zOJOwNOmncrHxTTiQH+C26E77VFezHJZyWHKqNrOfgeNHJpgUPl5FO/K58nxEcTfFMMI
         of15OZpdJ5+jQZwaymXhQrdboqjV7leOP5aTb/zEzVX1W95B/Hvz+NOXH9VZc+yE8KwR
         mxH+d32N8R7e4cCi6Pg2eLny+misRKCo0JN7zDd4ovYHfTmS6ntViWoWzpYf3QPAS2YQ
         sHdgICIm5w71qIG72iWylMBFVExjAEYpfoA2msL7SMlKipvd9aVQWAAH+rPTF+36iOTy
         URVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iBwtgZU7qEienEQgEVgaKwzY43NlebeQB2JfRwQK1dw=;
        b=kVjlMPfTnPxodPbV4xkDtTK02qG9S0ZUS2MHrqdoDo1MYAjg04PzGuaY58xTIclaFJ
         Ng+EGgc7H3xN9QVJxVMKZbABKYrBKF9Pc/6tYH5MVDyheAF8EOpBp2kpunpTNqVHMxH1
         Y8WzYZ7jHM8pdb6ANkcpNHNF+DJLWoo4zYAiU9B6RuKfYg1hJdawi4hPiQ2Ep6nf/4Vk
         1tGGgolkqltrUCEU2ehXORyb+8ezb1Inq1tlyqXq4OOIPyQZzczeUYd6fJBGTkG6D5Qs
         hWEHguz+K7MsRtbxQSYrtaFdLjVrYrL8LYSO6XZS03fXzzl1OI+ChP3gpXB4XvvRCu/i
         RU4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a1u7+crG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id q5si817283qkc.2.2020.09.07.09.33.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 09:33:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id w16so14040258oia.2
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 09:33:50 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr78646oib.121.1599496430150;
 Mon, 07 Sep 2020 09:33:50 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-10-elver@google.com>
 <CAAeHK+zGpJd6szPounYz6wogO9TMT18TmQu_mfXUWQd65QTf0w@mail.gmail.com>
In-Reply-To: <CAAeHK+zGpJd6szPounYz6wogO9TMT18TmQu_mfXUWQd65QTf0w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Sep 2020 18:33:38 +0200
Message-ID: <CANpmjNM14iW8vDuLANrCGBds930r2bZ=gwkoqORpuLa5-8gW6g@mail.gmail.com>
Subject: Re: [PATCH RFC 09/10] kfence, Documentation: add KFENCE documentation
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a1u7+crG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Mon, 7 Sep 2020 at 17:34, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
> >
> > Add KFENCE documentation in dev-tools/kfence.rst, and add to index.
> >
> > Co-developed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  Documentation/dev-tools/index.rst  |   1 +
> >  Documentation/dev-tools/kfence.rst | 285 +++++++++++++++++++++++++++++
> >  2 files changed, 286 insertions(+)
> >  create mode 100644 Documentation/dev-tools/kfence.rst
> >
> > diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
> > index f7809c7b1ba9..1b1cf4f5c9d9 100644
> > --- a/Documentation/dev-tools/index.rst
> > +++ b/Documentation/dev-tools/index.rst
> > @@ -22,6 +22,7 @@ whole; patches welcome!
> >     ubsan
> >     kmemleak
> >     kcsan
> > +   kfence
> >     gdb-kernel-debugging
> >     kgdb
> >     kselftest
> > diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
> > new file mode 100644
> > index 000000000000..254f4f089104
> > --- /dev/null
> > +++ b/Documentation/dev-tools/kfence.rst
> > @@ -0,0 +1,285 @@
> > +.. SPDX-License-Identifier: GPL-2.0
> > +
> > +Kernel Electric-Fence (KFENCE)
> > +==============================
> > +
> > +Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
> > +error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
> > +invalid-free errors.
> > +
> > +KFENCE is designed to be enabled in production kernels, and has near zero
> > +performance overhead. Compared to KASAN, KFENCE trades performance for
> > +precision. The main motivation behind KFENCE's design, is that with enough
> > +total uptime KFENCE will detect bugs in code paths not typically exercised by
> > +non-production test workloads. One way to quickly achieve a large enough total
> > +uptime is when the tool is deployed across a large fleet of machines.
> > +
> > +Usage
> > +-----
> > +
> > +To enable KFENCE, configure the kernel with::
> > +
> > +    CONFIG_KFENCE=y
> > +
> > +KFENCE provides several other configuration options to customize behaviour (see
> > +the respective help text in ``lib/Kconfig.kfence`` for more info).
> > +
> > +Tuning performance
> > +~~~~~~~~~~~~~~~~~~
> > +
> > +The most important parameter is KFENCE's sample interval, which can be set via
> > +the kernel boot parameter ``kfence.sample_interval`` in milliseconds. The
> > +sample interval determines the frequency with which heap allocations will be
> > +guarded by KFENCE. The default is configurable via the Kconfig option
> > +``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=0``
> > +disables KFENCE.
> > +
> > +With the Kconfig option ``CONFIG_KFENCE_NUM_OBJECTS`` (default 255), the number
> > +of available guarded objects can be controlled. Each object requires 2 pages,
> > +one for the object itself and the other one used as a guard page; object pages
> > +are interleaved with guard pages, and every object page is therefore surrounded
> > +by two guard pages.
> > +
> > +The total memory dedicated to the KFENCE memory pool can be computed as::
> > +
> > +    ( #objects + 1 ) * 2 * PAGE_SIZE
> > +
> > +Using the default config, and assuming a page size of 4 KiB, results in
> > +dedicating 2 MiB to the KFENCE memory pool.
> > +
> > +Error reports
> > +~~~~~~~~~~~~~
> > +
> > +A typical out-of-bounds access looks like this::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: out-of-bounds in test_out_of_bounds_read+0xa3/0x22b
> > +
> > +    Out-of-bounds access at 0xffffffffb672efff (left of kfence-#17):
> > +     test_out_of_bounds_read+0xa3/0x22b
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32, cache=kmalloc-32] allocated in:
>
> Does the user need to know that this is object #17? This doesn't seem
> like something that can be useful for anything.

Some arguments for keeping it:

- We need to write something like "left of <object>". And then we need
to say where <object> is allocated. Giving objects names makes it
easier to understand the link between "left of <object>" and the
stacktrace shown after "<object> allocated in". We could make <object>
just "object", but reading "left/right of object" and then "object
allocated in:" can be a little confusing.

- We can look up the object via its number in the debugfs objects list
(/sys/kernel/debug/kfence/objects). For example, if we see an OOB
access, we can then check the objects file and see if the object is
still allocated or not, or if it has been recycled.

I don't believe it's distracting anyone, and if there is a chance that
keeping this information can help debug a problem, we ought to keep
it.

> > +     __kfence_alloc+0x42d/0x4c0
> > +     __kmalloc+0x133/0x200
> > +     test_alloc+0xf3/0x25b
> > +     test_out_of_bounds_read+0x98/0x22b
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 107 Comm: kunit_try_catch Not tainted 5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +The header of the report provides a short summary of the function involved in
> > +the access. It is followed by more detailed information about the access and
> > +its origin.
> > +
> > +Use-after-free accesses are reported as::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: use-after-free in test_use_after_free_read+0xb3/0x143
> > +
> > +    Use-after-free access at 0xffffffffb673dfe0:
> > +     test_use_after_free_read+0xb3/0x143
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=32, cache=kmalloc-32] allocated in:
>
> Same here.
>
> Also, this says object #24, but the stack trace above doesn't mention
> which object it is. Is it the same one?

Right, the above stacktrace should then say "kfence-#24". (But the
address also hints at this.)

> > +     __kfence_alloc+0x277/0x4c0
> > +     __kmalloc+0x133/0x200
> > +     test_alloc+0xf3/0x25b
> > +     test_use_after_free_read+0x76/0x143
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +    freed in:
> > +     kfence_guarded_free+0x158/0x380
> > +     __kfence_free+0x38/0xc0
> > +     test_use_after_free_read+0xa8/0x143
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 109 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +KFENCE also reports on invalid frees, such as double-frees::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: invalid free in test_double_free+0xdc/0x171
> > +
> > +    Invalid free of 0xffffffffb6741000:
> > +     test_double_free+0xdc/0x171
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=32, cache=kmalloc-32] allocated in:
> > +     __kfence_alloc+0x42d/0x4c0
> > +     __kmalloc+0x133/0x200
> > +     test_alloc+0xf3/0x25b
> > +     test_double_free+0x76/0x171
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +    freed in:
> > +     kfence_guarded_free+0x158/0x380
> > +     __kfence_free+0x38/0xc0
> > +     test_double_free+0xa8/0x171
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 111 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +KFENCE also uses pattern-based redzones on the other side of an object's guard
> > +page, to detect out-of-bounds writes on the unprotected side of the object.
> > +These are reported on frees::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0xef/0x184
> > +
> > +    Detected corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ]:
>
> It's not really clear what is 0xac here. Value of the corrupted byte?
> What does '.' stand for?

We can probably explain that better below. The values are the corrupt
bytes, the '.' are untouched bytes.

> Also, if this is to be used in production, printing kernel memory
> bytes might lead to info-leaks.

We do not print them if !CONFIG_DEBUG_KERNEL, and instead show '!' for
changed bytes. Maybe we can add this somewhere here as well.

> > +     test_kmalloc_aligned_oob_write+0xef/0x184
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=73, cache=kmalloc-96] allocated in:
> > +     __kfence_alloc+0x277/0x4c0
> > +     __kmalloc+0x133/0x200
> > +     test_alloc+0xf3/0x25b
> > +     test_kmalloc_aligned_oob_write+0x57/0x184
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 120 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +For such errors, the address where the corruption as well as the corrupt bytes
> > +are shown.
> > +
> > +And finally, KFENCE may also report on invalid accesses to any protected page
> > +where it was not possible to determine an associated object, e.g. if adjacent
> > +object pages had not yet been allocated::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: invalid access in test_invalid_access+0x26/0xe0
> > +
> > +    Invalid access at 0xffffffffb670b00a:
> > +     test_invalid_access+0x26/0xe0
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 124 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +DebugFS interface
> > +~~~~~~~~~~~~~~~~~
> > +
> > +Some debugging information is exposed via debugfs:
> > +
> > +* The file ``/sys/kernel/debug/kfence/stats`` provides runtime statistics.
> > +
> > +* The file ``/sys/kernel/debug/kfence/objects`` provides a list of objects
> > +  allocated via KFENCE, including those already freed but protected.
> > +
> > +Implementation Details
> > +----------------------
> > +
> > +Guarded allocations are set up based on the sample interval. After expiration
> > +of the sample interval, a guarded allocation from the KFENCE object pool is
> > +returned to the main allocator (SLAB or SLUB).
>
> Only for freed allocations, right?

Which "freed allocation"? What this paragraph says is that after the
sample interval elapsed, we'll return a KFENCE allocation on kmalloc.
It doesn't yet talk about freeing.

> > At this point, the timer is
> > +reset, and the next allocation is set up after the expiration of the interval.
> > +To "gate" a KFENCE allocation through the main allocator's fast-path without
> > +overhead, KFENCE relies on static branches via the static keys infrastructure.
> > +The static branch is toggled to redirect the allocation to KFENCE.
> > +
> > +KFENCE objects each reside on a dedicated page, at either the left or right
> > +page boundaries selected at random. The pages to the left and right of the
> > +object page are "guard pages", whose attributes are changed to a protected
> > +state, and cause page faults on any attempted access. Such page faults are then
> > +intercepted by KFENCE, which handles the fault gracefully by reporting an
> > +out-of-bounds access.
>
> I'd start a new paragraph here:
>
> > The side opposite of an object's guard page is used as a
>
> Not a native speaker, but "The side opposite _to_" sounds better. Or
> "The opposite side of".

All are fine. Using "to" indicates direction, which in this case is valid too.

> > +pattern-based redzone, to detect out-of-bounds writes on the unprotected sed of
>
> "sed"?

side

> > +the object on frees (for special alignment and size combinations, both sides of
> > +the object are redzoned).
> > +
> > +KFENCE also uses pattern-based redzones on the other side of an object's guard
> > +page, to detect out-of-bounds writes on the unprotected side of the object;
> > +these are reported on frees.
>
> Not really clear, what is "other side" and how it's different from the
> "opposite side" mentioned above. The figure doesn't really help.

Redzone and guard page sandwich the object. Not sure how I can make it
clearer yet, but I'll try.

> > +
> > +The following figure illustrates the page layout::
> > +
> > +    ---+-----------+-----------+-----------+-----------+-----------+---
> > +       | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
> > +       | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
> > +       | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
> > +       | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
> > +       | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
> > +       | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
> > +    ---+-----------+-----------+-----------+-----------+-----------+---
> > +
> > +Upon deallocation of a KFENCE object, the object's page is again protected and
> > +the object is marked as freed. Any further access to the object causes a fault
> > +and KFENCE reports a use-after-free access. Freed objects are inserted at the
> > +tail of KFENCE's freelist, so that the least recently freed objects are reused
> > +first, and the chances of detecting use-after-frees of recently freed objects
> > +is increased.
>
> Seems really similar to KASAN's quarantine? Is the implementation much
> different?

It's a list, and we just insert at the tail. Why does it matter?



Thanks for the comments. I'll try to fix in v2.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM14iW8vDuLANrCGBds930r2bZ%3DgwkoqORpuLa5-8gW6g%40mail.gmail.com.
