Return-Path: <kasan-dev+bncBD4LX4523YGBBLHET6MAMGQEB2D4FEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 22C175A1BE0
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 00:05:34 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id g74-20020a1f9d4d000000b0037ceb9be394sf3795505vke.4
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Aug 2022 15:05:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661465133; cv=pass;
        d=google.com; s=arc-20160816;
        b=CO7/Z8QyHne9BSs46K6N7sTyD22KHDTp7h7eDluz8WYhZlsJEV7Qj6cG4qDv+vj/oi
         HoyNwR2G3v5cOEdC0eD4JQUBYgYz9P2LcGO/qvHSYVgksxiUL78LuU4CALufpyuiOasR
         0HmTFi7pb3evYpRT+yTqjlOgAFig0nSLM/bAdtxHRyWMnUY/WV85unxTGPfjpWJRod/U
         Q9l6c3jukrhbpCm1dM9+Fdnk4qaBSINQ+RHfG+MgimvmBaoRb2gX92gZuTtrkriWD4tr
         zMWz0I2Lt6P8vKa/jd7Xr6ps7HEuqvQqbO8ohofNUs8ofCQVoHJPWmUDc6rAtiPLjm6D
         UPyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=uS5PsJTk0F1k8PxZOFT/7BtmIRM1BVd/0weoQZqROEc=;
        b=w9pOxapysuL6wsVnafiND+XZfhiWMU7gbI+dtPntTxjLHAVaVcAgwDdp61pwWL5DIL
         kOTz3TQD7UBk6CpLK4X/Pr0Lbu8dagRroQFysIn1SBwMugG3kw8o+D9n/HpWACNfgMyn
         W5u+2d6KmLNdN5AePXynmkAmpiWcOI8rlnoPP/mFgBMfPlsGGFDVTt0pENTPUTCjwRte
         z6qZrNq6QFGPRpdjVpfBiOjsnIfR2C7PKtcNHyqehHHKD+ZinmWmS1h1CWRQ0WaTR1dU
         ipuqitoW+vbleZjpMc8ld784mY/GuC7R63z8/ImdKwHX/Y2TvN+xWLmnhromIdaDWjTV
         iuAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc;
        bh=uS5PsJTk0F1k8PxZOFT/7BtmIRM1BVd/0weoQZqROEc=;
        b=GXPVOzOMfx/N8fke3yxgz1HPJXXQZIHeiinZ1Y07y53OkolorAKxfBbCbecpKQzCl9
         yIAACgFNi2IKYcA1EclzkpTC1p64b+RndD5v4HtSIK7G+KxVHMmdzKL4/8LxNuprEjQc
         RDzUsfmaMdmGPR1iu5C1p0Ua0EEEye6pBU5sUjk0vRpQjwH/rGkzHC+BgxTI6rLMGlhH
         44U9S6V5m+yVgSeHENdMwMCHr6tlvySIgF7kgQI2fuDHasXpeYoRMsCiFsjfVY1AxkDY
         JBr4prUYCSXckL8igSPMIfLf6eLK5KhHjrGBes/EYokV7He4ZMBJtGK/a3X/EBNGG16y
         F+oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=uS5PsJTk0F1k8PxZOFT/7BtmIRM1BVd/0weoQZqROEc=;
        b=ZTSsa7QM+9RFQwKP3QUWH09gipmBogC7e7yjvQOT5qKgLER/35P2KoKJOFK8bwRb1p
         5p+9V7bJtbdGJiBHJMxv51O5Xlem2BhevGb8Cpq19GVic9+kTdrjyRvpuXPsnsOAHKs0
         GJ9vsA09Sqp9zd4OX3U9e8RXb0M4ERBQLwBMJUHzIav8nGvLl+ptdW7ZIht9LMjJjGBM
         UhSwKL9+KS5zxs1Vfzt29pEWeDNKvZC40YN60lNElXE5WIawXcsasPtWUBLmU5zU966X
         Vw3fkf+dHTiwX+ZE3OSY/QS9RafD/ZiTongkJKei15RFqeVVpL0VbU6ymE90YCq4Bil7
         m/EQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1gNgzk46RaAhUdvD0DkQR7QvBHM0svGhOLDF8UPgNtMAQ9WxrW
	lEQ7P/TMKdW+KE/zT5XHZmw=
X-Google-Smtp-Source: AA6agR5GTS81Wk/eagikGIrm6/UY5Pk93BICgv5zvCH/lvD7B0MZ7et58xNZ9fhw3ZGrRTDWii8sww==
X-Received: by 2002:a67:1c05:0:b0:38a:bbb0:4f8f with SMTP id c5-20020a671c05000000b0038abbb04f8fmr2690014vsc.40.1661465132958;
        Thu, 25 Aug 2022 15:05:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e082:0:b0:38c:e94f:3b4e with SMTP id f2-20020a67e082000000b0038ce94f3b4els551596vsl.5.-pod-prod-gmail;
 Thu, 25 Aug 2022 15:05:32 -0700 (PDT)
X-Received: by 2002:a05:6102:3ec7:b0:356:cbdf:122d with SMTP id n7-20020a0561023ec700b00356cbdf122dmr2199516vsv.9.1661465132214;
        Thu, 25 Aug 2022 15:05:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661465132; cv=none;
        d=google.com; s=arc-20160816;
        b=uD2UAD9vxUJ0kyGDctmKZt3xUfsSAj3dHa7LL0NgD04DDGzmD4L9dmi1NZa+tG3VcR
         RyMqRn0h2Oo4cRrfMJ2aSEvAR1+ilIC/vs97MqBt0K559TbDKW/DE4uQtheaMeVpC5VK
         hIKHyWAHfW/DjMwxTvEKsu5W0GWGBckqz9gWiFSbZaBQvANXptiPi3GJSkuEFBV5MSDP
         6Dv97DgSKMLJo3ugkXW4JxcvaZhreOnr2n7XmLSDQkSsYFv/nvx+vmthq0dQbWUTa3Rh
         lhCSNlvPOVFzCE9ndpR+lZgolFPnHi0xQfdJtMbBaydM0GVCqA/ncNcRFDTikFV7jCwF
         w6Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=iTVVWi9PtYsMXHi1gCNwfaOCLV6c3tLKr+5lgYNA1RU=;
        b=XsQU+/bev+T3RJGUzAkRiW0tGkMGN/+EiZkVf/pbD0iOBLl6VfOqt9HsytHrOPFmDd
         iMcuPuJvzAPriLQV1QIuiulKSYc+QA3sdlaacR76CJ/uOFzT/Se9LoHrm0tMYKkz1PSL
         84zZ6R9dRw7WMQr82oJHK81h+Kfqm1LDnUCerkbTp7wZu0ejjwnm5agEzNOZMiq12UBr
         Ci2Dy+RiKFxH2kIYiiA8eBP5v74SYI1ymHa5Tr0kA2RBIMOehxChoMGEWhQEFkfLsmrz
         dMw2RSc9+1EndNqUi/bflDp4eNR3dBGuqRztxy56D5Ca38gLHNZqV7Q5rJyYKXZNlSUl
         I2Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id x18-20020a67be12000000b00388460869f7si11245vsq.1.2022.08.25.15.05.29
        for <kasan-dev@googlegroups.com>;
        Thu, 25 Aug 2022 15:05:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 27PLvwJJ030264;
	Thu, 25 Aug 2022 16:57:58 -0500
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 27PLvtxj030255;
	Thu, 25 Aug 2022 16:57:55 -0500
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Thu, 25 Aug 2022 16:57:54 -0500
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>,
        Matthew Wilcox <willy@infradead.org>,
        Thomas Gleixner <tglx@linutronix.de>,
        Alexander Viro <viro@zeniv.linux.org.uk>,
        Alexei Starovoitov <ast@kernel.org>,
        Andrew Morton <akpm@linux-foundation.org>,
        Andrey Konovalov <andreyknvl@google.com>,
        Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
        Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Herbert Xu <herbert@gondor.apana.org.au>,
        Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>,
        Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
        Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
        Mark Rutland <mark.rutland@arm.com>,
        "Michael S. Tsirkin" <mst@redhat.com>,
        Pekka Enberg <penberg@kernel.org>,
        Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>,
        Steven Rostedt <rostedt@goodmis.org>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Vegard Nossum <vegard.nossum@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Linux Memory Management List <linux-mm@kvack.org>,
        Linux-Arch <linux-arch@vger.kernel.org>,
        LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v4 44/45] mm: fs: initialize fsdata passed to write_begin/write_end interface
Message-ID: <20220825215754.GI25951@gate.crashing.org>
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-45-glider@google.com> <YsNIjwTw41y0Ij0n@casper.infradead.org> <CAG_fn=VbvbYVPfdKXrYRTq7HwmvXPQUeUDWZjwe8x8W=ttq6KA@mail.gmail.com> <CAHk-=wg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw@mail.gmail.com>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHk-=wg-LXL4ZDMveCf9M7gWWwCMDG1dHCjD7g1u_vUXsU6Bzw@mail.gmail.com>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Thu, Aug 25, 2022 at 09:33:18AM -0700, Linus Torvalds wrote:
> On Thu, Aug 25, 2022 at 8:40 AM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Mon, Jul 4, 2022 at 10:07 PM Matthew Wilcox <willy@infradead.org> wrote:
> > >
> > > ... wait, passing an uninitialised variable to a function *which doesn't
> > > actually use it* is now UB?  What genius came up with that rule?  What
> > > purpose does it serve?
> > >
> >
> > There is a discussion at [1], with Segher pointing out a reason for
> > this rule [2] and Linus requesting that we should be warning about the
> > cases where uninitialized variables are passed by value.
> 
> I think Matthew was actually more wondering how that UB rule came to be.
> 
> Personally, I pretty much despise *all* cases of "undefined behavior",

Let me start by saying you're not alone.  But some UB *cannot* be worked
around by compilers (we cannot solve the halting problem), and some is
very expensive to work around (initialising huge structures is a
typical example).

Many (if not most) instances of undefined behaviour are unavoidable with
a language like C.  A very big part of this is separate compilation,
that is, compiling translation units separately from each other, so that
the compiler does not see all the ways that something is used when it is
compiling it.  There only is UB if something is *used*.

> but "uninitialized argument" across a function call is one of the more
> understandable ones.

Allowing this essentially never allows generating better machine code,
so there are no real arguments for ever allowing it, other than just
inertia: uninitialised everything else is allowed just fine, and only
actually *using* such data is UB.  Passing it around is not!  That is
how everything used to work (with static data, automatic data, function
parameters, the lot).

But it now is clarified that passing data to a function as function
argument is a use of that data by itself, even if the function will not
even look at it ever.

> I personally was actually surprised compilers didn't warn for "you are
> using an uninitialized value" for a function call argument, because I
> mentally consider function call arguments to *be* a use of a value.

The function call is a use of all passed arguments.

> Except when the function is inlined, and then it's all different - the
> call itself goes away, and I *expect* the compiler to DTRT and not
> "use" the argument except when it's used inside the inlined function.

> Because hey, that's literally the whole point of inlining, and it
> makes the "static checking" problem go away at least for a compiler.

But UB is defined in terms of the abstract machine (like *all* of C),
not in terms of the generated machine code.  Typically things will work
fine if they "become invisible" by inlining, but this does not make the
program a correct program ever.  Sorry :-(


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220825215754.GI25951%40gate.crashing.org.
