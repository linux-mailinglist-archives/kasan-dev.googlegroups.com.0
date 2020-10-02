Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBX6S335QKGQEWE7MGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 1827F281E4B
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Oct 2020 00:27:44 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id w7sf1087167wrp.2
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 15:27:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601677663; cv=pass;
        d=google.com; s=arc-20160816;
        b=dYaKi5fARGG6nwoV0ax4wrujzSRDrlnsnvb7FUIjkec9ZnbigjddMfbENer2wlpw9f
         ueAobvhZ7oD4UpQIJoAE78ejCoV1yUhWv3XDLKbwsoBij6IFGNfEWGEW1vyVOlzz0rdp
         rYhgzJxDfZruFCxQL2aVESQIg0iYWalVtT9PII+dDPuigxxNXkcxcmovLEQBoYReIgXK
         GXH9qRz4IDEcFVdUfaL4ZhjcNkd6Jw7v1myxVTBSmMK+g39dVQGECv33thj/tKQU2k4S
         GXvkbvfi8Gi61582pf5MsHHleZC+5Cql1tHRIZxHXWc1nM9uPv/bEjlTCZ9wP3npUJEv
         N34g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9BTiytnC2YtXrZCGjL4kJ7vVCdQbU4DM0eSfgCHLUTk=;
        b=UfYQs3PqvXxygRcnDoTuFsOtvlOqyFPj2RPg4V7bCz2ccUDK+2w7aPjJlmmHNKhqjv
         bKz4B9FmYlLTPYO+pkmYAoqJXhc3j4WxTJTNruGNbI3dbBNvz6LOKufJudq7CRCaqs2F
         b1gy0s0kshz4lFFgl9u1l2pavz0JNCT0tAYGJ2ksrMnWidodHXTOBrQrzpayH48AwoeR
         +HHX3H0kxAKTgxgg+vwAl9IgXnn7jj9XNEbBFrWceifgf0w9hVxQpOfs1PQvPZkpdsUp
         6ZSv4jYvuDG1LyBZP9vBY8+PEEaqgpVU00LJg7/gMQIao4ohw90LvsIzIhZrt53H1URT
         HU2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qpOS6AVU;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9BTiytnC2YtXrZCGjL4kJ7vVCdQbU4DM0eSfgCHLUTk=;
        b=ZZ3l5wvI/zFIuNQRj/3mA/KUBAmuFQLWj+szir/KmF4Tu8A5rje69JhyoQn4/fWiec
         ZX61/kUvb6gFDeS6CDK+mS523r5w+5XZxhESGlaORs3uOp/D7+vUBV/i86iPNwaky7Cy
         YN27red8rTahj75r2u9R/2lfAemI3v/dCuWRHRxD9nZzrgN4glBGvkZZk8tbT2oDT9lA
         GtH736drZ1rIeWEU2ovpaqYd7EzaQpnCC/Q/j69w9R5RxN1/3yJDhAZePcF5kJFvgbji
         cdrBffd2KLE80sDYtpKvr1U9Ie0A/ponE3WL5Rg9jElPGriPjKG76NxghV3EK50dL/LX
         yHZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9BTiytnC2YtXrZCGjL4kJ7vVCdQbU4DM0eSfgCHLUTk=;
        b=pv1DUMzkMiRCjerc+WdBX+4WUuiLvSW0st8TSip9rjPhJyLs1kH9uUEI48FEcIr2NU
         8l/mwuPTYpQy/Sqa6gq7J0LasYbeX1teMlsEp+/msgSMwBlUN47gEoTRXYt+xhlOulY1
         X6jLB20X/Up6opeo8n0+k5bLKvRd9AxULSf9Y6ANKKIbacpLFOFOgZ2Mgl0rBJMgqS0L
         FPtIXNPmnn49zGpNoYVcV80TXyO8UYAVQzIeSeRLXWlrvcMstxBGaZEudTTmZTGj35uo
         /8/l3RZMhJUQTV8jkYBmu5X/cPIefuBkkVZSntqb4RvPdw9FiOMmeVBRdV6C8ubPVO6v
         Kr9Q==
X-Gm-Message-State: AOAM533PMWYeNSsSpFp6EizF4eDVDOC8ouFwS7PIkVusriZOYdvcy7vO
	VFUZnzBqBxX3Q64jBFEs5Ok=
X-Google-Smtp-Source: ABdhPJz7Dl5q1Q+NpS0ImBhuOOCYxXcbH2lWQoLGIfqbYkpC8toFoQnV505zfw2s3PpykiAFcrHfFA==
X-Received: by 2002:a5d:4682:: with SMTP id u2mr5632540wrq.254.1601677663803;
        Fri, 02 Oct 2020 15:27:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:8:: with SMTP id h8ls408860wrx.3.gmail; Fri, 02 Oct
 2020 15:27:43 -0700 (PDT)
X-Received: by 2002:adf:e5c8:: with SMTP id a8mr5389512wrn.5.1601677662985;
        Fri, 02 Oct 2020 15:27:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601677662; cv=none;
        d=google.com; s=arc-20160816;
        b=OnNySlqWXm3oGoPCFRJ/No9n/vPOfAUj8lnlLM/U7YDawsGV4DnbnuOpTyfW4oay/o
         R+E6kwbsyFBtYGaGsURXMAuebojyXjNxPAX472YsoxKfpN1zcgvFedxfSEwMmsHwFtmz
         qKjzTSlzY5PCqkrz7ZJWzNQiGsSKsw4G4S1UuY5g0/i3dGvs5KrfMZooq0PVcL0Eirbh
         8t6uBCbRERPKT/cFCntFMkvIPLvI+Ys+weE0ZQde5FgI99qA12+NTJCwWA/VzcDnxyp0
         CN7FDkviTIeoBTpw4Fmwk0EWg2uUWEQjA9udR/E9MEAup574fgZAAEEIKEZ/3FeuCjuB
         dAQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WenNmI5oUkGle0L0WRFJAM5U4b70dfVnKCotDQT26ic=;
        b=lKbDIZfumZ2m9CNAPCvWo2fWMsIhqhfJDJwm+W6t7/hOo6xPvEE1HrGblqAzGJlHZb
         gICGkBmHMtzA6mCq69VhsB+U8JHrirx1XxY9GemtVQxfbcGOBfEFTrERssNPxvYciO5p
         j7KsrHZyjMHHBZrtIZC2t20QxyOsIV2cCoR6XWRmUGuswkZS9t71kI5aF4p14fzfilDg
         HmSzUV8tWJUKUsiopGTwHdw565co5AC8M+rQ/AqaDsqcb40YWZiy3El227c5vq2e/hu1
         kNc0gtJe8HQGaYLbiygOUriTGMwsJ99xnUN0GzGW/hydZ+lmcyhv6QDN9hZ9Gaw3W/3k
         mm2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qpOS6AVU;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::544 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id z11si118518wrp.4.2020.10.02.15.27.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 15:27:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::544 as permitted sender) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id l17so3308251edq.12
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 15:27:42 -0700 (PDT)
X-Received: by 2002:a05:6402:b0e:: with SMTP id bm14mr5117814edb.259.1601677662551;
 Fri, 02 Oct 2020 15:27:42 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
 <20201002171959.GA986344@elver.google.com> <CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nadeuiu1Byv+xp5A@mail.gmail.com>
 <CANpmjNN7s3o4DYbP64iLYo0MeDWciQnKd61njJKLsiZv+ZLQdA@mail.gmail.com>
In-Reply-To: <CANpmjNN7s3o4DYbP64iLYo0MeDWciQnKd61njJKLsiZv+ZLQdA@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 3 Oct 2020 00:27:16 +0200
Message-ID: <CAG48ez0az-Mv1f6EpnQwO6cYQANwx4qCDLa+yda_i15AzciS1Q@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
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
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qpOS6AVU;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::544 as
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

On Fri, Oct 2, 2020 at 11:28 PM Marco Elver <elver@google.com> wrote:
> On Fri, 2 Oct 2020 at 21:32, Jann Horn <jannh@google.com> wrote:
> > > That's another check; we don't want to make this more expensive.
> >
> > Ah, right, I missed that this is the one piece of KFENCE that is
> > actually really hot code until Dmitry pointed that out.
> >
> > But actually, can't you reduce how hot this is for SLUB by moving
> > is_kfence_address() down into the freeing slowpath? At the moment you
> > use it in slab_free_freelist_hook(), which is in the super-hot
> > fastpath, but you should be able to at least move it down into
> > __slab_free()...
> >
> > Actually, you already have hooked into __slab_free(), so can't you
> > just get rid of the check in the slab_free_freelist_hook()?
>
> I missed this bit: the loop that follows wants the free pointer, so I
> currently see how this might work. :-/

reverse call graph:
__slab_free
  do_slab_free
    slab_free
      kmem_cache_free (frees a single non-kmalloc allocation)
      kmem_cache_free_bulk (frees multiple)
      kfree (frees a single kmalloc allocation)
    ___cache_free (frees a single allocation for KASAN)

So the only path for which we can actually loop in __slab_free() is
kmem_cache_free_bulk(); and you've already changed
build_detached_freelist() (which is used by kmem_cache_free_bulk() to
group objects from the same page) to consume KFENCE allocations before
they can ever reach __slab_free(). So we know that if we've reached
__slab_free(), then we are being called with either a single object
(which may be a KFENCE object) or with a list of objects that all
belong to the same page and don't contain any KFENCE allocations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0az-Mv1f6EpnQwO6cYQANwx4qCDLa%2Byda_i15AzciS1Q%40mail.gmail.com.
