Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6NW335QKGQEVEH7NFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CD3C281DA8
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 23:28:26 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id f10sf2193837ilq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 14:28:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601674105; cv=pass;
        d=google.com; s=arc-20160816;
        b=AQUbYKLbQifBw3pGiGAmaohyKLFxphmZ0lvsMHKOWQPGpqz0wu0jwI98U/fC3K1A3A
         InHf2EeqQcKj6LhJGhDwp0wPPkKWJ90hxsUNPpzMC/N3flmqcBeJS/fe1PAXTNheXdW+
         h8E4xLOl9iAEQNjrCRTZBYYvt24aMbG798wcw+qYI0e8X1AZFIe9vPW13f1PhBPUOYdw
         biId6+2mEofQNaB9cfWuAfkVzPdVwiwmpzCUSDj8xIaPiyzkiSREUmmZ2JDpJHoXld/k
         W2SvOzyGIgxGrZOs8DRlwIOn/kftUycW7xBTntDgzwqKjkwv+Sfw83tHMzDsqiRhQHG5
         GLjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BDSIw6IqVTKzmmhdpxxI7KFFLm8lV2eE3I3vCvr25cg=;
        b=AYGqgXYCsJmkExyjugzIPCCxNlU3srC1pdjXx0t0kFRYsiDCg4QO6pGfhE85x2RPk6
         ITGWRRQpvk4fCaX+VaCgN0kg8RSFWysFWVutATEDjrsbIC92PIt3Xz0N6IqBsuOK7moL
         Y5WWAbIdazUsBG21pyByb0zqcTjQBToYIT5UkaKkpS2u8ofXONCcN94/IjHYOiU7sVfW
         x7OZeCRMA09eKDCm+/sK5iN4uezTlWF4tatpEvn7C82849mQN3vEASxORhFbk7Hp1AmQ
         auJ1QwkVQKNJ8OyCgT3EKp8BY1GrQqcWFg6Asb4cVKFjSQXO3wI+YBN53wVowbk9IxHz
         gacg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T9S8Ib37;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BDSIw6IqVTKzmmhdpxxI7KFFLm8lV2eE3I3vCvr25cg=;
        b=soeA6sCCw9olj2F3KVNqQARcgS9toJHOqTRGAsqwG+/tDXsFHwa9cnD3L//IXg6tBy
         tIMdH+jlbdxO7IZ+CvxrwuFpy6gxLZvSZqLmKAnYKceNC8gmHuSiUJGQacMyWJlRh6pX
         uAkok+/OzVruMV2hUr2BUNK+ugVXzyLMm0CtqMxZFW8g2QPCQlXlupl1kkD/SB8GNMRd
         pnFLAHsSdAwycJjcH7UCLf5YNLcd6FA4eWAtlutO6Q+pXS3v5uqfADt0yv90cq0cN3vA
         rXhekiJ9Dij1roNISLhOp7fkv49MooX8iK2xn5W+0Otv1l0yuIIPFTmLj/qiEsCixxnX
         f75w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BDSIw6IqVTKzmmhdpxxI7KFFLm8lV2eE3I3vCvr25cg=;
        b=bbizACpCxLyXcdIegaUpzePg6+K9gr/tSFB4YK2Z4lqsYzgzG4nCQLLttcE66JIHsr
         qF37BoTL/SZ9eFzoR9SKsajNOB+/ba4gtSLAnNwRLCxOuerds8lwXU1t9UyWjkR5Sx1P
         pP5f2sejP6gfyDRVMXPwrgxhAVbxFE76ijrzxKmxiVvzgpC19b4dtI6vHYIJaC/kYBfy
         PeIUQcCIk445PCNDgGsq7tRcieZDyAC2J8ngX5Gyco7VqMOTyWLapTe85dKcoPZx6KDd
         pzb5CPSmJ0/wZhFlh4j3oYXGMI05I1D60Ez0GsRO4TfBOYxNDuGGJp6JYGEOmaR5IA8G
         SMOQ==
X-Gm-Message-State: AOAM533yOTUybUEhfDrD8l6IpNLl6AV4STly6DTDkcgEK4cEI6589Baf
	lAJn6imexvzf6jR1HvR4JXo=
X-Google-Smtp-Source: ABdhPJx6NPO1p/GbkJZL70AEu9K0yHXuHXdV8Zxl5HvZ11iH+oenE+SW2dXkhs2AMgUnmlMDqP72OQ==
X-Received: by 2002:a92:cbcd:: with SMTP id s13mr3170204ilq.306.1601674105351;
        Fri, 02 Oct 2020 14:28:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:cc3c:: with SMTP id o28ls409617jap.6.gmail; Fri, 02 Oct
 2020 14:28:25 -0700 (PDT)
X-Received: by 2002:a02:69ca:: with SMTP id e193mr4099308jac.27.1601674104984;
        Fri, 02 Oct 2020 14:28:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601674104; cv=none;
        d=google.com; s=arc-20160816;
        b=0LOKWTPdui4dqT35Y3dcwYduSLnP6wOtBSxHWuqSrgCI+jx+EvjoxeDJbl0AmYWjcg
         9FgaBuki/Gu8uq0k8nWxj0owe9Rd9N1Cg0psBG6FR16ktImkTQ7Z+hzqZpjo++Jn25wu
         d2wAlPWiaJEmhgYTw2hva0P/b+cnGgJph/WN50M0BcTA6wtCkgmd6FD4AGRZUeLL2xgG
         xr+C5aeksXc226crfF6nJNamTKxhvsuij8qiozF23eRPLZJmRBdqrLL7D0wyi/bUNDDK
         udpSKCcwiDv16gOvu3H6JfffBESm66hLovWd+u+EMewjuFowi41J1FLw7aS1tReWvJR+
         VISg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zH8zzrg+xXVXd7NQ8OqgeM7KZ5LB+ZSk1cWcX09tTBI=;
        b=utuUyZzzBSvMzocMRfdRDJDEZij4jTFIWW45/bPGRnWs2xfp4l1FUfbEE7w9ygiVgp
         utoo48zm7Zun+Chv8eFYejivUp+49VNwc+Phwb54wRLf3IyOIf1Buv4RYZ5n6s7j2UFB
         eMMj/1KNp7isD8jt+eyxgpmqnXxox9AEI4EOcbgZs/o2gQuecyLnm9G2aO8wUFOKby7G
         sDve2DM4+0hHjUgjB6uL2EvlK/CmPKunog+5JShg2PLKLEGww4C4uKzo5Vlo99xtTPQt
         fCOeZC2QszB/9sS3sCN1Ewl5DsTckSCdyM5iHu+dMbDyIe0DcduFDTHAIwvfcWe5ej9m
         cgTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=T9S8Ib37;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc41.google.com (mail-oo1-xc41.google.com. [2607:f8b0:4864:20::c41])
        by gmr-mx.google.com with ESMTPS id n86si265117ild.4.2020.10.02.14.28.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 14:28:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as permitted sender) client-ip=2607:f8b0:4864:20::c41;
Received: by mail-oo1-xc41.google.com with SMTP id w25so716604oos.10
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 14:28:24 -0700 (PDT)
X-Received: by 2002:a4a:4fd0:: with SMTP id c199mr3387390oob.54.1601674104417;
 Fri, 02 Oct 2020 14:28:24 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
 <20201002171959.GA986344@elver.google.com> <CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nadeuiu1Byv+xp5A@mail.gmail.com>
In-Reply-To: <CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nadeuiu1Byv+xp5A@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 23:28:12 +0200
Message-ID: <CANpmjNN7s3o4DYbP64iLYo0MeDWciQnKd61njJKLsiZv+ZLQdA@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
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
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=T9S8Ib37;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c41 as
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

On Fri, 2 Oct 2020 at 21:32, Jann Horn <jannh@google.com> wrote:

> > That's another check; we don't want to make this more expensive.
>
> Ah, right, I missed that this is the one piece of KFENCE that is
> actually really hot code until Dmitry pointed that out.
>
> But actually, can't you reduce how hot this is for SLUB by moving
> is_kfence_address() down into the freeing slowpath? At the moment you
> use it in slab_free_freelist_hook(), which is in the super-hot
> fastpath, but you should be able to at least move it down into
> __slab_free()...
>
> Actually, you already have hooked into __slab_free(), so can't you
> just get rid of the check in the slab_free_freelist_hook()?

I missed this bit: the loop that follows wants the free pointer, so I
currently see how this might work. :-/

We'll look at your other email re optimizing is_kfence_address() next
week; and thank you for the detailed comments thus far!

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN7s3o4DYbP64iLYo0MeDWciQnKd61njJKLsiZv%2BZLQdA%40mail.gmail.com.
