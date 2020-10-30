Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPEB6H6AKGQEGII7NAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A66C52A0B47
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 17:35:09 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id 203sf200376vkt.7
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 09:35:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604075708; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ik8lipAkAxsPXyGBqpMJ/x82LHN14yNQ3hLpYEwjsyYHMfHXNJ00l02Qi8Cd6Z54u4
         lKRE0BTrv2IVYCbDQlcNEsbKUaI3ZVj8zi/I6ImQtpLK/c6AcyO+DdGoFbs9IObVXaQv
         xtrtuGMt+XroHWKUwU/RRkd1zCcycBAedXUPaW9v0G8LTREOcp+zYSjB9IeIsEWQRb9o
         r5s2rmqPaaUqXx65EnWU6yNcqusf6W5BcWvol1IG7egCKfHRCGt+6SlD/emOm+6wamGW
         NWpZjGtfEcYwTrgk3sor1/G+rZFVr+KdJzZsa4X8DyArQGEQEvh/LO9IWCbKGgZF2uDM
         Wohg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=h0LCxFkXELUvCG//CSGPLSisVsYU10trpR0stMcbj+4=;
        b=xPxvYlw4RsAmZW+8DH5Sj8Cy56Thdlb1cxWsAptVoTZFfq/IvyS0tPGcBHXv+xq+uO
         6oPS0yImp/5i22W6aqnZY1KYQkuhOKK+vnEtJE6U//713nb6+XKi9D6nk9zTzUQ+aATy
         uzcEctS4kr4VqhxLbbK4ZBcoVS3AMUKNPdb090U9qHX8yUBaS68sWuKa5/GhE9XxXcYQ
         y8v8abOSi32gpLoB1clKhUpfUg2JeLYVbEXfhQEhXGbKyMxxCYP+v3T7sI2JUBeqv/QJ
         pLK/pugHNZmX/XABTD7sWdZ2g9HK7Xzlx5BoDcQz4Jx3dotENopP2Y4CM12jH2t1JZHQ
         x48Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=niyYm0qY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h0LCxFkXELUvCG//CSGPLSisVsYU10trpR0stMcbj+4=;
        b=Z7x+t92poK+qjwFBJL7NumrYgt5miJacci8/n1sj8JmJKIPlNZ89hEng1hgHtDoosg
         jEeLhomsqoDyAPz8XZSVVB/OoLkaq635ThORs4N+vzndDstJc51gf8QAnSsQN+cB6Wyk
         Apqz6RJZ4t/Yjo5LJ+BXAYl2TLkjuuMeNNWHGfZ9Iz3JhKNW6n6vsKW46uRbh182P0g0
         tRADyz57/t6vL5aHDlRRciy0K3gy54pO+eOEYyysgHWzDzRfe9OWgxPCDJbsz0CUSiqP
         l70D5YpiG72LYm9hZT3pbBXxiJBkLu6XcLtJWJGh7E/5pqBgTXLETKrpp6uZJ34rfSNT
         hZtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h0LCxFkXELUvCG//CSGPLSisVsYU10trpR0stMcbj+4=;
        b=k5w3ql1nzJSQnHWjp5iSFZEW2zFTbjozOC+xa+v1GJNiyClBe6XW6GVPkQtNq260fF
         OF1m7HxcMD5sP58vJOGOV1hshXK1IlFHPfAgmz/15/4A/ibYB8n/BFt7MxRgjVYbVsyK
         S9bCZDV3JoW/xkjJajz1cMLR/0OF1B6RMAqtcm84+FeQDRROA3MVr8mnyvM6aVaZkPgv
         ckz+kQwDELyLPe4zpAGiw1mFAUWkKd9uvwF1GMCuqjUIQ1i7NmXUTmwigzsONOT7Q5Yi
         xNFdGys/d5UKeQFSleiOu95naJo/VQNKS2xZ/6xUXJMwME/LLlZJhaABgtSTrx6ABlZE
         C0hA==
X-Gm-Message-State: AOAM531p54ZQoO5cMoFjHW3zOSPbeog3+P7iiY1zvx3Nbsk1LkPlaU6a
	ozR8TLQlPLKSbNI7LWkKGXM=
X-Google-Smtp-Source: ABdhPJzaW085e7Mqn4zDjZr0Hr51v9UE4sGAHH7ozqQCTHegU4KL4Y1n3oCUwAC8yPr8J68wj5+rVA==
X-Received: by 2002:a67:3251:: with SMTP id y78mr2779363vsy.36.1604075708525;
        Fri, 30 Oct 2020 09:35:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3f51:: with SMTP id m78ls426942vka.6.gmail; Fri, 30 Oct
 2020 09:35:08 -0700 (PDT)
X-Received: by 2002:a1f:2ad0:: with SMTP id q199mr7952310vkq.20.1604075707990;
        Fri, 30 Oct 2020 09:35:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604075707; cv=none;
        d=google.com; s=arc-20160816;
        b=KeAsaXUlNccoSvNhp0pbZnlbVInsFuS0nqRbReSwk1GE9LXunXoWi7oTHHnW254tlb
         UI3rfsR3WEp/ame+4Jr4WCE2sL91Ioce0olZ+n3O/O3eBt+ybHkzb4UEHbKITRipyuIq
         M0WjJAOWLmXRc3jacPdCEo7tDv+PM+T0LYtMtAPKEvC5oxkoxaG7wsLR5guNLZ/T0mgl
         R/COFTrb9fdkIJzgQXUoFtQyhmR+2kUPQh/1YncwafoRM0m8AeuLvKoBUmYrZjlCW7fd
         1mVztTKs87L0G166TD90dTJe5kQ1+73jBtqTUNsN1ecqpXyE/kmCYE0Bg8iOG97c4OO7
         UYTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OEG72fK9A86Aj1ReEdXuRoNmABKVsj8ImdviwWVYFfY=;
        b=HVir+4xpTBitt+9eLtJB5V19E1u29+SiGRi0iOgq8Hv+8uk4bq6KYbAkuLCnaOyyIk
         MEGXqvSgpsIDdFZk9/LJ69MXu5H8ta16JJxs2fq7Urt4HlUGju1czoY1sogEW36eTPXw
         KSSdmqBSVCTKPqSZTT2JhIcy5eZP9xhIitZ/br/tFB2CPAj8OT9y9qxKLM+Pp7q1CoQq
         xeds8VGuSFZP7YPAbCkFhz37RnTNt9qj3lljP2zNYRLg67G65UIQsNy6DyMXtEVcp8KD
         fSKfVblfEq4AYOgi280nOOb9LZ4iFot0/J7PL8NLmGT7cCVliM6CLt4zYesiM563YfoL
         mOrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=niyYm0qY;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id p4si322533vsn.0.2020.10.30.09.35.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 09:35:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id w65so5765422pfd.3
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 09:35:07 -0700 (PDT)
X-Received: by 2002:a63:d456:: with SMTP id i22mr2896479pgj.440.1604075707465;
 Fri, 30 Oct 2020 09:35:07 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6f87cb86aeeca9f4148d435ff01ad7d21af4bdfc.1603372719.git.andreyknvl@google.com>
 <CACT4Y+bJxJ+EeStyytnnRyjRwoZNPGJ9ws20GfoCBFGWvUSBPg@mail.gmail.com>
In-Reply-To: <CACT4Y+bJxJ+EeStyytnnRyjRwoZNPGJ9ws20GfoCBFGWvUSBPg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 17:34:56 +0100
Message-ID: <CAAeHK+wkjVVHy+fB2SHpqNOC3s2afKEGG-=gs=Z8nwwF7hJdmA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 12/21] kasan: inline and rename kasan_unpoison_memory
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=niyYm0qY;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Wed, Oct 28, 2020 at 12:36 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Currently kasan_unpoison_memory() is used as both an external annotation
> > and as internal memory poisoning helper. Rename external annotation to
> > kasan_unpoison_data() and inline the internal helper for for hardware
> > tag-based mode to avoid undeeded function calls.
> >
> > There's the external annotation kasan_unpoison_slab() that is currently
> > defined as static inline and uses kasan_unpoison_memory(). With this
> > change it's turned into a function call. Overall, this results in the
> > same number of calls for hardware tag-based mode as
> > kasan_unpoison_memory() is now inlined.
>
> Can't we leave kasan_unpoison_slab as is? Or there are other reasons
> to uninline it?

Just to have cleaner kasan.h callbacks definitions.

> It seems that uninling it is orthogonal to the rest of this patch.

I can split it out into a separate patch if you think this makes sense?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwkjVVHy%2BfB2SHpqNOC3s2afKEGG-%3Dgs%3DZ8nwwF7hJdmA%40mail.gmail.com.
