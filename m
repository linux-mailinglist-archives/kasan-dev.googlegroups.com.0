Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRFZ42AAMGQEZ7327CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 21DBF30CA1A
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 19:41:10 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id z3sf14098558pfj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 10:41:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612291269; cv=pass;
        d=google.com; s=arc-20160816;
        b=eIc+KsZTKMO9SvgQel0CVQG6FvquYKd+1SVr9nQg7nT/7vOLsbZ7/sC3BAtpW11tdr
         AK+paMFxZS/jI9U+ZJgSfhG4+jW0GObGpMxs5zoxPMTALT5M+JO+KaxCuz20Ai1HWfzT
         34NVR6qDi0ToAcP1FYCbu6GPmBfk6Okx/7U+3f0e3DmvaJW3c5dlsM7J2qOoPvHZPLSd
         nIHpOyQiCci6uTvm7A5gTXhsjRNGSvfpt0cRlUFjGxo/LfsFzSYJKv2plX4ygmez2NcD
         gz0VJ/5YAn5MvaKrDfu89dV3OI9aSEEw6uO7uxIwlJ4agt+NoTt3ONvYsPpAWhms6RAF
         eZaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xghrWBKyhXqYLpmsnC2oL+GIti8vs1AvfRygOfZJZK0=;
        b=f7nDuzTKiJg5wr0dqCVcGbrdv/XmHXevipbcuD9QwCQLJGi2adUX5pna2wfpnLH4vq
         m85XCs2LYIWuadmjnlp2UXKJSnKVbkiACdss+B0xHdeNwlzf5T4jdY/dCdwL7TEnaJDv
         e1L5AHQ7JewWZaynDSoQYWIrr5A2Tqonn2lSH46pgsSVE9T2//sxR9ubrP1apIXrhH0S
         wrK3RpGu+yEzt5uYqCoJ91Zjink5OixUQCZFQ33cmlvBjAJIRuTXAfniOntkhDXlw5v7
         KLYMrWFlVZVhSYkotDnQw9jd1Wvbjbvbm5TKi2B+3LrkoQnKpSAfUYDzYA9UWKFxTnW6
         0rQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s9rHW2e0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xghrWBKyhXqYLpmsnC2oL+GIti8vs1AvfRygOfZJZK0=;
        b=lwGKrHPeEhIpgy80TuySXST5TK3pqY1YtxzFs/Iah93boRV3122R3+QfcXIUKof4DV
         aovuM9a8c/oBzIWAKjwS/h+F40ZIEiWx9VmvzD0y7iUFtuP06MFL2gpp7/22Xb61eJ09
         kQ6GQGoDUJLIGaoEWmjO/ERsx+IX0NO8ZxkEyUa8qLzZu4MsRcKjPnY36EcQuvlNJFSm
         /Ki+Fcm3VvmqjXkpx3Bro3aABraljOLRe5YCCjkfwjApFjNT7fNLgCvibNGvAFCoSFY5
         AGXH5+jTr1t5KI2TrrMLI5ZQfZgfSgGnkjLkVcmOB4FCgma/Kp6HVqa61y2Jg7QX9rcB
         6mCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xghrWBKyhXqYLpmsnC2oL+GIti8vs1AvfRygOfZJZK0=;
        b=k4fryysk8USWULqIakfez2z1VBDaMXKh4GVZ+oYZOjPwX4hocsMbqIxs7A9XHS7QSj
         jmzzRs2FEA7CAqxidCV6qNV4WcM7/2W1pGYjZl31KPQKJhdXReyEEvyjI77yfpFWo0jB
         HUOwCzQpy5Z3fJ+nCH+73E+o2tqLnqkW+iCQ1E8T0I3Vl7bmH59DwhpSfYBWSA1xNhxd
         Ru7ZsT5b2m5t6MzepbnEtuE8TyeuFhMIFi51Ern9HAxbpzqG13e2tKGY7bKvPwVTgUGz
         1LPDj5B6YBXa3s66fVJ6j6hpLwMIxOT3IlLlJrdZ44yVudIYwbhrhZrwu995RBeLbjmg
         vwoA==
X-Gm-Message-State: AOAM533pG397p5wTdGp+9VRH882Yc68aJ7gKng/xGIri+VCBxyW2XxH8
	MTdtAU3p9nMdTrgC6/rrPqc=
X-Google-Smtp-Source: ABdhPJyO0Y61MAQN/qApv8achzXNDR2ozQ0FR1VD1eCsr1fKLbDUv421dUB/ZUBA5Hy50+gvB42HkQ==
X-Received: by 2002:a62:2cd0:0:b029:1bb:2947:5d5e with SMTP id s199-20020a622cd00000b02901bb29475d5emr509207pfs.22.1612291268845;
        Tue, 02 Feb 2021 10:41:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:cd09:: with SMTP id i9ls8200056pgg.10.gmail; Tue, 02 Feb
 2021 10:41:08 -0800 (PST)
X-Received: by 2002:a63:4d4e:: with SMTP id n14mr23249933pgl.37.1612291268164;
        Tue, 02 Feb 2021 10:41:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612291268; cv=none;
        d=google.com; s=arc-20160816;
        b=iu2X0SujRS3X4f6X9qYApEC15tA7yRgRuudHmU2L65G0KoQRMEAm0b401Dv4/UekW3
         PrqwqQLIL2dl+v86dCvf01b3QBZ5WSvhLsGdZ6g5ApoltCdETw67v5CksWj9kvXFpPFO
         yUc1efhvijJlHVa418RC8lIwiOLWcPw7c9wQ0dtwyRtOfT+yDC06Fv4QMbbSstrbqPZs
         KE8AuDBbvIIhII8ahLkgvr4XYuBd8/ShxmH//fYLnlb4n3guIWuAOLCdYFytOmDx2ZVG
         vbq7lkQ/CRM6jIJ+g/LRuo/3kOq8kUyaPPxSnDqRUb3KLMVQVhjGc+gses2zAYf4+G4O
         wY4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AM9+VMIDUzwgmsYBk9umRY0HUzM3XXRBDO1nka7d3og=;
        b=taV7dH+KQwoT8hHT+drunRZ1KljbjCLcOdNOiCOFw2XF7SVLgFInH9JzvJaNG7FUgR
         KKtFxbpDFXrTUhQhoR6sqH3deSzs1QWA3qZKFPSC8vSII5ogP4kyuy4uk8vfq1DgjXiO
         KSqlo2YnlscANLmUJZ504Q2AYrXae7G7NtrTELtumGBbT5H7PxjdsFJ33nfhf5XUzgxT
         J3eun31or5eogtPqFZ/HSms9kP3j2qwzNl1foYm/b5aD8vwU4s9x0HRtYxrB4PtwgsTy
         ostDZaio0nkAglawZcY0SRLIJ2yeA2fKZn6U/hAPwLb3ukrVL2KX2mqA7r8xr7FDZT+x
         /ddw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s9rHW2e0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id x14si1226259pgx.2.2021.02.02.10.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 10:41:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id d1so20798699otl.13
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 10:41:08 -0800 (PST)
X-Received: by 2002:a05:6830:1d79:: with SMTP id l25mr15633121oti.17.1612291267706;
 Tue, 02 Feb 2021 10:41:07 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com> <c153f78b173df7537c9be6f2f3a888ddf0b42a3b.1612208222.git.andreyknvl@google.com>
 <YBl4fY54BN4PaLVG@elver.google.com> <CAAeHK+wnufE=jOAOsG6LTA5Objcj=OyakEDr4zPKVW+Qq+y28g@mail.gmail.com>
In-Reply-To: <CAAeHK+wnufE=jOAOsG6LTA5Objcj=OyakEDr4zPKVW+Qq+y28g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Feb 2021 19:40:56 +0100
Message-ID: <CANpmjNOkBQdvgB-4QNXQMoNFppzVCsCz+ZcuviDL0HX5zJ4kbg@mail.gmail.com>
Subject: Re: [PATCH 01/12] kasan, mm: don't save alloc stacks twice
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
 header.i=@google.com header.s=20161025 header.b=s9rHW2e0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
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

On Tue, 2 Feb 2021 at 19:01, 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
[...]
> > > @@ -83,6 +83,7 @@ static inline void kasan_disable_current(void) {}
> > >  struct kasan_cache {
> > >       int alloc_meta_offset;
> > >       int free_meta_offset;
> > > +     bool is_kmalloc;
[...]
> > >       if (kasan_stack_collection_enabled())
> > > -             set_alloc_info(cache, (void *)object, flags);
> > > +             set_alloc_info(cache, (void *)object, flags, kmalloc);
> >
> > It doesn't bother me too much, but: 'bool kmalloc' shadows function
> > 'kmalloc' so this is technically fine, but using 'kmalloc' as the
> > variable name here might be confusing and there is a small chance it
> > might cause problems in a future refactor.
>
> Good point. Does "is_kmalloc" sound good?

Sure, that's also consistent with the new struct field.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOkBQdvgB-4QNXQMoNFppzVCsCz%2BZcuviDL0HX5zJ4kbg%40mail.gmail.com.
