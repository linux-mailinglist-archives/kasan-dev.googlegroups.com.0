Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2WP7P7QKGQEXDPVDEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BF852F4B47
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 13:30:35 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id l138sf1113984qke.4
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 04:30:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610541034; cv=pass;
        d=google.com; s=arc-20160816;
        b=sjv7INhZfivXmnElApT9n3WVB3jctO4JEZhmZW+jVgyuJNAZw0bh9yAdwQwRyAGeeg
         8f8bT2L8isSzn63FnlDCZB0FM4/nDSRW6pjjdFFr0FmxKm5kiUvOTcEcp/1qCwufGnvV
         xdgGX65YVl8G94YM3yYQk6ibBMRx2NFfh21P+JcQ5Q+cvKsIdJf3Sb35J/kIOjCiBkMy
         ZGSkKzZ8/ky781IZhCjvXcT3CzjBVPVUPvN5aBiePgA9wvKoThUHuS79yK2zEnVfLSQS
         Q+wGNFEwZ/FY7cKqYViRhx2g+VFzBsawfoCBCZq/nT/kv/HZHy0IfHVSD5xmKMGJgadr
         JVUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GQKtryblSeaQw+xusodf/oU59GomlcAt1rIkOmjdJDI=;
        b=rOaSsiqOc2dK11EPzi38JC/vg2xuoGG7pO3GCW36vJOgDocOjlEzcKEdfhnQZrJCkX
         YdnMsoIFcQIaRaI7e9njBWGnwY55Idh0zLiDtVtHJB9H0PzKdHHCWC9KFFKDmnhvxNK3
         jiBEL7LzsJIc+W+n1U1evfBDkw99PluE6R0v5pSyb6kM7ILMAmRN0xbd/9uOkCBLsSQT
         oMGW1LWcryiydEhDEo6XyJYFUfcnZs6g3NkqzQZvcVKf+NZMTgPkP6mOFT5WuyJMVdxH
         VcXzjA1ST7catokf4MggHw0vzTDi7K4hYV8U1rcTqrMXnNu5asUGQSnvegBlE8n8fArs
         Gk9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A4DDeU2V;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GQKtryblSeaQw+xusodf/oU59GomlcAt1rIkOmjdJDI=;
        b=gTGHRqOFsTvx9IzDeHU6uU4QpYCOYqf1TvaSuQe4vQvSKzMTILyaqWD/xYdoyPmFeM
         KmZaWB/uxALrmGQlG75ZepyhBRGCyPiIbDupAqeU5V1QXQDQgm/JZrsKQseelQqXRrDR
         nzlI+0te6vw6sJwzn6ExoCQfFikJ11I5C9pwIyTntQokQv/grUUtx6yRnoaZ0m4zwBdU
         TFGx9evYI/atvA0nQ/dgWrkfKIiXenJWXKWfMkW1TKRvsKkMzK3aM9hcYLVeoLXSGnF4
         MbAGvZZ/ze6ZhM7gVv45XtqfAPKS9qQg05KdArXkcRamsAvwNX8s5LAljaCDBtJ/M+nW
         mubw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GQKtryblSeaQw+xusodf/oU59GomlcAt1rIkOmjdJDI=;
        b=c4EHsHuLKRe3Q2cAxhBJdmFhzGTLzTFLR+41KGAcTutcWn8TpbuicJMl4D3r9j1vJB
         8eAWH+tyGAeB4wKNZJg7KdJrLmm5N9fn3RoSpbHjCthIZN7KhuaNmtY6khvNT6/L+407
         yQDIG2W7UwdxXiOcfi7h3DYYUYllBl7TFQHEKlw0qszc73nNBsHC013uYt+ojaPUU/tK
         zalxMd7Wl13mFfAj2qTNksEvqvPyigfAyoCJkL5DQegrxbY0QoQSuo4JrlaQcFt0cDdn
         9gfxDjrhP4Jgl3sMwIQGC1Op1zhJwlh2QAre2zXOoUlJ8ENsprFSkcDL9AkTt4Ar4GWz
         cXKQ==
X-Gm-Message-State: AOAM533TW9SwMnJ0z64T1LnTmx8Lj0yVcGYE4M8EmyLAGYHPmBEq5uOs
	tKmTN4mtgs7twm4CHtcmzK0=
X-Google-Smtp-Source: ABdhPJwRf7gu1ijVh4H24+SkgvbYH63n7Em6DxSBBdqjW/Ysybu03UHIUtYSl/M1MpMZ36TGIq391w==
X-Received: by 2002:a0c:a366:: with SMTP id u93mr1984489qvu.53.1610541034309;
        Wed, 13 Jan 2021 04:30:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4812:: with SMTP id g18ls399364qvy.11.gmail; Wed, 13 Jan
 2021 04:30:33 -0800 (PST)
X-Received: by 2002:ad4:4b21:: with SMTP id s1mr2093404qvw.59.1610541033868;
        Wed, 13 Jan 2021 04:30:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610541033; cv=none;
        d=google.com; s=arc-20160816;
        b=Didecy3iGtZ3sJ6isgq2xtMk0ub0ycYXXSehZ/M9iV6rWL1lahGcfIRzdmRTzs9V7e
         F/fwzlNYQjlOftQzhev8z5mDcEAcqG8Tqgiox3fqc+8nqhdG9D1mZJAzmx5Nh5tLIKwr
         hLihquDOzzkkkgJTnS9UNuoJ3RHB3XhQ2/UqEHc9Cb/L6s6p/sdokVmaIJd1HMQmz1PU
         gtSaCLaO/SPz2CbxdQ1FfdY3YeUt6/uuRtIkhT1RQS1aTfknL5ADnQYnG6Vng7gYwfG3
         slWCshoiB+KcNLqn1Jq6qwe8a7rBSfZmcoxUCZPwmUQ4m0qeUYC0JOh0Eda3Ylep1A8h
         BWBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YHb853OW+nOYLu/IE6QCDFLb71LosLe9lCUBT46DGFo=;
        b=b8e+vPTLfdmV+6UhItNxpZZW2YScGu120XaDAkXZXkmLvPizj1v3guKC4BR4exNe3d
         AKB/V3OngDk1WovwSkkEe588bSnOfDqiE3pys/80l8M5zWVqk4q8Zj2rcO4cuCuQc1h2
         Y7o08XaBmZsjk92MXXBbIEfqTFIb9/Na0AAC3CYJvPWNNO/te/27CnKu24YaVlvb+iWZ
         voKj3HLqRZ6Nb8Iai+nK3wPhKho1zdUbPFl4lTRRkrtqq8lJP0Cs4Lz8dRWoUy70sCkC
         Ief7GlF6wBpSy0Zd8TVg4JxX4we3V/GJjYee5kTWftv8E70EwPtZQbyVn50gQqmWZiEX
         sp/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A4DDeU2V;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id i2si92593qkg.4.2021.01.13.04.30.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 04:30:33 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id b9so955703qtr.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 04:30:33 -0800 (PST)
X-Received: by 2002:ac8:6f32:: with SMTP id i18mr1908368qtv.175.1610541033304;
 Wed, 13 Jan 2021 04:30:33 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <0c51a7266ea851797dc9816405fc40d860a48db1.1609871239.git.andreyknvl@google.com>
 <CAG_fn=VXe2AZZ3q6+HoV+zB=9GLP+kgyW_r9hfqvX-NJHurTRg@mail.gmail.com> <CAAeHK+xbYpuipd3+Jew7=fL8Mn2J1ZzOVyzK+X6bvtLCeiGFuw@mail.gmail.com>
In-Reply-To: <CAAeHK+xbYpuipd3+Jew7=fL8Mn2J1ZzOVyzK+X6bvtLCeiGFuw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 13:30:22 +0100
Message-ID: <CAG_fn=XfNb_tuUiGDhRAyihTQhW8RQ8zVjT+gXM_Efhw0cBg6Q@mail.gmail.com>
Subject: Re: [PATCH 09/11] kasan: fix memory corruption in kasan_bitops_tags test
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A4DDeU2V;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::830 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jan 12, 2021 at 9:07 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Jan 12, 2021 at 9:30 AM Alexander Potapenko <glider@google.com> wrote:
> >
> > On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > Since the hardware tag-based KASAN mode might not have a redzone that
> > > comes after an allocated object (when kasan.mode=prod is enabled), the
> > > kasan_bitops_tags() test ends up corrupting the next object in memory.
> > >
> > > Change the test so it always accesses the redzone that lies within the
> > > allocated object's boundaries.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > Link: https://linux-review.googlesource.com/id/I67f51d1ee48f0a8d0fe2658c2a39e4879fe0832a
Reviewed-by: Alexander Potapenko <glider@google.com>

> > > ---
> > >  lib/test_kasan.c | 12 ++++++------
> > >  1 file changed, 6 insertions(+), 6 deletions(-)
> > >
> > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > index b67da7f6e17f..3ea52da52714 100644
> > > --- a/lib/test_kasan.c
> > > +++ b/lib/test_kasan.c
> > > @@ -771,17 +771,17 @@ static void kasan_bitops_tags(struct kunit *test)
> > >
> > >         /* This test is specifically crafted for the tag-based mode. */
> > >         if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > > -               kunit_info(test, "skipping, CONFIG_KASAN_SW_TAGS required");
> > > +               kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
> > >                 return;
> > >         }
> > >
> > > -       /* Allocation size will be rounded to up granule size, which is 16. */
> > > -       bits = kzalloc(sizeof(*bits), GFP_KERNEL);
> > > +       /* kmalloc-64 cache will be used and the last 16 bytes will be the redzone. */
> > > +       bits = kzalloc(48, GFP_KERNEL);
> >
> > I think it might make sense to call ksize() here to ensure we have
> > these spare bytes.
>
> Calling ksize() will unpoison the whole object.

Ah, that's right.

> I think it's OK to make assumptions about KASAN internals in tests. I
> would actually say that we need more tests that check such internal
> properties.

Agreed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXfNb_tuUiGDhRAyihTQhW8RQ8zVjT%2BgXM_Efhw0cBg6Q%40mail.gmail.com.
