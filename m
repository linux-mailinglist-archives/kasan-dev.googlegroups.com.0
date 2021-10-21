Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7GRYSFQMGQEC3IZDFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DC66435D44
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 10:46:53 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id o12-20020ab0150c000000b002cb5393147dsf1356609uae.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 01:46:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634806012; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kv/DYW+gS4qosm/um/AcBkx/cy0REwYyY8nCcVr3Dim81WDiHJlNNaQVBiVSu5qsiD
         gx2RPcwELLU/2OhZApLrkuj8k4S0hsFknwN4qaPQOGL3K/0u3UEI0Jac6QVLFSHAdE2g
         2emmw1Jmd4RPUKZknDBJEvfNFldECYPpBHdti9YrdCHZ3FvLrl7nIwRadK9rIA/h8u8g
         1cHvMlgWH7ddwxZOZ6vbYioK/VhLwT7qQ7NsucY5zNQxTM1jTuRXZ2LguwRXB3TAJKEf
         4U16GPxRFj+r+gpaufe1LOEQWcgJJuyCcXXwZKuaVBffUy45f6GQrRzR9N5e/f163fx3
         A+Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6Hd2v19tJGpuyr+vU/cSiabKd1BSkUJG1ko6CvKiOA0=;
        b=H2VgUuQKlaye+U3RD+14YW29aP8UbvtSm4abAjxj3vaxOcQtbpm+Sz2gMigq3faXP1
         XiJPRt0I7BV9hRpUfwlWN/gdEb+9/yUjjM5hTNh+/ICoK1KoiVG4A87gtK10Y1apm6M4
         OlWIeph35gmxQg94cxyrfzJlN2eK+gZHmAa9cb0ORLA7JwVDhdJRN9VK9JDwqeZ6SJVS
         J/vu25cOLYquLlWI8S1LTN6yDMcSdFXAB/Xv43c31KdHFfY15pNat/p1OSGlPWVEB00I
         jkTtEfo+1pCEt1xhjDl5ftMjRrJmhmSqbmM6ESvILEEfv+V+wFMMd/w6H95/zCfJB/NH
         fgug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cnx7RWXe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Hd2v19tJGpuyr+vU/cSiabKd1BSkUJG1ko6CvKiOA0=;
        b=YD19HX1O7NpQCcL6GmCFXVHphyVN0dcsUf08P8UEzLjX2saheZZMAy/kJ6XcgA0s6O
         076kHJMMh306PA46DnV8meKDN5a9yA+2vqo7w69hk6TbMUcjO4pH/2Pij7EoNIZHaLGy
         dC0nZWKY0EOP0uuQ/GOdqM3GAYtlSqfV4Q0CbQ9/itXkrcgQcx2GENfoz0n/p/rvZiz3
         B+e4udBUcPfEZOfRdXNvy7EvSFa3VKM4k45ANZUQwQWHRNurLc0K7ROilwM7sewJq6+K
         oiFeYPeFwtD7d0BjGkdSNcoNgfWY2QYWrH35LpHQqihhN2FYEedfy7o91ZNbGkJBE14c
         IM0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Hd2v19tJGpuyr+vU/cSiabKd1BSkUJG1ko6CvKiOA0=;
        b=6rjuLih8NaX6ONSAjDYLqNqncPqSadYYrDiU/6QKoaRoErJKKMCz3o2Vqm/DRfO+Ma
         mDTvorK1O9iLRS5VhEHc/YcpjyE98UdLNt8c5k7YXISpeFJL0G6UiDVa57eqVcLJPM/n
         rn85PgVEucgPVdjrgJstMXDgrhiPst2ohjaquaMdYjDHo5ipnJ8ETcoAIz/CmT+0F3FT
         Rwxzu/76YnQUXAMOgoXPc9gc1qhGOU7d7Mcs2PlpjhA2s/kjZUz7567gX56kus84TjEg
         9jBKb0nBuNDxacAn665JTBEOrMOuvpKcPOAClzc8KKA4V7Kuu8nebjH2tchIeF4b4uAi
         CKew==
X-Gm-Message-State: AOAM5308KRL9rckFM6sZ4HJA17OC5aSMTr4gPWjrIJAa7HlpKQMyuVVn
	pxbRubvCtvnKHJS2MRrLhSs=
X-Google-Smtp-Source: ABdhPJya1tMvomxiBv/Ly2VMrMXupD0TsQai4GafdQezvDtQMYOBJ7jxoif+dUT9dvJ8RS+FJ1IDZw==
X-Received: by 2002:a05:6122:2194:: with SMTP id j20mr4583536vkd.16.1634806012137;
        Thu, 21 Oct 2021 01:46:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3763:: with SMTP id o3ls963202uat.6.gmail; Thu, 21 Oct
 2021 01:46:51 -0700 (PDT)
X-Received: by 2002:a05:6130:3a0:: with SMTP id az32mr4693821uab.137.1634806011625;
        Thu, 21 Oct 2021 01:46:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634806011; cv=none;
        d=google.com; s=arc-20160816;
        b=cJWGn9DdMj+qRkwnUTNqJtq42gvlWIo57zW0DGeS02uwi1Bf1JxQ+w5hZ3+VKTVokG
         RFT+r/C5vWSJwvw8gW9hjlhPOFPn7Ut+HChh1/475YGSnDivPIHK4jEXRB0KhFW+4XkU
         ySV9gIjGouJ1D2eBLAuOWUz7EnU4tdqRlMHlv3qPQb6WgzfQPKmI0hXZZIdpGoWQ63/C
         fVJO/vqwMvm4QPN3JJvdcqOq2q62A73Rh5SiBkF0pXeSk/SG+JnX8kkhfPhtgQRKFKZE
         a/3Cih9Q+KwoSYM/FffFl+o8T0hBvYHpWp6M9D9JD/w6kylCMnptpdAowomGNJeqVL8m
         iYQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LdXFjy61Qy/rnsWDdjxcnajZ2gMgamPPbsD5FZNqukA=;
        b=g8RfNUg4KrF+EaEOH7qngxneozEfxiyLcLBeg/lH2Ui5wPshUeyuWKCjeOdyyVJaoM
         RKjbAO03e0yG0Tj2svyjnmnrCsGth0xlx9NSzCcDtfcQuUvCgWH4LT5RRRmFJoEH1I8g
         HnK+t6rCMsSN4WiQpis8JA40VOLwg3zi3fe/YQPH9CsvchVg3S5yi/nBb/AmJQxsqoke
         UpU62j/cuuII/1MmoKcSQEPtZ4/OHS6o+Jpe8VzLYg1flPpH0Onlmx4nuorqpZsjnD86
         n1ZVQRfrKfv4DwrAewXkYgDUvbO2CMB6tuZdPZnUAsty82q3s0E5ZOlrmGjcmSbCSxos
         mzEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cnx7RWXe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id h133si320715vka.3.2021.10.21.01.46.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Oct 2021 01:46:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id o204so12831670oih.13
        for <kasan-dev@googlegroups.com>; Thu, 21 Oct 2021 01:46:51 -0700 (PDT)
X-Received: by 2002:a05:6808:6ce:: with SMTP id m14mr398982oih.134.1634806011175;
 Thu, 21 Oct 2021 01:46:51 -0700 (PDT)
MIME-Version: 1.0
References: <20211020200039.170424-1-keescook@chromium.org>
 <CANpmjNMPaLpw_FoMzmShLSEBNq_Cn6t86tO_FiYLR2eD001=4Q@mail.gmail.com> <202110210141.18C98C4@keescook>
In-Reply-To: <202110210141.18C98C4@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Oct 2021 10:46:39 +0200
Message-ID: <CANpmjNNwEXH2=mp4RS6UUU7U9az7_zgVM223w-NJgqw1Zp-4xQ@mail.gmail.com>
Subject: Re: [PATCH] compiler-gcc.h: Define __SANITIZE_ADDRESS__ under
 hwaddress sanitizer
To: Kees Cook <keescook@chromium.org>
Cc: Miguel Ojeda <ojeda@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>, 
	Arvind Sankar <nivedita@alum.mit.edu>, Masahiro Yamada <masahiroy@kernel.org>, llvm@lists.linux.dev, 
	Ard Biesheuvel <ardb@kernel.org>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Konstantin Ryabitsev <konstantin@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cnx7RWXe;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
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

On Thu, 21 Oct 2021 at 10:43, Kees Cook <keescook@chromium.org> wrote:

> > Other than that,
> >
> >   Reviewed-by: Marco Elver <elver@google.com>
>
> Thanks! (Oh, BTW, it seems "b4" won't include your Reviewed-by: tag if
> it is indented like this.)

Ah, I'll stop doing that then -- or can we make b4 play along?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNwEXH2%3Dmp4RS6UUU7U9az7_zgVM223w-NJgqw1Zp-4xQ%40mail.gmail.com.
