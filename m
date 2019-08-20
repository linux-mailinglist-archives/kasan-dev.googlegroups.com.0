Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOEH57VAKGQEEAT5AKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C2DC95BBD
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 11:56:10 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id m10sf1993532oim.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 02:56:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566294969; cv=pass;
        d=google.com; s=arc-20160816;
        b=CysWcjk9Bv5N3hq3qODKmufN6SP5kMKOJHZHM7LJlkuCyHRWhtoZ6Hl5BrRqJySg3Y
         yZqZ6tQCFX+N6c90Co5awUAw7M3WsLNOdwFxWADFafIE4Ts3IA0Umem7EOAUrFlkWIKR
         6TdNpkwnQxJqylnkiv+vsEYJNMulH9AM6/Fr9flPJirgcoNn+aCC3PMKISHsBUjeQZzn
         IHSoTraaPTdnmsCpil+3IjrNhU054mKlFHOwsJI5HQWRwKF7a8ytQrB3uMPmYHrz7OBA
         AdX0vrEw8Di6sZcOp7J7nvDag+4LbkOa/XQGf8cJlJKTxuQtdoim+YB4Fa/6SegpR3rU
         dGPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ugSFdEyPNmzAJyMqbQvH9dOJ1SfGbn1YcqlhS9AKjCY=;
        b=jU4m8ujrVYDNPiYbZdJyVFsSppr5JweiiHK5gW6L1bs7Q8U6+YSGSyUhabfJ8mX+x3
         R4V1/nrlnsckeYra6SyLbF/m958XQfsO5bMu/beD+qWw4RyHm9kLFQxnjhUm5qlXFqU8
         tbhYSuy/gw2ScYulmDu9PKjJ2rKsBL84/8IKuMNaZBqCzZuzD8jWzIhEzVU+T+9VHfRP
         xdvxVM6ZokE7Q0/68DIeI6lJhfjPM9Rne8Gw/cCWdXgreJvqX/eX5sg3wbbAUJNTcBkU
         V+rJAYsO+J2+DzE4GPE2FPrs7jZ2LjOMykBK+P0QUI5r4WhsnuLCzH6uiXhVKInFQbHK
         nZEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=esBS8tvW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ugSFdEyPNmzAJyMqbQvH9dOJ1SfGbn1YcqlhS9AKjCY=;
        b=Xm3TK3HEqCy1BZo0hMYC5NVrQH3ngTIFDRMBknwJe/1Ax4Uev36cV8TzzGgqVvssVQ
         0Sb8GZFHyvyUm4LhG6oSaK+LJY1m0cKoAyIOFbk5MGvc/2O1D6qbdfFAAFD7oJCmjbh6
         PAiRgJi0UhqeH1wiCBb/vxmF34ZLSfX8QL6YkfLrePLm/aVqPjAeeiwafXqrBnmOFq3E
         Q52QqRCto33X0R13EsBNp8Y3z3WGySb8GVUO3/p7kw3RenlydABl9WetIwWIETi+nfCh
         M9BHoxEzJSkJ7x/HS+0MOLMitaYYAOz0g4tdcEGMGLx3aYZmVHZeBrio8SrTb1jChPRD
         tARQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ugSFdEyPNmzAJyMqbQvH9dOJ1SfGbn1YcqlhS9AKjCY=;
        b=dk7FsQQTBiLGTPkMIxSaDTlu/3DuRsBtEecMmxDLL+0OCixEfXOjKeY1rY9dBOMCm8
         rFc5oBri+ZZC3JZ+Mt25UtMl8VAYd3Zwfdie8mP/vzRTCPMVG0k+G3PNe1FjQrcBK+TU
         j97UyA9KUL6GkhQZQiTeVHHdPIxocKoEqFYEkbuRmHrQA4sqruHv8a2GNrTWKKPyTCV7
         zQbJFlTvVyL3utLSxToTvZFf2pJB1piVS7t/Zu/lrjMsNr+jDH1S7HtoxdBuX37eHRhn
         Rr6a31d9rf2yUvMRZhZrZ5oGVltnTbkqRgStB0ActNt/7k6BRi1wef022mXf+L451emd
         yutQ==
X-Gm-Message-State: APjAAAWf7whlqYmIiMeOVxxkcxNPDHSpvhn8iNZ28tTvcyxXsbeMcwi9
	MOzmqe4nylNswtJUC480Tlg=
X-Google-Smtp-Source: APXvYqzKjOIPXGaQOyWQ8k5ySF3TplJox3b9mQAJxiqGwya9JHxkedrGAfY5B+1Trf3loU2ei+qjWA==
X-Received: by 2002:aca:b104:: with SMTP id a4mr16834072oif.14.1566294968792;
        Tue, 20 Aug 2019 02:56:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:b8b:: with SMTP id 11ls3351643oth.6.gmail; Tue, 20 Aug
 2019 02:56:08 -0700 (PDT)
X-Received: by 2002:a9d:6c1a:: with SMTP id f26mr22878238otq.83.1566294968497;
        Tue, 20 Aug 2019 02:56:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566294968; cv=none;
        d=google.com; s=arc-20160816;
        b=CcHo/bTfeGSLKtAhn+iss2NWBs0MhDVoUHQrtjrh4rWkvQ/ofQkFK/Bnl3EmyJkSXA
         9YvRwPizPpx260a3Fkdvi+sonZGcGGVNgwncU1CJwnisM6VUhirjY+DCyEvLs6VQ915L
         muA0TwOCoW8F8RCSFrk0p40vWGG462xysQxi36wJi3XxBgWbS7FEcb5gAlvjVameFhyq
         2P14nxk4qXGmaPjPmdjpmEqdND/vpa7j3Dst1Yc/OkDXuxDmJD9FwPiiC7ICg1TqZD1T
         No+gNqPIBMvZTOvKS3KIep7Un03gGKxqW+vztNRzrZ3uSYS2Z0Cgz9uZKrmAwLvMB1N+
         V7Og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ERy6C+OfX7AwXRit4NjtghifEuheVTJjPNjjGxnVXl4=;
        b=EBUIc42rxEuQP2e8wnaWUMkoOXbdr7XQAdsOt+mNqmGu07JRAhptXt2JtLNEHIIwVl
         AEVU5/NU3FI4gMEPyWui5kM9EleQ79hsiUrg4K6rRkyJjW4JwFZlcezkY/hOJnVrYE0w
         Jn4DQgZ6lpc7tPMD+9ySyMCY2QDUVyKkMkUhEk7vIg0XWzy0tBqa/r4v8hsZNRKWssiw
         eZ6l740YdTmjNrCEXvIg2r/oKVrrhYILb0kDSPLuh0Ejy2aza8YM44BBTlYkWYrMOlln
         CBEVagt5zQEwCh06a7KJCVbMRXKn4eV/BZkkp5DdqmZLgFp7Dozzu2I9GbDY2Xsw32u7
         U+bw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=esBS8tvW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id y188si705784oig.3.2019.08.20.02.56.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Aug 2019 02:56:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id g7so3630674oia.8
        for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2019 02:56:08 -0700 (PDT)
X-Received: by 2002:aca:c396:: with SMTP id t144mr11367178oif.172.1566294967836;
 Tue, 20 Aug 2019 02:56:07 -0700 (PDT)
MIME-Version: 1.0
References: <20190820024941.12640-1-dja@axtens.net>
In-Reply-To: <20190820024941.12640-1-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 Aug 2019 11:55:56 +0200
Message-ID: <CANpmjNMpBAjX4G2GYmM6-z8TfXdbzLCuAMQ-fmGRwEDFMci4Ow@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with
 generic bitops
To: Daniel Axtens <dja@axtens.net>
Cc: christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, 
	linux-arch <linux-arch@vger.kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=esBS8tvW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Tue, 20 Aug 2019 at 04:50, Daniel Axtens <dja@axtens.net> wrote:
>
> Currently bitops-instrumented.h assumes that the architecture provides
> atomic, non-atomic and locking bitops (e.g. both set_bit and __set_bit).
> This is true on x86 and s390, but is not always true: there is a
> generic bitops/non-atomic.h header that provides generic non-atomic
> operations, and also a generic bitops/lock.h for locking operations.
>
> powerpc uses the generic non-atomic version, so it does not have it's
> own e.g. __set_bit that could be renamed arch___set_bit.
>
> Split up bitops-instrumented.h to mirror the atomic/non-atomic/lock
> split. This allows arches to only include the headers where they
> have arch-specific versions to rename. Update x86 and s390.
>
> (The generic operations are automatically instrumented because they're
> written in C, not asm.)
>
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Acked-by: Marco Elver <elver@google.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMpBAjX4G2GYmM6-z8TfXdbzLCuAMQ-fmGRwEDFMci4Ow%40mail.gmail.com.
