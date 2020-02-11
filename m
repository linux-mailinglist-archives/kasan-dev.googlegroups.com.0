Return-Path: <kasan-dev+bncBDK3TPOVRULBBT72RTZAKGQEPOBXMIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E6238159DA7
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 00:48:31 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id j1sf13369lja.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 15:48:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581464911; cv=pass;
        d=google.com; s=arc-20160816;
        b=kJtJEFDhHgb8JYreFMk79/POd1PL65UtY2vwb346CuJVnbeVoQyoYYJc0SUjYiS4q6
         WKqjmpvKtMKFc2s3u3fPuI7pKgP/XiJ04NIxiGzp3iisrD3IZ1ck/EiFoWslX1dkbzWK
         UkhSTCb9Vf+0s9mJnNCAtzAedWs7ksuaWo/2/hroWpr5If/BqQ7+b5pzGdGzEWa70ZSm
         +THoyCuLcTmH7xQh47A4YWGSrwHmLADqS+Lent5DekQp4VbkyvdUoNVSIDLHno6gdvix
         OsZ2UxTr/DVVeQc2GXKpKblBPqhK2hi8nTx1TEhu4wdVDG+9RUF3HNSAQ79y4iWQA+mM
         UXHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PtS9xefayivHBDttpCM8hvnfJABuagWM4CYXp1dVY+c=;
        b=Yy8OANg8zeXseyYCEBOFQIQIGMnGezxJA4X6lRIMbx1k2An99ptrIMeMU7nA5iq6LY
         hIu7KQyPRZBfKk4jq2NUdUYahetmAJXtK0royGM5TFHLYhNTItr042rCOEIeGvnpc0oX
         arP0pms+BQh7tbBnwo9jCP0Ojd+euRNbal2zZGQD/fiGeMcwfOxY0NfBVIswgH+by5hD
         VaGxSQyP2mFOPZ83MBV274QmKPXFqcRdhC2xsssUl0GgqdeJ9cq3hZ4G6g0okuJegzG8
         v4edn3xGrqyQbAyQIOFyuV3bp7Aih4zozhC9K5p0qvrzpFrQluv3Q/DcDLceHQPrNHXl
         RSig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oJdxQzfC;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PtS9xefayivHBDttpCM8hvnfJABuagWM4CYXp1dVY+c=;
        b=cR4sCzbHxE0jrBkahIav8RhKPOXRH5LrOJIwAOu6ZacyUoSttSMcPslDG8J48PCmU6
         fQnO2yNehFRa+CGoJiQAQp1/rD9CIRNaimG21R7Fj0FHYUSjLaYEJ0bew0NSUD6ngGIu
         Ns9sm5yTBjUcQ6q+ppCjFEtlNDpdKUbFzTSYirnuLvyFBui8JUa8UcOW5y6K9o5ThCdx
         UZdv1D8Lt5ZuTbLDFVBGbRLXLpqC0RgcBscED9gqirXAjh6qGiErf3tZL0YJ0R52+5Jd
         JOXg/v0OPJwaFVTMdg0fshUayZ3AyrpOCuaJWK6HGzm/jsE+rLp3PoAE1fkYJlQB80OJ
         y3ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PtS9xefayivHBDttpCM8hvnfJABuagWM4CYXp1dVY+c=;
        b=cHMC1Qy1sF00vhN8GiUw821cJRkr2I4EfUUJK/4y9bryhodkleM6PL02QVD/JIsczp
         9tyvq9vn7SZiE5GezK8TQNb77hkAuiaZe5q+Lp4pZUSUI49ycvW41FUZLkdKSUsTEr52
         GTvmSLxO0whNAemVO1Fdl81kIFemqy50ykwHEt4RKAYrYH0rREplmcrrsjEYQ2CGuQB2
         rnbecgwTb9uEPiLDoZh6coz7tvLEnCnTRpGajJhV5zaOPgzzKMg3NAJ6c0Lw+7carjTt
         i4YgWdIIioDgXTridrEbyHbEO86l58brfstEWI7DUahZ2gs+23Ta2+QqoFbHbz5av3Qc
         bGtg==
X-Gm-Message-State: APjAAAX79T6wWqq033HxUfclU5A5NVFjrn0g8CJhfbeEb4+Nr29eLHS9
	Cpfbk32CiwBjMKHE4IioriA=
X-Google-Smtp-Source: APXvYqz/AuyWnll+IfBEsUi4r4vkuxPl1D+Cs7uwC3kQVjVhMgMtp9CG6X+f6HY3jtjIMSXols+SLg==
X-Received: by 2002:a2e:96da:: with SMTP id d26mr6087492ljj.6.1581464911480;
        Tue, 11 Feb 2020 15:48:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9786:: with SMTP id y6ls2837936lji.4.gmail; Tue, 11 Feb
 2020 15:48:30 -0800 (PST)
X-Received: by 2002:a05:651c:10f:: with SMTP id a15mr5897545ljb.237.1581464910856;
        Tue, 11 Feb 2020 15:48:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581464910; cv=none;
        d=google.com; s=arc-20160816;
        b=QPxVaEb9ZPIb9DU1lmQ3TInxSITOvtaVagMiOCbrD74WQ5ChZJtaHgqVfFbBfvaT7P
         DqGwMVYiaEntvu9SOUr/65WmNnqJnkLthlQt9knVkUnPXOlkWpL+Qw86bmfK3Y3C4RgV
         7CivxpxotI4JaO9ceriSvZ3jHe2KfPZqt2hKfMUsZsQ9YvqqKJKhL9N5yHL+DBtggNmN
         SaSQX83ROWuIdmd0Oenoa0r4JN8rLgARLPiMX4G/+TUcPjCh6gn7sClPjV5NIkbCJUhr
         01A1gecWEEKfS2OrmEt52nag9jhSIpQi4NsH5R/x6n28mkGPFMquJCsnKlcAie44+RIY
         iaKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tKZVKd7LefiyWeQ0F2PuNMLHXMThkRotLuzYefuE5rc=;
        b=qj7B6O1oVOwrADOTuRWMktJ/4Ubru0JOa5GwgqQ5HpfjCATBxMXiCGFoRnLsU7ysEb
         YLyCZZbzCyfyhRwSh3NW2nOBy1QYcXxnkgLtyGhbT9wRxyAxN+hkj4RPBsz4SlHkTLGU
         CmJtvopBvuZZDj6N8BvC7Uu8j9/r8d89d/5oWke329lVlEvEVJh/ge4l6l6QwzIVtSJn
         We5WTbClPsmqRB6v9tQtXXwcMCoVoIJbcc7zhqUR5zAsl0gdF1DmaS4JG/VeSsfIXAYh
         z4gTUlPGrv6WhOYEVOaVtPiWgQm5Gd/CReAvEk4bnq9Pl2hJzE/NWNvALIvn1ap9AR7b
         zkCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oJdxQzfC;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id d8si270928lji.0.2020.02.11.15.48.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 15:48:30 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id m16so14683136wrx.11
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 15:48:30 -0800 (PST)
X-Received: by 2002:adf:dd51:: with SMTP id u17mr10871983wrm.290.1581464909891;
 Tue, 11 Feb 2020 15:48:29 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com> <CACT4Y+bPzRbWw-dPQkLVENPKy_DBdjrbSce0f6XE3=W7RhfhBA@mail.gmail.com>
In-Reply-To: <CACT4Y+bPzRbWw-dPQkLVENPKy_DBdjrbSce0f6XE3=W7RhfhBA@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Feb 2020 15:48:18 -0800
Message-ID: <CAKFsvUKhwAOV9O+LWBr=-zLEJCFJvKOH-ePsXMMVJzHotqd3Ug@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oJdxQzfC;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Thu, Jan 16, 2020 at 12:44 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Jan 15, 2020 at 7:28 PM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> > +config KASAN_SHADOW_OFFSET
> > +       hex
> > +       depends on KASAN
> > +       default 0x100000000000
> > +       help
> > +         This is the offset at which the ~2.25TB of shadow memory is
> > +         initialized and used by KASAN for memory debugging. The default
> > +         is 0x100000000000.
>
> What are restrictions on this value?
The only restriction is that there is enough space there to map all of
the KASAN shadow memory without conflicting with anything else.

> In user-space we use 0x7fff8000 as a base (just below 2GB) and it's
> extremely profitable wrt codegen since it fits into immediate of most
> instructions.
> We can load and add the base with a short instruction:
>     2d8c: 48 81 c2 00 80 ff 7f    add    $0x7fff8000,%rdx
> Or even add base, load shadow and check it with a single 7-byte instruction:
>      1e4: 80 b8 00 80 ff 7f 00    cmpb   $0x0,0x7fff8000(%rax)
>
I just tested with 0x7fff8000 as the KASAN_SHADOW_OFFSET and it worked
so I can make that the default if it will be more efficient.

-- 
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUKhwAOV9O%2BLWBr%3D-zLEJCFJvKOH-ePsXMMVJzHotqd3Ug%40mail.gmail.com.
