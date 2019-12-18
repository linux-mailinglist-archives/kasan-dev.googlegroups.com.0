Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB3OS5LXQKGQEMWIGVMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D4F771256CF
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 23:34:22 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id f18sf2087291iol.5
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 14:34:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576708461; cv=pass;
        d=google.com; s=arc-20160816;
        b=GnyOUrJiqRfsDIm/OBWjqpjs+G2tHh2Ph4ThFM8PMzbQM73kwKruGZrjR0mBfAFcc5
         +pYC6BS05MoZL+CNAmikVLUCmWD5pQyXdmlxyuejx0w1Yhrv3bYdjIug1xVKVE+ikfYa
         ZFSHMO4aIopBOseqvwZ5oUOdb7O+xeNwz5VX03qHhM572p5z6GP0kI5np3Nq4Grl0uhh
         btkWvFTmZFMRJ/qrjsA2ZYFpQsELy/dyKDCWOI1RHkGmzeQh1+2gRP77znyJ26b/3U/Z
         IOXCyScV1t9qIOM/B3SxGyR95kIcLbejrmoE1e73m4ssaK0jDy6Dw1qmKtA9oECUmAvb
         Oz3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vUBP420McfCQDGxwtVV3nMYrh/fvL3eLBO984qeHeDA=;
        b=eG8xhPMBqnyU8ef6sarOw3Nzx2TCAaw19Y92uc6gJRpGGNq7KjA1XUh6am1+InfX71
         ZMKftZNDTjhSNs3PHdwSdSl90/lhJgFw6g/fpMuttUhqJLE/ElDLoj+lqqWnHtLn5NMT
         ivUpjFsV1dZ9e17oGeFDuhsDv86wW7ajF6mxg84zRLm6IkGP2Ft9t1OPWHrCIbq+oAps
         HVSQgyabYU8KSFV4L09caolaUuMBVEWw8RVbtE8/DzYjFfp12LNYc6BXrt7OGwFmw3sV
         VoMnF8rMpdRjza6byRIdYee1PX0HxI32t3OemAQe1rBOIKgWJGGxfOWr2YHhGQQr5Zia
         m5QA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OvOglgIp;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vUBP420McfCQDGxwtVV3nMYrh/fvL3eLBO984qeHeDA=;
        b=K1Vw3LX6ed3ty0qS6yWz5RWSRLK2W2MONzi5wdOnJ3++QWj4QIfFDycn9rU1K/7Pgi
         y78kCzsNVYxeRr8DRu131kLvYhdfyKWldJwtsj60ugF/Uqv0YKS/RODRoJZe8G3tNESo
         2X8mSFmpnUPAunNRUhPuJ5fhPLM4ruh1Ks4EH76nJyCfM5i437jP6sNaD0bu8ewgk1mt
         lvSSMKn8jzeE5U+CJuuivRm47PnMdswnL2TW3FqAM4iIX8OK1U4P6E3aKZdz8eDYpcOv
         F41XVM4a9+opefC4IVtOCg+1BIom9mcMY2hXTYncSo0TT9b5xjpOut9Uc42xTNenjllI
         01xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vUBP420McfCQDGxwtVV3nMYrh/fvL3eLBO984qeHeDA=;
        b=JFpycYqUXeZAupWtYl6nxKjI+J495nTLJN4Blb6qS5TRTzHiyiMqIWG61eW1BzegWk
         vMaSvd9TWUywHRUTFuou9PCxhWT4VaHrTzVbwsXsFNWOScUBUF4u/zASfr0ySbDCrhxF
         EvaSy5WAlRBKrRQoG5PLP9A3F5SCkNghl8egsW0SHpynuYXhEUh6xXUWDcl4KB90Ft0F
         p894dUpLhcuVyKYuAMepHos0ywMxul8VkKAKlZy88XFViTlUj700TzueYnBqrCn4p4XJ
         D/5rlHAPaZlGVjyzXdYL1gE+/olq5rDROTH1jiNKNUDm6OAEBqKbqItKZ5ucq1uNSV1y
         A3eg==
X-Gm-Message-State: APjAAAXI5ijnAgvsDm66YC1e+yWW33PDj51rCZLejzkK91O/Aca/D88I
	TFiBMoKaE9YGlPmphxUv4Ds=
X-Google-Smtp-Source: APXvYqy+oohKzFnFXQMTTAB7BhyA+MlUGeI4iJlW/ZldXmiEK/XSM2b8pcgoPSttbtJqwGCjq9PZAA==
X-Received: by 2002:a5d:9c52:: with SMTP id 18mr3505891iof.180.1576708461430;
        Wed, 18 Dec 2019 14:34:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:b047:: with SMTP id q7ls276037jah.15.gmail; Wed, 18 Dec
 2019 14:34:21 -0800 (PST)
X-Received: by 2002:a02:3409:: with SMTP id x9mr4565899jae.3.1576708460978;
        Wed, 18 Dec 2019 14:34:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576708460; cv=none;
        d=google.com; s=arc-20160816;
        b=o4fLAPbkeMt+1sQtcMyzD7nNmlw3TPwMFOt2f1IrOmpkiV5PL5eHMtQLvj/cGA+LaN
         KZcKuOGHI4Flled8b2IlefH9ZoSwqhi7WPZh02HuWPIdire8b9IICGI6taKoKPvGilKi
         fBkRljPSfc0CU8IcjtIab3GfF9Mo5yb+IStxF3tE87Z6MckdcnEhc+Pm2D+ZnIs1WKh2
         GGUZhNlKn1WS2e/9eJpwJgjXSJc+EEOJEHoSk6pXImFROsS+d5v7wVeDaxSbt9JSvN+H
         Wxn1v5V6rwhgh9RazPkTU4DMXYntFtye/fEOh+3D1DpesTS4nzBEfe43bJyujahQ8XH9
         8dkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q0o+3IFWqjXrZk2VGX8AZpqrFD1hgC3oeYUhyHktLWk=;
        b=zW5KeRAqMl+JRpJkUVWc/xFMX2FAlBHMa8gNvTBX3Gp+4Y7kwyw07Al9tjcgY+myYK
         sK2g4I0l+HsYXNUCUtoaXHoLHAnfr1w8pfNZdd4YnkNUzkoLkkVXD6F5kIDaAIlHFbE+
         /BxwpONzabCaOXiKeYxqb0bxVvDQRkOows9jtd1k+THIUYK7gBdvxWH0C3ptqeANGzZ2
         AW5du6lkIz+PhrphGVZ0CnT6dPYxonb9C9Za/cS25+gRjsMOXvIQNhv5WR5Ukom4mllg
         9fcacPqttPkSf+65m0GjUdlfW2RXxd2r8lxRwgbNZhfz3/gqQzreJygcCiUs4wrGfb7u
         LfKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OvOglgIp;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id z20si247310ill.5.2019.12.18.14.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 14:34:20 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id c22so4382313otj.13
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 14:34:20 -0800 (PST)
X-Received: by 2002:a05:6830:2057:: with SMTP id f23mr659352otp.110.1576708460339;
 Wed, 18 Dec 2019 14:34:20 -0800 (PST)
MIME-Version: 1.0
References: <20191209143120.60100-1-jannh@google.com> <20191209143120.60100-4-jannh@google.com>
 <20191211173711.GF14821@zn.tnic>
In-Reply-To: <20191211173711.GF14821@zn.tnic>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Dec 2019 23:33:54 +0100
Message-ID: <CAG48ez1-u8DbxSAu9DXTEEy3-ADquQLWXB6ufV+By7TnuxWOsQ@mail.gmail.com>
Subject: Re: [PATCH v6 4/4] x86/kasan: Print original address on #GP
To: Borislav Petkov <bp@alien8.de>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OvOglgIp;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::341 as
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

On Wed, Dec 11, 2019 at 6:37 PM Borislav Petkov <bp@alien8.de> wrote:
> On Mon, Dec 09, 2019 at 03:31:20PM +0100, Jann Horn wrote:
> >  arch/x86/kernel/traps.c     | 12 ++++++++++-
> >  arch/x86/mm/kasan_init_64.c | 21 -------------------
> >  include/linux/kasan.h       |  6 ++++++
> >  mm/kasan/report.c           | 40 +++++++++++++++++++++++++++++++++++++
> >  4 files changed, 57 insertions(+), 22 deletions(-)
>
> I need a KASAN person ACK here, I'd guess.

Right, I got a Reviewed-by from Dmitry for v2, but cleared that when I
made changes to the patch later - I'll ask Dmitry for a fresh ack on
the v7 patch.

[...]
> > -             die(desc, regs, error_code);
> > +             flags = oops_begin();
> > +             sig = SIGSEGV;
> > +             __die_header(desc, regs, error_code);
> > +             if (hint == GP_NON_CANONICAL)
> > +                     kasan_non_canonical_hook(gp_addr);
> > +             if (__die_body(desc, regs, error_code))
> > +                     sig = 0;
> > +             oops_end(flags, regs, sig);
>
> Instead of opencoding it like this, can we add a
>
>         die_addr(desc, regs, error_code, gp_addr);
>
> to arch/x86/kernel/dumpstack.c and call it from here:
>
>         if (hint != GP_NON_CANONICAL)
>                 gp_addr = 0;
>
>         die_addr(desc, regs, error_code, gp_addr);

Okay, so I'll make __die_header() and __die_body() static, introduce
and hook up die_addr() in patch 3/4, and then in patch 4/4 insert the
call to the KASAN hook.

> This way you won't need to pass down to die_addr() the hint too - you
> code into gp_addr whether it was non-canonical or not.
>
> The
>
> +       if (addr < KASAN_SHADOW_OFFSET)
> +               return;
>
> check in kasan_non_canonical_hook() would then catch it when addr == 0.

I'll add an explicit check for nonzero address before calling
kasan_non_canonical_hook() so that the semantics are a bit more
cleanly split.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1-u8DbxSAu9DXTEEy3-ADquQLWXB6ufV%2BBy7TnuxWOsQ%40mail.gmail.com.
