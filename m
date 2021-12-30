Return-Path: <kasan-dev+bncBDW2JDUY5AORB3EIXCHAMGQEKV7CPEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id C5268481F6C
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:11:41 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id kc21-20020a056214411500b00411a4b1db94sf15410167qvb.19
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:11:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891500; cv=pass;
        d=google.com; s=arc-20160816;
        b=owXXmCSz/C73wYao/OTb2dd4z1zZ9WU0AJLOP8hNecYXC2YDM1O7oUXl35QJeVD/VV
         1XPV0BcjIu9UCaE/CiSTkt/IHUz4KEhnfxUWKzKG5k9t8hTCsn8CNMsig8cJjJ93IxXe
         wQnx+PBSomOl86G7J+E0tMRsJCxy2AfxXVQVF+FURlTFUW/1zLphy7a0GXZbw+d9amfr
         vOmyauvQ6OSHJPrVKPx8g9rZZNtX/NgTO6F6o+xlwqi0gWDXhfFq77ekZwq6Awk0dy0J
         WwWg0OUirgLPp7Gogk9KqOBA3APl7xthCW40NyOtWZRpmq+gCJBIzsc5Km/HXTK8EB5p
         /WlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=wTqOMWituTNW0l+qkPUdZron8WvTbCv/36Dbauj/W7M=;
        b=V+LaWMxeheA4BfZyCKhpcGW9ET9nTc8MdokpszfwprvrEC+NADOISRRRN0vwwG2dO/
         ewcJPiBlm6NLq2bpUvk7QjwYMHZGTGLiwHt70PInTgG364JcNcq/Bm2b4Gh4U4EXqYI6
         Fh2P2krWO3n4/iHOBiAaX/+vTohQzUooHSLGZAGOytSqz93Q5+Sn5gspztrPvDoMnq1k
         96fMBN9rXB9QUwLXUzzHJnf0g6xHFH9ZGTFf07XJdvj2qdilCcfJJiy2vPYg0/GeYo2s
         ZqtKjWZqvlXCTiutPylDi5f4Mwl/1KpdY83FTadceaDaQ2OsXZbVazFXU/4Kx+MVswYL
         ddcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="DYv3/L8m";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wTqOMWituTNW0l+qkPUdZron8WvTbCv/36Dbauj/W7M=;
        b=IUD2I/Mci0zlC2DMFPszmYNKz1E3WO1rvALTD/CKPTQQNw8dLeFq/K8G2lNeORmnro
         4/VUJR6E13zEABJZcqzx3XJ0CBocC1+bPpWq14ET6kL7QoJO+IBZ36ZKABvKIDd8rOJo
         whJkQ6SDlpwBoQsbGvCT87wrhMlv6X/i96DVdn321vcae/t7wAaRyB9A6ntnbEcSLd4p
         5xR0ZT5phrm4HiNl5y9vDd9H/MJHhB2l9/2jc+bGYvZWVzstrCT3oAjz9GpiL2aKhYK9
         Vc965qnyIv7H9HoURItBlbeHGksqKa5jTMs8aycVKO2FQF3XP3H4MrUQuRzYZUXTgbTH
         kiUg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wTqOMWituTNW0l+qkPUdZron8WvTbCv/36Dbauj/W7M=;
        b=T3+/YfujCdqkBSrXedTm5W13OlUcRgS+Sb2haD3YJmoVcnOh98t+f3WSLmtdfK0KOc
         szrIZeWLVwinOzzePxAAd+4Y7VdMDUmRtsOGaqpHsyS5nsMaGEyBC2KemfDGIgTsJ5ZL
         xbx2dl+GZLPT4671zbW+gVBj27OpU8WX0/UCvOqkfyEz5Kxl/8x6hmgjqZENVtG0OiHz
         ZDYlTyXvFtawyE1njhfh/NBYI4k+W5O6xy/oSXaqf1i7n4RfHxEQSk7+DZJvuDexz7aZ
         CmukcEBXQzVKyRi0h+TCdh8ooSg0fNA7kQ/eh5dZxSHaISli6m5x7uQhjWKcOYLlZCMV
         02Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wTqOMWituTNW0l+qkPUdZron8WvTbCv/36Dbauj/W7M=;
        b=u7kUm1bbUtGK42i+A2gx26HE6ndvUzhSJQF2AgU/dgNsR1kvtBWanPRGPYTeNcR3tu
         zpLfbmk2lC5gDBIfjr1fIcXDcAcNYIstRm+ZVMfItllK6fYE5kW6Ca2wzZnI5yFo9svh
         2b/Z0tSJ/cp/BfSHMISC0MzO4J/lbp3YXK+z7tdPX/g5drLKBfcSzFDO2yivxD4UDyK8
         xDZqurSlE9PCygtRqywRGATJVZjDQhksIjzgKCgPbfj7HURQa/5Ta06ryfuLS2WVvi1m
         aqu8hEaAfYGljt3+4mqZbjSznUnjKyTuBh3nl425g1zgfap06C5QhQDnjP6oZ4YiphDo
         9EDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532c7PcGN81wgJ+Ltt+iVKcUSPjuHtRZRD9Io+zwPTiyI1V9YfqD
	r7cVrnv89mt09k4XQX3LAlw=
X-Google-Smtp-Source: ABdhPJywlxI3633ncYBUEuPBkkryZCmFqOhbncbqe1kimShJ0Ee2/UBOs78LIR/563TbLnGLDv3qTw==
X-Received: by 2002:a05:6214:27cc:: with SMTP id ge12mr28628347qvb.122.1640891500695;
        Thu, 30 Dec 2021 11:11:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d47:: with SMTP id h7ls13368999qtb.6.gmail; Thu, 30 Dec
 2021 11:11:40 -0800 (PST)
X-Received: by 2002:a05:622a:81:: with SMTP id o1mr27830486qtw.327.1640891500348;
        Thu, 30 Dec 2021 11:11:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891500; cv=none;
        d=google.com; s=arc-20160816;
        b=GokDACEPsPjr3USYrK/0iG2Ei1heoaQRypdI7pjFlrCqIyF0DG2egc5C0mOGnDYIge
         q8ycQvOEZTBaCeozcl0PVfO+QmCQKHZCtlRhwQqF5jGghwFfM46w0hxudrNPuxyunk8T
         RckDEymZ2UrDYeFRMmImeHPFVS/mtJIk778i1/gNs/gvvhcoCQm9QeCOn3cHkfnbItNO
         FNla48bHNt0PDR1a7toIDwrGSJKp9dFhOjWhZjzZQmLfRoXTREOZdTtPuxuPDkBhwtaQ
         /W1FlvF+bLvCms3FkbrwzudhF2msrgoUpwKN6CpOIAgNDe+ztud7qVx4KwzMkNUqaimt
         H2hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GPu8b1zm5l26lxQv3Kupma6jp1vzEvVrzyOVnWiH1iE=;
        b=QvfNKPiIC6J7tl0B9uIveJRoDRUNLK47zaus/RIbcja+sh5y318U22y9nw7ScmeLS3
         STonRZdRXescQknaHTfq7wLXGzd6uqS3hDRG7fm7YBt/1rPHqhQYtVtSFKCEmhrnAYV8
         Z6HpE2WBIaV1wn00Ca8LBiVWT1uCFaqI3wX+X9iOHMO57WycKgMWxNUIWh2a6mzm4dPj
         znN0/mSR06lB5/8R4BLlH3IQ39j7pwxT8xlL7Eyuc/8B81jpMs6jquJdWzp5MX3Au5Cf
         ZgySh/7fVJG79abAEBK0MDIT5Jwymn0pASEDimyxlT5df0nEuDFcJ1CxjbkW2JqFv7wl
         9h8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="DYv3/L8m";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id w9si3750192qtc.5.2021.12.30.11.11.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Dec 2021 11:11:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id y11so25320437iod.6
        for <kasan-dev@googlegroups.com>; Thu, 30 Dec 2021 11:11:40 -0800 (PST)
X-Received: by 2002:a05:6602:26d0:: with SMTP id g16mr8170007ioo.56.1640891499870;
 Thu, 30 Dec 2021 11:11:39 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <73a0b47ec72a9c29e0efc18a9941237b3b3ad736.1640036051.git.andreyknvl@google.com>
 <YcHC5c9ssDrcnORl@elver.google.com>
In-Reply-To: <YcHC5c9ssDrcnORl@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Dec 2021 20:11:29 +0100
Message-ID: <CA+fCnZdFJ3r8bcpqhMz5fLn63DoecE1kJY1fvcmpP7zg+Q2Fig@mail.gmail.com>
Subject: Re: [PATCH mm v4 28/39] kasan, page_alloc: allow skipping unpoisoning
 for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="DYv3/L8m";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Dec 21, 2021 at 1:05 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, Dec 20, 2021 at 11:02PM +0100, andrey.konovalov@linux.dev wrote:
> [...]
> >  #ifdef CONFIG_KASAN_HW_TAGS
> >  #define __def_gfpflag_names_kasan                                          \
> > -     , {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"}
> > +     , {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"} \
> > +     , {(unsigned long)__GFP_SKIP_KASAN_UNPOISON,                          \
> > +                                             "__GFP_SKIP_KASAN_UNPOISON"}
> >  #else
> >  #define __def_gfpflag_names_kasan
> >  #endif
>
> Adhering to 80 cols here makes the above less readable. If you do a v5,
> my suggestion is:
>
> diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
> index f18eeb5fdde2..f9f0ae3a4b6b 100644
> --- a/include/trace/events/mmflags.h
> +++ b/include/trace/events/mmflags.h
> @@ -51,11 +51,10 @@
>         {(unsigned long)__GFP_ZEROTAGS,         "__GFP_ZEROTAGS"}       \
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define __def_gfpflag_names_kasan                                            \
> -       , {(unsigned long)__GFP_SKIP_ZERO, "__GFP_SKIP_ZERO"}                 \
> -       , {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"} \
> -       , {(unsigned long)__GFP_SKIP_KASAN_UNPOISON,                          \
> -                                               "__GFP_SKIP_KASAN_UNPOISON"}
> +#define __def_gfpflag_names_kasan ,                                                    \
> +       {(unsigned long)__GFP_SKIP_ZERO,                "__GFP_SKIP_ZERO"},             \
> +       {(unsigned long)__GFP_SKIP_KASAN_POISON,        "__GFP_SKIP_KASAN_POISON"},     \
> +       {(unsigned long)__GFP_SKIP_KASAN_UNPOISON,      "__GFP_SKIP_KASAN_UNPOISON"}
>  #else
>  #define __def_gfpflag_names_kasan
>  #endif

Will do in v5, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdFJ3r8bcpqhMz5fLn63DoecE1kJY1fvcmpP7zg%2BQ2Fig%40mail.gmail.com.
