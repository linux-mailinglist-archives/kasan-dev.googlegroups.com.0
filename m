Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6XMSD6QKGQERF2OVLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 824892A84E6
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 18:29:31 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id 10sf157384uae.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 09:29:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604597370; cv=pass;
        d=google.com; s=arc-20160816;
        b=LSvBqijiaOBfJBxLf32A/PRs7gFGaU12lAh0y6SSkd1sU/aMQenl4uYmGKn/xHgbAu
         1V1zOHOA+YOYT7WS2BGt5vrDXsP9WIpJPykh9/nF3UVsyOFMkKNuQSMaYKhbSKLcG+ah
         jwfM2ZVZE8zBn98qe4i3SRJ7UqYEHvxZIYdH+mnzYMgYgFmw2JhycaiFlO9wvmyI5lT7
         8ELubRKzy1UApS/X0pY/yKp4DPQy9q2+Td5JSuRrUz/YL+88/Bbrk//EwzPzdbj+RVfH
         IoVt1tPIneuNYO/I+tkcSqICw5/u9aieelZMy2o32ro42SBZ+HqD6SMV1qNj0LRvhJjF
         SMUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2O46ENLf94uYTQpBnGLzsSkWuGO+6ThPHElXUFtTL5k=;
        b=zRjdbLvvqFC8OSa+Fi3hAOlDXwBJ6ZVD6MS5zR0wqJkePi9vXSTt2f5z4qOx0PK8xl
         nr6j8UHYQKJka6hZWE7kDSf7y7Cfw1uGZop/oDsYn15VSX0vXp0joqsyFX13/Q5bbpsf
         pk2ztLJy86Mi71OzXhTHBXWbsAiI2amS3KNQMN1nYQhIrIZlBr06R+L6/HwrJiVF8huw
         uAnQAO00UknBHzWbr7NXYsNR2QYzHPvNUDpmkXazoi/HdHRZPbbaGlsVqQZYDhjpUJ4G
         RQaf3GZqXfbAknPcrj+ZNFTJlZveKjnuhb4M8lZgaoRUkylu/o0OGHvVCrUExwvh0m/O
         Enjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pAsUxnB2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2O46ENLf94uYTQpBnGLzsSkWuGO+6ThPHElXUFtTL5k=;
        b=F0ehu/nKnFZQ47tRinYZ/JHMrclNigxA8VownujdTl1S3R+nDm/Pm11SftPxsF4yuJ
         Tlu8ANftU0p2AMENr9lLUJI8u3b3XtcvCO52WdaY+MiDWsXroNfqqi9OtZTMAz+xXPmu
         ggZqY/3zCrgOLe6ExWY5SEhMuYQp5u3Zx6J5wyz8Htw403A66i23mow6xgBqV7JkJDlV
         IdDGFUTpryqaKjAYvhP4FKN8Iic9iMlqxgdFTCKoIO1rl4OnJNEolqR3BGIlVYE4qUsQ
         afSvy9RARP1yJ+zQjfOsZ4gjNm0T56GX7g4OwqhWhQsXxivglD33Pye5JtwWQW+T/Q4L
         xpaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2O46ENLf94uYTQpBnGLzsSkWuGO+6ThPHElXUFtTL5k=;
        b=nd7CI9emZY40VkuyGraDE0KKkY1MibR0zNRidrFv8VlM3HxJ8nAzUid7lZRc3ZVSqK
         XpthxXNXLYo8kAhQQZUYi042boazG5Q9k3cOT7DA+hOVE9zobeLodMallxXRWMBsa/ub
         ygtpV5Wcs/AzxLsP3VAONCdyMQ9JZxbKWMzO5nYi37KfmQPdkaB4kZXCtljNHs1MMfW/
         L+bwi++Iagfupch/DzdodDleWpMRnGuUIPTpDnuizpxFDjm8rTQZqFJ2XmChUpI6r2yw
         QqbPyw97tmzKEysQIWDN8+Tm7IavZ+5bwE6lIS9fYhCqIDX5j+8VuUqrTAI5MS7pq4M7
         gp3A==
X-Gm-Message-State: AOAM530t3uigm05E3/EH1IjCZHHRr7JbUHJV7LGxONsZJMKYNpC0S/zR
	6F/NmoPvuDeuWK8kTL2Y0DE=
X-Google-Smtp-Source: ABdhPJx78vbwAhtr5PR/H0lAjMX10hQFGxuUHi5qdw8fx9HCw6+oGI4UWvNzNt4VSB4GJREGBILNIg==
X-Received: by 2002:a67:3256:: with SMTP id y83mr2437527vsy.48.1604597370444;
        Thu, 05 Nov 2020 09:29:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:649:: with SMTP id f67ls159103uaf.8.gmail; Thu, 05 Nov
 2020 09:29:29 -0800 (PST)
X-Received: by 2002:ab0:2302:: with SMTP id a2mr1880938uao.138.1604597369872;
        Thu, 05 Nov 2020 09:29:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604597369; cv=none;
        d=google.com; s=arc-20160816;
        b=pXy7eUltRdVad9aT4BV+SgwMcQyejcmbvczM/AfK2V3XKOoYuasWZrZSH79WZgBsxp
         tvKlzlbCVBglOLrxYBo9I5X3fk8Ibi9AhOkdqbnhFyoD0TD2fP0b77hityt+rgPTUa+n
         p4bnZTxiGoqfvjjruNshdW/YEujfOOtWw31LyJhpjiGw0PkAOtLOmiftFUdjedKA2ivw
         oO213ynX+o+BCqQvQnvNSfKoTxvD5CW9Dx3HkGGRcnIaA5ss58ha2s/GaAhUPh/0+obT
         v+YYdaEyLO8nEiz9xi8K8aE483vup5VRpc1BUTNV16UKlFLyoIihc/VzToW3QRnQVbr1
         l+Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hezyq/zpP2iNRlcrlDKy/FRFvbv86R32DSeUr4scc0o=;
        b=V5s++eo/sONgocAtnKXX3rd1QSGeFiI1ndVWv0vU+bF0NiMo3sOglQV/yBq4Hbp13/
         f14Q2g/VDs6KcoK5W2rWzcETt3s584Y7c4IRYwPVcikZfdk77EW+MtuBtylEIUKdOLZu
         C2KJq96NKDkzvlCI+D0tcU2sDZ7eGtyBNY7KToy+SecVg2a2FlALHT+EpqSQyBvJ0Vmf
         5VcDiCf2SbgXbKjzfeAYUhcDlfewFDpRy8iECBGTlM3fVL+/o8nRo3QnwmzNvcRPNi1/
         zu1Q4CcG30dL/JpqYF0HPl0/9gsTkczIyfd2J3MC8/Kl4g/zQBwnTVZVsuu27pzVchij
         e3Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pAsUxnB2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id k3si173220vkg.3.2020.11.05.09.29.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 09:29:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id z24so1835008pgk.3
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 09:29:29 -0800 (PST)
X-Received: by 2002:a62:64c1:0:b029:18a:d791:8162 with SMTP id
 y184-20020a6264c10000b029018ad7918162mr3218301pfb.24.1604597368896; Thu, 05
 Nov 2020 09:29:28 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com> <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <20201105172549.GE30030@gaia>
In-Reply-To: <20201105172549.GE30030@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 18:29:17 +0100
Message-ID: <CAAeHK+x0pQyQFG9e9HRxW5p8AYamPFmP-mKpHDWTwL_XUq7msA@mail.gmail.com>
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pAsUxnB2;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
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

On Thu, Nov 5, 2020 at 6:26 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Thu, Nov 05, 2020 at 12:18:45AM +0100, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > index 06ba6c923ab7..fcfbefcc3174 100644
> > --- a/arch/arm64/kernel/mte.c
> > +++ b/arch/arm64/kernel/mte.c
> > @@ -121,6 +121,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> >       return ptr;
> >  }
> >
> > +void __init mte_init_tags(u64 max_tag)
> > +{
> > +     /* Enable MTE Sync Mode for EL1. */
> > +     sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> > +     isb();
> > +}
>
> Is this going to be called on each CPU? I quickly went through the rest
> of the patches and couldn't see how.

Yes, on each CPU. This is done via kasan_init_hw_tags() that is called
from cpu_enable_mte(). This change is added in the "kasan, arm64:
implement HW_TAGS runtime". Would it make sense to put it into a
separate patch?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx0pQyQFG9e9HRxW5p8AYamPFmP-mKpHDWTwL_XUq7msA%40mail.gmail.com.
