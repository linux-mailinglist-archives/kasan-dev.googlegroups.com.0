Return-Path: <kasan-dev+bncBDX4HWEMTEBRB3NC335AKGQEHDZJVEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 220C326126F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:13:03 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id v131sf496105vsv.9
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:13:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599574382; cv=pass;
        d=google.com; s=arc-20160816;
        b=uAPnRMpUDY5LLQxk2R45yzwi2Un7HCshukqVxRyzOi1Z1CaYKKUuaIpq3tQu5On6M5
         Ar0z2s8gUugf71PgVxjDnWSn+O7fhcbgJkNFPdmU/qAtp8T/zso7E0nkZntLIT0rG2L4
         3l0U7hSyDqC1FYlrrNlrsbAkcMdEmXeBtP3ErtTgqRg2ZNAbh6mygG4FtQXjL/rUqzpW
         Lf1k+fA8B9hSWc5nKrnkm+/4mVJmlmJcUNbSQDwzZZ5DU/NV3dhQ3ARtU01URc+ixbvc
         d/v3lURK6OVMSfXQTgZe1kJ7nvTElBf1D+vrtx9PU3glVCIK/edhrQAa7SVKQOVf+5Ny
         yFrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=y8+lWISaf2CaRKzPAqwNZyz8OXmsPJZkscTwm3LW4ls=;
        b=rs/WwjgrA63VGcCqxnu/w/NP67DaJeHpzhTRmZprvzeHQIhV4Nzce+5IwwsniNhcrL
         4VVBazHmMf8mz+JSBQhQDKLlJcxIuNhi/Axhj5nW8q4n6GHovPjSzHV3eDQM9DL3ikPe
         0SKj/QojbN8P8KwxV+S/EChOcHsIyk2EK9WOZ1SLp7np3/kq0UPE+JcQF9BNbQsZVOF3
         tO0ErSNAwfYKJx9GZlW0w5UF816kGdkpb4JFmDv+BmBDCL/NGw32B4+xE9anFccquPEZ
         brgy77JbQk9kI9ve1tDthCvz/1UxKw3g6I3m2+B+PuRjvJZ6CoPGfJbDyvoIrfhSuU9K
         fMTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jzzh0sjM;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y8+lWISaf2CaRKzPAqwNZyz8OXmsPJZkscTwm3LW4ls=;
        b=ZjGbOPUhenzXsTEtwl5At3IYDuatl0y56vl+7gvocXo44NKWDoL6KJLOApPfC61vy4
         pTExgRrPb74IgXg9LzKbuoYvhVHjYuGHVCBG3IiSELFeaImZujk1XPyhK2ack3HsA7Ij
         14rVpWqKrH2T6K4uTonQjTUiOiM7gEHJR7LK1fKRQ5rYQGt57ehBAwlbreIvkZjD5Tj7
         ZS1UuL0RtHm8XSjXzl6QZrnZlxNJfFQC2Yu46K+G+/J2Oc7T80QtnP7UvInHJf7ebwZ8
         Y9dwrafSJUJJ+bsUSFzJRW/5c9ttQN8e59RU2+6tZ8MpVRNDIMCdVeD+rLtH0nGqbv1s
         Xq3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y8+lWISaf2CaRKzPAqwNZyz8OXmsPJZkscTwm3LW4ls=;
        b=d3qiwJYasAfSMZqD5CPft8uxX2O9wOg0QfIaGojlRPJYHRlxrqxht1ZTlJe4KGeFzL
         l3Y2uMwLnBQCggE5WoieQq33AvPk/bqLBdOpy2OvVo2MpnJqAhS4eh/Eu9UXs9tYUd3s
         kmHhFT8F5NVmhIfN2260NOUlGoXvTKE1gvDpd6bvR/QM5M2jxv/wUUKS2U9FlKcqwSHw
         47PWHP1AxMujzq4svHU4DuxQtpxdGai9MyzQ0A8+apWW+IgeRhHB2PLHtbihxK2IvPk5
         +nHkyX3/TPV7JIJ0SoLtKqokP730De1ya2G0eI5xs5xrLI4qjMyh0kVxTPTETbgY46Vk
         jgRQ==
X-Gm-Message-State: AOAM5335iyNaA9VlYsMQ20n4VS+WP9L6pCmHrwqDGU6wRcDB7QJlb8c1
	2iWJmuyUBJk/S2FzCS8narQ=
X-Google-Smtp-Source: ABdhPJxKB1ifXfUmdJTMoRBUS5Qm89hCF+1H7q2yGHoxKRToi/VndL7fUQs9dPOJfvBe9yIqVWhRYg==
X-Received: by 2002:ab0:73c3:: with SMTP id m3mr12979975uaq.33.1599574382144;
        Tue, 08 Sep 2020 07:13:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:bfcb:: with SMTP id p194ls1094112vkf.8.gmail; Tue, 08
 Sep 2020 07:13:01 -0700 (PDT)
X-Received: by 2002:a1f:41d2:: with SMTP id o201mr966898vka.10.1599574381689;
        Tue, 08 Sep 2020 07:13:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599574381; cv=none;
        d=google.com; s=arc-20160816;
        b=W0YZQs/biKt1kDdr2xDcLH+cz+eAkLDY+GtUOzYWLE2uJ+TppcmR7fWmaNYVcH8Q68
         fA0jXeonwtzyuQLVasXVNswvgC00ZbU3DcQUVShpW2lA8HSqMrd6/drGxs6UwU3C5eIF
         lwOZlTeN/k5JoHD5dYkMEyJZusCDBG1BhkVNKJmB4gMX/Cj4mkMOddxVE+w9RpEfPIFN
         /XOgRTt83f8B+6TagHF43ALzrJVUT78VImiixLoK/ITlt5VhpiaEkNI0PBBHNep1ellC
         fuUcKs3qomBjfApIHgXcgbgT5F/BxPILXLsb6c86Ooslw9wt+Lz6a6unDsBoA4s71AZ2
         pUPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SMcWrEBFn4y8oWuAmn2eZMWAoBr3QRyf1vevmm6kpYs=;
        b=EIC5JLrXvN+VBgZeJQnHk0CH8hfvjU49y9tkPjL83ageyw4UJtMJI14m2VbiVG0QJH
         c3vSWvXXUzNa2hqiXm6LxxusOSGhKtAq/P40jSOcj5rKJ8DgVcdqWypkCFkh3SK9rBN9
         ZcYflsyD+xDzTuOZk1/7234ZCyqJcKBMhB4yncsZQf3hbIA7AMaCN7F4a9NqF/L74u8j
         4V5qsr2mCQTwhygi9SUwFavNhqWdFqkY+p9awMjZKgJBrWZeEkHjchmwT3Y0OsPTSml0
         yYi2Z2/XU/L0TqywlpGM87wWh5JohPZipP7soASEI9O+9KEEdEwPn+xRhJ7LOavtLOO2
         5kXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jzzh0sjM;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id u19si969712vsl.0.2020.09.08.07.13.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:13:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id v196so11068986pfc.1
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 07:13:01 -0700 (PDT)
X-Received: by 2002:a62:c2:: with SMTP id 185mr25215607pfa.11.1599574380885;
 Tue, 08 Sep 2020 07:13:00 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia> <CAAeHK+x_B+R3VcXndaQ=rwOExyQeFZEKZX-33oStiDFu1qePyg@mail.gmail.com>
 <20200908140620.GE25591@gaia>
In-Reply-To: <20200908140620.GE25591@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 16:12:49 +0200
Message-ID: <CAAeHK+zkWojbbq1WgoC2D6JuR=Jy+jSU78PF74qdmD0aTg6cQQ@mail.gmail.com>
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Jzzh0sjM;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
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

On Tue, Sep 8, 2020 at 4:06 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Sep 08, 2020 at 03:18:04PM +0200, Andrey Konovalov wrote:
> > On Thu, Aug 27, 2020 at 12:40 PM Catalin Marinas
> > <catalin.marinas@arm.com> wrote:
> > >
> > > On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
> > > > diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> > > > index 152d74f2cc9c..6880ddaa5144 100644
> > > > --- a/arch/arm64/mm/proc.S
> > > > +++ b/arch/arm64/mm/proc.S
> > > > @@ -38,7 +38,7 @@
> > > >  /* PTWs cacheable, inner/outer WBWA */
> > > >  #define TCR_CACHE_FLAGS      TCR_IRGN_WBWA | TCR_ORGN_WBWA
> > > >
> > > > -#ifdef CONFIG_KASAN_SW_TAGS
> > > > +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > > >  #define TCR_KASAN_FLAGS TCR_TBI1
> > > >  #else
> > > >  #define TCR_KASAN_FLAGS 0
> > >
> > > I prefer to turn TBI1 on only if MTE is present. So on top of the v8
> > > user series, just do this in __cpu_setup.
> >
> > Started working on this, but realized that I don't understand what
> > exactly is suggested here. TCR_KASAN_FLAGS are used in __cpu_setup(),
> > so this already happens in __cpu_setup().
> >
> > Do you mean that TBI1 should be enabled when CONFIG_ARM64_MTE is
> > enabled, but CONFIG_KASAN_HW_TAGS is disabled?
>
> What I meant is that we should turn TBI1 only when the MTE is present in
> hardware (and the ARM64_MTE option is on). But I probably missed the way
> MTE is used with KASAN.
>
> So what happens if CONFIG_KASAN_HW_TAGS and CONFIG_ARM64_MTE are both on
> but the hardware does not support MTE? Does KASAN still generate tagged
> pointers? If yes, then the current patch is fine, we should always set
> TBI1.

No, the tag is always 0xFF when MTE is not supported.

Should we then only enable TBI1 if system_supports_mte() or something like that?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzkWojbbq1WgoC2D6JuR%3DJy%2BjSU78PF74qdmD0aTg6cQQ%40mail.gmail.com.
