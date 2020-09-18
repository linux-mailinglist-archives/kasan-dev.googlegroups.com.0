Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQFPSP5QKGQEKUD3Z7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 536AF27015F
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:52:34 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id s204sf3935003pfs.18
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:52:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600444353; cv=pass;
        d=google.com; s=arc-20160816;
        b=cTQUzsvQROu9n6z4S2cR0BziFIYJmog/KFnKT+FASk30PCAg9gPIfLy9F30/wbWpZc
         I3RDGLvdP/ItXD0NjbvNhOjidGcebdxX9ZJJHmOrvQy3R91BGuPm1+XJRm2LSRyNWSiP
         lBZ8ysI29LNxMLjlEi9Ln2X/tEr1BExEfbw0459yu23HGInPDdZzmlSMVQihncCqQ/k4
         YijKWmDl6J0iExOhRRibA1FPJecT3+FT2ghU2iBJUfng3vyoV6ohTvJqjpKy+pwU4L1N
         JUnaFN3HeMY7cDCvSSudx8ycuw3f+oPZB2XRu0A+m0G6G04ozXU4VR6ppjEptTNt/8Ro
         8XJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5Jg/i2E8QXWFdqT/mpmV4En1xkZUPJAXkMLiluUWuko=;
        b=hrww7waFjkaM0fh1T6iK0ZnUqn7g9/5Y22EwRt7aYsC6GNVoFLw6mGGgJqf624sjU+
         ct/ujco87cqpcNfVwIhWQKhStUZm3ju/rt3JC0h0QAXTXreU38d0sAoktfl5TOhsYLbw
         KnY/oZoszjbpQYtP/k1BShvfK+3MEhrS96T575O1oVYORbV6t7D8QRFSm4hiGEm0c/L0
         pihmN8L6xBxZ6Ob5u3bMTExePnp+bAU3P7QNwhDwsmHpGsp9s1NEyR2goRMmDUq7oj8v
         UmJJTywzV1xgAEioxzGHtf5435VnlStOHARLEgeosws8F+2D99BkfhQkwdru1AQuL00s
         dr0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="cV5/3df6";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Jg/i2E8QXWFdqT/mpmV4En1xkZUPJAXkMLiluUWuko=;
        b=EGAs37Li59ocXae6Ekjp67cJfIrwaJewDDLqYAT8koA5iMums3FXo9RHospedTWYjc
         vcpeQaphFoRmjxW7uzo1jI+JEaat77koI/imo9doUtmArzkgMUe3n52t9TtNsxJBFA38
         sevFVpyprCWm2DAauq+PW4xUtDR6QKvAkh8mUQGWhE3lezkH67gfLhO5IKp6REhUH9o8
         lfmYOq4dTGySX8WdTOc2w5tFQi8Gu7202WF/i6fC84tMxXO38g+KiQdAQ/FgSlPH96YO
         waqkw7VJ7mdkV4vaF6dRdE5JtD60GT02w+AkgnDu8YILKKIV68vAuTDUplhSUor3zMbR
         3Q/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Jg/i2E8QXWFdqT/mpmV4En1xkZUPJAXkMLiluUWuko=;
        b=lm5sOLbVH47sjptfbiKVEyDEJ0Cxhsj74Owd0I5VKcIY5w+AhU4Dj6ITLGxcOCtqJO
         1ylGJ6jufd/5W2qqCWB1atXUF1KtBKKmN+CJUUVhRE1+Ei7eGN6jtts2kEbQ+XpYeTwB
         swzRpWEisW2iBR7T9UQMU7/BMxUGwB2oAzBHitF178Zd9RyVBLbszwTr2hJzyJ7kjV2e
         k/j/bDT5+NRmk8IH3gJ/3fpadiwgmQB3FIs++FhNm6j/NB4ifyNCjDsJleJFflDJMUqt
         QZKbYA9G+GvLYFKc5sTMV6F4zgn/mYjrVGcK0mgAvWY0gpuFkx5XjAgr+VrrN4YjFgOl
         gkeA==
X-Gm-Message-State: AOAM532SkiurgUND4cdL5N/6lL2remJNZe4vSUdBDmGcY2+uI4pB6VLw
	dJ6gjk45CGfJT2KdazDx1zw=
X-Google-Smtp-Source: ABdhPJyD4gcFyweWRpEW/PkHlhXgc0ja9zJgOOgVZATEHCnTXMdXIEEN0y/WHlTzyEw2m3LbSLaWPQ==
X-Received: by 2002:a17:90a:9317:: with SMTP id p23mr13347128pjo.160.1600444352776;
        Fri, 18 Sep 2020 08:52:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7612:: with SMTP id k18ls2904496pll.8.gmail; Fri, 18
 Sep 2020 08:52:32 -0700 (PDT)
X-Received: by 2002:a17:90a:72c7:: with SMTP id l7mr14259179pjk.19.1600444352207;
        Fri, 18 Sep 2020 08:52:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600444352; cv=none;
        d=google.com; s=arc-20160816;
        b=IBQJo8LuomqPjUhZLBoX63UXWC7BZ4jPJ2tDuuBSURk4ib9EcPukSvR4W6dr2yk/8+
         j/bkxkLHaQ3eMlnIUN/xIJNhKT0SqJbb+dhRb5tra8yWMIxn9EoRGfpxvhqvv5qWUxvb
         shX5wn4nPUKNVNbqy9Hs6yVtJQfP8bq91kzLfxN8PmS6WHo6cbuBeb4r4JT/AeR5Wwq2
         ykkaJocrvG8VwHtuL4vmtKN1SQp96+FMkXb3Dwquaf1Nm9I+sCUhBiqEYZNjrkoE3QGa
         Z3PbvlM28T5ZfQps6maB0U19tA5V/chKGSe4YF0G642BsMH0uKJE7r6MvcGZdtdv0HgN
         Z5Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=omeCvyN2X/k16jy28HRYjKOUfMdEZR+hVsENqh7IFVI=;
        b=TgOdz7g9xhS1MLfDE767IIcM/Bw1UMbeg6yPOv48J+RTYPTrCVe+ggfiEyFKuMtC0I
         0RnRA8WZ7uOOJspRdfi0WETu/MjP08lm85yEmLLX2Fl2N+4ToGgRvOuOq4jk18IrtMik
         VsI8w0sQmk5thtJKojxugxgoGVj3psZW5+2HxJxUAL2w2gOKXxF6T4OZvqqqBfoiiEfj
         0HATuHhGpiZXFcjVhuLqcJVY8rAVjCEAaFXrxEOgC1rgB8KUF+InypZx0vzdeACUVt2o
         75lWSZyLlNGkAaFrWCY4JtlekJI7TvtIBoNI2ry+ZdSz4De4+XdBeKCvhsjeHFH4P5O1
         soxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="cV5/3df6";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id lj12si235832pjb.0.2020.09.18.08.52.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:52:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id q4so3387886pjh.5
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 08:52:32 -0700 (PDT)
X-Received: by 2002:a17:90a:cc0e:: with SMTP id b14mr12998779pju.166.1600444351596;
 Fri, 18 Sep 2020 08:52:31 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <74133d1a57c47cb8fec791dd5d1e6417b0579fc3.1600204505.git.andreyknvl@google.com>
 <20200918151939.GA2465533@elver.google.com>
In-Reply-To: <20200918151939.GA2465533@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 17:52:20 +0200
Message-ID: <CAAeHK+ywW5S3fg=1=i4qXRNH_G3spXgV+f9XSAwtX1BUndyoKQ@mail.gmail.com>
Subject: Re: [PATCH v2 33/37] kasan, arm64: implement HW_TAGS runtime
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="cV5/3df6";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1042
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

On Fri, Sep 18, 2020 at 5:19 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
>
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index 875bbcedd994..613c9d38eee5 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -184,7 +184,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
> >
> >  #endif /* CONFIG_KASAN_GENERIC */
> >
> > -#ifdef CONFIG_KASAN_SW_TAGS
> > +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> >
> >  void kasan_init_tags(void);
> >
> > @@ -193,7 +193,7 @@ void *kasan_reset_tag(const void *addr);
> >  bool kasan_report(unsigned long addr, size_t size,
> >               bool is_write, unsigned long ip);
> >
> > -#else /* CONFIG_KASAN_SW_TAGS */
> > +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> >
> >  static inline void kasan_init_tags(void) { }
> >
> > @@ -202,7 +202,7 @@ static inline void *kasan_reset_tag(const void *addr)
> >       return (void *)addr;
> >  }
> >
> > -#endif /* CONFIG_KASAN_SW_TAGS */
> > +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
> >
> >  #ifdef CONFIG_KASAN_VMALLOC
>
> It's not visible by looking at this diff, but there is some
> #ifdef-redundancy that I do not understand where it came from.
>
> This is what I have to fix it:
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 613c9d38eee5..80a0e5b11f2b 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -40,6 +40,12 @@ static inline void *kasan_mem_to_shadow(const void *addr)
>  int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
>
> +/* Enable reporting bugs after kasan_disable_current() */
> +extern void kasan_enable_current(void);
> +
> +/* Disable reporting bugs for current task */
> +extern void kasan_disable_current(void);
> +
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
>  static inline int kasan_add_zero_shadow(void *start, unsigned long size)
> @@ -50,18 +56,6 @@ static inline void kasan_remove_zero_shadow(void *start,
>                                         unsigned long size)
>  {}
>
> -#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> -
> -#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> -
> -/* Enable reporting bugs after kasan_disable_current() */
> -extern void kasan_enable_current(void);
> -
> -/* Disable reporting bugs for current task */
> -extern void kasan_disable_current(void);
> -
> -#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> -
>  static inline void kasan_enable_current(void) {}
>  static inline void kasan_disable_current(void) {}

Oh yeah, I'll fix this, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BywW5S3fg%3D1%3Di4qXRNH_G3spXgV%2Bf9XSAwtX1BUndyoKQ%40mail.gmail.com.
