Return-Path: <kasan-dev+bncBDYZDG4VSMIRBK463OOQMGQEWEDYPGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E378465ECDB
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 14:22:52 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id i13-20020ac2522d000000b004cb23bf5c6csf5592470lfl.20
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Jan 2023 05:22:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672924972; cv=pass;
        d=google.com; s=arc-20160816;
        b=lHkJMpleiObJLzJWIdOR1ascRnEBdB1OWJHcLmTeHb/pDZpViewET8WAXj+xDTr3Bc
         DppexZOcXaMEkuRxo2AwgxiXBjKLk8Pmf3D5lMwCbIw08XkRmWhV6L/3wapTgptYWrGi
         BCEvF7P+H30ofcxQu8FIe9YRsTjvOd2vjMo778l/uvYep6it8bNVU47rg6wSX5Qs/0zA
         RRctFiq3UeLgznWcxx+3m1wCTdzGx/EESq2/j+EEz/Kn50rIHbXbmC/ot8bLpC1DXqfi
         OuJg1yKIDHyQoUS0dYOpXMSRuItC4f3Wf+7uPhjBLAsSBpIJCwpzZOyGv9cEQuIp4PKB
         Kthw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:mail-followup-to:message-id:subject:cc:to
         :from:date:sender:dkim-signature;
        bh=A/c/9sT0CcZ3eNoMoErz5LkyNYoI1m0OpER5d89Vhcs=;
        b=qt2JYGzBXqkjPdpg7d/B6wnXcfzuYdtK5JI7dAzypH9ftzQlu+t4NKwpBWQPzejAhT
         ed8sfQmF99+0Jq4RJHrO/ydgHbOoFgnmG+6VQ6FGKRxdb55HOdRHlYp1jXq7fkV+wp94
         1dcb3vwVSBAjGL5WAyr1oEBXzAlRLmFgnEIpeKteIaQW6qp+thB6uVD8qh4g8C9Bo+32
         kTOcJ9PV/HfcnrODyddcJ5cYoTJ7W2A09kWVClsdobBCK1GFXxNq4E3WyJ5eaD+7zBv1
         2hQK1tZzFo/EHo3IoH4TwTxQ0GKLY/0VjJsH+Pipa0xMENlpT2wGlfarYWYuKO4W1wKW
         daDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ffwll.ch header.s=google header.b=V94j5uLs;
       spf=neutral (google.com: 2a00:1450:4864:20::330 is neither permitted nor denied by best guess record for domain of daniel@ffwll.ch) smtp.mailfrom=daniel@ffwll.ch
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:mail-followup-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=A/c/9sT0CcZ3eNoMoErz5LkyNYoI1m0OpER5d89Vhcs=;
        b=TVxk0IlznrLZZKl8Q2EAwNOfD5F4YtWj4ZQFKi6PiAsgUyP0jXyeotYmtw0zK6yzJL
         5CPMr1pVFVj57fOq38rCP/qLU6cATrf6e9M61zTDvrZZCfFqR4lgsyU38Mvy5hrx8jui
         dmz8FHCD55ZNIc1EcDKuwM31enR4WR8aZwvcnQIl4WhiugCPZnWcnOIKv+/x8h2mK9uD
         BINicKml4VWIYfT/qLGKvCGQEqdKQYjTeCKlPsHUNnOrYW7LXTycOZ7xCrwxOYW1akLN
         jQ79/EPdkmYWu9/ZHLi9TZdjdyFW3Yu/FqVQgwKOTxweElwNfVYWyJTzCXPyZoksldDE
         Fcrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:mail-followup-to
         :message-id:subject:cc:to:from:date:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=A/c/9sT0CcZ3eNoMoErz5LkyNYoI1m0OpER5d89Vhcs=;
        b=tbyunrcwRhW923Cilwa3gVrqr5618Ey8qzlY6hrZI5CLM/s1CRTq68dtFgnoNWpJiN
         VQtK3TSbb3pWfxaidEHrAklsPkFwjfSTKi9m6uzzelg2yf4lGBBfze39lSAQC894TNke
         iA6PBYkF1mxtteFd9ezx688Wod1v7PTVgHuDCmlbBrnPS7aJpkdVs200vmbiUE4ouuB+
         8qJRhQIufukTksBx1gx1lIe6v0OM1322AFJAtdPmpPwnIIiffyLaOaVJl7zqatE+Bxen
         W6gBA7QvRpxUxxj2HELSMKelUFeAzAimNwh7KdGUIXRpSnONvH3csXiKCj/x9au1QIQH
         YnYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kopNJAY66WEkqlhFqemC3DMvkap3UZeBAWWoQjbTAU1WpFJMp8/
	FbbSF9t7Z/1jpWRnBA3bGmQ=
X-Google-Smtp-Source: AMrXdXuBFZKCQsDRdV1FAK3Yc+1ZV/v9re7YcRtXA9Cx452wJb5f9OafcOt0lgjwRNI4Hu56iUoBIQ==
X-Received: by 2002:ac2:46ed:0:b0:4b6:ed1d:38eb with SMTP id q13-20020ac246ed000000b004b6ed1d38ebmr2751722lfo.521.1672924972257;
        Thu, 05 Jan 2023 05:22:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:753:b0:49a:b814:856d with SMTP id
 c19-20020a056512075300b0049ab814856dls2296472lfs.1.-pod-prod-gmail; Thu, 05
 Jan 2023 05:22:51 -0800 (PST)
X-Received: by 2002:ac2:599d:0:b0:4b5:b8a9:b42c with SMTP id w29-20020ac2599d000000b004b5b8a9b42cmr12965060lfn.17.1672924970999;
        Thu, 05 Jan 2023 05:22:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672924970; cv=none;
        d=google.com; s=arc-20160816;
        b=1B9mLRlTc3+L6fEM8lJ+YOnTSw37o5T1tvw+oX9Xi+CIF7IepaB8bm20/AdIVABpUn
         lHFfkGdlVGYZiAYA9gKqifR6rt5Ub85xmZJe8omX8aSJzF76GYUYyDkIhwlGXNs2Frh6
         vFXePd8sVLV6cFtexYrbYh7YKRFf5d4y/DC375GulzDb21IN32wKFQgbzdJY3fzzJ/gP
         1f5GuH7XF+y5tjapLvgCiN9C1OvWh+HAxZOD5WblcQZ79HBhICRaaFoztyQhJVB7nuCo
         /rbjFxPugmhQ/rhqum/dOw6YNTMaL6ILh45opODz4hsuDllcXMbVFWujnb4rDhUowIE8
         CQSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references
         :mail-followup-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=TMYXEk4lndOrw8goIICh9q2Q+fxdp6yIZD9WFVuj+yo=;
        b=SxSrUMam+q+k9mCuBPfgJz73ZPlMx5ivdXSaLQh6OTGn1uSafquo8JqS+FzsTxUdzi
         Yve+s6yNeCYg+lS9c3fMlZikFMNF0+in7S7Age6aJwDKekrf0uAtSkBbt/7KFhqlO0kI
         Nu51mg60p6ni2lgbraq8MDrcsUEvGcba+1eibilzlKP9VB/uD/SnJ91G5KCCLAqPf+S9
         Vsg9rqWJSgwNSlkZpIFNWXoIoviIPMmlrlpTRWXr30Zwz3b3LN/9GXuDHPOO9sKXM6NL
         18QjMs8HsJDqEDHV4jA5LyWrFkyh4o+ByfgGeARMWlbF3Kzbx+mFUfbxx8HuONS8MLbb
         kYQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ffwll.ch header.s=google header.b=V94j5uLs;
       spf=neutral (google.com: 2a00:1450:4864:20::330 is neither permitted nor denied by best guess record for domain of daniel@ffwll.ch) smtp.mailfrom=daniel@ffwll.ch
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id s4-20020a056512202400b004abdb5d1128si1289839lfs.2.2023.01.05.05.22.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Jan 2023 05:22:50 -0800 (PST)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::330 is neither permitted nor denied by best guess record for domain of daniel@ffwll.ch) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id ay2-20020a05600c1e0200b003d22e3e796dso1312369wmb.0
        for <kasan-dev@googlegroups.com>; Thu, 05 Jan 2023 05:22:50 -0800 (PST)
X-Received: by 2002:a05:600c:1d89:b0:3d3:5cd6:781 with SMTP id p9-20020a05600c1d8900b003d35cd60781mr35560523wms.37.1672924970434;
        Thu, 05 Jan 2023 05:22:50 -0800 (PST)
Received: from phenom.ffwll.local ([2a02:168:57f4:0:efd0:b9e5:5ae6:c2fa])
        by smtp.gmail.com with ESMTPSA id j25-20020a05600c1c1900b003cfa80443a0sm2701132wms.35.2023.01.05.05.22.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Jan 2023 05:22:49 -0800 (PST)
Date: Thu, 5 Jan 2023 14:22:47 +0100
From: Daniel Vetter <daniel@ffwll.ch>
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Alexander Potapenko <glider@google.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Helge Deller <deller@gmx.de>,
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
	DRI <dri-devel@lists.freedesktop.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Kees Cook <keescook@chromium.org>
Subject: Re: [PATCH] fbcon: Use kzalloc() in fbcon_prepare_logo()
Message-ID: <Y7bPJzyVpqTK+DMd@phenom.ffwll.local>
Mail-Followup-To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Alexander Potapenko <glider@google.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Helge Deller <deller@gmx.de>,
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
	DRI <dri-devel@lists.freedesktop.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Kees Cook <keescook@chromium.org>
References: <cad03d25-0ea0-32c4-8173-fd1895314bce@I-love.SAKURA.ne.jp>
 <CAMuHMdUH4CU9EfoirSxjivg08FDimtstn7hizemzyQzYeq6b6g@mail.gmail.com>
 <86bdfea2-7125-2e54-c2c0-920f28ff80ce@I-love.SAKURA.ne.jp>
 <CAG_fn=VJrJDNSea6DksLt5uBe_sDu0+8Ofg+ifscOyDdMKj3XQ@mail.gmail.com>
 <Y7a6XkCNTkxxGMNC@phenom.ffwll.local>
 <032386fc-fffb-1f17-8cfd-94b35b6947ee@I-love.SAKURA.ne.jp>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <032386fc-fffb-1f17-8cfd-94b35b6947ee@I-love.SAKURA.ne.jp>
X-Operating-System: Linux phenom 5.19.0-2-amd64
X-Original-Sender: daniel@ffwll.ch
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ffwll.ch header.s=google header.b=V94j5uLs;       spf=neutral
 (google.com: 2a00:1450:4864:20::330 is neither permitted nor denied by best
 guess record for domain of daniel@ffwll.ch) smtp.mailfrom=daniel@ffwll.ch
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

On Thu, Jan 05, 2023 at 10:17:24PM +0900, Tetsuo Handa wrote:
> On 2023/01/05 20:54, Daniel Vetter wrote:
> >>> . Plain memset() in arch/x86/include/asm/string_64.h is redirected to __msan_memset()
> >>> but memsetXX() are not redirected to __msan_memsetXX(). That is, memory initialization
> >>> via memsetXX() results in KMSAN's shadow memory being not updated.
> >>>
> >>> KMSAN folks, how should we fix this problem?
> >>> Redirect assembly-implemented memset16(size) to memset(size*2) if KMSAN is enabled?
> >>>
> >>
> >> I think the easiest way to fix it would be disable memsetXX asm
> >> implementations by something like:
> >>
> >> -------------------------------------------------------------------------------------------------
> >> diff --git a/arch/x86/include/asm/string_64.h b/arch/x86/include/asm/string_64.h
> >> index 888731ccf1f67..5fb330150a7d1 100644
> >> --- a/arch/x86/include/asm/string_64.h
> >> +++ b/arch/x86/include/asm/string_64.h
> >> @@ -33,6 +33,7 @@ void *memset(void *s, int c, size_t n);
> >>  #endif
> >>  void *__memset(void *s, int c, size_t n);
> >>
> >> +#if !defined(__SANITIZE_MEMORY__)
> >>  #define __HAVE_ARCH_MEMSET16
> >>  static inline void *memset16(uint16_t *s, uint16_t v, size_t n)
> >>  {
> >> @@ -68,6 +69,7 @@ static inline void *memset64(uint64_t *s, uint64_t
> >> v, size_t n)
> >>                      : "memory");
> >>         return s;
> >>  }
> >> +#endif
> > 
> > So ... what should I do here? Can someone please send me a revert or patch
> > to apply. I don't think I should do this, since I already tossed my credit
> > for not looking at stuff carefully enough into the wind :-)
> > -Daniel
> > 
> >>
> >>  #define __HAVE_ARCH_MEMMOVE
> >>  #if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
> >> -------------------------------------------------------------------------------------------------
> >>
> >> This way we'll just pick the existing C implementations instead of
> >> reinventing them.
> >>
> 
> I'd like to avoid touching per-arch asm/string.h files if possible.
> 
> Can't we do like below (i.e. keep asm implementations as-is, but
> automatically redirect to __msan_memset()) ? If yes, we could move all
> __msan_*() redirection from per-arch asm/string.h files to the common
> linux/string.h file?

Oh I was more asking about the fbdev patch. This here sounds a lot more
something that needs to be discussed with kmsan people, that's definitely
not my area.
-Daniel

> 
> diff --git a/include/linux/string.h b/include/linux/string.h
> index c062c581a98b..403813b04e00 100644
> --- a/include/linux/string.h
> +++ b/include/linux/string.h
> @@ -360,4 +360,15 @@ static __always_inline size_t str_has_prefix(const char *str, const char *prefix
>  	return strncmp(str, prefix, len) == 0 ? len : 0;
>  }
>  
> +#if defined(__SANITIZE_MEMORY__) && defined(__NO_FORTIFY)
> +#undef memset
> +#define memset(dest, src, count) __msan_memset((dest), (src), (count))
> +#undef memset16
> +#define memset16(dest, src, count) __msan_memset((dest), (src), (count) << 1)
> +#undef memset32
> +#define memset32(dest, src, count) __msan_memset((dest), (src), (count) << 2)
> +#undef memset64
> +#define memset64(dest, src, count) __msan_memset((dest), (src), (count) << 3)
> +#endif
> +
>  #endif /* _LINUX_STRING_H_ */
> 
> 

-- 
Daniel Vetter
Software Engineer, Intel Corporation
http://blog.ffwll.ch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y7bPJzyVpqTK%2BDMd%40phenom.ffwll.local.
