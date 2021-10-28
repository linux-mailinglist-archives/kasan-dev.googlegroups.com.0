Return-Path: <kasan-dev+bncBCF5XGNWYQBRBIUW5SFQMGQE5ZIURFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 6227943E9CE
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 22:42:12 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id t12-20020a05621421ac00b00382ea49a7cbsf6118045qvc.0
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 13:42:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635453730; cv=pass;
        d=google.com; s=arc-20160816;
        b=LO4vfLzCB3ZXY9hGfp1A1gwq/CiHWwvnrAlS63U34EfEzOsKCA0REBsl38s0UqSIWH
         k3qbg3FGXygInd7fs1Fln0lPcYZIEBRSJsWVmvp/uH64W9T3CjQlEsb0sB9QaGAsjCwU
         yf011XnNoaP644o1/61xY3S10viw6g58+8JATZgOLamNfhdZTdSg6RIYoPwB34HpkcrP
         9R+qNzcDh+BA0s9/uOv9U/VRnMPpKCWwisJzkrpA1I99SLkGZ9NCJ4yv42XzsyS0jb4o
         RZEUsIaSkeh/VFUwjLYUG3h9X8nVLmtuRK4jrPfxgitnVS1tNKrzgNbiosQwD/0TPmcN
         uwzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yyB9ViUZ0wAsOaP65CoBpJZaOZPgSXzLxdceTq6ULoo=;
        b=fZvKiPHFqWUQ3gWAPxyKarjW61v8juUVn8GplTrLEeG/eGuLf2+Nc5zmf5RHqo4SzL
         kIlbzMPctyK6WvxtBdM3YxPYXDeUgBtDugXSO68Dst4cqAocd/OLc7vN9dLK+3ap9lKA
         LWO8qXyVSNFQym9HRNIwL/iqmpo5DNs9jtgYIC2Lth64E98/guC3EkWJmO+iu2lhuy8P
         c8lIjnPHTaF7ads0rhTjUkoTF+wOmKEECDiFicW1g5/Ilnupu4y/QjSJe82sx+9ThAGQ
         Ec/tzTvwUQy2vTKWTgrHXxGCoww8zdLJ+OVaZVGFY1tojeB76Q44ydYaPEELk2DkpLUP
         XmHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=VmGwAq85;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yyB9ViUZ0wAsOaP65CoBpJZaOZPgSXzLxdceTq6ULoo=;
        b=RoxK30LFFgJWGhiQAmG3gdYPIWtSn7wEL00w2Fa0YIakosl0xbS5J0IEELSp9WneBk
         gYzEX2zLntOcygwo5CDseA21uS2E5cEif9qbGJX8pcbDWzEFW+HfVOhBt4n0tH7aj3Fk
         PhQTBzLl20Nh8o7FF9OC7sfkkCNlOYoTKDGyu5Vg2FjCLAnWsJUksqKYVwBtBDjhdYda
         9NL/hKdylehRw2Hq81Fo2PKozQvfvwteTRGOYFHKb8dBP3kSLUEfiZHX6Cl2x2+fd59E
         KECLkEo6XkWIdxRbaj+zR7kcUkDPn2aaHU+8KRkIQJ3XZ4lr9qkni8yYmiJV7bWjn3Ge
         DHgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yyB9ViUZ0wAsOaP65CoBpJZaOZPgSXzLxdceTq6ULoo=;
        b=EyJqzHNXmoxfm8QvUodjbOoA8wBaZToDsV/QRZBiNyDWIbi8lhjjPecRMz6TFUaxcx
         LLgP1Ki/Ev3qZsP9sL0+lsop+W62OctOFN8P8P4o0WCjEEju5pmHo+Qweh6JCU/S6Xds
         rK0vkjsd2l+KUHqF7mYPYXWOHOj7nFZagejZoLegvguCrkxq17agocZnz2KaDxKyP9rN
         FBvUF+xCb5IwL49N+96tykIb26vvwR8SwseoxjYrNItaRPJnJ7rODc/wRmo11cfh0WKl
         W+0xMFqZPrVAFcteBaMyw718gP4RsIIEz27AW7vqKESe47p8jYGAFxB8lFC27NBBvqUr
         kqSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nx4+0zMXrdL9N45pxpT9XYiBiG01hByA5lQPSKtOXufz2ks9z
	aSBYTzBTRoTV7l6FfkMjBU0=
X-Google-Smtp-Source: ABdhPJw+mt3trdb22qw5xiBNfdlKWfJdluZwbV+lgUNizO5EaMuuT2TlqP/2/b6bUKOVQPntGxiLLA==
X-Received: by 2002:a05:620a:14b9:: with SMTP id x25mr1926374qkj.399.1635453730244;
        Thu, 28 Oct 2021 13:42:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:318d:: with SMTP id bi13ls2484853qkb.9.gmail; Thu,
 28 Oct 2021 13:42:09 -0700 (PDT)
X-Received: by 2002:a37:bfc4:: with SMTP id p187mr3950761qkf.158.1635453729769;
        Thu, 28 Oct 2021 13:42:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635453729; cv=none;
        d=google.com; s=arc-20160816;
        b=pyS0vXnrlGWjbB8fA4j+b96ZjAZGlv2IJDpO3apeGUGWLUX2UuKHv11PWVAdzbtQox
         i5Iu1P+da/6ZTp3P06LhxiawKlPP2ueri3a/FBxapmdPSx6L+2uF40isRqy+Kgdvc1vT
         f3nlx9tjDnQ/zszg4wBSxDyFEzoiv4tKavFrhcheJEDDpSMYvfwWQjNCIVqE4udKJTAM
         0xz5sHAr04N8jdd2i3NgS6B7FFt7Iy7UcvDGk7ukwGeNvREXCiW9bvuyvO9yLZKwrwrb
         bPpRFhNgGlqLv2OE7Zp+860FxpIsPcuCmtsK3g6xCRASkZwE+exyLenKHVBcUDk/x1rY
         vkfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mb/mWw8HAiK6lwVPCHL9I1kcRE7UYBim01+6DNM+U2o=;
        b=HUAPuC3S3z/ylnsP7l/1cQMv8MWGI4pyB1KfEwLntfn9b76OT8GXs+/fmhak5Vfuil
         XLnmY9nNKYmcUzWFGCX2tkA6uvWrh5BiYRoB3POd9ANUvghcvnPw93bITLGD/iNIrR5y
         WoMWNA0kKZtMvXmDtLG3z2lCeM2mGlobFZHFqKv08d2Mm6DH+VJgovWxNureHfwDjIkT
         b51GT4isf/WpXGg/FsvY7nDAt3afwDtakMVOqXHghwI2YBDQvgCacbx/kKWGxrY+kauT
         PFqimK3tVdCSCzz/Ztnu6Ho2HSyGCT+aZ0OmxGh+PT/Y20O/vsSM0rI5szV4GLtoh+o4
         9EwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=VmGwAq85;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id y8si532670qkp.6.2021.10.28.13.42.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Oct 2021 13:42:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id nn3-20020a17090b38c300b001a03bb6c4ebso5746003pjb.1
        for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 13:42:09 -0700 (PDT)
X-Received: by 2002:a17:902:a412:b0:140:a4a:4ba with SMTP id p18-20020a170902a41200b001400a4a04bamr5906072plq.52.1635453728984;
        Thu, 28 Oct 2021 13:42:08 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id 125sm4230631pfv.155.2021.10.28.13.42.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 13:42:08 -0700 (PDT)
Date: Thu, 28 Oct 2021 13:42:07 -0700
From: Kees Cook <keescook@chromium.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Arnd Bergmann <arnd@kernel.org>, linux-hardening@vger.kernel.org,
	Kees Cook <keescook@chomium.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Arnd Bergmann <arnd@arndb.de>, Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Patricia Alfonso <trishalfonso@google.com>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kasan: test: use underlying string helpers
Message-ID: <202110281341.8479EC4759@keescook>
References: <20211013150025.2875883-1-arnd@kernel.org>
 <b35768f5-8e06-ebe6-1cdd-65f7fe67ff7a@arm.com>
 <721BDA47-9998-4F0B-80B4-F4E4765E4885@chromium.org>
 <20211028131526.d63d1074a8faa20e1de5e209@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211028131526.d63d1074a8faa20e1de5e209@linux-foundation.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=VmGwAq85;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Oct 28, 2021 at 01:15:26PM -0700, Andrew Morton wrote:
> On Thu, 14 Oct 2021 19:40:45 -0700 Kees Cook <keescook@chromium.org> wrote:
> 
> > 
> > 
> > On October 14, 2021 1:12:54 AM PDT, Vincenzo Frascino <vincenzo.frascino@arm.com> wrote:
> > >
> > >
> > >On 10/13/21 5:00 PM, Arnd Bergmann wrote:
> > >> From: Arnd Bergmann <arnd@arndb.de>
> > >> 
> > >> Calling memcmp() and memchr() with an intentional buffer overflow
> > >> is now caught at compile time:
> > >> 
> > >> In function 'memcmp',
> > >>     inlined from 'kasan_memcmp' at lib/test_kasan.c:897:2:
> > >> include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
> > >>   263 |                         __read_overflow();
> > >>       |                         ^~~~~~~~~~~~~~~~~
> > >> In function 'memchr',
> > >>     inlined from 'kasan_memchr' at lib/test_kasan.c:872:2:
> > >> include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
> > >>   277 |                 __read_overflow();
> > >>       |                 ^~~~~~~~~~~~~~~~~
> > >> 
> > >> Change the kasan tests to wrap those inside of a noinline function
> > >> to prevent the compiler from noticing the bug and let kasan find
> > >> it at runtime.
> > >> 
> > >> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> > >
> > >Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > 
> > How about just explicitly making the size invisible to the compiler?
> > 
> > I did this for similar issues in the same source:
> > 
> > https://lore.kernel.org/linux-hardening/20211006181544.1670992-1-keescook@chromium.org/T/#u

This is already fixed in your tree with:

"kasan: test: consolidate workarounds for unwanted __alloc_size() protection"

which was based on this original patch (and my comments).

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202110281341.8479EC4759%40keescook.
