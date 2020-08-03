Return-Path: <kasan-dev+bncBCIO53XE7YHBBFFDUH4QKGQEMILWJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id D3AF923AC19
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Aug 2020 20:04:06 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id k21sf20343211pls.2
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Aug 2020 11:04:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596477845; cv=pass;
        d=google.com; s=arc-20160816;
        b=mbTDpsHpqxQIvrX0iFSu0EmUTQarBR+YO/rVKfoDSFmQ57YhJpVJHHPmX5GNndmnZW
         Y5f2saGNQoitP/jFSMOR+BS5ifoAZDHQ65jpWYXXOghiWzjk5o7OD+QOS07DEi+On13G
         hzV7ivEW8cC9HfAHoZ5BVOjheTYLoSC2laCqNKCmYiMZOeaqQ6cqi/wGfD0/ov4iRNAL
         1DxPSIJ1T1Wt9en6W3V+S4jz5Ke+pO0SiYU2mTsVQVNbg/LInq93HR8IICIFFTbQ6Erd
         fqh5jMcSC/8m1TaehbGbawvQ3qpYu+9H+qgmx9w8wxo+7Ek/W03llLfsHWJFeO/J1uyA
         RPsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature;
        bh=Y6emRigWvp14GfZq3MJJXdfEkBO31edBL38f+qQ5sJc=;
        b=Q9EGlSigzunIyuL/dje1LNgXVukIWm3NGJ2ClVwlRt12hLSquQEoqL/DODhEnzGJiD
         3QcQlKWaQLY8wQ03MBmHFX20hBZYm0e/oe8CgyQSMUys4A67JKLddduxYzJJ+RPtJTVP
         OvTyx1fN8AOdZoJKjEQM9/B24xPhx5EyKu01ouokj+3Pc0PYJ2UOyB0YYHsyaWhVf7Vy
         uMBXIfLfwH+f61qAO51KE5XWac+gG++/8TJmdORlkioXlTiVW8urr27HWQANNYB93Pjl
         ZyYVaA+rGF3zkkVsv916J+A+dtIQyQrOs1VsA2YMAJBGQ50syRF8skIDvnNcEpDJ0CWS
         yXew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="mQ/M8FnG";
       spf=pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:from:date:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Y6emRigWvp14GfZq3MJJXdfEkBO31edBL38f+qQ5sJc=;
        b=qhJpCqVe4z+B6Z3o4eBLAWuYwur6DHwz+qNZk+ks8erjyc9zAuilqW61IEt57T+Zgy
         ElmmmTca/qyFkaWgD32SW5lqc3ehn83oZTI8X+RD4jdGak+cc0/CRjdb/byp714ayZUt
         iiLsFJHBwr9V9PqEO8m0QWjcR9xzmySfxvXDq3MNluiOf1lyj/y9gwiDoCI7r+Jlp1vd
         lplSVfoxrZjFlFAz1jgTJd2r8pg1138eon62E6cNbbcKisLtnfd4+q7QxBwNtTtoBm11
         mMqXohTh6syATZUaWt0fLDs8fMcIeRN9Dirrh59c6JFYcLfdaE+1YRqTJPZvhnuUk9jv
         mVjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:from:date:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Y6emRigWvp14GfZq3MJJXdfEkBO31edBL38f+qQ5sJc=;
        b=sy38PGBrEali+dDK1WfoSyt/suH+yqaAypEbqWJQizjsTPxoRZyQTYjDDK7XAR43pk
         kGa8ZacaEYQWBNqSVu3Ug82r9vHTkjsGqH4X3TXLfqxJJqaPYIx+MIC3m2EiLCCbCTsB
         cYgYl6gtedxwOpKYhFfBCQDzGoNuPPci8u8IFrYagJlHV/bFFwzgyJP40BpmxGv14jse
         y1+9BSi56hCJu9jXN7RjN2Ld7IN/j4qmUYvsw5ELCNHlOz/qmcfr5ijM5zRITL2MnlzD
         wiDLZuWY8eOCnAPIXxQdjOx/B7YJynjuf7m0r+xjUcdyhASEymddi4sCeP6Zs2PFHmiG
         KT6A==
X-Gm-Message-State: AOAM532eSmE2phutb5aDwxbT0DnhIemFqjN+de+doSNquNHG8SO5qnmY
	IbeHo835TA/YBGEePqxO8ag=
X-Google-Smtp-Source: ABdhPJzYGNdTtldPQXDZk/KI7F/bsEtasY2KBaKI0KLmR4wUUI2ECjC87iOeqmJNt2Ll2hXB+lbysA==
X-Received: by 2002:a05:6a00:15d0:: with SMTP id o16mr1467066pfu.230.1596477845059;
        Mon, 03 Aug 2020 11:04:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:525b:: with SMTP id s27ls5440126pgl.11.gmail; Mon, 03
 Aug 2020 11:04:04 -0700 (PDT)
X-Received: by 2002:a65:63d4:: with SMTP id n20mr16398552pgv.213.1596477844605;
        Mon, 03 Aug 2020 11:04:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596477844; cv=none;
        d=google.com; s=arc-20160816;
        b=kG9XOir/yr3DXdOEBmdanncYki2lvjnoPVFiEgB7QwuHJmZRnAlDwJDrvuHchcaD3a
         1BaMcsXqpeUVvF6xuqN4RfXEkFY0ITHMlMH1NeuP6Gs7H/pIoO2WssZfqbEc8Mx/oEKR
         11o+d56HkPE8LUs3OqszlsqeELJQgFsRsIF8M+JoHr8HfWkTdrSq9Aev9OSrzG0BkON0
         Fjpl7Ph6dfTFZ6rge3zqc+DCdKfH+HKs+7hu4OPzWYMtCypqS2zpWBzlkXz3RlEAtXIK
         gcTYUKIqTRkvO4GCY/pRJzU+IypbLoyim8I3Ea4F8c5c7n8dC36lIdqj1W1bIqJwHb3g
         6q7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:sender:dkim-signature;
        bh=rQffdkDpJsvCogJyVsUeEYROYwZ62G9925/dWTW2BzU=;
        b=0RFu3KCI/6o9GrqyoFMipTwOUA453YPB/zL79IxUw7RFffEgrjjZH+gErWOt8WZlq7
         +q7w8QbtjL+2Qv7oWEdhlSeeTMSDYgu+wjoTtwhDJEZ34A72l+iWmpGENDozNHpXO4NE
         zcHhjm9zYS1egyaE12w37FOyXLBBViREEgECJ4KUlzQKwxlfCDPMMHlu2Dj2R3bmYgp2
         GVNicHFLwNib+DmWAGQCqGmh0w6rVu+uA1aueNeOnWEOBtNx3+Lr36NTklIlUlbPaNY7
         PFRbuTKTdKu1ScD8wlZTe9SQ+IwZFx2kYatccRuugUyKstzySBdeSIeMGqy/kp2jhnXw
         /tYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="mQ/M8FnG";
       spf=pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id x17si754176pll.0.2020.08.03.11.04.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Aug 2020 11:04:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id c12so19893545qtn.9
        for <kasan-dev@googlegroups.com>; Mon, 03 Aug 2020 11:04:04 -0700 (PDT)
X-Received: by 2002:ac8:777a:: with SMTP id h26mr17410449qtu.141.1596477843719;
        Mon, 03 Aug 2020 11:04:03 -0700 (PDT)
Received: from rani.riverdale.lan ([2001:470:1f07:5f3::b55f])
        by smtp.gmail.com with ESMTPSA id h13sm21625090qtu.7.2020.08.03.11.04.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Aug 2020 11:04:02 -0700 (PDT)
Sender: Arvind Sankar <niveditas98@gmail.com>
From: Arvind Sankar <nivedita@alum.mit.edu>
Date: Mon, 3 Aug 2020 14:03:58 -0400
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, linux-efi@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>, kbuild-all@lists.01.org,
	Johannes Weiner <hannes@cmpxchg.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	kernel test robot <lkp@intel.com>
Subject: Re: [hnaz-linux-mm:master 168/421] init/main.c:1012: undefined
 reference to `efi_enter_virtual_mode'
Message-ID: <20200803180358.GA1299225@rani.riverdale.lan>
References: <202008020649.TJ8Zu7ei%lkp@intel.com>
 <CAAeHK+zbBF0YVveGNZo0bJ8fWHVZRcrr6n90eYLDCov2vcfZyg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+zbBF0YVveGNZo0bJ8fWHVZRcrr6n90eYLDCov2vcfZyg@mail.gmail.com>
X-Original-Sender: nivedita@alum.mit.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="mQ/M8FnG";       spf=pass
 (google.com: domain of niveditas98@gmail.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=niveditas98@gmail.com
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

On Mon, Aug 03, 2020 at 05:37:32PM +0200, Andrey Konovalov wrote:
> On Sun, Aug 2, 2020 at 12:25 AM kernel test robot <lkp@intel.com> wrote:
> >
> > tree:   https://github.com/hnaz/linux-mm master
> > head:   2932a9e66c580f3c8d95ec27716d437198fb4c94
> > commit: 7c0265f304de3c3acd02d0015b56a076357bcce3 [168/421] kasan, arm64: don't instrument functions that enable kasan
> > config: x86_64-randconfig-r036-20200802 (attached as .config)
> > compiler: gcc-9 (Debian 9.3.0-14) 9.3.0
> > reproduce (this is a W=1 build):
> >         git checkout 7c0265f304de3c3acd02d0015b56a076357bcce3
> >         # save the attached .config to linux build tree
> >         make W=1 ARCH=x86_64
> >
> > If you fix the issue, kindly add following tag as appropriate
> > Reported-by: kernel test robot <lkp@intel.com>
> >
> > All errors (new ones prefixed by >>):
> >
> >    ld: init/main.o: in function `start_kernel':
> > >> init/main.c:1012: undefined reference to `efi_enter_virtual_mode'
> 
> Hm, I can reproduce the issue, but I don't understand why it happens.
> 
> +EFI and KASAN people, maybe someone has an idea.
> 
> This is the guilty patch:
> 
> https://github.com/hnaz/linux-mm/commit/7c0265f304de3c3acd02d0015b56a076357bcce3
> 
> The issue is only with efi_enter_virtual_mode() AFAIU, not with any of
> the other functions.
> 
> Thanks!
> 

After adding __no_sanitize_address, gcc doesn't inline efi_enabled() on
a KASAN build, even when CONFIG_EFI is disabled, and the function is
just
	return false;
and so it isn't optimizing out the call to efi_enter_virtual_mode().

Making efi_enabled() __always_inline fixes this, but not sure if that is
the correct fix?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200803180358.GA1299225%40rani.riverdale.lan.
