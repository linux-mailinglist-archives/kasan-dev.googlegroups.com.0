Return-Path: <kasan-dev+bncBD63HSEZTUIBBZOM6X7QKGQEXALMTGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id C99062F2A8C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 10:05:42 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id m7sf1179766pjr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 01:05:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610442341; cv=pass;
        d=google.com; s=arc-20160816;
        b=hx+5WgYqMPkZ02TzpT6eoMsaMLDOvHw/jIGMIB9pwfqMMxwIMhjn2bWsdxoAP7+bpJ
         mgDO1acDV3LOWFuIiVBl+hj8Aa1fJLNIuFDzx1aZU+r55QCMOAiohljTScpg/wSMb/f2
         k0K+UhjZua36Fj2z40PUEsRjN6W2f5KTRRfcneH4L0KI3tJYXlmP36ybr0zF1qKQ5z/u
         AaWCStPw4Kr8EysJJtyKcBslupkILJ9rEmg5yF64JkaDnXWnWQ8nbzIRZtUEIVnaMeqd
         tzfHGZ0/yiPtIbj9Ugu5Y55qpDvlRfcdva+vhLjtHQPQ+cgBDNzETd/PepFuXI/ZW8G6
         XpmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=eFFGt671W5/WdmJEPtNceyVsmUSXAKs677e+PFdXL2A=;
        b=JS+zpOV9aoagsjFei/SNhcOJtqxY/fr8k5L1fs/FzLTMF96PzTwK4+NIb3OPWWPrUD
         vRFIKNel7tF2GUlsoj/GB/iNC+x4OeBubw3PyFLHGH0NGJ+GjpYGDb83LtDRgpinEm3/
         Iy55PEhbMSLAm55wbLSRYx7tuZHj7VVshxgq7QnzeSHRkw9V1HalIeD9ns0qG6q7AWbI
         1h7tQ2gmL79me/FdjMMjUKUe8yBbBeokN7nOrb4bh5QfvuBPHJwhEfcBdITVj0XJKitf
         OTZMx4EFul8HBTV7Iz7wDUiUMrWLZvA2kaENtUe3V/yECJch+unigxz7+F2PYQ70cdhO
         1UBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VRoncQMt;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eFFGt671W5/WdmJEPtNceyVsmUSXAKs677e+PFdXL2A=;
        b=nftWZvhwYOKEicKvJEQkzZnkWdye3mKNv2Yi2teXIWf4lWrtaHA7nZ4dxfVX+mqv9o
         HrVyPfbOOja81w1h3EgUvJDXMTZe+HeLIb/okfMFgNG3lEUd9kj54OIMHr19Y5KaSyjH
         kJPlUbjzYTnlJ/EZ8DqzsTfrkQrP5bn96aQvuhWPbgtKc2UY1e2SGC78cS4OXUNqBSu1
         i5tX7y0ulKenGqV0uSc2AGUaO7lvyDTsuTe4iLdFqP7iKUvrmTLPMn0hx7zXIeCdjazc
         9w1Chp22NOrCuNwgQrop8p+ffkz9fxk9YlQhQ1437hhcu3nXS1EEXkJ0ixT4W61DXJpe
         KXPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eFFGt671W5/WdmJEPtNceyVsmUSXAKs677e+PFdXL2A=;
        b=rjJ7oD0RCZ87K3o4TbBlIi8C8GvwC3lJtwwCt/cDZwLblWtHIRsshiLCrPXE7tYEZR
         QnXidqb9SNwbsZbASaNq6zK6EoLsYiz7vYnPtiW7PN68WrWSWlykqB0AWAxYHbPT4dBC
         yaoi93tQTrCmNd0Lz4a3svyHrs5q/MysguH9xEkQhZ/n8j+LSbXNGAK6eLeypVSZRyki
         A9kUPAjXpEo2UoJXvor1O+GIqG5+2zc+iV23dqlF8yU0EHPGMdEloe5xDyQVMkzNb7MS
         VIEYVpWDw3UikmqfVfUNsXS6YHh3r6M07BT3z2S4skoM7xLmpbm90gnMcHSOWfXQE+NG
         a8jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334yuzKWBWpF6zSLQxyiYmN+gVrb5RLAQKvh7nQzv8kAJOhuPJ+
	1lsikHvef2TbyF4BEMOLPvg=
X-Google-Smtp-Source: ABdhPJyGsqeDBLxa3SrQqOS78TsD2SdUAfudVOf5tgvViwqXRsOsEZQsHxMpGPb7RmSQEKhJqlg7Dg==
X-Received: by 2002:a17:902:7d88:b029:db:7aa4:864c with SMTP id a8-20020a1709027d88b02900db7aa4864cmr3824107plm.34.1610442341546;
        Tue, 12 Jan 2021 01:05:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:cd46:: with SMTP id a6ls992147pgj.2.gmail; Tue, 12 Jan
 2021 01:05:41 -0800 (PST)
X-Received: by 2002:a63:a12:: with SMTP id 18mr3765668pgk.140.1610442340951;
        Tue, 12 Jan 2021 01:05:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610442340; cv=none;
        d=google.com; s=arc-20160816;
        b=fF4Ky34t00ChVp1by3VmEmJxTA/AWTtmJToyHrP4mOcHP2CRkct2pKs8VsMi7CXm/B
         ytl++GYAw2BlbBWWi71IpcjqOdWZIzXuTTV+i3RbhJGI8stOZf1b3JCeidySmxaJWlqE
         Jl6gKDjW6S0nQ1OGvgQ6GY/vrid8Ipre58Gj/clu4cT8n7fN5J93QKHkfQ7YiOw8/3v6
         6JOo9cRn5kVJOzsgC48iXMCMLP2bdKqwptVvP2tXaKrSAIMD+E+nz9fvu9TDQIb/Yqp8
         hBBrygUufiGtzK4BhcNUbrajgznoF8NTssdw+3qXnizIpa+iKW8vZUAiutliA6+d/OGb
         U2iA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y8XM4obLq9DvhCh3O1L/QWD4jL+xfXLn4XKxlLnOxro=;
        b=PPQmy+IJYOvsFs7nB18lBfRvP7UwGEiudq04+WDUCVQGgn+arTnBlUyQwDoPZrmW5W
         8Tn7NvXZ2JSttBu9MrWyTbUEX5w5lu5KXjjWbOkEnQtzp+FN7u11JoVG03kf/DB5i5No
         qES7VDA58RMtzvTc4fO+EHNEYLboHFE00m30K8MeXCvqJ+hm6evxPAhXmISaWrubl6DQ
         MMkF9cKznkcEvYAwnxIK8z6CNaoq5sqh0bEUCXoBI58PB8t7VTy41uZ+Mm8GZW4r1cpE
         bIsyv7/snV9BR7e8dQD1kIPaf+Dd9ko6SitIcoxrgrh8LIcCfStnLGPc6GKtjJ0U6GBX
         1yVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VRoncQMt;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q32si114307pja.2.2021.01.12.01.05.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 12 Jan 2021 01:05:40 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 681D122CE3
	for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 09:05:40 +0000 (UTC)
Received: by mail-ot1-f49.google.com with SMTP id x13so1591898oto.8
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 01:05:40 -0800 (PST)
X-Received: by 2002:a05:6830:1c24:: with SMTP id f4mr2131209ote.108.1610442339716;
 Tue, 12 Jan 2021 01:05:39 -0800 (PST)
MIME-Version: 1.0
References: <20210109044622.8312-1-hailongliiu@yeah.net> <CACRpkdb73diprma9Z1-4nm5A9OTQMeGVK=Hcqiwny9VOVdA=QQ@mail.gmail.com>
 <4c009d78.4e1.176ebcf8bc9.Coremail.hailongliiu@yeah.net> <CACRpkdY7eYyVNvqMRYvTQsLNrXa+fzPsWA5JHDuS4nqry+CHcw@mail.gmail.com>
 <20210111221820.b252f44de1e0bf4add506776@linux-foundation.org>
In-Reply-To: <20210111221820.b252f44de1e0bf4add506776@linux-foundation.org>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Tue, 12 Jan 2021 10:05:28 +0100
X-Gmail-Original-Message-ID: <CAMj1kXHengoRaQFVPmbH2hNdLK_-pLuiL6Aqcg8a=1CDvU+HpQ@mail.gmail.com>
Message-ID: <CAMj1kXHengoRaQFVPmbH2hNdLK_-pLuiL6Aqcg8a=1CDvU+HpQ@mail.gmail.com>
Subject: Re: [PATCH] arm/kasan:fix the arry size of kasan_early_shadow_pte
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Linus Walleij <linus.walleij@linaro.org>, Ziliang Guo <guo.ziliang@zte.com.cn>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Hailong Liu <liu.hailong6@zte.com.cn>, 
	Russell King <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	hailong <hailongliiu@yeah.net>, Linux Memory Management List <linux-mm@kvack.org>, 
	Alexander Potapenko <glider@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VRoncQMt;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, 12 Jan 2021 at 07:19, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Sun, 10 Jan 2021 13:03:49 +0100 Linus Walleij <linus.walleij@linaro.org> wrote:
>
> > On Sun, Jan 10, 2021 at 11:21 AM hailong <hailongliiu@yeah.net> wrote:
> >
> > > >> +#ifndef PTE_HWTABLE_PTRS
> > > >> +#define PTE_HWTABLE_PTRS 0
> > > >> +#endif
> > > >
> > > >Can this even happen? We have either pgtable-2level.h or
> > > >pgtable-3level.h, both of which define PTE_HWTABLE_PTRS.
> > > >
> > >
> > > I guess not for arm. But I'm not sure for other ARCHs.
> >
> > Oh it's a generic include. Sorry for the confusion.
> >
> > All good then!
> >
>
> This code is 2+ years old.  Do we think it warrants a cc:stable?
>

Not needed - ARM only gained Kasan support this cycle, and this patch
does not affect any other architectures

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXHengoRaQFVPmbH2hNdLK_-pLuiL6Aqcg8a%3D1CDvU%2BHpQ%40mail.gmail.com.
