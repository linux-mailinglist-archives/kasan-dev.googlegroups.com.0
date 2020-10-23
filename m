Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBE5QZT6AKGQE2LNENJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C77629761F
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 19:51:21 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id i9sf844977edx.10
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 10:51:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603475476; cv=pass;
        d=google.com; s=arc-20160816;
        b=CwPs0arbQ0HoFXPqxznjjSnLCYpUq+AXp+fN2GGkAElbl6zFYhG7tItBM4B6CnPBIy
         FWV4FATSorIBOpcQw3ctXRA7YNURD6wTZ1uL2w4g/a4ysBUQSfFGlws24WouGvekSPBS
         k1YUMDrZXET2KKU+7OMl7yh4heZlxPvO6MYCaF5gUNrzx23WxLDi8TP/OTns/1W9Mv4A
         ugV73tPGb2Xscv2LkT7NbdhokmkF2Cppo+JZDg5rIIMdV9kyFZF7AlDp9sPBFKJqhgpK
         kZtFeoJOSCKxkFZgeKVDx3xrD+Aln0XkoAg+5g+fGOer9rsYscH0dmMrQPL1trH918Uc
         twvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=wJrpYvOtk+QWCHFzslcUGPvMNtoUp9kFCFQHdpB7oIg=;
        b=jDck0FHk6ltE6Sxqd4lawELyRefUG2fm+ejA8H9Rbb0AHMNUKpspmrSDR1k1Ht6IjA
         faET0ANVy7GvdYvFAvAHWPuPTXo5jPSLeeYbvlsEc5NWy0aPOidpnd+TGA5aRlFTcYlw
         kEMx379HNpVGRx81IF+WjHR0cHdnZi6UXH7oP45xeIWy+no4L0H6S0gjp/6DoVKb+ZZs
         MqXL31BEnkhv2szsND9vOAZMLxJJSXGz/rGf4zHt7nJmVoqFaEYczN8GxZG8T1z1OrrD
         aB2yu4EtvtlWz1Kl4X3wmbSwInm+iPi+GmuVGeHdV31rNbx3B1FpqK0i0UKY9nT0A/qS
         DMgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=ThO1o259;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJrpYvOtk+QWCHFzslcUGPvMNtoUp9kFCFQHdpB7oIg=;
        b=Dzk8+n/48/pQVKb3uv3QlTvuMDxyXcfoA53vPrS7va1UGs+GJz7FG2AXofqRdTRLE+
         f1RsnLNhJPZebueG6dzoWg1K+MgFw4/YoIm2Odf6qTiQYKVzKyI6wBK4FMLnwiLClZvb
         3cQ+0EBN9v6dohkV6KxwA0e0u5l6Ids/A+aQRle12Oxd8R7mfjnkUg0TLOh13+CJ35G0
         IQ7nV/9o4CPNfpZ93PLyBR0VLvoIW45UOYURYrXNH4cdO0LRzHmwWD4Mo3T3mqSEpxD2
         a9KyF0KdEKZh89ohnPEiv/jA313Uk+GTMjBClFlXGkOONmQhiP//kgSFxRHHharZMRKb
         AJ6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wJrpYvOtk+QWCHFzslcUGPvMNtoUp9kFCFQHdpB7oIg=;
        b=XoSrHNFjE34XssYwe1X3nBiLjJtzVAFJ1EMFk+3CdWxz3pEOCnzaOiKzZ0Bw8xB4gR
         kwuAD9ODw3RqHIOqYCaYNjOqfOXApPWA5PgfIu/Pl55yQ2KkfZIvd9jbYwJ0f2fiXgQU
         5ot2wFpcjyB/u3fZAv9PSFsGnzEhVPH8vW03qGlaPUxiRcSuV6uxgPf+Ay9wqcOlIHvO
         PLhjHaY5DNqgeKAwdytfW9IAgUA+zIsERp3H3mFLGLoDUKeRkPC/95S1dvWTyDpH0y2O
         3hcs/O3q7aFXee0OQiH72ssfoXwpcYeeaOnMMKd9gEyH6yNQIYYJbE9/AtvbpGR4GNEC
         KlIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53233+m412BMtiKzGVHZpPlG8bh9RUnKHTaoDpCZZuVGNjgAUbqP
	8TQYR2htImvtDrZV/UEFANE=
X-Google-Smtp-Source: ABdhPJzxj2zZ61ArJQMyFSCR4uh1jljQ9UFCNx1j/bYAIlDzTXHQD6ZerOwD1v2jKwEnyIirIDrUKg==
X-Received: by 2002:aa7:de97:: with SMTP id j23mr3420106edv.45.1603475475973;
        Fri, 23 Oct 2020 10:51:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1d3c:: with SMTP id dh28ls2542322edb.0.gmail; Fri,
 23 Oct 2020 10:51:15 -0700 (PDT)
X-Received: by 2002:aa7:de97:: with SMTP id j23mr3420045edv.45.1603475474891;
        Fri, 23 Oct 2020 10:51:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603475474; cv=none;
        d=google.com; s=arc-20160816;
        b=MlM0xSz5YQ8/J2rALvL9TgqHnidxRIoyi0SOCye4qhsiTDozbzbWYJE1UBAMZxC2aN
         i6/+mqLGnbl04JQ+Tpe5R3WuSVl2eLb3Z/J62BTfoYI8dvZSL14puRAL/0HuDoUB3nOl
         f++BoyO0bEwSHNFo5HNVfVJ0aNy4C28z/9r+zV2ioVuzBvUqxJqQ8cY+ro7U6fkZPimH
         bER7APTbeNt/uzuB9WBwJU17IJVmx5BcAA7265bGii7UZYdtNZ/397YUAT9wYGy/VN/8
         btjgedPNnniDaEMc3nFK5EVIbn4/wGGfMT8LOZYLlhX8u+zOqL2J/KcSaH4dtw6nj85z
         1Cdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mjWltIsY/Tc/YTJZanmOnMdRvb0TAEPFdspWZ6zBj4M=;
        b=hy5AF8d1v+D2u86dLXWmbykb2OrpYmaoP5+8J+iF8up6c1U2jE2RfKjJOYgPX9uKQJ
         O7PMKaMZlPvafc3eE5hHzS3OoIWpxy7e0Rg5rtGqKRHnSHN/BoKjYiX2yvpfAfu9Pb3H
         yW6u6GUJPfQPs+lW0VgkmfVPC0JAJ0NPUw9YIVYGRC0QI517I0Q7i3KayHgU8XOoOo+0
         Mj+0QOyPaiCxtnrqPnDhwUMrUPo+FaLoGCCgh21Qe2iHDe5rVoCAyfot/jyH/iUWfd13
         y9aSxRVNltcmoZDDHZ8sbGH3fIRirtV6zRIVmPWSC41iGSxJkQTkzGpIVA6ico8CGOP1
         iuRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=ThO1o259;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id u13si30437edb.0.2020.10.23.10.51.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 10:51:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id c141so3095582lfg.5
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 10:51:14 -0700 (PDT)
X-Received: by 2002:ac2:550e:: with SMTP id j14mr1113834lfk.88.1603475474000;
        Fri, 23 Oct 2020 10:51:14 -0700 (PDT)
Received: from mail-lj1-f170.google.com (mail-lj1-f170.google.com. [209.85.208.170])
        by smtp.gmail.com with ESMTPSA id 196sm230283ljj.121.2020.10.23.10.51.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 10:51:12 -0700 (PDT)
Received: by mail-lj1-f170.google.com with SMTP id d24so2443712ljg.10
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 10:51:12 -0700 (PDT)
X-Received: by 2002:a2e:868b:: with SMTP id l11mr1279720lji.102.1603475472083;
 Fri, 23 Oct 2020 10:51:12 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
 <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com> <CA+G9fYu5aGbMHaR1tewV9dPwXrUR5cbGHJC1BT=GSLsYYwN6Nw@mail.gmail.com>
In-Reply-To: <CA+G9fYu5aGbMHaR1tewV9dPwXrUR5cbGHJC1BT=GSLsYYwN6Nw@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Fri, 23 Oct 2020 10:50:55 -0700
X-Gmail-Original-Message-ID: <CAHk-=wjyp3Y_vXJwvoieBJpmmTrs46kc4GKbq5x_nvonHvPJBw@mail.gmail.com>
Message-ID: <CAHk-=wjyp3Y_vXJwvoieBJpmmTrs46kc4GKbq5x_nvonHvPJBw@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: =?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=ThO1o259;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Fri, Oct 23, 2020 at 10:00 AM Naresh Kamboju
<naresh.kamboju@linaro.org> wrote:
>
> [Old patch from yesterday]
>
> After applying your patch on top on linux next tag 20201015
> there are two observations,
>   1) i386 build failed. please find build error build

Yes, this was expected. That patch explicitly only works on x86-64,
because 32-bit needs the double register handling for 64-bit values
(mainly loff_t).

>   2) x86_64 kasan test PASS and the reported error not found.

Ok, good. That confirms that the problem you reported is indeed the
register allocation.

The patch I sent an hour ago (the one based on Rasmus' one from
yesterday) should fix things too, and - unlike yesterday's - work on
32-bit.

But I'll wait for confirmation (and hopefully a sign-off from Rasmus
so that I can give him authorship) before actually committing it.

              Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwjyp3Y_vXJwvoieBJpmmTrs46kc4GKbq5x_nvonHvPJBw%40mail.gmail.com.
