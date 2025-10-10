Return-Path: <kasan-dev+bncBDAZZCVNSYPBBMXYUPDQMGQE5LO5FZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A8B9BCCE52
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 14:29:40 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-7a2acef26d7sf5900406a34.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Oct 2025 05:29:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760099379; cv=pass;
        d=google.com; s=arc-20240605;
        b=A19Eq8+53KUO8+uSwqGmCkIQjKUzPd5Oo4hkIhcsl5YHP16V1xHoZJ1EXvnq+uT4mj
         +zwPujGW0YYkrCto6/1fHM5iRZmgT30DjWkhddOEvG94QDeyEsdfeGdbDjoc5XkveO6Q
         vZPAxNcBWEx8wMmiWnp6xxlSM9yf2KwizXeMSWePfPFeUj0zPzUMOVbl3U4F2EzsCHB+
         l8bnkQxYA0UEwSm1g/MwIe4vnhdhy1LP3Hw0bp7+FtIc80B3MPfQmh0Sr+kKHzdJQlOd
         1QYJWGymVdbDnk5kYrEoHA+QWUsHXIVlD7CAg/d8NpeJhmNhGoNHeG4Q7rxb15SA1MbM
         fbiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=poAAXwEzcKcbuE8JYpuMEdv98wgp5kpBY3B2isu6JXM=;
        fh=30IutKjAk+Jlt6q6XchO2UStD7hpn6GqxITdSE2sn7c=;
        b=YzVyPmuriDWXAlLawlp4U3I9Wl5yj7hymC9EV6f28512TRHzHbADCgtU2/EHsPlQbD
         uTLq308c6PcOS7Swl/bFn/Boax6DplvAq/OQibluP1/CAhWPg0y8fiCQamA4wIYtGEFj
         H2p3MgZPsLVfYXWzWHtzi1/TI7lmZW3tH00MEOCmnhlDJ0xUYftaT2pWn+hypVU3gNCf
         JsxULdCqmRn/KSwES4EqkGgs7E4vY5kVIYmgLDGAxySJSjfWB/YvQpEZNnQXSNQiOuBh
         ZGl+/MO4u+Sd1S3/QeGJ60sAceCL5nocaBYd4y2XRHsj7GIKBu3VTArcfso/WXYENlnP
         qQyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M89jGeQ+;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760099379; x=1760704179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=poAAXwEzcKcbuE8JYpuMEdv98wgp5kpBY3B2isu6JXM=;
        b=Y+crdlkcZXUZgg2hoIMwyj4GpDpR4y1GrKfrORNQ5iy0Ft1PxteI83TB7aOZ+nXrOu
         7kuMEbtrhfv90/53nn4CzWKnz07a1Xx4h0LIGdhcw8Oh+QT3QlYravkNH/BqnyYhZw+/
         EUb7YVU6uax6wb7KdqoseSwsz/WI6aQsFkDgMpbiPZVqZhOm8k2aX4oQIZ1eKi9vqggu
         nbPIPCq0Iukaz6Ag9dGbH8cA+rMb4Xos/OpJv4TNFrrnZtOb5zFOMtwL2cuXhPGSW5nU
         r+s8UKIDmrxi/7+KCyhpfFCI72Md4lSmZGN9xRxDCgvKCVMjkev8JDnIZXpvMt0uPaQk
         nKnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760099379; x=1760704179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=poAAXwEzcKcbuE8JYpuMEdv98wgp5kpBY3B2isu6JXM=;
        b=h0WqyGMvS0JzmzceVp2bx/Q0DhuoeZ8sbUumBIVeEN4GGJH/uWfzo83NjHs2y7Ti7p
         dcVGwytVx5uguJPgmT3aMTIt65LMvui5XPIts/eSGaif+j3ao/e3wGXAgJZtRwGoaFIm
         oJT9EJA6FVKxn0B56fFPUaQyhS9Aw4ZxJMJQYN7nTICO2LFw0r8PdHGqbBD78xhZIbSU
         JRIxYmnD7c2tEVbWhacnqSZSZiuniOGxWX6Z3IaWQSUjJ93SzX3E2k0hANvgh1VN1Ux8
         Np7MM3gIRSBVHlzphPnF1WpkYRUdGo/e8zfh9W8iZqrIeydp5c9NI2XPS8UWH9D+/8vQ
         UQwQ==
X-Forwarded-Encrypted: i=2; AJvYcCVyMvRB916Z8+VwWlppMnBHl5/t9oz6LAy3EZ0+AKDYIahAwY1nl1sToAiwP/a0jJI2XHezmA==@lfdr.de
X-Gm-Message-State: AOJu0Yz7VXSf49k8ZxcjCTOdBxtDWDEW1O0RZzUX2NJl+ykHG4offL95
	dOJkygvtfIQ64SVMI77cFqt6jmKiZVB6m+JFyGEeL/HYiOWQE7Gd5Ztb
X-Google-Smtp-Source: AGHT+IEkvOmBMWqVDt4ExjPR9sXvlLL2Hx3yEEYE9/8usDcoMG2/yTUwFMpZKRoUF5IiOb4b4j1Ulg==
X-Received: by 2002:a4a:bf02:0:b0:650:73:b91d with SMTP id 006d021491bc7-6500073cbc9mr3079765eaf.5.1760099378870;
        Fri, 10 Oct 2025 05:29:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5/fTPbBCLtoT16QVB1HnIPSPkiVhTYYMZba9BAEqgfJQ=="
Received: by 2002:a05:6820:6782:b0:64d:c416:214c with SMTP id
 006d021491bc7-6500edd2960ls1082037eaf.1.-pod-prod-08-us; Fri, 10 Oct 2025
 05:29:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWaBMeF7gpHLXcBgw8C9j7MfxyYAxLjI50iBmaQbRvpQD3FribvfAZaBZBRpjow/oMTsXi4ALEWji4=@googlegroups.com
X-Received: by 2002:a05:6820:2489:b0:641:4a5d:d83b with SMTP id 006d021491bc7-64fffaac80dmr4047466eaf.0.1760099377782;
        Fri, 10 Oct 2025 05:29:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760099377; cv=none;
        d=google.com; s=arc-20240605;
        b=UewjlpHBOpJSuK7hhTzACBGqCeW2MA+0wy0djlCXbA5Zy9408jpi7IRD7aMfAFfOX3
         ww01uFbVtF2BspnMDxsWzjzFBOWyt2trCgN5L1VY6Dosram2lad6s7Ha+DXqYAbKpeso
         OQ9pLDoK+EgiJ795j6JvRAOw2pHPG1Z3uiX1Zvath6tFCdJMj3iR7F2+VNLhstAhjchy
         TwQijKlDHbi3hH77plUqPYtBuTG3owWUpA5ZGbfoTJ/DYG5nfdwHPBvO/2BdAEKOQQLW
         EwPQN6OyKOAhPR35nXNy2aDilfcxDW6/1dfEC+it+xuLLIxXUEa5ZBE2qeknIDHTs4iY
         xADw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=zFPQz4TK9Xo2d5s4+OYRx8/mVx/Je8Rfq5nWIrq1GPo=;
        fh=XQqzEJWWIGLNKcsTYrwUKbjAe8l3kboReX8B7yc29aw=;
        b=N50W0xaq0HSnVWCHUgeJZwWipyxd1SBDaj3whyEhhpsouoYyBEHUukkwzRHHO/97oc
         Vod4teQR9InaBjdYzkV/CuGmh5auzVwfRttPqrrQXcJDoWKwO11NkZAjvp7C7Yrxt/Gn
         sbWkUt9nfPIhadbO9W243+1lfONlTWy0t1IWX6e2wmPwTihh/qlITlFwRmrhkEnAPujZ
         YVfScYN4sg14USIuVr/U4gwXYf8rhPM+BtAEldGPRCSP4t4bJAdZQTQ5UWOg+9dfKHb5
         v6VYnZNSS8q4k3wx+RqejOjbWEOiI+sLkYFd7GefONh0EYY4NrtM+48IfFb8qlxxulGi
         UENA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M89jGeQ+;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-6501815b7e0si4374eaf.1.2025.10.10.05.29.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Oct 2025 05:29:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id E73E844F04;
	Fri, 10 Oct 2025 12:29:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C5D7CC4CEF1;
	Fri, 10 Oct 2025 12:29:33 +0000 (UTC)
Date: Fri, 10 Oct 2025 13:29:30 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: Yunseong Kim <ysk@kzalloc.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	James Morse <james.morse@arm.com>,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marc Zyngier <maz@kernel.org>, Mark Brown <broonie@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] arm64: cpufeature: Don't cpu_enable_mte() when
 KASAN_GENERIC is active
Message-ID: <aOj8KsntbVPRNBKL@willie-the-truck>
References: <20251008210425.125021-3-ysk@kzalloc.com>
 <CA+fCnZcknrhCOskgLLcTn_-o5jSiQsFni7ihMWuc1Qsd-Pu7gg@mail.gmail.com>
 <d0fc7dd9-d921-4d82-9b70-bedca7056961@kzalloc.com>
 <2b8e3ca5-1645-489c-9d7f-dd13e5fc43ed@kzalloc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <2b8e3ca5-1645-489c-9d7f-dd13e5fc43ed@kzalloc.com>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=M89jGeQ+;       spf=pass
 (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Thu, Oct 09, 2025 at 08:10:53AM +0900, Yunseong Kim wrote:
> To summarize my situation, I thought the boot panic issue might be due
> to incompatibility between MTE and KASAN Generic, so I sent this patch.
>=20
> However, it seems that the problem is related to the call path involving
> ZERO page. Also, I am curious how it works correctly in other machine.
>=20
> On 10/9/25 7:28 AM, Yunseong Kim wrote:
> > Hi Andrey,
> >=20
> > On 10/9/25 6:36 AM, Andrey Konovalov wrote:
> >> On Wed, Oct 8, 2025 at 11:13=E2=80=AFPM Yunseong Kim <ysk@kzalloc.com>=
 wrote:
> >>> [...]
> >> I do not understand this. Why is Generic KASAN incompatible with MTE?
> >=20
> > My board wouldn't boot on the debian debug kernel, so I enabled
> > earlycon=3Dpl011,0x40d0000 and checked via the UART console.
> >=20
> >> Running Generic KASAN in the kernel while having MTE enabled (and e.g.
> >> used in userspace) seems like a valid combination.
> >=20
> > Then it must be caused by something else. Thank you for letting me know=
.
> >=20
> > It seems to be occurring in the call path as follows:
> >=20
> > cpu_enable_mte()
> >  -> try_page_mte_tagging(ZERO_PAGE(0))
> >    -> VM_WARN_ON_ONCE(folio_test_hugetlb(page_folio(page)));
> >=20
> >  https://elixir.bootlin.com/linux/v6.17/source/arch/arm64/include/asm/m=
te.h#L83
>=20
>  -> page_folio(ZERO_PAGE(0))
>   -> (struct folio *)_compound_head(ZERO_PAGE(0))
>=20
>  https://elixir.bootlin.com/linux/v6.17/source/include/linux/page-flags.h=
#L307

Do you have:

https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/commit/?id=
=3Df620d66af3165838bfa845dcf9f5f9b4089bf508

?

Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
Oj8KsntbVPRNBKL%40willie-the-truck.
