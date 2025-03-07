Return-Path: <kasan-dev+bncBCU4TIPXUUFRBINLVO7AMGQE5QDJXFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id E9CE2A56667
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 12:16:51 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-22406ee0243sf24028395ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Mar 2025 03:16:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741346210; cv=pass;
        d=google.com; s=arc-20240605;
        b=I+H6vhYsyOaZShe7slJDwPRs2A+xT0TdqQQIfMwp8+HsZGTHLP7COx0aepmcqP406C
         SUJKwOHJoHbgCx1cCOl1f0F50be54IHTRO4wtcqgwq8xMAtGeAUSH2aotcKrfzwf7Z9R
         I9tv9j98nhIRDLsFOy0TX6chyjRBrjxNdmWP9EUCqGqsiR+vCXemrHAVXq90RgrxPRuF
         +4DB0/zhC9GGHLWTVjrbXclfL3s9lP6yTv2a0Rouc2dBy0v5R00T5dEEjQIz5AoQ3Jzp
         60DzT4WZcFZyRGJRNzDVdP1b2YQbuGfYaiV4IQzBKE7WOT3kxMJ8NW5Zg1dz038l9/xA
         rqBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ODsHn4dUOldUchCy+RgAZYJExuiP67bcUP0Eucmm0IY=;
        fh=P6Bb8BCmFVKBcUEXQvCLE+VBksD/kNqkB2h8J/j/9vw=;
        b=U5kfcog0GvH42J5S5h13V7wNcbrVHwY1VuzIzviqGCDsvnt30zk0VwpbM3mGUOt0zs
         h6xJIQvQUq06M7//Ogvl7mYJN9uawVvKGWcWMdTchqWOIi30M4SHw1enV4SoeGI+bqNd
         6d/lVwvZmYdSiadeWq7+V0Y9naz6AwjrhafiB7ZL6NiucgmcA3O1VmTjB8DONt8MN/2d
         TGEXB7spC21jqIblZ08/CGdxaiYDYB+s0zxus+EiqVByYRDltziXOjlDoXIilGsb6NCY
         HtnTQkaM7QixBPb3WOYe9gS55k15iz0HuhH8FxOCgFvhbKv0wYYnvYsROiLpaRqBhA+R
         VEtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YEcRD0nP;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741346210; x=1741951010; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ODsHn4dUOldUchCy+RgAZYJExuiP67bcUP0Eucmm0IY=;
        b=Tw0VRsPintvaFdlseixbARUsOtORr1Gr9Fjcri3+iGRfjSp8VhxMlx/EnWGXZ3a0IM
         wnZTPjalUCtQQ3YGiRXq5mX6a0Q0lZhNblvi4FI+gmXbcrhxG5sP+xw1rMDYUDBnnzQT
         D4jAOKkErFA5cyLnGY0ND9Zv2ptKqZG5ig9H7e1nbGWuAKMVkGwICjMZiDi6K02vCBsS
         3Nj8zBP+b9S6zjEgI1wVZy3iNbAKnKBHJq7zzAuy/mrSaMd5kVYon1TlH1a7IPoSa3qy
         IFMPgXk3Q9lRe2jY6WpeDMpZ/vGQp7fD4tQilR5aneiQwNHVG1VjxZReC9FihT/QGioC
         hZaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741346210; x=1741951010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ODsHn4dUOldUchCy+RgAZYJExuiP67bcUP0Eucmm0IY=;
        b=OcOiG68LSW0H17PjS3aY7tD26Arrh61Qtju4vtKfZWG/5N3vps3sqtf+856ceZ/Vv+
         84DrTh0Sb2xKOue14qfRMF5vEd9nelWyYV9RghUHL81MseioQ3ad8vJCKQWQ2vC/q+Pm
         GysgZvpvZ9h1oeogWiNVnme3l89fb0IN0NJjX+iBTJXaBqo7/AbdDVI5/LLGXUfal4PD
         YBSPkWVOaMKdzAvFkAAh84v+Kp+UR5sTl1AvkbMFuVewzd2lqEgUYF4ebhEfGi6LYlys
         yuXrLZvtjP5QScI3GbDkdjBqCBc0ioKchYt8eI9fst0rU5Llboz5x0+UJUlmVOJVFLHI
         nCSA==
X-Forwarded-Encrypted: i=2; AJvYcCWWP3eFIqs6yFHXF0IssmP3EorGlihuTb+7thcM2j6G2Dk9NrhgIZiuXQFxseRN35XZ/DDdRQ==@lfdr.de
X-Gm-Message-State: AOJu0YyS7ZF2KDtnPYP3ybJZMhaW66j8g3TTWheUILuRatcPWmV1iITL
	Sw44VW0G9xz2gXsGDY4KnNWoGC809HAK7FHnqt7FmX29EKs6cwgc
X-Google-Smtp-Source: AGHT+IE7ALFVAM8UeE9cPO2rV6riRlwdKGY5T5+vXhjoKPCoFxhwA0PH38UwKPe3Sx6cSgBXJ2Rdkg==
X-Received: by 2002:a05:6a00:174b:b0:736:6ac4:d204 with SMTP id d2e1a72fcca58-736aaa0f48amr4062057b3a.11.1741346209722;
        Fri, 07 Mar 2025 03:16:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHbFIRUHWEDOFGzVdpcq0fIaym4bJd7IZh/ZSHgkYaJKw==
Received: by 2002:aa7:90c2:0:b0:730:940f:4fa5 with SMTP id d2e1a72fcca58-73694ac37a2ls1774336b3a.1.-pod-prod-04-us;
 Fri, 07 Mar 2025 03:16:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUEdCdS6/lZ8WmG4iiU562C7Aigrhc6axpD1QSEXaclK1HHq+HK4pYhwX83C++w40EnQ7rqX5xudDY=@googlegroups.com
X-Received: by 2002:a05:6a20:3d85:b0:1f3:372d:3c60 with SMTP id adf61e73a8af0-1f544c80157mr6289899637.39.1741346208285;
        Fri, 07 Mar 2025 03:16:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741346208; cv=none;
        d=google.com; s=arc-20240605;
        b=gWHa2oXKBMNTug2YjLCCrvlxiHFag2tOaOfIpDIuj92CHuPt8WwdumAxygj3TDkzKh
         N+UXPYwXbiYfG83CKtHrmALVsxkoLOmjrCBmnAvPBwCTI9TbRHc3xPXm8deDOR7RrHqq
         mCMqVpAMvCtMvbQ0yHAJ+3F86oaBvZmIV+XS+yGalJDDm2Whi0edFcnbtiGH0UAuFkZD
         fjor6mcsdbvSOkuXGco9APMWPcNnHCXW6LZLBVcg59KzsM/CJFQHYF6Bw9SE09SGoW+x
         rtTfwEoxJsOy2hr7/CQeANFfswQmLLaxXFh9voHuimFVOOK4AMnIbmVtq60st2CfWAxm
         ABEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mRU/TFaL4e6XK0tcZjzvJPjDs61j/v0SE/FCbM4Kz8A=;
        fh=JlRmT0W1HRbabi4YizOIMHabDXRPPp/GI/HyQ+H+nj0=;
        b=M8R+QcIcBVFq88qsOs8KWfaxVou2wOfQrRzD7//MWzo8FRt2I9zQ8rH+l42XVKrPYc
         pgF3+U28ddz9KZv1hfyF3msepMNYLUy1YFiWsloFupFRJHlalg3eMgyLNlgBaadIUVd+
         mKiSHORi/M3Tx11MkHKk5ry0rOfG3zBNcKLfY3PI49xZdtJ4AmxMwoyjVfPE28IdNFJo
         cPNiDPH2mRL3woy/gmp34DMLa73Tzotvf6KDrM0HGNrfr5w7VAguprnSf9xXX82Tci+B
         65XclDcTUr27Qa7n8kNFIKVWmpesBOZJ6qFLv3brOwh9ajevqhvS1iMmRpnvGxPL9bEC
         /mBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YEcRD0nP;
       spf=pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-73698204fe4si151938b3a.2.2025.03.07.03.16.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Mar 2025 03:16:48 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CB7555C55A6
	for <kasan-dev@googlegroups.com>; Fri,  7 Mar 2025 11:14:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 45979C4CEE9
	for <kasan-dev@googlegroups.com>; Fri,  7 Mar 2025 11:16:47 +0000 (UTC)
Received: by mail-lf1-f44.google.com with SMTP id 2adb3069b0e04-5495888f12eso2125785e87.0
        for <kasan-dev@googlegroups.com>; Fri, 07 Mar 2025 03:16:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWppNzSrSy+AJEK6QjTla+0epkTPhTAd7BZWHwJKYhUDNvs08EG1oQR/iEGOgQ79OMs7cV91NP3DeU=@googlegroups.com
X-Received: by 2002:a05:6512:1242:b0:549:66d8:a1f1 with SMTP id
 2adb3069b0e04-54990ec56b5mr1217665e87.45.1741346205601; Fri, 07 Mar 2025
 03:16:45 -0800 (PST)
MIME-Version: 1.0
References: <20250307050851.4034393-1-anshuman.khandual@arm.com>
 <17931f83-7142-4ca6-8bfe-466ec53b6e2c@arm.com> <c3dddb6f-dce1-45a6-b5f1-1fd247c510ab@arm.com>
In-Reply-To: <c3dddb6f-dce1-45a6-b5f1-1fd247c510ab@arm.com>
From: "'Ard Biesheuvel' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Mar 2025 12:16:34 +0100
X-Gmail-Original-Message-ID: <CAMj1kXE0mCPSKLyNUkLZXLntX-=aCGKdn5b3Zgme3PbyYFgFdg@mail.gmail.com>
X-Gm-Features: AQ5f1JoPPqfSFsuuGLR7flaiIcakquC0OyiZXiqRSi8scsvaTC-cqIRH-u_m12o
Message-ID: <CAMj1kXE0mCPSKLyNUkLZXLntX-=aCGKdn5b3Zgme3PbyYFgFdg@mail.gmail.com>
Subject: Re: [PATCH] arm64/mm: Define PTE_SHIFT
To: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>, linux-arm-kernel@lists.infradead.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YEcRD0nP;       spf=pass
 (google.com: domain of ardb@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Ard Biesheuvel <ardb@kernel.org>
Reply-To: Ard Biesheuvel <ardb@kernel.org>
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

On Fri, 7 Mar 2025 at 10:21, Anshuman Khandual
<anshuman.khandual@arm.com> wrote:
>
>
>
> On 3/7/25 14:37, Ryan Roberts wrote:
> > On 07/03/2025 05:08, Anshuman Khandual wrote:
> >> Address bytes shifted with a single 64 bit page table entry (any page table
> >> level) has been always hard coded as 3 (aka 2^3 = 8). Although intuitive it
> >> is not very readable or easy to reason about. Besides it is going to change
> >> with D128, where each 128 bit page table entry will shift address bytes by
> >> 4 (aka 2^4 = 16) instead.
> >>
> >> Let's just formalise this address bytes shift value into a new macro called
> >> PTE_SHIFT establishing a logical abstraction, thus improving readability as
> >> well. This does not cause any functional change.
> >>
> >> Cc: Catalin Marinas <catalin.marinas@arm.com>
> >> Cc: Will Deacon <will@kernel.org>
> >> Cc: Mark Rutland <mark.rutland@arm.com>
> >> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> >> Cc: Alexander Potapenko <glider@google.com>
> >> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> >> Cc: Dmitry Vyukov <dvyukov@google.com>
> >> Cc: Ard Biesheuvel <ardb@kernel.org>
> >> Cc: Ryan Roberts <ryan.roberts@arm.com>
> >> Cc: linux-arm-kernel@lists.infradead.org
> >> Cc: linux-kernel@vger.kernel.org
> >> Cc: kasan-dev@googlegroups.com
> >> Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
> >
> >
> > +1 for PTDESC_ORDER
>
> Alright.
>

Agreed.

> >
> > Implementation looks good to me so:
> >
> > Reviewed-by: Ryan Roberts <ryan.roberts@arm.com>
>

With PTDESC_ORDER used throughout,

Acked-by: Ard Biesheuvel <ardb@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXE0mCPSKLyNUkLZXLntX-%3DaCGKdn5b3Zgme3PbyYFgFdg%40mail.gmail.com.
