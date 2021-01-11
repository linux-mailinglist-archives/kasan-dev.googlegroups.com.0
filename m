Return-Path: <kasan-dev+bncBD4NDKWHQYDRB7OF6L7QKGQEJV7TVIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B01EF2F1EB4
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 20:11:58 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id c9sf784376ybs.8
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 11:11:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610392317; cv=pass;
        d=google.com; s=arc-20160816;
        b=cUsJ8/jSbjRLEwuG3To+R7K7bkdscHRhTZ4ngzn+Whdcs2oRzsbnq8hGs3nF+uYgGr
         vOVRba+wfANcdG1F/oY4Ho9J7jJBZtuadN/3aDsfJrBBa6Gshfzo7TcRbf+ApSHsgra5
         kaGrv5/PoSLqSTqxg/JguIKaNPxqab6wO+EBrm1mYIQe6U4I8Wvc57d9kov0+t481JIJ
         XNFw3k7uVZFm1KvWywK6tikRqK2zsTjW2fQAHPHkhEcEd31h5njlOVu1ykBcYTWscKyH
         wB2G2Gm8pUE9tHAJLRoVwulsFWm7dUsIN8HU4k2Rjbkp3smut1MLKeWUEJCDtv+ExFrh
         rorQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=i3ZjgSX+t+IwjM8ihzKbhu+msyntgxavay2EYwpRM+o=;
        b=XWUu4nCa3AW6xX0Pz4kwRA2+aPwRAyJDYpTYtqG+MHGTmwlE9SDXMPpLsrkRab01Ds
         uirp9Sh7U/9ByouPThtCGX1LETewC7f3UjtCF6i32EATiC+6Xxfe7tt8KzSm5B1faIdF
         DnKBNEJtgdPJHniY1Kw4/w45AJRvGXNwWiu4EAoFyIZz3BkMAPRPgmLmU6NIm7QNLOYV
         HcRbxO0b/zz/3TM6m3FRI6k2RthG6/r8H+HFCJlpnKCjG4fpVe3polYxHPnR1jf70yrj
         e7ulJQHR01Vuxy+z68v2NYUp9uT7YN4jtLNtcvLFy9qpcaBIVsb2fVO0L0iHumvx02ge
         LNsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UJTB+Bj1;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=i3ZjgSX+t+IwjM8ihzKbhu+msyntgxavay2EYwpRM+o=;
        b=b+uRu2l8OFFB/2Z3TlgVWFHVMfT2WrtQyQLO9uVRh7Sw0itW3hhfm5MlXSXLpRHL5/
         vuFJ0uknOHEHLvvkQapQZM9LqpqhQS+/B5FjX+3SzQ8QVhv1bKfpPmuXW/aBb5t1xIqR
         PiXoYzuZfaO97P+Wg0/xUpuHf0cI8GGt5Pli2yp9JKc8i4zEFkYcroTE9gQ0zZJgQyXj
         4SCD2Igm8K+uyD/cpBksLKb9q7QpBhDhejvY677uEedpy0osxIe9NEmrhDAWTVj2LBw5
         UElH0U3gFWLDDme/I9dAT/WK08HEnoDWixe3eeC7eRXGS3ixqoFBayKqMBuoDz5on0dq
         6XXw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=i3ZjgSX+t+IwjM8ihzKbhu+msyntgxavay2EYwpRM+o=;
        b=BhAMoVltmclg+4v6iFaB6l11OU17nZZz+CrvHmjfakbCXPFEkp9x02n6mM24PfPEZS
         kXItWAdYkwGi3UYSLE52AcZI8zSEBGkee0RpvjB7Qg2y6pMUiol2wl+qwVbdGVGlreB0
         kjzHziDgtVeV1oBISNeX5NsTgcxCqKe8Otla/bEoyUz51HjKohsb9VQsMx58qwhoFtvo
         KjBwf1ENI5Lac9ygHuADe6UOiYN6YkTAuGHZqdDCxAU8pUCKVlMnZ+EaUC4tXcllpApw
         613FhK392zcFf40bcuF2wDi++iwNczzjjcUawdYjcDl1sBlQf0cbQvj5Sv+XQqeuvEhp
         LddA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=i3ZjgSX+t+IwjM8ihzKbhu+msyntgxavay2EYwpRM+o=;
        b=sFGm9b4MGSZAmyinXZdLAzWh0DHVLZfqQWh+r6lZT/5gBXtDUYvHHNtZGz4X0kKsbC
         WA6L075uX6txHoIDANeqjGT2MgaIWZWg5evhbrgcn+Ls2x3fu6+uGr2NvE3IlLjtQeUy
         hymr+5O5esi8mN5bq4ZDuSpaYRjL8aq5CKNZfrFOT7TaS+nITIShPFvRTwFqRODUYX/n
         ttr8dDxlAKaxVLUy1E6pey9qbMqTPsFJ2l537/ffnaL/hCAoaFEHm5AIXvcfRdgeg8QZ
         223k0X2MLndGZ+3o86aVJt5dCPPIGvdMGcacEjMHn1AwaIhT7XERN8/ts9snfeZquBuy
         Rb0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532rpis0ZMelou/3mvVaPV1xi0+z74hHjDhFGl4M7uleTCjif326
	q/FnwZUQoR3mB7xQDatBKAk=
X-Google-Smtp-Source: ABdhPJyUBfQM9cSt/Pds2cs66v0kVpDZxgFOZDZ+pICn85bwJByZV1pUS7mCxl5BKtlbRXA+7fKA+g==
X-Received: by 2002:a25:ea09:: with SMTP id p9mr1802952ybd.109.1610392317674;
        Mon, 11 Jan 2021 11:11:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c594:: with SMTP id v142ls383250ybe.9.gmail; Mon, 11 Jan
 2021 11:11:57 -0800 (PST)
X-Received: by 2002:a25:4207:: with SMTP id p7mr1685504yba.367.1610392317246;
        Mon, 11 Jan 2021 11:11:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610392317; cv=none;
        d=google.com; s=arc-20160816;
        b=zwBX3mFsJykQgwhGapThTaoyAC6zLw/YDxZ2Ou3afNyZUnRIZLa7eFHfaNnPaeofd3
         I4vCFAGb5GS+r0vdpBfGCy8zQUSI3JuzV2ZF0Ac54sDn9Ly8XCiy8+0og0sk8ZPcUkqs
         u4XhH0BGFD5l/Rocyw7gyK6t0i7RhZ73130ZLnbxXvNe+yx4U2lJHBjrCej2C1bTVBmO
         ZaQPm+NOWvp+XrllwL404kOX0EGzljcfjXt2pN+YkwOAMhM+nIrbmQ9XciIdZLFz/jQX
         TYWrmizLfKYN5UJPQiaWN5fM9h7IaU76fGzlm3N8A1XNML9HXaBOn35yVKTtzyXMM7KJ
         iPiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=810FEXKXHgKArsdDAMgoY00MSSyM0BmX9OCgjLnP4Og=;
        b=gU4ttd7Ngn8XX6rUCsRudZhVO9Hnxu0P+v5aXzEwZeML2LyHu1CqpIJNbu5T3wa3Mq
         tbBrGerBBZZz4e0LeUSztiNxYBgYBZwszrbS6etgJaZFRhpTeH1CwRL0NArvHqOuqW4r
         8TRCQHNiT/6LMwtnYkt6aMzNInqtBY09BHWph5tAgPkJxbTe1X+Z7/vsqsA2G15T9cQ9
         KWmQAvZULIIhyBe357aMIHQNaFM+l0yWNPu+BJbhDgUQT03019YBetuGgmnY07CGQGHl
         JuPkauqY5ovr1SyVkeHI4lm1yy222JpctZJGzT+VirJknXLWcTRjBE4+FF240hVJ0ecf
         KxOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UJTB+Bj1;
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id s187si112154ybc.2.2021.01.11.11.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 11:11:57 -0800 (PST)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id n9so266580ili.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 11:11:57 -0800 (PST)
X-Received: by 2002:a92:d2ce:: with SMTP id w14mr628841ilg.182.1610392316821;
        Mon, 11 Jan 2021 11:11:56 -0800 (PST)
Received: from ubuntu-m3-large-x86 ([2604:1380:45f1:1d00::1])
        by smtp.gmail.com with ESMTPSA id 143sm316464ila.4.2021.01.11.11.11.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 11 Jan 2021 11:11:55 -0800 (PST)
Date: Mon, 11 Jan 2021 12:11:54 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH v3] kasan: remove redundant config option
Message-ID: <20210111191154.GA2941328@ubuntu-m3-large-x86>
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
 <CAAeHK+weY_DMNbYGz0ZEWXp7yho3_L3qfzY94QbH9pxPgqczoQ@mail.gmail.com>
 <20210111185902.GA2112090@ubuntu-m3-large-x86>
 <CAAeHK+y8B9x2av0C3kj_nFEjgHmkxu1Y=5Y3U4-HzxWgTMh1uQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+y8B9x2av0C3kj_nFEjgHmkxu1Y=5Y3U4-HzxWgTMh1uQ@mail.gmail.com>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=UJTB+Bj1;       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Jan 11, 2021 at 08:03:29PM +0100, Andrey Konovalov wrote:
> On Mon, Jan 11, 2021 at 7:59 PM Nathan Chancellor
> <natechancellor@gmail.com> wrote:
> >
> > > > -config KASAN_STACK_ENABLE
> > > > +config KASAN_STACK
> > > >         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> > >
> > > Does this syntax mean that KASAN_STACK is only present for
> > > CC_IS_CLANG? Or that it can only be disabled for CC_IS_CLANG?
> >
> > It means that the option can only be disabled for clang.
> 
> OK, got it.
> 
> > > Anyway, I think it's better to 1. allow to control KASAN_STACK
> > > regardless of the compiler (as it was possible before), and 2. avoid
> >
> > It has never been possible to control KASAN_STACK for GCC because of the
> > bool ... if ... syntax. This patch does not change that logic. Making it
> > possible to control KASAN_STACK with GCC seems fine but that is going to
> > be a new change that would probably be suited for a new patch on top of
> > this one.
> 
> The if syntax was never applied to KASAN_STACK, only to
> KASAN_STACK_ENABLE, so it should have been possible (although I've
> never specifically tried it).

CONFIG_KASAN_STACK was not a user selectable symbol so it was always 1
for GCC.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210111191154.GA2941328%40ubuntu-m3-large-x86.
