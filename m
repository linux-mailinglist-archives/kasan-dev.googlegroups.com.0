Return-Path: <kasan-dev+bncBDW2JDUY5AORBMEMXCHAMGQECFO7J2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id B9F20481FCC
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:19:13 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id bi22-20020a05620a319600b00468606d7e7fsf14685454qkb.10
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:19:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891953; cv=pass;
        d=google.com; s=arc-20160816;
        b=RKCO9r7ys+wze3k50KGcd/KjYuffttZIWOdqfLnwv/Dd6Q5LYsZjow8pGqeb5lsayk
         u21eLD9cX7TssDq+5Dk74tyeBG/OAUAshsW5HRwUqc+X0nqjeq3nkpf0E3EZTPsNvnxT
         72eUEl7jpiIzXtewd7BAti71deC1SRhrC7nmJ/TIN5AItlvtLEeL9hIAZ2P5LkQilnqc
         vHHG83g7ESs+Ank3jWjrll1ygSSreyTkc7+UXITH8ZFKYVmzeustIl0d3ENQCqh+ytc5
         q5QLKdCcZUO+HtIr97ouLEZUEyjk0oRk9bpSbwZH1KfxOr9QHUryODxCu87Q/6ruUNpL
         97Hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=EBHBbvIOOGcwHhf4hKZpIOHngw47Ce0Y4is2drhMq1c=;
        b=0fbr8Abz77jLnExgNAG9Z9Edg8yvsljacsy2JxDGePOvlLbUyUOF5CDwzcZcGd8Mbq
         eDJdpfRLhWgCeql57bC1LtUHWuhOT74V09MYXUmKX5LikUzQwt/HTtY5deRuxzoszFzP
         vhdUFEomumeNxT2+yAHv6MOk4gm9MyYdopXmm3l59MYaAPzrAk/ESR+7R3vLTYvbm1P8
         wcMB+kWUvPspmC+p92ZJAyvhAicfrUHF+SUouEopQYF7GICaMoq8rm3woN6tarOrQwZg
         elf5IB7XiI8jVnxFNynhHFBNPscCJlblSDbyKLkxv96Fu0wW3EO9+XYmDcHxMOMxHoQk
         +oDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="mbg/EqmG";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EBHBbvIOOGcwHhf4hKZpIOHngw47Ce0Y4is2drhMq1c=;
        b=sF2oAO2y5qxMhqWlrk7U/AEjMu2Qc0VkOudWRxwT5VChkIimljK0cPw2z6pcxjrzLw
         0+KeeNvTSIvByGhGBjVUBOr8d+L7553PpYxxhozUzTSKURu7Ubrn6RW7c0ZyfP47BWIq
         syGoaRUgsxepjpUjbP3ZCFd5/WVBfUAzGTmsq9SSds1UbNkT88YhS/sW3fvECmQ9YFlo
         EPWzlTupH3GpwZEkSETZ6JE8GSzbsBCVjxNTlwMbh+G40bDkEQVf+DGN1Hz9decKE7MW
         S1gfmYxrczKJ0/NpG9f2w/4ONGDm9GcqT/OH5pAqtyEtFZDNrEe+nkS7B7nJVri69EU5
         sIXA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EBHBbvIOOGcwHhf4hKZpIOHngw47Ce0Y4is2drhMq1c=;
        b=PNiov9UVX81ba4PH96ClSQGggn/l111qizCpHQKelKpbB3hyJvyT2p+QegfeKFKlv5
         u3lZVwIud9IcJ1yLerNhsEfnC53US8xkk/iL4S4glSOZWH3+drlwSsPdgKNN/fnxZ2jT
         04+9rkpz8Vz0t2Ly9EIfZjd9J3NedST6Wa7qgk46u0FAhbDqquc1GtLX1XzmHAgo08QB
         HJEwbX7g61eqCJiYlVhC52PcF2yYAnvdk7fnMa2FRXVsvlQ2hAVDMg/eXYsz+sE1QCxu
         xqBKCX5GyVlYyW2DUoii0wu6a3NL0loCirIGCDc7OoHPHMR3GibQWoU37KlupUlxnj8Y
         ny8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EBHBbvIOOGcwHhf4hKZpIOHngw47Ce0Y4is2drhMq1c=;
        b=KL2OMll5sJ4VUvGwZFBcxPFS0gar2N/seWFFmoRGnJBK9CHf79wH3DUan0/dAVVh5w
         I7ypPWIT6iM8JRJEOwO2tjlyLQaaIKX8r8wiFYWv7etCNsWjWXJvg2/4WtOhMC9nBIXd
         45j6PdBB7E89FjEw0PfiXV1VHxYt/h38hOv/ftTjWyemSibXJjaWTwYoJJvEbKyuDPz5
         rt6PYqXH4drBEkzHSigxwy55RQj3FL7lHWTzp77u97CslujIuDUOM3HQPYeYA8rWCIMS
         87zGWoZelW9I+FP/TRBJILWPkwZZJs142kl9SnQk2DdFBC57Yyh1KGf2PC9M6PANcpWP
         nz4w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532REtygkdbSbu+AHx8gqgoV/lvg3Fsboe3+dIpMBcFH9Kc1CWnE
	Fs9uSLvH0HHveYcbDn2TYb8=
X-Google-Smtp-Source: ABdhPJx8qtoz3oYFqJVYNfwO371/XwasGLYGk0zSDagp+Gm10cZRVbTyDxiybeffEyoLxQtvByCsZg==
X-Received: by 2002:a05:622a:3cf:: with SMTP id k15mr27022235qtx.272.1640891952865;
        Thu, 30 Dec 2021 11:19:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4311:: with SMTP id u17ls12298475qko.6.gmail; Thu,
 30 Dec 2021 11:19:12 -0800 (PST)
X-Received: by 2002:a37:9cd7:: with SMTP id f206mr21647780qke.248.1640891952456;
        Thu, 30 Dec 2021 11:19:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891952; cv=none;
        d=google.com; s=arc-20160816;
        b=Q4ZQic2xuNLi3Mc2RQgLAPO25w3voiQAf0YfEeprcAM6oGqSj5ZFVzV86cBCqlOJdC
         lO80nqEFuux51ojPYeG42oPfJh4TELptwxMoUSGw1IVsqUo5PjJkf5ygC0rdxc8+wgZ+
         pSEP2awrhpidojks5osYb0ohdyKRaUXMIgBkZjGuNgEsppT43Y+n/6ekLfh/kO7o7ekc
         cZvyNTNi/Q/g5Qu/c0qwftIuu4oEkOnl4qW4ruA7KFKNV9Bd9VEecdjJ61/bSonmBCf9
         tGIe3nxkgyGU55di38Ls6jP9C2q48rbTlCHoiFMxICmWeuAC2xn9qaY00EIk17F8DKtV
         RJ9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DUj31a0vWo3+lEkWZ+Adl6dlbYeVbADGrJgYxEnUpUg=;
        b=xHEnN4IW9Bjnp8ak8ucqBDTBK/V7ZWNegn5kPp9Vwlc9D+VWmslYPoMYQUbtWVdFw8
         QKCrfZ9mWiroDyRiua7KJAbt7NG+yQU1RdYTghvNzv1GZvSPzzXLecxzmpa5uAMwlBMs
         ndqGC9YzQfQ0qc5Qpc2YjRX2PeojpJW6TFXoBxJD6PhmgEeFeEdNoMH1SI1pzwnIQLxQ
         D4akHHRYPWjOCE2Es1p7EnLESVI9+qgZHmOxaEseRBtSDC4i7dXoSbn4bK57SYz4LckN
         mKQ54RPWJsxemgb59T6kBMSvM99wiElELFK81N9ZM44YvKoA7Y4JRSk78K9TVsb/gGa0
         Trxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="mbg/EqmG";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id 22si3508452qty.4.2021.12.30.11.19.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Dec 2021 11:19:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id p65so30704954iof.3
        for <kasan-dev@googlegroups.com>; Thu, 30 Dec 2021 11:19:12 -0800 (PST)
X-Received: by 2002:a05:6638:2404:: with SMTP id z4mr9960690jat.9.1640891952203;
 Thu, 30 Dec 2021 11:19:12 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Dec 2021 20:19:01 +0100
Message-ID: <CA+fCnZd+sBzecOGBD8zR3CxXS1yjV-X3-epAb6N=ZT8rJdCU6A@mail.gmail.com>
Subject: Re: [PATCH mm v5 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="mbg/EqmG";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d36
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Dec 30, 2021 at 8:12 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Hi,
>
> This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
> KASAN modes.
>
> The tree with patches is available here:
>
> https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v5-akpm
>
> About half of patches are cleanups I went for along the way. None of
> them seem to be important enough to go through stable, so I decided
> not to split them out into separate patches/series.
>
> The patchset is partially based on an early version of the HW_TAGS
> patchset by Vincenzo that had vmalloc support. Thus, I added a
> Co-developed-by tag into a few patches.
>
> SW_TAGS vmalloc tagging support is straightforward. It reuses all of
> the generic KASAN machinery, but uses shadow memory to store tags
> instead of magic values. Naturally, vmalloc tagging requires adding
> a few kasan_reset_tag() annotations to the vmalloc code.
>
> HW_TAGS vmalloc tagging support stands out. HW_TAGS KASAN is based on
> Arm MTE, which can only assigns tags to physical memory. As a result,
> HW_TAGS KASAN only tags vmalloc() allocations, which are backed by
> page_alloc memory. It ignores vmap() and others.
>
> Thanks!

Hi Andrew,

Could you PTAL and consider taking this into mm?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZd%2BsBzecOGBD8zR3CxXS1yjV-X3-epAb6N%3DZT8rJdCU6A%40mail.gmail.com.
