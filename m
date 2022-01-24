Return-Path: <kasan-dev+bncBDW2JDUY5AORBZPBXOHQMGQEHJKPXXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 14509498866
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:33:11 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id i25-20020ab03759000000b00308e68dcb1fsf10783291uat.22
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:33:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643049190; cv=pass;
        d=google.com; s=arc-20160816;
        b=HpCBWAwVuow/udbRBw8rW2cu4Q6AKoXbsDIeBsgEx38sqtabLtAwVW/1xpnUMxkYpa
         Z1irZRMhTWrXMCdW5aHPsrOF1YVNrYPWhMwqre8Fup7C/2I9CiGJTTE45qOMRTN3Oq6T
         sPisgv8quWdOlxmBnCpNZiB+hLW/3tDtNmI8BrteU+A4fUsp51xDGcN5y3mHiVHHooVI
         dxgnM49XLxUmgouLvBR9qZx8B7LrbZyFI6ZUZ7uEpb5AgrcE2CSHj8YkG4DKTz4w2ubl
         aQSheoGcQ8m5RuCn7tFyIt0ct6XqqHkxT+5dTsPWwK2WiZ8L8JU01U3wishrSGynl9Uh
         6c3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Wcf5TERWKNvZTXa9mho98KadEo/ZPZqKd8OKA14PTz0=;
        b=N8zOuoNpSThXZGyMc6s49T15tHKoDAKQiWLwayBwjPyj893uEmtRk7kWL8PdLMo4nA
         LueiLxLOtCp0BN3OiuF/jbw0TjYeHgNk+Zvr7cZH+wYlr+yoR8TCeAi91m4sj0pcReMT
         H7Nt5BoKRWrAFhKpWJE+I4enF9uNAwfa7H6TOq56vPK1zfHzsjwJb3P2gsfP5nQ8/msK
         yr7/5DHkXz4lLt8f/Iu0lTa85vBq05UKN//t7OC8MfbFSeCibrZBfPEuV7tyj7NNRRY8
         sWjKlFIXEyixN35hzJ6Amio8Ui/e7N4XEdKY6PBUVIb//HylEWCPDezZOsdcxRglSb6W
         6oBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pGkU+DYD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wcf5TERWKNvZTXa9mho98KadEo/ZPZqKd8OKA14PTz0=;
        b=YRb8YoUtMr8UEilWICE4a6SxoGR+S4rCuWGkv6Uw3vMjLUapKwg0ZDPFs/0XzD2AW1
         oHk7GWReAAaZBSPABxAVDkVntPXv7g3MKzRgZ6shlCKBAg7hYc6ODQOtX2AY0DMt1bdv
         H2eAYh8bDnKiXtHjSn8tgbC8/5H09G2Gi3m3D5OGKCsr3Yv2YkSeiY9Dp7+yjNxSwFN3
         uGqmTwAWt/GdPCJUVPP5OKXzwfpGLQRXfVVReYclNeAUYEwitIpvWaqGf1SuRaXnqSyH
         jAducor+vVMDO0zjUjMXAQ2ELPm/XULt8Cp/cLkhihLlipeQsENMqwFY8k6ZVe0/diIg
         FeXg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wcf5TERWKNvZTXa9mho98KadEo/ZPZqKd8OKA14PTz0=;
        b=Mk1ZDE8bnzbLTvD+lWxdxn2fsttEt1PEJUAXEUZ3QIKg6SMt51Lp0VrIG8gO5OmQ+2
         zZaqivuiTGbIo5ar9ChMEkpgFxXT/zX8PiVmnopgoEkUqSSH65NW7aX3pNGKnCXmCARS
         97IzTDEZHyXUC+XSdrDDlCQojKha8IGlYg1f9N2QrcV7Ddc34zt1YpYQYGLxJl/9JO+q
         MdBGuCaIfbP5+e23ZNZISnKwo6KkGyfgpGLJjJMoiHDo8tgEPDbdXq8GmRPD/mYf/+lZ
         5mQADDoHZ52EIuCjSPuQYOyvKI9fdNniVl9XsaoTn4YgPPio8gNPWDo1hT59xcUrgh/M
         N9/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Wcf5TERWKNvZTXa9mho98KadEo/ZPZqKd8OKA14PTz0=;
        b=Ox3akfEHy57Ji04KUqAaPn1H2WUV1Mwea8DxotpJDYQ1kSZoryI6pI6rVq3gmuYf8I
         8jZmrXdVNRjncRSGnxgUuQGQlVyXklZO7Wy7soAU7s8g7y6nA/mptkzPsEXat0xFDYUT
         iu881bx7dL+i07GZebjpoTR6AUQZ5SR5jvHt4yJ/yG2pfUs6X6BEWB6IkpVU4mx7Y6Ed
         LI0COcEnIaCSxfbPS2nfo9XJBMpdAMq/6/5sL63mP1c1a3dcD+IZcXBebfdH/YRvMxaU
         tIzIovTA5xJq9+tZCE6byBPGLjJzsKn8Zy05wLWd4PB6lsgyjAY3LMKVnBdCkekTaWMw
         uvlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530xbRYCdBhlPWyiLFAV/s4//2Juk7xuWXqmsS8qwe+ljdSMqSLp
	O1jVkn+gKByRcordxDRQfw0=
X-Google-Smtp-Source: ABdhPJyHH1fjp2kPhjfae9RChPLnDTTlxlDHGfOvhnTqrsm+jNLTpLejKpZXvfeYpFVi9ZYQyYgCyg==
X-Received: by 2002:a1f:2089:: with SMTP id g131mr6427458vkg.14.1643049189891;
        Mon, 24 Jan 2022 10:33:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e104:: with SMTP id d4ls603108vsl.3.gmail; Mon, 24 Jan
 2022 10:33:09 -0800 (PST)
X-Received: by 2002:a67:c004:: with SMTP id v4mr6077492vsi.34.1643049189452;
        Mon, 24 Jan 2022 10:33:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643049189; cv=none;
        d=google.com; s=arc-20160816;
        b=yh2hSXQbIS0jtpqVP8xJMHKr17ryBIEQojDpvd/+Vupx3/v+1Ws8QQxhEahEVljzhV
         Li952/kWnuZkJxVkCgQHBSzhtOhHH9guj+Xxj0C+enEq1S+CcxB/8NkSL+N2lPI0v9dT
         WvD+xMOovWI7wdcckrnAFJyGblObHrcX+YsPctdYJwqDJN2YtK1M7HQZVtq1mtG+ZlXh
         8CEnQh8scwRObBaWisywuuNehlW/o3oRC2bqX+6IonyRHccNszC3gYT5LcaIqff1H/CA
         JpAmLAnxmPT7qAcxTW/ZyqfwczHNsZC6uOECaUWPdj56q75AofKfH7AVZBwc0ARQqCHo
         kgmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x+ahb+ncTkNINLBQrDuikTk5BgmagpsijNgGC5Fq2MY=;
        b=QRnsnC0r91DfM8/pDe7cFVsGQkAqHiaz0DqIrM87clOuQl3Vl+6cXwePi5G9jjuk/X
         t+uUuwpqJAXhyN1+b35c46l85ucFAocgS+fSbOxQ1BTEuORdq1ZIH2qiY6h7xNBrU6RK
         U+UzfqfhWS3fyCVxCWWy3+E/oFOBwh0kXmeIIisuJfn+BD98SgI5bxQLTY7Ev5kJNr/5
         u1jxnCWKYxIwGZE4LqnkyHXE17kIvuttoyjgAHoydNUd5XPv3uFouPH9PffOxxl4vyca
         ux1LShbWQNJLgzu3Fet4vRsGGS91u8hyXdv3OkeSsKBKPnjCkUGZrTYmFZIxGwMjJSQ4
         twsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pGkU+DYD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id 192si460645vkc.0.2022.01.24.10.33.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 10:33:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id y17so3135401ilm.1
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 10:33:09 -0800 (PST)
X-Received: by 2002:a92:d2c3:: with SMTP id w3mr1032639ilg.28.1643049189234;
 Mon, 24 Jan 2022 10:33:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1643047180.git.andreyknvl@google.com> <CANpmjNO2Lwq5+zy3pGj=cetMdB7qLmP0WWjbSCYucPVjEt4kWw@mail.gmail.com>
In-Reply-To: <CANpmjNO2Lwq5+zy3pGj=cetMdB7qLmP0WWjbSCYucPVjEt4kWw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 24 Jan 2022 19:32:58 +0100
Message-ID: <CA+fCnZdxFnxXJyv6rqRgZynK5NC-PS1jSpAdwqVgymr2AL+63Q@mail.gmail.com>
Subject: Re: [PATCH v6 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=pGkU+DYD;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12f
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

On Mon, Jan 24, 2022 at 7:09 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 24 Jan 2022 at 19:02, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Hi,
> >
> > This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
> > KASAN modes.
> [...]
> >
> > Acked-by: Marco Elver <elver@google.com>
>
> FYI, my Ack may get lost here - on rebase you could apply it to all
> patches to carry it forward. As-is, Andrew would still have to apply
> it manually.

Sounds good, will do if there is a v7.

> An Ack to the cover letter saves replying to each patch and thus
> generating less emails, which I think is preferred.
>
> My Ack is still valid, given v6 is mainly a rebase and I don't see any
> major changes.

Thanks, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdxFnxXJyv6rqRgZynK5NC-PS1jSpAdwqVgymr2AL%2B63Q%40mail.gmail.com.
