Return-Path: <kasan-dev+bncBAABB56VY6AAMGQEBBZMXZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D220306731
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 23:36:40 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id r17sf1704333ooq.6
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Jan 2021 14:36:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611786999; cv=pass;
        d=google.com; s=arc-20160816;
        b=LEwpJa7ZGofkvqG41tfg3R9XeBK4DYx+0N0PpAG+KTDevfe+KzL3Vphmf92rsErnyw
         YjN4Hv3VMtU3W5IbraX1QY0j3zzZby0kuanP+YCMOoISp+85PZgO7Ih+GnsR/9kKM0gl
         S1Cw1NZYprvCHwqKZSKespwUL2mLQq875BXdg+PRuUoVHht2yUvNTzf4J998L5hzKHU7
         btSmHFMbXYHS0AM9VRaraqKafoq7sO1oe2WNXzCAxGq+ph9zwd8uGYArPfwC6SFngfQQ
         OxO370yUJWzBz0HIB70yuFCqSK01XYqV02W+yyRi0VFlrtww8Z20eRf39b6gLkOvhWtX
         IrRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=GX7n09b4dH9M6hKJHHznYIUJah7FZ2KQHQKPTHt6Edo=;
        b=wSDvo1gLY4YYKae1n8584cmwk+FSpYvFrwzreHr4Cfaect476D+WDi94NC6HEjsXiR
         QVMmRxuZ8gsR0KlMBKJUomRxDog4m2+j+nCc0Nhyl/XaXnQJ9nytSvPUW3mAOtwnVpjo
         t4tnDMEQst/5tyaLIuqij/DNeTTdE2W8p5dHRE/9FLexT+E87kOx++vgrjvDlugUF1mZ
         h+5gx+y+GvEgOSedJ56qxdr/pI8WoNUjoIsZGKwtzwHVlwlU7qVFOq79Gco6Q1hlVY81
         ZW3DcaFAzHfpslQ5B3aGBLyrlvo14cjnvwAemUgXwV4MDWkneYk50VW+zkMI/AAfFcDP
         v8Eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bVXZ62br;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GX7n09b4dH9M6hKJHHznYIUJah7FZ2KQHQKPTHt6Edo=;
        b=YEzi3xaNpq7BbK6Ixs8cf2uDRRqrCVOSkFOkZn7p51Yat2QC6evx6B4QNrOFXUcW0r
         rxCDE0eob5pWQIcM1zahfate8D022QKAVRR+7Teojk+B2wUDliMkb1/2iVQ7Ao3ztve8
         rTjwkUT5Tk4DmtXxsGlkRLJJ4NMX6un+rVu+iWH4pYyhcNpXf6HoPiv5guQ9VSU7G9Ww
         gaf3+3pXBRYlpdaJpD5hmqVS1XjQcUvnzJfMF0+iZLUDR1JqAGBGa7ur1Ahs8Uq13rGL
         CkFOta0NUmk75pXDvJnlrHFpg9mVsNbtQYa66qq7WuNiee3u3u6uSCyrPcxEg+pjidr7
         1SDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GX7n09b4dH9M6hKJHHznYIUJah7FZ2KQHQKPTHt6Edo=;
        b=Zg0ybwE2nBPrKI7o1ly7G+5paOyAKhiDsAV4fB3Py0V1aua40P7TPZAp8Hh9ED5ncl
         PqGIOHLu4kI20Ni39raLbs343Hwi+kRsLPdDq7hRtyVfdmQLDwDiJlQ1l/jkpPBGAHB0
         4hQHQR01PXgGAdVRitirHYVSJRpy+F+2eVxD8Cqaz0zsW1A/16XvUFoYJ4UDU53yaXMC
         KxVtqDXKx4hs5jkJ5wE7TYQEcDclNEpUsVKNPEFpCEf3VrSGNJi649QTolDKliHxOo1l
         mulVtmlJhitY/w9oUdnp6Ru1QGJ65SIrzb8xqflAW2IO4Cb/KdYgDDoLOpgkJjnpXktE
         i7hA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530j9IzaqLrSezok6H8HabI0WXoPvCxzKKZLJTmC0GjgFvR1bAfM
	G1D3PMcStJFxiZtcTAb/3ms=
X-Google-Smtp-Source: ABdhPJxElrXsfPL3f4E9sgxdVm67CA8xcc1Sf3QwP0aSznxzX3KWFAf9E4BO2xd54kNh5o/L9/sGvw==
X-Received: by 2002:aca:b1d4:: with SMTP id a203mr4752147oif.150.1611786999556;
        Wed, 27 Jan 2021 14:36:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7290:: with SMTP id t16ls876711otj.11.gmail; Wed, 27 Jan
 2021 14:36:39 -0800 (PST)
X-Received: by 2002:a9d:62d9:: with SMTP id z25mr8951267otk.315.1611786999207;
        Wed, 27 Jan 2021 14:36:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611786999; cv=none;
        d=google.com; s=arc-20160816;
        b=B2W6UXmChh+nk4zcmFqW/65vw58ecnSUH2iodRAPvKXwdI/EQRSzzW0QYTl5I/81eU
         RDAdN5Qh+GQ7x7PGKxUPCEObVy4nN9Bxs+b48NuyA6P7oAOQkxnDdYqOdB6H3aKD271G
         ttgUbQ466YPtEdkxZgyh1+w6n94itKOXjVRJKiDjKdcKR87AcCFLD14ZnvGcPUTRvYob
         a5hweCV5ycFT61d/Mu09d3KX5qtwwRmcKPcju/6i5v0x44FXirN3QDtpMZAsKVoHFHNO
         dVP+WEimcXUo6HDLbSF1o/Vqy5l7jgu8cXidHAP1n2Qa/hwMtGf4IDDgZdK9KxVYk9Lr
         yjqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d5HAKmPdt4xuLQwVF7AEPzPsyaFYYQBfk9L1/F8MeBM=;
        b=WY0qgtp+j5uH5/9WSai+WESXSOkL27m++Ju855M0BCSdtvOtF4L/TDcgVfa6JvEoSZ
         fHi0ZI1unIhm5pypNLcjUSZU5s5dsjxF05+P/T+/+smMerD+wFetzv5qiu81rh5fWqwE
         t+WFpSn/ceUTGIkPNrdMJIi5AmSgK1tq3B1xcaDo8zpzBHkbpC+EPpi7WHD/+jUuRWpw
         BAekEJjbO12lJSZIN3A9MxUfVkWJNuttDj5aXTUbND9Dt9ziuWsfd5AZ4b5OSbjd5BnL
         vZe1BNuGwTwAosM9bX0BsTQxNjhtQTKolm+Ga6eslQO/bKr48DEICxProI/7MeeRZB9B
         kVTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bVXZ62br;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e184si289631oif.0.2021.01.27.14.36.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Jan 2021 14:36:39 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3D95764DDF
	for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 22:36:38 +0000 (UTC)
Received: by mail-ot1-f46.google.com with SMTP id a109so3371485otc.1
        for <kasan-dev@googlegroups.com>; Wed, 27 Jan 2021 14:36:38 -0800 (PST)
X-Received: by 2002:a05:6830:139a:: with SMTP id d26mr9405785otq.305.1611786997504;
 Wed, 27 Jan 2021 14:36:37 -0800 (PST)
MIME-Version: 1.0
References: <20210125112831.2156212-1-arnd@kernel.org> <CAAeHK+yOTiUWqo1fUNm56ez6dAXfu_rEpxLvB1jDCupZNgYQWw@mail.gmail.com>
In-Reply-To: <CAAeHK+yOTiUWqo1fUNm56ez6dAXfu_rEpxLvB1jDCupZNgYQWw@mail.gmail.com>
From: Arnd Bergmann <arnd@kernel.org>
Date: Wed, 27 Jan 2021 23:36:21 +0100
X-Gmail-Original-Message-ID: <CAK8P3a3QV9uArBsc4PY0bM_4KGLYhNPHUFuk9s8yu=kGKe8sUg@mail.gmail.com>
Message-ID: <CAK8P3a3QV9uArBsc4PY0bM_4KGLYhNPHUFuk9s8yu=kGKe8sUg@mail.gmail.com>
Subject: Re: [PATCH] kasan: export kasan_poison
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bVXZ62br;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Wed, Jan 27, 2021 at 10:25 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> On Mon, Jan 25, 2021 at 12:28 PM Arnd Bergmann <arnd@kernel.org> wrote:
> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > index de6b3f074742..32e7a5c148e6 100644
> > --- a/mm/kasan/shadow.c
> > +++ b/mm/kasan/shadow.c
> > @@ -94,6 +94,7 @@ void kasan_poison(const void *address, size_t size, u8 value)
> >
> >         __memset(shadow_start, value, shadow_end - shadow_start);
> >  }
> > +EXPORT_SYMBOL_GPL(kasan_poison);
>
> Should this be _GPL? All of the other EXPORT_SYMBOL() we use in KASAN
> are without the GPL suffix.

I don't care much either way, the reason I went for the _GPL  variant
was that this
seems to only be used internally in mm/kasan/ and lib/test_kasan.c,
unlike the other
symbols that are meant to be called by other modules.

         Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a3QV9uArBsc4PY0bM_4KGLYhNPHUFuk9s8yu%3DkGKe8sUg%40mail.gmail.com.
