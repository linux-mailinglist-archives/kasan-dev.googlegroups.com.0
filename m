Return-Path: <kasan-dev+bncBDHYDDNWVUNRBLN5XH3AKGQEQ2YGMOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 153671E4267
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 14:36:00 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id u10sf9353299uad.8
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 05:36:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590582959; cv=pass;
        d=google.com; s=arc-20160816;
        b=jRXph3F/6VZLCRoDIpzV9D8tyCsscpXdghkAnYQqIXLIy00XxDX+whYpbOXnioAkFW
         N3J3w+posVBQCYJVOh0Ech/LXCc0xJA1gtnov8xZHZbdg6clWl1bM8GReszjbpQI4BxX
         ZngBZ/kf1tE9PIEqunSwSCgbYK8tYS27T0xSwmO8eO0spXO4yE1MN402LSJSNaZfGRn4
         ZLSiK5qaXT58AYqQwA3bsKhgwtGDoqcncdpmaRsQVH7FGYoo1YlOTpO4Tnbv7lSPeGVc
         cSSB4NLKU5+KeV+CrwPZgc0W7GrRa+B2BAND2WJbAcNJQL19Mx9Bb3Qkx4UBGdUK0vIt
         PHBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :reply-to:in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=0OEfMN7OTibR4RSv33bBSA99eQr0CSUai1wdFcpGwk0=;
        b=BStbH068AC4+4R+DcM3UGIvbwYZDhjtVrYgfV4HNopXWEWO5tpBdx2B1EtppnPSPU0
         acZ4ZrVJjyYEbTvzN4xJp6piCtQDiu0o5nn4DFXCeYelcjsagXP1Gm6Og/UI6lDdBkHv
         VL+Q6RBSlJKaXZ7kjDKxCVCjLPyUTcjO0/8kj7dnlowQ6o6MGnMQ6n0E03m5aBP5KGPd
         +qP9vpgHoefcHyof8RMDf7R/icAGZZeRCIX1PbTjMeR5WG0TcgsQbtet1ZoY8T2S8Wh/
         U6e77hp0Tbe/2STyRLgQW6ROy5lPy1T8vr/1du0oDdmzIe7Ev0ck/DhgnEdwiCMofH4F
         P47w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=pvb7cjeW;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0OEfMN7OTibR4RSv33bBSA99eQr0CSUai1wdFcpGwk0=;
        b=tWlXhaag53LPIpqdN21MSMaXB2A6iPhQxAXfiQF+CXyXhcx51AkjTUHixNPuAIZd3P
         CeDPIn3ZbDczJFa3/EP4gTHwLP+6ljOZkwk6Ji57/E3fUta8rFsJtM+WmRZDHx1nauWp
         FI5pPk5R76gKe9zsdTNn99xAZY3uAEflwZth54hqXRjBvMMWMvF2eznH2tUBkWpddKH5
         MIP9Ixdw82zQY9ZyXfHtMqhQHCd/bzzqYYteFEEWMa35on381zYfsB4qu7sG3TBexTdn
         bd4AmqtORevEYs+D+9rjfD85I/47jXA6ENkGkACaeVGo0CiGGVIBRmyh2CZmpAnexNjR
         icOg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0OEfMN7OTibR4RSv33bBSA99eQr0CSUai1wdFcpGwk0=;
        b=lBj/SJNH1wZCxH3ROPb8JyfmOlc7B6iZJlndbF3xyh4UWu7YHMd9RWJUq9GVu/4hbZ
         2BYRk6s51bFkfsfgmc1sgCWxDJCIWkF0SVaiScTy4YDxbKhXK4HN4jTymrZ8tkKHE27a
         3AzhbyTRy+YgOf+Gm5Dn7bUaZ1YsmVxD+fOwvFCrbakGjN2Ewk7Il9GgwNiop9bDLkBf
         r5dkiecdxi/skCanvIL+VlQaOexLRFIahPgorQqFwxJ0ye2qrUD75uhleZFDlUwzKHf/
         5fPHKQtFNWdXY9El855cpHyZMHyZE3kP7kEyvcXN25hTwvzy8tJ23BeEyfEv4+dbv5sl
         PU4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to
         :reply-to:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0OEfMN7OTibR4RSv33bBSA99eQr0CSUai1wdFcpGwk0=;
        b=EZC8u1eW/syANQB++lwYN/gjXBh+rEoDUzRqxyrypmnTouhIZVDGtzuy2eN2njRGCE
         zrMTh17nkTWurHbeYhkRjAwMHX8u2r64aqpGy0TkvhoCHqPIvPpdN9jtqCPVL8ykvBN1
         LjFNNNjzdZ41F0xiSjlwXGcHHWQBNeg+Yj444mBC/HK/Wo5stSho8qNRKAwh/wx3S/mH
         OHGrgkTNnt78BroRVjkcrK4EiS3oi5QmBR9unbtYQCLjowkYmgGKQThOFy5AqHNEHlDU
         7evfGPRmba3SAdMvwvWRUqXbUNYJXkzUiYijmBXDQ7QLTNZxRpviK+4FD3z70Laxpx6Y
         /8Kg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532RANDuvtIxuFpD+HEk5olZnBG8CbtNqy2/Ac6PjaCPhsl4GcRZ
	8/BmQPU34m7BNRillnVCSxM=
X-Google-Smtp-Source: ABdhPJyOM/EgEv2dgEkJKpIb3Qkp9PaIAu4e2NX+/AQKcT5qkaiT82h6l4OZjrAOyRbha/G0WzUhyg==
X-Received: by 2002:a9f:2a82:: with SMTP id z2mr4402733uai.71.1590582957952;
        Wed, 27 May 2020 05:35:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fe91:: with SMTP id b17ls1517498vsr.5.gmail; Wed, 27 May
 2020 05:35:57 -0700 (PDT)
X-Received: by 2002:a67:f34d:: with SMTP id p13mr4979002vsm.164.1590582957632;
        Wed, 27 May 2020 05:35:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590582957; cv=none;
        d=google.com; s=arc-20160816;
        b=l4Os9UlCcXit4OjJRWdRCJLja5cW4ptmGj6tG0bW/Iz8Kfdl7HFBYY0TGv4OraofTs
         4w3I1ukIbP4I6sNjGRZyDhBOLnEQLFe/2g2b8LBZln54RYBeMp9poUhmn9fhSeCjYVUv
         z1suHPF/6tvIRaT8JtxhIVrC6P0RUZydiq/wUzXu4gfvgJz8plkxAdHx/ifFpzNfSl2S
         uaooNi8oz2kbUNqFuClfF/gYDbehNiSivz7RKQCzELEPusIo2xwwP8Mqsz4GaCpZTfVJ
         08FnTB1Mx1mmsmwqWSXP1deqSzr735dCBfs0n3OrOHel6YbFTFgBxjifuJlNhLvw7OtS
         zKvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:reply-to:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dLQVgKcEwQ1FC39ZISDlNHseQJ/tL1cI3JXpTq890qw=;
        b=gPTv3InFTUeukvB40RfpkDpksJwbpC6yUr2yfu65g6ipIG/LamZyPEiFmV/cgBm0s0
         jitnX/62NVrZJrJid59i8bVXu5fdXJg+lv6N8vzvh8QV21wcZdQY984TV8hqTTXt4gHA
         uNkvPtyf2EUBbqxxNDO3wr1jOn/zqpMfXZG8ugS9B2F+96M3ChmVLiLxjyHOr5eZmdKj
         ghoKeVpUXjc3cYf9ecYL7aUhquq2oVoW8U5dvQ+Mbpx/J4LF7d9OAcdRG9VHKX+CQc/z
         SReLRyM0Gvwfxrlp4Z6iRXxkOSyCHFOouJSzGPss//HMZ+iF0wyYdt6Oygo1mFavF2g1
         1qFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=pvb7cjeW;
       spf=pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x142.google.com (mail-il1-x142.google.com. [2607:f8b0:4864:20::142])
        by gmr-mx.google.com with ESMTPS id j5si302421vkl.3.2020.05.27.05.35.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 05:35:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) client-ip=2607:f8b0:4864:20::142;
Received: by mail-il1-x142.google.com with SMTP id 17so23817305ilj.3;
        Wed, 27 May 2020 05:35:57 -0700 (PDT)
X-Received: by 2002:a92:898e:: with SMTP id w14mr5303714ilk.212.1590582957180;
 Wed, 27 May 2020 05:35:57 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com> <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
In-Reply-To: <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
Reply-To: sedat.dilek@gmail.com
From: Sedat Dilek <sedat.dilek@gmail.com>
Date: Wed, 27 May 2020 14:35:49 +0200
Message-ID: <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: Arnd Bergmann <arnd@arndb.de>
Cc: Marco Elver <elver@google.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sedat.dilek@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=pvb7cjeW;       spf=pass
 (google.com: domain of sedat.dilek@gmail.com designates 2607:f8b0:4864:20::142
 as permitted sender) smtp.mailfrom=sedat.dilek@gmail.com;       dmarc=pass
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

On Wed, May 27, 2020 at 2:31 PM Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Wed, May 27, 2020 at 1:36 PM Sedat Dilek <sedat.dilek@gmail.com> wrote:
> > On Wed, May 27, 2020 at 1:27 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > On Wed, May 27, 2020 at 12:33 PM Marco Elver <elver@google.com> wrote:
> > >
> > > This gives us back 80% of the performance drop on clang, and 50%
> > > of the drop I saw with gcc, compared to current mainline.
> > >
> > > Tested-by: Arnd Bergmann <arnd@arndb.de>
> > >
> >
> > Hi Arnd,
> >
> > with "mainline" you mean Linux-next aka Linux v5.8 - not v5.7?
>
> I meant v5.7.
>
> > I have not seen __unqual_scalar_typeof(x) in compiler_types.h in Linux v5.7.
> >
> > Is there a speedup benefit also for Linux v5.7?
> > Which patches do I need?
>
> v5.7-rc is the baseline and is the fastest I currently see. On certain files,
> I saw an intermittent 10x slowdown that was already fixed earlier, now
> linux-next
> is more like 2x slowdown for me and 1.2x with this patch on top, so we're
> almost back to the speed of linux-5.7.
>

Which clang version did you use - and have you set KCSAN kconfigs -
AFAICS this needs clang-11?

- Sedat -

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BicZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg%40mail.gmail.com.
