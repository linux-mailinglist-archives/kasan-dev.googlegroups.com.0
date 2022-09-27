Return-Path: <kasan-dev+bncBCLI747UVAFRBGHLZKMQMGQEUAXRXEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B01D85EBD61
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:34:33 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id g189-20020a25dbc6000000b006b53e647b7esf7976833ybf.14
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 01:34:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664267672; cv=pass;
        d=google.com; s=arc-20160816;
        b=GCeKwzi7A/GvD40uoGI9pzekE9FWk5DsOgcA2ESzntHfzfEAOwq0jykeWpj9QfAzKA
         oyTLZeO2YwmuTfultFnMr/64NKdqdc8eDf+LI8Qg9aQbfO7NHQY498RGBgx+XNC0FyVI
         lWdXDtKUVhXSydSGu0WDFBEJHUpDz6Oq4YtcT+m3IuZeH25bBlSTPXV2eicEKI1oL2lg
         TQmvY8nWD1hKVWSWhEtMbl2i+ssYsOkuHd/TtsT1wqtGeDNYF6jFd+W2xuzwpxmgwTKX
         w6uRMwvscQz6l5Ut4dUr6p60nmaPuneWcplrrzySDZ+00dYZgaAg4QdD3EF93kqlATZy
         vPRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2Ls00FgNqyTck/eaez2iF6g4K0FF+51eLYu66lnryAg=;
        b=auo8Wz4GV55kYAoQdDs2RyIwLrUS/exdCYvZJOm7xnGQFKwpeSSHxX2GTFI/fxh9EB
         sBQxgPoD31x8ZDNNyLY5uccRrcZEAqcLSM2qt0gOSNz8fiMJ8JdjNIKE1NVZe+DgHZbu
         n6WpxHmPxSVh8O9FBSzQaLJqJlQ4208gQsWHV3iqN7PdOgnDmJ4hs2pZiwoRTGjA1dCR
         TiXZTYKILXTBRL0yi43WnFJzg3zF1HsNcXaGBuMBZ6YTuXztNkuqzzB2ROlCDHIZU7kk
         AuUkteNmTdcVTjaAmyGzhKcGF2NcDjl7uO6F67xDh4xF803cjE0HPf7HUkZDdDb1wKJK
         Jw1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=BeuQ3Qnt;
       spf=pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=2Ls00FgNqyTck/eaez2iF6g4K0FF+51eLYu66lnryAg=;
        b=Gahzv35F8Z9rjjThdtcEiYqvwY2K/C7iw/hq4pHDXUhZncrljeHB4xSt31o5+1EUW7
         cEf7WY8WUgDg7ngFdE+2LMJCwASuVew/tF3DOjE5vdRAdhflX5BteeXbkNBcnLl0Nqeq
         Ks4oP4KnhdynkV3lrtBwW1kAFgWbp28+ZlnpuKd0A+WkXPX8biDnoGL5a3/aTz7eKdGL
         OEZkpGm12V88gOzJtZ+R9L2QG+pAzyxpGiXvu3xNXjbffy275m3f/YHisZ/sTG3HIwtd
         N1EWhi4H8WxR30OWSnKIuEmXTxuBgrv+bJe5dW/e6h3zOlEpCi2BJsYL3lZEM2HQw4UX
         2E3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=2Ls00FgNqyTck/eaez2iF6g4K0FF+51eLYu66lnryAg=;
        b=S3tHR3f2kp6dug3xPoiAEfq/YaHCiM90uKoLZCVDU7jHkyZ4jvc9o+JBicE0GBnUJa
         tEcHEoWmizrLi6I/O1xNGkkIvx6vj4pygWi+v1R/ktG61MU1xaC0W+njO7uuoUy+IMTd
         vYgB38uEdLgq+a1SU0ZZ6EuiPTx9RYaQDTN4+4Zz/D9Dsd/sn5hTmABZZEMzuSq2Au0u
         PFN42eA6SErPW3LTabQgkd3aazfiKH2Qx1D3Y/nRtSgH3XilaQE5HWVv3JEoKoHYZoTP
         /RjysRFt+yKdj7nN9okpiQNLm05h8WDHE7A7/FsKg7vC1ZN8FVhUxui1y0o9CglECkhP
         Ru9g==
X-Gm-Message-State: ACrzQf1IwMa7z7nQCDxcaZTUhyrwDU0msJXMCmgZIWBFzDuENBPftksr
	YU9W1xlsBt3IhF1kXjvslBE=
X-Google-Smtp-Source: AMsMyM7Vw/0UtWhY9vuEn4+UE6xQXqQ0bEIrDAaHOwkn5eLjrmwnxrO+baPO+Qkl2eyfuVWYM7pscg==
X-Received: by 2002:a81:4786:0:b0:348:9544:69a7 with SMTP id u128-20020a814786000000b00348954469a7mr24248450ywa.501.1664267672643;
        Tue, 27 Sep 2022 01:34:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:c307:0:b0:335:4596:25ac with SMTP id r7-20020a81c307000000b00335459625acls927554ywk.6.-pod-prod-gmail;
 Tue, 27 Sep 2022 01:34:32 -0700 (PDT)
X-Received: by 2002:a81:6a88:0:b0:345:a49e:16a with SMTP id f130-20020a816a88000000b00345a49e016amr24362192ywc.304.1664267672135;
        Tue, 27 Sep 2022 01:34:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664267672; cv=none;
        d=google.com; s=arc-20160816;
        b=aev30FM75BTI3jt2M7hWTn36dRnzfGHFsn5dlwwborigiF61C8/nKxIo2kE0w2YP+r
         BCGtnlWokiCfKNibEqBDDSBuo/maAe5NmBKio7wim44poam6vaWcmkl1Ym+7ojxJcYZp
         waVEa5tRQgR48Bw200xKfn4XvMpnjTJA0tHv6yAk/2opt1lTh5JRwzGF0TJZ8FaIOFWF
         xhFR9c+vftvLnXl6tGxKeYmKE0ETVU8oEprbWyi1n85/w9Iysj0hc+v5A6t21AiVyFRS
         XKqg+96pfCjty1efv40XrquNiPzZiSxo/9yvIJKqY4jETq8fbbW1bhMOazvMUXe7r2Zm
         3RHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ls3g6qEVoyxJ/LRppKHOZrlHupBiDmkmlvpmcbvCVBg=;
        b=akl0sThPnoiqD/Q9n8QLzKe0AmR9rSv9IZ2XrIpV1/uFLGp7clzQXeTVfiGyJOzGyP
         GxQMWrA97lMnSXbQJWSmB9/u8Iw+RDnxe98AWKDCHcvYoTGs9Rsgxwdp/QJZw2sK087C
         CBdvePIFEAcm5pbMMKacMjxrEOj/Pmo8zjpRML8HzzdQm3FD0glKS7ZBIudRoL1xdSZu
         TTwiJlg47MTaPM8TyqPuLg2OobCgzx8TOFz7oNDlnKzs4vJ3o2iQ8uhMb85JTXDRaYEt
         9KwmxV+wb64XH+VJZp5bDMNO8kZD5+tetaGhbsYvp2bgglLm4QY0ZU99aJAsBPBw4VQj
         51qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=BeuQ3Qnt;
       spf=pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x197-20020a25e0ce000000b006aaf1e08d7fsi54705ybg.3.2022.09.27.01.34.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Sep 2022 01:34:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BD555616FF
	for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 08:34:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D9F2CC433D7
	for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 08:34:30 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 657ee9a5 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Tue, 27 Sep 2022 08:34:28 +0000 (UTC)
Received: by mail-ua1-f51.google.com with SMTP id i17so3290934uaq.9
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 01:34:28 -0700 (PDT)
X-Received: by 2002:ab0:758a:0:b0:3af:2b2d:dae7 with SMTP id
 q10-20020ab0758a000000b003af2b2ddae7mr11153931uap.24.1664267667770; Tue, 27
 Sep 2022 01:34:27 -0700 (PDT)
MIME-Version: 1.0
References: <20220926160332.1473462-1-Jason@zx2c4.com> <202209261105.9C6AEEEE1@keescook>
 <CAHmME9pFDzyKJd5ixyB9E05jkZvHShFimbiQsGTcdQO1E5R0QQ@mail.gmail.com> <202209262017.D751DDC38F@keescook>
In-Reply-To: <202209262017.D751DDC38F@keescook>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Sep 2022 10:34:16 +0200
X-Gmail-Original-Message-ID: <CAHmME9qTf+aDmBen2dFXPmbDGkn1E4=oXqqeBRiguLCo7K9EhQ@mail.gmail.com>
Message-ID: <CAHmME9qTf+aDmBen2dFXPmbDGkn1E4=oXqqeBRiguLCo7K9EhQ@mail.gmail.com>
Subject: Re: [PATCH] random: split initialization into early arch step and
 later non-arch step
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	Ard Biesheuvel <ardb@kernel.org>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=BeuQ3Qnt;       spf=pass
 (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Tue, Sep 27, 2022 at 5:23 AM Kees Cook <keescook@chromium.org> wrote:
>
> On Mon, Sep 26, 2022 at 08:52:39PM +0200, Jason A. Donenfeld wrote:
> > On Mon, Sep 26, 2022 at 8:22 PM Kees Cook <keescook@chromium.org> wrote:
> > > Can find a way to get efi_get_random_bytes() in here too? (As a separate
> > > patch.) I don't see where that actually happens anywhere currently,
> > > and we should have it available at this point in the boot, yes?
> >
> > No, absolutely not. That is not how EFI works. EFI gets its seed to
> > random.c much earlier by way of add_bootloader_randomness().
>
> Ah! Okay, so, yes, it _does_ get entropy in there, just via a path I
> didn't see?

Yes.

> > Yes, we could maybe *change* to using init_utsname if we wanted. That
> > seems kind of different though. So I'd prefer that to be a different
> > patch, which would require looking at the interaction with early
> > hostname setting and such. If you want to do that work, I'd certainly
> > welcome the patch.
>
> Er, isn't that _WAY_ later? Like, hostname isn't set until sysctls up
> and running, etc. I haven't actually verified 100% but it looks like
> current->utsname is exactly init_utsname currently.

If init_utsname()==utsname() and all is fine, can you please send a
patch atop random.git adjusting that and explaining why? I would
happily take such a patch. If your suspicion is correct, it would make
a most welcome improvement.

> > > Was there a reason kfence_init() was happening before time_init()?
> >
> > Historically there was, I think, because random_init() used to make
> > weird allocations. But that's been gone for a while. At this point
> > it's a mistake, and removing it allows me to do this:
> >
> > https://groups.google.com/g/kasan-dev/c/jhExcSv_Pj4
>
> Cool. Is that true for all the -stable releases this is aimed at?

Yes.

Though I'll likely drop the stable@ tag for this, and instead visit
backporting it later in 6.1's cycle, or even after. There's no need to
rush it, and this is an area that has been historically temperamental.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9qTf%2BaDmBen2dFXPmbDGkn1E4%3DoXqqeBRiguLCo7K9EhQ%40mail.gmail.com.
