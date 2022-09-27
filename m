Return-Path: <kasan-dev+bncBCF5XGNWYQBRBUGZZGMQMGQEYBM3WJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id B53275EB8A2
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 05:24:01 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id t6-20020a25b706000000b006b38040b6f7sf7426637ybj.6
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 20:24:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664249040; cv=pass;
        d=google.com; s=arc-20160816;
        b=fh7YKwEA61IL0jbAXipT5TRYgrYhwHSHkdWn3DeRJ60HnF+V0vFIy/g7H6yanPhzKS
         VM+qbFyWTNehRhi+40WB3uVVQrn3tBqOy/JFQ1B/R+D+9HQDDKjkCOi6Fwc5Q271anJt
         tTPCjqHumZ3tpVTiXuDgpVYm8oMTPF15yef8VD1yh4fz02J0z6GlJo7wL4g0My4zEA9S
         m2DVeKhsulI+J1DivX/U1sAGX28G4sBz+OYN3dWHYR6QtTRaQEmQHJQG6wCyEgBzmpFi
         NIO03N0Gi1dCm0K12z/i8u3rTv1XeVK+Go+Qxugep6/VRkY/kCes3r70qY/lKlz+5miF
         9tNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OmHgsu8Epr94zfejuYF/APlfuW5rUAdgemmmzuCy+qo=;
        b=YOjoKBWkj1jk2vgJvGJNe8g/gUjBY+kfVvduCVS3p2vEqpsELbbqsXtLYpECTnKh+/
         mTxhCq6/sw2iqYBlCpl3Ts/6EcNYFQ9oVhoQmVcRWsOs2RYoxMs3b+/IlFxsnHIBv84E
         gYpYdA5ElFY8OEpEohe+MPiJiCSufcYJLcPrYRuSQqeBzyeAjdMgukC+DgobH7mzNUMB
         jsWJLwp+ckeAnOuh/xF0QSVG7odIvJl0V+J70e3DlSCyWf/JjE/Z+f5ASddVbmpVd5s8
         WxF0v6yFpj5n5dvZ0UwK5UWDcWzKmIGKSVvPKWYoOAjXKYppMs9A96JN1ESBMQPHViO/
         g48A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=j18dmHaA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=OmHgsu8Epr94zfejuYF/APlfuW5rUAdgemmmzuCy+qo=;
        b=GHjG1693nHeE1RDGkkxjeLpMYlD4Wj0/lcvdr0DpUqgzVXEU42KO9pbTWyxCL/GWPI
         MnBibYYU9phiIR5dv0u82tIJ8KBKKmXIBgCN2nz767hCfjf6kE3MPCyhFwyKqDJWfWwX
         f6Wf42nixvbLra4cmGKNR43stxJb83hEeei9npO8ofK32x79mIXwOUAaENPlTMnIGtna
         kf7LYMYIULHuPkdAvIoTZy3aQVS5lGsimGWGIf58sWj0Fwu/PcPlsmw13fu/SIQ2MQNu
         bIM6IdmW52pm8YFWE2iCSQH7LX1L6+rkKabv8+9dIFhCMBLIghKVe5TlKTTQTb+dOfXJ
         ueuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=OmHgsu8Epr94zfejuYF/APlfuW5rUAdgemmmzuCy+qo=;
        b=2K1M4jyKgXSdazrYn7DclfaNFoZUf6ihdeeDxcZBeUm4pnwkdi8uUYrbNX/WryVbvi
         SeaRy6UCwjrhlfRw35ngh6BLz23YW7hC6rs3XwoR6eVUldmdWsfD/LO+csAA+0kob/i9
         ZK6YvzrzJngekXPyigOwHwpHTFg0EufU+0y1bG8xSA1pKoXVZAy5d2ItSn3yjBilf7zY
         sGTpMncCiKGqmK76dTU8hMxYQqPdvh+wGC72CH+nYMpSJRDYJbOkFDWnYjR8jpbRVejz
         /MXu/1jFQ/rPmaxphbeqp1/OcjTPjhznA5PyDICOYNJgJ31zwZZ5SGpICE20prP3P+ij
         l0EQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2MRGhdO9dUp/30sVPOR3B0rKxxvM4lv+FgD/sb4u6k/8WYG+Ox
	1B0ieOSIPkDJpRo2xLXPQpc=
X-Google-Smtp-Source: AMsMyM5C0x2WTVxWHWtFzmDqEEc0hEy9fpMxZV6dFADPGxz3dFRi+0Jhhe16vHtYW4FRAOl1nEUFgQ==
X-Received: by 2002:a81:6602:0:b0:345:3b42:fd53 with SMTP id a2-20020a816602000000b003453b42fd53mr22873300ywc.4.1664249040324;
        Mon, 26 Sep 2022 20:24:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ab73:0:b0:6b3:cd3c:e457 with SMTP id u106-20020a25ab73000000b006b3cd3ce457ls864652ybi.9.-pod-prod-gmail;
 Mon, 26 Sep 2022 20:23:59 -0700 (PDT)
X-Received: by 2002:a05:6902:45:b0:6ae:ce15:a08d with SMTP id m5-20020a056902004500b006aece15a08dmr23264045ybh.380.1664249039733;
        Mon, 26 Sep 2022 20:23:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664249039; cv=none;
        d=google.com; s=arc-20160816;
        b=0O0Fp+HvQlP4PJgOJaAag3eWcyIg6alV4p1AwwnDg9CSOAiMxBpIdqsuQaKQe9tMoW
         njmd9iAhUUC8/3z2TVm+HIFZWxbnJ5eX5hLnB66+9Re02sWUK8+uvj5m6pFMp69J6XAV
         6C8yNiI7ttCdjx9oCc0FxRtm3HgTK4Z8CtcWQJOmt7Sm6980GiK5VK6QDtR/FKU1dktl
         wO2lCT+PvgshQgYZnRLB8H5QyGP0qKNvp80b0KdU+Dt9gFpUbLjZ3q69g7AGJSM8Dfnx
         QGH/XcU2dmLXaSt3eLZQ/59URGeZMRBaJ9MeKH+7d+HlTtTxSOFJokeJTnehwHVAlgW+
         NVUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6qnuVXzVK4CfrmKG46F4wOs5bWFBYOAqV06iNpVAm8Q=;
        b=n4MKj8Aj1Uw8W1TNOsdfY97C+s2TkJIqyVDUoiPhfe5AH8RmnTXl/0dSKEvgMxj77j
         UWrTKprVAQE08/4lvqFAvhUINFIn03CcTr4MLxQyXxTZNPb934v7WMFTdi4/giWQkPyt
         17vb+zLAIWvovad/eT/LRdFZ7xJBYQYUX8ovOZkh2w4wunHoGgNSMPzBIOLOmzGqVd1j
         D2DfVDQN85K1c/oE3B3S5Qhye+0US8fMuV8Ir67OC13I+Nk1gJIffGAkr0vRMF/wx3Ww
         Y+QNNlw/3VGiZkuwRPfQA8dXoIhvP0CO+pasa32awHOOh7e35niaZGlu25DtRi3RxkDT
         x2Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=j18dmHaA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id j68-20020a253c47000000b006b0256821a4si18502yba.2.2022.09.26.20.23.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 20:23:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id w20so7920695ply.12
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 20:23:59 -0700 (PDT)
X-Received: by 2002:a17:903:18d:b0:178:28d1:4a13 with SMTP id z13-20020a170903018d00b0017828d14a13mr25170592plg.160.1664249039360;
        Mon, 26 Sep 2022 20:23:59 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id lt21-20020a17090b355500b002002f9eb8c4sm238643pjb.12.2022.09.26.20.23.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Sep 2022 20:23:58 -0700 (PDT)
Date: Mon, 26 Sep 2022 20:23:57 -0700
From: Kees Cook <keescook@chromium.org>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] random: split initialization into early arch step and
 later non-arch step
Message-ID: <202209262017.D751DDC38F@keescook>
References: <20220926160332.1473462-1-Jason@zx2c4.com>
 <202209261105.9C6AEEEE1@keescook>
 <CAHmME9pFDzyKJd5ixyB9E05jkZvHShFimbiQsGTcdQO1E5R0QQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHmME9pFDzyKJd5ixyB9E05jkZvHShFimbiQsGTcdQO1E5R0QQ@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=j18dmHaA;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62e
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Sep 26, 2022 at 08:52:39PM +0200, Jason A. Donenfeld wrote:
> On Mon, Sep 26, 2022 at 8:22 PM Kees Cook <keescook@chromium.org> wrote:
> > Can find a way to get efi_get_random_bytes() in here too? (As a separate
> > patch.) I don't see where that actually happens anywhere currently,
> > and we should have it available at this point in the boot, yes?
> 
> No, absolutely not. That is not how EFI works. EFI gets its seed to
> random.c much earlier by way of add_bootloader_randomness().

Ah! Okay, so, yes, it _does_ get entropy in there, just via a path I
didn't see?

> 
> > > -             entropy[0] = random_get_entropy();
> > > -             _mix_pool_bytes(entropy, sizeof(*entropy));
> > >               arch_bits -= sizeof(*entropy) * 8;
> > >               ++i;
> > >       }
> > > -     _mix_pool_bytes(&now, sizeof(now));
> > > -     _mix_pool_bytes(utsname(), sizeof(*(utsname())));
> >
> > Hm, can't we keep utsname in the early half by using init_utsname() ?
> 
> Yes, we could maybe *change* to using init_utsname if we wanted. That
> seems kind of different though. So I'd prefer that to be a different
> patch, which would require looking at the interaction with early
> hostname setting and such. If you want to do that work, I'd certainly
> welcome the patch.

Er, isn't that _WAY_ later? Like, hostname isn't set until sysctls up
and running, etc. I haven't actually verified 100% but it looks like
current->utsname is exactly init_utsname currently.

But if not, I guess it could just get added in both places. I'd be nice
to keep kernel version as part of the pre-time-keeping entropy stuffing.

> > Was there a reason kfence_init() was happening before time_init()?
> 
> Historically there was, I think, because random_init() used to make
> weird allocations. But that's been gone for a while. At this point
> it's a mistake, and removing it allows me to do this:
> 
> https://groups.google.com/g/kasan-dev/c/jhExcSv_Pj4

Cool. Is that true for all the -stable releases this is aimed at?

Anyway, just to repeat before: yay! I really like seeing this split up.
:)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202209262017.D751DDC38F%40keescook.
