Return-Path: <kasan-dev+bncBCLI747UVAFRBCPKY6MQMGQEZGFCXPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5487B5EB08B
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 20:52:59 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id e17-20020a056122023100b003a1e6de5bf9sf2580656vko.17
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 11:52:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664218378; cv=pass;
        d=google.com; s=arc-20160816;
        b=pH/miVGAc9AlS+4I+XAU4OAl4Rdrw2Q0Bc1W8Lb5LKp92LIItD2IxWU4Z3UyfZE8Lm
         pOXx1A9T5m4Mql3Ugd9tRhHmjWtsLv8D0AFng40grQJ3hxIezKoE/7XJHQaOtMimT3gC
         ASJ34THMEbhok1v/cEWIqghKWvR9i+Qz56UPg+zB/QTuly1CBDqcTZjsjzQLb8XVIpqg
         6f2zSKxBu9dJy3bhV0W2Elm/Psya4gNaV6+9LJCoWWLN106YNpd1WoT/P71BLMw6CvLB
         +BWVVKwr8uB8Oj4KlOVckfN6+lIuvnB0GxHzUg8YZVeA68VOgg0ahLjwMvpnxX8dqzaw
         EQhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3zuCixQD1AaYfmEtFmoUMEqoJe6zC1JQPVS+x76quLo=;
        b=sX85+g80RqDPB/rKhnM8B11V+TJvwqTJ/T00aW7GNMmDBJmxjEJh4QXiuaPwdS2OaW
         11EJFbB8xwn+wzNvxfaRDH8xlnMYiQ3TnxsKnTIC/dtFyBJhg+j6lbIwM3iqXY72U9xn
         qef61RZxpPJsOyQPoiI1pO51xZ99CPkMe5sEMjrb9J1ekG7QD/DtC3oGUbTWfXTFBAXO
         tYJuBbxQD1nuibzP9MgrHoPfgZAVEV51e9oyMh/cn3gntvzuhKIqK9LAmqCs2Y1iJcFW
         TQPjuEcUamLVc7et0wkpQye8r/v+BeS9u2weG3kExhMBCam8IG1mlbrLMP2QvlytW8ww
         46Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=GHUYsDZj;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=3zuCixQD1AaYfmEtFmoUMEqoJe6zC1JQPVS+x76quLo=;
        b=jWgQpT+hLW+QHRluNe/jqPKRQoBkE4KykGrzEikN1usYNBqcgn9YDltfWhHL43gw6j
         n9ppi12tcpaJAxp7RLi2Psa75bynYJkbHUwbHFtU6C+xE80mCoSk8HGYEKoqbVCP+zXX
         eLzOW3csyB2/sMVP51OC0s4q8s3eC1PFQ+3ukWgmfpRpmQpOIx9JF8yCQMuiNSpedKRf
         pr9DXzK/QTpAfx+OBXbUfcqm+V8EbnVlPwHHdxxemUpKRBa2kNQghGRVHmHfGnOifH/g
         iFW0m3iMTzXfHWxclhLuidVq1BYMcD4/THS4zKb8c5xLbFmeBubxHceKVnJQu0F3MIl4
         iFtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=3zuCixQD1AaYfmEtFmoUMEqoJe6zC1JQPVS+x76quLo=;
        b=K/IhkmEPIeKUq7VUWnDdifr9z2lNB7rspdFTcwZ3Div80J/wtbEUL+e2mnbNDkTjJ1
         wXlxwA7zmcy0+Ii6xFuhkgXhD5uu+6PcOqvxW3iGwAPVHdtftkT6Q2v20ZHlcCl9evtD
         3G+iVT/3usJ2kRHlMVAMc1LdTlHWszdPpHEDaIJ7p3mYWpcvwC2OSPEOJJ2dKchN2qeO
         NkPjr2stzSk1r1n5UOMmkl/jffwZ8Bw+nEgVJF/rKOB6ECHVNfiLPkxSS9PEip3FykHU
         WyE5qfXqYeZTvI+K2LkMbxw5QjwLsXvsX0v422ZoOpEU4/YNwd2dz0/GaQZ3LPCnQIit
         xhWw==
X-Gm-Message-State: ACrzQf03VPo/HOWfICHYAorhvt0wfofWVNddbo7dZWdfVaI2zaWsEuSs
	cGlGQ71kQH+WuQpgVoyaj3I=
X-Google-Smtp-Source: AMsMyM5IRHZJPNVxead7lX4irUbfug3MuQImK6z9jXHgbuD/amX0AWn6uFiajL27rnZSGaaBTl6IMw==
X-Received: by 2002:a1f:f8cd:0:b0:3a2:9470:1ec with SMTP id w196-20020a1ff8cd000000b003a2947001ecmr9915360vkh.40.1664218377992;
        Mon, 26 Sep 2022 11:52:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c993:0:b0:3a5:8fbd:ded2 with SMTP id y19-20020a67c993000000b003a58fbdded2ls24776vsk.1.-pod-prod-gmail;
 Mon, 26 Sep 2022 11:52:57 -0700 (PDT)
X-Received: by 2002:a67:d085:0:b0:398:c9b4:3804 with SMTP id s5-20020a67d085000000b00398c9b43804mr9389039vsi.79.1664218377414;
        Mon, 26 Sep 2022 11:52:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664218377; cv=none;
        d=google.com; s=arc-20160816;
        b=dC1/DCjNOfQLQhJDoaGv/0qGvtiIJZh0w3QusknuDSOFBex0uUTBe8/kzU7Azax/3e
         i7Rqmo946B1OPNawv8xZBUH8UClqQ1H4uBGxm5IynUIj9oz+VHPKIuf+jIe2nDSvaq7B
         YZawN7r7PXtrbEZSIY2m5EOMUW/vy5HKiSApQ1ezH4AI7IPDXf/pb00FYwsHH6CAOVs+
         XZqLtsCyPj3dBnG4LgfkhVgCwdOdB/F05JeN62zcHrzk21mJ0zTQcCByvHaRc9Yt+87b
         lqs+iQzr6GVc2Cgqpov//EcZTUvDergZW97fYBVOhi+75AtbrL1HhKw8ewygc6umzzph
         Ng5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pDXoUOQlmNgJmVAlYuuj5yi+ly/HlT4KdcY9eEm5eBQ=;
        b=XfNrM1gcGUGHeymopCeLMdzON0JsCT12y5zcvKX1yH5njaDfaL6jSP/1JOw4pHl7ix
         DXE+cpAcWs7yiAH/KU4UbA2nhk5fWBj7nNtByMU3mDVCiDK/L69Dbsu3MC0M/c33ab2B
         XA2x0uP2fL/xt9Upn004ldRv6FHX9rWTx7GJWe4QrWEz9chSKGA6qohWNnMOwxZSmDKJ
         tsuH4kCialiaGc2BiF3yacOTOYCCqWkYPGFAead0Tjbo2tIPsV0E6ibscabRsxwR9iW8
         hx6T4Xi4AVq/XG0ojW2sf1jfQspblzws73BSCk0/xk7cIGsBKYszpZ7hDbGU7hWMjTJt
         98Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=GHUYsDZj;
       spf=pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id o14-20020a1f280e000000b003a4a4b2a98dsi291156vko.3.2022.09.26.11.52.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 26 Sep 2022 11:52:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D9B65611CA
	for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 18:52:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 077ECC433D6
	for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 18:52:55 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 6ba5633a (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Mon, 26 Sep 2022 18:52:51 +0000 (UTC)
Received: by mail-vk1-f177.google.com with SMTP id s12so3851265vkn.11
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 11:52:51 -0700 (PDT)
X-Received: by 2002:a1f:1b45:0:b0:3a7:ba13:11ce with SMTP id
 b66-20020a1f1b45000000b003a7ba1311cemr3104747vkb.3.1664218370625; Mon, 26 Sep
 2022 11:52:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220926160332.1473462-1-Jason@zx2c4.com> <202209261105.9C6AEEEE1@keescook>
In-Reply-To: <202209261105.9C6AEEEE1@keescook>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Sep 2022 20:52:39 +0200
X-Gmail-Original-Message-ID: <CAHmME9pFDzyKJd5ixyB9E05jkZvHShFimbiQsGTcdQO1E5R0QQ@mail.gmail.com>
Message-ID: <CAHmME9pFDzyKJd5ixyB9E05jkZvHShFimbiQsGTcdQO1E5R0QQ@mail.gmail.com>
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
 header.i=@zx2c4.com header.s=20210105 header.b=GHUYsDZj;       spf=pass
 (google.com: domain of srs0=wzr3=z5=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=WzR3=Z5=zx2c4.com=Jason@kernel.org";
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

On Mon, Sep 26, 2022 at 8:22 PM Kees Cook <keescook@chromium.org> wrote:
> Can find a way to get efi_get_random_bytes() in here too? (As a separate
> patch.) I don't see where that actually happens anywhere currently,
> and we should have it available at this point in the boot, yes?

No, absolutely not. That is not how EFI works. EFI gets its seed to
random.c much earlier by way of add_bootloader_randomness().

> > -             entropy[0] = random_get_entropy();
> > -             _mix_pool_bytes(entropy, sizeof(*entropy));
> >               arch_bits -= sizeof(*entropy) * 8;
> >               ++i;
> >       }
> > -     _mix_pool_bytes(&now, sizeof(now));
> > -     _mix_pool_bytes(utsname(), sizeof(*(utsname())));
>
> Hm, can't we keep utsname in the early half by using init_utsname() ?

Yes, we could maybe *change* to using init_utsname if we wanted. That
seems kind of different though. So I'd prefer that to be a different
patch, which would require looking at the interaction with early
hostname setting and such. If you want to do that work, I'd certainly
welcome the patch.

> > @@ -976,6 +976,9 @@ asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
> >               parse_args("Setting extra init args", extra_init_args,
> >                          NULL, 0, -1, -1, NULL, set_init_arg);
> >
> > +     /* Call before any memory or allocators are initialized */
>
> Maybe for greater clarity:
>
>         /* Pre-time-keeping entropy collection before allocator init. */

Will do.

>
> > +     random_init_early(command_line);
> > +
> >       /*
> >        * These use large bootmem allocations and must precede
> >        * kmem_cache_init()
> > @@ -1035,17 +1038,13 @@ asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
> >       hrtimers_init();
> >       softirq_init();
> >       timekeeping_init();
> > -     kfence_init();
> >       time_init();
>
> Was there a reason kfence_init() was happening before time_init()?

Historically there was, I think, because random_init() used to make
weird allocations. But that's been gone for a while. At this point
it's a mistake, and removing it allows me to do this:

https://groups.google.com/g/kasan-dev/c/jhExcSv_Pj4

>
> >
> > -     /*
> > -      * For best initial stack canary entropy, prepare it after:
> > -      * - setup_arch() for any UEFI RNG entropy and boot cmdline access
> > -      * - timekeeping_init() for ktime entropy used in random_init()
> > -      * - time_init() for making random_get_entropy() work on some platforms
> > -      * - random_init() to initialize the RNG from from early entropy sources
> > -      */
> > -     random_init(command_line);
> > +     /* This must be after timekeeping is initialized */
> > +     random_init();
> > +
> > +     /* These make use of the initialized randomness */
>
> I'd clarify this more:
>
>         /* These make use of the fully initialized randomness entropy. */

Okay will do.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9pFDzyKJd5ixyB9E05jkZvHShFimbiQsGTcdQO1E5R0QQ%40mail.gmail.com.
