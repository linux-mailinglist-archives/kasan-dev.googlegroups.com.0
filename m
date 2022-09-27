Return-Path: <kasan-dev+bncBCLI747UVAFRBJPOZKMQMGQECDWMVFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id AB5A95EBD9C
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:41:10 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id b16-20020a056402279000b0044f1102e6e2sf7399686ede.20
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 01:41:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664268070; cv=pass;
        d=google.com; s=arc-20160816;
        b=luARZMRs5ynQgf1C7Yi3sj5KQ3AsZW1SN5SUfl19yY4ZPR3zH0tw5n8F1u2ccnCYVW
         urW3ThAsGDeht0EDaACmvVBRTKexqe0cIeVWLSWrndAN9LBslQBe21upr63P7FK3Jde5
         wrUcUg4Xyi1+1ahPgxoxLrxkH3MkKxvOxurW3ubeQWwDn1yLFVoeHCOO5mcToxq18jmB
         0o+nAo+mFS5G+AWclAKC8QV+bckbkH0KF7leKWoRMyFB16alX3IYjhvpZaojAQHT7L4Z
         wyCKnSGmS8xltKaLDkV6vvG2WBwQXrPir6QuM02EAhYLDsoGj1U2udvHhPJYuZ9BFzvs
         V3RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NUtHEFUM1oe0YZq9jUVNG6Cf8HoXV6gU1VMb0B4VuWY=;
        b=WGl3lY1le0CPq+a5axkiVlERXZPQaf/Q5v+CtsqxtrT4/ajjttPok2nlj39Z+aShCy
         5vbIjSaiFHIoj29A0LcXr/XTfGy517rsIrdNDOQO5+4tJiG3wlsLayL0ww+DNRlxcMwb
         ciu8ojgmVnVN4cBugnVLWv78ZdnB1PfRnFhX6oEX6iru6/ugtjleucUCTmS6ZJwNBtBO
         cioiwRh9T6ELKowRVzdu/aSoZoWFFfLu3BqkLmPfi368bZDIA0GFzcw4sbbx9k7DPNDa
         3RjDugoXbIY+G7OhLuL3sOp85uu9kK6nj210B+K58OJYOPmb47lOWdQyx3Bb3a0tjCym
         JDQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=U2RFQizA;
       spf=pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=NUtHEFUM1oe0YZq9jUVNG6Cf8HoXV6gU1VMb0B4VuWY=;
        b=KX4zKXSl+K7DCSX5lQfJBnrMlBV0szS52y4DL+c65OwWz/kxOUv07rjU7rk/WacHxs
         XJSl0tF80CceTc0rFQH3EtxUi+rF4EtHypg5ak5u37zHHr/khU9X9VThpYgGl8UJyY82
         7IoLHsi27aPtDDJwFB8lhl9F8QRNb0SgWlBaSfBHAG0m6v8AWEjOILJ1RuzWzK1lYbFP
         jm9gmvuVbL4ObNrs/11VGIAAtGaqVnst9SloZEw2UdpUKWz4F6yWXEhr2C+89/z9C55g
         wyrgebA9tCfGOE3DPi2LBcxBSHFefc7z/3pEyWUZDKkHfTghu6GG3N8iyUqUCiWDXAlW
         3bEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=NUtHEFUM1oe0YZq9jUVNG6Cf8HoXV6gU1VMb0B4VuWY=;
        b=d/0dmK01lTRSt9YwRjhKK8MCHEIe9GxpupNdVqn9ffLbzR8rkDHg0+tiOvH4X7yITP
         mDvGufh4Ng/RC5pE9owPZKcEYmPI5fISc3EDvDL/hOH1dcbdrqx9rLcZICuX1unBCcgc
         P1Fc6i3T9RM5wqyqlKl04K8BGwjniCAymSton76mQJsPwIsbuoVUUT/2j6YrgZqkEVan
         oIsewjh7i3bWkYW268BeTlITH1iXPvoA0c5S5xxy2W4jKpBTu+G6MOOKpw9O3KTBaYaJ
         wEiJehjbivIRX9tuODmx+NlR94/fwbCDHzCGxhSTVrJVwcbQ70BCLgOUrju8t78xvfCB
         k7zQ==
X-Gm-Message-State: ACrzQf1TOm1Hn5GHmHZqT2lggY3ZWywvksa57CyKJvSrDZwIPGKlKQQE
	18MDb3jr2UZwVaCU6jzKqlI=
X-Google-Smtp-Source: AMsMyM6BJPyuVUcCh4u8EzurQnmXTqCDt6sb9fNupI3ffoy68s5Q2rr0mgCzOvr9s1+bOhp7fyAPhQ==
X-Received: by 2002:a17:907:96ab:b0:782:2f88:cf29 with SMTP id hd43-20020a17090796ab00b007822f88cf29mr22067844ejc.72.1664268069888;
        Tue, 27 Sep 2022 01:41:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2690:b0:457:99eb:cba9 with SMTP id
 w16-20020a056402269000b0045799ebcba9ls1057114edd.0.-pod-prod-gmail; Tue, 27
 Sep 2022 01:41:08 -0700 (PDT)
X-Received: by 2002:a05:6402:703:b0:456:53e9:9b70 with SMTP id w3-20020a056402070300b0045653e99b70mr21601635edx.24.1664268068763;
        Tue, 27 Sep 2022 01:41:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664268068; cv=none;
        d=google.com; s=arc-20160816;
        b=W2Yu0jgcrh19tPE7FNZnACsC/pRO/qjzHRPidEzcmUDZcUs6PgkdEr0QI/Xn7d99fR
         oQsu4DnpxPw7ZQquRd2s5/+F9HHnGdWtWT7Hf551fq6UKdiRGz0o1sS206m+pfgWwAZu
         zuZ/rvI1WUyY7YKIRoJargj65ZDA/xDDag+TouVNDcVMRgDmTVvkJeKNceUj54hDD/+C
         3S/In+otyqs4mttjk79usFMDzRklW0tZn8kNCVVWTWiG7oprmGImj617qpnEyc037src
         OktvIjuLwjiXno/Wn6HqoumD67QUkwc4AjjFaY0QSsN/V/F8YREJHB8bEaIm2vybPno8
         k99g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IV/Em9oY+NQiUPjmtckttX54KTlCyU8xGN0JLMqvDIc=;
        b=TldmyWynX87blRL9oYqjKC5vOogA/CrAKo/z1+flClMPEqKzxIo5iO/eq9doErBulR
         u+5fDnLmbYYql6LBAxGmTte0KNU0YK/nTCvoKAPQf8BmbWBnz72aOFDSd67JUr7MUAZQ
         OTQJIcCSLRmmm3KZBXo3tjxg2I8jOyrAva35zfqwrz/UMQ/qosB814Q0nqwEd9fQy4fJ
         y6X5YkkiYCWk5q/bnA8nOm2dPRI7OYxuLe1hPmxHE+zTsw6VkUOUOLxvHaqghwuNIqF7
         2zapPZ3UNZOCO3MGHyvP59gEYifTisHDnJs07V6wzaAXXGiM3r1tinToypPQP+uas3Li
         VF1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=U2RFQizA;
       spf=pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id t11-20020aa7d4cb000000b0045757c7cb91si36306edr.4.2022.09.27.01.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Sep 2022 01:41:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 86493B81A60
	for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 08:41:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 108F2C433D6
	for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 08:41:06 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id f222571c (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Tue, 27 Sep 2022 08:41:04 +0000 (UTC)
Received: by mail-ua1-f48.google.com with SMTP id y20so3298012uao.8
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 01:41:03 -0700 (PDT)
X-Received: by 2002:a9f:3562:0:b0:3d0:ad99:b875 with SMTP id
 o89-20020a9f3562000000b003d0ad99b875mr1217071uao.102.1664268062673; Tue, 27
 Sep 2022 01:41:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220926213130.1508261-1-Jason@zx2c4.com> <YzKZnkwCi0UwY/4Q@owl.dominikbrodowski.net>
 <CAHmME9oGkjAxvoBvWMBRSjFmKLzOdzfcQAB4q3P869BsySSfNg@mail.gmail.com> <YzK0ntZJvMzFzui0@owl.dominikbrodowski.net>
In-Reply-To: <YzK0ntZJvMzFzui0@owl.dominikbrodowski.net>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Sep 2022 10:40:51 +0200
X-Gmail-Original-Message-ID: <CAHmME9q3w1XHyS5QpyW79xK9xjnZmzyBr-Pk3QOsp=mJ_Loauw@mail.gmail.com>
Message-ID: <CAHmME9q3w1XHyS5QpyW79xK9xjnZmzyBr-Pk3QOsp=mJ_Loauw@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] random: split initialization into early step and
 later step
To: Dominik Brodowski <linux@dominikbrodowski.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>, 
	Andrew Morton <akpm@linux-foundation.org>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=U2RFQizA;       spf=pass
 (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
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

On Tue, Sep 27, 2022 at 10:30 AM Dominik Brodowski
<linux@dominikbrodowski.net> wrote:
>
> Am Tue, Sep 27, 2022 at 10:28:11AM +0200 schrieb Jason A. Donenfeld:
> > On Tue, Sep 27, 2022 at 8:35 AM Dominik Brodowski
> > <linux@dominikbrodowski.net> wrote:
> > > >  #if defined(LATENT_ENTROPY_PLUGIN)
> > > >       static const u8 compiletime_seed[BLAKE2S_BLOCK_SIZE] __initconst __latent_entropy;
> > > > @@ -803,34 +798,46 @@ int __init random_init(const char *command_line)
> > > >                       i += longs;
> > > >                       continue;
> > > >               }
> > > > -             entropy[0] = random_get_entropy();
> > > > -             _mix_pool_bytes(entropy, sizeof(*entropy));
> > > >               arch_bits -= sizeof(*entropy) * 8;
> > > >               ++i;
> > > >       }
> > >
> > >
> > > Previously, random_get_entropy() was mixed into the pool ARRAY_SIZE(entropy)
> > > times.
> > >
> > > > +/*
> > > > + * This is called a little bit after the prior function, and now there is
> > > > + * access to timestamps counters. Interrupts are not yet enabled.
> > > > + */
> > > > +void __init random_init(void)
> > > > +{
> > > > +     unsigned long entropy = random_get_entropy();
> > > > +     ktime_t now = ktime_get_real();
> > > > +
> > > > +     _mix_pool_bytes(utsname(), sizeof(*(utsname())));
> > >
> > > But now, it's only mixed into the pool once. Is this change on purpose?
> >
> > Yea, it is. I don't think it's really doing much of use. Before we did
> > it because it was convenient -- because we simply could. But in
> > reality mostly what we care about is capturing when it gets to that
> > point in the execution. For jitter, the actual jitter function
> > (try_to_generate_entropy()) is better here.
> >
> > However, before feeling too sad about it, remember that
> > extract_entropy() is still filling a block with rdtsc when rdrand
> > fails, the same way as this function was. So it's still in there
> > anyway.
>
> With that explanation on the record (I think it's important to make such
> subtle changes explicit),
>
>         Reviewed-by: Dominik Brodowski <linux@dominikbrodowski.net>

I'll augment the commit message to note this too. Thanks for the review.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9q3w1XHyS5QpyW79xK9xjnZmzyBr-Pk3QOsp%3DmJ_Loauw%40mail.gmail.com.
