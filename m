Return-Path: <kasan-dev+bncBCWZBO5OREMRBMPJZKMQMGQEVXI5CUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 452A95EBD4A
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:30:42 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id xc12-20020a170907074c00b007416699ea14sf3411277ejb.19
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 01:30:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664267441; cv=pass;
        d=google.com; s=arc-20160816;
        b=glWpfzf60+ZmIcFGuygWkJcr0Yi6jzlJXhJpN8gSlW1sLUGhbaFvOHqE5iwQZFT0VE
         VGvVGypHc6/ws+ecjBy6J3ytL2MmdLW2PeRPIfavG+suoTA+jKEMGjTrInjS2hv4s/Uy
         O4EM4aVtLfCVxVHTHdEfpOhjpxPFXC1tOfiVT8rFzqRDYqvec9L7pLgCK9ki/DAKQ5w4
         0uf+Hj6NZFewKM+Sf6iS+VLPw7ZYcms/ZO/Yi3M8tBFCNpz4en+dg2EqTDy/qhzEuGin
         JFdizMzmF7hxtAFDKZOcwbAHsDiN57F66HN0GLa9XyEAsNNDIFLgQ54nxYac9RVdBPTo
         Ddsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=m6c/n9D/ei+FrUz5yZyoT9fWj8XC4c1c58orE5T9itY=;
        b=cfLITTT5GP7cf72MZShwvlK91i5LfpQnLMsqTANzHrOD6cXzxM+jdFypdYL9RDCbbo
         V1NKmPgQ91OUbIPiWK8QkWkV5oTO/XUSf9h3l14J0x1DM1T0da74IM3NM0vWQ52nqJnE
         wVjtxa8pG5KxccsbxJd3prAwEH5j1MS9wqDXcAEvhusONic4a2piMppQ22o5NAf5Iiv+
         fjcjjxitXSyZmboIA12MW2bMWcMchYywKusCE09KnRVN0l3YjG/lKrkXb0WVtF6LrZJH
         BmG+QK2wLQH4OjHwDEL25QOfgdx5xYz5W5s4mcN5a52qnM/1pMDybjaMF6LIzAAnA3UB
         yL4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 136.243.71.142 is neither permitted nor denied by best guess record for domain of linux@dominikbrodowski.net) smtp.mailfrom=linux@dominikbrodowski.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=m6c/n9D/ei+FrUz5yZyoT9fWj8XC4c1c58orE5T9itY=;
        b=GY6Jnq7GKlKiTwvLkjREZ/Ppe0vZG4Hx96MyT89bMxL7TL7iwaj/B0iuTewznOKeNu
         HX8nw+gznM2jk4k56gBwDTnjP5mcHi4aol3X85GfuXqD398NHBIG3wysDbsnjF/UiE1k
         5yOcqMsqiVDBBw9VAXYvSxUOMM7sJon0+K+IYAfLmT+vxjnAaJzi3cynaiIyfyBowoBT
         gfo4iP37fRfZ82fEnSKphwBsZlIRElQ6niGYC9L2Vi0e29svTPnBsfoOkg9Nlzyqu3YR
         qrevLcYUonmHqMCtVORlNO2Q/dMhRSJk+hMTz40JogGbeUYx3hiek01HcZS/1RES94fd
         CVaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=m6c/n9D/ei+FrUz5yZyoT9fWj8XC4c1c58orE5T9itY=;
        b=alkA4q/C9oJf/L9SnfZ6+YQLzAr5FGBm7bldp49EW1Zt7tROGU4TYhOOQxG35NTZKd
         wWQEtAvvPUHqp4GxmWD+UeoTF4nLPjNzWIrYEaW8MFwgpf5B8+ap7EwHIEzicHzucMRv
         YM8L4lJaZ3VG4yGZLKPlDzrkb5LAQvK5G+gWBEA7/F5dUXz9WyDFCAmwQ2kIyLfkCSQ0
         DDaVtFfVFhVUCxUzc1w8JOOWt+DEUZUilmzHlIYaTh8DYsER0QZ1oplIUDSK55oUEHDM
         fXC5erOCQP9ZlslzmVWhkfUTiY7vvfWfjLLpEMxtlCH9sN59P4q8T7GRDu7CJeu0Hywe
         MXVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2AupnM32s1JF5oH3x99W2MKUJWmtiLESifjgw6bnVwLMiIM8bq
	zgBFikmdapHkLxBGUf0ut3U=
X-Google-Smtp-Source: AMsMyM7C3I2YxZcV0RdEK6EZ/Zaf3jgOxxCxkQNQQlhFK8PyT7/LPm7OPbLm49vvwuQwMUml3BjDgw==
X-Received: by 2002:a17:906:cc10:b0:77b:df70:efd2 with SMTP id ml16-20020a170906cc1000b0077bdf70efd2mr22471489ejb.590.1664267441523;
        Tue, 27 Sep 2022 01:30:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:27ca:b0:43d:b3c4:cd21 with SMTP id
 c10-20020a05640227ca00b0043db3c4cd21ls1022110ede.2.-pod-prod-gmail; Tue, 27
 Sep 2022 01:30:40 -0700 (PDT)
X-Received: by 2002:aa7:c693:0:b0:456:f97b:8884 with SMTP id n19-20020aa7c693000000b00456f97b8884mr15765650edq.341.1664267440369;
        Tue, 27 Sep 2022 01:30:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664267440; cv=none;
        d=google.com; s=arc-20160816;
        b=BBYeREhYIP2Q+tHRT6GgGdwmHtjTJRHR6unGJqQuyawkvcfXMv4ce9gcEB1ffYekA4
         3Xh9xZnb6zpkD4vSpxC0ZIcssLuh4ssOkHzSDFU9RDww+D7uaEnHhEeS2uM3z79DgrUx
         5PmpZubajliFObsdJJiX4NUvbuu7fCBYtrDTnQrs6crPeiu0t5+ahosFv845uEet+Ktk
         Q/y1Xea1aYahNtUDZPPQaluEOSKpLLQMISbAUXw+IT+tmGpqEEasSEqnDKDO/BkfLEBs
         LZrynLne5rfZNJm0PFEhZIPImm/ZpR1xsvzUen5SIT8wsJEn7N3lY4MLyyKVIhhgQhIO
         NNpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=HQirqvyR11JUrFWBiZTkWi870cgxn67Y2EKlmqXlH+c=;
        b=UmugCesXS2p5hLB/ag1OAZcbjfbw+LhO13k6DPKNEPAE2LkUhWPEovk5tRW7oJDzNU
         mgVlUjlWr+IKbL0qhpR0KKKrw0gwX4cQ1QrI8u9VovVWYmyCY6RI5Kq+Q0KuuiL0Qw7j
         7uIMx8cbfqbmOOEiiiMR3zuP7CjP9DmtDmctZFiPy5/PHJb9cPU0YiJeKyrQpS/5jWtM
         zAjPiOySx2a1I1J8PIj3Nsy0+Myf9iCgul7hzofJvefeesK6oOfIx41zgJIL3CpXOdSS
         meY/zeQ4XFy+4B4GeRYi1BJYGfIpC8M4RrVxbrzR8KhTTOLpl0Wy0/Zq7MaHzbmjkNYc
         IEyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 136.243.71.142 is neither permitted nor denied by best guess record for domain of linux@dominikbrodowski.net) smtp.mailfrom=linux@dominikbrodowski.net
Received: from isilmar-4.linta.de (isilmar-4.linta.de. [136.243.71.142])
        by gmr-mx.google.com with ESMTPS id by12-20020a0564021b0c00b004542c733389si42669edb.5.2022.09.27.01.30.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Sep 2022 01:30:40 -0700 (PDT)
Received-SPF: neutral (google.com: 136.243.71.142 is neither permitted nor denied by best guess record for domain of linux@dominikbrodowski.net) client-ip=136.243.71.142;
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
X-isilmar-external: YES
Received: from owl.dominikbrodowski.net (owl.brodo.linta [10.2.0.111])
	by isilmar-4.linta.de (Postfix) with ESMTPSA id 38C19201335;
	Tue, 27 Sep 2022 08:30:39 +0000 (UTC)
Received: by owl.dominikbrodowski.net (Postfix, from userid 1000)
	id 8A4968052E; Tue, 27 Sep 2022 10:30:22 +0200 (CEST)
Date: Tue, 27 Sep 2022 10:30:22 +0200
From: Dominik Brodowski <linux@dominikbrodowski.net>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, Kees Cook <keescook@chromium.org>,
	Andrew Morton <akpm@linux-foundation.org>, stable@vger.kernel.org
Subject: Re: [PATCH v2 1/2] random: split initialization into early step and
 later step
Message-ID: <YzK0ntZJvMzFzui0@owl.dominikbrodowski.net>
References: <20220926213130.1508261-1-Jason@zx2c4.com>
 <YzKZnkwCi0UwY/4Q@owl.dominikbrodowski.net>
 <CAHmME9oGkjAxvoBvWMBRSjFmKLzOdzfcQAB4q3P869BsySSfNg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHmME9oGkjAxvoBvWMBRSjFmKLzOdzfcQAB4q3P869BsySSfNg@mail.gmail.com>
X-Original-Sender: linux@dominikbrodowski.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 136.243.71.142 is neither permitted nor denied by best guess
 record for domain of linux@dominikbrodowski.net) smtp.mailfrom=linux@dominikbrodowski.net
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

Am Tue, Sep 27, 2022 at 10:28:11AM +0200 schrieb Jason A. Donenfeld:
> On Tue, Sep 27, 2022 at 8:35 AM Dominik Brodowski
> <linux@dominikbrodowski.net> wrote:
> > >  #if defined(LATENT_ENTROPY_PLUGIN)
> > >       static const u8 compiletime_seed[BLAKE2S_BLOCK_SIZE] __initconst __latent_entropy;
> > > @@ -803,34 +798,46 @@ int __init random_init(const char *command_line)
> > >                       i += longs;
> > >                       continue;
> > >               }
> > > -             entropy[0] = random_get_entropy();
> > > -             _mix_pool_bytes(entropy, sizeof(*entropy));
> > >               arch_bits -= sizeof(*entropy) * 8;
> > >               ++i;
> > >       }
> >
> >
> > Previously, random_get_entropy() was mixed into the pool ARRAY_SIZE(entropy)
> > times.
> >
> > > +/*
> > > + * This is called a little bit after the prior function, and now there is
> > > + * access to timestamps counters. Interrupts are not yet enabled.
> > > + */
> > > +void __init random_init(void)
> > > +{
> > > +     unsigned long entropy = random_get_entropy();
> > > +     ktime_t now = ktime_get_real();
> > > +
> > > +     _mix_pool_bytes(utsname(), sizeof(*(utsname())));
> >
> > But now, it's only mixed into the pool once. Is this change on purpose?
> 
> Yea, it is. I don't think it's really doing much of use. Before we did
> it because it was convenient -- because we simply could. But in
> reality mostly what we care about is capturing when it gets to that
> point in the execution. For jitter, the actual jitter function
> (try_to_generate_entropy()) is better here.
> 
> However, before feeling too sad about it, remember that
> extract_entropy() is still filling a block with rdtsc when rdrand
> fails, the same way as this function was. So it's still in there
> anyway.

With that explanation on the record (I think it's important to make such
subtle changes explicit),

	Reviewed-by: Dominik Brodowski <linux@dominikbrodowski.net>

Thanks,
	Dominik

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzK0ntZJvMzFzui0%40owl.dominikbrodowski.net.
