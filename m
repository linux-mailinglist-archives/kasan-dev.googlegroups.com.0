Return-Path: <kasan-dev+bncBCJZRXGY5YJBBF5Y7SCAMGQEUMRIDSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id DFA263814C3
	for <lists+kasan-dev@lfdr.de>; Sat, 15 May 2021 02:55:52 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id z12-20020a05620a08ccb02902ea1e4a963dsf502690qkz.13
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 17:55:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621040152; cv=pass;
        d=google.com; s=arc-20160816;
        b=fVViCedKllkGnq9PQ+db+CPBHdKKxzINVRfjf9euMFbDKuSa+yEnNLA6/hbiU8Cl0y
         7OnwHk6Hb/CQ1FRl+aKpc1xQZsowpX6/Ddc5rPv5T4EtqT44J7QW6zd295mtS2UFvNBg
         NbznIWIavCtzoEfCLsB+jhn37NDZFS5va8QUg0EpOlPWvgxGfpUT6pTTpf/L6PIp0/O1
         M8D0ynMpZZpChb+TLORpoihvtjmnPacNPpMUNwNwLlQvOFpVm6DjKQCyMXrp/dOK1x0x
         bLhi9OT8MKkMjhzMmhBmhDLkQpcZ4BIWuuaDzVv6lDQHV2lF2Ql23nfHa5df6r9PSg9E
         caCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=syUX6T7cKH+V+RaacIAaVQBUXnQVwqG6900zsF2Whuo=;
        b=J0dj/351MRujq8HZtMSPvh6hU4H3QtgE7/pFhOu80n6Tv0mGRPTHRJ0rXzuEv1eEtH
         gXvXCvt1YeXDX7u2k+t917OPJrkVCgTo8dMxywx0XW1kjs9PVW4RNwLHkaI54Aq5ED4R
         JHyawaG5x0AamIFTu6GGvy/0f1miVU92m5/nfP3zC94Fvlm2gAnYx+QkEzpzl/T+6H+a
         hjM+C1nZ2C2h3Q/xu5ewRdGiK3OTjQ6SLGzotwLY0SY0k9423+iN14rbyRmVdqRk0gpd
         ug8FlzjNVApC21aBooGXYsBZXj9jjjeyoDvoj5+x/ghH1upAcZmSs96qM36I03FNNGCL
         qj/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vE1zjlua;
       spf=pass (google.com: domain of srs0=ic6j=kk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ic6J=KK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=syUX6T7cKH+V+RaacIAaVQBUXnQVwqG6900zsF2Whuo=;
        b=UWUTLmuvE/fSReJ7H+eerYpYNjy4u7EvukYDjlwiVayNcGpQ4bcYCGmhnSVUnDiEos
         Nb7oORVWf6Z2zMotyBfyWtRGie8HrTFxwbYRRVHfTpeQL5TkK4gQS8k5x/SFDOApdz8k
         4KmiJaoYA/HjsOb96T3uqdSjas0UU5cE2effQDuw3NqnF26NZTQJkRJGo34TMtF5TRba
         VyDBYRNGARDIKfNk916mKtSt3Qe+GIkHov0sPEqykleLcYeVLHhl+cpugT45caLRIlVt
         8Dh1orJpooWz9+6ZTSAKwl4QqRWqQyzKn+xVgljm0hvvNZQ3BnQa3is6cInzWUQAHf1d
         eR+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=syUX6T7cKH+V+RaacIAaVQBUXnQVwqG6900zsF2Whuo=;
        b=PcbarBwKYpMh6xltQ/7NBf7YWmr3HzGJZwluZA9zCL1ebd6f/62EUURQRDeRaLbXCT
         00h1CCzhsS09xVCIkprHw7rvZHJF5T6O4wlowCS0pcuwRyZ+CIKrzqJZxepkUoRttQm1
         lTYtVJ6NGJUtvsyoKQgpmEusRT6zklv6cZKoXIJdIanXeP775YxkZtPyO6y9JWWFBQ7A
         PNDrN5/64P6bqJmqWr57Va1+BwxTl9PqpRYAaykzomRN59MNhnl74aQcE6vlbsx1pZNH
         y8RpZ8PdwwV4rpUEtUZ8LuoxCclld+0LiePVAGR0yDBekeK1FRnIUdVpCCdRAyRlI81O
         npEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IlpZRmMQ6bM5f1sfCelP6CUDaFXEw1kY1QGO2tVUSwrIklW+2
	8yz+DnNJyG/a9vjVmq8FB1k=
X-Google-Smtp-Source: ABdhPJy3PqqqoFGRRnHoi0Wx3Z+A6b9mtvl9t0K8mvmogsuxXLPIHzv7vsrh7Jf2qbGcTXzObHADHg==
X-Received: by 2002:a37:444a:: with SMTP id r71mr8779276qka.381.1621040151903;
        Fri, 14 May 2021 17:55:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:af04:: with SMTP id y4ls6946868qke.8.gmail; Fri, 14 May
 2021 17:55:51 -0700 (PDT)
X-Received: by 2002:a05:620a:14a5:: with SMTP id x5mr25012691qkj.143.1621040151499;
        Fri, 14 May 2021 17:55:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621040151; cv=none;
        d=google.com; s=arc-20160816;
        b=eHy2KO0PpZYACtYa2COUb4DnXUaIsqxK8jj80noOH2fo8NQ4CtvxzhBFihz01M5gZR
         xA23GN6vYj+N2QTbSBbVeY0vqwgYAacm7y6bFuAa+7xcmKra3wqP4y+kwrKglXrN2cka
         zmJbcgoryqg+UQ24kKDs0XhB4HL+/SuYA0pYd0/6q1VXsX6gjPdPT+B1I8wFh7jZymf/
         hH2uAG6MfDBSoNdCw14Ci8FxbJYjqFGw05g2efRZ3N62bh5IWfnIgAvAYdAikafzfaXA
         rkO003NZ1WIeMFUre9v9xcrD0xoU17YQZDAVwyHkU9vmHxLeTE2gow4fQDTflTcyDZ8s
         gp0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=MbMRH9aQGBcpuLiuC5ysrrHyZ2X4NOOtBqxMIQmcVZg=;
        b=nKYXpesl0ynmvVOXTsvp4J5DUbyNfVotoOefVRf7BHG+Tt8dhKjLHvId1BzM4h5k0V
         pGkpj5LwkTH3IfA0gEG/3Y2ZvJ3wDHOcHKAbrW+daQpkTaiaySD/9pG5St33uTgvHbwj
         d8PurLFtvOHaKVFwL+wXs2x36zWkWo04DdT9B2R8iCDUiANHSY0Z7BjGXwdkt0Dt5D+O
         qJOhkP4j4YcLC4QnK57g6YA57gSRYJdNMCirwaLDg5V06wHquPUBCuhTQzY6LqNXENAN
         C+5OSCj7uRsqnCDNaLyriCPHQfITa+sZaCI6uROUqiBcfBENTvu/kCCHVuevPpDgjn8K
         74zA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vE1zjlua;
       spf=pass (google.com: domain of srs0=ic6j=kk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ic6J=KK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 142si747315qko.4.2021.05.14.17.55.51
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 17:55:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ic6j=kk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6411B6135C;
	Sat, 15 May 2021 00:55:50 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 231B25C02A5; Fri, 14 May 2021 17:55:50 -0700 (PDT)
Date: Fri, 14 May 2021 17:55:50 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
Message-ID: <20210515005550.GQ975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210514140015.2944744-1-arnd@kernel.org>
 <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1>
 <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
 <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1>
 <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
 <YJ8BS9fs5qrtQIzg@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YJ8BS9fs5qrtQIzg@elver.google.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=vE1zjlua;       spf=pass
 (google.com: domain of srs0=ic6j=kk=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=ic6J=KK=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Sat, May 15, 2021 at 01:01:31AM +0200, Marco Elver wrote:
> On Fri, May 14, 2021 at 11:16PM +0200, Arnd Bergmann wrote:
> > On Fri, May 14, 2021 at 10:18 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > > On Fri, May 14, 2021 at 01:11:05PM -0700, Nathan Chancellor wrote:
> > 
> > > > You can see my response to Marco here:
> > > >
> > > > https://lore.kernel.org/r/ad7fa126-f371-5a24-1d80-27fe8f655b05@kernel.org/
> > > >
> > > > Maybe some improved wording might look like
> > > >
> > > > clang with CONFIG_LTO_CLANG points out that an initcall function should
> > > > return an 'int' due to the changes made to the initcall macros in commit
> > > > 3578ad11f3fb ("init: lto: fix PREL32 relocations"):
> > >
> > > OK, so the naive reading was correct, thank you!
> > >
> > > > ...
> > > >
> > > > Arnd, do you have any objections?
> > >
> > > In the meantime, here is what I have.  Please let me know of any needed
> > > updates.
> > >
> > 
> > Looks good to me, thanks for the improvements!
> 
> FWIW, this prompted me to see if I can convince the compiler to complain
> in all configs. The below is what I came up with and will send once the
> fix here has landed. Need to check a few other config+arch combinations
> (allyesconfig with gcc on x86_64 is good).

Cool!

If I have not sent the pull request for Arnd's fix by Wednesday, please
remind me.

							Thanx, Paul

> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> >From 96c1c4e9902e96485268909d5ea8f91b9595e187 Mon Sep 17 00:00:00 2001
> From: Marco Elver <elver@google.com>
> Date: Fri, 14 May 2021 21:08:50 +0200
> Subject: [PATCH] init: verify that function is initcall_t at compile-time
> 
> In the spirit of making it hard to misuse an interface, add a
> compile-time assertion in the CONFIG_HAVE_ARCH_PREL32_RELOCATIONS case
> to verify the initcall function matches initcall_t, because the inline
> asm bypasses any type-checking the compiler would otherwise do. This
> will help developers catch incorrect API use in all configurations.
> 
> A recent example of this is:
> https://lkml.kernel.org/r/20210514140015.2944744-1-arnd@kernel.org
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Arnd Bergmann <arnd@arndb.de>
> Cc: Joe Perches <joe@perches.com>
> Cc: Masahiro Yamada <masahiroy@kernel.org>
> Cc: Miguel Ojeda <ojeda@kernel.org>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: "Paul E. McKenney" <paulmck@kernel.org>
> ---
>  include/linux/init.h | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/init.h b/include/linux/init.h
> index 045ad1650ed1..d82b4b2e1d25 100644
> --- a/include/linux/init.h
> +++ b/include/linux/init.h
> @@ -242,7 +242,8 @@ extern bool initcall_debug;
>  	asm(".section	\"" __sec "\", \"a\"		\n"	\
>  	    __stringify(__name) ":			\n"	\
>  	    ".long	" __stringify(__stub) " - .	\n"	\
> -	    ".previous					\n");
> +	    ".previous					\n");	\
> +	static_assert(__same_type(initcall_t, &fn));
>  #else
>  #define ____define_initcall(fn, __unused, __name, __sec)	\
>  	static initcall_t __name __used 			\
> -- 
> 2.31.1.751.gd2f1c929bd-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210515005550.GQ975577%40paulmck-ThinkPad-P17-Gen-1.
