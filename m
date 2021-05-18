Return-Path: <kasan-dev+bncBCJZRXGY5YJBBLMXSGCQMGQEAP7AT7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 044E738830C
	for <lists+kasan-dev@lfdr.de>; Wed, 19 May 2021 01:20:15 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id f89-20020a9d2c620000b0290280d753a255sf7728519otb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 May 2021 16:20:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621380014; cv=pass;
        d=google.com; s=arc-20160816;
        b=dNSta0PumVfqmUdCHCXQR7eZ6AVtWeZkgmcEiYOWGKQnrI5dix1HL8nyayoeCG2zHh
         yScthz5LAEaIGWwLvoCjMRoYFNk4USxnccVNqwfMa0N76Wm3GpMskhTzIGK0IwTKbiuN
         e0kTsiYYCSk/d9g1ieO8/JchupPaBY56xLMkyHGkv/m0r9iV6+hkPGopR6JOtmUuX3OI
         U5FtVMR1/L5v3NbA4Ci5wXf8kGs47tnNSorRM1ngZ1cOdOpXt0zTmEwyyRyyq8l781oW
         TgH8s+RgmKRcjRePtfHXzMJk44ZOS1NyDipDayJ+qSZ8mayQrdT3IYkE75rhy8uL8xVh
         1OxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=yPikgt8Gy13+Trr8moH+g2TTF0O5pHwWR1EPIT3x7U0=;
        b=ON5bXfNENMWWvixMzGjB/6woMdcP+CKoI9VjIIdofgwn+V5c4LQhiHi0hTgYz3za03
         G48cZa4bemNxKkuBe7nuj9tn0Z/Ay7qjqQoB63MSOG2UY+27EcG78RM0a3TX2Iq9i3bP
         pl5n4bvSahPUY2VGIeTbvuGWb3+/UGV2TYpYjG6JUeCbriu3xT17YXjCiDQvO4Hh7Bl4
         xAuAz+7ixNB6lylFZ7hNP8IgXiDZmLlQ9uqePyBfBEOxw6ukFexeJF2f5f7nSuKUOq1V
         gE2QhJ5tIMTf41Myo2Sin5UxNgRz1KMCZj1zjFOn3KGbuC7WnUfY5nsC0T4fWGkasCLA
         VWqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LB8tvo8I;
       spf=pass (google.com: domain of srs0=vemi=kn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VemI=KN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yPikgt8Gy13+Trr8moH+g2TTF0O5pHwWR1EPIT3x7U0=;
        b=SGEgJoGTnYqlIBOLhQi7YHwTs67hTvciVu9zAmtyTbdcn2/nvj9/WbORVjQgOA+4XT
         ZalQJ5mzShPp2dJx6qRj1QgdAeQC0KVt+cUWE00KSWb0usd9LgsfwPSN+zWqbi1pVFAO
         F+xV6/865q+0hiEd2Xu3xs/0U7ssTbift5TYw05G7ZFY4fMclo7oI0GnhbZ3j/X9GYcK
         3FERT4To8We+en1p/S9eftaE2OmNrz6RDdYDZu3wVqTtjqGk1ARuFmwvqkSj4D3VBJ1K
         1PlMjTAbN8L4gRCRQCXGaduLB50bhz2XY4GqJ0wr9JxDdo84XJttHd7/p8Hzc6/yJvEy
         NtLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yPikgt8Gy13+Trr8moH+g2TTF0O5pHwWR1EPIT3x7U0=;
        b=ExrLhTjjuWTF9cTwCh32e3W07TTyiXl/Gc8K90AwPtarRW7omqYRpmzyyal607cVny
         0u2d83qsuQzTNSSMVnITOO9M3IgTVkQ4e9cVYSiUIa2G1dPeq44d8gAoYqzg2sOr7ma6
         PyeQql4yvKkkkxUCMnIp38HJq4vW9DWKbe2b1bJ7arh1GHEUa5R108RcnID/N2K/SVoV
         uT4vPRIo3JUHaCoRe9p70+nTcRyUJ5A74LOeQkpOT5BgNmzXhObTlL47ioc7YffXzqfR
         PAaVvtSM+E/w7zlQYxYAtjeLSdI8KdmA8JWa6y6SP6R+yU3F962f8PNy9RT5xy66JPYj
         xGEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cULF2u+C4RdHKEHkyHGMp+FN4By1SOGeR0CLP0MGeGBax/+4Z
	F29z4TCv7Md9OcN8jDxYzn8=
X-Google-Smtp-Source: ABdhPJxU39vJTbgaXR3thrTMF1PIUqb/cJ8MpvH3TwAFIhE/X/gussevRw/A43Al29wmuHQqtnJciQ==
X-Received: by 2002:a54:4694:: with SMTP id k20mr5847906oic.134.1621380013980;
        Tue, 18 May 2021 16:20:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:b443:: with SMTP id h3ls425461ooo.4.gmail; Tue, 18 May
 2021 16:20:13 -0700 (PDT)
X-Received: by 2002:a4a:8706:: with SMTP id z6mr6269081ooh.41.1621380013646;
        Tue, 18 May 2021 16:20:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621380013; cv=none;
        d=google.com; s=arc-20160816;
        b=eMH2DQW87dCKiq14+rEjkzLXLX9b0nK4aGC6XfMS0qkkh0V2BQVuIbpqjnHhcs3X6m
         wWR4qfCDC+qA5gfN2MS4NqK2WL+UkdlG9Gdu3FgLsLddvrx6X67ulRlKJbW5sHxQHioT
         h5aEhqKApFPQb4VCQnMLvVXfrwTBqg6Xydi9y6Qu4CjUqsQO8X/PqGz/wvQBTQanXZ55
         6E5bLTAAlOVxgqCD7t3jajFktCcOtoMjAsuxK8QRvxAkxrQX1XeNpw0qefZxwMR67ckb
         I5D/Bou/SxLzITcoAB6MdNdRYtu32OSWsCWX14X6nSh6VcEjeFSrAA3ROIP/7e1r7Xe9
         za5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=aLUI75Dpi4IC9OegSu4OzqJl6UaBUSAsSgBD8zulNCE=;
        b=iKWCrGb7spLV5PYyVhwWXl+51ffphmVrFb+GoBGppHzwKK99/gSuhsxm269juEXfpJ
         lqViBRyh6SPNIxNDcrVmmf6yx19eYmwvpDKz5ZQINQN61eqUlNklzxkvfRqLV7QdUN4I
         UxwMyHJkZdaYMwnK7pJloO8x8LMgFfI15SofGTifoIX0eSEJvXI/K1ZqiPHhCM92fHag
         jkfDJUWvT27IEtVXKlbGcpfNV8nzQjjGnlpH5a0wHD0Yaz1z6yYsfwt1Q/knId8BQqjp
         HCMpVJgZjjCEi9I52W0BnvgYhRRjTh4EqXa0AuYs8iwK5Kg9Nr2u/Ws/SIPAyLtpkhGo
         cKiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LB8tvo8I;
       spf=pass (google.com: domain of srs0=vemi=kn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VemI=KN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 88si1796471otx.3.2021.05.18.16.20.13
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 May 2021 16:20:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=vemi=kn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id EBB6061059;
	Tue, 18 May 2021 23:20:12 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B862D5C013C; Tue, 18 May 2021 16:20:12 -0700 (PDT)
Date: Tue, 18 May 2021 16:20:12 -0700
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
Message-ID: <20210518232012.GA2976391@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20210514140015.2944744-1-arnd@kernel.org>
 <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
 <20210514193657.GM975577@paulmck-ThinkPad-P17-Gen-1>
 <534d9b03-6fb2-627a-399d-36e7127e19ff@kernel.org>
 <20210514201808.GO975577@paulmck-ThinkPad-P17-Gen-1>
 <CAK8P3a3O=DPgsXZpBxz+cPEHAzGaW+64GBDM4BMzAZQ+5w6Dow@mail.gmail.com>
 <YJ8BS9fs5qrtQIzg@elver.google.com>
 <20210515005550.GQ975577@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210515005550.GQ975577@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LB8tvo8I;       spf=pass
 (google.com: domain of srs0=vemi=kn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VemI=KN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, May 14, 2021 at 05:55:50PM -0700, Paul E. McKenney wrote:
> On Sat, May 15, 2021 at 01:01:31AM +0200, Marco Elver wrote:
> > On Fri, May 14, 2021 at 11:16PM +0200, Arnd Bergmann wrote:
> > > On Fri, May 14, 2021 at 10:18 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > On Fri, May 14, 2021 at 01:11:05PM -0700, Nathan Chancellor wrote:
> > > 
> > > > > You can see my response to Marco here:
> > > > >
> > > > > https://lore.kernel.org/r/ad7fa126-f371-5a24-1d80-27fe8f655b05@kernel.org/
> > > > >
> > > > > Maybe some improved wording might look like
> > > > >
> > > > > clang with CONFIG_LTO_CLANG points out that an initcall function should
> > > > > return an 'int' due to the changes made to the initcall macros in commit
> > > > > 3578ad11f3fb ("init: lto: fix PREL32 relocations"):
> > > >
> > > > OK, so the naive reading was correct, thank you!
> > > >
> > > > > ...
> > > > >
> > > > > Arnd, do you have any objections?
> > > >
> > > > In the meantime, here is what I have.  Please let me know of any needed
> > > > updates.
> > > >
> > > 
> > > Looks good to me, thanks for the improvements!
> > 
> > FWIW, this prompted me to see if I can convince the compiler to complain
> > in all configs. The below is what I came up with and will send once the
> > fix here has landed. Need to check a few other config+arch combinations
> > (allyesconfig with gcc on x86_64 is good).
> 
> Cool!
> 
> If I have not sent the pull request for Arnd's fix by Wednesday, please
> remind me.

Except that I was slow getting Miguel Ojeda's Reviewed-by applied.
I need to wait for -next to incorporate this change (hopefully by
tomorrow, Pacific Time), and then test this.  With luck, I will send
this Thursday, Pacific Time.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210518232012.GA2976391%40paulmck-ThinkPad-P17-Gen-1.
