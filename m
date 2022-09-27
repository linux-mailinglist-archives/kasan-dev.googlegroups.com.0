Return-Path: <kasan-dev+bncBCLI747UVAFRBUUFZOMQMGQEBOCYLUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 5486F5EBEA4
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 11:30:59 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id n7-20020a1c2707000000b003a638356355sf5293397wmn.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 02:30:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664271059; cv=pass;
        d=google.com; s=arc-20160816;
        b=C5k+Bc7/J3QUwOyTMVKC81yNSxxOIW5Y7sdSBvf0Pu0X8k79L+ktz+erYD2YxAHJSY
         cWaDv5fHwMFPASbBlGxbmCGJLzGBIvLeC2L5AdYqg+ZfhUOp+QrnOtim0MGRhkFKihSy
         9PESaip34hxBglpXYJ/LMaQ9JAEuqybsNBrVFs9DX70F0rIigquOk1RfglNUPT/sU09s
         YvClXum9MT1+SbWgpRnymvCOQ2KhjWhrswbggx/BQ5kaqFC0a8W326Kv+Ma51vrL40q5
         WFZg0fW9j3MqUwkmjkSxM7n+DGXYkR5+gWOVIfB6lRzDL4sTMS3nS3skBebB7fxfHbUZ
         1pYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=PYHkM2LVncFwAweVnhLvMHQiL/QwH2SgHhg07BMi9wc=;
        b=HtRhsivRgXI2Qjm1eUFeZpR8LGyZ+PSTidAcBhI4q0/7yHCpGF0FuoVQI9MXzjBPgX
         4YaGFSU6g4pGVvR+wCakWtzCPlWtmH+1HcW9RxheyVcKai5YCWJ2OrqVqQw0QUHbXbWE
         IAv/Q54u8EdJ4JiBtexWOiUxpoWiJQ5aKdTVjL4BhcCpl0z9+MTpbwAln5reWNtUTuWZ
         zLpKNypztU+nRlXo8XgpIBO3nliqmRk635LNcJ7M7lKJ7/WQHRkbmrSaaA7bZzaYLI5Y
         /pOTYdhPn/CyiFpDqKr4En7vqREHZTWWIqf7SOLPz7Nsoj/cgMZvsjihxnN4C2Mqoma1
         P1+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=kF3gAJq9;
       spf=pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=PYHkM2LVncFwAweVnhLvMHQiL/QwH2SgHhg07BMi9wc=;
        b=p+xVNPGiR12GxOsf7uV76IodmsRjrd4bqgocSpghJDYaXPWIJ46d7VyLRtAv818ThL
         QfCqBckuWkxvvxmWiL7xwd9xofmgsAkWd2HdifH7kl5qvSe7Y0mxFqt1s8nzPOL2Ss30
         Uh0f1aKVLBMp7kWWy0wSRk1nASGrkM+3kc/ndFAlV4s+KC/xqGSGPyIps7eodX/xu4jY
         KBTO6BiHm2qOPN1V/H3d/uSprjbyt7WuzE7JWXIKjUSgcSvDAt5c4hZQpgv6whB/2cth
         70Ngn5kCG83MKQKzif4e9TFIQ4iGftCb17ZxhFWSBt9qprkjaleSf0QuY1OZUBYMuSpM
         JgPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=PYHkM2LVncFwAweVnhLvMHQiL/QwH2SgHhg07BMi9wc=;
        b=36nNRJzU19g6IQ2UwAhroRGfltxJPGK5vVW/X1guOeqhZKJsZ5U2YBDcIAOeZjvyZE
         YfbLED51G700vFDt23x1YXz+3bp2tjHcxsqmOZWxOfKweORDY+tm87ldxZG5KU8oXn3N
         ligyZCkitr1yqbozo/yUIaKC+D874Z2AfHDLnn256dbLKoUmqSkGlYfVGuQnepmNo+Ne
         Mhs8l41akWiS67AVNV0nfJwbQ1rHyAy+DN860Uko8fT5SCn77C8dsydAL+Crl5f3Pxrv
         NZMHV9lDxe6P55tANVHhhjwJ84/L24U0CjD2BGByj3DZ+3xO9hQ8KUNUtc44aziaLdpR
         0Hog==
X-Gm-Message-State: ACrzQf1XJKqF/aCU6VCz32cjxCbqDGiv5BZi2Z0fVzivgviYkf+SDKPn
	WiR8fObdvEhkZ2yuvoKB1NE=
X-Google-Smtp-Source: AMsMyM5Gwvp5pOPZKrKIPRHE9VqXwLE4lfyESgX8M9+F+ZZ36OY67djtuz+NlyKwFGfh1tk9nqXnZA==
X-Received: by 2002:a5d:608d:0:b0:228:d095:4a15 with SMTP id w13-20020a5d608d000000b00228d0954a15mr16221157wrt.499.1664271059026;
        Tue, 27 Sep 2022 02:30:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:4b11:0:b0:3a5:24fe:28ff with SMTP id y17-20020a1c4b11000000b003a524fe28ffls640850wma.0.-pod-control-gmail;
 Tue, 27 Sep 2022 02:30:58 -0700 (PDT)
X-Received: by 2002:a05:600c:22c7:b0:3b4:92ba:ff99 with SMTP id 7-20020a05600c22c700b003b492baff99mr1986320wmg.190.1664271057968;
        Tue, 27 Sep 2022 02:30:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664271057; cv=none;
        d=google.com; s=arc-20160816;
        b=rAyzlhwX7f4JqYLV0yL4XYo3unVHo26sewRwy+deHq+VMn19Ge3l+oWjo6UivLyjwi
         lobuBXlLFvimiploV4OiW/omBylFRvkgNdwzXH9q0QW2A5ni/QQYbPD9qFrzv0WCPsIj
         Z2b+8ADyr6TVzi0NUXnEAULkHRuhUQPf9BSyWraHPZBh/oy+282shS7yVf8hYk0oBTrZ
         TXdo8kSAfsCM85CYXgswE82/lxLq74KZ+eUTYZyO0VWacqP0Ta1i/J1sRYI6mhpTPDye
         NVRchtNLIHNSFMoc/wyrzh02VBcMGYClSxW/Lg4F78aUOJkKeHYOOTrIgkjRnP43WrTW
         ovOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=dOsRsI2SbqGs1hFMWbK9H3koFhP046bcsz2N8V78ieg=;
        b=VxcDY0FPkA3nQccfM+oEBJOQLS1nBa+12R1YZq1mgpjJXp9DA5Pr6GS9ZdZbC6eX6H
         /ftb8yrQPZptgVGk5ojofR8TnfqgpEzYLb19UlAW1QVzEKtFGJVbgG0yoeMKa+UCgrgh
         Fc9yQ7Cw5jN4W59hjnorbxk92KAmaPYKT85FEEtACU7no+zPfYuu/pDVmYkX73rMxKLe
         bubY3JAUiuKcWL0uI+wHp9iA5KG4/6Fu1QkT5j8S/v7lzN8sbhsyVjkLYm7aarGqYGT/
         m4mlcsNImhlM/VEQx3W6sbW40+7L9KOTIJlW920QoydM3BR8PtupFWEwGIAgDFTCAcFS
         k3Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=kF3gAJq9;
       spf=pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id l21-20020a1ced15000000b003a83f11cec0si52970wmh.2.2022.09.27.02.30.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Sep 2022 02:30:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 97E66B81ACE;
	Tue, 27 Sep 2022 09:30:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3E0F0C433D6;
	Tue, 27 Sep 2022 09:30:55 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id bd881e4f (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Tue, 27 Sep 2022 09:30:53 +0000 (UTC)
Date: Tue, 27 Sep 2022 11:30:51 +0200
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] random: split initialization into early arch step and
 later non-arch step
Message-ID: <YzLCy2rVIBebeMrB@zx2c4.com>
References: <20220926160332.1473462-1-Jason@zx2c4.com>
 <202209261105.9C6AEEEE1@keescook>
 <CAHmME9pFDzyKJd5ixyB9E05jkZvHShFimbiQsGTcdQO1E5R0QQ@mail.gmail.com>
 <202209262017.D751DDC38F@keescook>
 <CAHmME9qTf+aDmBen2dFXPmbDGkn1E4=oXqqeBRiguLCo7K9EhQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAHmME9qTf+aDmBen2dFXPmbDGkn1E4=oXqqeBRiguLCo7K9EhQ@mail.gmail.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=kF3gAJq9;       spf=pass
 (google.com: domain of srs0=o2zr=z6=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=O2ZR=Z6=zx2c4.com=Jason@kernel.org";
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

On Tue, Sep 27, 2022 at 10:34:16AM +0200, Jason A. Donenfeld wrote:
> > > Yes, we could maybe *change* to using init_utsname if we wanted. That
> > > seems kind of different though. So I'd prefer that to be a different
> > > patch, which would require looking at the interaction with early
> > > hostname setting and such. If you want to do that work, I'd certainly
> > > welcome the patch.
> >
> > Er, isn't that _WAY_ later? Like, hostname isn't set until sysctls up
> > and running, etc. I haven't actually verified 100% but it looks like
> > current->utsname is exactly init_utsname currently.
> 
> If init_utsname()==utsname() and all is fine, can you please send a
> patch atop random.git adjusting that and explaining why? I would
> happily take such a patch. If your suspicion is correct, it would make
> a most welcome improvement.

https://lore.kernel.org/lkml/20220927092920.1559685-1-Jason@zx2c4.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YzLCy2rVIBebeMrB%40zx2c4.com.
