Return-Path: <kasan-dev+bncBDE6RCFOWIARB6XVSSHAMGQEIFMWBTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 6573547EAC3
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Dec 2021 04:14:03 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id x9-20020ab05789000000b002fa60bdf012sf3527612uaa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 19:14:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640315642; cv=pass;
        d=google.com; s=arc-20160816;
        b=CrZN1MEgas5gajGbVNhs1RT4OMWUkDYXHNfV5BldMNpYf1/EPsMZOiExGTFXGG8aRy
         WEV6fs3WA0qKIRcLrCzKfjlW73xsYvKbihVMhiU8I/dXzEFzFQjDCf1RjjcDhz9R/rRE
         KnvHxQ+L45LuYNHdsVdbNX7BuqQLe90dg3V86WIwoJwWaFdRNKceEBJWCEgZsoC08ua1
         UQjoVfZ3IAWXWR1aausH8UQkO8pvZlY81oMhVKXYaljMUy3ggeev+DlwVCRodzOFZiav
         5dhXUH1uhIvjvvnYMlu5v70KMKBOKLOp7An7o9+oOmqLlTJJrvcadotbiz6UF5CaSRwa
         w7yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=TRxEAlED9WkrBBIDsUzL9zZqslc8irNKsRYNCLGzaEc=;
        b=0a0dtum3jsq7Tc7woNt5w8+t14K8xulWHOyp6ZxoV3Kpi17uNRXfjr2lVi7OAZCzev
         dRkR+sCL1lI9IrPciQDZxD3y2D1vIX4LB0rEEy9aHNSlYcBThhR12y3JRODjK6SxgL1N
         yeY8QUqRmOnRxLBUBpOFbs5mt7gqTyEw8aBwCie+hDrKaub/R7TRmrBwJxnyfDWlbGSV
         Y3W06wFa8JS+Xasyg+R1McNhSKrtSGkXOoYPp3lIBCGnkm2m3dnDKiRWMSKFPEIALKkC
         zPEAmTTOLD25luSKCb0ppjIT0jx7M5zx5NbvcAg2if97LmOEVwgBRDEQDlggegAd7/1O
         oVvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=pskhFOzC;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TRxEAlED9WkrBBIDsUzL9zZqslc8irNKsRYNCLGzaEc=;
        b=o7gAiYdZDps7yb/BT3Fp22nnnG6lMXJ4YM2WSoEJqimZt2CFu7oD/NGZezitDpa6I4
         22ixo3aQVUGuJAi1LWBwHmY5Sv845QvMdIOkoje2UKFvQYirE8ouY2YcNRKb6KDLYinc
         gF2ImBL26Y72DUWUu6W0vOrbEPlRSL4GPqZXWNo00MRn0Cy4/HAyA8TvFH9Q1jkieLps
         HqQErgMVGrs//LSNVSLU69gT0bQlsYcNLBf3jDlmKdMPYan3Fmc/FV/wIC69MLASKfsO
         EGmAABTkVLoAHZYVoaPtRzU2YyaOPwHc1A4xRIE2AJ/LCJAL6Qh+yOcgQnFsnJtEKygF
         x2Ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TRxEAlED9WkrBBIDsUzL9zZqslc8irNKsRYNCLGzaEc=;
        b=zwVVwpxDZCmnXIKVF/TryZpuQfzuvpdE1xZoJqhUmQJgbZpcnqb58xd29BhMABFRsJ
         tA5b5s2DTMSafoXMu8M5gYtgG5co+GEXZ8EUgg6Ou7RvsBExSrty5Q0hghDaf998Q+qW
         /snl4/kkgG4/+G7//HUAEZ7LqjnQhobVchHomiOxV9CrzUeYnp/Djy0NJ0L4CCjHaqAr
         t0E/Yf+hCVBY6MtDPrky/z1Vd87P2KpUlNf6aZn2tQ8wrl3i8Rc4BX9clt8N7p4eALu7
         0j+qBx58GFTa23YEbQnYNpAWu0mBZMw9eJOW9r9KyCjB0GQJJag0EDkoYlZ23bvl/c8u
         AnvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JVReB+ss15uG5T1MbjU9yKsARz8VQ64as7b1/9ViP2kuVEfPW
	gcvuipHh9acPbSRA73nWBdk=
X-Google-Smtp-Source: ABdhPJywUahdmRIuq3/P9CwACQF+LDGeEMHm9RKtxWz6DvJEnLsPn3fVWN88t9391PH8lm0gdyPSxw==
X-Received: by 2002:ab0:6f49:: with SMTP id r9mr1640921uat.111.1640315642170;
        Thu, 23 Dec 2021 19:14:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:568a:: with SMTP id a10ls524439uab.6.gmail; Thu, 23 Dec
 2021 19:14:01 -0800 (PST)
X-Received: by 2002:ab0:20ad:: with SMTP id y13mr1623640ual.15.1640315641659;
        Thu, 23 Dec 2021 19:14:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640315641; cv=none;
        d=google.com; s=arc-20160816;
        b=0uex0m8CknJB+7xndwnWvy0myYoUZhUbFP/iITz0rQlQnzdSEgx7B1/+OYURl2thkQ
         KgP81BSfJI6BX/o65lDaGycDZP/xYh3Z4+bPqOMOt6xng5dsncATL55ohgjUaNTwdlxm
         ro9WpxfNdVDP7+nXLDbYLWo0pT4ufFUdwUE8fWukLETpjiqFFPAKJyElRT0uSgl98en6
         54fI1PWdDcq6tOu5bLzz2aojt4jbxG2pIoAptjACvvW1KCcffTBrKbj+HYpdosSCDVvw
         ClWqY7Yjr9lUhcidsEFW1cUN43q/oRVi8Y+JeiptRJAz4hAGe3K68/Lq/keEwVYgDNBR
         arrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i+p7JMtxiJhKbk+HUedbmrpIzQr2u83bgpY8rPoMJJA=;
        b=mboE73DTo3G0mQQIFQqrUqnbGcbJldjWdyvS0q0uW5jOuEYkN2FOrXGYRFPF+hnrlI
         46fdHzD87HAvx6oG7pOFo2sRPiFGuG83jcyJaeOn1yBsyfNsHLPLyw0Z5YVBq+rbg4wB
         fuXxaxkHQ2J2VLzrrtgrSeF2o1OMC5UbPFQMzaAYNhlEVQavJIttXFGnsYilL8RGyo4M
         S+dzlmC4PymhGnNZj4p9A9tScM3S0L1CmAIWbqi8ckpmNWtvMa3FJSbC5083pS+QkVYm
         RPNfHWOG2LVa7Dym/XTW57Bq762kcSYWek858CH7IAzJrpNAkyI+Ohvj+bkqxIjYMlpz
         yhTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=pskhFOzC;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id e76si335086vke.5.2021.12.23.19.14.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Dec 2021 19:14:01 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id j124so11740776oih.12
        for <kasan-dev@googlegroups.com>; Thu, 23 Dec 2021 19:14:01 -0800 (PST)
X-Received: by 2002:a54:4613:: with SMTP id p19mr3571744oip.162.1640315641099;
 Thu, 23 Dec 2021 19:14:01 -0800 (PST)
MIME-Version: 1.0
References: <20211223101551.19991-1-lecopzer.chen@mediatek.com> <CAMj1kXGL++stjcuryn8zVwMgH4F05mONoU3Kca9Ch8N2dW-_bg@mail.gmail.com>
In-Reply-To: <CAMj1kXGL++stjcuryn8zVwMgH4F05mONoU3Kca9Ch8N2dW-_bg@mail.gmail.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Fri, 24 Dec 2021 04:13:49 +0100
Message-ID: <CACRpkda_42LSWcaq0Q8aGB+12bo2494snk1Tua62UTLjVE1fQA@mail.gmail.com>
Subject: Re: [PATCH] ARM: module: fix MODULE_PLTS not work for KASAN
To: Ard Biesheuvel <ardb@kernel.org>
Cc: Lecopzer Chen <lecopzer.chen@mediatek.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Russell King <linux@armlinux.org.uk>, 
	Abbott Liu <liuwenliang@huawei.com>, Florian Fainelli <f.fainelli@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, yj.chiang@mediatek.com, 
	"# 3.4.x" <stable@vger.kernel.org>, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=pskhFOzC;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Thu, Dec 23, 2021 at 12:01 PM Ard Biesheuvel <ardb@kernel.org> wrote:
> On Thu, 23 Dec 2021 at 11:16, Lecopzer Chen <lecopzer.chen@mediatek.com> wrote:
> >
> > When we run out of module space address with ko insertion,
> > and with MODULE_PLTS, module would turn to try to find memory
> > from VMALLOC address space.
> >
> > Unfortunately, with KASAN enabled, VMALLOC doesn't work without
> > VMALLOC_KASAN which is unimplemented in ARM.
(...)
> This is not the right place to fix this. If module PLTs are
> incompatible with KAsan, they should not be selectable in Kconfig at
> the same time.
>
> But ideally, we should implement KASAN_VMALLOC for ARM as well - we
> also need this for the vmap'ed stacks.

I also need it for my kernel-in-vmalloc patch, I guess it's the
reason why I can't seem to get it to work. So a lot depends on
this.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkda_42LSWcaq0Q8aGB%2B12bo2494snk1Tua62UTLjVE1fQA%40mail.gmail.com.
