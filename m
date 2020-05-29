Return-Path: <kasan-dev+bncBCMIZB7QWENRBKWTYX3AKGQEBQZYDMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id CDD2B1E8836
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 21:59:39 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id f130sf4263167yba.9
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 12:59:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590782378; cv=pass;
        d=google.com; s=arc-20160816;
        b=WFA/hHBLu/VlvSC9nQFqTrj8JXjVKWgkO7ibl34HOq13dFcUtHBAlX4N8SzlXmY6sQ
         70hZVDeo53YVd53NP1NpqzPI6KxYKqvXTUVmt5XHUYORvKZCok+KazJxkKbX95+kNPnH
         tgS7IcfD3aJMYIz/I0sIdIMpSiK/8W68eT34M7Wf99kupHJ6oJHiIeEoxDpvIMYCV5PI
         50lPv9I9DZfcYqF+FLRScQq1xPNQentWPqpEOSKLOVEi4XOT+8SaZJf5ZKa1r8G7M3iO
         wrJRPqf0PME7YoON0o5njinrgrpjakFmLCusAccq9Ik/gQqcJ3ZN8DqwzFKt/IVHPNkl
         2G+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f6yZGGEdmLi1VGtQpz3qjUtE07tgKAXJ7LnJjOWTJ6s=;
        b=YfsLr86+QOl4vzCERP83GKrQMjWD9e1GB7aNTCuQGczyZZLH/QzIab5Pg2EgSZaoGn
         odIemhEBDDTTMRgKytzRBCZEYpZT9ZTeS8caGXhMn3Yd0bpo2/m30awuxiFFi8wzUrfS
         AIjiQ5cacrQb1re4IyP840cwwtW3Mx9NiGlIEbbpgzu+t2dhN9HsZ4MZrHt48iuLr14b
         xES0nmC9y7EXJrGT9f0oeiOtc3kr7nUUNz4ixfwaZIShdtzhoR+mHgVP95IaVxWs46c4
         eQvWNhlQZ4lvjPBNVsUW5Mi73/pzlA2+mMiD+TgpX6Ls05ObnkN3sonPkAdmsWkTy6Vd
         CSMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wJxPMVDR;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f6yZGGEdmLi1VGtQpz3qjUtE07tgKAXJ7LnJjOWTJ6s=;
        b=rKvi0dCC+ZucATmyeKCDAkzexYxPbBxsVBXRnl+Ikwq0f5mLoWqzZFUYFiURTTsB1X
         j+1uO0YAE2f1KG5YaaistYDoRqF9XZPknu0UGLSjY1eInXFaUY4GPvBjnO0+E/4j5bR9
         yBfeWk34koJR4Qil/7sU9wbC89Guc0ylBHSimQpqo6mPd1R490LTHy6F0XyHDQU5rj21
         ryl2JQASu/RD8w/lSodTZiXCEpVh1iXM8/vuE8XgBrOOqPxWLoyYmdcb8PzDsRXsVfRn
         8I9wvPjcAj+ADuVox85GK82Cp191A0c9n+JadJdJL/xkzn2yO0hZm1ZFfLgl9Tkt1lPp
         VRaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f6yZGGEdmLi1VGtQpz3qjUtE07tgKAXJ7LnJjOWTJ6s=;
        b=q5iIdQACMpF6CsDHQhRDL1B2w6B6YC4nHj4GVZGaX3tLGGZ3vsM55Yng/X2Qr2qF6M
         IXNI0B6/Kssr7tPKlTR6lO8cUcahmksQLT61i7X6dXSSGc7Ml+Xt3H6wJgBOk4bp7TUk
         hl1JVlmL9YCe/Jl9TsJ9Y45Vvt1bvgA8WcWKKtUSre0FfXkhxeJ4bJcT+5bZWezXUA5D
         aP1nJDXo0dhhDKEsySgqwXElVqSrJdQVIWSIS98r+w6hJR5g5D1L2wYWL3pf5VlrP0TO
         zsEz4xq8SgBvXTIMjOegah1ua4EDdNp3NSHGsjVElP6xAfboTxYSTDrjtMOGSETFUfwZ
         XoDA==
X-Gm-Message-State: AOAM5315Fbhmoi+Cw65B6u1Pf9gGuyyolc6QGNogWZf9RghjynHh9p1A
	hCXkeyNPOcNIGY9prPX9scs=
X-Google-Smtp-Source: ABdhPJz4BWbZyRI3UnLcNHsiU7lXxfh+m+yIWThwYimPgBcpTfxtcUY2XeEGSN5dgPmFk7LkLx8vRQ==
X-Received: by 2002:a5b:c87:: with SMTP id i7mr15898249ybq.182.1590782378680;
        Fri, 29 May 2020 12:59:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:72b:: with SMTP id l11ls2788131ybt.8.gmail; Fri, 29
 May 2020 12:59:38 -0700 (PDT)
X-Received: by 2002:a25:80c3:: with SMTP id c3mr18152690ybm.33.1590782378258;
        Fri, 29 May 2020 12:59:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590782378; cv=none;
        d=google.com; s=arc-20160816;
        b=PAdN1PaAaC72qpYFGQ4xRx6cbv/saI3gYyhPiv7shQGHX4tnJf1DcAk/2wHco7R3Gy
         sYSilWfA3sVEBHpnHZJLtEhFtqVokIIK4krynCIwiZC0FwLUvBirZm2P4Sty0eOyEGvM
         ZQ8p0CSHPK9Hq47+il+Ewms7MOdtG26OVrd+Oe+vRucrM9Jt1COpQSNf+eqWtbU5XI+1
         BxtGT/wDTA0sN/Grmp6yolu1Z+KryQreQdpBtmybBdZku89AGZwfd61uuAmlBgFaPOmC
         78NSkNKkiuA19CxO4+b6Vpzq4USMzRJFc9yNW25ZvRAVm0P74gDwIZ2T5gvp4SAgqu2F
         /LcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=umtq5FGga4TFsycTMhzc++9pclocPWtIsuhQM8z4ozs=;
        b=Dv5RcCl3ggwHQeDHBezRUhPyG/5q5FRIf1QRFiUj5icoZCyU/V8QybkK5vOWPE1rbQ
         OXGe247Jqf0eUzwS9F5vusEgnDxpT3dHYPQ/FEs1Je0yT07fPgk9lP+xRn/8wyXAx18D
         BC8M3TP0ASnmJkFv12FQItvcJB5ZsHK585wdnshnFET58zbDfxAbHIhIOAqr94ioJZ/Q
         1WKzHR9n0gfzlM8wcGzeqBaijI7lbIu8uV7Xyl+HomZdX1TxA6Hg16mvdYI7T1MZrDcL
         XR1lnm6ixdi3yiwq0+XeOi0SW3ZTSSyK1j7LrCGFM2pZdgegxmdUT+DfrOl+gqMRc4wL
         e+EA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wJxPMVDR;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id s63si740840yba.2.2020.05.29.12.59.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 12:59:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id u17so1850015qtq.1
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 12:59:38 -0700 (PDT)
X-Received: by 2002:aed:37e7:: with SMTP id j94mr10647931qtb.57.1590782377680;
 Fri, 29 May 2020 12:59:37 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
In-Reply-To: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 May 2020 21:59:26 +0200
Message-ID: <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Raju Sana <venkat.rajuece@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Linus Walleij <linus.walleij@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wJxPMVDR;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, May 29, 2020 at 5:39 PM Raju Sana <venkat.rajuece@gmail.com> wrote:
>
> Hello All,
>
> I started   porting https://github.com/torvalds/linux/compare/master...ffainelli:kasan-v7?expand=1
>
> to one out target , compilation seems fine but  target is not booting ,
>
> Any help can be greatly appreciated
>
> Thanks,
> Venkat Sana

Hi Venkat,

+Linus, Abbott who implemented KASAN for ARM (if I am not mistaken).

However, you need to provide more details. There is not much
information to act on.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm%3DCjgQ%40mail.gmail.com.
