Return-Path: <kasan-dev+bncBC6OLHHDVUOBBQE2RL2QKGQEDYDI6NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id ECD711B6E8B
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:54:56 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id l6sf3544707lfk.2
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 23:54:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587711296; cv=pass;
        d=google.com; s=arc-20160816;
        b=D8GBYhsM76cGqZpTXD/7GpQQ3mpa72CNpMu721T3z3mmyLKdwJ1kd8A23Da5+f3//q
         +VGPZfUxgLXWZ8yAtVAVl5SvmlkSgTSYMACBWsZqEzu/gi8zpdYHtn8QYISamSVIGKYa
         XyURoQkb0urnP0HNkysrmCS8934/ug2TIx9Dpqo42cyTsC/ig/1wor0qUi98ccDH5rRT
         cqNQxtH5CM94luwiXV11H3XeQ2ESd7Zi6ww8+xcByp3GtfnY/rJdfkBaIOzWKdb/3Gzs
         w65n9Kx08fpp/Zqxtf7pHMpqUkNRtmcFfXPwZZjs8G/WCc5BGWxLtkyn0ksN5TxBy4Gl
         a17g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HGklEcO9NqlhKq7/aMJa1tr0EyisegntSAB6sK7ESRo=;
        b=JhtrJ3y5/pQTfB6UcrRBMaZtQpqR0wTkG4atCC6m3cpo5zZTBBdYV7JTqLVO7Y04ED
         mBSCxgfNbt+gFsMbwlCt7SCmGppGnk5zUqN+GHpZBnfACjo/ln5NkRAv1ofR1h96mDic
         veaa+0lB8HkRiLkQSMFCJdbloDI9szAWwgEsvTGiv+rDZKsXxKj/yDe6SgbRVJbJBtWn
         EZ8wF4B1XQaZCO1QyhuzaAZb/dAc246OEBUahcVZtkru4Gl3maYjvtuZaFaaQexeBsPT
         RCJD8oF4sFa8T64M6ccwwuCPgp/xAwKmYV3LJ21pgckQm/Vr1IbszXStAPkL1SoPWYrP
         8JzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XZE878Fe;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HGklEcO9NqlhKq7/aMJa1tr0EyisegntSAB6sK7ESRo=;
        b=ngV6raNvbr0qPDSTRzEGHjQ/lGkjeluMtWqZZPwzzf60aBV+35HwomzgLA0QleK61H
         iFxac/aS7yu0mgrBl+pflmBXKvIVhP5yFzRGs/6aj9NhT7xbVvyILfMUUH8py5r3+hjS
         6i02YtLawwvFx4BHOGQZq6+wd9kDv7usw7huNxc2vv4AXtPuOvfF3q3yD82uMauRvRI/
         SDZGR1ETyDGR3257BFTRn68IXaVopPiP4z3qUm0FRAPJdE0jnF1SNAoTVzvgX0q/BUcS
         0DItjNKDGX+iqzsJCH0ah7JG8u7nDcUX7szHKiGfiqDSLACQDnSrQWS0whmtowDz/bif
         Ky1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HGklEcO9NqlhKq7/aMJa1tr0EyisegntSAB6sK7ESRo=;
        b=tRM/fSOQmSHA08GOC+R70JWDKye+oJbmCiqWK0M683e0AEfbMTcPlsqWFF4Igf/X52
         K08YIdR+VblxMV5pOKHVMvGS9gve4/WI3M6DJCBdqxhQME/lB1dXW/py1pdee99UESRx
         8cVYY8DtLelo8kMIucMQIvjbl4KibJuQrBts6oDD1yRtXHACEKgwD7fUOyjTYuuxY7Er
         125nIe1ij00N7x9twuQdeAl2y1T25ET+TV12jgjCklGY9moPcSGVY6NWXNkdh5s8XF0q
         iVf37CBmuDSW4Mapbp3eApfS4wmmDRFn0awE+rkIwN8jtecGe//4zPX8OPBZmybPBFhY
         zx2Q==
X-Gm-Message-State: AGi0PuZ1BWGiA+mM1d87/un817P4TmWZnO3Jr7XdAElaWQMGl56cGp3F
	d67ROSjStV6Mp+ZyVrXVHdw=
X-Google-Smtp-Source: APiQypKIiQmDuNNbqu3dBNQV7seGPZoIY6piT7eLZJMVl/aMTYAtumC+MCZ5upVr+sOgA+xCMsfJeA==
X-Received: by 2002:a2e:b8c4:: with SMTP id s4mr752160ljp.101.1587711296477;
        Thu, 23 Apr 2020 23:54:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:86cf:: with SMTP id n15ls2602939ljj.11.gmail; Thu, 23
 Apr 2020 23:54:55 -0700 (PDT)
X-Received: by 2002:a2e:8e98:: with SMTP id z24mr5092657ljk.134.1587711295753;
        Thu, 23 Apr 2020 23:54:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587711295; cv=none;
        d=google.com; s=arc-20160816;
        b=h1ntmqBU/fJhvXIHNTqyZ56C2Magquy+FWVaM2RwE9RMhjH+sD60A1BvA7+3438DiN
         rbFrL0zA+KLsyLXryUvAVPW1Rul1CO70b76CHrY+pKUkLgiexb4okWHD4n1BcNXw2Ypo
         qZDOm7BkqACSWMDAJtBOhNgSne7A7JL3XJOqsjvvpwsdh57u2VfyFQG1ytptOtF3soYx
         +0NA8JoTwFT6d/1ZsN3m6qRr0t691jDc8SO7/TRhvGb9BFjcbSr9q7zoz2oPcVTa6aMC
         WZTjVgy9nBALxvdpI89s4D2CivBPumwF/pkhRze7T/E6TDgaN6ZOaxELyXa2dftueVAV
         ySzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=suQ4RDO6wFMF7yNndDjyQyI4nxOZRUEOPb3EJG29NcI=;
        b=DClDtnCjrws4sqbCsxyn1LTwdvZ2HQaYS+oNOb9m0jcV0Vku2PHc98Z2fDNTH9OEo2
         rbdcocjTYL5e3MsXBe0xOQCDJFqZ4cxirf01HDSZIZcei24e7P73WG087klxB6JTgc/i
         3vxxc/4MzPKZgVGlnJZ1QEO+EjCjuQ0X12hHPIvdERoX666iIkbwWKe21m7NRm2srJMI
         24iSoAy/oYjd6U6m+70Bie2idQ/PlqDDcxisZKF4JBn3WfhtNBF2eKu5OCIVvC3dW2mf
         qFZ+GhyR2nz4yYMMMKnT+N0wcjxrmGJm1ftv9vrDLsvJSGYo+FwwIGcUVOOe8t4OSzjh
         R4Eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XZE878Fe;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id j13si306203lfj.1.2020.04.23.23.54.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 23:54:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id b11so9397736wrs.6
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 23:54:55 -0700 (PDT)
X-Received: by 2002:a05:6000:10c4:: with SMTP id b4mr9377644wrx.203.1587711294889;
 Thu, 23 Apr 2020 23:54:54 -0700 (PDT)
MIME-Version: 1.0
References: <20200423154503.5103-1-dja@axtens.net>
In-Reply-To: <20200423154503.5103-1-dja@axtens.net>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Apr 2020 14:54:43 +0800
Message-ID: <CABVgOSkwn2Y0khsWw4xLASj5e-m7hng6Z+5wCMYomZbZGn_N2Q@mail.gmail.com>
Subject: Re: [PATCH v3 0/3] Fix some incompatibilites between KASAN and FORTIFY_SOURCE
To: Daniel Axtens <dja@axtens.net>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-mm@kvack.org, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, christophe.leroy@c-s.fr
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XZE878Fe;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Thu, Apr 23, 2020 at 11:45 PM Daniel Axtens <dja@axtens.net> wrote:
>
> 3 KASAN self-tests fail on a kernel with both KASAN and FORTIFY_SOURCE:
> memchr, memcmp and strlen. I have observed this on x86 and powerpc.
>
> When FORTIFY_SOURCE is on, a number of functions are replaced with
> fortified versions, which attempt to check the sizes of the
> operands. However, these functions often directly invoke __builtin_foo()
> once they have performed the fortify check.
>
> This breaks things in 2 ways:
>
>  - the three function calls are technically dead code, and can be
>    eliminated. When __builtin_ versions are used, the compiler can detect
>    this.
>
>  - Using __builtins may bypass KASAN checks if the compiler decides to
>    inline it's own implementation as sequence of instructions, rather than
>    emit a function call that goes out to a KASAN-instrumented
>    implementation.
>
> The patches address each reason in turn. Finally, test_memcmp used a
> stack array without explicit initialisation, which can sometimes break
> too, so fix that up.
>
> v3: resend with Reviewed-bys, hopefully for inclusion in 5.8.
>
> v2: - some cleanups, don't mess with arch code as I missed some wrinkles.
>     - add stack array init (patch 3)
>
> Daniel Axtens (3):
>   kasan: stop tests being eliminated as dead code with FORTIFY_SOURCE
>   string.h: fix incompatibility between FORTIFY_SOURCE and KASAN
>   kasan: initialise array in kasan_memcmp test
>
>  include/linux/string.h | 60 +++++++++++++++++++++++++++++++++---------
>  lib/test_kasan.c       | 32 +++++++++++++---------
>  2 files changed, 68 insertions(+), 24 deletions(-)
>
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200423154503.5103-1-dja%40axtens.net.

Thanks, Daniel!

For the series:
Tested-by: David Gow <davidgow@google.com>

(Though I will mirror Dmitry's comment[1] on patch 3 -- I also have a
memset() already present in my branch...)

I'd been digging into what turns out to be this issue, which we were
seeing sporadically[2] with the KUnit port of these tests. v7 of the
KUnit port[3] includes your changes, and fixes the issues.

Cheers,
-- David

[1]: https://lkml.org/lkml/2020/4/23/838
[2]: https://lkml.org/lkml/2020/4/18/570
[3]: https://lkml.org/lkml/2020/4/24/80

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkwn2Y0khsWw4xLASj5e-m7hng6Z%2B5wCMYomZbZGn_N2Q%40mail.gmail.com.
