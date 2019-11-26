Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2XC6TXAKGQEV57U6UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id C515B109FDD
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 15:06:35 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id p18sf1017321pfn.4
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Nov 2019 06:06:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574777194; cv=pass;
        d=google.com; s=arc-20160816;
        b=J1XTQ9i14/UTYM9MThkA/zwWo/NWdmRUm/r5Hlc31WVnv0JbB2wJMj0M2qSESLbd5N
         qJB3+hwyMFdaMe+OSWRV5L3A2ENADd8/jaqF5rOcPjXtG2YcNlc2gv1nYGqFbCSSFuP4
         Sa73h0fXC0k5dNrqLXVhw7B9bg/QrcPN6RvbO/ZOEdIbvHiM+Rar4WG0HtnOh9e/0e1G
         qUFxq8gD2JqAUgP1I3IAb9oTNirjAEYNz6XSIDIEgckjdtjTUONLR4JSkdH09RUh3e3A
         KwU66r94frbHm4maUVKabyxsaGqcvbzEuvRc10LVGoKUWtsKPDI3LoFXpjgYW8CmWcSU
         DAEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zjVFFkFadLRmgQL4RzKFmwKx/2BMCaKsHM5FmzpI4AY=;
        b=N1UOOMRDU25dWtnUjNVt+21JhaEYOCSFlYXx78tZ22hgLZ7gWENrlcI8oNwTPtOnjW
         pX7BOryLOrRElRvbBBaWfNxHn9PB2pmE9Nz9DsnMHCgSQu26yo5VYBYWPpgZKE+UJb++
         63jsPOSljCvvIt2I4l+3Tdr3TcmJ79SA7tqRPmpa52I/Z7Pifkwo4CC4WhBaI+4VLo+f
         TbZnvN1fqlmRsK7Ua69UWc0gxk798dY9Q16gNQVwTZdIO16pmVo0+HzzgzizyG4+1k6e
         47y8vGZtN3L3DQQg1jsVhaTNngGh3u5i+20M+oudjHyUoOC8elbinFj9zPkWXiCQQjYT
         Eb0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dw4HY62q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zjVFFkFadLRmgQL4RzKFmwKx/2BMCaKsHM5FmzpI4AY=;
        b=m5W20HLSxo5mUIF2G/FkFYYZWfTPPBQKm1jl54hUIzhJPI5kOfuhGdLRl4QeppgYH1
         6RVgOG23TCS4ZPEM2OE5evMUAjOmul2DBjG/8iDP5j4CQ3zjay/KT0dXkBr3VYc+6z24
         ykPyU2VNqZQ5WqXk2DwszQbUp9sKfaE/FUKQZTmzkELh0v98eNsyKQSRQZoQMHOnOzvl
         gn/BxJ+uSkOzRxIA0p/BrvdlomGegBskUoAiFqKEGTiSIacp+B83B2ks7rA+mhfIaO91
         +/hiEhLWOmFjUY8Xs9NPEuOcEykeHu1qFVj2ywUcgmsr97Z0ISam74q/6lXFTa+JQyLX
         hr8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zjVFFkFadLRmgQL4RzKFmwKx/2BMCaKsHM5FmzpI4AY=;
        b=cW6KV78VeywWzivy1vlQ0tZUhpss0l8aHQ57+QbKIlPMA7fmUioPddXK4Rlbw/o+Uw
         tpjjSsQ6xONPaQcC/QwH8r4iTmUS94qUDua2qFShY/jl93o5SkhjmFdw0+EmCWfKmhSg
         0XHlheI90LZuNLaJ5xhw6n/yHi/M0Nv0L8H3roMVIpX8PrtLuWVq9tN8wT1kkUTwCN3G
         lz7VNu9Wej1nH74UgybBm2J6+JEojCgAdPlEYX9iOQm+9EmwrTHDxZvklbs3MqtWRFM+
         FX3lSphUYf+VlkhKPIyD42YnZ6OU+/BZgQbDOEpP8N9grw65brSMypKD/R3vTH39IwgC
         F6lg==
X-Gm-Message-State: APjAAAV2cyHh+u0DpLcCO2T/yP/pU9C5dN5EXDiEBienajsJDeWWGK6V
	jhfzoUWb6KqYTmgxwVVzj4A=
X-Google-Smtp-Source: APXvYqyg53C3zKEaPcv1NRGfbqgYL7OkQ96uQEvLLYvfe7+UCya50Ls7Lx4qACsR3h9jsljWeuivRw==
X-Received: by 2002:a17:902:a98b:: with SMTP id bh11mr35090240plb.281.1574777194099;
        Tue, 26 Nov 2019 06:06:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:b519:: with SMTP id y25ls96204pfe.15.gmail; Tue, 26 Nov
 2019 06:06:33 -0800 (PST)
X-Received: by 2002:aa7:868c:: with SMTP id d12mr42113234pfo.189.1574777193399;
        Tue, 26 Nov 2019 06:06:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574777193; cv=none;
        d=google.com; s=arc-20160816;
        b=wMpKb5MQeHU2LHGr8rShNZ05GDxdHkL8tWXZnj06/2zSLiajl4vqqkDeWXjd+eEKjv
         WgbHYh5yJtcJtbT5adAHX4yHvj+/l4+IUp/KZuUFIEEjaD+9BWGena482k10Xf7jeObe
         iuhyVjtXUZ4ZwWp8TO8OfbuPwk/f4iCSjgu9XDGdPn1lCgF+/QV0T+xxhLov1U/s0Owf
         xUUllMftHoCj4wcZGwVNzVcGWMofbS7x2aWn7eLpdKOp+XUdkRbKtdv7Yl2kv6HQJ+Wf
         3jyJ2tapcZCVrgdjDlItjUioHwYsUxOE1l99FIvr/pO+Y7HsFDZNrAXdB0Lw8ZLTFk6L
         0YDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KPOiBiMl69XGQDBmycxuawKOxsJQrxoI/O+sj/Y0vXA=;
        b=SI2R+RMLMHrifm8y5kyVcMuTExHhTGHaxi5Od5GICcqTZkrlPBLr5gHkYCqss+yjlv
         3oKaBBHPnqOIdwMjSTqWt6uSuDcUGOu7L3L9N4oFS40F5sWC/2jm28HzFqsc9ZiX2Sji
         sxcopfyTtV0CJzdvL+Dc2CPBaLLaqgSBrSb87vLEa+hG40MsCxTr7+Lvt61Z7t0ZTHNm
         qFtgfatqyQpfM0H8Kf/X9c4iN9dagosTRKKYS8x/KBabrxMx+R2wv8E4tO3T9HBs59P3
         PmOHZysSIJWw9SbNhE6oUyV5S2IlNL2ZFxXBmYNSt1fsujgrF/pUnZ+P1oOSTqKz8UYS
         y8sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Dw4HY62q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id x1si408337plo.0.2019.11.26.06.06.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Nov 2019 06:06:33 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id m15so15971309otq.7
        for <kasan-dev@googlegroups.com>; Tue, 26 Nov 2019 06:06:33 -0800 (PST)
X-Received: by 2002:a9d:8d2:: with SMTP id 76mr25447839otf.17.1574777192640;
 Tue, 26 Nov 2019 06:06:32 -0800 (PST)
MIME-Version: 1.0
References: <20191126114121.85552-1-elver@google.com> <20191126122917.GA37833@lakrids.cambridge.arm.com>
In-Reply-To: <20191126122917.GA37833@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Nov 2019 15:06:21 +0100
Message-ID: <CANpmjNNcWujm-Q8WD2Lgf2ww5aG-kfmFca7YC96BdcFOkwgxXw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] asm-generic/atomic: Use __always_inline for pure wrappers
To: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Dw4HY62q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 26 Nov 2019 at 13:29, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Tue, Nov 26, 2019 at 12:41:19PM +0100, Marco Elver wrote:
> > Prefer __always_inline for atomic wrappers. When building for size
> > (CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
> > inline even relatively small static inline functions that are assumed to
> > be inlinable such as atomic ops. This can cause problems, for example in
> > UACCESS regions.
> >
> > By using __always_inline, we let the real implementation and not the
> > wrapper determine the final inlining preference.
> >
> > For x86 tinyconfig we observe:
> > - vmlinux baseline: 1316204
> > - vmlinux with patch: 1315988 (-216 bytes)
> >
> > This came up when addressing UACCESS warnings with CC_OPTIMIZE_FOR_SIZE
> > in the KCSAN runtime:
> > http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> >
> > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > v2:
> > * Add missing '#include <linux/compiler.h>'
> > * Add size diff to commit message.
> >
> > v1: http://lkml.kernel.org/r/20191122154221.247680-1-elver@google.com
> > ---
> >  include/asm-generic/atomic-instrumented.h | 335 +++++++++++-----------
> >  include/asm-generic/atomic-long.h         | 331 ++++++++++-----------
> >  scripts/atomic/gen-atomic-instrumented.sh |   7 +-
> >  scripts/atomic/gen-atomic-long.sh         |   3 +-
> >  4 files changed, 340 insertions(+), 336 deletions(-)
>
> > diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> > index 8b8b2a6f8d68..86d27252b988 100755
> > --- a/scripts/atomic/gen-atomic-instrumented.sh
> > +++ b/scripts/atomic/gen-atomic-instrumented.sh
> > @@ -84,7 +84,7 @@ gen_proto_order_variant()
> >       [ ! -z "${guard}" ] && printf "#if ${guard}\n"
> >
> >  cat <<EOF
> > -static inline ${ret}
> > +static __always_inline ${ret}
> >  ${atomicname}(${params})
> >  {
> >  ${checks}
> > @@ -146,17 +146,18 @@ cat << EOF
> >  #ifndef _ASM_GENERIC_ATOMIC_INSTRUMENTED_H
> >  #define _ASM_GENERIC_ATOMIC_INSTRUMENTED_H
> >
> > +#include <linux/compiler.h>
> >  #include <linux/build_bug.h>
>
> Sorry for the (super) trivial nit, but could you please re-order these
> two alphabetically, i.e.
>
> #include <linux/build_bug.h>
> #include <linux/compiler.h>
>
> With that:
>
> Acked-by: Mark Rutland <mark.rutland@arm.com>

Done, thanks for the acks!

v3: http://lkml.kernel.org/r/20191126140406.164870-1-elver@google.com

> [...]
>
> > @@ -64,6 +64,7 @@ cat << EOF
> >  #ifndef _ASM_GENERIC_ATOMIC_LONG_H
> >  #define _ASM_GENERIC_ATOMIC_LONG_H
> >
> > +#include <linux/compiler.h>
> >  #include <asm/types.h>
>
> Unlike the above, this doesn't need to be re-ordered; for whatever
> reason, linux/* includes typically come before asm/* includes.
>
> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNcWujm-Q8WD2Lgf2ww5aG-kfmFca7YC96BdcFOkwgxXw%40mail.gmail.com.
