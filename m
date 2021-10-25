Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOUQ3GFQMGQEEOZP2DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BC55438F12
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Oct 2021 08:01:33 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id gg23-20020a17090b0a1700b001a213f91dedsf839539pjb.8
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Oct 2021 23:01:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635141691; cv=pass;
        d=google.com; s=arc-20160816;
        b=JPeKfug+XLC6jWdnBEFstVHaC8pZOrcDvYZKicG4jNNg5obii2dll+x/dXhhS7CfTD
         rBOIMfqyTnvM7ZEBmOOvudZppoK60RSoIwtreD49wskbCx3+NzM3awwdQ0cZXX/+mtUY
         onRMmPSh74Py1MqBW4NDHBiWo0Wsf1IeWDDSQmb7eIzmkYAVPAkCLp7wUjOZaKzwyhdQ
         11vx/ogQwdNF0JzLzdoa/RTNTzduVPdxVihXdyToIOhkBRFZIurpl7P+SzB1Cf3PkfKn
         NJAmif5Ms4a7M5Lxcek/hNUlHfVSY+3FZzadLwGbFYchxkTHnZBa68Le+7Rzg94NaWxc
         +wvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zVm2D7oAebTI8geOOaEB4IonUpKbpYFTn0sLPK0i6Hw=;
        b=bNgZjqEwC88OK7X3TOc45KriQDy7i8uK1iAT1Y7xtHi/4wzPAPGDNjXQscisUslsWj
         LsCPUP9DwgOrUNFM0A6KtZT/RVifWj+g9G4MDGn0cok6rsjuuEe63HwgvVFJ3JG7Zmf8
         UA4Uwfj8MTwb58eO9A9UktpHV9jByzIzY/wPbFJGX87BZZl4VWxvxpuO8tl8IG0eUAg+
         x62GSMSqa3G8pVDDGm5dvX6BhJaSLK2cIkqke03y+DIgDM+c7yYzpJLOjX6G+EELf3wx
         kn9K1WnOlqb64kEmtpNBQPWgs5Gedn8j0N0yf/s65+9Y8vqmE3s23aoApYOK5SbYt0MT
         05vQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U57c8msb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=zVm2D7oAebTI8geOOaEB4IonUpKbpYFTn0sLPK0i6Hw=;
        b=hi6pQDQC1ZKdculmnSkz0uVCAoidyN7PA0Y2UHzPfTX3l6cUyn6RMxjwGHnQ6PdOoq
         fC3/yJyP4UCjBDH0Sj85/z5cvcDZo72i+Tk/T80cbnFNTaPzIJ1geIt59jN3Y14uWmSJ
         wPuG6j3P5BcIR2YNUMdtXtZ6F9QuHMDqX/6kTTnHFwrC1JBUU8PYH9wBkXXnpUu+O5jJ
         Kr8npA1td4e9OeWOdBzV40vvIdJZCPawi0XqDKNvde/BCMG0gFbN5rjmd21C9KKjL11l
         DtBhltlEuFKnqgN+mk3sAhWBfj2U9etfqIEkOFEzBBMnZ20OQb1fiLzGQgluHx9epAS+
         /4/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zVm2D7oAebTI8geOOaEB4IonUpKbpYFTn0sLPK0i6Hw=;
        b=SyJYTsL+pk4ayGdeUrgYh2bgEi4KTFLFTdetCdWrzzUEyIki6Gm18AIFrkXc4hcTAk
         ayhgSBUGgv0WbN7jU0ds6vDHpTHjrOtqGYGdpIrbTBC+A9u91P2XQRnFv5/S2HZLHC/2
         W7LI8PHxzNaFcC5wdz8/H3CwtvVqcKOGxddVNVKGAkQQX18vh1QLOz8Mk7XeMjZ4P+a3
         1sS0cxBaEOMQ9Q4wWD85jE+DYjTxs1oL/i2meOPJ/YjCy2NTaEnlVR+ReSKUsA07MqF0
         rqiHpxRylSXBaa9vBxTsZSIv7ukLgoiPvGjdgTlTn2LiBSui67prA/Hb9mKhMdP8Jaba
         cVeQ==
X-Gm-Message-State: AOAM5308qy6pUyk30pvgn5RCen1e+0CwmMFxbGesLMGAP2RYoXqmPeGI
	Q3tx+FkZp4G+dfPcgUqbl9g=
X-Google-Smtp-Source: ABdhPJzhKEMeJCgPtFWthOaYT5jha0vHDJaOnq7RLA4O+moEmKeI9H7adQ1v9T/g38MpvNNpZIRVIg==
X-Received: by 2002:a63:ff11:: with SMTP id k17mr12068186pgi.405.1635141691013;
        Sun, 24 Oct 2021 23:01:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6401:: with SMTP id y1ls6820162pfb.10.gmail; Sun, 24 Oct
 2021 23:01:30 -0700 (PDT)
X-Received: by 2002:a65:4209:: with SMTP id c9mr11981511pgq.399.1635141690328;
        Sun, 24 Oct 2021 23:01:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635141690; cv=none;
        d=google.com; s=arc-20160816;
        b=pjD0OkBMEaj5D0BUKu4nt90WsaQ/mmwp5OW31xr1WRUfEZGzZoHBestVgmhvZDMoz0
         ysWdXi6oDzPpM/2p93Ra/PMchmy6DdqN2NygfoI9Jd1CKtqwIkv8JSjQpOqGpDlG3/kq
         ltUuByF2LvJhkTTzSzUdRpfYVrnFG04mRx+62/YohB6Szx1MRUq0b4vcIYCLWbx7YlZK
         J+6963RwDpIK/kJe6mgsOg8QbQXcw8DzXAcfJBXNqcHTw7xc6U0kvNF+GNdls3z/qKKe
         n2jAxw+jnWER/87X2aga2qWQ5ILwV/nG1rm08NrMudH/gZPtjj/ZtSC2k9bl8JQTobnR
         vixw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BHDHCA2tdEWpGSchMhf7ru08fjMx1410uewWoCJjgb8=;
        b=Q48tolGOcs68PQ+ftEL4T00/DDndJErin5cCqKA3i4tC5RzYlWlcG/LGytGLD4Cgbg
         dPu7bQMHtvl+64gYHbQ7XG6cR76q6kIJxm2f6HTx9NQS6JwoJEpJZ3YnVpfgQN5AkFin
         VVfFG2e0XPvSFMRlSQrY+2CXkXK9RE3MrAugfA56ungH02e/h0egQxlvuuSQkemiV3LE
         /g4EROxFQIkZESiK3paGNFeDNJQhWOONjmqWVXdJWSyS4tQS9j8UkwU1J9yg/vHJ2vux
         PUwW9IP0JQHJQv8IWsN99CxfiengM6T3ZPX0VtBElsL/o/bSQOOq4DbQMTCh4UKjaV+A
         vAAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U57c8msb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id mh15si1990907pjb.0.2021.10.24.23.01.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 24 Oct 2021 23:01:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id o4so14082850oia.10
        for <kasan-dev@googlegroups.com>; Sun, 24 Oct 2021 23:01:30 -0700 (PDT)
X-Received: by 2002:a05:6808:6ce:: with SMTP id m14mr10715106oih.134.1635141689795;
 Sun, 24 Oct 2021 23:01:29 -0700 (PDT)
MIME-Version: 1.0
References: <20211023171802.4693-1-cyeaa@connect.ust.hk> <CANpmjNP8uAexEZ3Qa-GfBfX6V8tAd7NK0vt3T3Xjh4CkzxfS-g@mail.gmail.com>
 <TYCP286MB1188F7FAA423CFA03225B3BE8A819@TYCP286MB1188.JPNP286.PROD.OUTLOOK.COM>
In-Reply-To: <TYCP286MB1188F7FAA423CFA03225B3BE8A819@TYCP286MB1188.JPNP286.PROD.OUTLOOK.COM>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 Oct 2021 08:00:00 +0200
Message-ID: <CANpmjNO5-o1B9r2eYS_482RBVJSyPoHSnV2t+M8fJdFzBf6d2A@mail.gmail.com>
Subject: Re: [PATCH] mm/kfence: fix null pointer dereference on pointer meta
To: YE Chengfeng <cyeaa@connect.ust.hk>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=U57c8msb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
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

On Sat, 23 Oct 2021 at 21:22, YE Chengfeng <cyeaa@connect.ust.hk> wrote:
[...]
> Thanks for your reply, this is reported by a static analysis tool develop=
ed by us. It just checks dataflow and doesn't know other complex semantics.=
 I didn't know whether it is a real bug, so I send the patch just in case. =
It seems that if the index is incorrect, the function addr_to_metadata will=
 also return null-ptr, I don't know whether this is checked by other upper-=
level functions.
[...]
> And you are right, if it is a null-ptr, the root cause of it should be in=
 the upper-level function. I think you can add some null-ptr check like ass=
ert(meta !=3D null) if you want, this will suppress this kind of false posi=
tive report. Anyway, I think it is not a very good thing to just let this n=
ull-ptr dereference happen, even though it is not a big deal. Adding some c=
hecking to handle this case may be better, for example, print some error lo=
gging.

It's a little more complicated than this: the negative index may
happen when called with an object in range R =3D [__kfence_pool,
__kfence_pool+(PAGE_SIZE*2)-1]. The first thing to note is that this
address range is never returned by KFENCE as a valid object because
both pages are "guard pages".

Secondly, while calling kfence_free(R) will result in the NULL-deref,
however, such a call is either buggy or malicious because it's only
meant to be called from the allocators' kfree slow-path (slub.c and
slab.c). Calling kfree(R) _does not_ lead to the kfree slow-path which
calls kfence_free(), because the first 2 pages in KFENCE's pool do not
have PageSlab nor page->slab_cache set.

You can try it yourself by randomly doing a kfree(__kfence_pool)
somewhere, and observing that nothing happens.

As you can see, encountering the NULL-deref in __kfence_free() really
should be impossible, unless something really bad is happening (e.g.
malicious invocation, corrupt memory, bad CPU, etc.).

And regarding assert(meta !=3D null) you mentioned: the kernel does not
have asserts, and the closest we have to asserts are WARN_ON() and
BUG_ON(). That latter of which is closest to an assert() you may be
familiar with from user space. However, its use is heavily
discouraged: unlike user space, the kernel crashing takes the whole
machine down. Therefore, the kernel wants to handle errors as
gracefully as possible, i.e. recover where possible.

However, something like BUG_ON(!ptr) is quite redundant, because a
NULL-deref always crashes the kernel and also prints a helpful call
trace.

But as reasoned above, really shouldn't happen in our case. And if it
does, we'd _really_ want to know about it (just crash) -- we either
have a serious bug somewhere, or something more malicious is
happening. Therefore, handling this case more gracefully, be it with a
WARN_ON() or otherwise, does not seem appropriate as I couldn't say if
it's safe to recover and continue execution in such a state.

The same is true for any other place in the kernel handling pointers:
if a NULL-deref really isn't expected, often it makes more sense to
crash rather than continue in an unknown bad state potentially
corrupting more data.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNO5-o1B9r2eYS_482RBVJSyPoHSnV2t%2BM8fJdFzBf6d2A%40mail.gmai=
l.com.
